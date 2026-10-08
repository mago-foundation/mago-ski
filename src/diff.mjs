import { TextDecoder } from 'node:util';
import { collectSkillTree } from './tree-digest.mjs';
import { hasExactApproval } from './trust.mjs';
import { parseManifestBytes, serializeCanonicalJson, validateDigest } from './manifest.mjs';

const textDecoder = new TextDecoder('utf-8', { fatal: true });
const MAX_ANALYZED_TEXT_BYTES = 2 * 1024 * 1024;
const MAX_REPORTED_FILES = 200;
const MAX_REPORTED_SECTIONS = 32;
const urlPattern = /https?:\/\/[^\s"'`<>()[\]{}]+/giu;

function collectOrigins(files) {
  const origins = new Set();
  let complete = true;
  for (const file of files) {
    const content = file.content;
    if (content.length > MAX_ANALYZED_TEXT_BYTES || content.includes(0)) {
      complete = false;
      continue;
    }
    let text;
    try {
      text = textDecoder.decode(content);
    } catch {
      complete = false;
      continue;
    }
    for (const match of text.matchAll(urlPattern)) {
      const candidate = match[0].replace(/[.,;:!?]+$/u, '');
      try {
        const parsed = new URL(candidate);
        if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') continue;
        const origin = parsed.origin.toLowerCase();
        if (origins.has(origin)) continue;
        if (origins.size >= 128) {
          complete = false;
          continue;
        }
        origins.add(origin);
      } catch {
        // Invalid URL-like text is not capability evidence.
      }
    }
  }
  return { origins: [...origins].sort(), complete };
}

function markdownSections(content) {
  let text;
  try {
    text = textDecoder.decode(content);
  } catch {
    return null;
  }
  const sections = new Map();
  let current = '(document body)';
  let occurrence = new Map();
  let body = [];
  const flush = () => sections.set(current, body.join('\n'));
  for (const line of text.split(/\r?\n/u)) {
    const heading = /^(#{1,6})[ \t]+(.+?)\s*#*\s*$/u.exec(line);
    if (heading) {
      flush();
      const label = heading[2].trim() || '(empty heading)';
      const count = (occurrence.get(label) ?? 0) + 1;
      occurrence.set(label, count);
      current = count === 1 ? label : `${label} (${count})`;
      body = [line];
    } else {
      body.push(line);
    }
  }
  flush();
  return sections;
}

function changedSections(path, before, after) {
  if (!before || !after) return { sections: [before ? '(file removed)' : '(file added)'], truncated: false };
  if (!/\.md$/iu.test(path)) return { sections: ['(whole file)'], truncated: false };
  if (before.content.length > MAX_ANALYZED_TEXT_BYTES || after.content.length > MAX_ANALYZED_TEXT_BYTES) {
    return { sections: ['(whole file; section size limit)'], truncated: true };
  }
  const beforeSections = markdownSections(before.content);
  const afterSections = markdownSections(after.content);
  if (!beforeSections || !afterSections) return { sections: ['(whole file; non-text content)'], truncated: false };
  const names = new Set([...beforeSections.keys(), ...afterSections.keys()]);
  const changed = [...names].filter((name) => beforeSections.get(name) !== afterSections.get(name)).sort();
  return { sections: changed.slice(0, MAX_REPORTED_SECTIONS), truncated: changed.length > MAX_REPORTED_SECTIONS };
}

function manifestMatchesTree(manifest, tree, label) {
  if (!manifest || manifest.tree_digest !== tree.digest || manifest.tree_profile !== tree.profile) {
    throw new Error(`${label} manifest does not match the current Skill directory bytes`);
  }
  validateDigest(manifest.tree_digest, `${label} tree_digest`);
}

function fileChanges(beforeFiles, afterFiles) {
  const beforeByPath = new Map(beforeFiles.map((file) => [file.path, file]));
  const afterByPath = new Map(afterFiles.map((file) => [file.path, file]));
  const paths = [...new Set([...beforeByPath.keys(), ...afterByPath.keys()])].sort();
  const changes = [];
  for (const filePath of paths) {
    const before = beforeByPath.get(filePath);
    const after = afterByPath.get(filePath);
    if (before && after && before.sha256 === after.sha256 && before.size === after.size) continue;
    const change = !before ? 'added' : !after ? 'deleted' : 'modified';
    const sectionDiff = changedSections(filePath, before, after);
    changes.push({
      path: filePath,
      change,
      before_bytes: before?.size ?? 0,
      after_bytes: after?.size ?? 0,
      changed_sections: sectionDiff.sections,
      sections_truncated: sectionDiff.truncated,
    });
  }
  return changes;
}

export async function compareSkillTrees({
  baseRoot,
  candidateRoot,
  baseManifest,
  candidateManifest,
  approvals,
}) {
  baseManifest = parseManifestBytes(Buffer.from(serializeCanonicalJson(baseManifest), 'utf8'), 'Base manifest');
  candidateManifest = parseManifestBytes(Buffer.from(serializeCanonicalJson(candidateManifest), 'utf8'), 'Candidate manifest');
  const baseTree = await collectSkillTree(baseRoot, { includeContents: true });
  const candidateTree = await collectSkillTree(candidateRoot, { includeContents: true });
  manifestMatchesTree(baseManifest, baseTree, 'Base');
  manifestMatchesTree(candidateManifest, candidateTree, 'Candidate');

  const sameName = baseManifest.skill_name === candidateManifest.skill_name;
  const baseApproved = hasExactApproval(approvals, baseManifest.skill_name, baseTree.digest);
  const candidateApproved = sameName && hasExactApproval(approvals, candidateManifest.skill_name, candidateTree.digest);
  const contentChanged = baseTree.digest !== candidateTree.digest;
  const changes = contentChanged ? fileChanges(baseTree.files, candidateTree.files) : [];
  const boundedChanges = changes.slice(0, MAX_REPORTED_FILES);
  const diffTruncated = changes.length > MAX_REPORTED_FILES || boundedChanges.some((change) => change.sections_truncated);

  if (contentChanged && sameName && baseApproved) {
    const baseCapabilities = collectOrigins(baseTree.files);
    const candidateCapabilities = collectOrigins(candidateTree.files);
    const added = candidateCapabilities.origins.filter((origin) => !baseCapabilities.origins.includes(origin));
    const removed = baseCapabilities.origins.filter((origin) => !candidateCapabilities.origins.includes(origin));
    const capabilityChanged = added.length > 0 || removed.length > 0;
    const analysisComplete = baseCapabilities.complete && candidateCapabilities.complete && !diffTruncated;
    const verdict = capabilityChanged ? 'CAPABILITY_CHANGED' : 'INCONCLUSIVE';
    return {
      verdict,
      skill_name: candidateManifest.skill_name,
      base_digest: baseTree.digest,
      candidate_digest: candidateTree.digest,
      content_changed: true,
      base_approval: 'approved-exact-digest',
      candidate_approval: candidateApproved ? 'approved-exact-digest' : 'not-approved',
      review_required: !candidateApproved,
      capability_evidence: {
        profile: 'mago.network-origin-scan/v1',
        status: capabilityChanged ? 'observed-change' : analysisComplete ? 'no-detected-delta' : 'incomplete',
        analysis_complete: analysisComplete,
        added_network_origins: added,
        removed_network_origins: removed,
        note: 'Partial text evidence only; no detected capability delta does not approve changed content or establish safety.',
      },
      diff_truncated: diffTruncated,
      files: boundedChanges,
    };
  }

  if (!contentChanged && sameName && baseApproved && candidateApproved) {
    return {
      verdict: 'VERIFIED_UNCHANGED',
      skill_name: candidateManifest.skill_name,
      base_digest: baseTree.digest,
      candidate_digest: candidateTree.digest,
      content_changed: false,
      base_approval: 'approved-exact-digest',
      candidate_approval: 'approved-exact-digest',
      review_required: false,
      capability_evidence: {
        profile: 'mago.network-origin-scan/v1',
        status: 'not-needed-identical-bytes',
        analysis_complete: true,
        added_network_origins: [],
        removed_network_origins: [],
        note: 'The covered directory bytes exactly match an explicitly approved digest; this is integrity evidence, not a safety assessment.',
      },
      diff_truncated: false,
      files: [],
    };
  }

  const reasons = [];
  if (!sameName) reasons.push('skill-name-changed');
  if (!baseApproved) reasons.push('base-digest-not-approved');
  if (!contentChanged && !candidateApproved) reasons.push('same-bytes-without-exact-approval');
  return {
    verdict: 'INCONCLUSIVE',
    skill_name: candidateManifest.skill_name,
    base_digest: baseTree.digest,
    candidate_digest: candidateTree.digest,
    content_changed: contentChanged,
    base_approval: baseApproved ? 'approved-exact-digest' : 'not-approved',
    candidate_approval: candidateApproved ? 'approved-exact-digest' : 'not-approved',
    review_required: !candidateApproved || !sameName,
    reasons,
    capability_evidence: {
      profile: 'mago.network-origin-scan/v1',
      status: 'not-evaluated-without-an-approved-base',
      analysis_complete: false,
      added_network_origins: [],
      removed_network_origins: [],
      note: 'A comparison without an exact approved base is inconclusive; no detected capability delta does not approve changed content or establish safety.',
    },
    diff_truncated: diffTruncated,
    files: boundedChanges,
  };
}
