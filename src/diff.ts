import { collectSkillTree, type TreeFile } from './tree-digest.ts';

const textDecoder = new TextDecoder('utf-8', { fatal: true });
const MAX_ANALYZED_TEXT_BYTES = 2 * 1024 * 1024;
const MAX_REPORTED_FILES = 200;
const MAX_REPORTED_SECTIONS = 32;
const MAX_ORIGINS = 128;
const urlPattern = /https?:\/\/[^\s"'`<>()[\]{}]+/giu;

export interface FileChange {
  path: string;
  change: 'added' | 'deleted' | 'modified' | 'mode-changed';
  before_bytes: number;
  after_bytes: number;
  exec_before: boolean | null;
  exec_after: boolean | null;
  changed_sections: string[];
  sections_truncated: boolean;
}

export interface DiffResult {
  result: 'UNCHANGED' | 'CAPABILITY_CHANGED' | 'CONTENT_CHANGED';
  recertification_required: boolean;
  base_digest: string;
  candidate_digest: string;
  capability_evidence: {
    profile: 'mago.network-origin-scan/v1';
    analysis_complete: boolean;
    added_network_origins: string[];
    removed_network_origins: string[];
    note: string;
  };
  diff_truncated: boolean;
  files: FileChange[];
}

function collectOrigins(contents: Map<string, Buffer>): { origins: string[]; complete: boolean } {
  const origins = new Set<string>();
  let complete = true;
  for (const content of contents.values()) {
    if (content.length > MAX_ANALYZED_TEXT_BYTES || content.includes(0)) {
      complete = false;
      continue;
    }
    let text: string;
    try {
      text = textDecoder.decode(content);
    } catch {
      complete = false;
      continue;
    }
    for (const match of text.matchAll(urlPattern)) {
      try {
        const parsed = new URL(match[0].replace(/[.,;:!?]+$/u, ''));
        if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') continue;
        const origin = parsed.origin.toLowerCase();
        if (origins.has(origin)) continue;
        if (origins.size >= MAX_ORIGINS) {
          complete = false;
          continue;
        }
        origins.add(origin);
      } catch {
        // URL-like text that does not parse is not capability evidence.
      }
    }
  }
  return { origins: [...origins].sort(), complete };
}

function markdownSections(content: Buffer): Map<string, string> | null {
  let text: string;
  try {
    text = textDecoder.decode(content);
  } catch {
    return null;
  }
  const sections = new Map<string, string>();
  const occurrence = new Map<string, number>();
  let current = '(document body)';
  let body: string[] = [];
  const flush = () => sections.set(current, body.join('\n'));
  for (const line of text.split(/\r?\n/u)) {
    const heading = /^(#{1,6})[ \t]+(.+?)\s*#*\s*$/u.exec(line);
    if (heading) {
      flush();
      const label = heading[2]!.trim() || '(empty heading)';
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

function changedSections(filePath: string, before?: Buffer, after?: Buffer): { sections: string[]; truncated: boolean } {
  if (!before || !after) return { sections: [before ? '(file removed)' : '(file added)'], truncated: false };
  if (before.equals(after)) return { sections: [], truncated: false };
  if (!/\.md$/iu.test(filePath)) return { sections: ['(whole file)'], truncated: false };
  if (before.length > MAX_ANALYZED_TEXT_BYTES || after.length > MAX_ANALYZED_TEXT_BYTES) return { sections: ['(whole file; size limit)'], truncated: true };
  const beforeSections = markdownSections(before);
  const afterSections = markdownSections(after);
  if (!beforeSections || !afterSections) return { sections: ['(whole file; non-text content)'], truncated: false };
  const names = new Set([...beforeSections.keys(), ...afterSections.keys()]);
  const changed = [...names].filter((name) => beforeSections.get(name) !== afterSections.get(name)).sort();
  return { sections: changed.slice(0, MAX_REPORTED_SECTIONS), truncated: changed.length > MAX_REPORTED_SECTIONS };
}

function fileChanges(beforeFiles: TreeFile[], afterFiles: TreeFile[], beforeContents: Map<string, Buffer>, afterContents: Map<string, Buffer>): FileChange[] {
  const beforeByPath = new Map(beforeFiles.map((file) => [file.path, file]));
  const afterByPath = new Map(afterFiles.map((file) => [file.path, file]));
  const paths = [...new Set([...beforeByPath.keys(), ...afterByPath.keys()])].sort();
  const changes: FileChange[] = [];
  for (const filePath of paths) {
    const before = beforeByPath.get(filePath);
    const after = afterByPath.get(filePath);
    if (before && after && before.sha256 === after.sha256 && before.exec === after.exec) continue;
    const change: FileChange['change'] = !before ? 'added' : !after ? 'deleted' : before.sha256 === after.sha256 ? 'mode-changed' : 'modified';
    const sections = changedSections(filePath, beforeContents.get(filePath), afterContents.get(filePath));
    changes.push({
      path: filePath,
      change,
      before_bytes: before?.size ?? 0,
      after_bytes: after?.size ?? 0,
      exec_before: before?.exec ?? null,
      exec_after: after?.exec ?? null,
      changed_sections: change === 'mode-changed' ? ['(executable bit)'] : sections.sections,
      sections_truncated: sections.truncated,
    });
  }
  return changes;
}

/**
 * Compares two Skill directories. Any digest difference requires a new certificate,
 * whatever the capability evidence says: unchanged origins never waive a content change.
 */
export async function diffSkillTrees(baseRoot: string, candidateRoot: string): Promise<DiffResult> {
  const base = await collectSkillTree(baseRoot, { includeContents: true });
  const candidate = await collectSkillTree(candidateRoot, { includeContents: true });
  const changed = base.digest !== candidate.digest;
  const changes = changed ? fileChanges(base.files, candidate.files, base.contents!, candidate.contents!) : [];
  const bounded = changes.slice(0, MAX_REPORTED_FILES);
  const truncated = changes.length > MAX_REPORTED_FILES || bounded.some((entry) => entry.sections_truncated);
  const baseOrigins = collectOrigins(base.contents!);
  const candidateOrigins = collectOrigins(candidate.contents!);
  const added = candidateOrigins.origins.filter((origin) => !baseOrigins.origins.includes(origin));
  const removed = baseOrigins.origins.filter((origin) => !candidateOrigins.origins.includes(origin));
  const capabilityChanged = added.length > 0 || removed.length > 0;
  return {
    result: !changed ? 'UNCHANGED' : capabilityChanged ? 'CAPABILITY_CHANGED' : 'CONTENT_CHANGED',
    recertification_required: changed,
    base_digest: base.digest,
    candidate_digest: candidate.digest,
    capability_evidence: {
      profile: 'mago.network-origin-scan/v1',
      analysis_complete: baseOrigins.complete && candidateOrigins.complete && !truncated,
      added_network_origins: added,
      removed_network_origins: removed,
      note: 'Partial evidence: only HTTP(S) origins in text files are detected. No detected change does not make changed content safe or approved.',
    },
    diff_truncated: truncated,
    files: bounded,
  };
}
