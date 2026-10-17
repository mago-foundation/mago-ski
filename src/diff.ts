import { collectSkillTree, compareTreePaths, type TreeFile } from './tree-digest.ts';

const textDecoder = new TextDecoder('utf-8', { fatal: true });
const MAX_ANALYZED_TEXT_BYTES = 2 * 1024 * 1024;
const MAX_REPORTED_FILES = 200;
const MAX_REPORTED_SECTIONS = 32;
const MAX_INDEXED_SECTIONS = 4_096;
const MAX_ORIGINS = 128;
const MAX_HEADING_LEVEL = 6;

const LABEL_DOCUMENT_BODY = '(document body)';
const LABEL_EMPTY_HEADING = '(empty heading)';
const LABEL_FILE_ADDED = '(file added)';
const LABEL_FILE_REMOVED = '(file removed)';
const LABEL_WHOLE_FILE = '(whole file)';
const LABEL_SIZE_LIMIT = '(whole file; size limit)';
const LABEL_NON_TEXT = '(whole file; non-text content)';
const LABEL_EXEC_BIT = '(executable bit)';

const urlPattern = /https?:\/\/[^\s"'`<>()[\]{}]+/giu;
const fenceOpenPattern = /^ {0,3}(`{3,}|~{3,})/u;
const atxHeadingPattern = /^ {0,3}(#{1,6})[ \t]+(.+?)\s*#*\s*$/u;
const linePattern = /[^\r\n]*(?:\r?\n|$)/gu;
const crlfPattern = /\r\n/gu;

interface MarkdownSection {
  level: number;
  title: string;
  content: string;
}

interface IndexedSection {
  label: string;
  content: string;
}

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

function collectOrigins(contents: Map<string, Buffer>): { 
  origins: string[]; 
  complete: boolean 
} {
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
        if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') 
          continue;
        
        const origin = parsed.origin.toLowerCase();
        if (origins.has(origin)) 
          continue;
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
  return { 
    origins: [...origins].sort(), 
    complete 
  };
}

/* ********************************************  */
/*               Markdown Parsing                */
/* ********************************************  */
function markdownSections(input: Uint8Array | string): MarkdownSection[] | null {
  const sections: MarkdownSection[] = [];
  let text: string;
  let currentLevel = 0;
  let currentTitle = '';
  let sectionStart = 0;
  let activeFence: { char: string; minLength: number } | null = null;

  if (typeof input === 'string') {
    text = input;
  } else {
    try {
      text = textDecoder.decode(input);
    } catch {
      return null;
    }
  }

  linePattern.lastIndex = 0;

  while (linePattern.lastIndex < text.length) {
    const lineStart = linePattern.lastIndex;
    const match = linePattern.exec(text);
    if (!match || match[0].length === 0) {
      break;
    }

    const line = match[0].replace(/\r?\n$/u, '');

    // 1. Track fenced code blocks (``` or ~~~) so '#' comments inside code are never mistaken for headings.
    if (activeFence !== null) {
      const trimmed = line.replace(/^ {0,3}/u, '');
      if (
        trimmed.startsWith(activeFence.char.repeat(activeFence.minLength)) &&
        new RegExp(`^${activeFence.char}+\\s*$`, 'u').test(trimmed)
      ) {
        activeFence = null;
      }
      continue;
    }

    const fenceMatch = fenceOpenPattern.exec(line);
    if (fenceMatch) {
      const fenceToken = fenceMatch[1]!;
      // In CommonMark, backtick info strings cannot contain backticks (inline code on one line).
      if (fenceToken[0] !== '`' || !line.slice(fenceMatch[0].length).includes('`')) {
        activeFence = { char: fenceToken[0]!, minLength: fenceToken.length };
        continue;
      }
    }

    // 2. Outside code blocks, check for ATX headings (# through ######).
    const headingMatch = atxHeadingPattern.exec(line);
    if (!headingMatch) {
      continue;
    }

    if (lineStart > sectionStart || currentLevel > 0) {
      sections.push({
        level: currentLevel,
        title: currentTitle,
        content: text.slice(sectionStart, lineStart),
      });
    }

    currentLevel = headingMatch[1]!.length;
    currentTitle = headingMatch[2]!.trim();
    sectionStart = lineStart;
  }

  if (text.length > sectionStart || currentLevel > 0) {
    sections.push({
      level: currentLevel,
      title: currentTitle,
      content: text.slice(sectionStart),
    });
  }

  return sections;
}

function clampHeadingLevel(level: number): number {
  if (!Number.isFinite(level) || level <= 0) {
    return 0;
  }
  return Math.min(MAX_HEADING_LEVEL, Math.floor(level));
}

function formatSectionLabel(section: MarkdownSection, occurrence: number): string {
  const safeLevel = clampHeadingLevel(section.level);
  const safeTitle = section.title.trim() || LABEL_EMPTY_HEADING;
  const baseLabel =
    safeLevel === 0
      ? LABEL_DOCUMENT_BODY
      : `${'#'.repeat(safeLevel)} ${safeTitle}`;

  return !Number.isFinite(occurrence) || occurrence <= 1
    ? baseLabel
    : `${baseLabel} (${Math.floor(occurrence)})`;
}

/* ********************************************  */
/*               Section Indexing                */
/* ********************************************  */
function indexSectionsByKey(
  sections: readonly MarkdownSection[],
): { indexed: Map<string, IndexedSection>; truncated: boolean } {
  const indexed = new Map<string, IndexedSection>();
  const counts = new Map<string, number>();
  let truncated = false;

  if (!Array.isArray(sections)) {
    return { indexed, truncated };
  }

  for (const section of sections) {
    if (!section || typeof section !== 'object') {
      continue;
    }

    if (indexed.size >= MAX_INDEXED_SECTIONS) {
      truncated = true;
      break;
    }

    const safeLevel = clampHeadingLevel(section.level);
    const rawTitle = typeof section.title === 'string' ? section.title : '';
    const rawContent = typeof section.content === 'string' ? section.content : '';
    const safeTitle = rawTitle.trim().normalize('NFC');

    // Length-prefixed key prevents delimiter collision even if the title contains NUL or special characters.
    const baseKey = `${safeLevel}:${safeTitle.length}:${safeTitle}`;
    const occurrence = (counts.get(baseKey) ?? 0) + 1;
    counts.set(baseKey, occurrence);

    const uniqueKey = `${occurrence}:${baseKey}`;
    indexed.set(uniqueKey, {
      label: formatSectionLabel({ level: safeLevel, title: safeTitle, content: rawContent }, occurrence),
      content: rawContent.replace(crlfPattern, '\n'),
    });
  }

  return { indexed, truncated };
}

function changedSections(
  filePath: string,
  before?: Uint8Array,
  after?: Uint8Array,
): { sections: string[]; truncated: boolean } {
  if (!before || !after)
    return { sections: [before ? LABEL_FILE_REMOVED : LABEL_FILE_ADDED], truncated: false };

  if (Buffer.compare(before, after) === 0)
    return { sections: [], truncated: false };

  if (!/\.md$/iu.test(filePath))
    return { sections: [LABEL_WHOLE_FILE], truncated: false };

  if (before.byteLength > MAX_ANALYZED_TEXT_BYTES || after.byteLength > MAX_ANALYZED_TEXT_BYTES)
    return { sections: [LABEL_SIZE_LIMIT], truncated: true };

  const beforeParsed = markdownSections(before);
  const afterParsed = markdownSections(after);
  if (!beforeParsed || !afterParsed)
    return { sections: [LABEL_NON_TEXT], truncated: false };

  const beforeResult = indexSectionsByKey(beforeParsed);
  const afterResult = indexSectionsByKey(afterParsed);
  const beforeMap = beforeResult.indexed;
  const afterMap = afterResult.indexed;
  const allKeys = new Set([...beforeMap.keys(), ...afterMap.keys()]);

  const changed: string[] = [];
  for (const key of allKeys) {
    const beforeEntry = beforeMap.get(key);
    const afterEntry = afterMap.get(key);
    if (beforeEntry?.content !== afterEntry?.content) {
      changed.push((afterEntry ?? beforeEntry)!.label);
    }
  }

  // If bytes differed (e.g. CRLF vs LF) while normalized section contents matched, still report whole-file change.
  if (changed.length === 0) {
    return {
      sections: [LABEL_WHOLE_FILE],
      truncated: beforeResult.truncated || afterResult.truncated,
    };
  }

  changed.sort();
  return {
    sections: changed.slice(0, MAX_REPORTED_SECTIONS),
    truncated:
      beforeResult.truncated ||
      afterResult.truncated ||
      changed.length > MAX_REPORTED_SECTIONS,
  };
}


function classifyFileChange(before?: TreeFile, after?: TreeFile): FileChange['change'] {
  if (!before) {
    return 'added';
  }
  if (!after) {
    return 'deleted';
  }
  if (before.sha256 === after.sha256) {
    return 'mode-changed';
  }
  return 'modified';
}

function fileChanges(
  beforeFiles: readonly TreeFile[],
  afterFiles: readonly TreeFile[],
  beforeContents: ReadonlyMap<string, Uint8Array>,
  afterContents: ReadonlyMap<string, Uint8Array>,
): { files: FileChange[]; truncated: boolean } {
  const beforeByPath = new Map<string, TreeFile>();
  const afterByPath = new Map<string, TreeFile>();
  const pathSet = new Set<string>();
  const files: FileChange[] = [];
  let truncated = false;

  for (const file of beforeFiles) {
    beforeByPath.set(file.path, file);
    pathSet.add(file.path);
  }
  for (const file of afterFiles) {
    afterByPath.set(file.path, file);
    pathSet.add(file.path);
  }

  const sortedPaths = [...pathSet].sort(compareTreePaths);

  for (const filePath of sortedPaths) {
    const before = beforeByPath.get(filePath);
    const after = afterByPath.get(filePath);

    if (
      before &&
      after &&
      before.sha256 === after.sha256 &&
      before.size === after.size &&
      before.exec === after.exec
    ) {
      continue;
    }

    // Stop expensive Markdown section diffing once the reported file budget is reached.
    if (files.length >= MAX_REPORTED_FILES) {
      truncated = true;
      break;
    }

    const change = classifyFileChange(before, after);
    const sectionDiff =
      change === 'mode-changed'
        ? { sections: [LABEL_EXEC_BIT], truncated: false }
        : changedSections(filePath, beforeContents.get(filePath), afterContents.get(filePath));

    if (sectionDiff.truncated) {
      truncated = true;
    }

    files.push({
      path: filePath,
      change,
      before_bytes: before?.size ?? 0,
      after_bytes: after?.size ?? 0,
      exec_before: before?.exec ?? null,
      exec_after: after?.exec ?? null,
      changed_sections: sectionDiff.sections,
      sections_truncated: sectionDiff.truncated,
    });
  }

  return { files, truncated };
}

/**
 * Compares two Skill directories. Any digest difference requires a new certificate,
 * whatever the capability evidence says: unchanged origins never waive a content change.
 */
export async function diffSkillTrees(baseRoot: string, candidateRoot: string): Promise<DiffResult> {
  const base = await collectSkillTree(baseRoot, { includeContents: true });
  const candidate = await collectSkillTree(candidateRoot, { includeContents: true });
  const changed = base.digest !== candidate.digest;
  const diff = changed
    ? fileChanges(base.files, candidate.files, base.contents!, candidate.contents!)
    : { files: [], truncated: false };
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
      analysis_complete: baseOrigins.complete && candidateOrigins.complete && !diff.truncated,
      added_network_origins: added,
      removed_network_origins: removed,
      note: 'Partial evidence: only HTTP(S) origins in text files are detected. No detected change does not make changed content safe or approved.',
    },
    diff_truncated: diff.truncated,
    files: diff.files,
  };
}
