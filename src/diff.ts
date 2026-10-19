import { collectSkillTree, compareTreePaths, sha256Hex, type TreeFile } from './tree-digest.ts';

const textDecoder = new TextDecoder('utf-8', { fatal: true });
const MAX_ANALYZED_TEXT_BYTES = 2 * 1024 * 1024;

/** Before + after bytes, summed over every file: per-file limits alone allow ~500 MiB of parsing. */
const MAX_SECTION_DIFF_BYTES = 16 * 1024 * 1024;
const MAX_REPORTED_FILES = 200;
const MAX_REPORTED_SECTIONS = 32;
const MAX_INDEXED_SECTIONS = 4_096;
const MAX_ORIGINS = 128;

/** Per tree. Each candidate costs a URL parse, and a 256 MiB tree can hold tens of millions. */
const MAX_URL_CANDIDATES = 100_000;

/** "https://", a 254-char DNS name (trailing dot included), ":65535". The URL parser accepts longer hosts. */
const MAX_ORIGIN_CHARS = 8 + 254 + 6;
const MAX_HEADING_LEVEL = 6;

/** One Markdown line can be megabytes long; reported labels must not be. */
const MAX_LABEL_TITLE_CHARS = 200;

const LABEL_DOCUMENT_BODY = '(document body)';
const LABEL_EMPTY_HEADING = '(empty heading)';
const LABEL_FILE_ADDED = '(file added)';
const LABEL_FILE_REMOVED = '(file removed)';
const LABEL_WHOLE_FILE = '(whole file)';
const LABEL_SIZE_LIMIT = '(whole file; size limit)';
const LABEL_TOTAL_SIZE_LIMIT = '(whole file; total size limit)';
const LABEL_NON_TEXT = '(whole file; non-text content)';
const LABEL_EXEC_BIT = '(executable bit)';

// Every pattern below runs on untrusted Skill content: keep each one free of overlapping quantifiers.
const urlPattern = /https?:\/\/[^\s"'`<>()[\]{}]+/giu;
const trailingPunctuation = '.,;:!?';
const fenceOpenPattern = /^ {0,3}(`{3,}|~{3,})/u;
const fenceClosePattern = /^ {0,3}(`{3,}|~{3,})\s*$/u;
const atxOpenPattern = /^ {0,3}(#{1,6})([ \t]+)/u;
const whitespacePattern = /\s/u;

/** What `.` refuses besides CR and LF, which never reach a line. */
const dotExcludedPattern = /[\u2028\u2029]/u;

// Sticky: a failed match must not rescan from every later offset (a lone CR made that quadratic).
const linePattern = /[^\r\n]*(?:\r\n|\r|\n|$)/uy;
const lineEndingPattern = /(?:\r\n|\r|\n)$/u;
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

/** Drops trailing sentence punctuation. A loop, because /[.,;:!?]+$/ backtracks quadratically on a long run. */
function trimTrailingPunctuation(value: string): string {
  let end = value.length;
  while (end > 0 && trailingPunctuation.includes(value[end - 1]!)) {
    end -= 1;
  }
  return value.slice(0, end);
}

function collectOrigins(contents: Map<string, Buffer>): {
  origins: string[];
  complete: boolean
} {
  const origins = new Set<string>();
  let complete = true;
  let candidates = 0;
  scan: for (const content of contents.values()) {
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
      candidates += 1;
      if (candidates > MAX_URL_CANDIDATES) {
        complete = false;
        break scan;
      }

      let origin: string;
      try {
        const parsed = new URL(trimTrailingPunctuation(match[0]));
        if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:')
          continue;
        origin = parsed.origin.toLowerCase();
      } catch {
        // URL-like text that does not parse is not capability evidence.
        continue;
      }

      // No DNS name resolves past this length, and one such origin could be megabytes of report.
      if (origin.length > MAX_ORIGIN_CHARS) {
        complete = false;
        continue;
      }

      if (origins.has(origin))
        continue;
      // A full set cannot change any more, so scanning on would only burn CPU.
      if (origins.size >= MAX_ORIGINS) {
        complete = false;
        break scan;
      }

      origins.add(origin);
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

/**
 * Linear-time equivalent of /^ {0,3}(#{1,6})[ \t]+(.+?)\s*#*\s*$/u. That regex lets its lazy title
 * overlap the optional closing sequence, and backtracks cubically on a long run of blanks.
 */
function atxHeading(line: string): { level: number; title: string } | null {
  const open = atxOpenPattern.exec(line);
  if (!open)
    return null;

  const level = open[1]!.length;
  const spacing = open[2]!.length;
  const rest = line.slice(open[0].length);

  // Start of the longest suffix matching \s*#*\s*: the closing sequence the title leaves out.
  let end = rest.length;
  while (end > 0 && whitespacePattern.test(rest[end - 1]!)) end -= 1;
  while (end > 0 && rest[end - 1] === '#') end -= 1;
  while (end > 0 && whitespacePattern.test(rest[end - 1]!)) end -= 1;

  // The title needs one character `.` accepts; failing that, the regex borrows one blank from the spacing.
  if (end === 0 && (rest === '' || dotExcludedPattern.test(rest[0]!))) {
    return spacing >= 2 ? { level, title: '' } : null;
  }
  const title = rest.slice(0, Math.max(1, end));

  return dotExcludedPattern.test(title) ? null : { level, title: title.trim() };
}

function markdownSections(input: Uint8Array | string): MarkdownSection[] | null {
  const sections: MarkdownSection[] = [];
  let text: string;
  let currentLevel = 0;
  let currentTitle = '';
  let sectionStart = 0;
  let activeFence: { char: string; minLength: number } | null = null;

  if (typeof input === 'string')
    text = input;
  
  else {
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
    
    if (!match || match[0].length === 0)
      break;

    const line = match[0].replace(lineEndingPattern, '');

    // 1. Track fenced code blocks (``` or ~~~) so '#' comments inside code are never mistaken for headings.
    if (activeFence !== null) {
      const close = fenceClosePattern.exec(line);
      if (close && close[1]![0] === activeFence.char && close[1]!.length >= activeFence.minLength) {
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
    const heading = atxHeading(line);
    if (!heading) {
      continue;
    }

    if (lineStart > sectionStart || currentLevel > 0) {
      sections.push({
        level: currentLevel,
        title: currentTitle,
        content: text.slice(sectionStart, lineStart),
      });
      // indexSectionsByKey keeps only MAX_INDEXED_SECTIONS; one more is enough for it to report truncation.
      if (sections.length > MAX_INDEXED_SECTIONS) {
        return sections;
      }
    }

    currentLevel = heading.level;
    currentTitle = heading.title;
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

function truncateTitle(title: string): string {
  if (title.length <= MAX_LABEL_TITLE_CHARS) {
    return title;
  }
  let end = MAX_LABEL_TITLE_CHARS;
  const last = title.charCodeAt(end - 1);
  // Never split a surrogate pair.
  if (last >= 0xd800 && last <= 0xdbff) {
    end -= 1;
  }
  return `${title.slice(0, end)}...`;
}

function formatSectionLabel(section: MarkdownSection, occurrence: number): string {
  const safeLevel = clampHeadingLevel(section.level);
  const safeTitle = truncateTitle(section.title.trim()) || LABEL_EMPTY_HEADING;
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
    if (!section || typeof section !== 'object')
      continue;

    if (indexed.size >= MAX_INDEXED_SECTIONS) {
      truncated = true;
      break;
    }

    const safeLevel = clampHeadingLevel(section.level);
    const rawTitle = typeof section.title === 'string' ? section.title : '';
    const rawContent = typeof section.content === 'string' ? section.content : '';
    const safeTitle = rawTitle.trim().normalize('NFC');

    // A fixed-size key: V8 hashes strings over 16,383 chars by length alone, so raw long titles would all
    // land in one Map bucket. The hex digest also has no delimiter for a crafted title to collide with.
    const baseKey = `${safeLevel}:${sha256Hex(Buffer.from(safeTitle, 'utf8'))}`;
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
  before: Uint8Array | undefined,
  after: Uint8Array | undefined,
  budget: { remainingBytes: number },
): { sections: string[]; truncated: boolean } {
  if (!before || !after)
    return { sections: [before ? LABEL_FILE_REMOVED : LABEL_FILE_ADDED], truncated: false };

  if (Buffer.compare(before, after) === 0)
    return { sections: [], truncated: false };

  if (!/\.md$/iu.test(filePath))
    return { sections: [LABEL_WHOLE_FILE], truncated: false };

  if (before.byteLength > MAX_ANALYZED_TEXT_BYTES || after.byteLength > MAX_ANALYZED_TEXT_BYTES)
    return { sections: [LABEL_SIZE_LIMIT], truncated: true };

  const cost = before.byteLength + after.byteLength;
  if (cost > budget.remainingBytes)
    return { sections: [LABEL_TOTAL_SIZE_LIMIT], truncated: true };
  budget.remainingBytes -= cost;

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
  const sectionBudget = { remainingBytes: MAX_SECTION_DIFF_BYTES };
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
        : changedSections(filePath, beforeContents.get(filePath), afterContents.get(filePath), sectionBudget);

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

/*
 * Compares two Skill directories. Any digest difference requires a new certificate,
 * whatever the capability evidence says: unchanged origins never waive a content change.
 */
export async function diffSkillTrees(baseRoot: string, candidateRoot: string): Promise<DiffResult> {
  const base                = await collectSkillTree(baseRoot, { includeContents: true });
  const candidate           = await collectSkillTree(candidateRoot, { includeContents: true });
  const changed             = base.digest !== candidate.digest;
  const diff                = changed
    ? fileChanges(base.files, candidate.files, base.contents!, candidate.contents!)
    : { files: [], truncated: false };
  const baseOrigins         = collectOrigins(base.contents!);
  // Equal digests mean equal contents: a second scan could only repeat the first.
  const candidateOrigins    = changed ? collectOrigins(candidate.contents!) : baseOrigins;
  const baseOriginSet       = new Set(baseOrigins.origins);
  const candidateOriginSet  = new Set(candidateOrigins.origins);
  const added               = candidateOrigins.origins.filter((origin) => !baseOriginSet.has(origin));
  const removed             = baseOrigins.origins.filter((origin) => !candidateOriginSet.has(origin));
  const capabilityChanged   = added.length > 0 || removed.length > 0;
  
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
