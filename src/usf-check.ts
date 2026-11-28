// The free Skill check: compares what a Skill declares in its OWASP USF manifest with what its files contain.
// Deterministic and offline. Nothing from the Skill is executed. Two things fail the check: a web address whose
// host is not in `permissions.network.allow`, and scripts or shell code while `permissions.shell` is not true.
import { isUtf8 } from 'node:buffer';
import path from 'node:path';
import { collectOrigins } from './diff.ts';
import { collectSkillTree, pathsNotCovered, SKILL_FILENAME } from './tree-digest.ts';
import { hostAllowed, parseUsfManifest, USF_FORMAT, UsfError, type UsfManifest } from './usf.ts';

/** Same limit as the origin scan in diff.ts: larger files are not read for web addresses. */
const MAX_SCANNED_TEXT_BYTES = 2 * 1024 * 1024;

const SCRIPT_EXTENSIONS = new Set(['.sh', '.bash', '.zsh', '.fish', '.ksh', '.py', '.js', '.mjs', '.cjs', '.ts', '.mts', '.cts', '.rb', '.pl', '.php', '.lua', '.ps1', '.psm1', '.bat', '.cmd',
  '.go', '.rs', '.java', '.kt', '.kts', '.swift', '.c', '.cc', '.cpp', '.cs', '.vbs', '.awk', '.tcl', '.r', '.jl', '.ex', '.exs', '.groovy', '.scala', '.applescript', '.scpt', '.jar', '.wasm', '.exe', '.dll', '.so', '.dylib']);
const SCRIPT_NAMES = new Set(['makefile', 'gnumakefile', 'justfile', 'rakefile', 'dockerfile', 'containerfile']);
/** Binary formats that hold no instructions or code for an agent; everything else that cannot be searched fails. */
const MEDIA_EXTENSIONS = new Set(['.png', '.jpg', '.jpeg', '.gif', '.webp', '.avif', '.bmp', '.ico', '.tif', '.tiff', '.heic', '.woff', '.woff2', '.ttf', '.otf', '.eot', '.mp3', '.wav', '.ogg', '.flac', '.m4a', '.mp4', '.webm', '.mov']);
const MARKDOWN_EXTENSIONS = new Set(['.md', '.markdown', '.mdx']);
const SHELL_FENCE_LANGUAGES = new Set(['sh', 'bash', 'shell', 'zsh', 'fish', 'ksh', 'console', 'shell-session', 'shellsession', 'terminal', 'powershell', 'ps1', 'pwsh', 'cmd', 'bat', 'batch', 'shellscript', 'sh-session', 'nushell', 'nu']);
// Any indentation and blockquote markers, then the fence, then `bash`, `{bash}` or `{.bash ...}`.
const fenceOpenPattern = /^[ \t>]*(?:`{3,}|~{3,})[ \t]*\{?\.?([A-Za-z0-9_+-]*)/u;

export interface ScriptEvidence { path: string; reason: string }

export interface SkillCheck {
  format: typeof USF_FORMAT;
  /** Directory relative to the checked root. */
  dir: string;
  ok: boolean;
  manifest: UsfManifest | null;
  manifestError: string | null;
  /** Host names found in web addresses in the Skill's files. */
  usedHosts: string[];
  undeclaredHosts: string[];
  scripts: ScriptEvidence[];
  /** Plain-word reasons the check failed; empty when it passed. */
  problems: string[];
  /** Plain-word remarks that do not fail the check. */
  notes: string[];
}

/**
 * Counts lines that open a shell code block. No open/close tracking on purpose: a fence that a reader would treat as
 * inert text can still be counted (stricter), but a crafted pairing can never hide a later shell block.
 */
function shellFences(text: string): number {
  let count = 0;
  for (const line of text.split(/\r?\n|\r/u)) {
    const match = fenceOpenPattern.exec(line);
    if (match && SHELL_FENCE_LANGUAGES.has(match[1]!.toLowerCase())) count += 1;
  }
  return count;
}

function scriptEvidence(file: string, exec: boolean, content: Buffer): string | null {
  if (exec) return 'executable file';
  if (content.subarray(0, 2).toString('latin1') === '#!') return 'starts with #!';
  const extension = path.posix.extname(file).toLowerCase();
  if (SCRIPT_EXTENSIONS.has(extension)) return `${extension} file`;
  if (SCRIPT_NAMES.has(path.posix.basename(file).toLowerCase())) return 'build or task file';
  if (MARKDOWN_EXTENSIONS.has(extension) && content.length <= MAX_SCANNED_TEXT_BYTES && isUtf8(content)) {
    const fences = shellFences(content.toString('utf8'));
    if (fences > 0) return `${fences} shell code block${fences === 1 ? '' : 's'}`;
  }
  return null;
}

function list(values: readonly string[], limit = 10): string {
  const shown = values.slice(0, limit).join(', ');
  return values.length > limit ? `${shown} and ${values.length - limit} more` : shown;
}

/** The `permissions` block a Skill could paste, filled in from what the check found. */
export function suggestedManifest(check: Pick<SkillCheck, 'usedHosts' | 'scripts' | 'manifest'>): string {
  // Host names pass the URL parser, which still allows characters such as backticks; only plain names are suggested.
  const hosts = [...new Set([...(check.manifest?.network.allow ?? []), ...check.usedHosts])].filter((host) => /^(?:\*|(?:\*\.)?[a-z0-9.-]+|\[[0-9a-f:.]+\])$/u.test(host)).sort();
  const shell = check.manifest?.shell === true || check.scripts.length > 0;
  return [
    'permissions:',
    '  network:',
    `    allow: [${hosts.map((host) => JSON.stringify(host)).join(', ')}]`,
    '    deny: "*"',
    `  shell: ${shell}`,
  ].join('\n');
}

export async function checkSkill(skillDir: string, root: string): Promise<SkillCheck> {
  const dir = path.relative(root, skillDir) || '.';
  const result: SkillCheck = {
    format: USF_FORMAT, dir, ok: false, manifest: null, manifestError: null, usedHosts: [], undeclaredHosts: [], scripts: [], problems: [], notes: [],
  };
  let tree;
  try {
    tree = await collectSkillTree(skillDir, { includeContents: true });
  } catch (error) {
    result.problems.push(`the Skill folder could not be read: ${(error as Error).message}`);
    return result;
  }
  const contents = tree.contents!;

  try {
    result.manifest = parseUsfManifest(contents.get(SKILL_FILENAME)!.toString('utf8'));
  } catch (error) {
    if (!(error instanceof UsfError)) throw error;
    result.manifestError = error.message;
    result.problems.push(`the USF manifest in ${SKILL_FILENAME} could not be read: ${error.message}`);
  }
  if (!isUtf8(contents.get(SKILL_FILENAME)!)) result.problems.push(`${SKILL_FILENAME} is not valid UTF-8 text`);

  const origins = collectOrigins(contents);
  result.usedHosts = [...new Set(origins.origins.map((origin) => new URL(origin).hostname))].sort();
  const unscanned = tree.files
    .filter((file) => { const content = contents.get(file.path)!; return content.length > MAX_SCANNED_TEXT_BYTES || content.includes(0) || !isUtf8(content); })
    .map((file) => file.path);
  const media = unscanned.filter((file) => MEDIA_EXTENSIONS.has(path.posix.extname(file).toLowerCase()));
  const hidden = unscanned.filter((file) => !MEDIA_EXTENSIONS.has(path.posix.extname(file).toLowerCase()));
  if (!origins.complete && unscanned.length === 0)
    result.problems.push('the Skill holds too many web addresses to check them all (more than 128 different sites, or more than 100,000 addresses)');
  if (hidden.length > 0)
    result.problems.push(`files that cannot be searched (binary, not UTF-8 text, or larger than 2 MiB): ${list(hidden)}`);
  if (media.length > 0) result.notes.push(`images, fonts and media files were not searched: ${list(media)}`);
  // .skilldigestignore is the author's own file; letting it hide files would let any Skill pass.
  const notCovered = pathsNotCovered(tree.excluded);
  if (notCovered.length > 0) result.problems.push(`files left out by .skilldigestignore cannot be checked: ${list(notCovered)}`);

  for (const file of tree.files) {
    const reason = scriptEvidence(file.path, file.exec, contents.get(file.path)!);
    if (reason) result.scripts.push({ path: file.path, reason });
  }

  const manifest = result.manifest;
  if (manifest === null && result.manifestError === null) {
    result.problems.push(`${SKILL_FILENAME} has no USF "permissions" block, so there is nothing to compare its files with`);
  }
  if (manifest) {
    result.undeclaredHosts = result.usedHosts.filter((host) => !hostAllowed(manifest.network.allow, host));
    if (result.undeclaredHosts.length > 0)
      result.problems.push(`uses web addresses on sites it does not declare in permissions.network.allow: ${list(result.undeclaredHosts)}`);
    if (manifest.shell !== true && result.scripts.length > 0)
      result.problems.push(`contains scripts or shell commands, but permissions.shell is ${manifest.shell === false ? 'false' : 'not set'}: ${list(result.scripts.map((script) => `${script.path} (${script.reason})`), 5)}`);
    if (manifest.network.allow.includes('*')) result.notes.push('declares that it may contact any website (network.allow: "*")');
    if (manifest.network.deny !== null && manifest.network.deny !== '*') result.notes.push(`network.deny is "${manifest.network.deny}"; USF expects "*"`);
    if (manifest.unknownKeys.length > 0) result.notes.push(`keys this check does not know were not checked: ${list(manifest.unknownKeys)}`);
  }
  result.ok = result.problems.length === 0;
  return result;
}

/** What a pull request adds to a Skill, in plain words, compared with the base revision. */
export function describeAdditions(base: SkillCheck | null, head: SkillCheck): string[] {
  if (base === null) return ['adds this Skill'];
  const added = (before: readonly string[], after: readonly string[]) => after.filter((value) => !before.includes(value));
  const lines: string[] = [];
  const before = base.manifest;
  const after = head.manifest;
  const newSites = added(base.usedHosts, head.usedHosts);
  if (newSites.length > 0) lines.push(`uses new websites: ${list(newSites)}`);
  const newAllowed = added(before?.network.allow ?? [], after?.network.allow ?? []);
  if (newAllowed.length > 0) lines.push(`declares permission for new websites: ${list(newAllowed)}`);
  if (before?.shell !== true && after?.shell === true) lines.push('asks for permission to run commands (shell: true)');
  const newScripts = added(base.scripts.map((script) => script.path), head.scripts.map((script) => script.path));
  if (newScripts.length > 0) lines.push(`adds scripts or shell commands: ${list(newScripts)}`);
  const newReads = added(before?.files.read ?? [], after?.files.read ?? []);
  if (newReads.length > 0) lines.push(`asks to read new files: ${list(newReads)}`);
  const newWrites = added(before?.files.write ?? [], after?.files.write ?? []);
  if (newWrites.length > 0) lines.push(`asks to write new files: ${list(newWrites)}`);
  const unprotected = (before?.files.deny_write ?? []).filter((file) => !(after?.files.deny_write ?? []).includes(file));
  if (unprotected.length > 0) lines.push(`no longer protects these files from writes: ${list(unprotected)}`);
  const newTools = added(before?.tools ?? [], after?.tools ?? []);
  if (newTools.length > 0) lines.push(`asks for new tools: ${list(newTools)}`);
  const newBinaries = added(before?.requires.binaries ?? [], after?.requires.binaries ?? []);
  if (newBinaries.length > 0) lines.push(`needs new programs: ${list(newBinaries)}`);
  return lines;
}
