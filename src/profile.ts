// Observed profile (mago.observed-profile/v1): what a Skill's own bytes show, computed deterministically and offline.
// It works on every Skill and never reads the frontmatter, so it cannot be steered by what a Skill says about itself.
// Spec: docs/spec/observed-profile-v1.md. Changing what it extracts needs a new profile version.
import { isUtf8 } from 'node:buffer';
import path from 'node:path';
import { collectOrigins } from './diff.ts';
import { collectSkillTree, pathsNotCovered, type SkillTree } from './tree-digest.ts';

export const PROFILE_FORMAT = 'mago.observed-profile/v1';

/** Same limit as the origin scan in diff.ts: larger files are not searched. */
export const MAX_SEARCHED_BYTES = 2 * 1024 * 1024;
const MAX_PROGRAMS = 200;

const SCRIPT_EXTENSIONS = new Set(['.sh', '.bash', '.zsh', '.fish', '.ksh', '.py', '.js', '.mjs', '.cjs', '.ts', '.mts', '.cts', '.rb', '.pl', '.php', '.lua', '.ps1', '.psm1', '.bat', '.cmd',
  '.go', '.rs', '.java', '.kt', '.kts', '.swift', '.c', '.cc', '.cpp', '.cs', '.vbs', '.awk', '.tcl', '.r', '.jl', '.ex', '.exs', '.groovy', '.scala', '.applescript', '.scpt', '.jar', '.wasm', '.exe', '.dll', '.so', '.dylib']);
const SCRIPT_NAMES = new Set(['makefile', 'gnumakefile', 'justfile', 'rakefile', 'dockerfile', 'containerfile']);
const MARKDOWN_EXTENSIONS = new Set(['.md', '.markdown', '.mdx']);
/** Binary formats that hold no instructions or code for an agent; they are not searched and are not a gap. */
const MEDIA_EXTENSIONS = new Set(['.png', '.jpg', '.jpeg', '.gif', '.webp', '.avif', '.bmp', '.ico', '.tif', '.tiff', '.heic', '.woff', '.woff2', '.ttf', '.otf', '.eot', '.mp3', '.wav', '.ogg', '.flac', '.m4a', '.mp4', '.webm', '.mov']);
/** Shell languages, compared on the info string's first part: `bash-session`, `zsh_session`, `sh+x` count as their shell. */
const SHELL_LANGUAGES = new Set(['sh', 'bash', 'shell', 'zsh', 'fish', 'ksh', 'csh', 'tcsh', 'dash', 'ash', 'console', 'shellsession', 'shellscript', 'terminal', 'powershell', 'ps1', 'pwsh', 'cmd', 'bat', 'batch', 'nushell', 'nu']);
const isShellLanguage = (info: string) => SHELL_LANGUAGES.has(info.toLowerCase().split(/[-_+.:]/u)[0]!);
// Indentation, blockquote markers and list markers (`-`, `*`, `+`, `1.`, `1)`), then the fence, then `bash`, `{bash}` or `{.bash ...}`.
// The three prefix alternatives start with different characters, so the pattern stays linear.
const fenceOpenPattern = /^(?:[ \t>]|[-*+][ \t]|[0-9]{1,9}[.)][ \t])*(`{3,}|~{3,})[ \t]*\{?\.?([A-Za-z0-9_+.:-]*)/u;
/** Bracketed IPv6 hosts, which the shared origin scan in diff.ts does not match. */
const ipv6UrlPattern = /https?:\/\/\[[0-9A-Fa-f:.]{2,45}\](?::[0-9]{1,5})?/gu;
const MAX_IPV6_HOSTS = 128;
// Brackets kept, so a bracketed IPv6 host after a backslash stays in the candidate.
const urlCandidatePattern = /https?:\/\/[^\s"'`<>(){}]+/giu;
const plainHostPattern = /^[a-z0-9-]+(?:\.[a-z0-9-]+)*$/u;

/**
 * The host another URL parser reads from an address with a backslash. WHATWG (used above) treats `\` like `/`, so
 * `https://api.github.com\@evil.example/` is api.github.com there; Python's urlparse and others read evil.example.
 * Both are listed.
 */
function backslashHost(candidate: string): string | null {
  if (!candidate.includes('\\')) return null;
  const rest = candidate.slice(candidate.indexOf('://') + 3);
  const end = rest.search(/[/?#]/u);
  const authority = end < 0 ? rest : rest.slice(0, end);
  let host = authority.slice(authority.lastIndexOf('@') + 1).replace(/:[0-9]*$/u, '');
  try {
    host = decodeURIComponent(host);
  } catch {
    // Not valid percent-encoding: keep the text as it is.
  }
  host = host.toLowerCase().replace(/\.$/u, '');
  if (/^\[[0-9a-f:.]+\]$/u.test(host)) {
    try {
      return new URL(`http://${host}/`).hostname;
    } catch {
      return null;
    }
  }
  return plainHostPattern.test(host) ? host : null;
}
const programPattern = /^[A-Za-z0-9._+-]{1,64}$/u;
const PREFIX_WORDS = new Set(['sudo', 'doas', 'env', 'exec', 'time', 'nohup', 'command', 'builtin', 'then', 'do', 'else', '!']);

export interface ScriptEvidence { path: string; reason: string }

export interface ObservedProfile {
  profile: typeof PROFILE_FORMAT;
  /** Tree digest (mago.skill-tree/v2) of the bytes this profile describes. */
  digest: string;
  /** Host names of http and https addresses found in any searched file. */
  web_hosts: string[];
  /** Files that are code: executable bit, `#!`, a script extension or a build-file name, or Markdown with shell code blocks. */
  scripts: ScriptEvidence[];
  /** Commands named first on a line inside shell code blocks in Markdown files (not a complete list). */
  programs: string[];
  not_searched: {
    /** Images, fonts, audio and video: not searched, not a gap. */
    media: string[];
    /** Binary, not UTF-8, or larger than 2 MiB. */
    unreadable: string[];
    /** Left out by `.skilldigestignore`. */
    ignored: string[];
  };
  /** False when anything above may be missing: an unreadable or ignored file, or a scan limit. */
  complete: boolean;
}

const extension = (file: string) => path.posix.extname(file).toLowerCase();

/** Counts lines that open a shell code block. No open/close tracking: a crafted pairing can never hide a block. */
function shellFenceCount(text: string): number {
  let count = 0;
  for (const line of text.split(/\r?\n|\r/u)) {
    const match = fenceOpenPattern.exec(line);
    if (match && isShellLanguage(match[2]!)) count += 1;
  }
  return count;
}

/** Programs named first on each command line of shell code blocks. Report-only, so open/close tracking is fine here. */
function shellPrograms(text: string, into: Set<string>): void {
  let open: { char: string; length: number; shell: boolean } | null = null;
  for (const line of text.split(/\r?\n|\r/u)) {
    const fence = fenceOpenPattern.exec(line);
    if (open) {
      if (fence && fence[1]![0] === open.char && fence[1]!.length >= open.length && fence[2] === '') { open = null; continue; }
      if (!open.shell) continue;
      let words = line.replace(/^(?:[ \t>]|[-*+][ \t]|[0-9]{1,9}[.)][ \t])*/u, '').replace(/^(?:\$|PS>|>|%)[ \t]+/u, '').split(/[ \t]+/u).filter(Boolean);
      while (words.length > 0 && (PREFIX_WORDS.has(words[0]!) || /^[A-Za-z_][A-Za-z0-9_]*=/u.test(words[0]!))) words = words.slice(1);
      const first = words[0];
      if (first === undefined || first.startsWith('#')) continue;
      const name = path.posix.basename(first);
      if (programPattern.test(name) && into.size < MAX_PROGRAMS) into.add(name);
      continue;
    }
    if (fence) open = { char: fence[1]![0]!, length: fence[1]!.length, shell: isShellLanguage(fence[2]!) };
  }
}

function scriptReason(file: string, exec: boolean, content: Buffer, text: string | null): string | null {
  if (exec) return 'executable file';
  if (content.subarray(0, 2).toString('latin1') === '#!') return 'starts with #!';
  if (SCRIPT_EXTENSIONS.has(extension(file))) return `${extension(file)} file`;
  if (SCRIPT_NAMES.has(path.posix.basename(file).toLowerCase())) return 'build or task file';
  if (text !== null && MARKDOWN_EXTENSIONS.has(extension(file))) {
    const fences = shellFenceCount(text);
    if (fences > 0) return `${fences} shell code block${fences === 1 ? '' : 's'}`;
  }
  return null;
}

/** The profile of a tree read with `collectSkillTree(dir, { includeContents: true })`. */
export function profileTree(tree: SkillTree & { contents?: Map<string, Buffer> }): ObservedProfile {
  const contents = tree.contents!;
  const searched = new Map<string, Buffer>();
  const media: string[] = [];
  const unreadable: string[] = [];
  const scripts: ScriptEvidence[] = [];
  const programs = new Set<string>();
  for (const file of tree.files) {
    const content = contents.get(file.path)!;
    const searchable = content.length <= MAX_SEARCHED_BYTES && !content.includes(0) && isUtf8(content);
    if (!searchable) (MEDIA_EXTENSIONS.has(extension(file.path)) ? media : unreadable).push(file.path);
    if (searchable) searched.set(file.path, content);
    const text = searchable ? content.toString('utf8') : null;
    const reason = scriptReason(file.path, file.exec, content, text);
    if (reason) scripts.push({ path: file.path, reason });
    if (text !== null && MARKDOWN_EXTENSIONS.has(extension(file.path))) shellPrograms(text, programs);
  }
  const ignored = pathsNotCovered(tree.excluded);
  // Only searchable files go in, so an incomplete scan means a limit was hit (sites or addresses).
  const origins = collectOrigins(searched);
  const hosts = new Set(origins.origins.map((origin) => new URL(origin).hostname));
  let limitHit = !origins.complete;
  scan: for (const content of searched.values()) {
    const text = content.toString('utf8');
    if (text.includes('\\')) {
      for (const match of text.matchAll(urlCandidatePattern)) {
        const host = backslashHost(match[0]);
        if (host) hosts.add(host);
        if (hosts.size > origins.origins.length + MAX_IPV6_HOSTS) { limitHit = true; break scan; }
      }
    }
    for (const match of text.matchAll(ipv6UrlPattern)) {
      let host: string;
      try {
        host = new URL(match[0]).hostname;
      } catch {
        continue;
      }
      hosts.add(host);
      if (hosts.size > origins.origins.length + MAX_IPV6_HOSTS) { limitHit = true; break scan; }
    }
  }
  return {
    profile: PROFILE_FORMAT,
    digest: tree.digest,
    web_hosts: [...hosts].sort(),
    scripts,
    programs: [...programs].sort(),
    not_searched: { media, unreadable, ignored },
    complete: !limitHit && unreadable.length === 0 && ignored.length === 0,
  };
}

export async function observeSkill(skillDir: string): Promise<ObservedProfile> {
  return profileTree(await collectSkillTree(skillDir, { includeContents: true }));
}
