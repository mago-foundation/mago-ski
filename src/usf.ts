// OWASP Universal Skill Format (USF) v1.0: the optional `permissions` and `requires` blocks of a SKILL.md frontmatter.
// Real Skills write ordinary YAML, so the frontmatter is read with a full YAML parser. Readers disagree on some plain
// values (YAML 1.1, used by PyYAML, reads `yes`, `on` and dates as non-text; YAML 1.2 does not), so the declaration is
// read under both rules, and a field whose two readings differ is reported as ambiguous instead of being guessed.
import { CST, Lexer, parseDocument } from 'yaml';

export const USF_FORMAT = 'owasp.usf/v1.0';

/** Frontmatter larger than this is not read. */
export const MAX_FRONTMATTER_BYTES = 64 * 1024;
const MAX_ALIASES = 50;
/** Real frontmatter has tens of keys; the YAML parser's cost grows faster than linearly with thousands. */
const MAX_KEYS = 2_000;
const MAX_HOST_CHARS = 253;

export interface UsfManifest {
  files: { read: string[]; write: string[]; deny_write: string[] };
  network: { allow: string[]; deny: string | null };
  shell: boolean | null;
  tools: string[];
  requires: { binaries: string[]; min_runtime_version: string | null };
  /** Keys this reader does not know; they are listed, not enforced. */
  unknownKeys: string[];
}

export interface UsfReading {
  /** The declaration, when the frontmatter has a `permissions` block that reads the same under YAML 1.1 and 1.2. */
  manifest: UsfManifest | null;
  /** Whether the frontmatter has a `permissions` key at all. */
  declared: boolean;
  /** Why the frontmatter or the declaration could not be read; null when it could. */
  error: string | null;
  /** Fields whose YAML 1.1 and YAML 1.2 readings differ. */
  ambiguous: string[];
}

export class UsfError extends Error {}

const hostPattern = /^(?:\*\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)*\.?$/u;
const ipv6Pattern = /^\[[0-9a-f:.]+\]$/u;

/**
 * The frontmatter text between the opening and the closing `---`, or null when SKILL.md has none.
 * Lines end at LF or CRLF, as in the Markdown frontmatter convention hosts follow.
 */
export function frontmatter(skillMd: string): string | null {
  const text = skillMd.startsWith('﻿') ? skillMd.slice(1) : skillMd;
  const lines = text.split(/\r?\n/u);
  if (lines.length < 2 || !/^---[ \t]*$/u.test(lines[0]!)) return null;
  const close = lines.findIndex((line, index) => index > 0 && /^---[ \t]*$/u.test(line));
  if (close < 0) throw new UsfError('SKILL.md frontmatter has no closing --- line');
  const body = lines.slice(1, close).join('\n');
  if (Buffer.byteLength(body) > MAX_FRONTMATTER_BYTES) throw new UsfError(`SKILL.md frontmatter is larger than ${MAX_FRONTMATTER_BYTES} bytes`);
  return body;
}

/**
 * A token pass before parsing. It refuses the YAML forms where the readers in use disagree, or where this
 * parser accepts what PyYAML rejects: directives and document markers (`%YAML 1.1` would override the version a
 * reading asks for), tags, `?` keys, collections as keys and a tab before `:`. It also bounds the work.
 */
function requireSimpleYaml(text: string): void {
  let keys = 0;
  let anchors = 0;
  let previousSolid = 'start';
  const history: string[] = [];
  // Controls and the characters YAML 1.1 (PyYAML) reads as line breaks but YAML 1.2 does not. Tabs are checked below.
  if (/[\u0000-\u0008\u000b-\u001f\u007f\u0085\u2028\u2029]/u.test(text)) throw new UsfError('the frontmatter holds a control character or a Unicode line break (U+0085, U+2028, U+2029)');
  for (const source of new Lexer().lex(text)) {
    const type = CST.tokenType(source) ?? '';
    // A | or > block's text arrives as one token after its header; tabs are fine there and refused everywhere else.
    const blockText = history.length >= 3 && history[history.length - 3] === 'block-scalar-header' && history[history.length - 2] === 'newline' && history[history.length - 1] === 'scalar';
    if (type === 'space' && source.includes('\t') && !blockText) throw new UsfError('the frontmatter has a tab outside quoted or | > text; PyYAML refuses it');
    // A plain value or key (the lexer gives it no type) with a tab: PyYAML refuses it; quoted text may hold tabs.
    if (type === '' && source.includes('\t') && !/^["']/u.test(source)) throw new UsfError('the frontmatter has a tab in an unquoted value or key; PyYAML refuses it');
    history.push(type);
    if (history.length > 3) history.shift();
    if (type === 'directive-line' || type === 'doc-start' || type === 'doc-end') throw new UsfError('the frontmatter holds a YAML directive or a document marker (%, --- or ...); remove it');
    if (type === 'tag') throw new UsfError(`the frontmatter uses the YAML tag ${source.slice(0, 40)}; tags are not accepted, because YAML readers resolve them differently`);
    if (type === 'explicit-key-ind') throw new UsfError('the frontmatter uses a "?" key; write keys as plain text');
    if (type === 'map-value-ind') {
      if (previousSolid !== '' && previousSolid !== 'flow-seq-end' && previousSolid !== 'flow-map-end') throw new UsfError('the frontmatter has a ":" without a key');
      if (previousSolid === 'flow-seq-end' || previousSolid === 'flow-map-end') throw new UsfError('the frontmatter uses a list or map as a key; write keys as plain text');
      keys += 1;
      if (keys > MAX_KEYS) throw new UsfError(`the frontmatter has more than ${MAX_KEYS} keys`);
    }
    if (type === 'anchor' || type === 'alias') {
      anchors += 1;
      if (anchors > MAX_ALIASES) throw new UsfError(`the frontmatter has more than ${MAX_ALIASES} anchors and aliases`);
    }
    if (type !== 'space') previousSolid = type;
  }
}

function readYaml(text: string, version: '1.1' | '1.2'): unknown {
  // Duplicate keys are an error: readers keep different copies (PyYAML the last, others the first or none).
  const doc = parseDocument(text, { version, uniqueKeys: true, prettyErrors: false });
  const error = doc.errors[0];
  if (error) throw new UsfError(`the frontmatter is not valid YAML ${version}: ${error.message.split('\n')[0]}`);
  try {
    // Alias expansion is capped, so a few lines cannot expand into a huge value.
    return doc.toJS({ maxAliasCount: MAX_ALIASES });
  } catch (error) {
    throw new UsfError(`the frontmatter could not be read as YAML ${version}: ${(error as Error).message}`);
  }
}

type Plain = { [key: string]: unknown };
const isMap = (value: unknown): value is Plain => typeof value === 'object' && value !== null && !Array.isArray(value) && !(value instanceof Date);

function stringList(value: unknown, label: string): string[] {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value) || !value.every((item): item is string => typeof item === 'string'))
    throw new UsfError(`${label} must be a list of text values`);
  return value;
}

function section(value: unknown, label: string, known: readonly string[], unknownKeys: string[]): Plain {
  if (value === undefined || value === null) return {};
  if (!isMap(value)) throw new UsfError(`${label} must be a block of keys`);
  for (const key of Object.keys(value)) if (!known.includes(key)) unknownKeys.push(`${label}.${key}`);
  return value;
}

/** A `network.allow` entry: a host name, `*.` plus a host name (its subdomains), a bracketed IPv6 address, or `*` (any host). */
export function normalizeHostEntry(entry: string): string {
  const trimmed = entry.trim();
  // ASCII only before case folding: toLowerCase() turns some non-ASCII letters (the Kelvin sign) into ASCII ones.
  const host = /^[\x21-\x7e]+$/u.test(trimmed) ? trimmed.toLowerCase() : '';
  if (host === '*') return host;
  if (host.length > MAX_HOST_CHARS || !(hostPattern.test(host) || ipv6Pattern.test(host)))
    throw new UsfError(`permissions.network.allow entry "${entry.slice(0, 80)}" is not a host name (write api.example.com, not a URL)`);
  if (ipv6Pattern.test(host)) {
    // The same normal form the profile's URL parser gives (it rewrites, for example, IPv4-mapped addresses).
    try {
      return new URL(`http://${host}/`).hostname;
    } catch {
      throw new UsfError(`permissions.network.allow entry "${entry.slice(0, 80)}" is not an IPv6 address`);
    }
  }
  return host.endsWith('.') ? host.slice(0, -1) : host;
}

/** The declaration in one YAML reading of the frontmatter. */
function declaration(document: Plain): UsfManifest {
  const unknownKeys: string[] = [];
  const permissions = section(document.permissions, 'permissions', ['files', 'network', 'shell', 'tools'], unknownKeys);
  const files = section(permissions.files, 'permissions.files', ['read', 'write', 'deny_write'], unknownKeys);
  const network = section(permissions.network, 'permissions.network', ['allow', 'deny'], unknownKeys);
  const requires = section(document.requires, 'requires', ['binaries', 'min_runtime_version'], unknownKeys);
  const shell = permissions.shell ?? null;
  if (shell !== null && typeof shell !== 'boolean') throw new UsfError('permissions.shell must be true or false');
  const deny = network.deny ?? null;
  if (deny !== null && typeof deny !== 'string') throw new UsfError('permissions.network.deny must be a text value such as "*"');
  const minRuntime = requires.min_runtime_version ?? null;
  if (minRuntime !== null && typeof minRuntime !== 'string') throw new UsfError('requires.min_runtime_version must be a text value');
  return {
    files: {
      read: stringList(files.read, 'permissions.files.read'),
      write: stringList(files.write, 'permissions.files.write'),
      deny_write: stringList(files.deny_write, 'permissions.files.deny_write'),
    },
    network: { allow: [...new Set(stringList(network.allow, 'permissions.network.allow').map(normalizeHostEntry))].sort(), deny },
    shell,
    tools: stringList(permissions.tools, 'permissions.tools'),
    requires: { binaries: stringList(requires.binaries, 'requires.binaries'), min_runtime_version: minRuntime },
    unknownKeys: unknownKeys.sort(),
  };
}

type Outcome = { manifest: UsfManifest } | { error: string };

function attempt(read: () => UsfManifest): Outcome {
  try {
    return { manifest: read() };
  } catch (error) {
    if (error instanceof UsfError) return { error: error.message };
    throw error;
  }
}

const FIELDS: ReadonlyArray<[string, (m: UsfManifest) => unknown]> = [
  ['permissions.shell', (m) => m.shell],
  ['permissions.network.allow', (m) => m.network.allow],
  ['permissions.network.deny', (m) => m.network.deny],
  ['permissions.files.read', (m) => m.files.read],
  ['permissions.files.write', (m) => m.files.write],
  ['permissions.files.deny_write', (m) => m.files.deny_write],
  ['permissions.tools', (m) => m.tools],
  ['requires.binaries', (m) => m.requires.binaries],
  ['requires.min_runtime_version', (m) => m.requires.min_runtime_version],
];

/**
 * Reads the USF declaration from SKILL.md. Never throws on Skill content: a Skill without frontmatter, with
 * frontmatter that is not YAML, or without a `permissions` block simply has no declaration, and `error` says why.
 */
export function readUsf(skillMd: string): UsfReading {
  const none = (error: string | null, declared = false): UsfReading => ({ manifest: null, declared, error, ambiguous: [] });
  let text: string | null;
  try {
    text = frontmatter(skillMd);
  } catch (error) {
    if (error instanceof UsfError) return none(error.message);
    throw error;
  }
  if (text === null) return none(null);

  let modern: unknown;
  let legacy: unknown;
  try {
    requireSimpleYaml(text);
    modern = readYaml(text, '1.2');
    legacy = readYaml(text, '1.1');
  } catch (error) {
    if (!(error instanceof UsfError)) throw error;
    // Unreadable: count it as declared whenever a permissions key may be there, so it cannot pass as "no declaration".
    return none(error.message, /permissions["']?[ \t]*:/u.test(text));
  }
  if (modern === null || modern === undefined) return none(null);
  if (!isMap(modern) || !isMap(legacy)) return none('the frontmatter is not a block of keys');
  if (!Object.hasOwn(modern, 'permissions') && !Object.hasOwn(legacy, 'permissions')) return none(null);

  const a = attempt(() => declaration(modern));
  const b = attempt(() => declaration(legacy));
  if ('error' in a && 'error' in b) return none(a.error, true);
  if ('error' in a || 'error' in b) {
    const failed = 'error' in a ? `in YAML 1.2, ${a.error}` : `in YAML 1.1 (PyYAML), ${(b as { error: string }).error}`;
    return { manifest: null, declared: true, error: `the declaration reads differently in YAML 1.1 and 1.2 (${failed}); quote text values and write true or false`, ambiguous: ['permissions'] };
  }
  const ambiguous = FIELDS.filter(([, get]) => JSON.stringify(get(a.manifest)) !== JSON.stringify(get(b.manifest))).map(([name]) => name);
  if (ambiguous.length > 0)
    return { manifest: null, declared: true, error: `these fields read differently in YAML 1.1 (PyYAML) and YAML 1.2: ${ambiguous.join(', ')}; quote text values and write true or false`, ambiguous };
  return { manifest: a.manifest, declared: true, error: null, ambiguous: [] };
}

/** Whether a declared `network.allow` list covers a host found in the Skill's files. */
export function hostAllowed(allow: readonly string[], host: string): boolean {
  const name = host.toLowerCase().replace(/\.$/u, '');
  return allow.some((entry) => entry === '*' || entry === name || (entry.startsWith('*.') && name.endsWith(entry.slice(1))));
}
