// OWASP Universal Skill Format (USF) v1.0: the `permissions` and `requires` blocks of a SKILL.md frontmatter.
// The input is untrusted Skill content. The parser accepts a small, strict YAML subset and refuses everything
// else, so two YAML readers can never disagree about what a Skill declared.

export const USF_FORMAT = 'owasp.usf/v1.0';

/** Frontmatter larger than this is refused rather than parsed. */
export const MAX_FRONTMATTER_BYTES = 256 * 1024;
const MAX_LIST_ITEMS = 1_000;
const MAX_SCALAR_CHARS = 2_048;
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

export class UsfError extends Error {}

/** A plain value that YAML 1.1 reads as a number, date or yes/no boolean: never text, never `true`. */
class Typed {
  readonly text: string;
  constructor(text: string) { this.text = text; }
}

type Value = string | boolean | null | Typed | Value[] | { [key: string]: Value };

/** `tab`: the raw line holds a tab anywhere (only block scalar text may). */
interface Line { indent: number; text: string; number: number; tab: boolean; afterComment: boolean; blankBefore: number }

// `|`, `>`, optionally with `+` or `-`. Explicit indentation digits are refused: YAML's rules for them are easy to get wrong.
const blockScalarPattern = /^[|>][+-]?(?:[ \t]+#.*)?$/u;
const keyPattern = /^([A-Za-z_][A-Za-z0-9_-]*):(?: +(.*))?$/u;
/**
 * Refused anywhere in the frontmatter: controls, and the Unicode spaces and format characters that JavaScript's trim()
 * removes but YAML keeps as text (or reads as a line break, as with U+0085).
 */
const refusedCharacters = /[\u0000-\u0008\u000b-\u001f\u007f\u0085\u00a0\u1680\u180e\u2000-\u200f\u2028-\u202f\u205f-\u2064\u3000\ufeff]/u;
// YAML 1.1 implicit types (PyYAML's resolver): these plain values are not strings there.
const yaml11Bool = /^(?:y|Y|yes|Yes|YES|n|N|no|No|NO|on|On|ON|off|Off|OFF)$/u;
const yaml11Number = /^(?:[-+]?(?:0b[01_]+|0x[0-9a-fA-F_]+|0[0-7_]+|0|[1-9][0-9_]*(?::[0-5]?[0-9])*)|[-+]?(?:[0-9][0-9_]*)?\.[0-9_]*(?:[eE][-+][0-9]+)?|[-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+\.[0-9_]*|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN))$/u;
const yaml11Date = /^[0-9]{4}-[0-9]{1,2}-[0-9]{1,2}(?:(?:[Tt]|[ \t]+)[0-9]{1,2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]*)?(?:[ \t]*(?:Z|[-+][0-9]{1,2}(?::[0-9]{2})?))?)?$/u;

/** What YAML refuses in a plain value, or reads as structure: `: `, a trailing `:`, or a leading indicator. */
function requirePlainText(plain: string, line: Line): void {
  if (/^[-?:](?:[ \t]|$)/u.test(plain) || /^[&*!|>%@`{}[\],#'"]/u.test(plain))
    fail(line, `"${plain.slice(0, 40)}" starts with YAML syntax this reader does not accept (anchors, aliases, tags, flow maps, indicators)`);
  if (/:(?:[ \t]|$)/u.test(plain)) fail(line, `"${plain.slice(0, 40)}" contains ": "; quote the value`);
}
const hostPattern = /^(?:\*\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)*\.?$/u;
const ipv6Pattern = /^\[[0-9a-f:.]+\]$/u;

/**
 * The frontmatter text between the opening and closing `---`, or null when SKILL.md has none. Lines end only at
 * LF or CRLF; a lone CR or U+2028 stays inside a line, where the parser then refuses it.
 */
export function frontmatter(skillMd: string): string | null {
  const text = skillMd.startsWith('\uFEFF') ? skillMd.slice(1) : skillMd;
  const lines = text.split(/\r?\n/u);
  if (!/^---[ \t]*$/u.test(lines[0]!) || lines.length < 2) return null;
  const close = lines.findIndex((line, index) => index > 0 && /^---[ \t]*$/u.test(line));
  if (close < 0) throw new UsfError('SKILL.md frontmatter has no closing --- line');
  const body = lines.slice(1, close).join('\n');
  if (Buffer.byteLength(body) > MAX_FRONTMATTER_BYTES) throw new UsfError(`SKILL.md frontmatter is larger than ${MAX_FRONTMATTER_BYTES} bytes`);
  return body;
}

function fail(line: Line | undefined, message: string): never {
  throw new UsfError(line ? `frontmatter line ${line.number}: ${message}` : message);
}

/** Removes a ` #comment` outside quotes. Quoted text is scanned by the scalar parser, so only plain text gets here. */
function stripComment(text: string): string {
  const hash = text.search(/(?:^|[ \t])#/u);
  return (hash < 0 ? text : text.slice(0, hash)).trimEnd();
}

function scalar(raw: string, line: Line): string | boolean | null | Typed {
  const text = raw.trim();
  if (text.length > MAX_SCALAR_CHARS) fail(line, `value is longer than ${MAX_SCALAR_CHARS} characters`);
  if (text.startsWith('"')) {
    const end = closingDoubleQuote(text);
    if (end < 0) fail(line, 'unterminated double-quoted value');
    if (stripComment(text.slice(end + 1)) !== '') fail(line, 'text after a quoted value');
    try {
      return JSON.parse(text.slice(0, end + 1)) as string;
    } catch {
      fail(line, 'double-quoted value uses an escape this reader does not accept');
    }
  }
  if (text.startsWith("'")) {
    let end = 1;
    for (;;) {
      end = text.indexOf("'", end);
      if (end < 0) fail(line, 'unterminated single-quoted value');
      if (text[end + 1] === "'") { end += 2; continue; }
      break;
    }
    if (stripComment(text.slice(end + 1)) !== '') fail(line, 'text after a quoted value');
    return text.slice(1, end).replace(/''/gu, "'");
  }
  const plain = stripComment(text);
  if (plain !== '') requirePlainText(plain, line);
  if (plain === '' || plain === '~' || plain === 'null' || plain === 'Null' || plain === 'NULL') return null;
  if (plain === 'true' || plain === 'True' || plain === 'TRUE') return true;
  if (plain === 'false' || plain === 'False' || plain === 'FALSE') return false;
  // PyYAML cannot build a value from these two, so the whole frontmatter fails there.
  if (plain === '=' || plain === '<<') fail(line, `"${plain}" is not accepted as a value; quote it`);
  if (yaml11Date.test(plain) && !validDate(plain)) fail(line, `"${plain.slice(0, 40)}" looks like a date but is not one; quote it`);
  if (yaml11Bool.test(plain) || yaml11Number.test(plain) || yaml11Date.test(plain)) return new Typed(plain);
  return plain;
}

/** Whether a YAML 1.1 timestamp has real field values, as PyYAML requires to build it. */
function validDate(text: string): boolean {
  const [y, mo, d, h = '0', mi = '0', se = '0'] = text.match(/[0-9]+/gu)!;
  const zone = /[-+]([0-9]{1,2})(?::[0-9]{2})?$/u.exec(text.slice(10));
  if (Number(y) < 1 || (zone && Number(zone[1]) >= 24)) return false;
  const date = new Date(0);
  date.setUTCFullYear(Number(y), Number(mo) - 1, Number(d));
  return date.getUTCMonth() === Number(mo) - 1 && date.getUTCDate() === Number(d) && Number(h) < 24 && Number(mi) < 60 && Number(se) < 60;
}

function closingDoubleQuote(text: string): number {
  for (let index = 1; index < text.length; index += 1) {
    if (text[index] === '\\') index += 1;
    else if (text[index] === '"') return index;
  }
  return -1;
}

/** `[a, "b", c]` on one line; items are scalars. */
function flowList(text: string, line: Line): Value[] {
  const body = stripCommentAfterFlow(text, line).slice(1, -1).trim();
  if (body === '') return [];
  const items: Value[] = [];
  let start = 0;
  let quote: string | null = null;
  for (let index = 0; index <= body.length; index += 1) {
    const char = body[index];
    if (quote) {
      if (char === '\\' && quote === '"') index += 1;
      else if (char === quote) quote = null;
      continue;
    }
    // A quote opens a quoted item only at the start of the item; inside a plain item it is a letter.
    if ((char === '"' || char === "'") && body.slice(start, index).trim() === '') quote = char;
    else if (char === '#') fail(line, 'a # inside a [ ] list is not accepted; quote the item');
    else if (char === '[' || char === ']' || char === '{' || char === '}') fail(line, 'nested flow collections are not accepted');
    else if (char === ',' || index === body.length) {
      const item = body.slice(start, index).trim();
      if (item === '') fail(line, 'empty item in a flow list');
      if (!/^["']/u.test(item) && (item.includes('?') || item.startsWith(':'))) fail(line, `"${item.slice(0, 40)}": a ? or leading : in an unquoted list item is not accepted; quote it`);
      items.push(scalar(item, line));
      if (items.length > MAX_LIST_ITEMS) fail(line, `list has more than ${MAX_LIST_ITEMS} items`);
      start = index + 1;
    }
  }
  if (quote) fail(line, 'unterminated quoted item in a flow list');
  return items;
}

function stripCommentAfterFlow(text: string, line: Line): string {
  const end = text.lastIndexOf(']');
  if (end < 0 || stripComment(text.slice(end + 1)) !== '') fail(line, 'a flow list must end with ] on the same line');
  return text.slice(0, end + 1);
}

function inlineValue(raw: string | undefined, line: Line): Value | undefined {
  if (raw === undefined || stripComment(raw) === '') return undefined;
  return raw.trimStart().startsWith('[') ? flowList(raw.trim(), line) : scalar(raw, line);
}

/** Skips a block scalar's text: the lines deeper than `indent`, none less indented than the first. */
function skipBlockScalar(lines: Line[], index: number, indent: number): number {
  const contentIndent = lines[index]?.indent ?? 0;
  // YAML refuses a leading blank line with more spaces than the first text line.
  if (lines[index] && lines[index]!.indent > indent && lines[index]!.blankBefore > contentIndent) fail(lines[index], 'a blank line in a | or > block has more spaces than its first line');
  for (; index < lines.length && lines[index]!.indent > indent; index += 1)
    if (lines[index]!.indent < contentIndent) fail(lines[index], 'a block scalar line is less indented than its first line');
  return index;
}

/** Skips a plain value's continuation lines; each must be plain text that YAML also reads as text. */
function skipPlainContinuation(lines: Line[], index: number, indent: number): number {
  for (; index < lines.length && lines[index]!.indent > indent; index += 1) {
    const line = lines[index]!;
    if (line.afterComment) fail(line, 'a comment line inside a value that goes on over several lines');
    if (line.tab) fail(line, 'tabs are not accepted in the frontmatter (except inside | and > text)');
    if (stripComment(line.text) !== line.text) fail(line, 'a comment inside a value that goes on over several lines');
    requirePlainText(line.text, line);
  }
  return index;
}

const isItem = (line: Line) => line.text === '-' || line.text.startsWith('- ');

/** Parses the block that starts at `lines[start]` with indentation `indent`; returns the value and the next index. */
function block(lines: Line[], start: number, indent: number, depth: number): [Value, number] {
  if (depth > 8) fail(lines[start], 'nesting is deeper than 8 levels');
  // YAML refuses a tab in most places outside quotes; this reader refuses it everywhere outside block scalar text.
  const structural = (line: Line) => { if (line.tab) fail(line, 'tabs are not accepted in the frontmatter (except inside | and > text)'); return line; };
  if (isItem(lines[start]!)) {
    const items: Value[] = [];
    let index = start;
    while (index < lines.length && lines[index]!.indent === indent && isItem(lines[index]!)) {
      const line = structural(lines[index]!);
      const rest = line.text.slice(1);
      const item = rest.trim();
      if (items.length >= MAX_LIST_ITEMS) fail(line, `list has more than ${MAX_LIST_ITEMS} items`);
      if (keyPattern.test(item)) {
        // `- key: value` starts a map whose keys line up with `key`.
        const childIndent = indent + 1 + (rest.length - rest.trimStart().length);
        lines[index] = { ...line, indent: childIndent, text: item };
        let value: Value;
        [value, index] = block(lines, index, childIndent, depth + 1);
        items.push(value);
        continue;
      }
      if (item === '' || item.startsWith('- ') || item === '-' || item.startsWith('[')) fail(line, 'nested or empty list items are not accepted');
      items.push(scalar(item, line));
      index += 1;
    }
    if (index < lines.length && lines[index]!.indent > indent) fail(lines[index], 'unexpected indentation inside a list');
    return [items, index];
  }
  const map: { [key: string]: Value } = Object.create(null) as { [key: string]: Value };
  let index = start;
  while (index < lines.length && lines[index]!.indent === indent) {
    const line = structural(lines[index]!);
    const match = keyPattern.exec(line.text);
    if (!match) fail(line, 'expected "key: value" (quoted keys, ? keys and other YAML forms are not accepted)');
    const key = match[1]!;
    if (Object.hasOwn(map, key)) fail(line, `duplicate key "${key}"`);
    index += 1;
    const raw = match[2] === undefined ? '' : stripComment(match[2]);
    if (blockScalarPattern.test(raw)) {
      // Only the text's existence matters here; a typed field given as text fails its type check.
      map[key] = '';
      index = skipBlockScalar(lines, index, indent);
      continue;
    }
    const inline = inlineValue(match[2], line);
    const next = lines[index];
    if (inline !== undefined) {
      map[key] = inline;
      if (next && next.indent > indent) {
        // A plain value may go on over deeper lines; quoted and [ ] values must close on their own line.
        if (/^["'[]/u.test(match[2]!.trim())) fail(next, `"${key}" has both an inline value and an indented block`);
        map[key] = inline instanceof Typed ? inline.text : String(inline);
        index = skipPlainContinuation(lines, index, indent);
      }
      continue;
    }
    // YAML lets a list sit at its parent key's indentation.
    if (next && (next.indent > indent || (next.indent === indent && isItem(next)))) {
      [map[key], index] = block(lines, index, next.indent, depth + 1);
    } else {
      map[key] = null;
    }
  }
  if (index < lines.length && lines[index]!.indent > indent) fail(lines[index], 'unexpected indentation');
  return [map, index];
}

/**
 * Parses the whole frontmatter with the strict subset, so that every line is read the way a YAML reader reads it or
 * refused; values outside `wanted` are then dropped. Reading only the wanted blocks let text that YAML keeps inside
 * another value (a quote running over several lines, say) pass as a `permissions` block.
 */
function topLevel(text: string, wanted: readonly string[]): Map<string, Value> {
  const lines: Line[] = [];
  let afterComment = false;
  let blankBefore = 0;
  text.split('\n').forEach((raw, offset) => {
    const number = offset + 2;
    if (refusedCharacters.test(raw)) fail({ indent: 0, text: raw, number, tab: false, afterComment, blankBefore }, 'contains a control character or a Unicode space that YAML and this reader treat differently');
    if (/^[ \t]*$/u.test(raw)) {
      if (raw.includes('\t')) fail({ indent: 0, text: raw, number, tab: true, afterComment, blankBefore }, 'a blank line holds a tab; remove it');
      blankBefore = Math.max(blankBefore, raw.length);
      return;
    }
    if (/^[ \t]*#/u.test(raw)) {
      if (/^ *\t/u.test(raw)) fail({ indent: 0, text: raw, number, tab: true, afterComment, blankBefore }, 'a comment line is indented with a tab');
      afterComment = true;
      return;
    }
    const indent = /^ */u.exec(raw)![0].length;
    lines.push({ indent, text: raw.slice(indent).trimEnd(), number, tab: raw.includes('\t'), afterComment, blankBefore });
    afterComment = false;
    blankBefore = 0;
  });
  const values = new Map<string, Value>();
  if (lines.length === 0) return values;
  if (lines[0]!.indent !== 0 || isItem(lines[0]!)) fail(lines[0], 'the frontmatter must be a list of "key: value" lines');
  const [document, next] = block(lines, 0, 0, 0);
  if (next !== lines.length) fail(lines[next], 'unexpected line');
  for (const key of wanted) if (Object.hasOwn(document as object, key)) values.set(key, (document as { [key: string]: Value })[key]!);
  return values;
}

function isMap(value: Value | undefined): value is { [key: string]: Value } {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function stringList(value: Value | undefined, label: string): string[] {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value) || !value.every((item): item is string => typeof item === 'string'))
    throw new UsfError(`${label} must be a list of text values`);
  return value;
}

function section(value: Value | undefined, label: string, known: readonly string[], unknownKeys: string[]): { [key: string]: Value } {
  if (value === undefined || value === null) return {};
  if (!isMap(value)) throw new UsfError(`${label} must be a block of keys`);
  for (const key of Object.keys(value)) if (!known.includes(key)) unknownKeys.push(`${label}.${key}`);
  return value;
}

/** A `network.allow` entry: a host name, `*.` plus a host name (its subdomains), a bracketed IPv6 address, or `*` (any host). */
export function normalizeHostEntry(entry: string): string {
  // ASCII only before case folding: toLowerCase() turns some non-ASCII letters (the Kelvin sign) into ASCII ones.
  const host = /^[\x21-\x7e]+$/u.test(entry.trim()) ? entry.trim().toLowerCase() : '\u0000';
  if (host === '*') return host;
  if (host.length > MAX_HOST_CHARS || !(hostPattern.test(host) || ipv6Pattern.test(host)))
    throw new UsfError(`permissions.network.allow entry "${entry.slice(0, 80)}" is not a host name (write api.example.com, not a URL)`);
  return host.endsWith('.') ? host.slice(0, -1) : host;
}

/**
 * Reads the USF manifest from SKILL.md. Returns null when the frontmatter has no `permissions` block
 * (the Skill declares nothing). Throws UsfError when the block is present but cannot be read exactly.
 */
export function parseUsfManifest(skillMd: string): UsfManifest | null {
  const text = frontmatter(skillMd);
  if (text === null) return null;
  const values = topLevel(text, ['permissions', 'requires']);
  if (!values.has('permissions')) return null;
  const unknownKeys: string[] = [];
  const permissions = section(values.get('permissions'), 'permissions', ['files', 'network', 'shell', 'tools'], unknownKeys);
  const files = section(permissions.files, 'permissions.files', ['read', 'write', 'deny_write'], unknownKeys);
  const network = section(permissions.network, 'permissions.network', ['allow', 'deny'], unknownKeys);
  const requires = section(values.get('requires'), 'requires', ['binaries', 'min_runtime_version'], unknownKeys);
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
    unknownKeys,
  };
}

/** Whether a declared `network.allow` list covers a host found in the Skill's files. */
export function hostAllowed(allow: readonly string[], host: string): boolean {
  const name = host.toLowerCase().replace(/\.$/u, '');
  return allow.some((entry) => entry === '*' || entry === name || (entry.startsWith('*.') && name.endsWith(entry.slice(1))));
}
