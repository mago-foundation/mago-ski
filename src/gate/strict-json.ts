// Strict parser for untrusted, non-canonical JSON (host hook input, gate IPC).
// JSON.parse silently keeps the last duplicate member, so this is a small
// recursive-descent parser. Objects are built with a null prototype AFTER the
// forbidden-name check (`__proto__`, `constructor`, `prototype` are rejected
// outright), so no prototype pollution is possible. Errors carry a reason and
// a character offset only, never input content.

export interface StrictJsonLimits {
  maxBytes: number;
  maxDepth: number;
  maxMembers: number;
  maxStringLength: number;
}

export const DEFAULT_STRICT_JSON_LIMITS: StrictJsonLimits = {
  maxBytes: 64 * 1024,
  maxDepth: 16,
  maxMembers: 256,
  maxStringLength: 16 * 1024,
};

export class StrictJsonError extends Error {
  constructor(reason: string, offset?: number) {
    super(offset === undefined ? reason : `${reason} at offset ${offset}`);
    this.name = 'StrictJsonError';
  }
}

const FORBIDDEN_NAMES = new Set(['__proto__', 'constructor', 'prototype']);
const decoder         = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
const NUMBER_PATTERN  = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/u;
const SIMPLE_ESCAPES: Record<string, string> = {
  '"': '"', '\\': '\\', '/': '/', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t',
};

export function parseStrictJson(
  bytes: Uint8Array,
  limits: StrictJsonLimits = DEFAULT_STRICT_JSON_LIMITS,
): unknown {
  if (bytes.length > limits.maxBytes)
    throw new StrictJsonError('input exceeds byte limit');

  let text: string;
  try {
    text = decoder.decode(bytes);
  } catch {
    throw new StrictJsonError('input is not valid UTF-8');
  }
  if (text.charCodeAt(0) === 0xfeff)
    throw new StrictJsonError('byte order mark not allowed', 0);

  let pos = 0;
  const fail = (reason: string): never => { throw new StrictJsonError(reason, pos); };

  const skipWhitespace = (): void => {
    while (pos < text.length && ' \t\n\r'.includes(text[pos]!)) pos += 1;
  };

  const parseString = (): string => {
    pos += 1; // opening quote
    let out = '';
    for (;;) {
      if (pos >= text.length) fail('unterminated string');
      const ch = text[pos]!;
      if (ch === '"') { pos += 1; return out; }
      if (ch.charCodeAt(0) < 0x20) fail('control character in string');
      if (ch === '\\') {
        pos += 1;
        const esc = text[pos];
        if (esc === 'u') {
          const unit = readHex4();
          if (unit >= 0xdc00 && unit <= 0xdfff) fail('lone low surrogate');
          if (unit >= 0xd800 && unit <= 0xdbff) {
            if (text[pos] !== '\\' || text[pos + 1] !== 'u') fail('lone high surrogate');
            pos += 1;
            const low = readHex4();
            if (low < 0xdc00 || low > 0xdfff) fail('lone high surrogate');
            out += String.fromCharCode(unit, low);
          } else {
            out += String.fromCharCode(unit);
          }
        } else if (esc !== undefined && esc in SIMPLE_ESCAPES) {
          out += SIMPLE_ESCAPES[esc]!;
          pos += 1;
        } else {
          fail('invalid escape');
        }
      } else {
        out += ch;
        pos += 1;
      }
      if (out.length > limits.maxStringLength) fail('string exceeds length limit');
    }
  };

  // pos is on the 'u'; leaves pos after the four hex digits.
  const readHex4 = (): number => {
    const hex = text.slice(pos + 1, pos + 5);
    if (!/^[0-9A-Fa-f]{4}$/u.test(hex)) fail('invalid unicode escape');
    pos += 5;
    return Number.parseInt(hex, 16);
  };

  const parseValue = (depth: number): unknown => {
    skipWhitespace();
    const ch = text[pos];
    if (ch === '{' || ch === '[') {
      if (depth >= limits.maxDepth) fail('nesting exceeds depth limit');
      return ch === '{' ? parseObject(depth + 1) : parseArray(depth + 1);
    }
    if (ch === '"') return parseString();
    for (const [word, value] of [['true', true], ['false', false], ['null', null]] as const) {
      if (text.startsWith(word, pos)) { pos += word.length; return value; }
    }
    const match = NUMBER_PATTERN.exec(text.slice(pos, pos + 400));
    if (!match) return fail('unexpected token');
    const number = Number(match[0]);
    if (!Number.isFinite(number)) fail('number out of range');
    pos += match[0].length;
    return number;
  };

  const parseArray = (depth: number): unknown[] => {
    pos += 1;
    const out: unknown[] = [];
    skipWhitespace();
    if (text[pos] === ']') { pos += 1; return out; }
    for (;;) {
      if (out.length >= limits.maxMembers) fail('array exceeds member limit');
      out.push(parseValue(depth));
      skipWhitespace();
      if (text[pos] === ',') { pos += 1; continue; }
      if (text[pos] === ']') { pos += 1; return out; }
      fail('expected "," or "]"');
    }
  };

  const parseObject = (depth: number): Record<string, unknown> => {
    pos += 1;
    const out: Record<string, unknown> = Object.create(null);
    skipWhitespace();
    if (text[pos] === '}') { pos += 1; return out; }
    for (;;) {
      skipWhitespace();
      if (text[pos] !== '"') fail('expected member name');
      const name = parseString();
      if (FORBIDDEN_NAMES.has(name)) fail('forbidden member name');
      if (Object.hasOwn(out, name)) fail('duplicate member name');
      if (Object.keys(out).length >= limits.maxMembers) fail('object exceeds member limit');
      skipWhitespace();
      if (text[pos] !== ':') fail('expected ":"');
      pos += 1;
      out[name] = parseValue(depth);
      skipWhitespace();
      if (text[pos] === ',') { pos += 1; continue; }
      if (text[pos] === '}') { pos += 1; return out; }
      fail('expected "," or "}"');
    }
  };

  const value = parseValue(0);
  skipWhitespace();
  if (pos !== text.length) fail('trailing data');
  return value;
}
