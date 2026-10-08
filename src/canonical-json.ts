// Canonical JSON: sorted object keys, no insignificant whitespace, one trailing LF.
// Parsing rejects any byte sequence that is not exactly the canonical form, so
// duplicate keys, alternate escapes and reordered fields cannot change meaning.

export const MAX_CANONICAL_JSON_BYTES = 4 * 1024 * 1024;

export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };

const utf8Decoder = new TextDecoder('utf-8', { fatal: true });

export function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function canonicalValue(value: unknown, depth: number, state: { nodes: number }): string {
  state.nodes += 1;
  if (state.nodes > 200_000 || depth > 64) throw new Error('Canonical JSON exceeds structural limits');
  if (value === null) return 'null';
  if (typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) throw new Error('Canonical JSON numbers must be safe integers');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalValue(item, depth + 1, state)).join(',')}]`;
  }
  if (isRecord(value)) {
    const entries = Object.keys(value).sort().map((key) => {
      const item = value[key];
      if (item === undefined) throw new Error(`Canonical JSON field ${JSON.stringify(key)} is undefined`);
      return `${JSON.stringify(key)}:${canonicalValue(item, depth + 1, state)}`;
    });
    return `{${entries.join(',')}}`;
  }
  throw new Error('Canonical JSON contains an unsupported value');
}

export function serializeCanonicalJson(value: unknown): string {
  return `${canonicalValue(value, 0, { nodes: 0 })}\n`;
}

export function canonicalBytes(value: unknown): Buffer {
  return Buffer.from(serializeCanonicalJson(value), 'utf8');
}

export function parseCanonicalJsonBytes(input: Uint8Array, label = 'JSON document'): unknown {
  const bytes = Buffer.from(input);
  if (bytes.length === 0 || bytes.length > MAX_CANONICAL_JSON_BYTES) {
    throw new Error(`${label} must be between 1 byte and ${MAX_CANONICAL_JSON_BYTES} bytes`);
  }
  let text: string;
  try {
    text = utf8Decoder.decode(bytes);
  } catch {
    throw new Error(`${label} is not valid UTF-8`);
  }
  if (text.charCodeAt(0) === 0xfeff || !text.endsWith('\n')) {
    throw new Error(`${label} must be canonical UTF-8 JSON with one trailing LF`);
  }
  let value: unknown;
  try {
    value = JSON.parse(text.slice(0, -1));
  } catch {
    throw new Error(`${label} is not valid JSON`);
  }
  let canonical: string;
  try {
    canonical = serializeCanonicalJson(value);
  } catch (error) {
    throw new Error(`${label} is structurally invalid: ${(error as Error).message}`);
  }
  if (!bytes.equals(Buffer.from(canonical, 'utf8'))) {
    throw new Error(`${label} is not canonical JSON (duplicate keys and alternate encodings are rejected)`);
  }
  return value;
}

export function exactKeys(value: unknown, keys: readonly string[], label: string): Record<string, unknown> {
  if (!isRecord(value)) throw new Error(`${label} must be a JSON object`);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error(`${label} has missing or unsupported fields`);
  }
  return value;
}

export function requireString(value: unknown, label: string, maxLength = 1024): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > maxLength || /[\u0000-\u001f\u007f]/u.test(value)) {
    throw new Error(`${label} must be a non-empty string of at most ${maxLength} characters without control characters`);
  }
  return value;
}

export function requireArray(value: unknown, label: string, maxLength: number): unknown[] {
  if (!Array.isArray(value) || value.length > maxLength) throw new Error(`${label} must be an array of at most ${maxLength} items`);
  return value;
}

export function requirePositiveInteger(value: unknown, label: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1) {
    throw new Error(`${label} must be a positive integer`);
  }
  return value;
}
