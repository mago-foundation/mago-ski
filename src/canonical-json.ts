// Canonical JSON: sorted object keys, no insignificant whitespace, one trailing LF.
// Parsing rejects any byte sequence that is not exactly the canonical form, so
// duplicate keys, alternate escapes and reordered fields cannot change meaning.

export const MAX_CANONICAL_JSON_BYTES = 4 * 1024 * 1024;
const MAX_CANONICAL_JSON_NODES        = 200_000;
const MAX_CANONICAL_JSON_DEPTH        = 64;
const DEFAULT_MAX_STRING_LENGTH       = 1_024;
const UTF8_BOM_CHAR_CODE              = 0xfeff;

const utf8Decoder         = new TextDecoder('utf-8', { fatal: true });
const controlCharPattern  = /[\u0000-\u001f\u007f]/u;

export type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [key: string]: JsonValue };

interface SerializationState {
  nodes: number;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function canonicalValue(value: unknown, depth: number, state: SerializationState): string {
  state.nodes += 1;
  if (state.nodes > MAX_CANONICAL_JSON_NODES || depth > MAX_CANONICAL_JSON_DEPTH) {
    throw new Error('Canonical JSON exceeds structural limits');
  }

  if (value === null) {
    return 'null';
  }

  if (typeof value === 'string') {
    return JSON.stringify(value);
  }

  if (typeof value === 'boolean') {
    return value ? 'true' : 'false';
  }

  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) {
      throw new Error('Canonical JSON numbers must be safe integers');
    }
    return Object.is(value, -0) ? '0' : JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    const elements = value.map((item) => canonicalValue(item, depth + 1, state));
    return `[${elements.join(',')}]`;
  }

  if (isRecord(value)) {
    const sortedKeys = Object.keys(value).sort();
    const entries = sortedKeys.map((key) => {
      if (key === '__proto__') {
        throw new Error('Canonical JSON forbids "__proto__" object keys');
      }
      const item = value[key];
      if (item === undefined) {
        throw new Error(`Canonical JSON field ${JSON.stringify(key)} is undefined`);
      }
      return `${JSON.stringify(key)}:${canonicalValue(item, depth + 1, state)}`;
    });
    return `{${entries.join(',')}}`;
  }

  throw new Error('Canonical JSON contains an unsupported value');
}

export function serializeCanonicalJson(value: unknown): string {
  const state: SerializationState = { nodes: 0 };
  return `${canonicalValue(value, 0, state)}\n`;
}

export function canonicalBytes(value: unknown): Buffer {
  return Buffer.from(serializeCanonicalJson(value), 'utf8');
}

export function parseCanonicalJsonBytes(input: Uint8Array, label = 'JSON document'): unknown {
  let text: string;
  let value: unknown;
  let canonical: string;

  if (
    !(input instanceof Uint8Array) ||
    input.byteLength === 0 ||
    input.byteLength > MAX_CANONICAL_JSON_BYTES
  ) {
    throw new Error(`${label} must be between 1 byte and ${MAX_CANONICAL_JSON_BYTES} bytes`);
  }

  try {
    text = utf8Decoder.decode(input);
  } catch {
    throw new Error(`${label} is not valid UTF-8`);
  }

  if (text.charCodeAt(0) === UTF8_BOM_CHAR_CODE || !text.endsWith('\n')) {
    throw new Error(`${label} must be canonical UTF-8 JSON with one trailing LF`);
  }

  try {
    value = JSON.parse(text.slice(0, -1), (key, parsedValue) => {
      if (key === '__proto__') {
        throw new Error('__proto__ key is forbidden');
      }
      if (typeof parsedValue === 'number' && Object.is(parsedValue, -0)) {
        throw new Error('negative zero is not canonical');
      }
      return parsedValue;
    });
  } catch {
    throw new Error(`${label} is not valid JSON`);
  }

  try {
    canonical = serializeCanonicalJson(value);
  } catch (error) {
    throw new Error(`${label} is structurally invalid: ${errorMessage(error)}`);
  }

  if (canonical !== text) {
    throw new Error(`${label} is not canonical JSON (duplicate keys and alternate encodings are rejected)`);
  }

  return value;
}

export function exactKeys(
  value: unknown,
  keys: readonly string[],
  label: string,
): Record<string, unknown> {
  if (!isRecord(value)) {
    throw new Error(`${label} must be a JSON object`);
  }

  const actualKeys = Object.keys(value).sort();
  const expectedKeys = [...new Set(keys)].sort();

  if (
    actualKeys.length !== expectedKeys.length ||
    actualKeys.some((key, index) => key !== expectedKeys[index])
  ) {
    throw new Error(`${label} has missing or unsupported fields`);
  }

  return value;
}

export function requireString(
  value: unknown,
  label: string,
  maxLength = DEFAULT_MAX_STRING_LENGTH,
): string {
  if (!Number.isSafeInteger(maxLength) || maxLength < 1) {
    throw new Error(`Invalid maxLength limit for ${label}`);
  }

  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > maxLength ||
    controlCharPattern.test(value)
  ) {
    throw new Error(
      `${label} must be a non-empty string of at most ${maxLength} characters without control characters`,
    );
  }

  return value;
}

export function requireArray(value: unknown, label: string, maxLength: number): unknown[] {
  if (!Number.isSafeInteger(maxLength) || maxLength < 0) {
    throw new Error(`Invalid maxLength limit for ${label}`);
  }

  if (!Array.isArray(value) || value.length > maxLength) {
    throw new Error(`${label} must be an array of at most ${maxLength} items`);
  }

  return value;
}

export function requirePositiveInteger(value: unknown, label: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1) {
    throw new Error(`${label} must be a positive integer`);
  }

  return value;
}
