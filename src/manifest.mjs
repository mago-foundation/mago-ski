import { createHash } from 'node:crypto';
import { open, unlink } from 'node:fs/promises';
import { readRegularFile } from './tree-digest.mjs';

export const MANIFEST_VERSION = 'mago.skill-manifest/v1';
export const SIGNATURE_VERSION = 'mago.skill-signature/v1';
export const ATTESTATION_VERSION = 'mago.skill-attestation/v1';
export const MAX_CANONICAL_JSON_BYTES = 1024 * 1024;
const digestPattern = /^sha256:[0-9a-f]{64}$/u;
const utf8Decoder = new TextDecoder('utf-8', { fatal: true });

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function hasExactKeys(value, keys, label) {
  if (!isRecord(value)) throw new Error(`${label} must be a JSON object`);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error(`${label} has missing or unsupported fields`);
  }
}

function canonicalValue(value, depth, state) {
  state.nodes += 1;
  if (state.nodes > 100_000 || depth > 64) throw new Error('Canonical JSON exceeds structural limits');
  if (value === null) return 'null';
  if (typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('Canonical JSON cannot contain non-finite numbers');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalValue(item, depth + 1, state)).join(',')}]`;
  }
  if (isRecord(value)) {
    const entries = Object.keys(value).sort().map((key) => {
      return `${JSON.stringify(key)}:${canonicalValue(value[key], depth + 1, state)}`;
    });
    return `{${entries.join(',')}}`;
  }
  throw new Error('Canonical JSON contains an unsupported value');
}

export function serializeCanonicalJson(value) {
  return `${canonicalValue(value, 0, { nodes: 0 })}\n`;
}

export function parseCanonicalJsonBytes(bytes, label = 'JSON document') {
  if (!Buffer.isBuffer(bytes)) bytes = Buffer.from(bytes);
  if (bytes.length === 0 || bytes.length > MAX_CANONICAL_JSON_BYTES) {
    throw new Error(`${label} must be between 1 byte and ${MAX_CANONICAL_JSON_BYTES} bytes`);
  }
  let text;
  try {
    text = utf8Decoder.decode(bytes);
  } catch {
    throw new Error(`${label} is not valid UTF-8`);
  }
  if (text.charCodeAt(0) === 0xfeff || !text.endsWith('\n')) {
    throw new Error(`${label} must use canonical UTF-8 JSON with one trailing LF`);
  }
  let value;
  try {
    value = JSON.parse(text.slice(0, -1));
  } catch {
    throw new Error(`${label} is not valid JSON`);
  }
  let canonical;
  try {
    canonical = serializeCanonicalJson(value);
  } catch (error) {
    throw new Error(`${label} is structurally invalid: ${error.message}`);
  }
  if (!bytes.equals(Buffer.from(canonical, 'utf8'))) {
    throw new Error(`${label} is not canonical JSON (duplicate keys and alternate encodings are rejected)`);
  }
  return value;
}

export function validateSkillName(name, label = 'skill name') {
  if (typeof name !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u.test(name) || name === '.' || name === '..') {
    throw new Error(`${label} must be 1-128 ASCII letters, digits, dot, underscore or hyphen, starting with a letter or digit`);
  }
  return name;
}

export function validateDigest(digest, label = 'digest') {
  if (typeof digest !== 'string' || !digestPattern.test(digest)) {
    throw new Error(`${label} must be a lowercase SHA-256 digest`);
  }
  return digest;
}

export function createManifest(skillName, tree) {
  validateSkillName(skillName);
  validateDigest(tree.digest, 'tree digest');
  if (typeof tree.profile !== 'string' || tree.profile !== 'mago.skill-tree/v1') {
    throw new Error('Unsupported Skill tree digest profile');
  }
  return {
    manifest_version: MANIFEST_VERSION,
    skill_name: skillName,
    tree_digest: tree.digest,
    tree_profile: tree.profile,
  };
}

export function parseManifestBytes(bytes, label = 'manifest') {
  const value = parseCanonicalJsonBytes(bytes, label);
  hasExactKeys(value, ['manifest_version', 'skill_name', 'tree_digest', 'tree_profile'], label);
  if (value.manifest_version !== MANIFEST_VERSION) throw new Error(`${label} has an unsupported manifest_version`);
  validateSkillName(value.skill_name, `${label} skill_name`);
  validateDigest(value.tree_digest, `${label} tree_digest`);
  if (value.tree_profile !== 'mago.skill-tree/v1') throw new Error(`${label} has an unsupported tree_profile`);
  return value;
}

export async function readManifest(filePath) {
  const bytes = await readRegularFile(filePath, 'Manifest', MAX_CANONICAL_JSON_BYTES);
  return parseManifestBytes(bytes, 'Manifest');
}

export function createAttestationPayload(manifest) {
  const strictManifest = parseManifestBytes(Buffer.from(serializeCanonicalJson(manifest), 'utf8'));
  return Buffer.from(serializeCanonicalJson({
    attestation_version: ATTESTATION_VERSION,
    manifest_sha256: `sha256:${createHashForManifest(strictManifest)}`,
    skill_name: strictManifest.skill_name,
    tree_digest: strictManifest.tree_digest,
    tree_profile: strictManifest.tree_profile,
  }), 'utf8');
}

function createHashForManifest(manifest) {
  return createHash('sha256').update(serializeCanonicalJson(manifest), 'utf8').digest('hex');
}

export async function writeNewCanonicalFile(filePath, value, mode = 0o644, label = 'file') {
  const bytes = Buffer.from(serializeCanonicalJson(value), 'utf8');
  if (bytes.length > MAX_CANONICAL_JSON_BYTES) throw new Error(`${label} exceeds the ${MAX_CANONICAL_JSON_BYTES}-byte limit`);
  const handle = await open(filePath, 'wx', mode);
  try {
    await handle.writeFile(bytes);
    await handle.sync();
  } catch (error) {
    await handle.close();
    await unlink(filePath).catch(() => {});
    throw error;
  }
  await handle.close();
  return bytes;
}

