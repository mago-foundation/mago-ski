import { createHash, createPublicKey } from 'node:crypto';
import { realpath } from 'node:fs/promises';
import path from 'node:path';
import {
  parseCanonicalJsonBytes,
  validateDigest,
  validateSkillName,
} from './manifest.mjs';
import { readRegularFile } from './tree-digest.mjs';

export const TRUST_VERSION = 'mago.skill-trust/v1';
export const APPROVAL_VERSION = 'mago.skill-approval/v1';
const MAX_TRUST_ANCHORS = 64;
const base64Pattern = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u;

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function exactKeys(value, expected, label) {
  if (!isRecord(value)) throw new Error(`${label} must be a JSON object`);
  const keys = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (keys.length !== wanted.length || keys.some((key, index) => key !== wanted[index])) {
    throw new Error(`${label} has missing or unsupported fields`);
  }
}

function validateIdentity(value, label) {
  if (typeof value !== 'string' || value.length < 1 || value.length > 512 || /[\u0000-\u001f\u007f]/u.test(value)) {
    throw new Error(`${label} must be a non-empty identity string of at most 512 characters`);
  }
  return value;
}

function validateIssuer(value) {
  if (typeof value !== 'string' || value.length > 512 || /[\u0000-\u001f\u007f]/u.test(value)) {
    throw new Error('Sigstore OIDC issuer must be a valid HTTPS URL');
  }
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error('Sigstore OIDC issuer must be a valid HTTPS URL');
  }
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.hash || parsed.search) {
    throw new Error('Sigstore OIDC issuer must be an exact HTTPS origin or issuer URL');
  }
  return value;
}

function trustTuple(entry) {
  return `${entry.certificate_identity}\0${entry.certificate_oidc_issuer}\0${entry.trusted_root}`;
}

function validateTrustedRootFilename(value) {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value === '.' ||
    value === '..' ||
    value.includes('/') ||
    value.includes('\\') ||
    value.includes(':') ||
    /[\u0000-\u001f\u007f]/u.test(value)
  ) {
    throw new Error('Sigstore trusted_root must be a file beside the trust configuration');
  }
  return value;
}

export function parseTrustConfigBytes(bytes, label = 'trust configuration') {
  const value = parseCanonicalJsonBytes(bytes, label);
  exactKeys(value, ['trust_version', 'ed25519', 'sigstore'], label);
  if (value.trust_version !== TRUST_VERSION) throw new Error(`${label} has an unsupported trust_version`);
  if (!Array.isArray(value.ed25519) || !Array.isArray(value.sigstore)) {
    throw new Error(`${label} ed25519 and sigstore fields must be arrays`);
  }
  if (value.ed25519.length + value.sigstore.length === 0) throw new Error(`${label} must contain at least one trust anchor`);
  if (value.ed25519.length + value.sigstore.length > MAX_TRUST_ANCHORS) {
    throw new Error(`${label} exceeds the ${MAX_TRUST_ANCHORS}-anchor limit`);
  }

  const ed25519 = [];
  const seenKeyIds = new Set();
  let previousKeyId = '';
  for (const [index, entry] of value.ed25519.entries()) {
    const labelEntry = `${label} ed25519[${index}]`;
    exactKeys(entry, ['key_id', 'public_key'], labelEntry);
    if (typeof entry.key_id !== 'string' || !/^sha256:[0-9a-f]{64}$/u.test(entry.key_id)) {
      throw new Error(`${labelEntry} key_id must be a lowercase SHA-256 key identifier`);
    }
    if (entry.key_id <= previousKeyId) throw new Error(`${label} Ed25519 keys must be unique and sorted by key_id`);
    previousKeyId = entry.key_id;
    if (typeof entry.public_key !== 'string' || !base64Pattern.test(entry.public_key)) {
      throw new Error(`${labelEntry} public_key must be canonical base64 SubjectPublicKeyInfo`);
    }
    const der = Buffer.from(entry.public_key, 'base64');
    if (der.length === 0 || der.toString('base64') !== entry.public_key) {
      throw new Error(`${labelEntry} public_key must be canonical base64 SubjectPublicKeyInfo`);
    }
    let publicKey;
    try {
      publicKey = createPublicKey({ key: der, format: 'der', type: 'spki' });
    } catch {
      throw new Error(`${labelEntry} public_key is invalid`);
    }
    if (publicKey.asymmetricKeyType !== 'ed25519') throw new Error(`${labelEntry} public_key is not Ed25519`);
    const canonicalDer = publicKey.export({ format: 'der', type: 'spki' });
    const actualKeyId = `sha256:${createHash('sha256').update(canonicalDer).digest('hex')}`;
    if (actualKeyId !== entry.key_id) throw new Error(`${labelEntry} key_id does not match public_key`);
    if (seenKeyIds.has(entry.key_id)) throw new Error(`${label} contains a duplicate Ed25519 key_id`);
    seenKeyIds.add(entry.key_id);
    ed25519.push({ keyId: entry.key_id, publicKey, publicKeyDer: canonicalDer });
  }

  const sigstore = [];
  const seenTuples = new Set();
  let previousTuple = '';
  for (const [index, entry] of value.sigstore.entries()) {
    const labelEntry = `${label} sigstore[${index}]`;
    exactKeys(entry, ['certificate_identity', 'certificate_oidc_issuer', 'trusted_root'], labelEntry);
    const normalized = {
      certificate_identity: validateIdentity(entry.certificate_identity, `${labelEntry} certificate_identity`),
      certificate_oidc_issuer: validateIssuer(entry.certificate_oidc_issuer),
      trusted_root: validateTrustedRootFilename(entry.trusted_root),
    };
    const tuple = trustTuple(normalized);
    if (tuple <= previousTuple) throw new Error(`${label} Sigstore identities must be unique and sorted`);
    previousTuple = tuple;
    if (seenTuples.has(tuple)) throw new Error(`${label} contains a duplicate Sigstore identity and issuer`);
    seenTuples.add(tuple);
    sigstore.push(normalized);
  }

  return { version: TRUST_VERSION, ed25519, sigstore };
}

export async function loadTrustConfig(filePath, { skillRoot } = {}) {
  const bytes = await readRegularFile(filePath, 'Trust configuration');
  const parsed = parseTrustConfigBytes(bytes);
  const canonicalPath = await realpath(filePath);
  const trustDirectory = path.dirname(canonicalPath);
  const trustedRoots = new Map();
  for (const entry of parsed.sigstore) {
    const trustedRootPath = path.join(trustDirectory, entry.trusted_root);
    const rootBytes = trustedRoots.get(entry.trusted_root) ?? await readRegularFile(trustedRootPath, 'Sigstore trusted root', 4 * 1024 * 1024);
    trustedRoots.set(entry.trusted_root, rootBytes);
    if (skillRoot) {
      const root = await realpath(skillRoot);
      const rootRealPath = await realpath(trustedRootPath);
      const relative = path.relative(root, rootRealPath);
      if (relative === '' || relative === '..' || relative.startsWith(`..${path.sep}`)) {
        throw new Error('Sigstore trusted root must be outside the Skill directory');
      }
    }
    entry.trustedRootPath = trustedRootPath;
  }
  return parsed;
}

export function trustedEd25519Key(trust, keyId) {
  return trust.ed25519.find((entry) => entry.keyId === keyId) ?? null;
}

export function trustedSigstoreIdentity(trust, identity, issuer) {
  return trust.sigstore.find((entry) => {
    return entry.certificate_identity === identity && entry.certificate_oidc_issuer === issuer;
  }) ?? null;
}

export function parseApprovalConfigBytes(bytes, label = 'approval configuration') {
  const value = parseCanonicalJsonBytes(bytes, label);
  exactKeys(value, ['approval_version', 'approvals'], label);
  if (value.approval_version !== APPROVAL_VERSION || !Array.isArray(value.approvals)) {
    throw new Error(`${label} has an unsupported approval_version or approvals field`);
  }
  const approvals = [];
  let previous = '';
  const seen = new Set();
  for (const [index, item] of value.approvals.entries()) {
    const labelItem = `${label} approvals[${index}]`;
    exactKeys(item, ['skill_name', 'digest'], labelItem);
    validateSkillName(item.skill_name, `${labelItem} skill_name`);
    validateDigest(item.digest, `${labelItem} digest`);
    const tuple = `${item.skill_name}\0${item.digest}`;
    if (tuple <= previous) throw new Error(`${label} approvals must be unique and sorted by skill_name and digest`);
    previous = tuple;
    if (seen.has(tuple)) throw new Error(`${label} contains a duplicate approval`);
    seen.add(tuple);
    approvals.push({ skillName: item.skill_name, digest: item.digest });
  }
  return { version: APPROVAL_VERSION, approvals };
}

export async function loadApprovalConfig(filePath) {
  const bytes = await readRegularFile(filePath, 'Approval configuration');
  return parseApprovalConfigBytes(bytes);
}

export function hasExactApproval(approvals, skillName, digest) {
  return approvals.approvals.some((approval) => approval.skillName === skillName && approval.digest === digest);
}

export function makeEd25519TrustEntry(keyId, publicKeyDer) {
  return { key_id: keyId, public_key: Buffer.from(publicKeyDer).toString('base64') };
}

