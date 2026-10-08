import type { KeyObject } from 'node:crypto';
import { canonicalBytes, exactKeys, parseCanonicalJsonBytes, requireArray, requirePositiveInteger, requireString } from './canonical-json.ts';
import { envelopeBytes, parseEnvelope, signEnvelope, verifyEnvelopeSignature } from './dsse.ts';
import { validateKeyId } from './keys.ts';
import { validateDigest } from './names.ts';
import { formatTimestamp, parseTimestamp } from './time.ts';
import { TrustDocumentError, type TrustRoot } from './trust-root.ts';

export const REVOCATIONS_PAYLOAD_TYPE = 'application/vnd.mago-ski.revocations+json';
export const REVOCATIONS_TYPE = 'mago.revocations/v1';
const MAX_REVOCATIONS = 10_000;

export interface RevokedKey {
  keyId: string;
  reason: string;
  revokedAt: Date;
}

export interface RevokedDigest {
  digest: string;
  reason: string;
  revokedAt: Date;
}

export interface Revocations {
  version: number;
  issuedAt: Date;
  expiresAt: Date;
  rootKeyId: string;
  keys: RevokedKey[];
  digests: RevokedDigest[];
}

export function revocationsPayload(revocations: Revocations): Record<string, unknown> {
  return {
    type: REVOCATIONS_TYPE,
    version: revocations.version,
    issued_at: formatTimestamp(revocations.issuedAt),
    expires_at: formatTimestamp(revocations.expiresAt),
    root_key_id: revocations.rootKeyId,
    revoked_keys: [...revocations.keys].sort((a, b) => (a.keyId < b.keyId ? -1 : 1))
      .map((entry) => ({ key_id: entry.keyId, reason: entry.reason, revoked_at: formatTimestamp(entry.revokedAt) })),
    revoked_digests: [...revocations.digests].sort((a, b) => (a.digest < b.digest ? -1 : 1))
      .map((entry) => ({ digest: entry.digest, reason: entry.reason, revoked_at: formatTimestamp(entry.revokedAt) })),
  };
}

export function signRevocations(revocations: Revocations, rootPrivateKey: KeyObject): Buffer {
  const payload = canonicalBytes(revocationsPayload(revocations));
  return envelopeBytes(signEnvelope(REVOCATIONS_PAYLOAD_TYPE, payload, revocations.rootKeyId, rootPrivateKey));
}

function sortedUnique(values: string[], label: string): void {
  for (let index = 1; index < values.length; index += 1) {
    if (values[index - 1]! >= values[index]!) throw new Error(`${label} must be unique and sorted`);
  }
}

export function parseRevocationsPayload(bytes: Uint8Array): Revocations {
  const label = 'revocations payload';
  const value = exactKeys(parseCanonicalJsonBytes(bytes, label),
    ['type', 'version', 'issued_at', 'expires_at', 'root_key_id', 'revoked_keys', 'revoked_digests'], label);
  if (value.type !== REVOCATIONS_TYPE) throw new Error(`${label} has unsupported type`);
  const keys = requireArray(value.revoked_keys, `${label} revoked_keys`, MAX_REVOCATIONS).map((item, index) => {
    const entry = exactKeys(item, ['key_id', 'reason', 'revoked_at'], `${label} revoked_keys[${index}]`);
    return {
      keyId: validateKeyId(entry.key_id, `${label} revoked_keys[${index}] key_id`),
      reason: requireString(entry.reason, `${label} revoked_keys[${index}] reason`, 512),
      revokedAt: parseTimestamp(entry.revoked_at, `${label} revoked_keys[${index}] revoked_at`),
    };
  });
  const digests = requireArray(value.revoked_digests, `${label} revoked_digests`, MAX_REVOCATIONS).map((item, index) => {
    const entry = exactKeys(item, ['digest', 'reason', 'revoked_at'], `${label} revoked_digests[${index}]`);
    return {
      digest: validateDigest(entry.digest, `${label} revoked_digests[${index}] digest`),
      reason: requireString(entry.reason, `${label} revoked_digests[${index}] reason`, 512),
      revokedAt: parseTimestamp(entry.revoked_at, `${label} revoked_digests[${index}] revoked_at`),
    };
  });
  sortedUnique(keys.map((entry) => entry.keyId), `${label} revoked_keys`);
  sortedUnique(digests.map((entry) => entry.digest), `${label} revoked_digests`);
  const issuedAt = parseTimestamp(value.issued_at, `${label} issued_at`);
  const expiresAt = parseTimestamp(value.expires_at, `${label} expires_at`);
  if (expiresAt <= issuedAt) throw new Error(`${label} expires before it is issued`);
  return {
    version: requirePositiveInteger(value.version, `${label} version`), issuedAt, expiresAt,
    rootKeyId: validateKeyId(value.root_key_id, `${label} root_key_id`), keys, digests,
  };
}

export function verifyRevocations(bytes: Uint8Array, trustRoot: TrustRoot, now: Date): Revocations {
  let revocations: Revocations;
  try {
    revocations = readRevocationsForUpdate(bytes, trustRoot.root.keyId, trustRoot.root.publicKey);
  } catch (error) {
    throw new TrustDocumentError('UNVERIFIABLE', (error as Error).message);
  }
  if (revocations.expiresAt <= now) {
    throw new TrustDocumentError('EXPIRED', `revocation list expired at ${formatTimestamp(revocations.expiresAt)}; publish a fresh one`);
  }
  return revocations;
}

/** Verifies the root signature without the freshness check, for editing. */
export function readRevocationsForUpdate(bytes: Uint8Array, rootKeyId: string, rootPublicKey: KeyObject): Revocations {
  const envelope = parseEnvelope(bytes, 'revocation list');
  if (envelope.payloadType !== REVOCATIONS_PAYLOAD_TYPE) throw new Error('revocation list has the wrong payload type');
  if (envelope.signatures[0].keyid !== rootKeyId) throw new Error('revocation list is not signed by the root key');
  const revocations = parseRevocationsPayload(envelope.payloadBytes);
  if (revocations.rootKeyId !== rootKeyId) throw new Error('revocation list names a different root key');
  if (!verifyEnvelopeSignature(envelope, rootPublicKey)) throw new Error('revocation list signature is invalid');
  return revocations;
}
