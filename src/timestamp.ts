// Freshness (docs/spec/root-recovery-v1.md#freshness): an online timestamp key regularly signs a short-lived
// statement of exactly which root event log, trust root and revocation list are current. A host that is fed old
// files stops trusting them once the newest timestamp naming them expires.
import type { KeyObject } from 'node:crypto';
import { canonicalBytes, exactKeys, parseCanonicalJsonBytes, requirePositiveInteger } from './canonical-json.ts';
import { envelopeBytes, parseEnvelope, signEnvelope, verifyEnvelopeSignature } from './dsse.ts';
import { parseSpki, validateKeyId, type PublicKeyInfo } from './keys.ts';
import { CLOCK_SKEW_MS, formatTimestamp, parseTimestamp, requireValidDate } from './time.ts';

export const TIMESTAMP_PAYLOAD_TYPE = 'application/vnd.mago-ski.timestamp+json';
export const TIMESTAMP_TYPE         = 'mago.timestamp/v1';
export const MAX_TIMESTAMP_BYTES    = 64 * 1024;
export const DEFAULT_MAX_TIMESTAMP_LIFETIME = '24h';
export const MAX_TIMESTAMP_LIFETIME_MS      = 7 * 24 * 60 * 60 * 1000;

const SHA256_HEX = /^[0-9a-f]{64}$/u;

/** The timestamp is older than one this host has already seen; callers match on the class, not the message. */
export class TimestampRollbackError extends Error {}

export interface Timestamp {
  version:     number;
  issuedAt:    Date;
  expiresAt:   Date;
  key:         PublicKeyInfo;
  rootEvents:  { sha256: string; count: number };
  trustRoot:   { sha256: string; version: number };
  revocations: { sha256: string; version: number };
}

/** What a host read, to compare against the timestamp. */
export interface FreshnessInputs {
  rootEvents:  { sha256: string; count: number };
  trustRoot:   { sha256: string };
  revocations: { sha256: string };
}

function requireSha256(value: unknown, label: string): string {
  if (typeof value !== 'string' || !SHA256_HEX.test(value))
    throw new Error(`${label} must be 64 lowercase hex characters`);
  return value;
}

function requireCount(value: unknown, label: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0)
    throw new Error(`${label} must be a non-negative integer`);
  return value;
}

export function timestampPayload(timestamp: Timestamp): Record<string, unknown> {
  return {
    type:          TIMESTAMP_TYPE,
    version:       timestamp.version,
    issued_at:     formatTimestamp(timestamp.issuedAt),
    expires_at:    formatTimestamp(timestamp.expiresAt),
    timestamp_key: { key_id: timestamp.key.keyId, public_key: timestamp.key.spki },
    root_events:   { sha256: timestamp.rootEvents.sha256, count: timestamp.rootEvents.count },
    trust_root:    { sha256: timestamp.trustRoot.sha256, version: timestamp.trustRoot.version },
    revocations:   { sha256: timestamp.revocations.sha256, version: timestamp.revocations.version },
  };
}

export function signTimestamp(timestamp: Timestamp, privateKey: KeyObject): Buffer {
  return envelopeBytes(signEnvelope(TIMESTAMP_PAYLOAD_TYPE, canonicalBytes(timestampPayload(timestamp)), timestamp.key.keyId, privateKey));
}

export function parseTimestampPayload(bytes: Uint8Array): Timestamp {
  const label = 'timestamp';
  const value = exactKeys(parseCanonicalJsonBytes(bytes, label),
    ['type', 'version', 'issued_at', 'expires_at', 'timestamp_key', 'root_events', 'trust_root', 'revocations'], label);
  if (value.type !== TIMESTAMP_TYPE)
    throw new Error(`${label} has unsupported type`);
  const keyEntry    = exactKeys(value.timestamp_key, ['key_id', 'public_key'], `${label} timestamp_key`);
  const key         = parseSpki(keyEntry.public_key, `${label} timestamp_key public_key`, validateKeyId(keyEntry.key_id, `${label} timestamp_key key_id`));
  const events      = exactKeys(value.root_events, ['sha256', 'count'], `${label} root_events`);
  const trustRoot   = exactKeys(value.trust_root, ['sha256', 'version'], `${label} trust_root`);
  const revocations = exactKeys(value.revocations, ['sha256', 'version'], `${label} revocations`);
  const issuedAt    = parseTimestamp(value.issued_at, `${label} issued_at`);
  const expiresAt   = parseTimestamp(value.expires_at, `${label} expires_at`);
  if (expiresAt <= issuedAt)
    throw new Error(`${label} expires before it is issued`);
  return {
    version:     requirePositiveInteger(value.version, `${label} version`),
    issuedAt,
    expiresAt,
    key,
    rootEvents:  { sha256: requireSha256(events.sha256, `${label} root_events sha256`), count: requireCount(events.count, `${label} root_events count`) },
    trustRoot:   { sha256: requireSha256(trustRoot.sha256, `${label} trust_root sha256`), version: requirePositiveInteger(trustRoot.version, `${label} trust_root version`) },
    revocations: { sha256: requireSha256(revocations.sha256, `${label} revocations sha256`), version: requirePositiveInteger(revocations.version, `${label} revocations version`) },
  };
}

/** Reads a timestamp signed by `keyId` without the time checks (for the signing job, to find the next version). */
export function readTimestampForUpdate(bytes: Uint8Array, keyId: string): Timestamp {
  if (bytes.byteLength > MAX_TIMESTAMP_BYTES)
    throw new Error(`timestamp exceeds the ${MAX_TIMESTAMP_BYTES}-byte limit`);
  const envelope = parseEnvelope(bytes, 'timestamp');
  if (envelope.payloadType !== TIMESTAMP_PAYLOAD_TYPE)
    throw new Error('timestamp has the wrong payload type');
  if (envelope.signatures[0].keyid !== keyId)
    throw new Error(`timestamp is not signed by the active timestamp key ${keyId}`);
  const timestamp = parseTimestampPayload(envelope.payloadBytes);
  if (timestamp.key.keyId !== keyId)
    throw new Error('timestamp names a different timestamp key than the one that signed it');
  if (!verifyEnvelopeSignature(envelope, timestamp.key.publicKey))
    throw new Error('timestamp signature is invalid');
  return timestamp;
}

/**
 * Verifies a timestamp against the active timestamp key, the clock, the policy's lifetime cap and the lowest version
 * the host accepts, then checks that it names exactly the files the host read. Throws with the reason on any failure.
 * The trust root and revocation list versions are compared by the caller once those documents are parsed.
 */
export function verifyTimestamp(bytes: Uint8Array, options: {
  keyId:          string;
  now:            Date;
  maxLifetimeMs:  number;
  minimumVersion?: number | undefined;
  inputs:         FreshnessInputs;
}): Timestamp {
  requireValidDate(options.now, 'Verification time');
  const timestamp = readTimestampForUpdate(bytes, options.keyId);
  const now = options.now.getTime();
  if (timestamp.issuedAt.getTime() > now + CLOCK_SKEW_MS)
    throw new Error(`timestamp is issued in the future (${formatTimestamp(timestamp.issuedAt)})`);
  if (timestamp.expiresAt.getTime() - timestamp.issuedAt.getTime() > options.maxLifetimeMs)
    throw new Error('timestamp lifetime is longer than the policy\'s freshness max_lifetime');
  if (timestamp.expiresAt.getTime() <= now)
    throw new Error(`timestamp expired at ${formatTimestamp(timestamp.expiresAt)}; the timestamp job may have stopped`);
  if (options.minimumVersion !== undefined && timestamp.version < options.minimumVersion)
    throw new TimestampRollbackError(`timestamp version ${timestamp.version} is older than version ${options.minimumVersion} already seen (rollback)`);
  const { inputs } = options;
  if (timestamp.rootEvents.sha256 !== inputs.rootEvents.sha256 || timestamp.rootEvents.count !== inputs.rootEvents.count)
    throw new Error('the root event log does not match the timestamp');
  if (timestamp.trustRoot.sha256 !== inputs.trustRoot.sha256)
    throw new Error('the trust root does not match the timestamp');
  if (timestamp.revocations.sha256 !== inputs.revocations.sha256)
    throw new Error('the revocation list does not match the timestamp');
  return timestamp;
}
