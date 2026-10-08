import type { KeyObject } from 'node:crypto';
import { canonicalBytes, exactKeys, parseCanonicalJsonBytes, requireArray, requirePositiveInteger, requireString } from './canonical-json.ts';
import { envelopeBytes, parseEnvelope, signEnvelope, verifyEnvelopeSignature } from './dsse.ts';
import { parseSpki, validateKeyId, type PublicKeyInfo } from './keys.ts';
import { validateScope } from './names.ts';
import { formatTimestamp, parseTimestamp } from './time.ts';

export const TRUST_ROOT_PAYLOAD_TYPE = 'application/vnd.mago-ski.trust-root+json';
export const TRUST_ROOT_TYPE = 'mago.trust-root/v1';
export const MAX_APPROVERS = 256;
export const MAX_SCOPES = 64;

export interface Approver extends PublicKeyInfo {
  name: string;
  scopes: string[];
  expiresAt: Date;
}

export interface TrustRoot {
  version: number;
  issuedAt: Date;
  expiresAt: Date;
  root: PublicKeyInfo;
  approvers: Approver[];
}

/** Failure of a signed policy document; `code` maps to a verdict. */
export class TrustDocumentError extends Error {
  readonly code: 'UNVERIFIABLE' | 'EXPIRED';
  constructor(code: 'UNVERIFIABLE' | 'EXPIRED', message: string) {
    super(message);
    this.code = code;
    this.name = 'TrustDocumentError';
  }
}

export function trustRootPayload(trustRoot: TrustRoot): Record<string, unknown> {
  return {
    type: TRUST_ROOT_TYPE,
    version: trustRoot.version,
    issued_at: formatTimestamp(trustRoot.issuedAt),
    expires_at: formatTimestamp(trustRoot.expiresAt),
    root: { key_id: trustRoot.root.keyId, public_key: trustRoot.root.spki },
    approvers: [...trustRoot.approvers]
      .sort((left, right) => (left.keyId < right.keyId ? -1 : 1))
      .map((approver) => ({
        key_id: approver.keyId,
        public_key: approver.spki,
        name: approver.name,
        scopes: [...approver.scopes].sort(),
        expires_at: formatTimestamp(approver.expiresAt),
      })),
  };
}

export function signTrustRoot(trustRoot: TrustRoot, rootPrivateKey: KeyObject): Buffer {
  const payload = canonicalBytes(trustRootPayload(trustRoot));
  return envelopeBytes(signEnvelope(TRUST_ROOT_PAYLOAD_TYPE, payload, trustRoot.root.keyId, rootPrivateKey));
}

export function parseTrustRootPayload(bytes: Uint8Array): TrustRoot {
  const label = 'trust-root payload';
  const value = exactKeys(parseCanonicalJsonBytes(bytes, label), ['type', 'version', 'issued_at', 'expires_at', 'root', 'approvers'], label);
  if (value.type !== TRUST_ROOT_TYPE) throw new Error(`${label} has unsupported type`);
  const rootValue = exactKeys(value.root, ['key_id', 'public_key'], `${label} root`);
  const root = parseSpki(rootValue.public_key, `${label} root public_key`, validateKeyId(rootValue.key_id, `${label} root key_id`));
  const approvers: Approver[] = [];
  let previous = '';
  for (const [index, item] of requireArray(value.approvers, `${label} approvers`, MAX_APPROVERS).entries()) {
    const itemLabel = `${label} approvers[${index}]`;
    const entry = exactKeys(item, ['key_id', 'public_key', 'name', 'scopes', 'expires_at'], itemLabel);
    const keyId = validateKeyId(entry.key_id, `${itemLabel} key_id`);
    if (keyId <= previous) throw new Error(`${label} approvers must be unique and sorted by key_id`);
    previous = keyId;
    if (keyId === root.keyId) throw new Error(`${label}: the root key must not also be an approver`);
    const scopes = requireArray(entry.scopes, `${itemLabel} scopes`, MAX_SCOPES).map((scope, scopeIndex) => validateScope(scope, `${itemLabel} scopes[${scopeIndex}]`));
    if (scopes.length === 0) throw new Error(`${itemLabel} needs at least one scope`);
    for (let scopeIndex = 1; scopeIndex < scopes.length; scopeIndex += 1) {
      if (scopes[scopeIndex - 1]! >= scopes[scopeIndex]!) throw new Error(`${itemLabel} scopes must be unique and sorted`);
    }
    approvers.push({
      ...parseSpki(entry.public_key, `${itemLabel} public_key`, keyId),
      name: requireString(entry.name, `${itemLabel} name`, 128),
      scopes,
      expiresAt: parseTimestamp(entry.expires_at, `${itemLabel} expires_at`),
    });
  }
  const issuedAt = parseTimestamp(value.issued_at, `${label} issued_at`);
  const expiresAt = parseTimestamp(value.expires_at, `${label} expires_at`);
  if (expiresAt <= issuedAt) throw new Error(`${label} expires before it is issued`);
  return { version: requirePositiveInteger(value.version, `${label} version`), issuedAt, expiresAt, root, approvers };
}

/**
 * Verifies a signed trust root against the pinned root key fingerprint and the current time.
 * Rollback (an older version than already seen) is checked separately against host state.
 */
export function verifyTrustRoot(bytes: Uint8Array, pinnedRootKeyId: string, now: Date): TrustRoot {
  let trustRoot: TrustRoot;
  try {
    const envelope = parseEnvelope(bytes, 'trust root');
    if (envelope.payloadType !== TRUST_ROOT_PAYLOAD_TYPE) throw new Error('trust root has the wrong payload type');
    if (envelope.signatures[0].keyid !== pinnedRootKeyId) throw new Error('trust root is not signed by the pinned root key');
    trustRoot = parseTrustRootPayload(envelope.payloadBytes);
    if (trustRoot.root.keyId !== pinnedRootKeyId) throw new Error('trust root names a different root key than the pinned fingerprint');
    if (!verifyEnvelopeSignature(envelope, trustRoot.root.publicKey)) throw new Error('trust root signature is invalid');
  } catch (error) {
    throw new TrustDocumentError('UNVERIFIABLE', (error as Error).message);
  }
  if (trustRoot.expiresAt <= now) throw new TrustDocumentError('EXPIRED', `trust root expired at ${formatTimestamp(trustRoot.expiresAt)}`);
  return trustRoot;
}

/** Parses a trust root signed by `rootKeyId` without the expiry check, for editing. */
export function readTrustRootForUpdate(bytes: Uint8Array, rootKeyId: string): TrustRoot {
  const envelope = parseEnvelope(bytes, 'trust root');
  if (envelope.payloadType !== TRUST_ROOT_PAYLOAD_TYPE) throw new Error('trust root has the wrong payload type');
  const trustRoot = parseTrustRootPayload(envelope.payloadBytes);
  if (trustRoot.root.keyId !== rootKeyId || envelope.signatures[0].keyid !== rootKeyId) throw new Error('trust root belongs to a different root key');
  if (!verifyEnvelopeSignature(envelope, trustRoot.root.publicKey)) throw new Error('trust root signature is invalid');
  return trustRoot;
}
