// Organization-side commands for root recovery: build the recovery set, prepare, sign and append root events,
// sign timestamps, and move the trust documents to a new root key after a rotation.
// `append` runs the same walk a host runs, so a log that append accepts is a log hosts accept.
import { readRegularFile, writeFileAtomic, writeNewFile } from './fs-safe.ts';
import { loadPrivateKey, loadPublicKey, type PublicKeyInfo } from './keys.ts';
import type { Policy } from './policy.ts';
import { readRevocationsForUpdate, signRevocations } from './revocations.ts';
import {
  addEnvelopeSignature, emptyRootEventLog, MAX_ROOT_EVENT_REASON, MAX_ROOT_EVENTS_BYTES, parseMultiEnvelope, parseRecoverySet,
  parseRootEventLog, parseRootEventPayload, recoverySetJson, requireDisplaySafeText, requiredSigners, ROOT_EVENT_PAYLOAD_TYPE,
  rootEventLogBytes, unsignedEventEnvelope, walkRootEvents, type MultiEnvelope, type RecoverySet, type RootEvent, type RootWalk,
} from './root-events.ts';
import { addDuration, formatTimestamp, parseDuration, truncateToSecond } from './time.ts';
import { MAX_TIMESTAMP_BYTES, readTimestampForUpdate, signTimestamp, type Timestamp } from './timestamp.ts';
import { sha256Hex } from './tree-digest.ts';
import { readTrustRootForUpdate, signTrustRoot, type TrustRoot } from './trust-root.ts';
import { canonicalBytes, parseCanonicalJsonBytes } from './canonical-json.ts';
import { parseEnvelope } from './dsse.ts';

const MAX_PROPOSAL_BYTES = 256 * 1024;

function requireRecovery(policy: Policy): NonNullable<Policy['recovery']> {
  if (!policy.recovery)
    throw new Error(`Policy ${policy.path} has no "recovery" block; root events need policy_version "mago.policy/v2" with recovery`);
  return policy.recovery;
}

async function uniqueKeys(paths: string[], label: string): Promise<PublicKeyInfo[]> {
  const keys = await Promise.all(paths.map((file) => loadPublicKey(file)));
  const ids = new Set(keys.map((key) => key.keyId));
  if (ids.size !== keys.length)
    throw new Error(`${label}: the same key is given more than once`);
  return keys.sort((a, b) => (a.keyId < b.keyId ? -1 : 1));
}

/** Builds and validates a recovery set from public key files. */
export async function buildRecoverySet(options: { publicKeyPaths: string[]; rotateThreshold: number; revokeThreshold: number }): Promise<RecoverySet> {
  const keys = await uniqueKeys(options.publicKeyPaths, 'Recovery keys');
  return parseRecoverySet({
    key_ids: keys.map((key) => key.keyId), rotate_threshold: options.rotateThreshold, revoke_threshold: options.revokeThreshold,
  }, 'Recovery set');
}

export async function initRootEventLog(out: string): Promise<string> {
  return await writeNewFile(out, emptyRootEventLog());
}

async function readLog(policy: Policy): Promise<Buffer> {
  return await readRegularFile(requireRecovery(policy).rootEventsPath, 'Root event log', MAX_ROOT_EVENTS_BYTES);
}

function walkFromPolicy(policy: Policy, bytes: Uint8Array, now: Date): RootWalk {
  const recovery = requireRecovery(policy);
  return walkRootEvents(bytes, {
    rootKeyId: policy.rootKeyId, recovery: recovery.set, timestampKeyId: recovery.freshness?.keyId ?? null, eventsAfter: recovery.eventsAfter,
  }, now);
}

/** Walks the policy's log the way a host does and returns the current root state. */
export async function currentRootState(policy: Policy, now: Date): Promise<RootWalk> {
  try {
    return walkFromPolicy(policy, await readLog(policy), now);
  } catch (error) {
    throw new Error(`root event log: ${(error as Error).message}`);
  }
}

export interface PreparedEvent {
  path:     string;
  event:    RootEvent;
  /** Keys that must sign before the event can be appended. */
  required: string[];
}

/**
 * Writes an unsigned proposal for the next root event. Every signer is fixed now, because the signatures cover the
 * list of signers; trustees then sign the same proposal file, and `appendRootEvent` adds it to the log.
 */
export async function prepareRootEvent(options: {
  policy:                 Policy;
  action:                 'revoke' | 'rotate';
  reason:                 string;
  signerPublicPaths:      string[];
  out:                    string;
  now:                    Date;
  newRootPublicPath?:     string | undefined;
  newRecoveryPublicPaths?: string[] | undefined;
  rotateThreshold?:       number | undefined;
  revokeThreshold?:       number | undefined;
  newTimestampPublicPath?: string | undefined;
}): Promise<PreparedEvent> {
  const state   = await currentRootState(options.policy, options.now);
  const reason  = requireDisplaySafeText(options.reason, 'Reason', MAX_ROOT_EVENT_REASON);
  const signers = await uniqueKeys(options.signerPublicPaths, 'Signers');
  if (signers.length === 0)
    throw new Error('At least one --signer-public key is required');

  const event: RootEvent = {
    sequence:  state.count + 1,
    action:    options.action,
    rootKeyId: state.activeRootKeyId,
    issuedAt:  truncateToSecond(options.now),
    reason,
    signers,
  };

  if (options.action === 'revoke') {
    if (state.revoked)
      throw new Error(`Root key ${state.activeRootKeyId} is already revoked (root event ${state.revoked.sequence}); prepare a rotate`);
    if (options.newRootPublicPath || options.newRecoveryPublicPaths?.length || options.newTimestampPublicPath
      || options.rotateThreshold !== undefined || options.revokeThreshold !== undefined)
      throw new Error('A revoke takes only --reason and --signer-public');
    const outside = signers.find((key) => !state.recovery.keyIds.includes(key.keyId));
    if (outside)
      throw new Error(`Signer ${outside.keyId} is not in the current recovery set`);
    if (signers.length < state.recovery.revokeThreshold)
      throw new Error(`A revoke needs ${state.recovery.revokeThreshold} recovery signer(s); ${signers.length} given`);
  } else {
    if (!options.newRootPublicPath)
      throw new Error('A rotate needs --new-root-public');
    event.newRoot = await loadPublicKey(options.newRootPublicPath);
    const newKeys = options.newRecoveryPublicPaths?.length ? (await uniqueKeys(options.newRecoveryPublicPaths, 'New recovery keys')).map((key) => key.keyId) : state.recovery.keyIds;
    const changingKeys = Boolean(options.newRecoveryPublicPaths?.length);
    if (changingKeys && (options.rotateThreshold === undefined || options.revokeThreshold === undefined))
      throw new Error('A new recovery set needs --rotate-threshold and --revoke-threshold');
    event.newRecovery = parseRecoverySet({
      key_ids:          newKeys,
      rotate_threshold: options.rotateThreshold ?? state.recovery.rotateThreshold,
      revoke_threshold: options.revokeThreshold ?? state.recovery.revokeThreshold,
    }, 'New recovery set');
    if (options.newTimestampPublicPath)
      event.newTimestamp = await loadPublicKey(options.newTimestampPublicPath);
    const outside = signers.find((key) => !state.recovery.keyIds.includes(key.keyId) && !event.newRecovery!.keyIds.includes(key.keyId));
    if (outside)
      throw new Error(`Signer ${outside.keyId} is in neither the current nor the new recovery set`);
  }

  const written = await writeNewFile(options.out, canonicalBytes(unsignedEventEnvelope(event)));
  return { path: written, event, required: requiredSigners(event).map((key) => key.keyId) };
}

async function readProposal(file: string): Promise<{ envelope: MultiEnvelope; event: RootEvent }> {
  const bytes    = await readRegularFile(file, 'Root event proposal', MAX_PROPOSAL_BYTES);
  const parsed   = parseMultiEnvelope(parseCanonicalJsonBytes(bytes, 'root event proposal'), 'root event proposal', { minSignatures: 0 });
  if (parsed.payloadType !== ROOT_EVENT_PAYLOAD_TYPE)
    throw new Error('root event proposal has the wrong payload type');
  const event = parseRootEventPayload(parsed.payloadBytes);
  return { envelope: { payloadType: parsed.payloadType, payload: parsed.payload, signatures: parsed.signatures }, event };
}

/** What a trustee should compare with what was agreed before signing. */
export function describeRootEvent(event: RootEvent): Record<string, unknown> {
  return {
    sequence:      event.sequence,
    action:        event.action,
    root_key_id:   event.rootKeyId,
    issued_at:     formatTimestamp(event.issuedAt),
    reason:        event.reason,
    signers:       event.signers.map((key) => key.keyId),
    ...(event.newRoot ? { new_root: event.newRoot.keyId } : {}),
    ...(event.newRecovery ? { new_recovery: recoverySetJson(event.newRecovery) } : {}),
    ...(event.newTimestamp ? { new_timestamp: event.newTimestamp.keyId } : {}),
  };
}

/** Refuses a proposal that does not extend the policy's log as it is now (wrong number or root key). */
async function checkExtendsLog(policy: Policy, event: RootEvent, now: Date): Promise<void> {
  const state = await currentRootState(policy, now);
  if (event.sequence !== state.count + 1)
    throw new Error(`The proposal is event ${event.sequence}, but the log has ${state.count} event(s); prepare it again against the published log`);
  if (event.rootKeyId !== state.activeRootKeyId)
    throw new Error(`The proposal names root key ${event.rootKeyId}, but the active root key is ${state.activeRootKeyId}`);
}

/** Reads a proposal and, with a policy, checks that it extends the published log. Signs nothing. */
export async function showRootEvent(options: { proposalPath: string; policy?: Policy | undefined; now: Date }): Promise<{ event: RootEvent; signed: string[]; missing: string[] }> {
  const { envelope, event } = await readProposal(options.proposalPath);
  if (options.policy) await checkExtendsLog(options.policy, event, options.now);
  const signed = envelope.signatures.map((item) => item.keyid);
  return { event, signed, missing: requiredSigners(event).map((key) => key.keyId).filter((keyId) => !signed.includes(keyId)) };
}

/**
 * Adds one signature to a proposal. Refuses a key the event does not name as a signer, new root or new timestamp key,
 * and, with a policy, a proposal that does not extend the published log. Returns the event so it can be shown.
 */
export async function signRootEvent(options: { proposalPath: string; keyPath: string; policy?: Policy | undefined; now?: Date | undefined }): Promise<{ keyId: string; event: RootEvent; signed: string[]; missing: string[] }> {
  const { envelope, event } = await readProposal(options.proposalPath);
  if (options.policy) await checkExtendsLog(options.policy, event, options.now ?? new Date());
  const key      = await loadPrivateKey(options.keyPath);
  const required = requiredSigners(event).map((item) => item.keyId);
  if (!required.includes(key.keyId))
    throw new Error(`Key ${key.keyId} is not one of the keys this event must be signed by (${required.join(', ')})`);
  const next = addEnvelopeSignature(envelope, key.keyId, key.privateKey);
  await writeFileAtomic(options.proposalPath, canonicalBytes(next));
  const signed = next.signatures.map((item) => item.keyid);
  return { keyId: key.keyId, event, signed, missing: required.filter((keyId) => !signed.includes(keyId)) };
}

/**
 * Appends a fully signed proposal to the policy's root event log, after walking the whole new log exactly as a host
 * would. Nothing is written if any rule fails.
 */
export async function appendRootEvent(options: { policy: Policy; proposalPath: string; now: Date }): Promise<{ path: string; walk: RootWalk; event: RootEvent }> {
  const recovery = requireRecovery(options.policy);
  const { envelope, event } = await readProposal(options.proposalPath);
  const required = requiredSigners(event).map((key) => key.keyId);
  const missing  = required.filter((keyId) => !envelope.signatures.some((item) => item.keyid === keyId));
  if (missing.length > 0)
    throw new Error(`The proposal is missing signatures from ${missing.join(', ')}`);
  const current  = await readLog(options.policy);
  const existing = parseRootEventLog(current).map((item) => ({ payloadType: item.payloadType, payload: item.payload, signatures: item.signatures }));
  const nextLog  = rootEventLogBytes([...existing, envelope]);
  if (nextLog.byteLength > MAX_ROOT_EVENTS_BYTES)
    throw new Error('The root event log would exceed its size limit');
  let walk: RootWalk;
  try {
    walk = walkFromPolicy(options.policy, nextLog, options.now);
  } catch (error) {
    throw new Error(`Refusing to append: ${(error as Error).message}`);
  }
  // The log only grows, and must not have changed since it was read.
  const again = await readLog(options.policy);
  if (sha256Hex(again) !== sha256Hex(current))
    throw new Error('The root event log changed while appending; run append again');
  const written = await writeFileAtomic(recovery.rootEventsPath, nextLog);
  return { path: written, walk, event };
}

/**
 * Signs the policy's timestamp: the digests of the root event log, trust root and revocation list as published now,
 * with the next version. Run by the timestamp job, with the active timestamp key.
 */
export async function signPolicyTimestamp(options: {
  policy:   Policy;
  keyPath:  string;
  now:      Date;
  expires?: string | undefined;
  version?: number | undefined;
}): Promise<{ path: string; timestamp: Timestamp }> {
  const recovery  = requireRecovery(options.policy);
  const freshness = recovery.freshness;
  if (!freshness)
    throw new Error(`Policy ${options.policy.path} has no "freshness" block`);
  const logBytes = await readLog(options.policy);
  let walk: RootWalk;
  try {
    walk = walkFromPolicy(options.policy, logBytes, options.now);
  } catch (error) {
    throw new Error(`root event log: ${(error as Error).message}`);
  }
  const key = await loadPrivateKey(options.keyPath);
  if (key.keyId !== walk.timestampKeyId)
    throw new Error(`Key ${key.keyId} is not the active timestamp key ${walk.timestampKeyId}`);

  const trustRootBytes   = await readRegularFile(options.policy.trustRootPath, 'Trust root', 4 * 1024 * 1024);
  const revocationsBytes = await readRegularFile(options.policy.revocationsPath, 'Revocation list', 8 * 1024 * 1024);
  // Only documents hosts would accept from the active root are timestamped.
  const trustRoot   = readTrustRootForUpdate(trustRootBytes, walk.activeRootKeyId);
  const revocations = readRevocationsForUpdate(revocationsBytes, walk.activeRootKeyId, trustRoot.root.publicKey);

  // Versions are per timestamp key: a missing timestamp, or one by an earlier timestamp key, starts at 1.
  let version = 1;
  let previousBytes: Buffer | null = null;
  try {
    previousBytes = await readRegularFile(freshness.timestampPath, 'Timestamp', MAX_TIMESTAMP_BYTES);
  } catch (error) {
    if ((error as NodeJS.ErrnoException)?.code !== 'ENOENT') throw error;
  }
  if (previousBytes) {
    try {
      version = readTimestampForUpdate(previousBytes, key.keyId).version + 1;
    } catch (error) {
      let byOtherKey = false;
      try {
        byOtherKey = parseEnvelope(previousBytes, 'timestamp').signatures[0].keyid !== key.keyId;
      } catch {
        byOtherKey = false;
      }
      if (!byOtherKey && options.version === undefined)
        throw new Error(`The current timestamp cannot be read (${(error as Error).message}); pass --version with a number above the last one published`);
    }
  }
  if (options.version !== undefined) {
    if (!Number.isSafeInteger(options.version) || options.version < 1)
      throw new Error('--version must be a positive integer');
    if (options.version < version)
      throw new Error(`--version ${options.version} is lower than the next version ${version}`);
    version = options.version;
  }

  const issuedAt  = truncateToSecond(options.now);
  const lifetime  = options.expires ?? '24h';
  if (parseDuration(lifetime, 'timestamp lifetime') > freshness.maxLifetimeMs)
    throw new Error('The timestamp lifetime is longer than the policy\'s freshness max_lifetime');
  const timestamp: Timestamp = {
    version,
    issuedAt,
    expiresAt:   addDuration(issuedAt, lifetime, 'timestamp lifetime'),
    key,
    rootEvents:  { sha256: sha256Hex(logBytes), count: walk.count },
    trustRoot:   { sha256: sha256Hex(trustRootBytes), version: trustRoot.version },
    revocations: { sha256: sha256Hex(revocationsBytes), version: revocations.version },
  };
  const written = await writeFileAtomic(freshness.timestampPath, signTimestamp(timestamp, key.privateKey));
  return { path: written, timestamp };
}

/**
 * After a rotate: re-signs the trust root and revocation list with the new root key, keeping every approver and
 * revocation entry, each with the next version. The current documents must be signed by `fromRootKeyId`.
 */
export async function adoptTrustDocuments(options: {
  rootKeyPath:        string;
  fromRootKeyId:      string;
  trustRootPath:      string;
  revocationsPath:    string;
  now:                Date;
  trustRootExpires?:  string | undefined;
  revocationsExpires?: string | undefined;
}): Promise<{ trustRoot: TrustRoot; trustRootVersion: number; revocationsVersion: number }> {
  const root = await loadPrivateKey(options.rootKeyPath);
  if (root.keyId === options.fromRootKeyId)
    throw new Error('The new root key is the same as the current one; nothing to adopt');
  const currentTrust = readTrustRootForUpdate(await readRegularFile(options.trustRootPath, 'Trust root', 4 * 1024 * 1024), options.fromRootKeyId);
  const currentList  = readRevocationsForUpdate(await readRegularFile(options.revocationsPath, 'Revocation list', 8 * 1024 * 1024), options.fromRootKeyId, currentTrust.root.publicKey);
  if (currentTrust.approvers.some((approver) => approver.keyId === root.keyId))
    throw new Error('The new root key is listed as an approver; remove it first');
  const issuedAt = truncateToSecond(options.now);
  const trustRoot: TrustRoot = {
    ...currentTrust,
    version:   currentTrust.version + 1,
    issuedAt,
    expiresAt: addDuration(issuedAt, options.trustRootExpires ?? '365d', 'trust root expiry'),
    root,
  };
  const revocations = {
    ...currentList,
    version:   currentList.version + 1,
    issuedAt,
    expiresAt: addDuration(issuedAt, options.revocationsExpires ?? '30d', 'revocation list expiry'),
    rootKeyId: root.keyId,
  };
  const trustBytes = signTrustRoot(trustRoot, root.privateKey);
  const listBytes  = signRevocations(revocations, root.privateKey);
  await writeFileAtomic(options.trustRootPath, trustBytes);
  await writeFileAtomic(options.revocationsPath, listBytes);
  return { trustRoot, trustRootVersion: trustRoot.version, revocationsVersion: revocations.version };
}

export { recoverySetJson };
