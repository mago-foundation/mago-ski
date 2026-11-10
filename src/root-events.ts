// Root recovery (docs/spec/root-recovery-v1.md): a recovery set of offline keys, pinned by fingerprint in the host
// policy, signs numbered root events that revoke or replace the root key. Hosts walk the log from the policy's
// starting point at every trust check; one event that breaks a rule makes the whole log UNVERIFIABLE.
import { sign, verify, type KeyObject } from 'node:crypto';
import { canonicalBytes, exactKeys, isRecord, parseCanonicalJsonBytes, requireArray, requirePositiveInteger, requireString } from './canonical-json.ts';
import { preAuthEncoding } from './dsse.ts';
import { parseSpki, validateKeyId, type PublicKeyInfo } from './keys.ts';
import { CLOCK_SKEW_MS, formatTimestamp, parseTimestamp, requireValidDate } from './time.ts';
import { sha256Hex } from './tree-digest.ts';

export const ROOT_EVENT_PAYLOAD_TYPE = 'application/vnd.mago-ski.root-event+json';
export const ROOT_EVENT_TYPE         = 'mago.root-event/v1';
export const ROOT_EVENTS_TYPE        = 'mago.root-events/v1';
export const MAX_ROOT_EVENTS         = 256;
export const MAX_ROOT_EVENTS_BYTES   = 4 * 1024 * 1024;
export const MAX_RECOVERY_KEYS       = 16;
/** 16 current + 16 new recovery keys + the new root + the new timestamp key. */
export const MAX_EVENT_SIGNATURES    = 2 * MAX_RECOVERY_KEYS + 2;
export const MAX_ROOT_EVENT_REASON   = 1024;
const MAX_EVENT_PAYLOAD_BYTES        = 64 * 1024;
const BASE64_PATTERN                 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u;
/**
 * Reasons are shown in verdicts, terminals, notifications, annotations and Pi block messages the model reads.
 * Besides the C0 controls that requireString refuses, refuse every other control (Cc), format (Cf: bidirectional
 * marks, zero-width characters, soft hyphens, tag characters), surrogate (Cs), private-use (Co) and unassigned (Cn)
 * code point, line and paragraph separators, and variation selectors, so a reason cannot hide, reorder or smuggle
 * text where it is displayed. One stolen recovery key can sign a revoke, so its reason must stay plain text.
 */
const UNSAFE_DISPLAY_PATTERN         = /[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Cn}\p{Zl}\p{Zp}\u{FE00}-\u{FE0F}\u{E0100}-\u{E01EF}\u{180B}-\u{180F}]/u;

export interface RecoverySet {
  /** Sorted, unique fingerprints. */
  keyIds:          string[];
  rotateThreshold: number;
  revokeThreshold: number;
}

export interface RootEvent {
  sequence:     number;
  action:       'revoke' | 'rotate';
  rootKeyId:    string;
  issuedAt:     Date;
  reason:       string;
  signers:      PublicKeyInfo[];
  newRoot?:     PublicKeyInfo;
  newRecovery?: RecoverySet;
  newTimestamp?: PublicKeyInfo;
}

/** A DSSE envelope with one or more signatures, sorted by keyid. */
export interface MultiEnvelope {
  payloadType: string;
  payload:     string;
  signatures:  Array<{ keyid: string; sig: string }>;
}

/** Where a walk starts: the keys the policy pins and how many events they already reflect. */
export interface RootStart {
  rootKeyId:      string;
  recovery:       RecoverySet;
  timestampKeyId: string | null;
  eventsAfter:    number;
}

export interface RootWalk {
  activeRootKeyId: string;
  recovery:        RecoverySet;
  timestampKeyId:  string | null;
  /** Set while the active root is revoked (only a rotate clears it). */
  revoked:         { sequence: number; reason: string } | null;
  /** Number of events in the log. */
  count:           number;
  /** `sha256:<hex>` of each event envelope as canonical JSON; index i is sequence i + 1. */
  eventDigests:    string[];
  /** SHA-256 (hex) of the log file's bytes. */
  logSha256:       string;
  /** Root and timestamp keys that left their role in the walked events (sorted); they never take another. */
  retired:         string[];
  /** Keys that were in a recovery set and left it in the walked events (sorted). */
  formerRecovery:  string[];
}

/** True when the text has no control, line-separator, bidirectional or invisible formatting characters. */
export function isDisplaySafeText(text: string): boolean {
  return !UNSAFE_DISPLAY_PATTERN.test(text);
}

export function requireDisplaySafeText(value: unknown, label: string, maxLength: number): string {
  const text = requireString(value, label, maxLength);
  if (!isDisplaySafeText(text))
    throw new Error(`${label} must not contain control, line-separator, bidirectional or invisible formatting characters`);
  return text;
}

function requireSortedUnique(values: string[], label: string): void {
  for (let index = 1; index < values.length; index += 1)
    if (values[index - 1]! >= values[index]!)
      throw new Error(`${label} must be unique and sorted`);
}

function decodeBase64(value: unknown, label: string, maxLength: number): Buffer {
  if (typeof value !== 'string' || value.length === 0 || value.length > maxLength || !BASE64_PATTERN.test(value))
    throw new Error(`${label} must be canonical base64`);
  const bytes = Buffer.from(value, 'base64');
  if (bytes.toString('base64') !== value)
    throw new Error(`${label} must be canonical base64`);
  return bytes;
}

/** Validates a recovery set as written in a policy or a rotate event (snake_case JSON). */
export function parseRecoverySet(value: unknown, label: string): RecoverySet {
  const entry   = exactKeys(value, ['key_ids', 'rotate_threshold', 'revoke_threshold'], label);
  const keyIds  = requireArray(entry.key_ids, `${label} key_ids`, MAX_RECOVERY_KEYS)
    .map((item, index) => validateKeyId(item, `${label} key_ids[${index}]`));
  if (keyIds.length === 0)
    throw new Error(`${label} key_ids must list at least one key`);
  requireSortedUnique(keyIds, `${label} key_ids`);
  const rotateThreshold = requirePositiveInteger(entry.rotate_threshold, `${label} rotate_threshold`);
  const revokeThreshold = requirePositiveInteger(entry.revoke_threshold, `${label} revoke_threshold`);
  if (!(revokeThreshold <= rotateThreshold && rotateThreshold <= keyIds.length))
    throw new Error(`${label} needs 1 <= revoke_threshold <= rotate_threshold <= number of key_ids`);
  return { keyIds, rotateThreshold, revokeThreshold };
}

export function recoverySetJson(set: RecoverySet): Record<string, unknown> {
  return { key_ids: [...set.keyIds], rotate_threshold: set.rotateThreshold, revoke_threshold: set.revokeThreshold };
}

const keyJson = (key: PublicKeyInfo) => ({ key_id: key.keyId, public_key: key.spki });

export function rootEventPayload(event: RootEvent): Record<string, unknown> {
  const payload: Record<string, unknown> = {
    type:        ROOT_EVENT_TYPE,
    sequence:    event.sequence,
    action:      event.action,
    root_key_id: event.rootKeyId,
    issued_at:   formatTimestamp(event.issuedAt),
    reason:      event.reason,
    signers:     [...event.signers].sort((a, b) => (a.keyId < b.keyId ? -1 : 1)).map(keyJson),
  };
  if (event.action === 'rotate') {
    if (!event.newRoot || !event.newRecovery)
      throw new Error('a rotate event needs a new root and a new recovery set');
    payload.new_root     = keyJson(event.newRoot);
    payload.new_recovery = recoverySetJson(event.newRecovery);
    if (event.newTimestamp)
      payload.new_timestamp = keyJson(event.newTimestamp);
  }
  return payload;
}

const EVENT_FIELDS  = ['type', 'sequence', 'action', 'root_key_id', 'issued_at', 'reason', 'signers'];
const ROTATE_FIELDS = [...EVENT_FIELDS, 'new_root', 'new_recovery'];

function parseKey(value: unknown, label: string): PublicKeyInfo {
  const entry = exactKeys(value, ['key_id', 'public_key'], label);
  return parseSpki(entry.public_key, `${label} public_key`, validateKeyId(entry.key_id, `${label} key_id`));
}

/** Reads and checks the shape of a root event payload. Signatures and the rules against host state are checked by the walk. */
export function parseRootEventPayload(bytes: Uint8Array): RootEvent {
  const label = 'root event';
  const raw   = parseCanonicalJsonBytes(bytes, label);
  if (!isRecord(raw))
    throw new Error(`${label} must be a JSON object`);
  const action = raw.action;
  if (action !== 'revoke' && action !== 'rotate')
    throw new Error(`${label} action must be "revoke" or "rotate"`);
  const fields = action === 'revoke' ? EVENT_FIELDS : 'new_timestamp' in raw ? [...ROTATE_FIELDS, 'new_timestamp'] : ROTATE_FIELDS;
  const value  = exactKeys(raw, fields, label);
  if (value.type !== ROOT_EVENT_TYPE)
    throw new Error(`${label} has unsupported type`);

  const signers = requireArray(value.signers, `${label} signers`, 2 * MAX_RECOVERY_KEYS)
    .map((item, index) => parseKey(item, `${label} signers[${index}]`));
  if (signers.length === 0)
    throw new Error(`${label} needs at least one signer`);
  requireSortedUnique(signers.map((key) => key.keyId), `${label} signers`);

  const event: RootEvent = {
    sequence:  requirePositiveInteger(value.sequence, `${label} sequence`),
    action,
    rootKeyId: validateKeyId(value.root_key_id, `${label} root_key_id`),
    issuedAt:  parseTimestamp(value.issued_at, `${label} issued_at`),
    reason:    requireDisplaySafeText(value.reason, `${label} reason`, MAX_ROOT_EVENT_REASON),
    signers,
  };
  if (action === 'rotate') {
    event.newRoot     = parseKey(value.new_root, `${label} new_root`);
    event.newRecovery = parseRecoverySet(value.new_recovery, `${label} new_recovery`);
    if (value.new_timestamp !== undefined)
      event.newTimestamp = parseKey(value.new_timestamp, `${label} new_timestamp`);
  }
  return event;
}

/** Parses a DSSE envelope object with 0..max signatures (a proposal may have none yet). */
export function parseMultiEnvelope(value: unknown, label: string, options: { minSignatures: number }): MultiEnvelope & { payloadBytes: Buffer; sigBytes: Buffer[] } {
  const entry        = exactKeys(value, ['payloadType', 'payload', 'signatures'], label);
  const payloadType  = requireString(entry.payloadType, `${label} payloadType`, 256);
  const payloadBytes = decodeBase64(entry.payload, `${label} payload`, Math.ceil(MAX_EVENT_PAYLOAD_BYTES / 3) * 4);
  const items        = requireArray(entry.signatures, `${label} signatures`, MAX_EVENT_SIGNATURES);
  if (items.length < options.minSignatures)
    throw new Error(`${label} must carry at least ${options.minSignatures} signature(s)`);
  const signatures: Array<{ keyid: string; sig: string }> = [];
  const sigBytes: Buffer[] = [];
  for (const [index, item] of items.entries()) {
    const signature = exactKeys(item, ['keyid', 'sig'], `${label} signatures[${index}]`);
    const keyid     = validateKeyId(signature.keyid, `${label} signatures[${index}] keyid`);
    const bytes     = decodeBase64(signature.sig, `${label} signatures[${index}] sig`, 128);
    if (bytes.length !== 64)
      throw new Error(`${label} signatures[${index}] must be a 64-byte Ed25519 signature`);
    signatures.push({ keyid, sig: signature.sig as string });
    sigBytes.push(bytes);
  }
  requireSortedUnique(signatures.map((item) => item.keyid), `${label} signatures`);
  return { payloadType, payload: entry.payload as string, signatures, payloadBytes, sigBytes };
}

/** Keys whose signatures a root event must carry, exactly: its signers, plus the new root and new timestamp key of a rotate. */
export function requiredSigners(event: RootEvent): PublicKeyInfo[] {
  const keys = [...event.signers];
  if (event.newRoot) keys.push(event.newRoot);
  if (event.newTimestamp) keys.push(event.newTimestamp);
  return keys.sort((a, b) => (a.keyId < b.keyId ? -1 : 1));
}

/** Adds (or replaces) one signature on an envelope, keeping signatures sorted by keyid. */
export function addEnvelopeSignature(envelope: MultiEnvelope, keyId: string, privateKey: KeyObject): MultiEnvelope {
  const payload = Buffer.from(envelope.payload, 'base64');
  const sig     = sign(null, preAuthEncoding(envelope.payloadType, payload), privateKey).toString('base64');
  const signatures = [...envelope.signatures.filter((item) => item.keyid !== keyId), { keyid: keyId, sig }]
    .sort((a, b) => (a.keyid < b.keyid ? -1 : 1));
  return { payloadType: envelope.payloadType, payload: envelope.payload, signatures };
}

export function unsignedEventEnvelope(event: RootEvent): MultiEnvelope {
  return {
    payloadType: ROOT_EVENT_PAYLOAD_TYPE,
    payload:     canonicalBytes(rootEventPayload(event)).toString('base64'),
    signatures:  [],
  };
}

export function emptyRootEventLog(): Buffer {
  return canonicalBytes({ events: [], type: ROOT_EVENTS_TYPE });
}

export function rootEventLogBytes(envelopes: MultiEnvelope[]): Buffer {
  return canonicalBytes({ events: envelopes, type: ROOT_EVENTS_TYPE });
}

/** `sha256:` + the SHA-256 of the envelope as canonical JSON with its trailing LF (the host state's event_digest). */
export function eventDigest(envelope: MultiEnvelope): string {
  return `sha256:${sha256Hex(canonicalBytes({ payload: envelope.payload, payloadType: envelope.payloadType, signatures: envelope.signatures }))}`;
}

/** Parses the log file. Each envelope's structure is checked; signatures and rules are checked by the walk. */
export function parseRootEventLog(bytes: Uint8Array): Array<MultiEnvelope & { payloadBytes: Buffer; sigBytes: Buffer[] }> {
  if (bytes.byteLength > MAX_ROOT_EVENTS_BYTES)
    throw new Error(`root event log exceeds the ${MAX_ROOT_EVENTS_BYTES}-byte limit`);
  const value = exactKeys(parseCanonicalJsonBytes(bytes, 'root event log'), ['events', 'type'], 'root event log');
  if (value.type !== ROOT_EVENTS_TYPE)
    throw new Error('root event log has unsupported type');
  return requireArray(value.events, 'root event log events', MAX_ROOT_EVENTS)
    .map((item, index) => parseMultiEnvelope(item, `root event ${index + 1}`, { minSignatures: 1 }));
}

interface WalkState {
  activeRootKeyId: string;
  recovery:        RecoverySet;
  timestampKeyId:  string | null;
  revoked:         { sequence: number; reason: string } | null;
  /** Keys that held the root or timestamp role and left it; they never take any role again. */
  retired:         Set<string>;
  /** Keys that left a recovery set in a walked rotate. */
  formerRecovery:  Set<string>;
  lastIssuedAt:    Date | null;
}

function checkRoles(state: Pick<WalkState, 'activeRootKeyId' | 'recovery' | 'timestampKeyId'>, label: string): void {
  if (state.recovery.keyIds.includes(state.activeRootKeyId))
    throw new Error(`${label}: the root key must not also be a recovery key`);
  if (state.timestampKeyId !== null) {
    if (state.timestampKeyId === state.activeRootKeyId)
      throw new Error(`${label}: the timestamp key must not also be the root key`);
    if (state.recovery.keyIds.includes(state.timestampKeyId))
      throw new Error(`${label}: the timestamp key must not also be a recovery key`);
  }
}

/** Checks one event against the state just before it, including every signature, and returns the state after it. */
function applyEvent(
  state:    WalkState,
  envelope: MultiEnvelope & { payloadBytes: Buffer; sigBytes: Buffer[] },
  sequence: number,
  now:      Date,
): WalkState {
  const label = `root event ${sequence}`;
  if (envelope.payloadType !== ROOT_EVENT_PAYLOAD_TYPE)
    throw new Error(`${label} has the wrong payload type`);
  let event: RootEvent;
  try {
    event = parseRootEventPayload(envelope.payloadBytes);
  } catch (error) {
    throw new Error(`${label}: ${(error as Error).message}`);
  }
  if (event.sequence !== sequence)
    throw new Error(`${label} carries sequence ${event.sequence}`);
  if (event.rootKeyId !== state.activeRootKeyId)
    throw new Error(`${label} names root key ${event.rootKeyId}, but the active root key is ${state.activeRootKeyId}`);
  if (event.issuedAt.getTime() > now.getTime() + CLOCK_SKEW_MS)
    throw new Error(`${label} is issued in the future (${formatTimestamp(event.issuedAt)})`);
  if (state.lastIssuedAt && event.issuedAt < state.lastIssuedAt)
    throw new Error(`${label} is issued before the event before it`);

  const current = state.recovery;
  const inCurrent = (keyId: string) => current.keyIds.includes(keyId);
  const signerIds = event.signers.map((key) => key.keyId);
  let next: WalkState;

  if (event.action === 'revoke') {
    if (state.revoked)
      throw new Error(`${label} revokes root key ${event.rootKeyId}, which root event ${state.revoked.sequence} already revoked`);
    if (!signerIds.every(inCurrent))
      throw new Error(`${label} is signed by a key that is not in the current recovery set`);
    if (signerIds.length < current.revokeThreshold)
      throw new Error(`${label} has ${signerIds.length} recovery signature(s); a revoke needs ${current.revokeThreshold}`);
    const retired = new Set(state.retired);
    retired.add(state.activeRootKeyId);
    next = { ...state, revoked: { sequence, reason: event.reason }, retired, lastIssuedAt: event.issuedAt };
  } else {
    const newRoot      = event.newRoot!;
    const newRecovery  = event.newRecovery!;
    const newTimestamp = event.newTimestamp;
    const inNew        = (keyId: string) => newRecovery.keyIds.includes(keyId);

    if (inCurrent(newRoot.keyId) || inNew(newRoot.keyId))
      throw new Error(`${label}: the new root key must not be a recovery key`);
    if (newRoot.keyId === event.rootKeyId ? state.revoked !== null : state.retired.has(newRoot.keyId))
      throw new Error(`${label}: the new root key ${newRoot.keyId} has left the root role and cannot return`);
    if (newRoot.keyId === state.timestampKeyId || newRoot.keyId === newTimestamp?.keyId)
      throw new Error(`${label}: the new root key must not also be a timestamp key`);
    for (const keyId of newRecovery.keyIds)
      if (state.retired.has(keyId) || keyId === state.activeRootKeyId || keyId === state.timestampKeyId)
        throw new Error(`${label}: recovery key ${keyId} has held the root or timestamp role`);
    if (newTimestamp) {
      const id = newTimestamp.keyId;
      if (id === event.rootKeyId || id === newRoot.keyId)
        throw new Error(`${label}: the new timestamp key must not be a root key`);
      if (inCurrent(id) || inNew(id))
        throw new Error(`${label}: the new timestamp key must not be a recovery key`);
      if (state.retired.has(id))
        throw new Error(`${label}: the new timestamp key ${id} has left a role and cannot return`);
    }
    if (!signerIds.every((keyId) => inCurrent(keyId) || inNew(keyId)))
      throw new Error(`${label} is signed by a key that is in neither the current nor the new recovery set`);
    const fromCurrent = signerIds.filter(inCurrent).length;
    const fromNew     = signerIds.filter(inNew).length;
    if (fromCurrent < current.rotateThreshold)
      throw new Error(`${label} has ${fromCurrent} signature(s) from the current recovery set; a rotate needs ${current.rotateThreshold}`);
    if (fromNew < newRecovery.rotateThreshold)
      throw new Error(`${label} has ${fromNew} signature(s) from the new recovery set; it needs ${newRecovery.rotateThreshold}`);

    const formerRecovery = new Set(state.formerRecovery);
    for (const keyId of current.keyIds)
      if (!inNew(keyId))
        formerRecovery.add(keyId);
    const retired = new Set(state.retired);
    if (newRoot.keyId !== state.activeRootKeyId)
      retired.add(state.activeRootKeyId);
    if (newTimestamp && state.timestampKeyId !== null && newTimestamp.keyId !== state.timestampKeyId)
      retired.add(state.timestampKeyId);
    next = {
      activeRootKeyId: newRoot.keyId,
      recovery:        newRecovery,
      timestampKeyId:  newTimestamp ? newTimestamp.keyId : state.timestampKeyId,
      revoked:         null,
      retired,
      formerRecovery,
      lastIssuedAt:    event.issuedAt,
    };
    checkRoles(next, label);
  }

  // Signatures last: exactly the required keys, each valid. An unknown or invalid signature rejects the event.
  const required = requiredSigners(event);
  if (envelope.signatures.length !== required.length || envelope.signatures.some((item, index) => item.keyid !== required[index]!.keyId))
    throw new Error(`${label} must be signed by exactly ${required.map((key) => key.keyId).join(', ')}`);
  const pae = preAuthEncoding(envelope.payloadType, envelope.payloadBytes);
  for (const [index, key] of required.entries()) {
    let valid = false;
    try {
      valid = verify(null, pae, key.publicKey, envelope.sigBytes[index]!);
    } catch {
      valid = false;
    }
    if (!valid)
      throw new Error(`${label} has an invalid signature from ${key.keyId}`);
  }
  return next;
}

/**
 * Walks the root event log from the policy's starting point. Throws (the log is UNVERIFIABLE) if any event after
 * `eventsAfter` breaks a rule; events are never skipped. Hashes every event so rollback and fork checks can use them.
 */
export function walkRootEvents(bytes: Uint8Array, start: RootStart, now: Date): RootWalk {
  requireValidDate(now, 'Verification time');
  checkRoles({ activeRootKeyId: start.rootKeyId, recovery: start.recovery, timestampKeyId: start.timestampKeyId }, 'policy');
  const envelopes = parseRootEventLog(bytes);
  if (envelopes.length < start.eventsAfter)
    throw new Error(`root event log has ${envelopes.length} event(s), fewer than root_events_after (${start.eventsAfter})`);
  let state: WalkState = {
    activeRootKeyId: start.rootKeyId,
    recovery:        start.recovery,
    timestampKeyId:  start.timestampKeyId,
    revoked:         null,
    retired:         new Set(),
    formerRecovery:  new Set(),
    lastIssuedAt:    null,
  };
  for (let index = start.eventsAfter; index < envelopes.length; index += 1)
    state = applyEvent(state, envelopes[index]!, index + 1, now);
  return {
    activeRootKeyId: state.activeRootKeyId,
    recovery:        { ...state.recovery, keyIds: [...state.recovery.keyIds] },
    timestampKeyId:  state.timestampKeyId,
    revoked:         state.revoked,
    count:           envelopes.length,
    eventDigests:    envelopes.map(eventDigest),
    logSha256:       sha256Hex(bytes),
    retired:         [...state.retired].sort(),
    formerRecovery:  [...state.formerRecovery].sort(),
  };
}

const WALK_CACHE_LIMIT = 32;
const walkCache = new Map<string, RootWalk>();

/**
 * walkRootEvents with a cache of successful walks, keyed by the starting point and the log's SHA-256. A walk that
 * succeeded stays valid as time passes (only "issued in the future" depends on the clock, and that only relaxes),
 * so an unchanged log costs one hash. Failed walks are not cached.
 */
export function walkRootEventsCached(bytes: Uint8Array, start: RootStart, now: Date): RootWalk {
  const key = JSON.stringify([start.rootKeyId, recoverySetJson(start.recovery), start.timestampKeyId, start.eventsAfter, sha256Hex(bytes)]);
  const hit = walkCache.get(key);
  if (hit) {
    requireValidDate(now, 'Verification time');
    return cloneWalk(hit);
  }
  const walk = walkRootEvents(bytes, start, now);
  if (walkCache.size >= WALK_CACHE_LIMIT)
    walkCache.delete(walkCache.keys().next().value!);
  walkCache.set(key, cloneWalk(walk));
  return walk;
}

function cloneWalk(walk: RootWalk): RootWalk {
  return {
    ...walk,
    recovery:     { ...walk.recovery, keyIds: [...walk.recovery.keyIds] },
    revoked:      walk.revoked ? { ...walk.revoked } : null,
    eventDigests: [...walk.eventDigests],
    retired:      [...walk.retired],
    formerRecovery: [...walk.formerRecovery],
  };
}

/** Tests only. */
export function clearRootWalkCache(): void {
  walkCache.clear();
}
