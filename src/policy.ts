import { lstat, opendir, stat } from 'node:fs/promises';
import { homedir, hostname } from 'node:os';
import path from 'node:path';
import { canonicalBytes, exactKeys, isRecord, parseCanonicalJsonBytes, requireArray, requireString } from './canonical-json.ts';
import { appendToRegularFile, isInside, readRegularFile, realpathAllowingMissing, resolveInsideDirectory, writeFileAtomic } from './fs-safe.ts';
import { validateKeyId } from './keys.ts';
import {
  MAX_ROOT_EVENTS_BYTES, parseRecoverySet, walkRootEventsCached, type RecoverySet, type RootWalk,
} from './root-events.ts';
import { formatTimestamp, parseDuration } from './time.ts';
import { DEFAULT_MAX_TIMESTAMP_LIFETIME, MAX_TIMESTAMP_BYTES, MAX_TIMESTAMP_LIFETIME_MS, TimestampRollbackError, verifyTimestamp } from './timestamp.ts';
import { CERTIFICATE_FILENAME, sha256Hex } from './tree-digest.ts';
import {
  loadTrustContext, unverifiable, verifySkill, type CertificateSource, type MinimumVersions,
  type TrustContext, type TrustContextResult, type VerificationResult,
} from './verify.ts';

export const POLICY_VERSION    = 'mago.policy/v1';
/** Adds root recovery and freshness; a v2 host reads v1 policies unchanged. */
export const POLICY_VERSION_V2 = 'mago.policy/v2';
export const STATE_TYPE        = 'mago.host-state/v1';
export const STATE_TYPE_V2     = 'mago.host-state/v2';

const MAX_CERTIFICATE_BYTES               = 8 * 1024 * 1024;
/** Per-Skill budget across all certificate candidates (explicit file, policy directories, in-Skill file). */
export const MAX_CERTIFICATE_CANDIDATES   = 64;
export const MAX_CERTIFICATE_TOTAL_BYTES  = 32 * 1024 * 1024;
export type Mode = 'shadow' | 'enforce';

const POLICY_KEYS          = ['policy_version', 'mode', 'root_fingerprint', 'trust_root', 'revocations', 'certificate_dirs', 'skill_dirs', 'state_file', 'decision_log'];
const POLICY_V2_KEYS       = ['recovery', 'root_events', 'root_events_after', 'freshness'];
const REQUIRED_POLICY_KEYS = ['policy_version', 'mode', 'root_fingerprint', 'trust_root', 'revocations'];
const FRESHNESS_KEYS       = ['timestamp', 'key_id', 'max_lifetime'];

interface RootState {
  trust_root_version: number;
  revocations_version: number;
}

/** Host state: versions per root key (v1), plus root event progress per pinned root and timestamp versions per key (v2). */
export interface HostState {
  roots:      Record<string, RootState>;
  /** `revoked` is set when the last applied event left the root revoked (written only when true). */
  rootEvents: Record<string, { sequence: number; event_digest: string; revoked?: true }>;
  timestamps: Record<string, { version: number }>;
  /** The state was read as v2; it is never written back as v1. */
  v2:         boolean;
}

/*
 * Where hosts and the CLI read policy when none is given: $MAGO_SKI_POLICY (absolute, or "~/..."), else ~/.mago-ski/policy.json.
 * Never a path in the current directory, because the project being checked may be controlled by the code under review.
 */
export function defaultPolicyPath(
  env: NodeJS.ProcessEnv = process.env, 
  home: string = homedir()
): string {
  const configured = env.MAGO_SKI_POLICY;
  if (!configured) 
    return path.join(home, '.mago-ski', 'policy.json');
  
  if (configured === '~' || configured.startsWith('~/')) 
    return path.join(home, configured.slice(2));
  
  if (!path.isAbsolute(configured)) 
    throw new Error(`MAGO_SKI_POLICY must be an absolute path (or start with "~/"); got "${configured}"`);
  
  return configured;
}

export interface FreshnessPolicy {
  timestampPath:  string;
  /** The timestamp key trusted before any root event. */
  keyId:          string;
  maxLifetimeMs:  number;
}

export interface RecoveryPolicy {
  /** The recovery set trusted before any root event. */
  set:            RecoverySet;
  rootEventsPath: string;
  /** How many events root_fingerprint, recovery and freshness.key_id already reflect. */
  eventsAfter:    number;
  freshness:      FreshnessPolicy | null;
}

export interface Policy {
  path:             string;
  mode:             Mode;
  /** The pinned root key: the one trusted before any root event (it does not change after a rotation). */
  rootKeyId:        string;
  trustRootPath:    string;
  revocationsPath:  string;
  certificateDirs:  string[];
  skillDirs:        string[];
  statePath:        string | null;
  decisionLogPath:  string | null;
  /** Root recovery (policy v2 with a "recovery" block); null behaves exactly as a v1 policy. */
  recovery:         RecoveryPolicy | null;
}

/** Policy files are hand-edited JSON; paths are relative to the policy file's directory. */
export async function loadPolicy(policyPath: string): Promise<Policy> {
  const absolute  = path.resolve(policyPath);
  const bytes     = await readRegularFile(absolute, 'Policy file', 256 * 1024);
  let value: unknown;
  try {
    value = JSON.parse(bytes.toString('utf8'));
  } catch {
    throw new Error(`Policy file ${absolute} is not valid JSON`);
  }

  if (!isRecord(value)) 
    throw new Error('Policy file must contain a JSON object');

  if (value.policy_version !== POLICY_VERSION && value.policy_version !== POLICY_VERSION_V2)
    throw new Error(`Policy file must declare policy_version "${POLICY_VERSION}" or "${POLICY_VERSION_V2}"`);
  const v2 = value.policy_version === POLICY_VERSION_V2;

  for (const key of Object.keys(value)) 
    if (!POLICY_KEYS.includes(key) && !(v2 && POLICY_V2_KEYS.includes(key)))
      throw new Error(`Policy file has unsupported field "${key}"${POLICY_V2_KEYS.includes(key) ? ` (it needs policy_version "${POLICY_VERSION_V2}")` : ''}`);
  
  for (const key of REQUIRED_POLICY_KEYS) 
    if (!(key in value)) 
      throw new Error(`Policy file is missing "${key}"`);

  if (value.mode !== 'shadow' && value.mode !== 'enforce') 
    throw new Error('Policy mode must be "shadow" or "enforce"');
  
  const base = path.dirname(absolute);
  const resolvePath = (item: unknown, label: string) => 
    path.resolve(base, requireString(item, `Policy ${label}`, 4096));
  // decision_log and state_file are files this tool writes, so the policy may only place them in its own directory.
  const writablePath = async (item: unknown, label: string) =>
    item === undefined || item === null ? null : await resolveInsideDirectory(base, requireString(item, `Policy ${label}`, 4096), `Policy ${label}`);
  const optionalList = (item: unknown, label: string) => item === undefined ? [] : requireArray(item, `Policy ${label}`, 256).map((entry, index) => resolvePath(entry, `${label}[${index}]`));
  const rootKeyId = validateKeyId(value.root_fingerprint, 'Policy root_fingerprint');
  const policy: Policy = {
    path:             absolute,
    mode:             value.mode,
    rootKeyId,
    trustRootPath:    resolvePath(value.trust_root, 'trust_root'),
    revocationsPath:  resolvePath(value.revocations, 'revocations'),
    certificateDirs:  optionalList(value.certificate_dirs, 'certificate_dirs'),
    skillDirs:        optionalList(value.skill_dirs, 'skill_dirs'),
    statePath:        await writablePath(value.state_file, 'state_file'),
    decisionLogPath:  await writablePath(value.decision_log, 'decision_log'),
    recovery:         parseRecoveryPolicy(value, rootKeyId, resolvePath),
  };
  await rejectWriteTargetsThatOverlapInputs(policy);
  
  return policy;
}

/** The v2 fields. A policy without "recovery" must not use the other recovery fields: it behaves as v1. */
function parseRecoveryPolicy(
  value: Record<string, unknown>,
  rootKeyId: string,
  resolvePath: (item: unknown, label: string) => string,
): RecoveryPolicy | null {
  if (value.recovery === undefined) {
    for (const key of ['root_events', 'root_events_after', 'freshness'])
      if (value[key] !== undefined)
        throw new Error(`Policy "${key}" requires "recovery"`);
    return null;
  }
  const set = parseRecoverySet(value.recovery, 'Policy recovery');
  if (set.keyIds.includes(rootKeyId))
    throw new Error('Policy recovery key_ids must not include root_fingerprint');
  if (value.root_events === undefined)
    throw new Error('Policy "recovery" requires "root_events" (publish an empty log with "mago-ski root-events init")');
  const eventsAfter = value.root_events_after === undefined ? 0 : value.root_events_after;
  if (typeof eventsAfter !== 'number' || !Number.isSafeInteger(eventsAfter) || eventsAfter < 0)
    throw new Error('Policy root_events_after must be a non-negative integer');

  let freshness: FreshnessPolicy | null = null;
  if (value.freshness !== undefined) {
    if (!isRecord(value.freshness))
      throw new Error('Policy freshness must be a JSON object');
    for (const key of Object.keys(value.freshness))
      if (!FRESHNESS_KEYS.includes(key))
        throw new Error(`Policy freshness has unsupported field "${key}"`);
    const keyId = validateKeyId(value.freshness.key_id, 'Policy freshness key_id');
    if (keyId === rootKeyId || set.keyIds.includes(keyId))
      throw new Error('Policy freshness key_id must not be root_fingerprint or a recovery key');
    const lifetime = value.freshness.max_lifetime === undefined ? DEFAULT_MAX_TIMESTAMP_LIFETIME : requireString(value.freshness.max_lifetime, 'Policy freshness max_lifetime', 16);
    const maxLifetimeMs = parseDuration(lifetime, 'Policy freshness max_lifetime');
    if (maxLifetimeMs > MAX_TIMESTAMP_LIFETIME_MS)
      throw new Error('Policy freshness max_lifetime must be at most 7d');
    freshness = { timestampPath: resolvePath(value.freshness.timestamp, 'freshness timestamp'), keyId, maxLifetimeMs };
  }
  return { set, rootEventsPath: resolvePath(value.root_events, 'root_events'), eventsAfter, freshness };
}

/** A path with symlinks resolved where possible; falls back to the lexical path (the read itself will fail later). */
async function canonicalOrLexical(target: string): Promise<string> {
  try {
    return await realpathAllowingMissing(target);
  } catch {
    return path.resolve(target);
  }
}

/** decision_log and state_file are overwritten or appended to, so they must not be a file the policy reads. */
async function rejectWriteTargetsThatOverlapInputs(policy: Policy): Promise<void> {
  const inputs: Array<[string, string]>         = [
    ['the policy file', policy.path], ['trust_root', policy.trustRootPath], ['revocations', policy.revocationsPath],
    ...(policy.recovery ? [['root_events', policy.recovery.rootEventsPath] as [string, string]] : []),
    ...(policy.recovery?.freshness ? [['freshness timestamp', policy.recovery.freshness.timestampPath] as [string, string]] : []),
  ];
  const directories                             = await Promise.all(policy.certificateDirs.map(canonicalOrLexical));
  const targets: Array<[string, string | null]> = [['state_file', policy.statePath], ['decision_log', policy.decisionLogPath]];
  const seen: Array<[string, string]>           = [];
  
  for (const [label, target] of targets) {
    if (!target) 
      continue;
    
    const canonical = await canonicalOrLexical(target);
    for (const [name, input] of inputs) {
      if (canonical === await canonicalOrLexical(input)) 
        throw new Error(`Policy ${label} must not be ${name}`);
    }
    
    if (directories.some((directory) => isInside(directory, canonical))) 
      throw new Error(`Policy ${label} must not be inside a certificate_dirs directory`);
    
    for (const [other, otherPath] of seen) 
      if (canonical === otherPath) 
        throw new Error(`Policy ${label} must not be the same file as ${other}`);
    
    seen.push([label, canonical]);
  }
}

function stateCount(value: unknown, label: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1)
    throw new Error(`${label} must be a positive integer`);
  return value;
}

/** The host state file exists and was read, but its content or kind is wrong. Every other read error is not this. */
export class HostStateFormatError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'HostStateFormatError';
  }
}

const FORMAT_READ_ERROR = /(must be a regular, non-symlink file|exceeds the \d+-byte limit)$/;

async function readState(statePath: string): Promise<HostState> {
  let bytes: Buffer;
  try {
    bytes = await readRegularFile(statePath, 'Host state file', 1024 * 1024);
  } catch (error) {
    if ((error as NodeJS.ErrnoException)?.code === 'ENOENT') return { roots: {}, rootEvents: {}, timestamps: {}, v2: false };
    if (error instanceof Error && FORMAT_READ_ERROR.test(error.message)) throw new HostStateFormatError(error.message);
    throw error;
  }
  try {
    return parseState(bytes);
  } catch (error) {
    throw new HostStateFormatError((error as Error).message);
  }
}

function parseState(bytes: Buffer): HostState {
  const parsed = parseCanonicalJsonBytes(bytes, 'host state');
  const v2     = isRecord(parsed) && parsed.type === STATE_TYPE_V2;
  const value  = exactKeys(parsed, v2 ? ['type', 'roots', 'root_events', 'timestamps'] : ['type', 'roots'], 'host state');
  if ((value.type !== STATE_TYPE && !v2) || !isRecord(value.roots))
    throw new Error('host state file has an unsupported format');
  
  const state: HostState = { roots: {}, rootEvents: {}, timestamps: {}, v2 };
  for (const [rootKeyId, entry] of Object.entries(value.roots)) {
    const fields = exactKeys(entry, ['trust_root_version', 'revocations_version'], 'host state root');
    state.roots[validateKeyId(rootKeyId, 'host state root key')] = {
      trust_root_version:  stateCount(fields.trust_root_version, 'host state trust_root_version'),
      revocations_version: stateCount(fields.revocations_version, 'host state revocations_version'),
    };
  }
  if (v2) {
    if (!isRecord(value.root_events) || !isRecord(value.timestamps))
      throw new Error('host state file has an unsupported format');
    for (const [rootKeyId, entry] of Object.entries(value.root_events)) {
      const withRevoked = isRecord(entry) && 'revoked' in entry;
      const fields = exactKeys(entry, withRevoked ? ['sequence', 'event_digest', 'revoked'] : ['sequence', 'event_digest'], 'host state root_events');
      if (withRevoked && fields.revoked !== true)
        throw new Error('host state root_events revoked must be true when present');
      state.rootEvents[validateKeyId(rootKeyId, 'host state root_events key')] = {
        sequence:     stateCount(fields.sequence, 'host state root_events sequence'),
        event_digest: validateKeyId(fields.event_digest, 'host state root_events event_digest'),
        ...(withRevoked ? { revoked: true as const } : {}),
      };
    }
    for (const [keyId, entry] of Object.entries(value.timestamps)) {
      const fields = exactKeys(entry, ['version'], 'host state timestamps');
      state.timestamps[validateKeyId(keyId, 'host state timestamps key')] = { version: stateCount(fields.version, 'host state timestamp version') };
    }
  }
  return state;
}

/**
 * Combines this load's state with the state file as it is now, so two hosts sharing one state file (two Pi sessions,
 * Pi and the CLI) cannot erase each other's progress: every counter keeps its highest value, the root event entry
 * with the higher sequence wins (on a tie with different digests, the one already on disk stays, so the fork is
 * reported on the next load), and v2 is never written back as v1.
 */
export function mergeHostState(ours: HostState, disk: HostState): HostState {
  const merged: HostState = { roots: { ...disk.roots }, rootEvents: { ...disk.rootEvents }, timestamps: { ...disk.timestamps }, v2: ours.v2 || disk.v2 };
  for (const [keyId, entry] of Object.entries(ours.roots)) {
    const other = merged.roots[keyId];
    merged.roots[keyId] = other ? {
      trust_root_version:  Math.max(entry.trust_root_version, other.trust_root_version),
      revocations_version: Math.max(entry.revocations_version, other.revocations_version),
    } : entry;
  }
  for (const [keyId, entry] of Object.entries(ours.rootEvents)) {
    const other = merged.rootEvents[keyId];
    if (!other || entry.sequence > other.sequence) merged.rootEvents[keyId] = entry;
  }
  for (const [keyId, entry] of Object.entries(ours.timestamps)) {
    const other = merged.timestamps[keyId];
    if (!other || entry.version > other.version) merged.timestamps[keyId] = entry;
  }
  return merged;
}

function stateBytes(state: HostState): Buffer {
  if (!state.v2)
    return canonicalBytes({ type: STATE_TYPE, roots: state.roots });
  return canonicalBytes({ type: STATE_TYPE_V2, roots: state.roots, root_events: state.rootEvents, timestamps: state.timestamps });
}

/** Reads a file once, so the bytes that are hashed for freshness are the bytes that are parsed. */
async function readTrustFile(filePath: string, label: string, maxBytes: number): Promise<Buffer> {
  try {
    return await readRegularFile(filePath, label, maxBytes);
  } catch (error) {
    if ((error as NodeJS.ErrnoException)?.code === 'ENOENT' && (label === 'Root event log' || label === 'Timestamp'))
      throw new Error(`${label} not found: ${filePath}`);
    throw error;
  }
}

type RootProgress = NonNullable<HostState['rootEvents'][string]>;
/** `null`: the policy has no recovery; `{ error }`: the log could not be read. */
type RootEventLog = { bytes: Buffer } | { error: string } | null;

type RootCheck =
  | { ok: true; walk: RootWalk | null; activeRootKeyId: string; progress: RootProgress | null }
  | { ok: false; reason: string; rootRevoked: boolean; rollback?: true; walk: RootWalk | null; progress: RootProgress | null };

/*
 * A revoke this host has applied stays in force while the log cannot be checked: making the log missing, malformed,
 * shorter or forked must not turn root-revoked into trust-unavailable, which shadow mode would let through.
 */
function rootBlocked(problem: string, entry: RootProgress | undefined): { reason: string; rootRevoked: boolean } {
  return entry?.revoked
    ? { reason: `root key was revoked by root event ${entry.sequence}, and the root event log cannot be checked now (${problem}); waiting for a valid log with a rotation`, rootRevoked: true }
    : { reason: problem, rootRevoked: false };
}

/**
 * The root-event part of a load, without I/O: walks the log, compares it with what this host has applied (rollback,
 * fork), and says which progress to record. `loadPolicyTrust` and `loadPolicyRoot` both apply `progress` to their state.
 * Only a revoke result carries a walk on failure; a log that is old, forked or unreadable yields no walk and so no roles.
 */
function checkRootEvents(policy: Policy, state: HostState, log: RootEventLog, now: Date): RootCheck {
  const recovery = policy.recovery;
  const pinned   = policy.rootKeyId;
  if (!recovery || log === null) return { ok: true, walk: null, activeRootKeyId: pinned, progress: null };

  const seen = state.rootEvents[pinned];
  const stop = (problem: string, rollback?: true): RootCheck =>
    ({ ok: false, ...rootBlocked(problem, seen), ...(rollback ? { rollback } : {}), walk: null, progress: null });

  if ('error' in log) return stop(`root event log: ${log.error}`);
  let walk: RootWalk;
  try {
    walk = walkRootEventsCached(log.bytes, {
      rootKeyId: pinned, recovery: recovery.set, timestampKeyId: recovery.freshness?.keyId ?? null, eventsAfter: recovery.eventsAfter,
    }, now);
  } catch (error) {
    return stop(`root event log: ${(error as Error).message}`);
  }
  if (seen) {
    if (walk.count < seen.sequence)
      return stop(`root event log has ${walk.count} event(s), but this host has already applied ${seen.sequence} (rollback)`, true);
    if (walk.eventDigests[seen.sequence - 1] !== seen.event_digest)
      return stop(`root event ${seen.sequence} differs from the one this host already applied (fork); the organization must resolve it`);
  }
  // Only events this host checked are recorded: those before root_events_after were never verified here.
  const progress: RootProgress | null = walk.count > recovery.eventsAfter && (!seen || walk.count > seen.sequence)
    ? { sequence: walk.count, event_digest: walk.eventDigests[walk.count - 1]!, ...(walk.revoked ? { revoked: true as const } : {}) }
    : null;
  if (walk.revoked) {
    return {
      ok: false, rootRevoked: true, walk, progress,
      reason: `root key ${walk.activeRootKeyId} was revoked by root event ${walk.revoked.sequence} (${walk.revoked.reason}); waiting for a rotation`,
    };
  }
  return { ok: true, walk, activeRootKeyId: walk.activeRootKeyId, progress };
}

async function readRootEventLog(policy: Policy): Promise<RootEventLog> {
  if (!policy.recovery) return null;
  try {
    return { bytes: await readTrustFile(policy.recovery.rootEventsPath, 'Root event log', MAX_ROOT_EVENTS_BYTES) };
  } catch (error) {
    return { error: (error as Error).message };
  }
}

/** Applies a progress entry to a state, as the loads record it. */
function applyProgress(state: HostState, pinned: string, progress: RootProgress): void {
  state.v2 = true;
  state.rootEvents[pinned] = progress;
}

/**
 * Merges `state` with the state file as it is now and writes the result. An unreadable file is replaced by this
 * load's state, as before. Returns the merged state, or the reason the write failed.
 */
const persistChains = new Map<string, Promise<unknown>>();

async function persistState(statePath: string, state: HostState): Promise<{ state: HostState } | { error: string }> {
  const key = await canonicalOrLexical(statePath);
  const previous = persistChains.get(key) ?? Promise.resolve();
  const run = previous.then(() => persistStateNow(statePath, state));
  const tail = run.catch(() => undefined);
  persistChains.set(key, tail);
  try {
    return await run;
  } finally {
    if (persistChains.get(key) === tail) persistChains.delete(key);
  }
}

async function persistStateNow(statePath: string, state: HostState): Promise<{ state: HostState } | { error: string }> {
  try {
    let disk: HostState | null = null;
    try {
      disk = await readState(statePath);
    } catch (error) {
      if ((error as NodeJS.ErrnoException)?.code !== 'ENOENT') throw error;
    }
    const merged = disk ? mergeHostState(state, disk) : state;
    await writeFileAtomic(statePath, stateBytes(merged), 0o600);
    return { state: merged };
  } catch (error) {
    return { error: `cannot record trust versions in ${statePath}: ${(error as Error).message}` };
  }
}

const stateErrorKind = (error: unknown): 'corrupt' | 'unreadable' => error instanceof HostStateFormatError ? 'corrupt' : 'unreadable';

export type StateErrorKind = 'corrupt' | 'unreadable' | 'write';

type FailureExtra = { rootRevoked?: boolean; rollback?: true; stateError?: StateErrorKind };

const failure = (reason: string, extra: FailureExtra = {}): TrustContextResult =>
  ({ ok: false, verdict: 'UNVERIFIABLE', reason, ...extra });

export type PolicyRootResult =
  | { ok: true; walk: RootWalk | null; activeRootKeyId: string }
  | { ok: false; reason: string; rootRevoked: boolean; walk: RootWalk | null; rollback?: true; stateError?: StateErrorKind };

/**
 * Only the root-event part of `loadPolicyTrust`: which root key is active, whether it is revoked, and the walk. It
 * reads the state and the log, checks rollback and forks the same way, and with `recordVersions` (the default) and a
 * state file records the progress with the same merge-before-write. A policy without `recovery` reads nothing.
 */
export async function loadPolicyRoot(policy: Policy, now: Date, options: { recordVersions?: boolean } = {}): Promise<PolicyRootResult> {
  if (!policy.recovery) return { ok: true, walk: null, activeRootKeyId: policy.rootKeyId };
  const pinned = policy.rootKeyId;
  let state: HostState = { roots: {}, rootEvents: {}, timestamps: {}, v2: false };
  try {
    if (policy.statePath) state = await readState(policy.statePath);
  } catch (error) {
    return { ok: false, reason: (error as Error).message, rootRevoked: false, walk: null, stateError: stateErrorKind(error) };
  }
  const checked = checkRootEvents(policy, state, await readRootEventLog(policy), now);
  if (checked.progress) applyProgress(state, pinned, checked.progress);

  if (checked.progress && options.recordVersions !== false && policy.statePath !== null) {
    const saved = await persistState(policy.statePath, state);
    if ('error' in saved) {
      // A revoke stays reported as a revoke even when it could not be recorded.
      if (!checked.ok) return { ok: false, reason: checked.reason, rootRevoked: checked.rootRevoked, walk: checked.walk, ...(checked.rollback ? { rollback: true as const } : {}) };
      return { ok: false, reason: saved.error, rootRevoked: false, walk: null, stateError: 'write' };
    }
    const merged = saved.state.rootEvents[pinned];
    if (checked.ok && checked.walk && merged && merged.sequence > checked.walk.count)
      return { ok: false, ...rootBlocked(`root event log has ${checked.walk.count} event(s), but this host has already applied ${merged.sequence} (rollback)`, merged), walk: null, rollback: true };
  }
  if (!checked.ok)
    return { ok: false, reason: checked.reason, rootRevoked: checked.rootRevoked, walk: checked.walk, ...(checked.rollback ? { rollback: true as const } : {}) };
  return { ok: true, walk: checked.walk, activeRootKeyId: checked.activeRootKeyId };
}

/**
 * Loads trust documents for a policy, enforcing rollback protection through the state file.
 * With `recordVersions: false` the state file is still read (the same rollback minimums apply) but never written:
 * for observers such as the GUI, which must not move a host's rollback memory.
 *
 * With root recovery (policy v2), the order is: walk the root event log, check rollback and forks, stop if the active
 * root is revoked (`rootRevoked`, which blocks in every mode), check the timestamp, then the trust root and revocation
 * list against the active root, then record the new state.
 */
export async function loadPolicyTrust(policy: Policy, now: Date, options: { recordVersions?: boolean } = {}): Promise<TrustContextResult> {
  const record = options.recordVersions !== false && policy.statePath !== null;
  let state: HostState = { roots: {}, rootEvents: {}, timestamps: {}, v2: false };
  try {
    if (policy.statePath) state = await readState(policy.statePath);
  } catch (error) {
    return failure((error as Error).message, { stateError: stateErrorKind(error) });
  }
  const recovery = policy.recovery;
  const pinned = policy.rootKeyId;
  let activeRootKeyId = pinned;
  let walk: RootWalk | null = null;
  let logBytes: Buffer | null = null;

  // Root event progress is recorded as soon as the log is accepted, even if a later step fails: the events are signed
  // by recovery keys, and remembering them is what stops a host being moved back to a log without a revoke.
  let stateChanged = false;
  const saveState = async (): Promise<TrustContextResult | null> => {
    if (!record || !stateChanged) return null;
    const saved = await persistState(policy.statePath!, state);
    if ('error' in saved) return failure(saved.error, { stateError: 'write' });
    state = saved.state;
    stateChanged = false;
    // Another load on this host may have applied later root events meanwhile; this load's log is then a rollback.
    const merged = state.rootEvents[pinned];
    if (walk && merged && merged.sequence > walk.count) {
      const { reason, rootRevoked } = rootBlocked(`root event log has ${walk.count} event(s), but this host has already applied ${merged.sequence} (rollback)`, merged);
      return failure(reason, { ...(rootRevoked ? { rootRevoked } : {}), rollback: true });
    }
    return null;
  };

  if (recovery) {
    const log = await readRootEventLog(policy);
    const checked = checkRootEvents(policy, state, log, now);
    if (checked.progress) {
      applyProgress(state, pinned, checked.progress);
      stateChanged = true;
    }
    walk = checked.walk;
    if (!checked.ok) {
      if (checked.progress) await saveState();
      return failure(checked.reason, { ...(checked.rootRevoked ? { rootRevoked: true } : {}), ...(checked.rollback ? { rollback: true as const } : {}) });
    }
    logBytes = log !== null && 'bytes' in log ? log.bytes : null;
    activeRootKeyId = checked.activeRootKeyId;
  }

  let trustRootBytes: Buffer;
  let revocationsBytes: Buffer;
  let timestampBytes: Buffer | null = null;
  try {
    trustRootBytes   = await readTrustFile(policy.trustRootPath, 'Trust root', 4 * 1024 * 1024);
    revocationsBytes = await readTrustFile(policy.revocationsPath, 'Revocation list', 8 * 1024 * 1024);
    if (recovery?.freshness) timestampBytes = await readTrustFile(recovery.freshness.timestampPath, 'Timestamp', MAX_TIMESTAMP_BYTES);
  } catch (error) {
    return await saveState() ?? failure((error as Error).message);
  }

  let timestamp: ReturnType<typeof verifyTimestamp> | null = null;
  if (recovery?.freshness) {
    // Freshness is configured, so a missing input fails closed instead of skipping the check.
    if (!walk || !logBytes || !timestampBytes || walk.timestampKeyId === null)
      return await saveState() ?? failure('freshness: the timestamp could not be checked');
    const timestampKeyId = walk.timestampKeyId;
    try {
      timestamp = verifyTimestamp(timestampBytes, {
        keyId: timestampKeyId, now, maxLifetimeMs: recovery.freshness.maxLifetimeMs,
        minimumVersion: state.timestamps[timestampKeyId]?.version,
        inputs: {
          rootEvents:  { sha256: walk.logSha256, count: walk.count },
          trustRoot:   { sha256: sha256Hex(trustRootBytes) },
          revocations: { sha256: sha256Hex(revocationsBytes) },
        },
      });
    } catch (error) {
      return await saveState() ?? failure(`freshness: ${(error as Error).message}`, error instanceof TimestampRollbackError ? { rollback: true } : {});
    }
  }

  const seen = state.roots[activeRootKeyId];
  const minimum: MinimumVersions | undefined = seen ? { trustRootVersion: seen.trust_root_version, revocationsVersion: seen.revocations_version } : undefined;
  const result = loadTrustContext({ trustRootBytes, revocationsBytes, rootKeyId: activeRootKeyId, now, minimum });
  if (!result.ok)
    return await saveState() ?? result;

  const { trustRoot, revocations } = result.context;
  if (walk) {
    const collision = trustRoot.approvers.find((approver) => walk.recovery.keyIds.includes(approver.keyId) || approver.keyId === walk.timestampKeyId);
    if (collision)
      return await saveState() ?? failure(`trust root lists approver ${collision.keyId}, which is a recovery or timestamp key; no key may hold two roles`);
  }
  if (timestamp && (timestamp.trustRoot.version !== trustRoot.version || timestamp.revocations.version !== revocations.version))
    return await saveState() ?? failure('freshness: the trust root or revocation list version does not match the timestamp');

  const next = { trust_root_version: trustRoot.version, revocations_version: revocations.version };
  if (!seen || next.trust_root_version > seen.trust_root_version || next.revocations_version > seen.revocations_version) {
    state.roots[activeRootKeyId] = {
      trust_root_version:   Math.max(next.trust_root_version, seen?.trust_root_version ?? 0),
      revocations_version:  Math.max(next.revocations_version, seen?.revocations_version ?? 0),
    };
    stateChanged = true;
  }
  if (timestamp && walk?.timestampKeyId) {
    const previous = state.timestamps[walk.timestampKeyId]?.version ?? 0;
    if (timestamp.version > previous) {
      state.v2 = true;
      state.timestamps[walk.timestampKeyId] = { version: timestamp.version };
      stateChanged = true;
    }
  }
  const problem = await saveState();
  if (problem) return problem;

  if (walk) {
    result.context.root = {
      pinnedRootKeyId: policy.rootKeyId,
      activeRootKeyId,
      sequence:        walk.count,
      recovery:        walk.recovery,
      timestampKeyId:  walk.timestampKeyId,
      timestamp:       timestamp ? { version: timestamp.version, expiresAt: timestamp.expiresAt } : null,
    };
  }
  return result;
}

async function readOptional(filePath: string, label: string): Promise<Buffer | undefined> {
  try {
    return await readRegularFile(filePath, label, MAX_CERTIFICATE_BYTES);
  } catch (error) {
    if ((error as NodeJS.ErrnoException)?.code === 'ENOENT') 
      return undefined;
    throw error;
  }
}

/*
 * Certificate lookup order: explicit file, policy certificate directories (<name>.cert.json), then the in-Skill certificate.
 * Candidates are read lazily, one at a time, so a caller that stops early never reads the rest and none are retained here.
 * Candidates come from the checkout under review, so a Skill may have at most MAX_CERTIFICATE_CANDIDATES candidate files
 * totalling MAX_CERTIFICATE_TOTAL_BYTES; going over throws (the Skill is UNVERIFIABLE) instead of reading further.
 */
export async function* iterateCertificates(
  skillName:        string, 
  skillRoot:        string, 
  certificateDirs:  string[], 
  explicit?:        string
): AsyncGenerator<CertificateSource> {
  let count = 0;
  let totalBytes = 0;
  const seen = new Set<string>();
  const account = (source: string, bytes: Buffer): CertificateSource => {
    count += 1;
    totalBytes += bytes.length;
    if (count > MAX_CERTIFICATE_CANDIDATES) 
      throw new Error(`more than ${MAX_CERTIFICATE_CANDIDATES} certificate candidates for this Skill; reduce certificate_dirs or remove stray certificates`);
    
    if (totalBytes > MAX_CERTIFICATE_TOTAL_BYTES) 
      throw new Error(`certificate candidates for this Skill exceed ${MAX_CERTIFICATE_TOTAL_BYTES} bytes in total`);
    return { source, bytes };
  };

  if (explicit) {
    const candidate = path.resolve(explicit);
    seen.add(candidate);
    yield account(candidate, await readRegularFile(candidate, 'Certificate', MAX_CERTIFICATE_BYTES));
  }

  for (const directory of certificateDirs) {
    const candidate = path.join(directory, `${skillName}.cert.json`);
    
    if (seen.has(candidate)) 
      continue;
    seen.add(candidate);
    
    const bytes = await readOptional(candidate, 'Certificate');
    if (bytes) 
      yield account(candidate, bytes);
  }

  const inSkill = path.join(skillRoot, CERTIFICATE_FILENAME);
  if (!seen.has(inSkill)) {
    const bytes = await readOptional(inSkill, 'Certificate');
    if (bytes) yield account(inSkill, bytes);
  }
}

/** Collects every candidate (within the same budget). Prefer `iterateCertificates`, which retains nothing. */
export async function discoverCertificates(
  skillName:        string, 
  skillRoot:        string, 
  certificateDirs:  string[], 
  explicit?:        string
): Promise<CertificateSource[]> {
  const sources: CertificateSource[] = [];
  for await (const source of iterateCertificates(skillName, skillRoot, certificateDirs, explicit)) 
  sources.push(source);
  return sources;
}

/**
 * Finds Skill directories (directories containing SKILL.md) under the given roots.
 * Symbolic links are never skipped silently: hosts such as Pi follow them, so a linked Skill
 * directory or a linked SKILL.md is returned as a Skill, and verification then rejects it.
 */
export const MAX_DISCOVERY_DEPTH = 16;
/** Work budget for one discovery run over untrusted trees; exceeding either throws DiscoveryBudgetError. */
export const MAX_DISCOVERED_SKILLS = 1_000;
export const MAX_DISCOVERY_ENTRIES = 50_000;

export interface DiscoveryLimits {
  /** Maximum Skills (including directories reported as too deep) found. */
  maxSkills?: number;
  /** Maximum directory entries visited across all roots. */
  maxEntries?: number;
}

/** Discovery stopped because the tree is larger than the budget. It never returns a partial list: callers must fail closed. */
export class DiscoveryBudgetError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'DiscoveryBudgetError';
  }
}

export interface SkillDiscovery {
  skillDirs:  string[];
  /*  * Directories at the depth limit that have subdirectories; 
      * Skills below them were not searched. */
  tooDeep:    string[];
}

export async function findSkillDirs(roots: string[], maxDepth = MAX_DISCOVERY_DEPTH, limits: DiscoveryLimits = {}): Promise<SkillDiscovery> {
  const maxSkills     = limits.maxSkills ?? MAX_DISCOVERED_SKILLS;
  const maxEntries    = limits.maxEntries ?? MAX_DISCOVERY_ENTRIES;
  const found         = new Set<string>();
  const tooDeep       = new Set<string>();
  let entries = 0;
  const checkSkills   = () => {
    if (found.size + tooDeep.size > maxSkills) 
      throw new DiscoveryBudgetError(`more than ${maxSkills} Skills found under skill_dirs; narrow skill_dirs or split the repository`);
  };
  
  async function walk(
    directory: string, 
    depth: number
  ): Promise<void> {
    try {
      await lstat(path.join(directory, 'SKILL.md'));
      found.add(directory);
      checkSkills();
      return;
    } 
    catch (error) {
      if ((error as NodeJS.ErrnoException)?.code !== 'ENOENT') 
        throw error;
    }
    
    let dir;
    try {
      dir = await opendir(directory);
    } 
    catch (error) {
      if ((error as NodeJS.ErrnoException)?.code === 'ENOENT') 
        return;
      throw error;
    }
    
    for await (const child of dir) {
      entries += 1;
      if (entries > maxEntries) 
        throw new DiscoveryBudgetError(`more than ${maxEntries} directory entries under skill_dirs; narrow skill_dirs or split the repository`);

      const childPath = path.join(directory, child.name);
      if (child.isSymbolicLink()) {
        try {
          if ((await stat(childPath)).isDirectory()) 
            found.add(childPath);
        } catch {
          // A dangling link has nothing a host could load.
        }
        checkSkills();
        continue;
      }
      
      if (!child.isDirectory() || child.name === '.git' || child.name === 'node_modules') 
        continue;
      // Hosts such as Pi search without a depth limit, so never skip deeper directories silently.
      if (depth + 1 > maxDepth) {
        tooDeep.add(childPath);
        checkSkills();
        continue;
      }
      await walk(childPath, depth + 1);
    }
  }
  for (const root of roots) 
    await walk(path.resolve(root), 0);
  return { skillDirs: [...found].sort(), tooDeep: [...tooDeep].sort() };
}

/** Result for a directory discovery could not search; it fails in enforce mode and is reported in shadow mode. */
export function tooDeepResult(directory: string, now: Date): VerificationResult {
  return unverifiable(directory, path.basename(directory),
    `directory is deeper than the discovery limit (${MAX_DISCOVERY_DEPTH} levels below skill_dirs); Skills below it were not checked. Point skill_dirs closer to the Skills`, now);
}

export interface DecisionRecord {
  timestamp:        string;
  host:             string;
  mode:             Mode;
  action:           'allow' | 'block' | 'would-block';
  event:            string;
  skill:            string;
  skill_dir:        string;
  digest:           string | null;
  certificate_id:   string | null;
  verdict:          string;
  reason:           string;
}

/** Event names for a failure of the trust documents, reported once per host instead of once per Skill. */
export type TrustFailureEvent = 'root-revoked' | 'trust-unavailable';

export function trustFailureEvent(failure: { rootRevoked?: boolean | undefined }): TrustFailureEvent {
  return failure.rootRevoked ? 'root-revoked' : 'trust-unavailable';
}

/**
 * The mode a host acts in for this trust state. A revoked root is a signed statement that the trust anchor is not
 * sound, so it blocks in shadow mode too; no policy setting changes that. Every other failure follows the policy.
 */
export function effectiveMode(mode: Mode, trust: TrustContextResult | { ok: false; rootRevoked?: boolean | undefined } | null | undefined): Mode {
  return trust && !trust.ok && trust.rootRevoked ? 'enforce' : mode;
}

/** The single decision-log record for a trust failure: empty skill and skill_dir, null digest and certificate_id. */
export function trustFailureRecord(
  failure: { reason: string; rootRevoked?: boolean | undefined },
  mode: Mode,
  now: Date,
  host = `${hostname()}`,
): DecisionRecord {
  return {
    timestamp:      formatTimestamp(now),
    host,
    mode,
    action:         failure.rootRevoked ? 'block' : actionFor(mode, false),
    event:          trustFailureEvent(failure),
    skill:          '',
    skill_dir:      '',
    digest:         null,
    certificate_id: null,
    verdict:        'UNVERIFIABLE',
    reason:         failure.reason,
  };
}

export function actionFor(mode: Mode, verified: boolean): DecisionRecord['action'] {
  if (verified) 
    return 'allow';
  
  return mode === 'enforce' ? 'block' : 'would-block';
}

export async function appendDecision(
  logPath: string | null, 
  record: DecisionRecord
): Promise<void> {
  if (!logPath) 
    return;
  // One JSON object per line. JSON.stringify escapes newlines and control characters; also escape the Unicode
  // line separators some JSON Lines readers split on, plus C1 controls, DEL and bidi controls. The text is data, not shell syntax: never source a log.
  const line = JSON.stringify(record).replace(/[\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]/gu, (char) => `\\u${char.charCodeAt(0).toString(16).padStart(4, '0')}`);
  
  await appendToRegularFile(logPath, `${line}\n`, 'Decision log');
}

/* */
export function decisionRecord(
  result: VerificationResult, 
  mode: Mode, 
  event: string, 
  host = `${hostname()}`
): DecisionRecord {
  return {
    timestamp:        result.checkedAt,
    host,
    mode,
    action:           actionFor(mode, result.verdict === 'VERIFIED'),
    event,
    skill:            result.skillName,
    skill_dir:        result.skillDir,
    digest:           result.digest,
    certificate_id:   result.certificateId,
    verdict:          result.verdict,
    reason:           result.reason,
  };
}

/** Verifies one Skill under a policy, including trust loading. */
export async function verifyWithPolicy(
  policy: Policy, 
  skillDir: string, 
  options: { 
    now: Date; 
    skillName?: string; 
    certificate?: string; 
    context?: TrustContext 
  }): Promise<VerificationResult> {
  let context = options.context;
  if (!context) {
    const loaded = await loadPolicyTrust(policy, options.now);
    if (!loaded.ok) 
      return unverifiable(path.resolve(skillDir), options.skillName ?? path.basename(path.resolve(skillDir)), loaded.reason, options.now, loaded.verdict);
    
    context = loaded.context;
  }

  return verifySkill({
    skillDir,
    skillName:    options.skillName,
    context,
    now:          options.now,
    certificates: (name, root) => iterateCertificates(name, root, policy.certificateDirs, options.certificate),
  });
}

