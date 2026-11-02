// Session admission and the generation-set rule.
// A session's set for Skill N = the generation of N current at the session's admission sequence (if any)
// + every digest published for N after it. It is derived from one append-only publication log; sessions store
// only their admission sequence. The gate allows N in S only if EVERY digest in that set is still VERIFIED.
// Single writer process per directory (as trust-store.ts); the directory must be root-only.
// Same-seq tampering (rewriting a log entry in place) needs write access to that root-only directory; the file has
// no MAC, so the directory permission is the control.
// Session refs MUST be minted by the service and bound to the host process by the service (packet 6), never an
// employee-supplied id; only authenticated host lifecycle events may call admitSession/endSession. Ended or expired
// refs are tombstoned until the boot id changes, so a ref cannot be re-admitted to shed its history.
// TIME. Every time here is boot-relative milliseconds (`bootMs`, a non-negative safe integer), never wall-clock time.
// The caller MUST pass CLOCK_BOOTTIME-based values: its own "now" from /proc/uptime, and a host process start from
// /proc/<pid>/stat field 22 / CLK_TCK. Those are immune to wall-clock steps; sessions are per boot already (bootId).
// CALLER CONTRACT: (1) read the bootMs passed to publish() AFTER the new generation is installed and visible to hosts
// (a stamp earlier than visibility by more than START_MARGIN_MS lets a host that started in between hold the old
// generation unrecorded); (2) bootId must be /proc/sys/kernel/random/boot_id, which changes on every boot.
// Each log entry stores `at_boot_ms`. The store persists `high_boot_ms` (largest bootMs seen) and refuses any operation
// below it (`clock-moved-backwards`), except uninstall, which still succeeds and is stamped max(bootMs, high). So stored
// times never decrease, and a later publish can never look earlier than an earlier one.
// A session's admission point is the last entry with at_boot_ms <= startedBootMs - START_MARGIN_MS (conservatively
// earlier than the host start), so a Skill version the host snapshotted before the SessionStart hook reached us still counts.
// Compaction folds only entries older than MAX_STARTUP_AGE_MS (vs high_boot_ms) and than every open session's point.
// `folded_at_boot_ms` is the at_boot_ms of the newest folded entry (0 = none); an admission whose point is at or before
// it is refused (`invalid-start`), because `base` cannot reconstruct what was current before the fold.
// A boot id change folds the whole log into `base` (boot-relative times of the old boot are meaningless), clears
// sessions and tombstones, resets high_boot_ms and folded_at_boot_ms to 0, and keeps current installs.
// `assess` runs `check` outside the lock. That is safe because the service publishes only VERIFIED generations and
// a revocation is a trust-state change that every later `check` sees; a stale answer can only be one decision old.
// Compaction folds log entries up to the oldest open session's sequence into `base` (current per Skill at that
// point), so no history an open session depends on is lost. Bounds fail closed (refuse / deny), never drop history.
import { constants as fsConstants } from 'node:fs';
import { lstat, mkdir, open, readdir } from 'node:fs/promises';
import path from 'node:path';
import { canonicalBytes, exactKeys, MAX_CANONICAL_JSON_BYTES, parseCanonicalJsonBytes, requireArray, requireString } from '../canonical-json.ts';
import { readRegularFile, writeFileAtomic } from '../fs-safe.ts';
import { VERDICT_RANK, type Verdict } from '../verify.ts';
import type { GateErrorCode } from './contract.ts';

export const MAX_SESSIONS = 1024;
export const MAX_LOG = 4096;
export const MAX_SET = 64;
/** Ended/expired refs remembered per boot; open sessions + tombstones never exceed this (fail closed when full). */
export const MAX_TOMBSTONES = 4 * MAX_SESSIONS;
/** Oldest host start time admission accepts; compaction never folds log entries newer than this. */
export const MAX_STARTUP_AGE_MS = 24 * 60 * 60 * 1000;
/** Fixed margin between two CLOCK_BOOTTIME readings (no wall-clock skew exists); the admission point is this much earlier than the host start. */
export const START_MARGIN_MS = 1000;
/** Uninstalls are exempt from MAX_LOG (revoke must always be able to uninstall); the parse bound allows for them. */
const MAX_LOG_PARSE = 2 * MAX_LOG;

/** `no-session-record` and `internal` come from contract.ts; the others are local to admission. */
export type AssessError = Extract<GateErrorCode, 'no-session-record' | 'internal'> | 'not-installed' | 'state-corrupt' | 'bound-exceeded';
export type AssessResult = { kind: 'verdict'; verdict: Verdict; digests: string[] } | { kind: 'error'; reason: AssessError };
export type MutationResult = { ok: true } | { ok: false; reason: 'state-corrupt' | 'session-exists' | 'session-ended' | 'invalid-start' | 'session-limit' | 'log-full' | 'write-failed' | 'clock-moved-backwards' };

export interface AdmissionStore {
  publish(name: string, digest: string, bootMs: number): Promise<MutationResult>;
  uninstall(name: string, bootMs: number): Promise<MutationResult>;
  admitSession(sessionRef: string, bootMs: number, options: { startedBootMs: number }): Promise<MutationResult>;
  endSession(sessionRef: string): Promise<MutationResult>;
  expireSessions(maxAgeMs: number, bootMs: number): Promise<MutationResult & { expired?: number }>;
  assess(sessionRef: string, name: string, check: (name: string, digest: string) => Promise<Verdict>): Promise<AssessResult>;
}

interface LogEntry { seq: number; name: string; digest: string | null; at: number }
interface Session { seq: number; at: number }
interface State { bootId: string; seq: number; high: number; folded: number; log: LogEntry[]; base: Map<string, string>; sessions: Map<string, Session>; ended: Set<string> }

const FILE = 'admission.json';
const TYPE = 'mago.gate-admission/v1';

const toBytes = (s: State): Buffer => canonicalBytes({
  type: TYPE, boot_id: s.bootId, seq: s.seq, high_boot_ms: s.high, folded_at_boot_ms: s.folded,
  log: s.log.map((e) => ({ seq: e.seq, name: e.name, digest: e.digest, at_boot_ms: e.at })),
  base: [...s.base].map(([name, digest]) => ({ name, digest })),
  sessions: [...s.sessions].map(([ref, v]) => ({ ref, seq: v.seq, at_boot_ms: v.at })),
  ended: [...s.ended],
});

function seqOf(v: unknown): number {
  if (typeof v !== 'number' || !Number.isSafeInteger(v) || v < 0) throw new Error('invalid sequence');
  return v;
}

function parse(bytes: Uint8Array): State {
  const o = exactKeys(parseCanonicalJsonBytes(bytes, 'admission state'), ['type', 'boot_id', 'seq', 'high_boot_ms', 'folded_at_boot_ms', 'log', 'base', 'sessions', 'ended'], 'admission state');
  if (o.type !== TYPE) throw new Error('unsupported type');
  const seq = seqOf(o.seq);
  const high = seqOf(o.high_boot_ms);
  const folded = seqOf(o.folded_at_boot_ms);
  const log = requireArray(o.log, 'log', MAX_LOG_PARSE).map((v): LogEntry => {
    const e = exactKeys(v, ['seq', 'name', 'digest', 'at_boot_ms'], 'log entry');
    return { seq: seqOf(e.seq), name: requireString(e.name, 'name', 128), digest: e.digest === null ? null : requireString(e.digest, 'digest', 128), at: seqOf(e.at_boot_ms) };
  });
  log.forEach((e, i) => { if (e.seq > seq || (i > 0 && e.seq <= log[i - 1]!.seq)) throw new Error('log is not ordered'); });
  log.forEach((e, i) => { if ((i > 0 && e.at < log[i - 1]!.at) || e.at > high || e.at < folded) throw new Error('log times are not monotonic'); });
  if (folded > high) throw new Error('fold watermark is ahead of the clock');
  const baseRows = requireArray(o.base, 'base', MAX_CANONICAL_JSON_BYTES).map((v): [string, string] => {
    const e = exactKeys(v, ['name', 'digest'], 'base entry');
    return [requireString(e.name, 'name', 128), requireString(e.digest, 'digest', 128)];
  });
  const base = new Map(baseRows);
  if (base.size !== baseRows.length) throw new Error('duplicate base name');
  const sessionRows = requireArray(o.sessions, 'sessions', MAX_SESSIONS).map((v): [string, Session] => {
    const e = exactKeys(v, ['ref', 'seq', 'at_boot_ms'], 'session');
    const s = seqOf(e.seq);
    if (s > seq) throw new Error('session is ahead of the log');
    return [requireString(e.ref, 'ref', 256), { seq: s, at: seqOf(e.at_boot_ms) }];
    // (session time is bounded by high below)
  });
  const sessions = new Map(sessionRows);
  if (sessions.size !== sessionRows.length) throw new Error('duplicate session ref');
  const endedRows = requireArray(o.ended, 'ended', MAX_TOMBSTONES).map((v) => requireString(v, 'ended ref', 256));
  const ended = new Set(endedRows);
  for (const r of sessions.keys()) if (ended.has(r)) throw new Error('ref is both open and ended');
  for (const v of sessions.values()) if (v.at > high) throw new Error('session is ahead of the clock');
  if (ended.size !== endedRows.length) throw new Error('duplicate ended ref');
  if (ended.size + sessions.size > MAX_TOMBSTONES) throw new Error('too many session refs');
  return { bootId: requireString(o.boot_id, 'boot_id', 128), seq, high, folded, log, base, sessions, ended };
}

const clone = (s: State): State => ({ ...s, log: [...s.log], base: new Map(s.base), sessions: new Map(s.sessions), ended: new Set(s.ended) });

function currentAt(s: State, name: string, at: number): string | null {
  for (let i = s.log.length - 1; i >= 0; i--) {
    const e = s.log[i]!;
    if (e.name === name && e.seq <= at) return e.digest;
  }
  return s.base.get(name) ?? null;
}

function setFor(s: State, name: string, at: number): string[] {
  const out: string[] = [];
  const first = currentAt(s, name, at);
  if (first !== null) out.push(first);
  for (const e of s.log) if (e.name === name && e.seq > at && e.digest !== null && !out.includes(e.digest)) out.push(e.digest);
  return out;
}

/** Fold entries no open session or admission can still need: older than every open session's point and than the startup window. */
function compact(s: State, nowMs: number): void {
  const windowStart = nowMs - MAX_STARTUP_AGE_MS;
  let windowSeq = 0; // last seq of the maximal log prefix older than the window
  for (const e of s.log) { if (e.at >= windowStart) break; windowSeq = e.seq; }
  const fold = Math.min(windowSeq, ...[...s.sessions.values()].map((v) => v.seq));
  const keep: LogEntry[] = [];
  for (const e of s.log) {
    if (e.seq > fold) { keep.push(e); continue; }
    if (e.digest === null) s.base.delete(e.name); // not installed == absent from base
    else s.base.set(e.name, e.digest);
    s.folded = Math.max(s.folded, e.at);
  }
  s.log = keep;
}

function requireBootMs(v: unknown, label: string): number {
  if (typeof v !== 'number' || !Number.isSafeInteger(v) || v < 0) throw new Error(`${label} must be a non-negative integer (boot ms)`);
  return v;
}
const BACKWARDS = { ok: false, reason: 'clock-moved-backwards' } as const;

export async function openAdmissionStore(dir: string, options: { bootId: string }): Promise<AdmissionStore> {
  const bootId = requireString(options.bootId, 'bootId', 128);
  dir = path.resolve(dir);
  await mkdir(dir, { mode: 0o700 }).catch((e) => { if ((e as NodeJS.ErrnoException)?.code !== 'EEXIST') throw e; });
  const info = await lstat(dir);
  if (info.isSymbolicLink() || !info.isDirectory()) throw new Error('admission directory must be a real directory, not a symlink');
  if ((info.mode & 0o022) !== 0) throw new Error('admission directory must not be group- or world-writable');

  const file = path.join(dir, FILE);
  let corrupt = false;
  let held: Buffer | null = null;
  let state: State | null = null;

  async function read(): Promise<Buffer | null> {
    try { return await readRegularFile(file, 'admission state', MAX_CANONICAL_JSON_BYTES); } catch (e) {
      if ((e as NodeJS.ErrnoException)?.code !== 'ENOENT') throw e;
      // A missing state file is a fresh store only if the directory is otherwise empty.
      if ((await readdir(dir)).some((n) => !/^\..*\.tmp$/u.test(n))) throw new Error('state file is missing but the directory is not empty');
      return null;
    }
  }
  async function persist(next: State): Promise<boolean> {
    const bytes = toBytes(next);
    try {
      await writeFileAtomic(file, bytes, 0o600);
      const h = await open(dir, fsConstants.O_RDONLY | (fsConstants.O_DIRECTORY ?? 0));
      try { await h.sync(); } finally { await h.close(); }
    } catch { corrupt = true; return false; } // on-disk state now unknown: stop rather than guess
    held = bytes; state = next;
    return true;
  }

  try {
    held = await read();
    const loaded = held ? parse(held) : null;
    state = loaded ?? { bootId, seq: 0, high: 0, folded: 0, log: [], base: new Map(), sessions: new Map(), ended: new Set() };
    // A different boot: no recorded session can still be running.
    if (!loaded || loaded.bootId !== bootId) {
      // Tombstones are per boot; boot-relative times are meaningless across boots, so fold the whole log into base.
      const base = new Map(state.base);
      for (const e of state.log) { if (e.digest === null) base.delete(e.name); else base.set(e.name, e.digest); }
      state = { ...state, bootId, high: 0, folded: 0, log: [], base, sessions: new Map(), ended: new Set() };
      if (!(await persist(state))) throw new Error('cannot persist');
    }
  } catch { corrupt = true; }

  /** Inside the lock: reload if the file changed under us; never accept older state. */
  async function refresh(): Promise<void> {
    if (corrupt || !state) return;
    try {
      const disk = await read();
      if (disk !== null && held !== null && disk.equals(held)) return;
      const next = disk ? parse(disk) : null;
      if (!next || next.bootId !== state.bootId || next.seq < state.seq) { corrupt = true; return; }
      state = next; held = disk;
    } catch { corrupt = true; }
  }

  let tail: Promise<unknown> = Promise.resolve();
  const locked = <T>(fn: () => Promise<T>): Promise<T> => {
    const run = tail.then(async () => { await refresh(); return fn(); });
    tail = run.catch(() => {});
    return run;
  };

  const mutate = (fn: (s: State) => MutationResult | void): Promise<MutationResult> => locked(async () => {
    if (corrupt || !state) return { ok: false, reason: 'state-corrupt' };
    const next = clone(state);
    const refused = fn(next);
    if (refused) return refused;
    return (await persist(next)) ? { ok: true } : { ok: false, reason: 'write-failed' };
  });

  const event = (name: string, digest: string | null, bootMs: number) => {
    requireString(name, 'name', 128);
    if (digest !== null) requireString(digest, 'digest', 128);
    requireBootMs(bootMs, 'bootMs');
    return mutate((s) => {
      let stamp = bootMs;
      if (bootMs < s.high) {
        if (digest !== null) return BACKWARDS;
        stamp = s.high; // an uninstall (revoke) must still succeed
      }
      s.high = stamp;
      compact(s, stamp);
      if (digest === null) {
        if (currentAt(s, name, s.seq) === null) return; // nothing installed: no entry, so uninstalls stay bounded
      } else if (s.log.length >= MAX_LOG) return { ok: false, reason: 'log-full' };
      s.log.push({ seq: ++s.seq, name, digest, at: stamp });
    });
  };

  return {
    publish: (name, digest, bootMs) => event(name, digest, bootMs),
    uninstall: (name, bootMs) => event(name, null, bootMs),

    admitSession(ref, bootMs, { startedBootMs }) {
      requireString(ref, 'sessionRef', 256);
      requireBootMs(bootMs, 'bootMs');
      requireBootMs(startedBootMs, 'startedBootMs');
      const cutoff = startedBootMs - START_MARGIN_MS; // conservatively earlier than the host start
      if (startedBootMs > bootMs || cutoff < bootMs - MAX_STARTUP_AGE_MS) return Promise.resolve({ ok: false, reason: 'invalid-start' });
      return mutate((s) => {
        if (bootMs < s.high) return BACKWARDS;
        if (s.ended.has(ref)) return { ok: false, reason: 'session-ended' };
        if (s.sessions.has(ref)) return { ok: false, reason: 'session-exists' };
        if (s.sessions.size >= MAX_SESSIONS || s.sessions.size + s.ended.size >= MAX_TOMBSTONES) return { ok: false, reason: 'session-limit' }; // fail closed
        s.high = bootMs;
        compact(s, bootMs);
        if (s.folded > 0 && cutoff <= s.folded) return { ok: false, reason: 'invalid-start' }; // base cannot reconstruct pre-fold history
        let seq = 0; // base alone is "before the log"; stop at the first entry newer than the cutoff
        for (const e of s.log) { if (e.at > cutoff) break; seq = e.seq; }
        s.sessions.set(ref, { seq, at: bootMs });
      });
    },

    // An unknown ref is tombstoned too, so it can never be admitted later in this boot (fail closed when full).
    endSession: (ref) => mutate((s) => {
      if (s.sessions.delete(ref)) { s.ended.add(ref); return; }
      if (s.ended.has(ref)) return;
      if (s.sessions.size + s.ended.size >= MAX_TOMBSTONES) return { ok: false, reason: 'session-limit' };
      s.ended.add(ref);
    }), // compaction waits for the next event (needs a time)

    async expireSessions(maxAgeMs, bootMs) {
      requireBootMs(bootMs, 'bootMs');
      if (typeof maxAgeMs !== 'number' || !Number.isFinite(maxAgeMs) || maxAgeMs < 0) throw new Error('maxAgeMs must be a finite non-negative number');
      let expired = 0;
      const r = await mutate((s) => {
        if (bootMs < s.high) return BACKWARDS;
        s.high = bootMs;
        for (const [ref, v] of s.sessions) if (bootMs - v.at > maxAgeMs) { s.sessions.delete(ref); s.ended.add(ref); expired++; }
        compact(s, bootMs);
      });
      return r.ok ? { ...r, expired } : r;
    },

    async assess(ref, name, check) {
      // Snapshot under the lock; the (slow) checks run outside it so they never block publishing.
      const snap = await locked(async () => {
        if (corrupt || !state) return { error: 'state-corrupt' as const, digests: undefined };
        const sess = state.sessions.get(ref);
        if (!sess) return { error: 'no-session-record' as const, digests: undefined };
        if (currentAt(state, name, state.seq) === null) return { error: 'not-installed' as const, digests: undefined };
        const digests = setFor(state, name, sess.seq);
        return digests.length > MAX_SET ? { error: 'bound-exceeded' as const, digests: undefined } : { error: undefined, digests };
      });
      if (!snap.digests) return { kind: 'error', reason: snap.error! };
      let worst: Verdict = 'VERIFIED';
      try {
        for (const d of snap.digests) {
          const v = await check(name, d);
          if (typeof v !== 'string' || !Object.hasOwn(VERDICT_RANK, v)) return { kind: 'error', reason: 'internal' };
          if (severity(v) > severity(worst)) worst = v;
        }
      } catch { return { kind: 'error', reason: 'internal' }; }
      return { kind: 'verdict', verdict: worst, digests: snap.digests };
    },
  };
}

// Most severe failing verdict across generations. The engine's VERDICT_RANK lists failure precedence with the
// highest-priority reason first (REVOKED, UNAPPROVED_CHANGE, EXPIRED, ...), so the lowest non-zero rank is reported.
function severity(v: Verdict): number {
  const rank = VERDICT_RANK[v];
  if (!Number.isFinite(rank)) throw new Error('non-finite verdict rank');
  return v === 'VERIFIED' ? -1 : 100 - rank;
}
