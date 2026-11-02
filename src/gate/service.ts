// Root gate service core (E3 packet 6). Linux only. It owns the trust store, the admission store, the generation
// store and a per-digest certificate store, and answers hook adapters on a Unix socket. Production runs as root
// (`rootUid` 0); tests pass their own uid. Out of scope here: metadata refresh, the decision log, harness adapters.
//
// IDENTITY. Node has no peer credentials, so the request's `session` (`pid:<n>`) is only a pointer. The service reads
// the kernel's view of that pid (/proc: start time, exe) and requires exe to be in the configured allowlist of host
// binaries; the admission ref `<pid>:<startedBootMs>` is derived from those kernel facts, never from the request. A
// forged request is harmless: the service answers only allow/deny to the asker; a forged session-start for someone
// else's pid admits it with its true kernel start time (no history shed, no rights gained); an unknown pid or a
// non-host exe is denied. There is no session-end event in the contract, so dead sessions are reaped (see REAPING). Any local user can send decisions (socket 0666) and so
// can only affect their own answers; a user who can run an allowlisted binary can already start sessions of their own.
//
// PROCESSES ONLY. /proc/<tid> resolves for threads too, and a thread starts later than its process, which would shorten
// its generation set; processFacts() therefore requires Tgid == pid and rejects nested pid namespaces (NSpid with
// more than one entry; unsupported). A replaced host binary reads `<path> (deleted)` in /proc/<pid>/exe; that is
// accepted as `<path>` only when the suffix is exactly " (deleted)" and `<path>` is allowlisted (the process was
// started from that root-owned path; allowlisted paths must not be creatable by employees).
//
// REAPING. Sessions have no end event, so dead ones are reaped: every 60 s while started, at start, and before an
// admission when open sessions are at >= 90% of MAX_SESSIONS or the asking uid is at its cap. Full /proc sweeps are
// rate-limited to one per `sweepMinIntervalMs` (default 1000; all triggers share it); a rate-limited sweep keeps the
// last counts, so an admission at the cap is refused (fail closed) until the next sweep may run. Only ENOENT/ESRCH, a
// different start time, a non-process Tgid or a nested pid namespace mean dead; ANY OTHER read error (EACCES, EMFILE,
// ...) keeps the session (admission.ts: an isLive that throws keeps the session), counted for the uid it was admitted under. A session is live if
// /proc/<pid> is a process whose start time equals the ref's (refs are kernel-derived `pid:starttime`, which cannot
// recur within a boot, the only reason admission.ts reapSessions is safe here). Per-uid cap (default 256): a new
// admission is refused (`internal`) while that uid has that many open LIVE sessions, counted from each open
// session's pid uid in /proc at the last sweep plus admissions since; a re-sent session-start from a capped uid is
// refused too. Admissions run one at a time, so the cap is exact within one service process.
//
// DEPLOYMENT REQUIREMENTS (not enforced here): the socket and state directories' ancestors are not checked, so
// every ancestor must be root-owned and not writable by employees; the service must see the hosts' pid namespace
// (no containers between) and /proc without hidepid hiding other uids (an unreadable pid keeps its session open, so
// hiding pids only delays reaping), and RLIMIT_NOFILE (soft) of at least decision cap + 4 (admin) + 256 (margin for
// stores, certificates, installs): start() caps the decision connections at (soft limit - 260) and refuses to start
// when that leaves fewer than 16.
// ADAPTER CONTRACT (packet 9). A local user can always overload a world-accessible socket that has no peer credentials;
// the service-side limits below only reduce the blast radius. Therefore every harness adapter MUST treat a missing, late
// (its own deadline, shorter than the host's hook timeout), empty or malformed answer as DENY in enforce mode, by
// returning the host's explicit block response itself (e.g. exit code 2 for Codex), never by crashing or timing out.
// WORK LIMITS. An answered connection is closed as soon as its reply is flushed, whatever the client does, and frees its
// slot at once. A connection destroyed before its answer is ready cancels the remaining work (checked before assess and
// before certificates are read) and nothing is written. A uid (taken from /proc for the request's session pid) may have
// 8 decision requests in flight; the 9th gets gate-error `internal` before any expensive work. The uid charged is the
// owner of the NAMED pid, not the sender (unknowable without peer credentials), so one local user can exhaust another
// user's share while flooding; that only yields denials (adapter contract below). Verdicts are cached per
// (name, digest, trust-root version, revocation-list version) for at most 1 s of the service clock: an accepted
// revocation or trust root changes the key, so it applies to the very next check; a certificate that expires or becomes
// valid inside that second (or whose approver expires in it) can be seen up to 1 s late (the TTL bounds the EXPIRED/VERIFIED boundary); storing a
// certificate clears the cache.
// The decision connection cap is also lowered to /proc/sys/net/core/somaxconn when that is smaller (a larger cap cannot
// be queued by the kernel); production should raise net.core.somaxconn to at least the cap (default 1024).
// CONNECTIONS. Decision socket (0666) at its cap: the OLDEST connection that has not yet delivered a complete request
// line is destroyed and the newcomer accepted; connections whose request is being processed are never evicted (an answered
// connection no longer exists, see WORK LIMITS); if every connection is processing, the newcomer is closed. A reconnecting flood therefore cannot starve a client that sends
// its request promptly. The idle deadline (300 ms / 2 s admin) ends when the request line is complete; processing then
// has its own deadline (5 s / 60 s admin) after which the connection closes without a reply.
// The listen backlog is 4096 (the kernel clamps it to net.core.somaxconn): with Node's default 511 a flood of
// queued connects made legitimate connects wait for SYN retries (measured 14-17 of 20 answered; 20 of 20 at 4096).
// check() reads at most 16 certificate files per digest (later files are ignored).
//
// READINESS. If startup could not open the stores, every decision is gate-error `trust-unavailable`. session-start
// needs only the admission store (so a session started while trust is stale is still recorded); skill events also
// need a ready trust store at decision time. A Skill that is not installed answers NO_CERTIFICATE.
//
// ORDERING (admission.ts caller contract): install = stage+verify+publish generation, store certificate, THEN read
// bootMs and publish to admission, so the stamp is never earlier than the generation's visibility. All admin
// operations run through one queue. Uninstall leaves immutable generations on disk; hiding them is packet 9's job.
import { createHash } from 'node:crypto';
import { chmod, lstat, mkdir, readdir, readFile, unlink } from 'node:fs/promises';
import net from 'node:net';
import path from 'node:path';
import { isRecord, MAX_CANONICAL_JSON_BYTES } from '../canonical-json.ts';
import { readRegularFile, writeFileAtomic } from '../fs-safe.ts';
import { validateDigest, validateSkillName } from '../names.ts';
import type { Mode } from '../policy.ts';
import { evaluateCertificate, VERDICT_RANK, type Verdict } from '../verify.ts';
import { MAX_SESSIONS, openAdmissionStore, type AdmissionStore, type MutationResult } from './admission.ts';
import { parseGateRequest, serializeGateResult, type GateRequest, type GateResult } from './contract.ts';
import { installSkill } from './generations.ts';
import { bootId, bootMs, NotLiveError, nofileSoftLimit, processFacts, processInfo } from './proc.ts';
import { parseStrictJson, DEFAULT_STRICT_JSON_LIMITS } from './strict-json.ts';
import { openTrustStore, type TrustStore } from './trust-store.ts';

export interface GateServiceConfig {
  /** Holds trust/, admission/, certs/ and staging/. */
  stateDir: string;
  generationsDir: string;
  /** Directory of the decision socket (`decision.sock`, mode 0666) and of the admin socket (`admin.sock`, 0600). */
  decisionSocketDir: string;
  adminSocketDir: string;
  rootFingerprint: string;
  mode: Mode;
  /** Absolute paths of the real host binaries (claude, codex); the host process's /proc/<pid>/exe must match exactly. */
  hostExes: readonly string[];
  /** Directories the service creates and checks must be owned by this uid: 0 in production, the test user's uid in tests. */
  rootUid: number;
  maxListAgeMs?: number;
  /** Tests: injectable wall clock for trust and certificate checks. */
  now?: () => Date;
  /** Idle limit for a request line: decision socket default 300 ms, admin socket default 2000 ms. */
  deadlineMs?: number;
  /** Decision socket connection cap (default 1024, lowered to the fd limit); the admin socket allows 4. */
  maxConnections?: number;
  /** Deadline for processing a complete request (default 5000 ms; admin socket 60000 ms). */
  processingMs?: number;
  /** Minimum time between full /proc sweeps (default 1000 ms). */
  sweepMinIntervalMs?: number;
  /** Tests: replaces the RLIMIT_NOFILE soft limit read from /proc/self/limits. */
  nofileLimit?: number;
  /** Tests: replaces the /proc reader used by sweeps. */
  processFacts?: typeof processFacts;
  /** Open live sessions allowed per uid (default 256). */
  maxSessionsPerUid?: number;
  /** Decision requests in flight per uid (default 8). */
  maxInflightPerUid?: number;
  /** Tests: replaces the /proc reader for a request's session pid. */
  processInfo?: typeof processInfo;
  /** Tests: replaces the reader of net.core.somaxconn (default /proc/sys/net/core/somaxconn; unreadable = no limit). */
  somaxconn?: () => Promise<number>;
  /** Tests: fault hook passed to the admission store (see admission.ts). */
  admissionFault?: (op: 'read' | 'write') => string | undefined;
}

export type AdminResult = { ok: true; [key: string]: unknown } | { ok: false; error: string };

export interface GateService {
  start(): Promise<void>;
  stop(): Promise<void>;
  handleDecision(request: GateRequest, ctx?: { cancelled: boolean }): Promise<GateResult>;
  handleAdmin(command: unknown): Promise<AdminResult>;
  /** Socket paths, valid after start(). */
  readonly sockets: { decision: string; admin: string };
  /** Effective decision connection cap, valid after start(). */
  readonly decisionCap: number;
}

const SESSION = /^pid:([1-9][0-9]{0,9})$/u;
const DELETED = ' (deleted)';
const MAX_CERT_BYTES = 256 * 1024;
const MAX_CERTS_PER_DIGEST = 16;
const ADMIN_LIMITS = { maxBytes: 12 * 1024 * 1024, maxDepth: 4, maxMembers: 8, maxStringLength: 6 * 1024 * 1024 };
const hex = (digest: string): string => validateDigest(digest).slice('sha256:'.length);

function b64(value: unknown, label: string, max: number): Buffer {
  if (typeof value !== 'string') throw new Error(`${label} must be a base64 string`);
  const bytes = Buffer.from(value, 'base64');
  if (bytes.toString('base64') !== value || bytes.length === 0 || bytes.length > max) throw new Error(`${label} is not valid base64 within the size limit`);
  return bytes;
}

function onlyKeys(c: Record<string, unknown>, keys: readonly string[]): void {
  if (c['v'] !== 1 || Object.keys(c).some((k) => k !== 'v' && k !== 'cmd' && !keys.includes(k)) || keys.some((k) => !Object.hasOwn(c, k)))
    throw new Error('command has missing or unknown fields');
}

async function ownedDir(dir: string, uid: number, mode: number, strict: boolean): Promise<void> {
  await mkdir(dir, { mode }).catch((e) => { if ((e as NodeJS.ErrnoException)?.code !== 'EEXIST') throw e; });
  const info = await lstat(dir);
  if (info.isSymbolicLink() || !info.isDirectory()) throw new Error(`${dir} must be a real directory`);
  if (info.uid !== uid) throw new Error(`${dir} must be owned by uid ${uid}`);
  if ((info.mode & (strict ? 0o077 : 0o022)) !== 0) throw new Error(`${dir} has unsafe permissions`);
}

/** net.core.somaxconn; unreadable means no limit. */
async function readSomaxconn(): Promise<number> {
  const n = Number((await readFile('/proc/sys/net/core/somaxconn', 'utf8')).trim());
  return Number.isSafeInteger(n) && n > 0 ? n : Infinity;
}

async function listen(server: net.Server, file: string, mode: number): Promise<void> {
  const old = await lstat(file).catch(() => undefined);
  if (old) { if (!old.isSocket()) throw new Error(`${file} exists and is not a socket`); await unlink(file); }
  await new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(file, 4096, () => { server.off('error', reject); resolve(); }); });
  await chmod(file, mode);
}

/** One request line per connection: read to the first newline (bounded, idle deadline), reply with one line, close. Anything else just closes. */
function serveOnce(live: Set<net.Socket>, limit: number, deadlineMs: number, processingMs: number, maxConnections: number, answer: (line: Buffer, ctx: { cancelled: boolean }) => Promise<string | undefined>): net.Server {
  const conns = new Set<net.Socket>();
  const pending = new Set<net.Socket>(); // no complete request line yet, oldest first
  return net.createServer({ allowHalfOpen: true }, (sock) => { // half-open: a client may end() right after its request and still get the reply
    if (conns.size >= maxConnections) {
      const oldest = pending.values().next().value as net.Socket | undefined;
      if (!oldest) { sock.destroy(); return; }
      conns.delete(oldest); pending.delete(oldest); live.delete(oldest); oldest.destroy();
    }
    conns.add(sock); pending.add(sock); live.add(sock);
    const chunks: Buffer[] = [];
    let size = 0;
    let done = false;
    const ctx = { cancelled: false };
    let timer = setTimeout(() => sock.destroy(), deadlineMs);
    sock.on('close', () => { ctx.cancelled = true; clearTimeout(timer); conns.delete(sock); pending.delete(sock); live.delete(sock); });
    sock.on('error', () => sock.destroy());
    sock.on('end', () => { if (!done) sock.destroy(); });
    sock.on('data', (chunk: Buffer) => {
      if (done) return; // later bytes (a second request) are ignored
      const nl = chunk.indexOf(0x0a);
      const head = nl < 0 ? chunk : chunk.subarray(0, nl);
      size += head.length;
      if (size > limit) { sock.destroy(); return; }
      chunks.push(head);
      if (nl < 0) return;
      done = true;
      pending.delete(sock);
      clearTimeout(timer);
      timer = setTimeout(() => sock.destroy(), processingMs);
      answer(Buffer.concat(chunks), ctx).then((reply) => {
        clearTimeout(timer);
        conns.delete(sock); // answered: the slot is free now, whatever the client does next
        if (sock.destroyed) return;
        if (reply === undefined) { sock.destroy(); return; }
        timer = setTimeout(() => sock.destroy(), 2000); // flush deadline for a client that never reads
        sock.end(`${reply}\n`, () => sock.destroy());
      }, () => sock.destroy());
    });
  });
}

export function createGateService(config: GateServiceConfig): GateService {
  const now = config.now ?? ((): Date => new Date());
  const mode = config.mode;
  const stateDir = path.resolve(config.stateDir);
  const certsDir = path.join(stateDir, 'certs');
  const stagingDir = path.join(stateDir, 'staging');
  let decisionCap = 0;
  const readFacts = config.processFacts ?? processFacts;
  const sweepMinMs = config.sweepMinIntervalMs ?? 1000;
  let lastSweep = -Infinity;
  const uidOf = new Map<string, number>(); // admitted ref -> uid, for sessions whose /proc state cannot be read
  const sockets = { decision: path.join(config.decisionSocketDir, 'decision.sock'), admin: path.join(config.adminSocketDir, 'admin.sock') };
  let trust: TrustStore | undefined;
  let admission: AdmissionStore | undefined;
  let ready = false;
  const servers: net.Server[] = [];
  const live = new Set<net.Socket>();
  let queue: Promise<unknown> = Promise.resolve();
  const serial = <T>(fn: () => Promise<T>): Promise<T> => { const run = queue.then(fn); queue = run.catch(() => {}); return run; };

  /** Re-reads the clock and retries once: concurrent admissions can stamp slightly ahead of a reading taken earlier. */
  async function stamped(fn: (ms: number) => Promise<MutationResult>): Promise<MutationResult> {
    const r = await fn(await bootMs());
    return !r.ok && r.reason === 'clock-moved-backwards' ? fn(await bootMs()) : r;
  }

  // Admissions, sweeps and their counters run one at a time.
  let gate: Promise<unknown> = Promise.resolve();
  const exclusive = <T>(fn: () => Promise<T>): Promise<T> => { const run = gate.then(fn); gate = run.catch(() => {}); return run; };
  let openCount = 0;
  let perUid = new Map<number, number>();
  const perUidCap = config.maxSessionsPerUid ?? 256;

  /** Reap dead sessions and recount the live ones per uid; at most one sweep per sweepMinMs (a skipped one changes nothing). */
  async function sweep(): Promise<void> {
    if (!admission) return;
    const t = performance.now();
    if (t - lastSweep < sweepMinMs) return;
    lastSweep = t;
    const counts = new Map<number, number>();
    let total = 0;
    const r = await admission.reapSessions(async (ref) => { // runs outside the store lock
      const m = /^([1-9][0-9]*):([0-9]+)$/u.exec(ref);
      if (!m) return false;
      const dead = (): false => { uidOf.delete(ref); return false; };
      try {
        const f = await readFacts(Number(m[1]));
        if (f.startedBootMs !== Number(m[2])) return dead();
        uidOf.set(ref, f.uid);
        counts.set(f.uid, (counts.get(f.uid) ?? 0) + 1); total++;
        return true;
      } catch (e) {
        const code = (e as NodeJS.ErrnoException)?.code;
        if (code === 'ENOENT' || code === 'ESRCH' || e instanceof NotLiveError) return dead();
        total++; // unknown state: keep the session, and count it for the uid it was admitted under
        const u = uidOf.get(ref);
        if (u !== undefined) counts.set(u, (counts.get(u) ?? 0) + 1);
        return true;
      }
    });
    if (r.ok) { openCount = total; perUid = counts; }
  }

  const admitOnce = (ref: string, startedBootMs: number, uid: number): Promise<MutationResult> => exclusive(async () => {
    if (openCount >= MAX_SESSIONS * 0.9 || (perUid.get(uid) ?? 0) >= perUidCap) await sweep();
    if ((perUid.get(uid) ?? 0) >= perUidCap) return { ok: false, reason: 'session-limit' } as const;
    const r = await stamped((ms) => admission!.admitSession(ref, ms, { startedBootMs }));
    if (r.ok) { uidOf.set(ref, uid); openCount++; perUid.set(uid, (perUid.get(uid) ?? 0) + 1); }
    return r;
  });
  let reaper: NodeJS.Timeout | undefined;

  /** Engine verdict for exactly this Skill name and digest under the trust context of this moment. */
  const verdictCache = new Map<string, { verdict: Verdict; at: number }>();
  const CACHE_TTL_MS = 1000;
  const CACHE_MAX = 4096;
  async function check(name: string, digest: string, ctx?: { cancelled: boolean }): Promise<Verdict> {
    const at = now().getTime();
    const current = await trust!.current(now());
    if (!current.ready) return 'UNVERIFIABLE';
    const key = `${current.versions.trustRootVersion}|${current.versions.revocationsVersion}|${name}|${digest}`;
    const hit = verdictCache.get(key);
    if (hit && at - hit.at >= 0 && at - hit.at < CACHE_TTL_MS) return hit.verdict;
    if (ctx?.cancelled) throw new Error('cancelled');
    const verdict = await compute(name, digest, current.context);
    if (verdictCache.size >= CACHE_MAX) verdictCache.clear();
    verdictCache.set(key, { verdict, at });
    return verdict;
  }

  async function compute(name: string, digest: string, context: Extract<Awaited<ReturnType<TrustStore['current']>>, { ready: true }>['context']): Promise<Verdict> {
    const dir = path.join(certsDir, name, hex(digest));
    const files = (await readdir(dir).catch((e: NodeJS.ErrnoException) => { if (e.code === 'ENOENT') return []; throw e; }))
      .filter((f) => /^[0-9a-f]{64}\.json$/u.test(f)).slice(0, MAX_CERTS_PER_DIGEST);
    let best: Verdict = 'NO_CERTIFICATE';
    for (const file of files) {
      const bytes = await readRegularFile(path.join(dir, file), 'certificate', MAX_CERT_BYTES);
      const verdict = evaluateCertificate(bytes, name, digest, context, now()).verdict;
      if (VERDICT_RANK[verdict] < VERDICT_RANK[best]) best = verdict;
    }
    return best;
  }

  const inflight = new Map<number, number>();
  const inflightCap = config.maxInflightPerUid ?? 8;
  const readInfo = config.processInfo ?? processInfo;

  async function handleDecision(request: GateRequest, ctx: { cancelled: boolean } = { cancelled: false }): Promise<GateResult> {
    const base = { v: 1 as const, request_id: request.request_id, mode };
    const fail = (code: Extract<GateResult, { kind: 'gate-error' }>['code']): GateResult => ({ ...base, kind: 'gate-error', code });
    try {
      if (!ready || !trust || !admission) return fail('trust-unavailable');
      const pid = SESSION.exec(request.session)?.[1];
      let ref: string; let startedBootMs: number; let uid: number;
      try {
        if (!pid) throw new Error('bad session');
        const info = await readInfo(Number(pid));
        const exe = info.exe.endsWith(DELETED) ? info.exe.slice(0, -DELETED.length) : info.exe;
        if (!config.hostExes.includes(info.exe) && !config.hostExes.includes(exe)) throw new Error('not a host binary');
        startedBootMs = info.startedBootMs; uid = info.uid; ref = `${pid}:${startedBootMs}`;
      } catch { return fail('no-session-record'); }

      if (ctx.cancelled) return fail('internal'); // the client is gone; nothing will be written
      if ((inflight.get(uid) ?? 0) >= inflightCap) return fail('internal'); // cheap refusal: this uid already has its share in flight
      inflight.set(uid, (inflight.get(uid) ?? 0) + 1);
      try {
        return await decideAdmitted(request, ctx, base, fail, ref, startedBootMs, uid);
      } finally {
        const left = (inflight.get(uid) ?? 1) - 1;
        if (left <= 0) inflight.delete(uid); else inflight.set(uid, left);
      }
    } catch { return fail('internal'); }
  }

  async function decideAdmitted(request: GateRequest, ctx: { cancelled: boolean }, base: { v: 1; request_id: string; mode: Mode },
    fail: (code: Extract<GateResult, { kind: 'gate-error' }>['code']) => GateResult, ref: string, startedBootMs: number, uid: number): Promise<GateResult> {
    if (request.event === 'session-start') {
      const r = await admitOnce(ref, startedBootMs, uid);
      // A re-sent start for the same live process is fine; the result is an acknowledgement, never a verdict.
      return r.ok || r.reason === 'session-exists' ? { ...base, kind: 'ack' } : fail('internal');
    }
    const current = await trust!.current(now());
    if (!current.ready) return fail('trust-unavailable');
    if (ctx.cancelled) return fail('internal');
    const a = await admission!.assess(ref, request.skill!, (n, d) => check(n, d, ctx));
    if (a.kind === 'verdict') return { ...base, kind: 'verdict', verdict: a.verdict };
    if (a.reason === 'no-session-record') return fail('no-session-record');
    if (a.reason === 'not-installed') return { ...base, kind: 'verdict', verdict: 'NO_CERTIFICATE' };
    return fail('internal'); // state-corrupt, bound-exceeded, io-busy, internal: contract.ts has no closer code
  }

  async function storeCertificate(name: string, digest: string, bytes: Buffer): Promise<void> {
    const dir = path.join(certsDir, name, hex(digest));
    await mkdir(dir, { recursive: true, mode: 0o755 });
    const file = path.join(dir, `${createHash('sha256').update(bytes).digest('hex')}.json`); // name = content hash: no overwrite with other bytes
    if (await lstat(file).then(() => true, () => false)) return;
    await writeFileAtomic(file, bytes, 0o444);
    verdictCache.clear();
  }

  async function admin(raw: unknown): Promise<AdminResult> {
    if (!isRecord(raw) || typeof raw['cmd'] !== 'string') throw new Error('command must be an object with cmd');
    if (!ready || !trust || !admission) return { ok: false, error: 'service is not ready' };
    switch (raw['cmd']) {
      case 'status': {
        onlyKeys(raw, []);
        const c = await trust.current(now());
        const health = await admission.health(); // also retries a store that could not load at start
        return { ok: true, ready: ready && health === 'ready', mode, trust: c.ready ? 'ready' : c.reason, admission: health };
      }
      case 'accept-trust': {
        onlyKeys(raw, ['trust_root_b64', 'revocations_b64']);
        const r = await trust.accept({
          trustRootBytes: b64(raw['trust_root_b64'], 'trust_root_b64', MAX_CANONICAL_JSON_BYTES),
          revocationsBytes: b64(raw['revocations_b64'], 'revocations_b64', MAX_CANONICAL_JSON_BYTES),
        }, now());
        return r.ok ? { ok: true, changed: r.changed } : { ok: false, error: `${r.reason}: ${r.message}` };
      }
      case 'install': {
        onlyKeys(raw, ['skill_name', 'source_dir', 'certificate_b64']);
        const name = validateSkillName(raw['skill_name']);
        const source = raw['source_dir'];
        if (typeof source !== 'string' || !path.isAbsolute(source)) throw new Error('source_dir must be an absolute path');
        const cert = b64(raw['certificate_b64'], 'certificate_b64', MAX_CERT_BYTES);
        const current = await trust.current(now());
        if (!current.ready) return { ok: false, error: `trust not ready: ${current.reason}` };
        const r = await installSkill(source, stagingDir, {
          generationsRoot: path.resolve(config.generationsDir), skillName: name,
          certificates: [{ source: 'admin', bytes: cert }], context: current.context, now: now(), buildProfile: 'gate-service/v1',
        });
        if (!r.ok) return { ok: false, error: `${r.reason}: ${r.detail}` };
        const digest = r.manifest.treeDigest;
        await storeCertificate(name, digest, cert);
        const p = await stamped((ms) => admission!.publish(name, digest, ms)); // after the generation is visible
        return p.ok ? { ok: true, digest, created: r.created } : { ok: false, error: `publish refused: ${p.reason}` };
      }
      case 'uninstall': {
        onlyKeys(raw, ['skill_name']);
        const u = await admission.uninstall(validateSkillName(raw['skill_name']), await bootMs());
        return u.ok ? { ok: true } : { ok: false, error: `uninstall refused: ${u.reason}` };
      }
      default: return { ok: false, error: 'unknown command' };
    }
  }

  const handleAdmin = (command: unknown): Promise<AdminResult> =>
    serial(() => admin(command)).catch((e: unknown) => ({ ok: false as const, error: e instanceof Error ? e.message : 'failed' }));

  return {
    sockets,
    get decisionCap() { return decisionCap; },
    handleDecision,
    handleAdmin,

    async start() {
      try {
        await ownedDir(stateDir, config.rootUid, 0o700, true);
        for (const d of [stagingDir, certsDir]) await ownedDir(d, config.rootUid, d === certsDir ? 0o755 : 0o700, d !== certsDir);
        trust = await openTrustStore(path.join(stateDir, 'trust'), { rootFingerprint: config.rootFingerprint, now: now(), ...(config.maxListAgeMs !== undefined ? { maxListAgeMs: config.maxListAgeMs } : {}) });
        admission = await openAdmissionStore(path.join(stateDir, 'admission'), { bootId: await bootId(), ...(config.admissionFault ? { fault: config.admissionFault } : {}) });
        ready = true;
        await exclusive(sweep).catch(() => {});
        reaper = setInterval(() => { void exclusive(sweep).catch(() => {}); }, 60_000);
        reaper.unref();
      } catch { ready = false; } // stay up and answer trust-unavailable
      const soft = config.nofileLimit ?? await nofileSoftLimit();
      if (!(soft - 260 >= 16)) throw new Error(`RLIMIT_NOFILE soft limit ${soft} is too low (need at least 276)`);
      const somax = await (config.somaxconn ?? readSomaxconn)().catch(() => Infinity);
      decisionCap = Math.min(config.maxConnections ?? 1024, soft - 260, somax);
      await ownedDir(config.decisionSocketDir, config.rootUid, 0o755, false);
      await ownedDir(config.adminSocketDir, config.rootUid, 0o700, true);
      const decision = serveOnce(live, DEFAULT_STRICT_JSON_LIMITS.maxBytes, config.deadlineMs ?? 300, config.processingMs ?? 5000, decisionCap, async (line) => {
        try { return serializeGateResult(await handleDecision(parseGateRequest(line))); } catch { return undefined; }
      });
      const adminServer = serveOnce(live, ADMIN_LIMITS.maxBytes, config.deadlineMs ?? 2000, config.processingMs ?? 60_000, 4, async (line) => {
        let result: AdminResult;
        try { result = await handleAdmin(parseStrictJson(line, ADMIN_LIMITS)); } catch (e) { result = { ok: false, error: e instanceof Error ? e.message : 'bad command' }; }
        return JSON.stringify({ v: 1, ...result });
      });
      servers.push(decision, adminServer);
      await listen(decision, sockets.decision, 0o666);
      await listen(adminServer, sockets.admin, 0o600);
    },

    async stop() {
      if (reaper) clearInterval(reaper);
      await Promise.all(servers.splice(0).map((s) => new Promise<void>((r) => { s.close(() => r()); for (const c of live) c.destroy(); })));
    },
  };
}
