// Protected decision log (E3 packet 8). Linux only. Append-only JSONL segments in a root-only directory.
//
// INTEGRITY LIMIT. Each record carries `prev` = SHA-256 (hex) of the previous record's line, and a checkpoint file
// holds the last sequence + hash. A chain stored next to a log that root can rewrite does NOT authenticate history
// against root: it detects accidental corruption and tampering by non-root users only. There is no integrity key here.
//
// RECORDS hold only the fixed fields in `Record` (no bodies, prompts, hook payloads, paths, certificate reasons or
// verifier stderr); the record is built field by field, so extra input is dropped.
//
// DURABILITY. `append(..., durable=true)` returns after fsync of the segment (the service uses it for an enforce allow,
// which is returned only after this). Non-durable appends skip fsync (a later fsync of the same file flushes them too).
//
// SEGMENTS `segment-<10-digit index>.jsonl` rotate at `maxSegmentBytes`; the first record of the next segment chains to
// the last hash of the previous one, and a checkpoint of that last record is written first. At most `maxSegments` are kept.
//
// RECOVERY (open, and before the next append after a failed one) checks the last segment: every line parses, `prev`
// matches the previous line, `seq` is consecutive, the last line is complete, and the checkpoint (when present) matches
// (same segment: the record with its seq has its hash; older segment: this segment starts at checkpoint.seq + 1 and chains
// to checkpoint.hash). Anything else is a BREAK: a new segment starts, its first record has `prev` null and `chain_break`
// = the old segment's file name, and the sequence continues from max(last valid, checkpoint). Limit: a checkpoint is the
// only anchor for earlier segments (they are not re-read), and a lost checkpoint plus a fully invalid last segment can
// restart the sequence low; the break marker still records it.
// Before each append the directory inode and the open segment are checked; when the segment is gone or the directory is a
// different inode, the next record starts a new segment with `chain_break` = the missing segment's name. Recovery re-runs
// the directory safety checks (a loose directory stays refused) and is rate-limited to one attempt per second; while
// limited, an append fails fast. If the fsync of a durable record fails, the next append first writes a correction
// (`action` deny, `result` internal, `supersedes` = that seq). shortcut: a correction not yet written at shutdown is lost,
// the next process cannot know about it; the caller already answered gate-error for that request.
import { createHash } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import { lstat, mkdir, open, readdir, unlink } from 'node:fs/promises';
import path from 'node:path';
import { readRegularFile, writeFileAtomic } from '../fs-safe.ts';

export interface LogInput {
  bootMs: number;
  mode: string;
  action: 'allow' | 'deny' | 'observe' | 'ack';
  event: string;
  /** Pseudonymous session reference (already keyed-hashed by the caller), or null. */
  session: string | null;
  skill: string | null;
  digests: readonly string[];
  trustRootVersion: number | null;
  revocationsVersion: number | null;
  /** Verdict or closed gate-error code. */
  result: string;
  build: string;
  elapsedMs: number;
}

export interface LogOptions {
  rootUid: number;
  maxSegmentBytes?: number;
  maxSegments?: number;
  checkpointEvery?: number;
  now?: () => Date;
  /** Tests: return true to make the next append fail before touching the disk. */
  fault?: () => boolean;
  /** Tests: return true to make the fsync of a durable append fail (the record is already written). */
  syncFault?: () => boolean;
}

export interface DecisionLog {
  append(input: LogInput, durable: boolean): Promise<void>;
  status(): { segment: string | null; lastSeq: number; chainBreaks: number };
  /** Drains pending appends and writes a checkpoint. */
  close(): Promise<void>;
}

const SEG = /^segment-([0-9]{10})\.jsonl$/u;
const CP = 'checkpoint.json';
const HEX64 = /^[0-9a-f]{64}$/u;
const MAX_DIGESTS = 64;
const noFollow = fsConstants.O_NOFOLLOW ?? 0;
const sha = (bytes: Buffer | string): string => createHash('sha256').update(bytes).digest('hex');
const segName = (i: number): string => `segment-${String(i).padStart(10, '0')}.jsonl`;
const idxOf = (name: string): number | undefined => { const m = SEG.exec(name); return m ? Number(m[1]) : undefined; };

interface Checkpoint { seq: number; hash: string; segment: string }
interface Tail { index: number; size: number; seq: number; hash: string | null; newSeg: boolean; breakFrom: string | null }

async function safeDir(dir: string, uid: number): Promise<number> {
  await mkdir(dir, { mode: 0o700 }).catch((e) => { if ((e as NodeJS.ErrnoException)?.code !== 'EEXIST') throw e; });
  const info = await lstat(dir);
  if (info.isSymbolicLink() || !info.isDirectory()) throw new Error(`${dir} must be a real directory`);
  if (info.uid !== uid) throw new Error(`${dir} must be owned by uid ${uid}`);
  if ((info.mode & 0o077) !== 0) throw new Error(`${dir} has unsafe permissions`);
  return info.ino;
}

export async function openDecisionLog(dir: string, opts: LogOptions): Promise<DecisionLog> {
  dir = path.resolve(dir);
  const maxBytes = opts.maxSegmentBytes ?? 16 * 1024 * 1024;
  const maxSegments = opts.maxSegments ?? 8;
  const every = opts.checkpointEvery ?? 100;
  const now = opts.now ?? ((): Date => new Date());
  let dirIno = await safeDir(dir, opts.rootUid);

  const segments = async (): Promise<string[]> => {
    const names = (await readdir(dir)).filter((n) => SEG.test(n)).sort();
    for (const n of names) { // refuse, never repair: a symlink or loose file here is not ours
      const info = await lstat(path.join(dir, n));
      if (info.isSymbolicLink() || !info.isFile() || info.uid !== opts.rootUid || (info.mode & 0o077) !== 0) throw new Error(`${n} is not a root-only regular file`);
    }
    return names;
  };

  async function readCheckpoint(): Promise<Checkpoint | 'invalid' | undefined> {
    let bytes: Buffer;
    try { bytes = await readRegularFile(path.join(dir, CP), 'checkpoint', 4096); }
    catch (e) { return (e as NodeJS.ErrnoException)?.code === 'ENOENT' ? undefined : 'invalid'; }
    try {
      const v = JSON.parse(bytes.toString('utf8')) as Partial<Checkpoint>;
      return Number.isSafeInteger(v.seq) && typeof v.hash === 'string' && HEX64.test(v.hash) && typeof v.segment === 'string' && SEG.test(v.segment) && Object.keys(v).length === 3
        ? { seq: v.seq!, hash: v.hash, segment: v.segment } : 'invalid';
    } catch { return 'invalid'; }
  }

  let breaks = 0;
  async function recover(): Promise<Tail> {
    const names = await segments();
    const cp = await readCheckpoint();
    const cpOk = cp !== undefined && cp !== 'invalid' ? cp : undefined;
    const cpSeq = cpOk?.seq ?? 0;
    const last = names.at(-1);
    const brk = (from: string | null, seq: number, index: number): Tail => {
      breaks++;
      return { index: index + 1, size: 0, seq: Math.max(seq, cpSeq), hash: null, newSeg: true, breakFrom: from };
    };
    if (last === undefined) {
      if (cp === undefined) return { index: 1, size: 0, seq: 0, hash: null, newSeg: true, breakFrom: null }; // fresh
      return brk(cpOk?.segment ?? null, 0, cpOk ? idxOf(cpOk.segment)! : 0); // log deleted but a checkpoint remains
    }
    const index = idxOf(last)!;
    let content: Buffer;
    try { content = await readRegularFile(path.join(dir, last), 'log segment', maxBytes + 1024 * 1024); }
    catch { return brk(last, 0, index); }
    const lines = content.toString('utf8').split('\n');
    const complete = lines.pop() === ''; // anything after the last newline is a partial write
    let ok = complete && lines.length > 0 && cp !== 'invalid';
    let seq = 0, hash: string | null = null, valid = 0, firstSeq = 0, firstPrev: unknown, cpHashSeen = cpOk?.segment === last ? false : true;
    for (const line of lines) {
      let r: { seq?: unknown; prev?: unknown };
      try { r = JSON.parse(line) as typeof r; } catch { ok = false; break; }
      if (!Number.isSafeInteger(r.seq) || (r.prev !== null && typeof r.prev !== 'string')) { ok = false; break; }
      if (valid === 0) { firstSeq = r.seq as number; firstPrev = r.prev; }
      else if (r.seq !== seq + 1 || r.prev !== hash) { ok = false; break; }
      seq = r.seq as number; hash = sha(line); valid++;
      if (cpOk?.segment === last && seq === cpOk.seq) cpHashSeen = hash === cpOk.hash;
    }
    if (valid === 0) return brk(last, 0, index);
    if (cpOk) {
      const ci = idxOf(cpOk.segment)!;
      if (ci > index || (ci === index && !cpHashSeen) || (ci < index && (firstSeq !== cpOk.seq + 1 || firstPrev !== cpOk.hash))) ok = false;
    }
    if (!ok) return brk(last, seq, index);
    return { index, size: content.length, seq, hash, newSeg: false, breakFrom: null };
  }

  let st = await recover();
  let dirty = false;
  let lastRecovery = 0;
  let pending: { seq: number; input: LogInput } | undefined; // an enforce allow whose fsync failed: it needs a correction record
  let sinceCheckpoint = 0;
  let queue: Promise<unknown> = Promise.resolve();

  const checkpoint = async (): Promise<void> => {
    if (st.hash === null || st.newSeg && st.breakFrom !== null) return; // nothing written since a break
    const cp: Checkpoint = { seq: st.seq, hash: st.hash, segment: segName(st.index) };
    await writeFileAtomic(path.join(dir, CP), Buffer.from(JSON.stringify(cp)), 0o600);
    sinceCheckpoint = 0;
  };

  async function doAppend(input: LogInput, durable: boolean): Promise<void> {
    if (opts.fault?.()) throw new Error('injected log fault');
    if (!dirty) { // a deleted or replaced directory/segment is noticed here, not by a failing open
      const stale = await Promise.all([lstat(dir), st.newSeg ? 0 : lstat(path.join(dir, segName(st.index)))]).then(([d]) => d.ino !== dirIno, () => true);
      if (stale) dirty = true;
    }
    if (dirty) {
      if (Date.now() - lastRecovery < 1000) throw new Error('log recovery rate-limited'); // fail fast instead of re-reading a segment per append
      lastRecovery = Date.now();
      const prev = st;
      const ino = await safeDir(dir, opts.rootUid); // a loose or replaced directory stays refused
      const prevName = prev.newSeg ? null : segName(prev.index);
      const gone = prevName !== null && (ino !== dirIno || await lstat(path.join(dir, prevName)).then(() => false, () => true));
      if (gone) {
        breaks++;
        const lastIdx = (await segments()).map((n) => idxOf(n)!).at(-1) ?? 0;
        st = { index: Math.max(prev.index, lastIdx) + 1, size: 0, seq: prev.seq, hash: null, newSeg: true, breakFrom: prevName };
      } else st = await recover();
      dirIno = ino; dirty = false;
    }
    if (pending) { // the user never got that allow: say so before anything else
      const p = pending;
      await writeRecord({ ...p.input, action: 'deny', result: 'internal' }, false, p.seq);
      pending = undefined;
    }
    await writeRecord(input, durable, null);
  }

  async function writeRecord(input: LogInput, durable: boolean, supersedes: number | null): Promise<void> {
    const rotate = !st.newSeg && st.size > 0 && st.size + 4096 > maxBytes; // 4 KiB is above any record's size
    let wrote: number | undefined;
    try {
      if (rotate) { await checkpoint(); st = { ...st, index: st.index + 1, size: 0, newSeg: true }; }
      const record = {
        seq: st.seq + 1, boot_ms: input.bootMs, at: now().toISOString(), mode: input.mode, action: input.action, event: input.event,
        session: input.session, skill: input.skill, digests: input.digests.slice(0, MAX_DIGESTS), trust_root_version: input.trustRootVersion,
        revocations_version: input.revocationsVersion, result: input.result, build: input.build, elapsed_ms: input.elapsedMs,
        prev: st.hash, chain_break: st.breakFrom, supersedes,
      };
      const line = JSON.stringify(record);
      const bytes = Buffer.from(`${line}\n`);
      const file = path.join(dir, segName(st.index));
      const flags = fsConstants.O_WRONLY | fsConstants.O_APPEND | noFollow | (st.newSeg ? fsConstants.O_CREAT | fsConstants.O_EXCL : 0);
      const handle = await open(file, flags, 0o600);
      try {
        await handle.writeFile(bytes); wrote = record.seq;
        if (durable) { if (opts.syncFault?.()) throw new Error('injected fsync fault'); await handle.sync(); }
      } finally { await handle.close(); }
      const created = st.newSeg;
      st = { index: st.index, size: st.size + bytes.length, seq: record.seq, hash: sha(line), newSeg: false, breakFrom: null };
      if (created) for (const old of (await segments().catch(() => [])).slice(0, -maxSegments)) await unlink(path.join(dir, old)).catch(() => {});
      if (++sinceCheckpoint >= every) await checkpoint().catch(() => {}); // a stale checkpoint is still consistent
    } catch (error) {
      dirty = true;
      if (durable && wrote !== undefined) pending = { seq: wrote, input }; // written but not synced: the caller reports failure
      throw error;
    }
  }

  return {
    append(input, durable) { const run = queue.then(() => doAppend(input, durable)); queue = run.catch(() => {}); return run; },
    status: () => ({ segment: st.newSeg ? null : segName(st.index), lastSeq: st.seq, chainBreaks: breaks }),
    async close() { await queue; if (!dirty) await checkpoint(); },
  };
}
