// Exactly ONE writer process per directory is supported (the root service guarantees this in a later packet).
// Every operation re-reads manifest.json and reloads the state if another instance changed it, so a stale or
// sequential second instance is safe; truly simultaneous commits from two processes are not supported.
// Remaining limits (by design):
// - The directory must be root-only: anyone who can write it can replay an older complete committed set
//   (manifest + documents) undetectably.
// - The persisted clock high-water means a single far-future `now` locks the store out until time catches up
//   (intended; protect the clock).
// - Tampering after open is detected only on the next open.
import { createHash } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import { lstat, mkdir, open, readdir, unlink } from 'node:fs/promises';
import path from 'node:path';
import { canonicalBytes, exactKeys, MAX_CANONICAL_JSON_BYTES, parseCanonicalJsonBytes, requirePositiveInteger, requireString } from '../canonical-json.ts';
import { readRegularFile, writeFileAtomic } from '../fs-safe.ts';
import { readRevocationsForUpdate } from '../revocations.ts';
import { CLOCK_SKEW_MS, formatTimestamp, parseTimestamp, requireValidDate } from '../time.ts';
import { readTrustRootForUpdate } from '../trust-root.ts';
import { loadTrustContext, type MinimumVersions, type TrustContext } from '../verify.ts';

export type NotReadyReason = 'no-state' | 'state-corrupt' | 'list-expired' | 'trust-root-expired' | 'clock-moved-backwards';

export type CurrentTrust =
  | { ready: true; context: TrustContext; versions: MinimumVersions }
  | { ready: false; reason: NotReadyReason };

export type AcceptResult = { ok: true; changed: boolean } | { ok: false; reason: NotReadyReason | 'rejected'; message: string };

export interface TrustStoreOptions {
  rootFingerprint: string;
  now: Date;
  /** Extra freshness limit measured from the list's signed issued_at; can only be stricter than expires_at. */
  maxListAgeMs?: number;
  /** Tests only: injection points to make interleavings deterministic. Never set in production. */
  testHooks?: { beforeManifestWrite?: () => Promise<void> };
}

export interface TrustStore {
  accept(docs: { trustRootBytes: Uint8Array; revocationsBytes: Uint8Array }, now: Date): Promise<AcceptResult>;
  current(now: Date): Promise<CurrentTrust>;
}

const MANIFEST = 'manifest.json';
const MANIFEST_TYPE = 'mago.gate-trust-state/v1';
const TIME_PERSIST_STEP_MS = 60_000;

interface Entry { file: string; sha256: string; version: number }
interface Manifest { trustRoot: Entry; revocations: Entry; highTime: Date }
interface State { manifest: Manifest; manifestBytes: Buffer; trustRootBytes: Buffer; revocationsBytes: Buffer }

const sha256 = (bytes: Uint8Array): string => createHash('sha256').update(bytes).digest('hex');

function manifestJson(m: Manifest): Buffer {
  const entry = (e: Entry) => ({ file: e.file, sha256: e.sha256, version: e.version });
  return canonicalBytes({
    type: MANIFEST_TYPE, trust_root: entry(m.trustRoot), revocations: entry(m.revocations), high_time: formatTimestamp(m.highTime),
  });
}

function parseEntry(value: unknown, label: string): Entry {
  const e = exactKeys(value, ['file', 'sha256', 'version'], label);
  const file = requireString(e.file, `${label} file`, 128);
  const digest = requireString(e.sha256, `${label} sha256`, 64);
  if (!/^[0-9a-f]{64}$/u.test(digest) || path.basename(file) !== file || file.startsWith('.'))
    throw new Error(`${label} is malformed`);
  return { file, sha256: digest, version: requirePositiveInteger(e.version, `${label} version`) };
}

function parseManifest(bytes: Uint8Array): Manifest {
  const m = exactKeys(parseCanonicalJsonBytes(bytes, 'trust-state manifest'), ['type', 'trust_root', 'revocations', 'high_time'], 'manifest');
  if (m.type !== MANIFEST_TYPE) throw new Error('manifest has unsupported type');
  return {
    trustRoot: parseEntry(m.trust_root, 'manifest trust_root'),
    revocations: parseEntry(m.revocations, 'manifest revocations'),
    highTime: parseTimestamp(m.high_time, 'manifest high_time'),
  };
}

async function fsyncDir(dir: string): Promise<void> {
  const handle = await open(dir, fsConstants.O_RDONLY | (fsConstants.O_DIRECTORY ?? 0));
  try { await handle.sync(); } finally { await handle.close(); }
}

/** Reads and re-verifies the committed state. Throws on any mismatch (the caller maps that to state-corrupt). */
async function loadState(dir: string, rootFingerprint: string): Promise<State | null> {
  let manifestBytes: Buffer;
  try {
    manifestBytes = await readRegularFile(path.join(dir, MANIFEST), 'trust-state manifest', MAX_CANONICAL_JSON_BYTES);
  } catch (error) {
    if ((error as NodeJS.ErrnoException)?.code !== 'ENOENT') throw error;
    // A missing manifest is a fresh store only if no committed document exists; otherwise rollback state was lost.
    if ((await readdir(dir)).some((name) => !/^\..*\.tmp$/u.test(name))) throw new Error('manifest is missing but the store is not empty');
    return null;
  }
  const manifest = parseManifest(manifestBytes);
  const read = async (entry: Entry): Promise<Buffer> => {
    const bytes = await readRegularFile(path.join(dir, entry.file), entry.file, MAX_CANONICAL_JSON_BYTES);
    if (sha256(bytes) !== entry.sha256) throw new Error(`${entry.file} does not match the manifest`);
    return bytes;
  };
  const trustRootBytes = await read(manifest.trustRoot);
  const revocationsBytes = await read(manifest.revocations);
  // Signatures only: expiry is judged per call in current().
  const trustRoot = readTrustRootForUpdate(trustRootBytes, rootFingerprint);
  const revocations = readRevocationsForUpdate(revocationsBytes, trustRoot.root.keyId, trustRoot.root.publicKey);
  if (trustRoot.version !== manifest.trustRoot.version || revocations.version !== manifest.revocations.version)
    throw new Error('document versions do not match the manifest');
  return { manifest, manifestBytes, trustRootBytes, revocationsBytes };
}

export async function openTrustStore(dir: string, options: TrustStoreOptions): Promise<TrustStore> {
  requireValidDate(options.now, 'Open time');
  dir = path.resolve(dir);
  await mkdir(dir, { mode: 0o700 }).catch((error) => {
    if ((error as NodeJS.ErrnoException)?.code !== 'EEXIST') throw error;
  });
  const info = await lstat(dir);
  if (info.isSymbolicLink() || !info.isDirectory()) throw new Error('trust store directory must be a real directory, not a symlink');
  if ((info.mode & 0o022) !== 0) throw new Error('trust store directory must not be group- or world-writable');

  let corrupt = false;
  let state: State | null = null;
  try {
    state = await loadState(dir, options.rootFingerprint);
  } catch {
    corrupt = true;
  }
  // Highest trusted time seen, in memory; persisted in the manifest in coarse steps.
  let highTime = state?.manifest.highTime ?? options.now;
  const { rootFingerprint, maxListAgeMs } = options;

  const clockBack = (now: Date): boolean => now.getTime() < highTime.getTime() - CLOCK_SKEW_MS;

  async function writeManifest(manifest: Manifest): Promise<Buffer> {
    const bytes = manifestJson(manifest);
    await writeFileAtomic(path.join(dir, MANIFEST), bytes, 0o600);
    await fsyncDir(dir);
    return bytes;
  }

  /** Inside the lock: reload from disk if manifest.json is not byte-identical to what this instance last held. */
  async function refresh(): Promise<void> {
    if (corrupt) return;
    let disk: Buffer | null = null;
    try {
      disk = await readRegularFile(path.join(dir, MANIFEST), 'trust-state manifest', MAX_CANONICAL_JSON_BYTES);
    } catch (error) {
      if ((error as NodeJS.ErrnoException)?.code !== 'ENOENT') { corrupt = true; return; }
    }
    const held = state?.manifestBytes ?? null;
    if (disk === null ? held === null : held !== null && disk.equals(held)) return;
    try {
      const previous = state;
      state = await loadState(dir, rootFingerprint);
      // A running instance never accepts a reload that is empty or older than what it held.
      if (previous && (!state
        || state.manifest.trustRoot.version < previous.manifest.trustRoot.version
        || state.manifest.revocations.version < previous.manifest.revocations.version)) { corrupt = true; return; }
      if (state && state.manifest.highTime > highTime) highTime = state.manifest.highTime;
    } catch {
      corrupt = true;
    }
  }

  async function advance(now: Date): Promise<void> {
    if (now > highTime) highTime = now;
    // shortcut: persisted time lags by up to a minute, so a restart can forget that much; upgrade if tighter is needed.
    if (state && highTime.getTime() - state.manifest.highTime.getTime() >= TIME_PERSIST_STEP_MS) {
      const next = { ...state.manifest, highTime };
      await options.testHooks?.beforeManifestWrite?.(); // tests only: pauses the time-persistence write
      // a failed refresh must not break decisions; the old persisted time stays
      const manifestBytes = await writeManifest(next).catch(() => null);
      if (manifestBytes) state = { ...state, manifest: next, manifestBytes };
    }
  }

  // One promise-chain mutex: each operation runs to completion (and always releases) before the next starts.
  let tail: Promise<unknown> = Promise.resolve();
  const locked = <T>(fn: () => Promise<T>): Promise<T> => {
    const run = tail.then(fn);
    tail = run.catch(() => {});
    return run;
  };

  return {
    current: (now) => locked(async () => {
      requireValidDate(now, 'Time');
      await refresh();
      if (corrupt) return { ready: false, reason: 'state-corrupt' };
      if (!state) return { ready: false, reason: 'no-state' };
      if (clockBack(now)) return { ready: false, reason: 'clock-moved-backwards' };
      const loaded = loadTrustContext({ trustRootBytes: state.trustRootBytes, revocationsBytes: state.revocationsBytes, rootKeyId: rootFingerprint, now });
      if (!loaded.ok) {
        if (loaded.verdict !== 'EXPIRED') return { ready: false, reason: 'state-corrupt' };
        return { ready: false, reason: loaded.reason.startsWith('trust root') ? 'trust-root-expired' : 'list-expired' };
      }
      const { revocations, trustRoot } = loaded.context;
      if (maxListAgeMs !== undefined && revocations.issuedAt.getTime() + maxListAgeMs <= now.getTime())
        return { ready: false, reason: 'list-expired' };
      await advance(now);
      return { ready: true, context: loaded.context, versions: { trustRootVersion: trustRoot.version, revocationsVersion: revocations.version } };
    }),

    accept: ({ trustRootBytes, revocationsBytes }, now) => locked(async () => {
      requireValidDate(now, 'Time');
      const reject = (reason: NotReadyReason | 'rejected', message: string): AcceptResult => ({ ok: false, reason, message });
      await refresh();
      if (corrupt) return reject('state-corrupt', 'existing trust state is corrupt; an administrator must reset it');
      if (clockBack(now)) return reject('clock-moved-backwards', 'clock is earlier than the highest trusted time');
      if (trustRootBytes.length > MAX_CANONICAL_JSON_BYTES || revocationsBytes.length > MAX_CANONICAL_JSON_BYTES)
        return reject('rejected', 'document exceeds the size limit');

      const loaded = loadTrustContext({
        trustRootBytes, revocationsBytes, rootKeyId: rootFingerprint, now,
        minimum: state ? { trustRootVersion: state.manifest.trustRoot.version, revocationsVersion: state.manifest.revocations.version } : undefined,
      });
      if (!loaded.ok) return reject('rejected', loaded.reason);
      const { trustRoot, revocations } = loaded.context;
      if (maxListAgeMs !== undefined && revocations.issuedAt.getTime() + maxListAgeMs <= now.getTime())
        return reject('rejected', 'revocation list is older than the configured maximum age');

      const sameTrustRoot = state !== null && Buffer.from(trustRootBytes).equals(state.trustRootBytes);
      const sameList = state !== null && Buffer.from(revocationsBytes).equals(state.revocationsBytes);
      if (state && !sameTrustRoot && trustRoot.version === state.manifest.trustRoot.version)
        return reject('rejected', 'a different trust root with the same version was already accepted');
      if (state && !sameList && revocations.version === state.manifest.revocations.version)
        return reject('rejected', 'a different revocation list with the same version was already accepted');
      if (sameTrustRoot && sameList) {
        await advance(now);
        return { ok: true, changed: false };
      }

      // Content-addressed names: the old files stay intact until the new manifest is in place.
      const trustHash = sha256(trustRootBytes);
      const listHash = sha256(revocationsBytes);
      const previous = state?.manifest;
      const manifest: Manifest = {
        trustRoot: { file: `trust-root.${trustHash}.json`, sha256: trustHash, version: trustRoot.version },
        revocations: { file: `revocations.${listHash}.json`, sha256: listHash, version: revocations.version },
        highTime: now > highTime ? now : highTime,
      };
      let manifestBytes: Buffer;
      try {
        await writeFileAtomic(path.join(dir, manifest.trustRoot.file), trustRootBytes, 0o600);
        await writeFileAtomic(path.join(dir, manifest.revocations.file), revocationsBytes, 0o600);
        await fsyncDir(dir);
        manifestBytes = await writeManifest(manifest); // last: this is the commit point
      } catch (error) {
        return reject('rejected', `could not commit trust state: ${(error as Error).message}`);
      }
      state = { manifest, manifestBytes, trustRootBytes: Buffer.from(trustRootBytes), revocationsBytes: Buffer.from(revocationsBytes) };
      highTime = manifest.highTime;

      // Best-effort cleanup: only files the previous manifest referenced and the new one does not.
      const keep = new Set([manifest.trustRoot.file, manifest.revocations.file]);
      for (const name of previous ? [previous.trustRoot.file, previous.revocations.file] : [])
        if (!keep.has(name)) await unlink(path.join(dir, name)).catch(() => {});
      return { ok: true, changed: true };
    }),
  };
}
