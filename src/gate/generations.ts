// Private staging and immutable generation store for the Skill gate (E3 packet 4).
// A candidate Skill is COPIED (never adopted) into a private staging directory, the COPIED bytes are verified with
// the engine, and only a VERIFIED copy is published as <generationsRoot>/<name>/<digest-hex>/ (read-only) plus a
// <digest-hex>.manifest.json. The manifest is local installation provenance written by this service, not an
// approval: approval is the certificate, checked again by the engine on every use.
// Profile (docs/spec/skill-tree-v2.md): a Skill with a root `.skilldigestignore` is rejected, because ignored paths
// are uncovered bytes that a read-only, fully verified generation must not contain. The root `.git` and the in-tree
// certificate are not copied (the digest already excludes them; certificates come from the caller).
// Linux only (shortcut): every root (source, staging, generations, <generations>/<name>) is opened by walking from `/`
// one component at a time with O_DIRECTORY|O_NOFOLLOW through /proc/self/fd, so no ancestor can be swapped for a
// symlink mid-operation. If /proc/self/fd is missing, staging and publishing fail closed (io-error); there is no
// path-based fallback. Staging and generations roots must not be group/world-writable. Ownership is not checked; in
// production the store is root-owned and root-only.
// Publication must be serialised by the service (packet 6). A crash (or a concurrent loser) between rename and
// manifest write leaves a generation directory without manifest, reported as generation-incomplete; it is never
// repaired automatically and needs an admin cleanup.
import { constants as fsConstants, existsSync, type Dirent } from 'node:fs';
import { chmod, lstat, mkdir, mkdtemp, open, readdir, rename, rm, type FileHandle } from 'node:fs/promises';
import path from 'node:path';
import { canonicalBytes, exactKeys, parseCanonicalJsonBytes, requirePositiveInteger, requireString } from '../canonical-json.ts';
import { writeFileAtomic } from '../fs-safe.ts';
import { validateDigest, validateSkillName } from '../names.ts';
import {
  CERTIFICATE_FILENAME, compareTreePaths, decodeEntryName, digestFileList, IGNORE_FILENAME, isExecutable, MAX_FILE_BYTES,
  MAX_RELATIVE_PATH_BYTES, MAX_TREE_BYTES, MAX_TREE_ENTRIES, MAX_TREE_FILES, sha256Hex, SKILL_FILENAME, TREE_PROFILE, type TreeFile,
} from '../tree-digest.ts';
import { decide, type CertificateSource, type TrustContext, type Verdict } from '../verify.ts';

export const GENERATION_TYPE = 'mago.gate-generation/v1';

export type Rejection =
  | 'symlink' | 'special-file' | 'hard-link' | 'unsafe-name' | 'too-large' | 'ignored-content-not-allowed'
  | 'not-verified' | 'generation-mismatch' | 'generation-incomplete' | 'io-error';

export interface Failure { ok: false; reason: Rejection; detail: string; verdict?: Verdict }

export interface GenerationManifest {
  type: typeof GENERATION_TYPE;
  skill: string;
  treeDigest: string;
  files: TreeFile[];
  certificateId: string;
  trustRootVersion: number;
  revocationsVersion: number;
  buildProfile: string;
}

export type PublishResult = { ok: true; created: boolean; manifest: GenerationManifest; dir: string } | Failure;
export type ReadResult = { ok: true; manifest: GenerationManifest } | Failure;

class GenError extends Error {
  reason: Rejection;
  verdict: Verdict | undefined;
  constructor(reason: Rejection, detail: string, verdict?: Verdict) { super(detail); this.reason = reason; this.verdict = verdict; }
}

function toFailure(error: unknown): Failure {
  if (error instanceof GenError) return { ok: false, reason: error.reason, detail: error.message, ...(error.verdict ? { verdict: error.verdict } : {}) };
  const code = (error as NodeJS.ErrnoException)?.code;
  return { ok: false, reason: 'io-error', detail: typeof code === 'string' ? code : 'unexpected error' };
}

const noFollow  = fsConstants.O_NOFOLLOW ?? 0;
const nonBlock  = fsConstants.O_NONBLOCK ?? 0;
const dirFlag   = fsConstants.O_DIRECTORY ?? 0;
const MAX_DEPTH = 64;
const useProcFd = existsSync('/proc/self/fd');

const procOf = (h: FileHandle): string => `/proc/self/fd/${h.fd}`;

async function openDirAt(parent: string, name: string, create?: number): Promise<FileHandle> {
  const p = `${parent}/${name}`;
  let handle: FileHandle | undefined;
  for (let attempt = 0; !handle; attempt++) {
    try {
      handle = await open(p, fsConstants.O_RDONLY | dirFlag | noFollow);
    } catch (error) {
      const code = (error as NodeJS.ErrnoException)?.code;
      if (code === 'ELOOP' || code === 'ENOTDIR') throw new GenError('symlink', JSON.stringify(name));
      if (code === 'ENOENT' && create !== undefined && attempt === 0) {
        await mkdir(p, { mode: create }).catch((e) => { if ((e as NodeJS.ErrnoException)?.code !== 'EEXIST') throw e; });
        continue;
      }
      throw error;
    }
  }
  if (!(await handle.stat()).isDirectory()) { await handle.close(); throw new GenError('symlink', JSON.stringify(name)); }
  return handle;
}

/** Opens an absolute directory race-free (no symlink on any component). `create` makes missing components. */
async function walkDir(abs: string, create?: number): Promise<FileHandle> {
  if (!useProcFd) throw new GenError('io-error', '/proc/self/fd unavailable (Linux only)');
  let cur = await open('/', fsConstants.O_RDONLY | dirFlag);
  for (const comp of path.resolve(abs).split('/').filter(Boolean)) {
    let next: FileHandle;
    try { next = await openDirAt(procOf(cur), comp, create); } finally { await cur.close(); }
    cur = next;
  }
  return cur;
}

async function requirePrivate(h: FileHandle, label: string): Promise<void> {
  if (((await h.stat()).mode & 0o022) !== 0) throw new GenError('io-error', `${label} is group/world-writable`);
}

interface Budget { entries: number; files: number; bytes: number }

async function openChecked(p: string, label: string, wantDir: boolean): Promise<FileHandle> {
  let handle: FileHandle;
  try {
    handle = await open(p, fsConstants.O_RDONLY | noFollow | nonBlock | (wantDir ? dirFlag : 0));
  } catch (error) {
    const code = (error as NodeJS.ErrnoException)?.code;
    if (code === 'ELOOP') throw new GenError('symlink', JSON.stringify(label));
    if (code === 'ENXIO') throw new GenError('special-file', JSON.stringify(label));
    throw error;
  }
  try {
    const st = await handle.stat();
    if (wantDir ? !st.isDirectory() : !st.isFile()) throw new GenError('special-file', JSON.stringify(label));
    if (!wantDir && st.nlink > 1) throw new GenError('hard-link', JSON.stringify(label));
  } catch (error) {
    await handle.close();
    throw error;
  }
  return handle;
}

async function copyFile(src: string, dst: string, label: string, b: Budget): Promise<void> {
  if (++b.files > MAX_TREE_FILES) throw new GenError('too-large', 'file count');
  const input = await openChecked(src, label, false);
  try {
    const exec = isExecutable((await input.stat()).mode);
    await mkdir(path.dirname(dst), { recursive: true, mode: 0o700 });
    const output = await open(dst, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | noFollow, 0o600);
    try {
      const chunk = Buffer.allocUnsafe(64 * 1024);
      let size = 0;
      while (true) {
        const { bytesRead } = await input.read(chunk, 0, chunk.length, null);
        if (bytesRead === 0) break;
        size += bytesRead;
        b.bytes += bytesRead;
        if (size > MAX_FILE_BYTES || b.bytes > MAX_TREE_BYTES) throw new GenError('too-large', JSON.stringify(label));
        await output.writeFile(chunk.subarray(0, bytesRead));
      }
      await output.chmod(exec ? 0o755 : 0o644);
    } finally {
      await output.close();
    }
  } finally {
    await input.close();
  }
}

async function copyDir(dir: FileHandle, rel: string, dst: string, depth: number, b: Budget): Promise<void> {
  if (depth > MAX_DEPTH) throw new GenError('too-large', 'directory depth');
  {
    // Children are addressed through the open directory fd so a swapped ancestor cannot redirect them.
    const base = procOf(dir);
    for (const entry of await readdir(base, { withFileTypes: true, encoding: 'buffer' }) as unknown as Dirent<Buffer>[]) {
      if (++b.entries > MAX_TREE_ENTRIES) throw new GenError('too-large', 'entry count');
      let name: string;
      try { name = decodeEntryName(entry.name); } catch { throw new GenError('unsafe-name', JSON.stringify(rel || '.')); }
      const relPath = rel ? `${rel}/${name}` : name;
      if (Buffer.byteLength(relPath) > MAX_RELATIVE_PATH_BYTES) throw new GenError('too-large', 'path length');
      if (!rel && name === IGNORE_FILENAME) throw new GenError('ignored-content-not-allowed', IGNORE_FILENAME);
      if (!rel && (name === '.git' || (name === CERTIFICATE_FILENAME && !entry.isDirectory()))) continue;
      const child = `${base}/${name}`;
      if (entry.isSymbolicLink()) throw new GenError('symlink', JSON.stringify(relPath));
      if (entry.isDirectory()) {
        const sub = await openChecked(child, relPath, true);
        try { await copyDir(sub, relPath, path.join(dst, name), depth + 1, b); } finally { await sub.close(); }
      }
      else if (entry.isFile()) await copyFile(child, path.join(dst, name), relPath, b);
      else throw new GenError('special-file', JSON.stringify(relPath));
    }
  }
}

/**
 * Opaque handle to a staged copy: the open staging root, the open stage directory and the stage name. publishStaged
 * is the only consumer; it reads the tree and renames through these descriptors, never through a caller path.
 * `stagedDir` is informational (display / tests) and is never used for I/O by this module.
 */
export class StagedSkill {
  readonly stagedDir: string;
  stagingH: FileHandle;
  stageH: FileHandle;
  name: string;
  closed = false;
  constructor(stagedDir: string, stagingH: FileHandle, stageH: FileHandle, name: string) {
    this.stagedDir = stagedDir; this.stagingH = stagingH; this.stageH = stageH; this.name = name;
  }
  /** Removes the staged copy and closes both handles (idempotent). publishStaged calls this on every path. */
  async discard(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    try { await rm(`${procOf(this.stagingH)}/${this.name}`, { recursive: true, force: true }); }
    finally { await this.stageH.close(); await this.stagingH.close(); }
  }
}

export type StageResult = { ok: true; staged: StagedSkill } | Failure;

/** Copies `sourceDir` into a fresh 0700 directory under `stagingRoot`. The caller must publish or discard the result. */
export async function stageSkill(sourceDir: string, stagingRoot: string): Promise<StageResult> {
  let rootH: FileHandle | undefined;
  let stagingH: FileHandle | undefined;
  let stageH: FileHandle | undefined;
  let name: string | undefined;
  try {
    rootH = await walkDir(sourceDir);
    stagingH = await walkDir(stagingRoot, 0o700);
    await requirePrivate(stagingH, 'staging root');
    name = path.basename(await mkdtemp(`${procOf(stagingH)}/stage-`));
    stageH = await openDirAt(procOf(stagingH), name);
    await copyDir(rootH, '', procOf(stageH), 0, { entries: 0, files: 0, bytes: 0 });
    const staged = new StagedSkill(path.join(path.resolve(stagingRoot), name), stagingH, stageH, name);
    stagingH = undefined; stageH = undefined;
    return { ok: true, staged };
  } catch (error) {
    if (name && stagingH) await rm(`${procOf(stagingH)}/${name}`, { recursive: true, force: true });
    return toFailure(error);
  } finally {
    await rootH?.close();
    await stageH?.close();
    await stagingH?.close();
  }
}

interface FdTree {
  digest: string; files: TreeFile[]; totalBytes: number; excluded: string[];
  dirs: Map<string, number>; fileModes: Map<string, number>;
}

/**
 * Collects and digests a tree reading ONLY through open descriptors (/proc/self/fd/<fd>/<child>, O_NOFOLLOW per
 * component), so no ancestor of the tree can redirect it. The kernel resolves /proc/self/fd/<fd> to the opened
 * directory itself, not by re-walking its path; the engine's collectSkillTree cannot be used here because it
 * re-resolves realpath(root) and walks by path. Stricter than the engine: hard links are rejected.
 * Same digest as the engine for the same bytes (tests compare against engine-issued certificates).
 */
async function collectFd(root: FileHandle): Promise<FdTree> {
  const files: TreeFile[] = [];
  const fileModes = new Map<string, number>();
  const dirs = new Map<string, number>([['', (await root.stat()).mode & 0o7777]]);
  const excluded: string[] = [];
  const seen = new Set<string>();
  let entries = 0, totalBytes = 0;
  const visit = async (dir: FileHandle, rel: string, depth: number): Promise<void> => {
    if (depth > MAX_DEPTH) throw new GenError('too-large', 'directory depth');
    const base = procOf(dir);
    for (const entry of await readdir(base, { withFileTypes: true, encoding: 'buffer' }) as unknown as Dirent<Buffer>[]) {
      if (++entries > MAX_TREE_ENTRIES) throw new GenError('too-large', 'entry count');
      let name: string;
      try { name = decodeEntryName(entry.name); } catch { throw new GenError('unsafe-name', JSON.stringify(rel || '.')); }
      const relPath = rel ? `${rel}/${name}` : name;
      if (Buffer.byteLength(relPath) > MAX_RELATIVE_PATH_BYTES) throw new GenError('too-large', 'path length');
      const caseKey = relPath.normalize('NFKC').toLowerCase();
      if (seen.has(caseKey)) throw new GenError('unsafe-name', `case collision ${JSON.stringify(relPath)}`);
      seen.add(caseKey);
      if (!rel && (name === '.git' || name === IGNORE_FILENAME || (name === CERTIFICATE_FILENAME && !entry.isDirectory()))) {
        excluded.push(relPath);
        continue;
      }
      const child = `${base}/${name}`;
      if (entry.isSymbolicLink()) throw new GenError('symlink', JSON.stringify(relPath));
      if (entry.isDirectory()) {
        const sub = await openChecked(child, relPath, true);
        try { dirs.set(relPath, (await sub.stat()).mode & 0o7777); await visit(sub, relPath, depth + 1); } finally { await sub.close(); }
      } else if (entry.isFile()) {
        if (files.length >= MAX_TREE_FILES) throw new GenError('too-large', 'file count');
        const h = await openChecked(child, relPath, false);
        try {
          const st = await h.stat();
          if (st.size > MAX_FILE_BYTES) throw new GenError('too-large', JSON.stringify(relPath));
          const content = await h.readFile();
          totalBytes += content.length;
          if (content.length > MAX_FILE_BYTES || totalBytes > MAX_TREE_BYTES) throw new GenError('too-large', JSON.stringify(relPath));
          files.push({ path: relPath, size: content.length, sha256: sha256Hex(content), exec: isExecutable(st.mode) });
          fileModes.set(relPath, st.mode & 0o7777);
        } finally { await h.close(); }
      } else throw new GenError('special-file', JSON.stringify(relPath));
    }
  };
  await visit(root, '', 0);
  files.sort((x, y) => compareTreePaths(x.path, y.path));
  if (!files.some((f) => f.path === SKILL_FILENAME)) throw new GenError('not-verified', 'SKILL.md missing');
  return { digest: digestFileList(files), files, totalBytes, excluded: excluded.sort(), dirs, fileModes };
}

const hexOf = (digest: string): string => validateDigest(digest).slice('sha256:'.length);
const pickFile = (f: TreeFile): TreeFile => ({ path: f.path, size: f.size, sha256: f.sha256, exec: f.exec });

function manifestBytes(m: GenerationManifest): Buffer {
  return canonicalBytes({
    type: m.type, skill: m.skill, tree_digest: m.treeDigest, files: m.files.map(pickFile),
    certificate_id: m.certificateId, trust_root_version: m.trustRootVersion,
    revocations_version: m.revocationsVersion, build_profile: m.buildProfile,
  });
}

const MAX_MANIFEST_BYTES = 16 * 1024 * 1024;

/** Re-verifies generation <digest> inside the open <generations>/<name> directory, reading only through descriptors. */
async function readGenerationAt(nameH: FileHandle, name: string, digest: string): Promise<ReadResult> {
  const hex = hexOf(digest);
  const bad = (detail: string) => new GenError('generation-mismatch', detail);
  let dirH: FileHandle | undefined;
  try {
    let raw: Buffer;
    try {
      const mh = await openChecked(`${procOf(nameH)}/${hex}.manifest.json`, 'generation manifest', false);
      try {
        if ((await mh.stat()).size > MAX_MANIFEST_BYTES) throw new Error('too large');
        raw = await mh.readFile();
      } finally { await mh.close(); }
    } catch { throw bad('manifest missing or unreadable'); }
    let manifest: GenerationManifest;
    try {
      const m = exactKeys(parseCanonicalJsonBytes(raw, 'generation manifest'), [
        'type', 'skill', 'tree_digest', 'files', 'certificate_id', 'trust_root_version', 'revocations_version', 'build_profile',
      ], 'generation manifest');
      if (m.type !== GENERATION_TYPE || !Array.isArray(m.files)) throw new Error('bad type');
      manifest = {
        type: GENERATION_TYPE, skill: requireString(m.skill, 'skill', 128), treeDigest: validateDigest(m.tree_digest),
        files: m.files as TreeFile[], certificateId: requireString(m.certificate_id, 'certificate_id', 256),
        trustRootVersion: requirePositiveInteger(m.trust_root_version, 'trust_root_version'),
        revocationsVersion: requirePositiveInteger(m.revocations_version, 'revocations_version'),
        buildProfile: requireString(m.build_profile, 'build_profile', 256),
      };
    } catch { throw bad('manifest invalid'); }
    if (manifest.skill !== name || manifest.treeDigest !== digest) throw bad('manifest names another generation');

    let tree: FdTree;
    try {
      dirH = await openDirAt(procOf(nameH), hex);
      tree = await collectFd(dirH);
    } catch { throw bad('tree unreadable or contains links or special files'); }
    // excluded must be empty: a planted .git, certificate or ignore rule would hide bytes from the digest.
    if (tree.digest !== digest || tree.excluded.length || !canonicalBytes(tree.files.map(pickFile)).equals(canonicalBytes(manifest.files)))
      throw bad('tree differs from manifest');
    // The digest covers bytes and exec bits; directories and modes are checked here from the same descriptors.
    const dirs = new Set(['']);
    for (const f of tree.files) for (let d = path.posix.dirname(f.path); d !== '.'; d = path.posix.dirname(d)) dirs.add(d);
    for (const [rel, mode] of tree.dirs) if (!dirs.has(rel) || mode !== 0o555) throw bad('directory mode or unexpected directory');
    for (const f of tree.files) if (tree.fileModes.get(f.path) !== (f.exec ? 0o555 : 0o444)) throw bad('file mode');
    return { ok: true, manifest };
  } catch (error) {
    return toFailure(error);
  } finally {
    await dirH?.close();
  }
}

/** Re-verifies a published generation against its manifest: bytes, exec bits, modes, no extras, no links. */
export async function readGeneration(generationsRoot: string, name: string, digest: string): Promise<ReadResult> {
  let gensH: FileHandle | undefined;
  let nameH: FileHandle | undefined;
  try {
    validateSkillName(name);
    hexOf(digest);
    try {
      gensH = await walkDir(generationsRoot);
      nameH = await openDirAt(procOf(gensH), name);
    } catch (error) {
      if ((error as NodeJS.ErrnoException)?.code === 'ENOENT') throw new GenError('generation-mismatch', 'generation missing');
      throw error;
    }
    return await readGenerationAt(nameH, name, digest);
  } catch (error) {
    return toFailure(error);
  } finally {
    await nameH?.close();
    await gensH?.close();
  }
}

async function seal(dir: string, files: readonly TreeFile[]): Promise<void> {
  const dirs = new Set(['']);
  for (const f of files) {
    await chmod(path.join(dir, f.path), f.exec ? 0o555 : 0o444);
    for (let d = path.posix.dirname(f.path); d !== '.'; d = path.posix.dirname(d)) dirs.add(d);
  }
  for (const d of [...dirs].sort((a, b) => b.length - a.length)) await chmod(path.join(dir, d), 0o555);
}

export interface PublishOptions {
  generationsRoot: string;
  skillName: string;
  certificates: readonly CertificateSource[];
  context: TrustContext;
  now: Date;
  /** Opaque build/profile identifier recorded in the manifest. */
  buildProfile: string;
}

/** Verifies the staged copy and publishes it as an immutable generation. The staged copy is always removed and its handles closed. */
export async function publishStaged(staged: StagedSkill, o: PublishOptions): Promise<PublishResult> {
  let gensH: FileHandle | undefined;
  let nameH: FileHandle | undefined;
  try {
    let tree: FdTree;
    try { tree = await collectFd(staged.stageH); } catch (e) { throw new GenError('not-verified', (e as Error).message); }
    if (tree.excluded.length) throw new GenError('ignored-content-not-allowed', 'excluded entries in staged tree');
    const result = decide({
      skillDir: staged.stagedDir, skillName: o.skillName, certificates: o.certificates, context: o.context, now: o.now,
      tree: { profile: TREE_PROFILE, digest: tree.digest, root: staged.stagedDir, files: tree.files, totalBytes: tree.totalBytes, excluded: tree.excluded },
    });
    if (result.verdict !== 'VERIFIED') throw new GenError('not-verified', result.reason, result.verdict);

    const skill = validateSkillName(o.skillName);
    const hexDigest = hexOf(tree.digest);
    const manifest: GenerationManifest = {
      type: GENERATION_TYPE, skill: o.skillName, treeDigest: tree.digest, files: tree.files.map(pickFile),
      certificateId: result.certificateId!, trustRootVersion: o.context.trustRoot.version,
      revocationsVersion: o.context.revocations.version, buildProfile: o.buildProfile,
    };

    gensH = await walkDir(o.generationsRoot, 0o755);
    await requirePrivate(gensH, 'generations root');
    nameH = await openDirAt(procOf(gensH), skill, 0o755);
    await requirePrivate(nameH, 'generation name directory');
    const dest = path.join(path.resolve(o.generationsRoot), skill, hexDigest);
    const destFd = `${procOf(nameH)}/${hexDigest}`;
    if (await lstat(destFd).then(() => true, () => false)) {
      if (!(await lstat(`${destFd}.manifest.json`).then(() => true, () => false)))
        throw new GenError('generation-incomplete', 'generation directory without manifest');
      const existing = await readGenerationAt(nameH, o.skillName, tree.digest);
      if (!existing.ok) return existing;
      return { ok: true, created: false, manifest: existing.manifest, dir: dest };
    }
    // The stage name must still be the directory we verified (same inode); the staging root itself is private.
    const src = `${procOf(staged.stagingH)}/${staged.name}`;
    const [a, b] = await Promise.all([lstat(src), staged.stageH.stat()]);
    if (a.ino !== b.ino || a.dev !== b.dev) throw new GenError('not-verified', 'staged directory changed');
    try {
      await rename(src, destFd);
    } catch (error) {
      if (['EEXIST', 'ENOTEMPTY'].includes((error as NodeJS.ErrnoException).code ?? '')) throw new GenError('generation-incomplete', 'generation appeared concurrently');
      throw error;
    }
    await seal(procOf(staged.stageH), manifest.files); // same inode as dest, reached by descriptor
    await writeFileAtomic(`${destFd}.manifest.json`, manifestBytes(manifest), 0o444);
    return { ok: true, created: true, manifest, dir: dest };
  } catch (error) {
    return toFailure(error);
  } finally {
    await nameH?.close();
    await gensH?.close();
    await staged.discard();
  }
}

/** Stage, verify the copy, publish. */
export async function installSkill(sourceDir: string, stagingRoot: string, o: PublishOptions): Promise<PublishResult> {
  const staged = await stageSkill(sourceDir, stagingRoot);
  return staged.ok ? await publishStaged(staged.staged, o) : staged;
}
