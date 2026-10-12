import { randomBytes } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import { lstat, open, realpath, rename, unlink } from 'node:fs/promises';
import path from 'node:path';

const noFollow = fsConstants.O_NOFOLLOW ?? 0;
const nonBlock = fsConstants.O_NONBLOCK ?? 0;

export function isInside(root: string, candidate: string): boolean {
  const relative = path.relative(root, candidate);
  return relative === '' || (relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative));
}

/** Reads a regular, non-symlink file, failing if it changes while being read. */
export async function readRegularFile(filePath: string, label: string, maxBytes = 1024 * 1024): Promise<Buffer> {
  const entry = await lstat(filePath);
  if (entry.isSymbolicLink() || !entry.isFile()) throw new Error(`${label} must be a regular, non-symlink file`);
  if (entry.size > maxBytes) throw new Error(`${label} exceeds the ${maxBytes}-byte limit`);
  const handle = await open(filePath, fsConstants.O_RDONLY | noFollow);
  try {
    const before = await handle.stat();
    if (!before.isFile() || before.dev !== entry.dev || before.ino !== entry.ino) throw new Error(`${label} changed while being read`);
    const bytes = await handle.readFile();
    const after = await handle.stat();
    if (bytes.length > maxBytes || before.size !== after.size || before.mtimeMs !== after.mtimeMs || bytes.length !== after.size) {
      throw new Error(`${label} changed while being read or exceeds its size limit`);
    }
    return bytes;
  } finally {
    await handle.close();
  }
}

/** Resolves a file path and requires it to be outside `root` (both canonicalized). */
export async function resolveOutside(filePath: string, root: string, label: string, { allowMissing = false } = {}): Promise<string> {
  const canonicalRoot = await realpath(path.resolve(root));
  const requested = path.resolve(filePath);
  let canonical: string;
  try {
    const entry = await lstat(requested);
    if (entry.isSymbolicLink()) throw new Error(`${label} must not be a symbolic link`);
    if (!entry.isFile()) throw new Error(`${label} must be a regular file`);
    canonical = await realpath(requested);
  } catch (error) {
    if (!allowMissing || (error as NodeJS.ErrnoException)?.code !== 'ENOENT') throw error;
    canonical = path.join(await realpath(path.dirname(requested)), path.basename(requested));
  }
  if (isInside(canonicalRoot, canonical)) throw new Error(`${label} must be outside ${canonicalRoot}`);
  return canonical;
}

async function writeHandle(filePath: string, bytes: Uint8Array, mode: number, flags: number): Promise<void> {
  const handle = await open(filePath, flags, mode);
  try {
    await handle.writeFile(bytes);
    await handle.sync();
  } catch (error) {
    await handle.close();
    await unlink(filePath).catch(() => {});
    throw error;
  }
  await handle.close();
}

/** Creates a new file; refuses to overwrite anything that already exists. */
export async function writeNewFile(filePath: string, bytes: Uint8Array, mode = 0o644): Promise<string> {
  const target = path.resolve(filePath);
  await writeHandle(target, bytes, mode, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | noFollow);
  return target;
}

/** Writes via a temporary sibling and rename, so readers see the old or the new file, never a partial one. */
export async function writeFileAtomic(filePath: string, bytes: Uint8Array, mode = 0o644): Promise<string> {
  const target = path.resolve(filePath);
  try {
    const existing = await lstat(target);
    if (existing.isSymbolicLink() || !existing.isFile()) throw new Error(`Refusing to replace non-regular file ${target}`);
  } catch (error) {
    if ((error as NodeJS.ErrnoException)?.code !== 'ENOENT') throw error;
  }
  const temporary = path.join(path.dirname(target), `.${path.basename(target)}.${randomBytes(6).toString('hex')}.tmp`);
  await writeHandle(temporary, bytes, mode, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | noFollow);
  try {
    await rename(temporary, target);
  } catch (error) {
    await unlink(temporary).catch(() => {});
    throw error;
  }
  return target;
}

/** Canonical path of `target`, resolving symlinks on the longest existing prefix. A dangling link on the way is an error. */
async function realpathAllowingMissing(target: string): Promise<string> {
  let current = path.resolve(target);
  const rest: string[] = [];
  while (true) {
    try {
      return path.join(await realpath(current), ...rest.reverse());
    } catch (error) {
      if ((error as NodeJS.ErrnoException)?.code !== 'ENOENT') throw error;
      // realpath also fails with ENOENT for a dangling symlink; its target could be created later.
      if (await lstat(current).then(() => true, () => false)) throw new Error(`${current} is a dangling symbolic link`);
      const parent = path.dirname(current);
      if (parent === current) throw error;
      rest.push(path.basename(current));
      current = parent;
    }
  }
}

/**
 * Resolves a policy-supplied path against `base` and requires it to name something strictly inside `base`,
 * after symlinks in its parent directories are resolved. An existing final component must be a regular,
 * non-symlink file. Returns the canonical path.
 */
export async function resolveInsideDirectory(base: string, item: string, label: string): Promise<string> {
  const canonicalBase = await realpath(path.resolve(base));
  const requested = path.resolve(base, item);
  const reject = () => new Error(`${label} must name a file inside the policy file's directory (${canonicalBase}); got "${item}"`);
  if (!isInside(path.resolve(base), requested) || requested === path.resolve(base)) throw reject();
  const canonical = path.join(await realpathAllowingMissing(path.dirname(requested)), path.basename(requested));
  if (canonical === canonicalBase || !isInside(canonicalBase, canonical)) throw reject();
  try {
    const entry = await lstat(canonical);
    if (entry.isSymbolicLink() || !entry.isFile()) throw new Error(`${label} must be a regular, non-symlink file`);
  } catch (error) {
    if ((error as NodeJS.ErrnoException)?.code !== 'ENOENT') throw error;
  }
  return canonical;
}

/**
 * Appends text to a log file, creating it (mode 600) if needed. Refuses symbolic links and anything that is not
 * a regular file; O_NONBLOCK keeps a FIFO from hanging the open.
 */
export async function appendToRegularFile(filePath: string, text: string, label: string, mode = 0o600): Promise<void> {
  const handle = await open(filePath, fsConstants.O_APPEND | fsConstants.O_CREAT | fsConstants.O_WRONLY | noFollow | nonBlock, mode);
  try {
    if (!(await handle.stat()).isFile()) throw new Error(`${label} must be a regular file`);
    await handle.appendFile(text, 'utf8');
  } finally {
    await handle.close();
  }
}
