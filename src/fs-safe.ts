import { randomBytes } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import { lstat, open, realpath, rename, unlink } from 'node:fs/promises';
import path from 'node:path';

const noFollow = fsConstants.O_NOFOLLOW ?? 0;

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
