import { createHash, randomBytes } from 'node:crypto';
import { constants as fsConstants, type BigIntStats } from 'node:fs';
import { lstat, open, realpath, rename, unlink, type FileHandle } from 'node:fs/promises';
import path from 'node:path';

const noFollow                = fsConstants.O_NOFOLLOW ?? 0;
// Never block in open(2) on a FIFO; O_NONBLOCK lets open return (or fail with ENXIO) and fstat rejects non-regular files.
const nonBlock                = fsConstants.O_NONBLOCK ?? 0;
const DEFAULT_MAX_READ_BYTES  = 1024 * 1024;
const READ_CHUNK_BYTES        = 64 * 1024;
const DEFAULT_FILE_MODE       = 0o644;
const DEFAULT_LOG_MODE        = 0o600;
const TEMP_RANDOM_BYTES       = 6;

function isNonRegularOpenError(error: unknown): boolean {
  const code = (error as NodeJS.ErrnoException)?.code;
  return code === 'ELOOP' || code === 'EISDIR' || code === 'ENXIO' || code === 'EOPNOTSUPP';
}

async function openRegularHandle(
  filePath: string,
  flags: number,
  notRegularMessage: string,
  mode?: number,
): Promise<FileHandle> {
  try {
    return mode === undefined ? await open(filePath, flags) : await open(filePath, flags, mode);
  } catch (error) {
    if (isNonRegularOpenError(error)) {
      throw new Error(notRegularMessage);
    }
    throw error;
  }
}

export interface ReadOwnedRegularFileOptions {
  maxBytes?: number;
  uid: number;
  disallowGroupOtherWrite?: boolean;
  notRegularMessage?: string;
  ownershipMessage?: string;
}

function sameFileIdentity(left: BigIntStats, right: BigIntStats): boolean {
  return left.dev === right.dev && left.ino === right.ino;
}

function sameFileVersion(left: BigIntStats, right: BigIntStats): boolean {
  return (
    sameFileIdentity(left, right) &&
    left.size === right.size &&
    left.mtimeNs === right.mtimeNs &&
    left.ctimeNs === right.ctimeNs
  );
}

export function isInside(root: string, candidate: string): boolean {
  const resolvedRoot      = path.resolve(root);
  const resolvedCandidate = path.resolve(candidate);
  const relative          = path.relative(resolvedRoot, resolvedCandidate);

  return (
    relative === '' ||
    (relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative))
  );
}

async function readRegularHandle(
  handle: FileHandle,
  before: BigIntStats,
  label: string,
  maxBytes: number,
): Promise<Buffer> {
  if (before.size > BigInt(maxBytes))
    throw new Error(`${label} exceeds the ${maxBytes}-byte limit`);

  const chunks: Buffer[] = [];
  let total = 0;

  while (total <= maxBytes) {
    const remaining     = maxBytes + 1 - total;
    const chunk         = Buffer.allocUnsafe(Math.min(READ_CHUNK_BYTES, remaining));
    const { bytesRead } = await handle.read(chunk, 0, chunk.length, null);
    if (bytesRead === 0)
      break;
    total += bytesRead;

    chunks.push(chunk.subarray(0, bytesRead));
  }

  const after = await handle.stat({ bigint: true });
  if (total > maxBytes || !sameFileVersion(before, after) || BigInt(total) !== after.size)
    throw new Error(`${label} changed while being read or exceeds its size limit`);

  return Buffer.concat(chunks, total);
}

async function openAndReadRegularFile(
  filePath: string,
  label: string,
  maxBytes: number,
  notRegularMessage: string,
  validateStat?: (before: BigIntStats) => void,
): Promise<Buffer> {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 0) {
    throw new Error(`Invalid maxBytes limit for ${label}`);
  }

  const handle = await openRegularHandle(
    filePath,
    fsConstants.O_RDONLY | noFollow | nonBlock,
    notRegularMessage,
  );
  try {
    const before = await handle.stat({ bigint: true });
    if (!before.isFile())
      throw new Error(notRegularMessage);

    validateStat?.(before);
    return await readRegularHandle(handle, before, label, maxBytes);
  } finally {
    await handle.close();
  }
}

/**
 * Reads a regular, non-symlink file without following symlinks on the final path component, failing if it changes
 * while being read. Opens directly with `O_NOFOLLOW | O_NONBLOCK`, then checks the opened handle's type and size
 * before reading at most `maxBytes` (+1 to detect growth).
 */
export async function readRegularFile(
  filePath: string,
  label: string,
  maxBytes = DEFAULT_MAX_READ_BYTES,
): Promise<Buffer> {
  return await openAndReadRegularFile(filePath, label, maxBytes, `${label} must be a regular, non-symlink file`);
}

/**
 * Reads a regular, non-symlink file whose opened handle is owned by `options.uid` (and by default not writable by
 * group or others), failing if it changes while being read.
 */
export async function readOwnedRegularFile(
  filePath: string,
  label: string,
  options: ReadOwnedRegularFileOptions,
): Promise<Buffer> {
  const maxBytes          = options.maxBytes ?? DEFAULT_MAX_READ_BYTES;
  const notRegularMessage = options.notRegularMessage ?? `${label} must be a regular, non-symlink file`;
  const ownershipMessage  = options.ownershipMessage ?? `${label} must be owned by root and not writable by group or others`;
  const checkMode         = options.disallowGroupOtherWrite ?? true;

  return await openAndReadRegularFile(filePath, label, maxBytes, notRegularMessage, (before) => {
    if (before.uid !== BigInt(options.uid) || (checkMode && (before.mode & 0o022n) !== 0n)) {
      throw new Error(ownershipMessage);
    }
  });
}

/** Resolves a file path and requires it to be outside `root` (both canonicalized). */
export async function resolveOutside(
  filePath: string,
  root: string,
  label: string,
  { allowMissing = false } = {},
): Promise<string> {
  const canonicalRoot = await realpath(path.resolve(root));
  const requested     = path.resolve(filePath);
  let canonical: string;

  try {
    const entry = await lstat(requested);
    if (entry.isSymbolicLink())
      throw new Error(`${label} must not be a symbolic link`);
    
    if (!entry.isFile())
      throw new Error(`${label} must be a regular file`);
  
    canonical = await realpath(requested);
  } catch (error) {
    const code = (error as NodeJS.ErrnoException)?.code;
    if (!allowMissing || code !== 'ENOENT')
      throw error;
    
    canonical = path.join(await realpathAllowingMissing(path.dirname(requested)), path.basename(requested));
  }

  if (isInside(canonicalRoot, canonical)) {
    throw new Error(`${label} must be outside ${canonicalRoot}`);
  }

  return canonical;
}

async function writeHandle(filePath: string, bytes: Uint8Array, mode: number, flags: number): Promise<void> {
  const handle = await open(filePath, flags, mode);
  let succeeded = false;

  try {
    await handle.writeFile(bytes);
    await handle.sync();
    succeeded = true;
  } finally {
    await handle.close().catch((closeError) => {
      if (succeeded) {
        succeeded = false;
        throw closeError;
      }
    });
    if (!succeeded)
      await unlink(filePath).catch(() => {});
  }
}

/** Creates a new file; refuses to overwrite anything that already exists. */
export async function writeNewFile(
  filePath: string,
  bytes: Uint8Array,
  mode = DEFAULT_FILE_MODE,
): Promise<string> {
  const target = path.resolve(filePath);
  const flags  = fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | noFollow;

  await writeHandle(target, bytes, mode, flags);
  return target;
}

/** The file a write was meant to replace was no longer the one that was read (see `writeFileAtomic`'s `expectSha256`). */
export class FileChangedError extends Error {
  constructor(message = 'File changed before it could be replaced') {
    super(message);
    this.name = 'FileChangedError';
  }
}

/** `sha256:<hex>` of the regular file at `target`, or `null` when it does not exist. Anything else throws. */
async function currentSha256(target: string): Promise<string | null> {
  let bytes: Buffer;
  try {
    bytes = await readRegularFile(target, 'Document', Number.MAX_SAFE_INTEGER);
  } catch (error) {
    if ((error as NodeJS.ErrnoException)?.code === 'ENOENT')
      return null;
    throw new FileChangedError();
  }
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

/**
 * Writes via a temporary sibling and rename, so readers see the old or the new file, never a partial one.
 *
 * `options.expectSha256`: `undefined` checks nothing. A `sha256:<hex>` string requires the existing path to be a regular
 * file with that SHA-256, `null` requires the path not to exist. The check runs after the temporary file is written and
 * immediately before the rename; a mismatch removes the temporary file and throws `FileChangedError`. A process that can
 * write the folder can still swap the file between that check and the rename.
 */
export async function writeFileAtomic(
  filePath: string,
  bytes: Uint8Array,
  mode = DEFAULT_FILE_MODE,
  options: { expectSha256?: string | null } = {},
): Promise<string> {
  const target    = path.resolve(filePath);
  const randomHex = randomBytes(TEMP_RANDOM_BYTES).toString('hex');
  const temporary = path.join(path.dirname(target), `.${path.basename(target)}.${randomHex}.tmp`);
  const flags     = fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | noFollow;

  try {
    const existing = await lstat(target);
    if (existing.isSymbolicLink() || !existing.isFile())
      throw new Error(`Refusing to replace non-regular file ${target}`);
    
  } catch (error) {
    if ((error as NodeJS.ErrnoException)?.code !== 'ENOENT')
      throw error;
    
  }

  await writeHandle(temporary, bytes, mode, flags);
  try {
    if (options.expectSha256 !== undefined && (await currentSha256(target)) !== options.expectSha256)
      throw new FileChangedError();
    await rename(temporary, target);
  } catch (error) {
    await unlink(temporary).catch(() => {});
    throw error;
  }

  return target;
}

/** Canonical path of `target`, resolving symlinks on the longest existing prefix. A dangling link on the way is an error. */
export async function realpathAllowingMissing(target: string): Promise<string> {
  let current        = path.resolve(target);
  const missingParts = [] as string[];

  while (true) {
    try {
      const resolvedPrefix = await realpath(current);
      return path.join(resolvedPrefix, ...missingParts.reverse());
    } catch (error) {
      if ((error as NodeJS.ErrnoException)?.code !== 'ENOENT')
        throw error;
    
      // realpath also fails with ENOENT for a dangling symlink; its target could be created later.
      const existsAsDanglingLink = await lstat(current).then(
        () => true,
        () => false,
      );
      if (existsAsDanglingLink)
        throw new Error(`${current} is a dangling symbolic link`);

      const parent = path.dirname(current);
      if (parent === current)
        throw error;

      missingParts.push(path.basename(current));
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
  const resolvedBase  = path.resolve(base);
  const canonicalBase = await realpath(resolvedBase);
  const requested     = path.resolve(resolvedBase, item);
  const reject        = () =>
    new Error(`${label} must name a file inside the policy file's directory (${canonicalBase}); got "${item}"`);

  if (!isInside(resolvedBase, requested) || requested === resolvedBase) {
    throw reject();
  }

  const canonicalParent = await realpathAllowingMissing(path.dirname(requested));
  const canonical       = path.join(canonicalParent, path.basename(requested));

  if (canonical === canonicalBase || !isInside(canonicalBase, canonical))
    throw reject();

  try {
    const entry = await lstat(canonical);
    if (entry.isSymbolicLink() || !entry.isFile())
      throw new Error(`${label} must be a regular, non-symlink file`);
  } catch (error) {
    if ((error as NodeJS.ErrnoException)?.code !== 'ENOENT')
      throw error;
  }

  return canonical;
}

/**
 * Appends text to a log file, creating it (mode 600) if needed. Refuses symbolic links and anything that is not
 * a regular file; O_NONBLOCK keeps a FIFO from hanging the open.
 */
export async function appendToRegularFile(
  filePath: string,
  text: string,
  label: string,
  mode = DEFAULT_LOG_MODE,
): Promise<void> {
  const target            = path.resolve(filePath);
  const flags             = fsConstants.O_APPEND | fsConstants.O_CREAT | fsConstants.O_WRONLY | noFollow | nonBlock;
  const notRegularMessage = `${label} must be a regular, non-symlink file`;
  const handle            = await openRegularHandle(target, flags, notRegularMessage, mode);

  try {
    const opened = await handle.stat({ bigint: true });
    if (!opened.isFile())
      throw new Error(notRegularMessage);

    await handle.appendFile(text, 'utf8');
  } finally {
    await handle.close();
  }
}
