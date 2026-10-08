import { createHash } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import { lstat, open, opendir, realpath } from 'node:fs/promises';
import path from 'node:path';
import { TextDecoder } from 'node:util';

export const TREE_DIGEST_PROFILE = 'mago.skill-tree/v1';
export const MAX_TREE_FILES = 20_000;
export const MAX_TREE_ENTRIES = 50_000;
export const MAX_FILE_BYTES = 64 * 1024 * 1024;
export const MAX_TREE_BYTES = 256 * 1024 * 1024;
export const MAX_RELATIVE_PATH_BYTES = 4_096;

// v1 hashes every regular-file path and raw byte sequence; sidecars stay outside the tree.
const TREE_HEADER = Buffer.from('MAGO-SKILL-TREE\0v1\n', 'utf8');
const utf8Decoder = new TextDecoder('utf-8', { fatal: true });
const noFollow = fsConstants.O_NOFOLLOW ?? 0;

function fail(message) {
  throw new Error(message);
}

function decodeEntryName(name) {
  const bytes = Buffer.isBuffer(name) ? name : Buffer.from(name, 'utf8');
  let decoded;
  try {
    decoded = utf8Decoder.decode(bytes);
  } catch {
    fail('Skill tree contains a path that is not valid UTF-8');
  }
  if (
    decoded.length === 0 ||
    decoded === '.' ||
    decoded === '..' ||
    decoded.includes('/') ||
    decoded.includes('\\') ||
    decoded.includes(':') ||
    /[. ]$/u.test(decoded) ||
    /^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?$/iu.test(decoded) ||
    /[\u0000-\u001f\u007f]/u.test(decoded) ||
    decoded.normalize('NFC') !== decoded
  ) {
    fail(`Skill tree contains an unsupported path component: ${JSON.stringify(decoded)}`);
  }
  return decoded;
}

function comparePaths(left, right) {
  return Buffer.compare(left.pathBytes, right.pathBytes);
}

function sameFileVersion(left, right) {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.size === right.size &&
    left.mtimeNs === right.mtimeNs &&
    left.ctimeNs === right.ctimeNs
  );
}

async function readStableFile(record) {
  const flags = fsConstants.O_RDONLY | noFollow;
  let handle;
  try {
    handle = await open(record.absolutePath, flags);
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || !sameFileVersion(record.stat, before)) {
      fail(`Skill file changed while being read: ${record.path}`);
    }
    if (before.size > BigInt(MAX_FILE_BYTES)) {
      fail(`Skill file exceeds the ${MAX_FILE_BYTES}-byte limit: ${record.path}`);
    }

    const chunks = [];
    let total = 0;
    while (true) {
      const chunk = Buffer.allocUnsafe(64 * 1024);
      const { bytesRead } = await handle.read(chunk, 0, chunk.length, null);
      if (bytesRead === 0) break;
      total += bytesRead;
      if (total > MAX_FILE_BYTES) {
        fail(`Skill file exceeds the ${MAX_FILE_BYTES}-byte limit: ${record.path}`);
      }
      chunks.push(chunk.subarray(0, bytesRead));
    }

    const after = await handle.stat({ bigint: true });
    if (!sameFileVersion(before, after) || total !== Number(before.size)) {
      fail(`Skill file changed while being read: ${record.path}`);
    }
    return Buffer.concat(chunks, total);
  } catch (error) {
    if (error?.code === 'ELOOP') fail(`Skill tree contains a symbolic link: ${record.path}`);
    throw error;
  } finally {
    await handle?.close();
  }
}

async function enumerateFiles(root) {
  const rootStat = await lstat(root, { bigint: true });
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) {
    fail('Skill root must be a real directory, not a symbolic link');
  }
  const canonicalRoot = await realpath(root);
  const records = [];
  const seenCaseFolded = new Set();
  let entryCount = 0;

  async function visit(directory, relativeDirectory, depth) {
    if (depth > 64) fail('Skill tree exceeds the maximum directory depth of 64');
    const directoryStat = await lstat(directory, { bigint: true });
    if (!directoryStat.isDirectory() || directoryStat.isSymbolicLink()) {
      fail(`Skill tree contains a changed or symbolic-link directory: ${relativeDirectory || '.'}`);
    }
    const canonicalDirectory = await realpath(directory);
    const expectedDirectory = relativeDirectory ? path.join(canonicalRoot, relativeDirectory) : canonicalRoot;
    if (canonicalDirectory !== expectedDirectory) {
      fail(`Skill tree directory path changed during traversal: ${relativeDirectory || '.'}`);
    }
    const dir = await opendir(canonicalDirectory, { encoding: 'buffer', bufferSize: 32 });
    for await (const entry of dir) {
      entryCount += 1;
      if (entryCount > MAX_TREE_ENTRIES) {
        fail(`Skill tree exceeds the ${MAX_TREE_ENTRIES}-entry limit`);
      }
      const name = decodeEntryName(entry.name);
      const relativePath = relativeDirectory ? `${relativeDirectory}/${name}` : name;
      const pathBytes = Buffer.from(relativePath, 'utf8');
      if (pathBytes.length > MAX_RELATIVE_PATH_BYTES) {
        fail(`Skill path exceeds the ${MAX_RELATIVE_PATH_BYTES}-byte limit`);
      }
      const caseKey = relativePath.normalize('NFKC').toLowerCase();
      if (seenCaseFolded.has(caseKey)) {
        fail(`Skill tree contains a case-insensitive path collision: ${relativePath}`);
      }
      seenCaseFolded.add(caseKey);

      const absolutePath = path.join(directory, name);
      const stat = await lstat(absolutePath, { bigint: true });
      if (stat.isSymbolicLink()) fail(`Skill tree contains a symbolic link: ${relativePath}`);
      if (stat.isDirectory()) {
        await visit(absolutePath, relativePath, depth + 1);
      } else if (stat.isFile()) {
        if (records.length >= MAX_TREE_FILES) {
          fail(`Skill tree exceeds the ${MAX_TREE_FILES}-file limit`);
        }
        if (stat.size > BigInt(MAX_FILE_BYTES)) {
          fail(`Skill file exceeds the ${MAX_FILE_BYTES}-byte limit: ${relativePath}`);
        }
        records.push({ path: relativePath, pathBytes, absolutePath, stat });
      } else {
        fail(`Skill tree contains an unsupported special file: ${relativePath}`);
      }
    }
  }

  await visit(canonicalRoot, '', 0);
  records.sort(comparePaths);
  return { root: canonicalRoot, records };
}

export async function collectSkillTree(rootPath, { includeContents = false } = {}) {
  const { root, records } = await enumerateFiles(path.resolve(rootPath));
  const digest = createHash('sha256');
  digest.update(TREE_HEADER);
  const files = [];
  let totalBytes = 0;

  for (const record of records) {
    const content = await readStableFile(record);
    totalBytes += content.length;
    if (totalBytes > MAX_TREE_BYTES) {
      fail(`Skill tree exceeds the ${MAX_TREE_BYTES}-byte total limit`);
    }

    const lengthHeader = Buffer.alloc(12);
    lengthHeader.writeUInt32BE(record.pathBytes.length, 0);
    lengthHeader.writeBigUInt64BE(BigInt(content.length), 4);
    digest.update(Buffer.from([0x46]));
    digest.update(lengthHeader.subarray(0, 4));
    digest.update(record.pathBytes);
    digest.update(lengthHeader.subarray(4));
    digest.update(content);

    const file = {
      path: record.path,
      size: content.length,
      sha256: createHash('sha256').update(content).digest('hex'),
    };
    if (includeContents) file.content = content;
    files.push(file);
  }

  return {
    digest: `sha256:${digest.digest('hex')}`,
    profile: TREE_DIGEST_PROFILE,
    root,
    fileCount: files.length,
    totalBytes,
    files,
  };
}

export async function computeTreeDigest(rootPath) {
  const tree = await collectSkillTree(rootPath);
  return {
    digest: tree.digest,
    profile: tree.profile,
    fileCount: tree.fileCount,
    totalBytes: tree.totalBytes,
  };
}

export async function resolveExternalFile(filePath, skillRoot, label, { allowMissing = false } = {}) {
  const root = await realpath(path.resolve(skillRoot));
  const requested = path.resolve(filePath);
  let canonical;
  try {
    const entryStat = await lstat(requested);
    if (entryStat.isSymbolicLink()) fail(`${label} must not be a symbolic link`);
    if (!entryStat.isFile()) fail(`${label} must be a regular file`);
    canonical = await realpath(requested);
  } catch (error) {
    if (!allowMissing || error?.code !== 'ENOENT') throw error;
    const parent = await realpath(path.dirname(requested));
    canonical = path.join(parent, path.basename(requested));
  }

  const relative = path.relative(root, canonical);
  const isInsideRoot = relative === '' || (
    relative !== '..' &&
    !relative.startsWith(`..${path.sep}`) &&
    !path.isAbsolute(relative)
  );
  if (isInsideRoot) fail(`${label} must be outside the Skill directory`);
  return canonical;
}

export async function readRegularFile(filePath, label, maxBytes = 1024 * 1024) {
  const fileStat = await lstat(filePath);
  if (fileStat.isSymbolicLink() || !fileStat.isFile()) fail(`${label} must be a regular, non-symlink file`);
  if (fileStat.size > maxBytes) fail(`${label} exceeds the ${maxBytes}-byte limit`);
  return await openAndRead(filePath, label, maxBytes, fileStat);
}

async function openAndRead(filePath, label, maxBytes, expectedStat) {
  const handle = await open(filePath, fsConstants.O_RDONLY | noFollow);
  try {
    const before = await handle.stat();
    if (!before.isFile() || before.dev !== expectedStat.dev || before.ino !== expectedStat.ino) {
      fail(`${label} changed while being read`);
    }
    const bytes = await handle.readFile();
    const after = await handle.stat();
    if (bytes.length > maxBytes || before.size !== after.size || before.mtimeMs !== after.mtimeMs) {
      fail(`${label} changed while being read or exceeds its size limit`);
    }
    return bytes;
  } finally {
    await handle.close();
  }
}
