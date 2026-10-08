import { createHash } from 'node:crypto';
import { constants as fsConstants, type BigIntStats } from 'node:fs';
import { lstat, open, opendir, realpath } from 'node:fs/promises';
import path from 'node:path';
import { canonicalBytes } from './canonical-json.ts';

export const TREE_PROFILE = 'mago.skill-tree/v2';
export const CERTIFICATE_FILENAME = '.mago-ski-cert.json';
export const IGNORE_FILENAME = '.skilldigestignore';
export const MAX_TREE_FILES = 20_000;
export const MAX_TREE_ENTRIES = 50_000;
export const MAX_FILE_BYTES = 64 * 1024 * 1024;
export const MAX_TREE_BYTES = 256 * 1024 * 1024;
export const MAX_RELATIVE_PATH_BYTES = 4_096;
const MAX_IGNORE_BYTES = 64 * 1024;
const MAX_IGNORE_PATTERNS = 256;

export interface TreeFile {
  path: string;
  size: number;
  sha256: string;
  exec: boolean;
}

export interface SkillTree {
  profile: typeof TREE_PROFILE;
  digest: string;
  root: string;
  files: TreeFile[];
  totalBytes: number;
  /** Paths left out of the digest: the root `.git`, the in-tree certificate, and `.skilldigestignore` entries. */
  excluded: string[];
}

interface FileRecord {
  path: string;
  pathBytes: Buffer;
  absolutePath: string;
  stat: BigIntStats;
}

const utf8Decoder = new TextDecoder('utf-8', { fatal: true });
const noFollow = fsConstants.O_NOFOLLOW ?? 0;

function fail(message: string): never {
  throw new Error(message);
}

function decodeEntryName(name: Buffer): string {
  let decoded: string;
  try {
    decoded = utf8Decoder.decode(name);
  } catch {
    fail('Skill tree contains a path that is not valid UTF-8');
  }
  if (
    decoded.length === 0 || decoded === '.' || decoded === '..' ||
    decoded.includes('/') || decoded.includes('\\') || decoded.includes(':') ||
    /[. ]$/u.test(decoded) ||
    /^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?$/iu.test(decoded) ||
    /[\u0000-\u001f\u007f]/u.test(decoded) ||
    decoded.normalize('NFC') !== decoded
  ) {
    fail(`Skill tree contains an unsupported path component: ${JSON.stringify(decoded)}`);
  }
  return decoded;
}

function sameFileVersion(left: BigIntStats, right: BigIntStats): boolean {
  return left.dev === right.dev && left.ino === right.ino && left.size === right.size &&
    left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs;
}

/** Executable bit of a regular file. Windows has no POSIX mode bits, so it always reports false there. */
export function isExecutable(mode: number | bigint): boolean {
  if (process.platform === 'win32') return false;
  return (BigInt(mode) & 0o111n) !== 0n;
}

async function readStable(absolutePath: string, label: string, expected?: BigIntStats): Promise<{ content: Buffer; stat: BigIntStats }> {
  let handle;
  try {
    handle = await open(absolutePath, fsConstants.O_RDONLY | noFollow);
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || (expected && !sameFileVersion(expected, before))) fail(`Skill file changed while being read: ${label}`);
    if (before.size > BigInt(MAX_FILE_BYTES)) fail(`Skill file exceeds the ${MAX_FILE_BYTES}-byte limit: ${label}`);
    const chunks: Buffer[] = [];
    let total = 0;
    while (true) {
      const chunk = Buffer.allocUnsafe(64 * 1024);
      const { bytesRead } = await handle.read(chunk, 0, chunk.length, null);
      if (bytesRead === 0) break;
      total += bytesRead;
      if (total > MAX_FILE_BYTES) fail(`Skill file exceeds the ${MAX_FILE_BYTES}-byte limit: ${label}`);
      chunks.push(chunk.subarray(0, bytesRead));
    }
    const after = await handle.stat({ bigint: true });
    if (!sameFileVersion(before, after) || total !== Number(before.size)) fail(`Skill file changed while being read: ${label}`);
    return { content: Buffer.concat(chunks, total), stat: after };
  } catch (error) {
    if ((error as NodeJS.ErrnoException)?.code === 'ELOOP') fail(`Skill tree contains a symbolic link: ${label}`);
    throw error;
  } finally {
    await handle?.close();
  }
}

export function sha256Hex(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

/** Hashes one file for read-time checks. Returns the same fields the certificate records. */
export async function hashFile(absolutePath: string, relativePath: string): Promise<TreeFile> {
  const entry = await lstat(absolutePath, { bigint: true });
  if (entry.isSymbolicLink() || !entry.isFile()) fail(`Not a regular file: ${relativePath}`);
  const { content, stat } = await readStable(absolutePath, relativePath, entry);
  return { path: relativePath, size: content.length, sha256: sha256Hex(content), exec: isExecutable(stat.mode) };
}

export interface IgnoreRule {
  pattern: string;
  directoryOnly: boolean;
}

export function parseIgnoreFile(text: string): IgnoreRule[] {
  const rules: IgnoreRule[] = [];
  for (const rawLine of text.split(/\r?\n/u)) {
    const line = rawLine.trim();
    if (line === '' || line.startsWith('#')) continue;
    if (rules.length >= MAX_IGNORE_PATTERNS) fail(`${IGNORE_FILENAME} exceeds ${MAX_IGNORE_PATTERNS} patterns`);
    const directoryOnly = line.endsWith('/');
    const pattern = directoryOnly ? line.slice(0, -1) : line;
    const segments = pattern.split('/');
    if (
      pattern === '' || pattern.startsWith('/') || pattern.includes('\\') || /[*?[\]!]/u.test(pattern) ||
      segments.some((segment) => segment === '' || segment === '.' || segment === '..') ||
      pattern === IGNORE_FILENAME || pattern.normalize('NFC') !== pattern
    ) {
      fail(`${IGNORE_FILENAME} contains an unsupported pattern: ${JSON.stringify(line)} (use plain relative paths; globs are not supported)`);
    }
    rules.push({ pattern, directoryOnly });
  }
  return rules;
}

function isIgnored(relativePath: string, isDirectory: boolean, rules: IgnoreRule[]): boolean {
  for (const rule of rules) {
    if (relativePath === rule.pattern && (isDirectory || !rule.directoryOnly)) return true;
    if (relativePath.startsWith(`${rule.pattern}/`)) return true;
  }
  return false;
}

async function enumerate(root: string): Promise<{ root: string; records: FileRecord[]; excluded: string[] }> {
  const rootStat = await lstat(root, { bigint: true });
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) fail('Skill root must be a real directory, not a symbolic link');
  const canonicalRoot = await realpath(root);
  let rules: IgnoreRule[] = [];
  const ignorePath = path.join(canonicalRoot, IGNORE_FILENAME);
  try {
    const entry = await lstat(ignorePath, { bigint: true });
    if (entry.isSymbolicLink() || !entry.isFile()) fail(`${IGNORE_FILENAME} must be a regular file`);
    if (entry.size > BigInt(MAX_IGNORE_BYTES)) fail(`${IGNORE_FILENAME} exceeds ${MAX_IGNORE_BYTES} bytes`);
    const { content } = await readStable(ignorePath, IGNORE_FILENAME, entry);
    rules = parseIgnoreFile(utf8Decoder.decode(content));
  } catch (error) {
    if ((error as NodeJS.ErrnoException)?.code !== 'ENOENT') throw error;
  }

  const records: FileRecord[] = [];
  const excluded: string[] = [];
  const seenCaseFolded = new Set<string>();
  let entryCount = 0;

  async function visit(directory: string, relativeDirectory: string, depth: number): Promise<void> {
    if (depth > 64) fail('Skill tree exceeds the maximum directory depth of 64');
    const directoryStat = await lstat(directory, { bigint: true });
    if (!directoryStat.isDirectory() || directoryStat.isSymbolicLink()) {
      fail(`Skill tree contains a changed or symbolic-link directory: ${relativeDirectory || '.'}`);
    }
    const expected = relativeDirectory ? path.join(canonicalRoot, relativeDirectory) : canonicalRoot;
    if (await realpath(directory) !== expected) fail(`Skill tree directory path changed during traversal: ${relativeDirectory || '.'}`);
    const dir = await opendir(expected, { encoding: 'buffer' as BufferEncoding, bufferSize: 32 });
    for await (const dirent of dir) {
      entryCount += 1;
      if (entryCount > MAX_TREE_ENTRIES) fail(`Skill tree exceeds the ${MAX_TREE_ENTRIES}-entry limit`);
      const name = decodeEntryName(dirent.name as unknown as Buffer);
      const relativePath = relativeDirectory ? `${relativeDirectory}/${name}` : name;
      const pathBytes = Buffer.from(relativePath, 'utf8');
      if (pathBytes.length > MAX_RELATIVE_PATH_BYTES) fail(`Skill path exceeds the ${MAX_RELATIVE_PATH_BYTES}-byte limit`);
      const caseKey = relativePath.normalize('NFKC').toLowerCase();
      if (seenCaseFolded.has(caseKey)) fail(`Skill tree contains a case-insensitive path collision: ${relativePath}`);
      seenCaseFolded.add(caseKey);

      const absolutePath = path.join(expected, name);
      const stat = await lstat(absolutePath, { bigint: true });
      if (stat.isSymbolicLink()) fail(`Skill tree contains a symbolic link: ${relativePath}`);
      const isDirectory = stat.isDirectory();
      if (!relativeDirectory && (name === '.git' || (name === CERTIFICATE_FILENAME && !isDirectory))) {
        excluded.push(isDirectory ? `${relativePath}/` : relativePath);
        continue;
      }
      if (isIgnored(relativePath, isDirectory, rules)) {
        excluded.push(isDirectory ? `${relativePath}/` : relativePath);
        continue;
      }
      if (isDirectory) {
        await visit(absolutePath, relativePath, depth + 1);
      } else if (stat.isFile()) {
        if (records.length >= MAX_TREE_FILES) fail(`Skill tree exceeds the ${MAX_TREE_FILES}-file limit`);
        if (stat.size > BigInt(MAX_FILE_BYTES)) fail(`Skill file exceeds the ${MAX_FILE_BYTES}-byte limit: ${relativePath}`);
        records.push({ path: relativePath, pathBytes, absolutePath, stat });
      } else {
        fail(`Skill tree contains an unsupported special file: ${relativePath}`);
      }
    }
  }

  await visit(canonicalRoot, '', 0);
  records.sort((left, right) => Buffer.compare(left.pathBytes, right.pathBytes));
  excluded.sort();
  return { root: canonicalRoot, records, excluded };
}

export function compareTreePaths(left: string, right: string): number {
  return Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
}

/** The tree digest is SHA-256 over the canonical JSON of the profile and the sorted per-file list. */
export function digestFileList(files: readonly TreeFile[]): string {
  for (let index = 1; index < files.length; index += 1) {
    if (compareTreePaths(files[index - 1]!.path, files[index]!.path) >= 0) fail('File list must be sorted by UTF-8 path bytes without duplicates');
  }
  const body = canonicalBytes({
    profile: TREE_PROFILE,
    files: files.map((file) => ({ path: file.path, size: file.size, sha256: file.sha256, exec: file.exec })),
  });
  return `sha256:${sha256Hex(body)}`;
}

export async function collectSkillTree(rootPath: string, { includeContents = false } = {}): Promise<SkillTree & { contents?: Map<string, Buffer> }> {
  const { root, records, excluded } = await enumerate(path.resolve(rootPath));
  const files: TreeFile[] = [];
  const contents = includeContents ? new Map<string, Buffer>() : undefined;
  let totalBytes = 0;
  for (const record of records) {
    const { content, stat } = await readStable(record.absolutePath, record.path, record.stat);
    totalBytes += content.length;
    if (totalBytes > MAX_TREE_BYTES) fail(`Skill tree exceeds the ${MAX_TREE_BYTES}-byte total limit`);
    files.push({ path: record.path, size: content.length, sha256: sha256Hex(content), exec: isExecutable(stat.mode) });
    contents?.set(record.path, content);
  }
  const tree: SkillTree & { contents?: Map<string, Buffer> } = {
    profile: TREE_PROFILE, digest: digestFileList(files), root, files, totalBytes, excluded,
  };
  if (contents) tree.contents = contents;
  return tree;
}
