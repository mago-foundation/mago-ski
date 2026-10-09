// Mirrors how Pi 1.1's built-in tools turn a tool `path` argument into a file system path
// (dist/utils/paths.js normalizePath/resolvePath and dist/core/tools/path-utils.js), so the
// extension authorizes the same file Pi will actually open. Keep in sync when Pi changes.
import { existsSync } from 'node:fs';
import { homedir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const UNICODE_SPACES = /[  -   　]/gu;

/** Git Bash, MSYS, Cygwin and WSL drive paths, as Pi converts them on native Windows. */
function normalizeWindowsShellPath(filePath: string): string {
  if (!filePath.startsWith('/') || filePath.startsWith('//') || filePath.includes('\\')) return filePath;
  const match = /^\/(?:mnt\/|cygdrive\/)?([a-z])(?:\/(.*))?$/iu.exec(filePath);
  if (!match) return filePath;
  return `${match[1]!.toUpperCase()}:\\${match[2]?.replaceAll('/', '\\') ?? ''}`;
}

/** Pi's resolveToCwd: Unicode spaces, leading "@", Windows shell paths, "~", file:// URLs, then resolve. */
export function piResolveToCwd(input: string, cwd: string): string {
  let normalized = input.replace(UNICODE_SPACES, ' ');
  if (normalized.startsWith('@')) normalized = normalized.slice(1);
  if (process.platform === 'win32') normalized = normalizeWindowsShellPath(normalized);
  if (normalized === '~') {
    normalized = homedir();
  } else if (normalized.startsWith('~/') || (process.platform === 'win32' && normalized.startsWith('~\\'))) {
    normalized = path.join(homedir(), normalized.slice(2));
  } else if (/^file:\/\//u.test(normalized)) {
    try {
      normalized = fileURLToPath(normalized);
    } catch {
      // Pi would throw too; leave the text so it is still matched lexically.
    }
  }
  return path.isAbsolute(normalized) ? path.resolve(normalized) : path.resolve(cwd, normalized);
}

/**
 * Pi's `read` tool tries these spellings in order when the resolved path does not exist
 * (macOS screenshot names, NFD, curly quotes) and opens the first that exists.
 */
export function piReadVariants(resolved: string): string[] {
  const amPm = resolved.replace(/ (AM|PM)\./giu, ' $1.');
  const nfd = resolved.normalize('NFD');
  const curly = resolved.replace(/'/gu, '’');
  const nfdCurly = nfd.replace(/'/gu, '’');
  return [...new Set([resolved, amPm, nfd, curly, nfdCurly])];
}

/** The path Pi's `read` will open: the first existing variant, or the resolved path. */
export function piReadTarget(resolved: string): string {
  return piReadVariants(resolved).find((candidate) => existsSync(candidate)) ?? resolved;
}
