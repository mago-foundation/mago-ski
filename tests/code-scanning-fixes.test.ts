// Regression tests for CodeQL code-scanning fixes (race-free file reads/appends and input hardening).
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmod, lstat, mkdir, readFile, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { appendToRegularFile, readOwnedRegularFile, readRegularFile } from '../src/fs-safe.ts';
import { loadConfig } from '../src/gate/adapters/claude-code.ts';
import { readInstanceConfig } from '../src/gate/instance.ts';
import { checkHostExe } from '../src/gate/setup.ts';
import { LINUX_ONLY, tempDir } from './helpers.ts';

const UID = process.getuid?.() ?? 0;
const POSIX_ONLY: false | string = process.platform === 'win32' ? 'POSIX only: requires uid and mode bits' : false;
const FP = `sha256:${'ab'.repeat(32)}`;

function makeFifo(fifoPath: string): void {
  const result = spawnSync('mkfifo', [fifoPath], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr || 'mkfifo failed');
}

function isEnoent(error: unknown): boolean {
  return (error as NodeJS.ErrnoException)?.code === 'ENOENT';
}

// ---- readRegularFile -------------------------------------------------------------------------

test('readRegularFile rejects symlink, directory, oversized file and preserves ENOENT', { skip: POSIX_ONLY }, async (t) => {
  const dir = await tempDir(t);
  const regular = path.join(dir, 'regular.txt');
  await writeFile(regular, 'hello world');
  assert.equal((await readRegularFile(regular, 'Doc')).toString('utf8'), 'hello world');

  const link = path.join(dir, 'link.txt');
  await symlink(regular, link);
  await assert.rejects(readRegularFile(link, 'Doc'), /Doc must be a regular, non-symlink file/u);

  const dangling = path.join(dir, 'dangling.txt');
  await symlink(path.join(dir, 'nope.txt'), dangling);
  await assert.rejects(readRegularFile(dangling, 'Doc'), /Doc must be a regular, non-symlink file/u);

  const sub = path.join(dir, 'subdir');
  await mkdir(sub);
  await assert.rejects(readRegularFile(sub, 'Doc'), /Doc must be a regular, non-symlink file/u);

  await assert.rejects(readRegularFile(regular, 'Doc', 5), /Doc exceeds the 5-byte limit/u);
  await assert.rejects(readRegularFile(path.join(dir, 'missing.txt'), 'Doc'), isEnoent);
});

test('readRegularFile rejects a FIFO without blocking', { skip: LINUX_ONLY }, async (t) => {
  const dir = await tempDir(t);
  const fifo = path.join(dir, 'pipe');
  makeFifo(fifo);
  await assert.rejects(readRegularFile(fifo, 'FifoDoc'), /FifoDoc must be a regular, non-symlink file/u);
});

// ---- readOwnedRegularFile --------------------------------------------------------------------

test('readOwnedRegularFile validates ownership, mode, non-regular files and preserves ENOENT', { skip: POSIX_ONLY }, async (t) => {
  const dir = await tempDir(t);
  const file = path.join(dir, 'owned.conf');
  await writeFile(file, 'secret=1\n');
  await chmod(file, 0o644);

  assert.equal((await readOwnedRegularFile(file, 'Config', { uid: UID })).toString('utf8'), 'secret=1\n');
  await assert.rejects(
    readOwnedRegularFile(file, 'Config', { uid: UID + 1 }),
    /Config must be owned by root and not writable by group or others/u,
  );

  for (const mode of [0o664, 0o666]) {
    await chmod(file, mode);
    await assert.rejects(
      readOwnedRegularFile(file, 'Config', { uid: UID }),
      /Config must be owned by root and not writable by group or others/u,
    );
  }
  await chmod(file, 0o644);

  const link = path.join(dir, 'link.conf');
  await symlink(file, link);
  await assert.rejects(
    readOwnedRegularFile(link, 'Config', { uid: UID, notRegularMessage: 'custom not regular' }),
    /custom not regular/u,
  );

  const sub = path.join(dir, 'dir.conf');
  await mkdir(sub);
  await assert.rejects(
    readOwnedRegularFile(sub, 'Config', { uid: UID, notRegularMessage: 'custom not regular' }),
    /custom not regular/u,
  );

  await assert.rejects(readOwnedRegularFile(path.join(dir, 'missing.conf'), 'Config', { uid: UID }), isEnoent);
});

test('readOwnedRegularFile rejects a FIFO without blocking using custom notRegularMessage', { skip: LINUX_ONLY }, async (t) => {
  const dir = await tempDir(t);
  const fifo = path.join(dir, 'fifo.conf');
  makeFifo(fifo);
  await assert.rejects(
    readOwnedRegularFile(fifo, 'Config', { uid: UID, notRegularMessage: 'custom not regular' }),
    /custom not regular/u,
  );
});

// ---- appendToRegularFile ---------------------------------------------------------------------

test('appendToRegularFile creates/appends regular files and rejects symlinks and directories', { skip: POSIX_ONLY }, async (t) => {
  const dir = await tempDir(t);
  const logFile = path.join(dir, 'decisions.jsonl');
  await appendToRegularFile(logFile, 'first\n', 'Log');
  await appendToRegularFile(logFile, 'second\n', 'Log');
  assert.equal(await readFile(logFile, 'utf8'), 'first\nsecond\n');

  const victim = path.join(dir, 'victim.txt');
  await writeFile(victim, 'keep\n');
  const existingLink = path.join(dir, 'existing-link');
  await symlink(victim, existingLink);
  await assert.rejects(appendToRegularFile(existingLink, 'evil\n', 'Log'), /Log must be a regular, non-symlink file/u);
  assert.equal(await readFile(victim, 'utf8'), 'keep\n');

  const danglingTarget = path.join(dir, 'dangling-target.txt');
  const danglingLink = path.join(dir, 'dangling-link');
  await symlink(danglingTarget, danglingLink);
  await assert.rejects(appendToRegularFile(danglingLink, 'evil\n', 'Log'), /Log must be a regular, non-symlink file/u);
  await assert.rejects(lstat(danglingTarget), isEnoent);

  const sub = path.join(dir, 'subdir');
  await mkdir(sub);
  await assert.rejects(appendToRegularFile(sub, 'evil\n', 'Log'), /Log must be a regular, non-symlink file/u);
});

test('appendToRegularFile rejects a FIFO without blocking', { skip: LINUX_ONLY }, async (t) => {
  const dir = await tempDir(t);
  const fifo = path.join(dir, 'log-fifo');
  makeFifo(fifo);
  await assert.rejects(appendToRegularFile(fifo, 'evil\n', 'Log'), /Log must be a regular, non-symlink file/u);
});

// ---- checkHostExe ----------------------------------------------------------------------------

test('checkHostExe rejects symlink, directory, FIFO and preserves ENOENT', { skip: LINUX_ONLY }, async (t) => {
  const dir = await tempDir(t);
  const exe = path.join(dir, 'host-bin');
  await writeFile(exe, Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0, 0, 0, 0]));
  await chmod(exe, 0o755);
  await checkHostExe(exe, UID, dir);

  const link = path.join(dir, 'host-link');
  await symlink(exe, link);
  await assert.rejects(checkHostExe(link, UID, dir), /is not a regular file/u);

  const sub = path.join(dir, 'host-dir');
  await mkdir(sub);
  await assert.rejects(checkHostExe(sub, UID, dir), /is not a regular file/u);

  const fifo = path.join(dir, 'host-fifo');
  makeFifo(fifo);
  await assert.rejects(checkHostExe(fifo, UID, dir), /is not a regular file/u);

  await assert.rejects(checkHostExe(path.join(dir, 'missing-bin'), UID, dir), isEnoent);
});

// ---- readInstanceConfig ----------------------------------------------------------------------

test('readInstanceConfig rejects symlink, wrong UID, writable mode and preserves ENOENT', { skip: POSIX_ONLY }, async (t) => {
  const dir = await tempDir(t);
  const cfgPath = path.join(dir, 'claude-code.json');
  await writeFile(cfgPath, JSON.stringify({
    v: 1,
    host: 'claude-code',
    mode: 'enforce',
    root_fingerprint: FP,
    host_exes: ['/usr/bin/node'],
    state_dir: path.join(dir, 'state'),
    generations_dir: path.join(dir, 'gens'),
    managed_dir: path.join(dir, 'managed'),
    decision_socket_dir: path.join(dir, 'dec'),
    admin_socket_dir: path.join(dir, 'adm'),
    inbox_dir: null,
    build_id: 'mago-ski test',
  }), { mode: 0o600 });

  const loaded = await readInstanceConfig(cfgPath, UID);
  assert.equal(loaded.host, 'claude-code');

  const link = path.join(dir, 'instance-link.json');
  await symlink(cfgPath, link);
  await assert.rejects(readInstanceConfig(link, UID), /must be a regular file/u);

  await assert.rejects(readInstanceConfig(cfgPath, UID + 1), /owned by root/u);

  await chmod(cfgPath, 0o664);
  await assert.rejects(readInstanceConfig(cfgPath, UID), /not writable by group or others/u);

  await assert.rejects(readInstanceConfig(path.join(dir, 'missing.json'), UID), isEnoent);
});

// ---- loadConfig (claude-code adapter) --------------------------------------------------------

test('loadConfig rejects symlink, wrong UID and writable mode', { skip: POSIX_ONLY }, async (t) => {
  const dir = await tempDir(t);
  const sockDir = path.join(dir, 'sockdir');
  await mkdir(sockDir, { mode: 0o700 });
  const cfgPath = path.join(dir, 'claude-code-hook.json');
  await writeFile(cfgPath, JSON.stringify({
    v: 1,
    socket: path.join(sockDir, 'decision.sock'),
    mode: 'enforce',
    host_exes: ['/usr/bin/node'],
    client_deadline_ms: 500,
    self_deadline_ms: 2000,
  }), { mode: 0o600 });

  const cfg = await loadConfig(cfgPath, UID);
  assert.equal(cfg.mode, 'enforce');

  const link = path.join(dir, 'hook-link.json');
  await symlink(cfgPath, link);
  await assert.rejects(loadConfig(link, UID), /config must be a regular, root-owned, non-writable file/u);

  await assert.rejects(loadConfig(cfgPath, UID + 1), /config must be a regular, root-owned, non-writable file/u);

  await chmod(cfgPath, 0o664);
  await assert.rejects(loadConfig(cfgPath, UID), /config must be a regular, root-owned, non-writable file/u);
});

test('loadConfig rejects a FIFO without blocking', { skip: LINUX_ONLY }, async (t) => {
  const dir = await tempDir(t);
  const fifo = path.join(dir, 'hook-fifo.json');
  makeFifo(fifo);
  await assert.rejects(loadConfig(fifo, UID), /config must be a regular, root-owned, non-writable file/u);
});
