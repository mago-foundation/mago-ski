import assert from 'node:assert/strict';
import { mkdir, readdir, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { CERTIFICATE_FILENAME, collectSkillTree, digestFileList, hashFile, IGNORE_FILENAME, parseIgnoreFile } from '../src/tree-digest.ts';
import { makeExecutable, tempDir, writeSkill } from './helpers.ts';

test('digest is deterministic, independent of creation order, and recomputable from the file list', async (t) => {
  const dir = await tempDir(t);
  const a = await writeSkill(path.join(dir, 'a'), 'demo', { 'z.txt': 'z', 'scripts/run.sh': 'echo hi\n' });
  const b = await writeSkill(path.join(dir, 'b'), 'demo', { 'scripts/run.sh': 'echo hi\n', 'z.txt': 'z' });
  const treeA = await collectSkillTree(a);
  const treeB = await collectSkillTree(b);
  assert.equal(treeA.digest, treeB.digest);
  assert.equal(digestFileList(treeA.files), treeA.digest);
  assert.deepEqual(treeA.files.map((file) => file.path), ['SKILL.md', 'scripts/run.sh', 'z.txt']);
});

test('a one-character text change changes the digest', async (t) => {
  const dir = await tempDir(t);
  const skill = await writeSkill(dir, 'demo');
  const before = await collectSkillTree(skill);
  await writeFile(path.join(skill, 'SKILL.md'), `---\nname: demo\ndescription: Test Skill demo.\n---\n# demo\n\nFollow the steps!\n`);
  const after = await collectSkillTree(skill);
  assert.notEqual(before.digest, after.digest);
});

test('the executable bit is part of the digest', { skip: process.platform === 'win32' ? 'no POSIX mode bits on Windows' : false }, async (t) => {
  const dir = await tempDir(t);
  const skill = await writeSkill(dir, 'demo', { 'run.sh': 'echo hi\n' });
  await makeExecutable(path.join(skill, 'run.sh'), false);
  const plain = await collectSkillTree(skill);
  await makeExecutable(path.join(skill, 'run.sh'), true);
  const executable = await collectSkillTree(skill);
  assert.notEqual(plain.digest, executable.digest);
  assert.equal(executable.files.find((file) => file.path === 'run.sh')?.exec, true);
});

test('root .git and the in-tree certificate are excluded; nested .git is not', async (t) => {
  const dir = await tempDir(t);
  const skill = await writeSkill(dir, 'demo');
  const clean = await collectSkillTree(skill);
  await mkdir(path.join(skill, '.git'));
  await writeFile(path.join(skill, '.git', 'HEAD'), 'ref: refs/heads/main\n');
  await writeFile(path.join(skill, CERTIFICATE_FILENAME), '{}\n');
  const withExtras = await collectSkillTree(skill);
  assert.equal(withExtras.digest, clean.digest);
  assert.deepEqual(withExtras.excluded, ['.git/', CERTIFICATE_FILENAME]);
  await mkdir(path.join(skill, 'sub', '.git'), { recursive: true });
  await writeFile(path.join(skill, 'sub', '.git', 'x'), 'x');
  assert.notEqual((await collectSkillTree(skill)).digest, clean.digest);
});

test('.skilldigestignore excludes listed paths and is itself covered', async (t) => {
  const dir = await tempDir(t);
  const skill = await writeSkill(dir, 'demo', { 'cache/a.bin': 'a', 'notes.txt': 'n' });
  await writeFile(path.join(skill, IGNORE_FILENAME), '# local files\ncache/\nnotes.txt\n');
  const tree = await collectSkillTree(skill);
  assert.deepEqual(tree.files.map((file) => file.path), [IGNORE_FILENAME, 'SKILL.md']);
  assert.deepEqual(tree.excluded, ['cache/', 'notes.txt']);
  await writeFile(path.join(skill, 'cache', 'b.bin'), 'b');
  assert.equal((await collectSkillTree(skill)).digest, tree.digest);
  await writeFile(path.join(skill, IGNORE_FILENAME), 'cache/\n');
  assert.notEqual((await collectSkillTree(skill)).digest, tree.digest);
});

test('ignore patterns reject globs, parent segments and absolute paths', () => {
  for (const bad of ['*.log', '../x', '/abs', 'a/../b', IGNORE_FILENAME, 'a\\b']) {
    assert.throws(() => parseIgnoreFile(bad), /unsupported pattern/u, bad);
  }
  assert.deepEqual(parseIgnoreFile('# c\n\nbuild/\nfile.txt\n'), [
    { pattern: 'build', directoryOnly: true }, { pattern: 'file.txt', directoryOnly: false },
  ]);
});

test('rejects symlinks, case-insensitive collisions and non-NFC names', async (t) => {
  const dir = await tempDir(t);
  const linked = await writeSkill(path.join(dir, 'l'), 'demo');
  await symlink('/etc/hostname', path.join(linked, 'link'));
  await assert.rejects(collectSkillTree(linked), /symbolic link/u);
  const collide = await writeSkill(path.join(dir, 'c'), 'demo', { 'Readme.txt': 'a', 'README.txt': 'b' });
  if ((await readdir(collide)).length === 3) await assert.rejects(collectSkillTree(collide), /collision/u);
  const nfd = await writeSkill(path.join(dir, 'n'), 'demo', { ['café.txt']: 'x' });
  await assert.rejects(collectSkillTree(nfd), /unsupported path component/u);
});

test('hashFile matches the tree entry for a single file', async (t) => {
  const dir = await tempDir(t);
  const skill = await writeSkill(dir, 'demo', { 'ref.md': 'reference\n' });
  const tree = await collectSkillTree(skill);
  assert.deepEqual(await hashFile(path.join(skill, 'ref.md'), 'ref.md'), tree.files.find((file) => file.path === 'ref.md'));
});
