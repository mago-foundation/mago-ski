import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtemp, mkdir, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { computeTreeDigest, MAX_FILE_BYTES, resolveExternalFile } from '../src/tree-digest.mjs';

async function temporaryDirectory(t) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'mago-ski-tree-'));
  t.after(async () => await import('node:fs/promises').then(({ rm }) => rm(directory, { recursive: true, force: true })));
  return directory;
}

test('tree digest follows the v1 byte framing and UTF-8 path ordering', async (t) => {
  const root = await temporaryDirectory(t);
  await mkdir(path.join(root, 'nested'));
  await writeFile(path.join(root, 'nested', 'beta.bin'), Buffer.from([0, 1, 255]));
  await writeFile(path.join(root, 'alpha.txt'), 'alpha\n');

  const result = await computeTreeDigest(root);
  assert.equal(result.profile, 'mago.skill-tree/v1');
  assert.equal(result.digest, 'sha256:be126c40579a4a19aab21265f8b644874a6d2fce230fd2ebe50ecc48d2daaea9');
  assert.equal(result.fileCount, 2);
  assert.equal(result.totalBytes, 9);
});

test('creation order does not affect a tree digest', async (t) => {
  const left = await temporaryDirectory(t);
  const right = await temporaryDirectory(t);
  await mkdir(path.join(left, 'sub'));
  await mkdir(path.join(right, 'sub'));
  await writeFile(path.join(left, 'sub', 'b'), 'two');
  await writeFile(path.join(left, 'a'), 'one');
  await writeFile(path.join(right, 'a'), 'one');
  await writeFile(path.join(right, 'sub', 'b'), 'two');
  assert.equal((await computeTreeDigest(left)).digest, (await computeTreeDigest(right)).digest);
});

test('rejects symlinks, case-fold collisions and non-NFC names', async (t) => {
  const linkRoot = await temporaryDirectory(t);
  const external = path.join(path.dirname(linkRoot), `${path.basename(linkRoot)}-external`);
  await writeFile(external, 'outside');
  t.after(async () => await import('node:fs/promises').then(({ unlink }) => unlink(external).catch(() => {})));
  await symlink(external, path.join(linkRoot, 'linked.txt'));
  await assert.rejects(computeTreeDigest(linkRoot), /symbolic link/u);

  const collisionRoot = await temporaryDirectory(t);
  await writeFile(path.join(collisionRoot, 'Skill.md'), 'upper');
  await writeFile(path.join(collisionRoot, 'skill.md'), 'lower');
  await assert.rejects(computeTreeDigest(collisionRoot), /case-insensitive path collision/u);

  const compatibilityCollisionRoot = await temporaryDirectory(t);
  await writeFile(path.join(compatibilityCollisionRoot, 'A.md'), 'ascii');
  await writeFile(path.join(compatibilityCollisionRoot, 'Ａ.md'), 'fullwidth');
  await assert.rejects(computeTreeDigest(compatibilityCollisionRoot), /case-insensitive path collision/u);

  const normalizationRoot = await temporaryDirectory(t);
  await writeFile(path.join(normalizationRoot, 'e\u0301.txt'), 'decomposed');
  await assert.rejects(computeTreeDigest(normalizationRoot), /unsupported path component/u);

  const reservedRoot = await temporaryDirectory(t);
  await writeFile(path.join(reservedRoot, 'CON.txt'), 'reserved');
  await assert.rejects(computeTreeDigest(reservedRoot), /unsupported path component/u);

  if (process.platform === 'linux') {
    const invalidUtf8Root = await temporaryDirectory(t);
    const invalidName = Buffer.concat([Buffer.from(`${invalidUtf8Root}/`), Buffer.from([0xff])]);
    await writeFile(invalidName, 'invalid path');
    await assert.rejects(computeTreeDigest(invalidUtf8Root), /not valid UTF-8/u);

    const specialFileRoot = await temporaryDirectory(t);
    execFileSync('mkfifo', [path.join(specialFileRoot, 'pipe')]);
    await assert.rejects(computeTreeDigest(specialFileRoot), /unsupported special file/u);
  }
});

test('rejects oversized files and sidecars inside the covered root', async (t) => {
  const root = await temporaryDirectory(t);
  const handle = await import('node:fs/promises').then(({ open }) => open(path.join(root, 'large.bin'), 'w'));
  try {
    await handle.truncate(MAX_FILE_BYTES + 1);
  } finally {
    await handle.close();
  }
  await assert.rejects(computeTreeDigest(root), /67108864-byte limit/u);
  await assert.rejects(resolveExternalFile(path.join(root, 'manifest.json'), root, 'Manifest', { allowMissing: true }), /outside the Skill directory/u);
});
