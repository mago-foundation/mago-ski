import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { chmod, cp, link, mkdir, mkdtemp, readdir, readFile, realpath, rename, rm, stat, symlink, unlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test, { type TestContext } from 'node:test';
import { updateRevocations } from '../src/admin.ts';
import { installSkill, publishStaged, readGeneration, stageSkill, type PublishOptions } from '../src/gate/generations.ts';
import { MAX_FILE_BYTES } from '../src/tree-digest.ts';
import { loadTrustContext } from '../src/verify.ts';
import { approve, daysAfter, makeExecutable, setupOrg, T0, tempDir, writeSkill, type Org } from './helpers.ts';

async function rmSealed(dir: string): Promise<void> {
  await readdir(dir, { recursive: true, withFileTypes: true }).then(async (entries) => {
    await chmod(dir, 0o755);
    for (const e of entries) if (e.isDirectory()) await chmod(path.join(e.parentPath, e.name), 0o755);
  }, () => {});
  await rm(dir, { recursive: true, force: true });
}

async function ctx(org: Org, now = T0) {
  const r = loadTrustContext({
    trustRootBytes: await readFile(org.trustRoot), revocationsBytes: await readFile(org.revocations), rootKeyId: org.rootKeyId, now,
  });
  assert.ok(r.ok);
  return r.context;
}

async function setup(t: TestContext, files: Record<string, string> = {}) {
  const org = await setupOrg(t);
  const work = await tempDir(t);
  const base = await realpath(await mkdtemp(path.join(os.tmpdir(), 'mago-gen-')));
  t.after(() => rmSealed(base));
  const gens = path.join(base, 'generations');
  const staging = path.join(base, 'staging');
  const src = await writeSkill(work, 'demo', files);
  const issued = await approve(org, src);
  const certificates = [{ source: 'test', bytes: await readFile(issued.path) }];
  const options = async (extra: Partial<PublishOptions> = {}): Promise<PublishOptions> => ({
    generationsRoot: gens, skillName: 'demo', certificates, context: await ctx(org), now: T0, buildProfile: 'test-profile/1', ...extra,
  });
  return { org, work, gens, staging, src, issued, options, base };
}

const hex = (d: string) => d.slice('sha256:'.length);

test('happy path: read-only generation, manifest, readGeneration ok, staging empty', async (t) => {
  const s = await setup(t, { 'bin/run.sh': '#!/bin/sh\n', 'docs/a.md': 'a' });
  await makeExecutable(path.join(s.src, 'bin/run.sh'), true);
  const issued = await approve(s.org, s.src);
  const o = await s.options({ certificates: [{ source: 't', bytes: await readFile(issued.path) }] });
  const r = await installSkill(s.src, s.staging, o);
  assert.ok(r.ok, JSON.stringify(r));
  assert.equal(r.created, true);
  const dir = path.join(s.gens, 'demo', hex(issued.digest));
  assert.equal(r.dir, dir);
  assert.equal((await stat(dir)).mode & 0o777, 0o555);
  assert.equal((await stat(path.join(dir, 'bin'))).mode & 0o777, 0o555);
  assert.equal((await stat(path.join(dir, 'SKILL.md'))).mode & 0o777, 0o444);
  assert.equal((await stat(path.join(dir, 'bin/run.sh'))).mode & 0o777, 0o555);
  assert.equal(r.manifest.treeDigest, issued.digest);
  assert.equal(r.manifest.certificateId, issued.certificateId);
  assert.equal(r.manifest.buildProfile, 'test-profile/1');
  assert.deepEqual(r.manifest.files.map((f) => [f.path, f.exec]), [['SKILL.md', false], ['bin/run.sh', true], ['docs/a.md', false]]);
  assert.equal(r.manifest.trustRootVersion, o.context.trustRoot.version);
  assert.equal(r.manifest.revocationsVersion, o.context.revocations.version);
  const read = await readGeneration(s.gens, 'demo', issued.digest);
  assert.ok(read.ok);
  assert.deepEqual(read.manifest, r.manifest);
  assert.deepEqual(await readdir(s.staging), []);
  assert.deepEqual((await readdir(path.join(s.gens, 'demo'))).sort(), [hex(issued.digest), `${hex(issued.digest)}.manifest.json`]);
});

test('idempotent re-publish is a no-op; tampered existing generation is generation-mismatch and untouched', async (t) => {
  const s = await setup(t);
  const o = await s.options();
  const a = await installSkill(s.src, s.staging, o);
  assert.ok(a.ok && a.created);
  const b = await installSkill(s.src, s.staging, o);
  assert.ok(b.ok && !b.created);
  assert.deepEqual(await readdir(s.staging), []);
  const file = path.join(a.dir, 'SKILL.md');
  await chmod(a.dir, 0o755); await chmod(file, 0o644);
  await writeFile(file, 'tampered');
  const c = await installSkill(s.src, s.staging, o);
  assert.ok(!c.ok && c.reason === 'generation-mismatch');
  assert.equal(await readFile(file, 'utf8'), 'tampered');
  assert.deepEqual(await readdir(s.staging), []);
});

test('source rejections leave nothing staged or published', async (t) => {
  const s = await setup(t);
  const o = await s.options();
  const expectReject = async (reason: string) => {
    const r = await installSkill(s.src, s.staging, o);
    assert.ok(!r.ok && r.reason === reason, JSON.stringify(r));
    assert.deepEqual(await readdir(s.staging), []);
    await assert.rejects(stat(s.gens));
  };
  const file = path.join(s.src, 'extra');

  await symlink('SKILL.md', file);
  await expectReject('symlink');
  await rm(file);

  await mkdir(path.join(s.work, 'elsewhere'));
  await symlink(path.join(s.work, 'elsewhere'), file);
  await expectReject('symlink');
  await rm(file);

  execFileSync('mkfifo', [file]);
  await expectReject('special-file');
  await rm(file);

  await writeFile(path.join(s.work, 'outside'), 'x');
  await link(path.join(s.work, 'outside'), file);
  await expectReject('hard-link');
  await rm(file);

  await writeFile(path.join(s.src, '.skilldigestignore'), 'extra\n');
  await expectReject('ignored-content-not-allowed');
  await rm(path.join(s.src, '.skilldigestignore'));

  await writeFile(path.join(s.src, 'bad\nname'), 'x');
  await expectReject('unsafe-name');
  await rm(path.join(s.src, 'bad\nname'));

  await writeFile(file, Buffer.alloc(MAX_FILE_BYTES + 1));
  await expectReject('too-large');
  await rm(file);

  const viaLink = path.join(s.work, 'demo-link');
  await symlink(s.src, viaLink);
  const r = await installSkill(viaLink, s.staging, o);
  assert.ok(!r.ok && r.reason === 'symlink');
});

test('not verified: changed source, revoked digest, wrong name, no certificate; nothing published', async (t) => {
  const s = await setup(t);
  const check = async (verdict: string, o: PublishOptions, src = s.src) => {
    const r = await installSkill(src, s.staging, o);
    assert.ok(!r.ok && r.reason === 'not-verified' && r.verdict === verdict, JSON.stringify(r));
    assert.deepEqual(await readdir(s.staging), []);
    await assert.rejects(stat(s.gens));
  };
  await check('NO_CERTIFICATE', await s.options({ skillName: 'other' }));
  await check('NO_CERTIFICATE', await s.options({ certificates: [] }));
  const expired = await s.options({ now: daysAfter(T0, 200) });
  await check('EXPIRED', { ...expired, context: await ctx(s.org, T0) });

  await writeFile(path.join(s.src, 'SKILL.md'), 'changed after approval');
  await check('UNAPPROVED_CHANGE', await s.options());

  const s2 = await setup(t);
  const out = path.join(s2.work, 'rev.json');
  await updateRevocations({ rootKeyPath: s2.org.rootKey, revocationsPath: s2.org.revocations, out, now: T0, expires: '30d', revokeDigest: s2.issued.digest, reason: 'test' } );
  await writeFile(s2.org.revocations, await readFile(out));
  const r = await installSkill(s2.src, s2.staging, await s2.options());
  assert.ok(!r.ok && r.reason === 'not-verified' && r.verdict === 'REVOKED', JSON.stringify(r));
  await assert.rejects(stat(s2.gens));
});

test('executable bit is preserved and covered by the digest', async (t) => {
  const s = await setup(t, { 'run.sh': 'x' });
  // approved as non-exec; making the source executable changes the digest
  await makeExecutable(path.join(s.src, 'run.sh'), true);
  const r = await installSkill(s.src, s.staging, await s.options());
  assert.ok(!r.ok && r.verdict === 'UNAPPROVED_CHANGE');
  const issued = await approve(s.org, s.src);
  const ok = await installSkill(s.src, s.staging, await s.options({ certificates: [{ source: 't', bytes: await readFile(issued.path) }] }));
  assert.ok(ok.ok && ok.manifest.files.find((f) => f.path === 'run.sh')?.exec === true);
  assert.equal((await stat(path.join(ok.dir, 'run.sh'))).mode & 0o777, 0o555);
});

test('changing the source after staging does not change what is published', async (t) => {
  const s = await setup(t);
  const staged = await stageSkill(s.src, s.staging);
  assert.ok(staged.ok);
  assert.equal((await stat(staged.staged.stagedDir)).mode & 0o777, 0o700);
  await writeFile(path.join(s.src, 'SKILL.md'), 'evil');
  const r = await publishStaged(staged.staged, await s.options());
  assert.ok(r.ok);
  assert.notEqual(await readFile(path.join(r.dir, 'SKILL.md'), 'utf8'), 'evil');
  assert.ok((await readGeneration(s.gens, 'demo', s.issued.digest)).ok);
  await assert.rejects(stat(staged.staged.stagedDir));
});

test('readGeneration detects extra file, mode change, modified file, planted symlink, extra dir, planted .git', async (t) => {
  const s = await setup(t, { 'sub/a.txt': 'a' });
  const r = await installSkill(s.src, s.staging, await s.options());
  assert.ok(r.ok);
  const check = async (mutate: () => Promise<void>, undo: () => Promise<void>) => {
    await mutate();
    const read = await readGeneration(s.gens, 'demo', s.issued.digest);
    assert.ok(!read.ok && read.reason === 'generation-mismatch', JSON.stringify(read));
    await undo();
    assert.ok((await readGeneration(s.gens, 'demo', s.issued.digest)).ok);
  };
  const sub = path.join(r.dir, 'sub');
  const open = async (d: string) => { await chmod(d, 0o755); };
  const seal = async (d: string) => { await chmod(d, 0o555); };

  await check(async () => { await open(sub); await writeFile(path.join(sub, 'extra'), 'x'); },
              async () => { await rm(path.join(sub, 'extra')); await seal(sub); });
  await check(async () => { await chmod(path.join(sub, 'a.txt'), 0o644); }, async () => { await chmod(path.join(sub, 'a.txt'), 0o444); });
  await check(async () => { await open(sub); await chmod(path.join(sub, 'a.txt'), 0o644); await writeFile(path.join(sub, 'a.txt'), 'b'); },
              async () => { await writeFile(path.join(sub, 'a.txt'), 'a'); await chmod(path.join(sub, 'a.txt'), 0o444); await seal(sub); });
  await check(async () => { await open(sub); await symlink('a.txt', path.join(sub, 'ln')); },
              async () => { await rm(path.join(sub, 'ln')); await seal(sub); });
  await check(async () => { await open(r.dir); await mkdir(path.join(r.dir, 'empty')); },
              async () => { await rm(path.join(r.dir, 'empty'), { recursive: true }); await seal(r.dir); });
  await check(async () => { await open(r.dir); await mkdir(path.join(r.dir, '.git')); },
              async () => { await rm(path.join(r.dir, '.git'), { recursive: true }); await seal(r.dir); });
  await check(async () => { await open(sub); await chmod(sub, 0o700); }, async () => { await seal(sub); });
});

test('readGeneration: missing generation and mismatching manifest are closed failures', async (t) => {
  const s = await setup(t);
  const missing = await readGeneration(s.gens, 'demo', s.issued.digest);
  assert.ok(!missing.ok && missing.reason === 'generation-mismatch');
  const r = await installSkill(s.src, s.staging, await s.options());
  assert.ok(r.ok);
  const other = 'sha256:' + '0'.repeat(64);
  assert.ok(!(await readGeneration(s.gens, 'demo', other)).ok);
  const bad = await readGeneration(s.gens, '../x', s.issued.digest);
  assert.ok(!bad.ok && bad.reason === 'io-error');
});

test('ancestor swapped for a symlink during staging never copies the other directory', async (t) => {
  const s = await setup(t);
  const race = path.join(s.base, 'race');
  await mkdir(path.join(race, 'other', 'demo'), { recursive: true });
  await writeFile(path.join(race, 'other', 'demo', 'EVIL'), 'attacker');
  await writeFile(path.join(race, 'other', 'demo', 'SKILL.md'), 'attacker');
  await mkdir(path.join(race, 'a'), { recursive: true });
  await cp(s.src, path.join(race, 'a', 'demo'), { recursive: true });
  let stop = false;
  const swapper = (async () => {
    while (!stop) {
      await rename(path.join(race, 'a'), path.join(race, 'a-real'));
      await symlink(path.join(race, 'other'), path.join(race, 'a'));
      await unlink(path.join(race, 'a'));
      await rename(path.join(race, 'a-real'), path.join(race, 'a'));
    }
  })();
  let ok = 0, runs = 0;
  const end = Date.now() + 2000;
  while (Date.now() < end) {
    runs++;
    const r = await stageSkill(path.join(race, 'a', 'demo'), s.staging);
    if (r.ok) {
      ok++;
      assert.ok(!(await readdir(r.staged.stagedDir)).includes('EVIL'), 'staged the attacker directory');
      assert.equal(await readFile(path.join(r.staged.stagedDir, 'SKILL.md'), 'utf8'), await readFile(path.join(s.src, 'SKILL.md'), 'utf8'));
      await r.staged.discard();
    }
  }
  stop = true;
  await swapper;
  assert.ok(runs > 0 && ok >= 0);
  assert.deepEqual(await readdir(s.staging), []);
});

test('symlinked stagingRoot, symlinked <gens>/<name> and writable roots are rejected', async (t) => {
  const s = await setup(t);
  const elsewhere = path.join(s.base, 'elsewhere');
  await mkdir(elsewhere);
  await symlink(elsewhere, s.staging);
  const r = await stageSkill(s.src, s.staging);
  assert.ok(!r.ok && r.reason === 'symlink', JSON.stringify(r));
  assert.deepEqual(await readdir(elsewhere), []);
  await unlink(s.staging);

  await mkdir(s.gens, { mode: 0o755 });
  await symlink(elsewhere, path.join(s.gens, 'demo'));
  const i = await installSkill(s.src, s.staging, await s.options());
  assert.ok(!i.ok && i.reason === 'symlink', JSON.stringify(i));
  assert.deepEqual(await readdir(elsewhere), []);
  assert.deepEqual(await readdir(s.staging), []);
  await unlink(path.join(s.gens, 'demo'));

  await chmod(s.gens, 0o775);
  const w = await installSkill(s.src, s.staging, await s.options());
  assert.ok(!w.ok && w.reason === 'io-error', JSON.stringify(w));
  await chmod(s.gens, 0o755);
  await chmod(s.staging, 0o770);
  const w2 = await stageSkill(s.src, s.staging);
  assert.ok(!w2.ok && w2.reason === 'io-error', JSON.stringify(w2));
});

test('publishStaged rejects hand-staged trees with excluded entries; nothing is published', async (t) => {
  const s = await setup(t);
  const o = await s.options();
  for (const plant of [
    async (d: string) => { await mkdir(path.join(d, '.git')); await writeFile(path.join(d, '.git', 'x'), 'x'); },
    async (d: string) => { await writeFile(path.join(d, '.skilldigestignore'), 'hidden\n'); await writeFile(path.join(d, 'hidden'), 'x'); },
  ]) {
    const staged = await stageSkill(s.src, s.staging);
    assert.ok(staged.ok);
    await plant(staged.staged.stagedDir);
    const r = await publishStaged(staged.staged, o);
    assert.ok(!r.ok && r.reason === 'ignored-content-not-allowed', JSON.stringify(r));
    await assert.rejects(stat(s.gens));
    assert.deepEqual(await readdir(s.staging), []);
  }
});

test('generation directory without manifest is generation-incomplete on republish', async (t) => {
  const s = await setup(t);
  const o = await s.options();
  const a = await installSkill(s.src, s.staging, o);
  assert.ok(a.ok);
  await rm(`${a.dir}.manifest.json`);
  const b = await installSkill(s.src, s.staging, o);
  assert.ok(!b.ok && b.reason === 'generation-incomplete', JSON.stringify(b));
  assert.deepEqual(await readdir(s.staging), []);
});

test('attacker-writable ancestor of the staging root swapped after verification never publishes decoy content', async (t) => {
  const s = await setup(t);
  const o = await s.options();
  const attk = path.join(s.base, 'attk');           // attacker-writable ancestor of the staging root
  const decoy = path.join(s.base, 'decoy');
  await mkdir(attk, { mode: 0o777 });
  await chmod(attk, 0o777);
  const staging = path.join(attk, 'staging');
  const fds = async () => (await readdir('/proc/self/fd')).length;
  assert.ok((await installSkill(s.src, staging, { ...o, generationsRoot: path.join(s.base, 'warm') })).ok);
  const baseline = await fds();

  let cur = '', stop = false, swaps = 0;
  const watcher = (async () => {
    while (!stop) {
      if (cur && await stat(path.join(cur, 'demo')).then(() => true, () => false)) {
        const names = await readdir(staging).catch(() => [] as string[]);
        for (const n of names) {
          await mkdir(path.join(decoy, 'staging', n), { recursive: true });
          await writeFile(path.join(decoy, 'staging', n, 'SKILL.md'), 'DECOY');
        }
        try {
          await rename(attk, `${attk}-real`);
          await symlink(decoy, attk);
          swaps++;
          await new Promise((r) => setTimeout(r, 5));
          await unlink(attk);
          await rename(`${attk}-real`, attk);
        } catch { /* lost the race with cleanup; keep going */ }
        cur = '';
      }
      await new Promise((r) => setImmediate(r));
    }
  })();

  const gensDirs: string[] = [];
  let okCount = 0;
  const end = Date.now() + 2000;
  for (let i = 0; Date.now() < end; i++) {
    const gens = path.join(s.base, `g${i}`);
    gensDirs.push(gens);
    cur = gens;
    const r = await installSkill(s.src, staging, { ...o, generationsRoot: gens });
    cur = '';
    if (!r.ok) continue;
    okCount++;
    assert.equal(await readFile(path.join(r.dir, 'SKILL.md'), 'utf8'), await readFile(path.join(s.src, 'SKILL.md'), 'utf8'));
    assert.ok((await readGeneration(gens, 'demo', s.issued.digest)).ok);
  }
  stop = true;
  await watcher;
  assert.ok(okCount > 0 && swaps > 0, `ok=${okCount} swaps=${swaps}`);
  for (const g of gensDirs) {
    for (const d of await readdir(path.join(g, 'demo')).catch(() => [] as string[])) {
      if (d.endsWith('.manifest.json')) continue;
      assert.notEqual(await readFile(path.join(g, 'demo', d, 'SKILL.md'), 'utf8').catch(() => ''), 'DECOY');
    }
  }
  assert.ok(await fds() <= baseline, `fd leak: ${await fds()} > ${baseline}`);
});
