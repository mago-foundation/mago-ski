import assert from 'node:assert/strict';
import { chmod, copyFile, lstat, mkdir, mkdtemp, readdir, readFile, readlink, rm, writeFile } from 'node:fs/promises';
import { realpathSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test, { type TestContext } from 'node:test';
import { updateRevocations } from '../src/admin.ts';
import { createGateService, type GateServiceConfig } from '../src/gate/service.ts';
import { approve, LINUX_ONLY, setupOrg, tempDir, writeSkill } from './helpers.ts';

const NODE = realpathSync(process.execPath);
const DAY = 86_400_000;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function fixture(t: TestContext, extra: Partial<GateServiceConfig> = {}) {
  const org = await setupOrg(t, { now: new Date() });
  const base = realpathSync(await mkdtemp(path.join(os.tmpdir(), 'mago-ski-cp-')));
  t.after(async () => {
    for (const e of await readdir(base, { recursive: true, withFileTypes: true }).catch(() => []))
      if (e.isDirectory()) await chmod(path.join(e.parentPath, e.name), 0o755).catch(() => {});
    await rm(base, { recursive: true, force: true });
  });
  const inbox = path.join(base, 'inbox');
  await mkdir(inbox, { mode: 0o700 });
  let clock = new Date();
  const svc = createGateService({
    stateDir: path.join(base, 'state'), generationsDir: path.join(base, 'gens'), managedDir: path.join(base, 'managed'),
    decisionSocketDir: path.join(base, 'dec'), adminSocketDir: path.join(base, 'adm'),
    rootFingerprint: org.rootKeyId, mode: 'enforce', hostExes: [NODE], rootUid: process.getuid!(),
    inboxDir: inbox, refreshIntervalMs: 3_600_000, reconcileIntervalMs: 3_600_000, now: () => clock, ...extra,
  });
  await svc.start();
  t.after(() => svc.stop());
  const b64 = async (p: string) => (await readFile(p)).toString('base64');
  const trust = async (list = org.revocations) =>
    svc.handleAdmin({ v: 1, cmd: 'accept-trust', trust_root_b64: await b64(org.trustRoot), revocations_b64: await b64(list) });
  assert.equal((await trust()).ok, true);
  const work = await tempDir(t);
  let n = 0;
  const installRaw = async (name: string, dir: string) => {
    const issued = await approve(org, dir, { now: clock, out: path.join(work, `cert-${++n}.json`) });
    return { issued, reply: await svc.handleAdmin({ v: 1, cmd: 'install', skill_name: name, source_dir: dir, certificate_b64: await b64(issued.path) }) };
  };
  const install = async (name: string, dir?: string) => {
    const { issued, reply } = await installRaw(name, dir ?? await writeSkill(work, name));
    assert.equal(reply.ok, true, JSON.stringify(reply));
    return issued.digest;
  };
  const list = async (revoke?: string) => {
    const out = path.join(work, `list-${++n}.json`);
    await updateRevocations({ rootKeyPath: org.rootKey, revocationsPath: org.revocations, out, now: clock, ...(revoke ? { revokeDigest: revoke, reason: 'test' } : {}) });
    return out;
  };
  const drop = async (l: string) => {
    await copyFile(org.trustRoot, path.join(inbox, 'trust-root.json'));
    await copyFile(l, path.join(inbox, 'revocations.json'));
  };
  const status = async () => (await svc.handleAdmin({ v: 1, cmd: 'status' })) as Record<string, any>;
  const managed = path.join(base, 'managed');
  const gens = path.join(base, 'gens');
  const links = async () => (await readdir(managed)).filter((e) => !e.startsWith('.')).sort();
  const reconcileLog = async () => {
    const dir = path.join(base, 'state', 'log');
    const out: Record<string, any>[] = [];
    for (const f of (await readdir(dir)).filter((x) => x.endsWith('.jsonl')).sort())
      for (const line of (await readFile(path.join(dir, f), 'utf8')).split('\n').filter(Boolean)) {
        const rec = JSON.parse(line);
        if (rec.event === 'reconcile') out.push(rec);
      }
    return out;
  };
  const removed = async () => JSON.parse(await readFile(path.join(managed, '.mago-ski-removed-names.json'), 'utf8')) as { type: string; entries: { name: string; digest: string; kind: string; at: string }[] };
  return { org, svc, work, base, managed, gens, install, installRaw, list, drop, trust, status, links, reconcileLog, removed, setClock: (d: Date) => { clock = d; }, clockNow: () => clock };
}

const refresh = (f: Awaited<ReturnType<typeof fixture>>) => f.svc.handleAdmin({ v: 1, cmd: 'refresh' });

test('install refuses a name that is not the plain install name, and a nested SKILL.md; nothing is linked or stored (C4, E3, E6)', { skip: LINUX_ONLY }, async (t) => {
  const f = await fixture(t);
  const bad: [string, Record<string, string>, RegExp][] = [
    ['other', { 'SKILL.md': '---\nname: different\ndescription: d\n---\nbody\n' }, /certificate is for Skill "different"/u], // the engine already refuses a differing name
    ['padded', { 'SKILL.md': '---\nname: padded \ndescription: d\n---\nbody\n' }, /must start its frontmatter with one plain line "name: padded" so every host names it the same/u],
    ['quoted', { 'SKILL.md': '---\nname: "quoted"\ndescription: d\n---\nbody\n' }, /plain line "name: quoted"/u],
    ['nodesc', { 'SKILL.md': '---\nname: nodesc\n---\nbody\n' }, /plain line "name: nodesc"/u],
    ['bom', { 'SKILL.md': '﻿---\nname: bom\ndescription: d\n---\n' }, /plain line "name: bom"/u],
    ['nested', { 'sub/SKILL.md': 'x' }, /the Skill contains another SKILL\.md at sub\/SKILL\.md; a nested Skill would be loaded without being approved/u],
    ['nested2', { 'a/b/skill.md': 'x' }, /another SKILL\.md at a\/b\/skill\.md/u],
  ];
  for (const [name, files, message] of bad) {
    const dir = await writeSkill(f.work, name, files);
    const { reply } = await f.installRaw(name, dir);
    assert.equal(reply.ok, false, name);
    assert.match((reply as { error: string }).error, message, name);
    assert.deepEqual(await f.links(), [], name);
    assert.deepEqual(await readdir(path.join(f.gens, name)).catch(() => []), [], `${name}: the staged generation is removed`);
    assert.deepEqual(await readdir(path.join(f.base, 'state', 'certs')).catch(() => []).then((e) => e.filter((x) => x === name)), [], `${name}: no certificate`);
  }
  assert.equal((await f.status())['admission'], 'ready');
  await f.install('fine'); // a plain Skill still installs
  assert.deepEqual(await f.links(), ['fine']);
});

test('uninstall records name and digest before the link goes; reinstall forgets the name; the file is canonical (C3, D6)', { skip: LINUX_ONLY }, async (t) => {
  const f = await fixture(t);
  const digest = await f.install('alpha');
  assert.deepEqual((await f.status())['removedNames'], { count: 0, full: false, evicted: 0, error: null });
  assert.equal((await f.svc.handleAdmin({ v: 1, cmd: 'uninstall', skill_name: 'alpha' })).ok, true);
  const file = await f.removed();
  assert.equal(file.type, 'mago-ski.gate.removed-names.v1');
  assert.deepEqual(file.entries.map((e) => [e.name, e.digest, e.kind]), [['alpha', digest.slice('sha256:'.length), 'uninstalled']]);
  assert.equal((await lstat(path.join(f.managed, '.mago-ski-removed-names.json'))).isFile(), true);
  assert.equal((await f.status())['removedNames'].count, 1);
  assert.equal(await f.install('alpha', await writeSkill(f.work, 'alpha')), digest); // same digest again
  assert.deepEqual((await f.removed()).entries, []);
  assert.equal((await f.svc.handleAdmin({ v: 1, cmd: 'uninstall', skill_name: 'alpha' })).ok, true);
  const second = await writeSkill(await mkdtemp(path.join(f.work, 'v2-')), 'alpha', { 'SKILL.md': '---\nname: alpha\ndescription: Another version.\n---\nbody\n' });
  const newDigest = await f.install('alpha', second);
  assert.notEqual(newDigest, digest);
  assert.deepEqual((await f.removed()).entries, []); // a new digest: the name's old entries are gone
});

test('a revocation records the name as revoked, uninstalls in the queue and logs a durable reconcile record (C3, F7.1)', { skip: LINUX_ONLY }, async (t) => {
  const f = await fixture(t);
  const digest = await f.install('alpha');
  await f.drop(await f.list(digest));
  assert.equal((await refresh(f)).ok, true);
  assert.deepEqual(await f.links(), []);
  assert.deepEqual((await f.removed()).entries.map((e) => [e.name, e.kind]), [['alpha', 'revoked']]);
  const log = await f.reconcileLog();
  assert.deepEqual(log.map((r) => [r.skill, r.result, r.action]), [['alpha', 'uninstall:REVOKED', 'deny']]);
  assert.deepEqual(log[0]!.digests, [digest]);
});

test('a full removed-names file keeps the cap, evicts the oldest and still removes the link (D6, E6)', { skip: LINUX_ONLY }, async (t) => {
  const f = await fixture(t);
  await f.install('alpha');
  const entries = Array.from({ length: 4096 }, (_, i) => ({ name: `n${i}`, digest: i.toString(16).padStart(64, '0'), kind: 'revoked', at: `2026-01-01T00:00:${String(i % 60).padStart(2, '0')}Z` }));
  entries[7]!.at = '2025-01-01T00:00:00Z'; // the oldest
  await writeFile(path.join(f.managed, '.mago-ski-removed-names.json'), JSON.stringify({ type: 'mago-ski.gate.removed-names.v1', entries }));
  assert.equal((await f.svc.handleAdmin({ v: 1, cmd: 'uninstall', skill_name: 'alpha' })).ok, true);
  assert.deepEqual(await f.links(), []);
  const file = await f.removed();
  assert.equal(file.entries.length, 4096);
  assert.equal(file.entries.some((e) => e.name === 'n7'), false);
  assert.equal(file.entries.some((e) => e.name === 'alpha'), true);
  const s = (await f.status())['removedNames'];
  assert.deepEqual([s.full, s.evicted, s.count], [true, 1, 4096]);
});

test('prune-removed drops entries by age, needs at least 7 days, runs through the admin queue (F6.6)', { skip: LINUX_ONLY }, async (t) => {
  const f = await fixture(t);
  await f.install('alpha');
  await f.svc.handleAdmin({ v: 1, cmd: 'uninstall', skill_name: 'alpha' });
  const file = path.join(f.managed, '.mago-ski-removed-names.json');
  const old = new Date(f.clockNow().getTime() - 100 * DAY).toISOString();
  const doc = await f.removed();
  doc.entries.push({ name: 'ancient', digest: 'c'.repeat(64), kind: 'revoked', at: old });
  await writeFile(file, JSON.stringify(doc));
  for (const days of [6, 0, -1, 7.5, '9']) {
    const r = await f.svc.handleAdmin({ v: 1, cmd: 'prune-removed', older_than_days: days });
    assert.deepEqual(r, { ok: false, error: 'older_than_days must be at least 7' });
  }
  const ok = await f.svc.handleAdmin({ v: 1, cmd: 'prune-removed', older_than_days: 90 });
  assert.deepEqual(ok, { ok: true, pruned: 1, remaining: 1 });
  assert.deepEqual((await f.removed()).entries.map((e) => e.name), ['alpha']);
  assert.deepEqual(await f.svc.handleAdmin({ v: 1, cmd: 'prune-removed' }), { ok: true, pruned: 0, remaining: 1 }); // default 90 days
  assert.equal((await f.svc.handleAdmin({ v: 1, cmd: 'prune-removed', older_than_days: 30, extra: 1 })).ok, false);
});

test('reconcile with stale trust hides every Skill in enforce, logs it durably, and restores only servable Skills (E2, F1)', { skip: LINUX_ONLY }, async (t) => {
  const f = await fixture(t);
  await f.install('alpha');
  await f.install('beta');
  assert.deepEqual(await f.links(), ['alpha', 'beta']);
  // beta gains a nested SKILL.md after install: it is not servable
  const betaGen = (await readdir(path.join(f.gens, 'beta'))).find((e) => /^[0-9a-f]{64}$/u.test(e))!;
  const betaDir = path.join(f.gens, 'beta', betaGen);
  await chmod(betaDir, 0o755);
  await mkdir(path.join(betaDir, 'sub'), { mode: 0o755 });
  await writeFile(path.join(betaDir, 'sub', 'SKILL.md'), 'x');
  const t0 = f.clockNow().getTime();
  f.setClock(new Date(t0 + 31 * DAY)); // revocation list (30 d) expired, certificates (90 d) still valid
  assert.equal((await refresh(f)).ok, true);
  assert.deepEqual(await f.links(), []); // fail closed: everything hidden, nothing uninstalled
  let s = await f.status();
  assert.equal(s['trust'], 'list-expired');
  assert.deepEqual(s['hidden'].sort(), ['alpha', 'beta']);
  assert.deepEqual(s['autoUninstalled'], []);
  assert.deepEqual((await f.reconcileLog()).map((r) => [r.skill, r.result]).sort(), [['alpha', 'hide-all:trust-list-expired'], ['beta', 'hide-all:trust-list-expired']]);
  await refresh(f); // a second pass does not log again
  assert.equal((await f.reconcileLog()).length, 2);
  // trust recovers: alpha is re-linked, beta (nested file) stays hidden
  await f.drop(await f.list());
  assert.equal(((await refresh(f)) as Record<string, unknown>)['result'], 'accepted');
  assert.deepEqual(await f.links(), ['alpha']);
  assert.equal(await readlink(path.join(f.managed, 'alpha')), path.join(f.gens, 'alpha', (await readdir(path.join(f.gens, 'alpha'))).find((e) => /^[0-9a-f]{64}$/u.test(e))!));
  s = await f.status();
  assert.deepEqual(s['hidden'], ['beta']);
  assert.deepEqual(s['nameMismatch'], ['beta']);
  const log = (await f.reconcileLog()).map((r) => [r.skill, r.result]);
  assert.ok(log.some(([k, v]) => k === 'alpha' && v === 'restore'));
  assert.ok(log.some(([k, v]) => k === 'beta' && v === 'hide:nested-skill-md'));
});

test('reconcile hides an install whose SKILL.md name is no longer the plain install name; doctor input shows nameMismatch (C4, F7.1)', { skip: LINUX_ONLY }, async (t) => {
  const f = await fixture(t);
  await f.install('alpha');
  const gen = path.join(f.gens, 'alpha', (await readdir(path.join(f.gens, 'alpha'))).find((e) => /^[0-9a-f]{64}$/u.test(e))!);
  await chmod(gen, 0o755);
  await chmod(path.join(gen, 'SKILL.md'), 0o644);
  await writeFile(path.join(gen, 'SKILL.md'), '---\nname: "alpha"\ndescription: d\n---\n'); // not whitelisted
  await refresh(f);
  assert.deepEqual(await f.links(), []);
  const s = await f.status();
  assert.deepEqual(s['nameMismatch'], ['alpha']);
  // the digest no longer matches the tree either, but the name check is what hid it first; the install record is kept
  assert.equal(s['hidden'].includes('alpha') || s['autoUninstalled'].length === 1, true);
});

test('shadow: reconcile hides nothing, re-links nothing and logs would-hide once (F6.4)', { skip: LINUX_ONLY }, async (t) => {
  const f = await fixture(t, { mode: 'shadow' });
  await f.install('alpha');
  await f.install('beta');
  const betaGen = (await readdir(path.join(f.gens, 'beta'))).find((e) => /^[0-9a-f]{64}$/u.test(e))!;
  await chmod(path.join(f.gens, 'beta', betaGen), 0o755);
  await mkdir(path.join(f.gens, 'beta', betaGen, 'sub'), { mode: 0o755 });
  await writeFile(path.join(f.gens, 'beta', betaGen, 'sub', 'SKILL.md'), 'x');
  f.setClock(new Date(f.clockNow().getTime() + 31 * DAY));
  await refresh(f);
  await refresh(f);
  assert.deepEqual(await f.links(), ['alpha', 'beta']); // nothing hidden
  const s = await f.status();
  assert.deepEqual(s['hidden'], []);
  const log = await f.reconcileLog();
  assert.deepEqual(log.map((r) => [r.skill, r.action]).sort(), [['alpha', 'observe'], ['beta', 'observe']]);
  assert.ok(log.every((r) => String(r.result).startsWith('would-hide:')));
});

test('the periodic reconcile runs inside the queue without an inbox (E2)', { skip: LINUX_ONLY }, async (t) => {
  const f = await fixture(t, { reconcileIntervalMs: 60 });
  // no inbox files are ever dropped; the timer alone must notice that the list expired
  await f.install('alpha');
  assert.deepEqual(await f.links(), ['alpha']);
  f.setClock(new Date(f.clockNow().getTime() + 31 * DAY));
  for (let i = 0; i < 50 && (await f.links()).length > 0; i++) await sleep(50);
  assert.deepEqual(await f.links(), []);
  assert.deepEqual((await f.status())['hidden'], ['alpha']);
});

test('a service that starts with stale trust hides what is installed at once (E2)', { skip: LINUX_ONLY }, async (t) => {
  const f = await fixture(t);
  await f.install('alpha');
  await f.svc.stop();
  const dirs = { stateDir: path.join(f.base, 'state'), generationsDir: f.gens, managedDir: f.managed, decisionSocketDir: path.join(f.base, 'dec2'), adminSocketDir: path.join(f.base, 'adm2') };
  const later = new Date(f.clockNow().getTime() + 31 * DAY);
  const again = createGateService({ ...dirs, rootFingerprint: f.org.rootKeyId, mode: 'enforce', hostExes: [NODE], rootUid: process.getuid!(), now: () => later, reconcileIntervalMs: 3_600_000 });
  await again.start();
  t.after(() => again.stop());
  assert.deepEqual(await f.links(), []);
  assert.equal(((await again.handleAdmin({ v: 1, cmd: 'status' })) as Record<string, any>)['trust'], 'list-expired');
});

test('install racing reconcile: both run in the queue, so the Skill ends up linked and recorded', { skip: LINUX_ONLY }, async (t) => {
  const f = await fixture(t);
  const dir = await writeSkill(f.work, 'alpha');
  const { issued } = await f.installRaw('alpha', dir); // first install
  const again = f.installRaw('alpha', dir);
  const recon = refresh(f);
  const [a] = await Promise.all([again, recon]);
  assert.equal(a.reply.ok, true);
  assert.deepEqual(await f.links(), ['alpha']);
  assert.equal((await f.svc.handleAdmin({ v: 1, cmd: 'install', skill_name: 'alpha', source_dir: dir, certificate_b64: (await readFile(issued.path)).toString('base64') })).ok, true);
});
