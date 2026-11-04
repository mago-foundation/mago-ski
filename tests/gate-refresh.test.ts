import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { chmod, copyFile, mkdir, mkdtemp, readFile, symlink, writeFile } from 'node:fs/promises';
import { realpathSync } from 'node:fs';
import os from 'node:os';
import net from 'node:net';
import path from 'node:path';
import test, { type TestContext } from 'node:test';
import { updateRevocations } from '../src/admin.ts';
import { createGateService, type GateServiceConfig } from '../src/gate/service.ts';
import { approve, LINUX_ONLY, setupOrg, tempDir, writeSkill } from './helpers.ts';
import { rm, readdir } from 'node:fs/promises';

const NODE = realpathSync(process.execPath);
const HOST = `pid:${process.pid}`;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
let seq = 0;

function decide(svc: { sockets: { decision: string } }, event: string, session: string, skill?: string) {
  return new Promise<{ kind: string; verdict?: string; code?: string }>((resolve) => {
    const c = net.connect(svc.sockets.decision);
    let out = '';
    c.on('data', (d) => { out += d; });
    c.on('close', () => resolve(JSON.parse(out)));
    c.write(`${JSON.stringify({ v: 1, request_id: `q${++seq}`, event, session, ...(skill ? { skill } : {}) })}\n`);
  });
}

async function fixture(t: TestContext, extra: Partial<GateServiceConfig> = {}) {
  const org = await setupOrg(t, { now: new Date() });
  const base = realpathSync(await mkdtemp(path.join(os.tmpdir(), 'mago-ski-rf-')));
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
    inboxDir: inbox, refreshIntervalMs: 3_600_000, now: () => clock, ...extra,
  });
  await svc.start();
  t.after(() => svc.stop());
  const b64 = async (p: string) => (await readFile(p)).toString('base64');
  assert.equal((await svc.handleAdmin({ v: 1, cmd: 'accept-trust', trust_root_b64: await b64(org.trustRoot), revocations_b64: await b64(org.revocations) })).ok, true);
  const work = await tempDir(t);
  let n = 0;
  const install = async (name: string, dir: string, now = clock) => {
    const issued = await approve(org, dir, { now, out: path.join(work, `cert-${++n}.json`) });
    const r = await svc.handleAdmin({ v: 1, cmd: 'install', skill_name: name, source_dir: dir, certificate_b64: await b64(issued.path) });
    assert.equal(r.ok, true, JSON.stringify(r));
    return issued.digest;
  };
  let prev = org.revocations;
  /** Signs a new list on top of `from` (default: the last one made); `revoke` adds a digest. */
  const makeList = async (opts: { revoke?: string; reason?: string; from?: string } = {}) => {
    const out = path.join(work, `list-${++n}.json`);
    await updateRevocations({ rootKeyPath: org.rootKey, revocationsPath: opts.from ?? prev, out, now: clock, ...(opts.revoke ? { revokeDigest: opts.revoke, reason: opts.reason ?? 'test' } : {}) });
    prev = out;
    return out;
  };
  const drop = async (list: string) => {
    await copyFile(org.trustRoot, path.join(inbox, 'trust-root.json'));
    await copyFile(list, path.join(inbox, 'revocations.json'));
  };
  const status = async () => (await svc.handleAdmin({ v: 1, cmd: 'status' })) as Record<string, any>;
  return { org, svc, work, install, makeList, drop, status, inbox, setClock: (d: Date) => { clock = d; }, clockNow: () => clock };
}

test('enforce: a newer list in the inbox revokes the current generation, which is uninstalled and then denied', { skip: LINUX_ONLY }, async (t) => {
  const f = await fixture(t);
  const digest = await f.install('alpha', await writeSkill(f.work, 'alpha'));
  await decide(f.svc, 'session-start', HOST);
  assert.equal((await decide(f.svc, 'skill-invoke', HOST, 'alpha')).verdict, 'VERIFIED');
  await f.drop(await f.makeList({ revoke: digest }));
  const r = await f.svc.handleAdmin({ v: 1, cmd: 'refresh' }) as Record<string, unknown>;
  assert.equal(r.ok, true, JSON.stringify(r));
  assert.equal(r['result'], 'accepted');
  assert.equal((await decide(f.svc, 'skill-invoke', HOST, 'alpha')).verdict, 'NO_CERTIFICATE'); // uninstalled
  const s = await f.status();
  assert.equal(s['autoUninstalled'].length, 1);
  assert.deepEqual([s['autoUninstalled'][0].name, s['autoUninstalled'][0].digest, s['autoUninstalled'][0].verdict], ['alpha', digest, 'REVOKED']);
  assert.equal(s['lastRefresh'].result, 'accepted');
  assert.equal(typeof s['lastRefresh'].atBootMs, 'number');
  assert.match(s['revocationsExpiresAt'], /^20\d\d-/u);
  // identical re-drop is a no-op; no fallback happens
  assert.equal(((await f.svc.handleAdmin({ v: 1, cmd: 'refresh' })) as Record<string, unknown>)['result'], 'unchanged');
  assert.equal((await f.status())['autoUninstalled'].length, 1);
});

test('shadow: nothing is uninstalled, would-uninstall is recorded', { skip: LINUX_ONLY }, async (t) => {
  const f = await fixture(t, { mode: 'shadow' });
  const digest = await f.install('alpha', await writeSkill(f.work, 'alpha'));
  await f.drop(await f.makeList({ revoke: digest }));
  assert.equal((await f.svc.handleAdmin({ v: 1, cmd: 'refresh' })).ok, true);
  await decide(f.svc, 'session-start', HOST);
  assert.equal((await decide(f.svc, 'skill-invoke', HOST, 'alpha')).verdict, 'REVOKED'); // still installed
  const s = await f.status();
  assert.deepEqual(s['autoUninstalled'], []);
  assert.deepEqual(s['wouldUninstall'], [{ name: 'alpha', digest, verdict: 'REVOKED' }]);
});

test('rejected documents change nothing and are reported', { skip: LINUX_ONLY }, async (t) => {
  const f = await fixture(t);
  const dir = await writeSkill(f.work, 'alpha');
  const digest = await f.install('alpha', dir);
  const original = f.org.revocations;
  const a = await f.makeList({ revoke: `sha256:${'0'.repeat(64)}`, reason: 'one' }); // v2, unrelated digest
  await f.drop(a);
  assert.equal(((await f.svc.handleAdmin({ v: 1, cmd: 'refresh' })) as Record<string, unknown>)['result'], 'accepted');
  const expiry = (await f.status())['revocationsExpiresAt'];
  const bad: [string, string][] = [];
  bad.push(['older', original]);
  bad.push(['same-version-other-bytes', await f.makeList({ revoke: digest, reason: 'two', from: original })]);
  const tampered = path.join(f.work, 'tampered.json');
  const env = JSON.parse(await readFile(a, 'utf8'));
  const sig = env.signatures[0].sig as string;
  env.signatures[0].sig = (sig[0] === 'A' ? 'B' : 'A') + sig.slice(1);
  await writeFile(tampered, JSON.stringify(env));
  bad.push(['bad-signature', tampered]);
  for (const [label, file] of bad) {
    await f.drop(file);
    const r = await f.svc.handleAdmin({ v: 1, cmd: 'refresh' });
    assert.equal(r.ok, false, label);
    const s = await f.status();
    assert.equal(s['lastRefresh'].result, 'rejected', label);
    assert.ok(s['lastRefresh'].reason, label);
    assert.equal(s['revocationsExpiresAt'], expiry, label);
    assert.deepEqual(s['autoUninstalled'], [], label);
  }
  await decide(f.svc, 'session-start', HOST);
  assert.equal((await decide(f.svc, 'skill-invoke', HOST, 'alpha')).verdict, 'VERIFIED');
});

test('list expiry: not ready denies; a fresh list then uninstalls the Skill whose certificate expired', { skip: LINUX_ONLY }, async (t) => {
  const f = await fixture(t);
  await f.install('alpha', await writeSkill(f.work, 'alpha'));
  await decide(f.svc, 'session-start', HOST);
  const day = 86_400_000;
  const t0 = f.clockNow().getTime();
  f.setClock(new Date(t0 + 31 * day)); // list (30d) expired, certificate (90d) still valid
  assert.equal((await decide(f.svc, 'skill-invoke', HOST, 'alpha')).code, 'trust-unavailable');
  assert.equal((await f.svc.handleAdmin({ v: 1, cmd: 'refresh' })).ok, true); // no files: nothing extended, nothing uninstalled
  let s = await f.status();
  assert.equal(s['trust'], 'list-expired');
  assert.deepEqual(s['autoUninstalled'], []);
  f.setClock(new Date(t0 + 100 * day)); // certificate expired too
  await f.drop(await f.makeList());
  assert.equal(((await f.svc.handleAdmin({ v: 1, cmd: 'refresh' })) as Record<string, unknown>)['result'], 'accepted');
  s = await f.status();
  assert.deepEqual(s['autoUninstalled'].map((u: any) => [u.name, u.verdict]), [['alpha', 'EXPIRED']]);
});

test('unsafe inbox: symlinked file, group-writable dir, oversized file, symlinked dir', { skip: LINUX_ONLY }, async (t) => {
  const f = await fixture(t);
  const list = await f.makeList();
  await f.drop(list);
  const refresh = async () => { await f.svc.handleAdmin({ v: 1, cmd: 'refresh' }); return (await f.status())['lastRefresh']; };
  await chmod(f.inbox, 0o770);
  assert.equal((await refresh()).result, 'unsafe-inbox');
  await chmod(f.inbox, 0o700);
  const revs = path.join(f.inbox, 'revocations.json');
  await rm(revs);
  await symlink(list, revs);
  assert.equal((await refresh()).result, 'unsafe-inbox');
  await rm(revs);
  await writeFile(revs, Buffer.alloc(5 * 1024 * 1024, 0x20));
  assert.equal((await refresh()).result, 'unsafe-inbox');
  const real = `${f.inbox}-real`;
  await mkdir(real, { mode: 0o700 });
  await rm(f.inbox, { recursive: true });
  await symlink(real, f.inbox);
  assert.equal((await refresh()).result, 'unsafe-inbox');
});

test('timer refresh picks up the inbox without an admin command', { skip: LINUX_ONLY }, async (t) => {
  const f = await fixture(t, { refreshIntervalMs: 50 });
  const digest = await f.install('alpha', await writeSkill(f.work, 'alpha'));
  await f.drop(await f.makeList({ revoke: digest }));
  for (let i = 0; i < 60 && (await f.status())['autoUninstalled'].length === 0; i++) await sleep(50);
  assert.equal((await f.status())['autoUninstalled'].length, 1);
});

test('only the CURRENT generation is evaluated: an older revoked generation is not uninstalled but still denies old sessions', { skip: LINUX_ONLY }, async (t) => {
  const f = await fixture(t);
  const dir = await writeSkill(f.work, 'beta');
  const v1 = await f.install('beta', dir);
  await decide(f.svc, 'session-start', HOST);
  await writeFile(path.join(dir, 'extra.md'), 'v2\n');
  await f.install('beta', dir);
  await sleep(1300); // a new session's skew-adjusted start must lie after the v2 publication
  const fresh = spawn(NODE, ['-e', 'setInterval(()=>{},1000)'], { stdio: 'ignore' });
  t.after(() => { fresh.kill('SIGKILL'); });
  assert.equal((await decide(f.svc, 'session-start', `pid:${fresh.pid}`)).kind, 'ack');
  await f.drop(await f.makeList({ revoke: v1 }));
  assert.equal(((await f.svc.handleAdmin({ v: 1, cmd: 'refresh' })) as Record<string, unknown>)['result'], 'accepted');
  assert.deepEqual((await f.status())['autoUninstalled'], []);
  assert.equal((await decide(f.svc, 'skill-invoke', HOST, 'beta')).verdict, 'REVOKED');
  assert.equal((await decide(f.svc, 'skill-invoke', `pid:${fresh.pid}`, 'beta')).verdict, 'VERIFIED');
});
