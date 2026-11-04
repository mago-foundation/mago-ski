import assert from 'node:assert/strict';
import { spawn, type ChildProcess } from 'node:child_process';
import { chmod, copyFile, mkdir, mkdtemp, readdir, readFile, rm, stat, symlink, unlink, writeFile } from 'node:fs/promises';
import { realpathSync } from 'node:fs';
import os from 'node:os';
import net from 'node:net';
import path from 'node:path';
import test, { type TestContext } from 'node:test';
import { readlinkSync } from 'node:fs';
import { Worker } from 'node:worker_threads';
import { updateRevocations } from '../src/admin.ts';
import { assertGatePlatform, bootId, bootMs, NotLiveError, parseStatus, processFacts as realFacts, processInfo } from '../src/gate/proc.ts';
import { createGateService, type GateServiceConfig } from '../src/gate/service.ts';
import { approve, LINUX_ONLY, setupOrg, tempDir, writeSkill, type Org } from './helpers.ts';

const NODE = realpathSync(process.execPath);
const HOST = `pid:${process.pid}`;
let seq = 0;
const req = (event: string, session: string, skill?: string) =>
  JSON.stringify({ v: 1, request_id: `r${++seq}`, event, session, ...(skill ? { skill } : {}) });

function talk(sock: string, data: string | Buffer, opts: { end?: boolean } = {}): Promise<string> {
  return new Promise((resolve) => {
    const c = net.connect(sock);
    let out = '';
    c.on('data', (d) => { out += d; });
    c.on('close', () => resolve(out));
    c.on('error', () => resolve(out));
    c.write(data, () => { if (opts.end) c.end(); });
  });
}
const decide = async (svc: { sockets: { decision: string } }, event: string, session: string, skill?: string) =>
  JSON.parse(await talk(svc.sockets.decision, `${req(event, session, skill)}\n`)) as { kind: string; verdict?: string; code?: string; mode: string };

/** Generations are read-only by design, so cleanup must make them writable first. */
async function scratch(t: TestContext): Promise<string> {
  const dir = realpathSync(await mkdtemp(path.join(os.tmpdir(), 'mago-ski-svc-')));
  t.after(async () => {
    for (const e of await readdir(dir, { recursive: true, withFileTypes: true }).catch(() => []))
      if (e.isDirectory()) await chmod(path.join(e.parentPath, e.name), 0o755).catch(() => {});
    await rm(dir, { recursive: true, force: true });
  });
  return dir;
}

async function fixture(t: TestContext, extra: Partial<GateServiceConfig> = {}, accept = true) {
  const org = await setupOrg(t, { now: new Date() });
  const base = await scratch(t);
  const svc = createGateService({
    stateDir: path.join(base, 'state'), generationsDir: path.join(base, 'gens'), managedDir: path.join(base, 'managed'),
    decisionSocketDir: path.join(base, 'dec'), adminSocketDir: path.join(base, 'adm'),
    rootFingerprint: org.rootKeyId, mode: 'enforce', hostExes: [NODE], rootUid: process.getuid!(), ...extra,
  });
  await svc.start();
  t.after(() => svc.stop());
  const docs = async (o: Org = org) => ({ trust_root_b64: (await readFile(o.trustRoot)).toString('base64'), revocations_b64: (await readFile(o.revocations)).toString('base64') });
  if (accept) assert.equal((await svc.handleAdmin({ v: 1, cmd: 'accept-trust', ...await docs() })).ok, true);
  const work = await tempDir(t);
  let n = 0;
  /** Approve the Skill dir as it is now and install it. */
  const install = async (name: string, dir: string) => {
    const issued = await approve(org, dir, { now: new Date(), out: path.join(work, `cert-${++n}.json`) });
    const r = await svc.handleAdmin({ v: 1, cmd: 'install', skill_name: name, source_dir: dir, certificate_b64: (await readFile(issued.path)).toString('base64') });
    assert.equal(r.ok, true, JSON.stringify(r));
    return issued.digest;
  };
  let rev = 0;
  const revoke = async (digest: string) => {
    const out = path.join(work, `rev-${++rev}.json`);
    await updateRevocations({ rootKeyPath: org.rootKey, revocationsPath: rev === 1 ? org.revocations : path.join(work, `rev-${rev - 1}.json`), out, now: new Date(), revokeDigest: digest, reason: 'test' });
    const r = await svc.handleAdmin({ v: 1, cmd: 'accept-trust', trust_root_b64: (await docs()).trust_root_b64, revocations_b64: (await readFile(out)).toString('base64') });
    assert.equal(r.ok, true, JSON.stringify(r));
  };
  return { org, svc, work, install, revoke, docs, state: path.join(base, 'state'), managed: path.join(base, 'managed'), gens: path.join(base, 'gens') };
}

function host(t: TestContext, file = NODE): ChildProcess {
  const c = spawn(file, ['-e', 'setInterval(()=>{},1000)'], { stdio: 'ignore' });
  t.after(() => { c.kill('SIGKILL'); });
  return c;
}
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

test('the gate platform check accepts Linux only and names the platform it refuses', () => {
  assert.doesNotThrow(() => assertGatePlatform('linux'));
  for (const platform of ['darwin', 'win32', 'freebsd'] as const) {
    assert.throws(() => assertGatePlatform(platform), new RegExp(`runs on Linux only \\(this is ${platform}\\)`, 'u'));
  }
});

test('on a platform other than Linux the service refuses to start and creates nothing', async (t) => {
  const real = Object.getOwnPropertyDescriptor(process, 'platform')!;
  Object.defineProperty(process, 'platform', { ...real, value: 'darwin' });
  t.after(() => { Object.defineProperty(process, 'platform', real); });
  const base = await scratch(t);
  const dirs = ['state', 'gens', 'dec', 'adm', 'managed'].map((d) => path.join(base, d));
  const svc = createGateService({
    stateDir: dirs[0]!, generationsDir: dirs[1]!, managedDir: dirs[4]!, decisionSocketDir: dirs[2]!, adminSocketDir: dirs[3]!,
    rootFingerprint: 'unused', mode: 'enforce', hostExes: [NODE], rootUid: process.getuid?.() ?? 0,
  });
  t.after(() => svc.stop()); // only matters if start() wrongly succeeds; stop() is safe on a service that never started
  await assert.rejects(svc.start(), /the mago-ski gate service runs on Linux only \(this is darwin\)/u);
  for (const dir of dirs) await assert.rejects(stat(dir), { code: 'ENOENT' });
});

test('proc: boot id, boot ms, own process, comm with spaces and parenthesis', { skip: LINUX_ONLY }, async (t) => {
  assert.match(await bootId(), /^[0-9a-f-]{36}$/u);
  const a = await bootMs(); await sleep(20);
  assert.ok((await bootMs()) >= a);
  const me = await processInfo(process.pid);
  assert.equal(me.exe, NODE);
  assert.equal(me.uid, process.getuid!());
  assert.ok(me.startedBootMs > 0 && me.startedBootMs <= (await bootMs()));
  const dir = await tempDir(t);
  const odd = path.join(dir, 'a b) (c d');
  await symlink(NODE, odd);
  const child = host(t, odd);
  const info = await processInfo(child.pid!);
  assert.equal(info.exe, NODE);
  assert.ok(info.startedBootMs >= me.startedBootMs);
  await assert.rejects(processInfo(2 ** 30));
});

test('session-start then invoke is allowed; revocation denies the next invoke; modes and socket modes', { skip: LINUX_ONLY }, async (t) => {
  const f = await fixture(t);
  const dir = await writeSkill(f.work, 'alpha');
  const digest = await f.install('alpha', dir);
  assert.deepEqual(await decide(f.svc, 'session-start', HOST), { v: 1, request_id: `r${seq}`, kind: 'ack', mode: 'enforce' });
  assert.equal((await decide(f.svc, 'session-start', HOST)).kind, 'ack'); // re-sent start
  for (const ev of ['skill-invoke', 'prompt-expansion']) assert.equal((await decide(f.svc, ev, HOST, 'alpha')).verdict, 'VERIFIED');
  await f.revoke(digest);
  assert.equal((await decide(f.svc, 'skill-invoke', HOST, 'alpha')).verdict, 'NO_CERTIFICATE'); // enforce: a revoked current generation is uninstalled
  assert.equal((await stat(f.svc.sockets.decision)).mode & 0o777, 0o666);
  assert.equal((await stat(f.svc.sockets.admin)).mode & 0o777, 0o600);
});

test('shadow mode is returned in results', { skip: LINUX_ONLY }, async (t) => {
  const f = await fixture(t, { mode: 'shadow' });
  assert.equal((await decide(f.svc, 'skill-invoke', HOST, 'alpha')).mode, 'shadow');
});

test('update v1 -> v2: allowed; v1 revoked later denies old sessions only', { skip: LINUX_ONLY }, async (t) => {
  const f = await fixture(t);
  const dir = await writeSkill(f.work, 'beta');
  const v1 = await f.install('beta', dir);
  await decide(f.svc, 'session-start', HOST);
  await writeFile(path.join(dir, 'extra.md'), 'v2\n');
  await f.install('beta', dir);
  assert.equal((await decide(f.svc, 'skill-invoke', HOST, 'beta')).verdict, 'VERIFIED');
  await sleep(1300); // the new session's skew-adjusted start must lie after the v2 publication
  const fresh = host(t);
  assert.equal((await decide(f.svc, 'session-start', `pid:${fresh.pid}`)).kind, 'ack');
  await f.revoke(v1);
  assert.equal((await decide(f.svc, 'skill-invoke', HOST, 'beta')).verdict, 'REVOKED');
  assert.equal((await decide(f.svc, 'skill-invoke', `pid:${fresh.pid}`, 'beta')).verdict, 'VERIFIED');
});

test('uninstall denies; an uninstalled or unknown Skill is NO_CERTIFICATE', { skip: LINUX_ONLY }, async (t) => {
  const f = await fixture(t);
  await f.install('gamma', await writeSkill(f.work, 'gamma'));
  await decide(f.svc, 'session-start', HOST);
  assert.equal((await decide(f.svc, 'skill-invoke', HOST, 'gamma')).verdict, 'VERIFIED');
  assert.equal((await f.svc.handleAdmin({ v: 1, cmd: 'uninstall', skill_name: 'gamma' })).ok, true);
  assert.equal((await decide(f.svc, 'skill-invoke', HOST, 'gamma')).verdict, 'NO_CERTIFICATE');
  assert.equal((await decide(f.svc, 'skill-invoke', HOST, 'never-installed')).verdict, 'NO_CERTIFICATE');
});

test('hosts see the installed generation: install links it, an update swaps the link, uninstall and revoke remove it', { skip: LINUX_ONLY }, async (t) => {
  const f = await fixture(t);
  const dir = await writeSkill(f.work, 'beta');
  const v1 = await f.install('beta', dir);
  const link = path.join(f.managed, 'beta');
  assert.equal(readlinkSync(link), path.join(f.gens, 'beta', v1.slice('sha256:'.length)));
  assert.equal(await readFile(path.join(link, 'SKILL.md'), 'utf8'), await readFile(path.join(dir, 'SKILL.md'), 'utf8'));
  await writeFile(path.join(dir, 'extra.md'), 'v2\n');
  const v2 = await f.install('beta', dir);
  assert.equal(readlinkSync(link), path.join(f.gens, 'beta', v2.slice('sha256:'.length)));
  assert.deepEqual((await readdir(f.managed)).sort(), ['beta']); // no temporary link left behind
  await f.revoke(v2); // enforce: auto-uninstall hides it from hosts
  await assert.rejects(stat(link), { code: 'ENOENT' });
  await f.install('gamma', await writeSkill(f.work, 'gamma'));
  assert.equal((await f.svc.handleAdmin({ v: 1, cmd: 'uninstall', skill_name: 'gamma' })).ok, true);
  await assert.rejects(stat(path.join(f.managed, 'gamma')), { code: 'ENOENT' });
});

test('hosts see the installed generation: a real directory in the managed folder is refused, never replaced or removed', { skip: LINUX_ONLY }, async (t) => {
  const f = await fixture(t);
  await mkdir(path.join(f.managed, 'delta', 'x'), { recursive: true });
  const dir = await writeSkill(f.work, 'delta');
  const issued = await approve(f.org, dir, { now: new Date(), out: path.join(f.work, 'delta-cert.json') });
  const r = await f.svc.handleAdmin({ v: 1, cmd: 'install', skill_name: 'delta', source_dir: dir, certificate_b64: (await readFile(issued.path)).toString('base64') });
  assert.equal(r.ok, false);
  await decide(f.svc, 'session-start', HOST);
  assert.equal((await decide(f.svc, 'skill-invoke', HOST, 'delta')).verdict, 'NO_CERTIFICATE'); // never recorded
  assert.equal((await f.svc.handleAdmin({ v: 1, cmd: 'uninstall', skill_name: 'delta' })).ok, false);
  assert.ok((await stat(path.join(f.managed, 'delta', 'x'))).isDirectory());
  assert.deepEqual((await readdir(f.managed)).sort(), ['delta']);
});

test('identity: unknown pid, exe not allowlisted, no session-start, malformed session', { skip: LINUX_ONLY }, async (t) => {
  const f = await fixture(t);
  await f.install('delta', await writeSkill(f.work, 'delta'));
  assert.equal((await decide(f.svc, 'session-start', 'pid:1073741824')).code, 'no-session-record');
  assert.equal((await decide(f.svc, 'session-start', 'sess-1')).code, 'no-session-record');
  assert.equal((await decide(f.svc, 'skill-invoke', HOST, 'delta')).code, 'no-session-record');
  const other = await fixture(t, { hostExes: ['/usr/bin/not-node'] });
  assert.equal((await decide(other.svc, 'session-start', HOST)).code, 'no-session-record');
});

test('trust not ready: no state yet, and stores that cannot open', { skip: LINUX_ONLY }, async (t) => {
  const f = await fixture(t, {}, false);
  assert.equal((await decide(f.svc, 'session-start', HOST)).kind, 'ack');
  assert.equal((await decide(f.svc, 'skill-invoke', HOST, 'x')).code, 'trust-unavailable');
  const base = await scratch(t);
  await writeFile(path.join(base, 'state'), 'a file, not a directory');
  const org = await setupOrg(t, { now: new Date() });
  const broken = createGateService({
    stateDir: path.join(base, 'state'), generationsDir: path.join(base, 'gens'), managedDir: path.join(base, 'managed'), decisionSocketDir: path.join(base, 'dec'),
    adminSocketDir: path.join(base, 'adm'), rootFingerprint: org.rootKeyId, mode: 'shadow', hostExes: [NODE], rootUid: process.getuid!(),
  });
  await broken.start();
  t.after(() => broken.stop());
  for (const ev of ['session-start', 'skill-invoke']) {
    const r = await decide(broken, ev, HOST, ev === 'session-start' ? undefined : 'x');
    assert.deepEqual([r.code, r.mode], ['trust-unavailable', 'shadow']);
  }
});

test('socket protocol: malformed, oversized, two requests, slow client, connection cap with eviction', { skip: LINUX_ONLY }, async (t) => {
  const f = await fixture(t, { deadlineMs: 300, maxConnections: 2 });
  const sock = f.svc.sockets.decision;
  assert.equal(await talk(sock, '{"v":1,\n'), '');
  assert.equal(await talk(sock, `${req('session-start', HOST).replace('"v":1', '"v":1,"v":1')}\n`), ''); // duplicate member
  assert.equal(await talk(sock, Buffer.alloc(70_000, 0x61)), '');
  const two = await talk(sock, `${req('session-start', HOST)}\n${req('session-start', HOST)}\n`);
  assert.equal(two.trim().split('\n').length, 1);
  const t0 = Date.now();
  assert.equal(await talk(sock, '{"v":1'), '');
  assert.ok(Date.now() - t0 < 3000);
  const idle = [net.connect(sock), net.connect(sock)];
  idle.forEach((c) => c.on('error', () => {}));
  const closed = idle.map((c) => new Promise((r) => c.once('close', r)));
  await sleep(50);
  assert.equal(JSON.parse(await talk(sock, `${req('session-start', HOST)}\n`)).kind, 'ack'); // at the cap: the oldest idle connection is evicted
  await Promise.race([closed[0], sleep(1000).then(() => assert.fail('oldest idle connection was not evicted'))]);
  assert.equal(idle[1]!.destroyed, false);
  idle.forEach((c) => c.destroy());
});

test('admin socket: unknown and malformed commands are rejected; status works', { skip: LINUX_ONLY }, async (t) => {
  const f = await fixture(t);
  const ask = async (o: unknown) => JSON.parse(await talk(f.svc.sockets.admin, `${JSON.stringify(o)}\n`)) as { ok: boolean; error?: string; ready?: boolean; trust?: string };
  assert.equal((await ask({ v: 1, cmd: 'shell', x: 1 })).ok, false);
  assert.equal((await ask({ v: 1, cmd: 'uninstall' })).ok, false);
  assert.equal((await ask({ v: 1, cmd: 'uninstall', skill_name: 'a', extra: 1 })).ok, false);
  assert.equal((await ask({ v: 1, cmd: 'install', skill_name: 'a', source_dir: 'relative', certificate_b64: 'AAAA' })).ok, false);
  assert.equal((await ask({ v: 1, cmd: 'install', skill_name: 'a', source_dir: '/x', certificate_b64: 'not base64!' })).ok, false);
  const status = await ask({ v: 1, cmd: 'status' });
  assert.deepEqual([status.ok, status.ready, status.trust], [true, true, 'ready']);
  // install over the admin socket end to end
  const dir = await writeSkill(f.work, 'eps');
  const issued = await approve(f.org, dir, { now: new Date(), out: path.join(f.work, 'eps-cert.json') });
  const r = await ask({ v: 1, cmd: 'install', skill_name: 'eps', source_dir: dir, certificate_b64: (await readFile(issued.path)).toString('base64') });
  assert.equal(r.ok, true);
  await decide(f.svc, 'session-start', HOST);
  assert.equal((await decide(f.svc, 'skill-invoke', HOST, 'eps')).verdict, 'VERIFIED');
});

test('install refuses a wrong-name or unapproved Skill and an unready trust store', { skip: LINUX_ONLY }, async (t) => {
  const f = await fixture(t);
  const dir = await writeSkill(f.work, 'zeta');
  const issued = await approve(f.org, dir, { now: new Date(), out: path.join(f.work, 'z.json') });
  const cert = (await readFile(issued.path)).toString('base64');
  assert.equal((await f.svc.handleAdmin({ v: 1, cmd: 'install', skill_name: 'other', source_dir: dir, certificate_b64: cert })).ok, false);
  await mkdir(path.join(dir, 'sub'));
  await writeFile(path.join(dir, 'sub', 'changed.md'), 'x'); // bytes no longer match the certificate
  assert.equal((await f.svc.handleAdmin({ v: 1, cmd: 'install', skill_name: 'zeta', source_dir: dir, certificate_b64: cert })).ok, false);
  const bare = await fixture(t, {}, false);
  assert.equal((await bare.svc.handleAdmin({ v: 1, cmd: 'install', skill_name: 'zeta', source_dir: dir, certificate_b64: cert })).ok, false);
});

test('a thread id is not a host process (Tgid check)', { skip: LINUX_ONLY }, async (t) => {
  const f = await fixture(t);
  const w = new Worker(`const { parentPort } = require('node:worker_threads'); parentPort.postMessage(require('node:fs').readlinkSync('/proc/thread-self')); setInterval(() => {}, 1000);`, { eval: true });
  t.after(() => w.terminate());
  const link = await new Promise<string>((resolve) => w.once('message', resolve)); // "<pid>/task/<tid>"
  const tid = Number(link.split('/').pop());
  assert.notEqual(tid, process.pid);
  await assert.rejects(processInfo(tid), /thread/u);
  await processInfo(process.pid); // the leader itself is fine
  assert.equal((await decide(f.svc, 'session-start', `pid:${tid}`)).code, 'no-session-record');
  assert.equal((await decide(f.svc, 'session-start', HOST)).kind, 'ack');
});

test('a replaced host binary (exe "<path> (deleted)") is accepted as the allowlisted path, only then', { skip: LINUX_ONLY }, async (t) => {
  const dir = await scratch(t);
  const copy = path.join(dir, 'host-copy');
  await copyFile(NODE, copy);
  await chmod(copy, 0o755);
  const f = await fixture(t, { hostExes: [copy] });
  const child = host(t, copy);
  await new Promise((r) => child.once('spawn', r));
  await unlink(copy);
  assert.equal(readlinkSync(`/proc/${child.pid}/exe`), `${copy} (deleted)`);
  assert.equal((await decide(f.svc, 'session-start', `pid:${child.pid}`)).kind, 'ack');
  const other = await fixture(t, { hostExes: [`${copy} (deleted)x`, '/nowhere'] });
  assert.equal((await decide(other.svc, 'session-start', `pid:${child.pid}`)).code, 'no-session-record');
});

test('dead sessions are reaped: more than 1100 short-lived hosts are all admitted', { skip: LINUX_ONLY }, async (t) => {
  const f = await fixture(t);
  let admitted = 0;
  for (let round = 0; round < 12; round++) {
    const kids = Array.from({ length: 100 }, () => spawn(NODE, ['-e', 'setInterval(()=>{},1000)'], { stdio: 'ignore' }));
    await Promise.all(kids.map((k) => new Promise((r) => k.once('spawn', r))));
    for (const k of kids) {
      const r = await decide(f.svc, 'session-start', `pid:${k.pid}`);
      assert.equal(r.kind, 'ack', JSON.stringify(r));
      admitted++;
    }
    await Promise.all(kids.map((k) => new Promise((r) => { k.once('exit', r); k.kill('SIGKILL'); })));
  }
  assert.equal(admitted, 1200);
});

test('per-uid cap on open live sessions; a dead one frees a slot', { skip: LINUX_ONLY }, async (t) => {
  const f = await fixture(t, { maxSessionsPerUid: 3 });
  const kids = [host(t), host(t), host(t), host(t)];
  await Promise.all(kids.map((k) => new Promise((r) => k.once('spawn', r))));
  for (const k of kids.slice(0, 3)) assert.equal((await decide(f.svc, 'session-start', `pid:${k.pid}`)).kind, 'ack');
  assert.equal((await decide(f.svc, 'session-start', `pid:${kids[3]!.pid}`)).code, 'internal');
  await new Promise((r) => { kids[0]!.once('exit', r); kids[0]!.kill('SIGKILL'); });
  await sleep(1100); // sweeps are rate limited to one per second
  assert.equal((await decide(f.svc, 'session-start', `pid:${kids[3]!.pid}`)).kind, 'ack');
});

test('idle decision connections close after 300 ms and do not starve a legitimate request', { skip: LINUX_ONLY }, async (t) => {
  const f = await fixture(t);
  const idle = Array.from({ length: 64 }, () => { const c = net.connect(f.svc.sockets.decision); c.on('error', () => {}); return c; });
  t.after(() => idle.forEach((c) => c.destroy()));
  await sleep(50);
  assert.equal(JSON.parse(await talk(f.svc.sockets.decision, `${req('session-start', HOST)}\n`)).kind, 'ack');
  await sleep(500);
  assert.ok(idle.every((c) => c.destroyed || c.readableEnded || !c.writable), 'idle connections were closed');
});

test('a client that half-closes right after its request still gets the reply', { skip: LINUX_ONLY }, async (t) => {
  const f = await fixture(t);
  assert.equal(JSON.parse(await talk(f.svc.sockets.decision, `${req('session-start', HOST)}\n`, { end: true })).kind, 'ack');
  assert.equal(JSON.parse(await talk(f.svc.sockets.admin, `${JSON.stringify({ v: 1, cmd: 'status' })}\n`, { end: true })).ok, true);
});

test('a reconnecting flood far above the cap does not starve legitimate requests (oldest pending is evicted)', { skip: LINUX_ONLY }, async (t) => {
  const nofile = Number((await readFile('/proc/self/limits', 'utf8')).match(/Max open files\s+(\d+)/u)?.[1] ?? 0);
  if (nofile < 4096) return t.skip(`RLIMIT_NOFILE soft limit ${nofile} is below 4096`);
  const f = await fixture(t, { maxConnections: 200 });
  assert.equal(f.svc.decisionCap, 200);
  const flood = spawn(NODE, ['-e', `
    const net = require('node:net'); const sock = process.argv[1];
    const open = () => { const c = net.connect(sock); c.on('error', () => {}); c.on('close', open); };
    for (let i = 0; i < 1500; i++) open();
    setInterval(() => {}, 1000);`, f.svc.sockets.decision], { stdio: 'ignore' });
  t.after(() => { flood.kill('SIGKILL'); });
  await sleep(500);
  let good = 0;
  for (let i = 0; i < 20; i++) {
    const out = await talk(f.svc.sockets.decision, `${req('session-start', HOST)}\n`);
    if (out && (JSON.parse(out) as { kind: string }).kind === 'ack') good++;
    await sleep(15);
  }
  assert.ok(good >= 18, `only ${good}/20 legitimate requests answered`);
});

test('a request whose processing outlasts the 300 ms idle deadline still gets its reply', { skip: LINUX_ONLY }, async (t) => {
  let slow = 0;
  const f = await fixture(t, {
    maxSessionsPerUid: 1, sweepMinIntervalMs: 0,
    processFacts: async (pid) => { if (slow) await sleep(slow); return realFacts(pid); },
  });
  assert.equal((await decide(f.svc, 'session-start', HOST)).kind, 'ack');
  slow = 600;
  const t0 = Date.now();
  const r = await decide(f.svc, 'session-start', HOST); // at the per-uid cap: the sweep is slow, then the start is refused
  assert.ok(Date.now() - t0 >= 500);
  assert.equal(r.code, 'internal');
});

test('sweep: only ENOENT/ESRCH mean dead; any other error keeps the session', { skip: LINUX_ONLY }, async (t) => {
  let err: NodeJS.ErrnoException | undefined;
  const f = await fixture(t, {
    maxSessionsPerUid: 1, sweepMinIntervalMs: 0,
    processFacts: async (pid) => { if (err) throw err; return realFacts(pid); },
  });
  assert.equal((await decide(f.svc, 'session-start', HOST)).kind, 'ack');
  for (const code of ['EACCES', 'EMFILE', 'EIO']) {
    err = Object.assign(new Error(code), { code });
    assert.equal((await decide(f.svc, 'session-start', HOST)).code, 'internal', code); // still capped: the session was kept
  }
  err = Object.assign(new Error('gone'), { code: 'ENOENT' });
  assert.equal((await decide(f.svc, 'session-start', HOST)).kind, 'ack'); // reaped, then admitted afresh
});

test('sweeps are rate limited: a burst of capped admissions triggers at most one sweep per second', { skip: LINUX_ONLY }, async (t) => {
  let calls = 0;
  const f = await fixture(t, {
    maxSessionsPerUid: 1,
    processFacts: async (pid) => { calls++; return realFacts(pid); },
  });
  assert.equal((await decide(f.svc, 'session-start', HOST)).kind, 'ack');
  await sleep(1100);
  calls = 0;
  const codes = await Promise.all(Array.from({ length: 20 }, () => decide(f.svc, 'session-start', HOST).then((r) => r.code)));
  assert.ok(codes.every((c) => c === 'internal'), codes.join());
  assert.equal(calls, 1);
});

test('the connection cap follows the file-descriptor limit; a limit that is too low refuses to start', { skip: LINUX_ONLY }, async (t) => {
  const f = await fixture(t, { nofileLimit: 1000 });
  assert.equal(f.svc.decisionCap, 740); // soft limit - 4 (admin) - 256 (margin)
  const base = await scratch(t);
  const org = await setupOrg(t, { now: new Date() });
  const low = createGateService({
    stateDir: path.join(base, 'state'), generationsDir: path.join(base, 'gens'), managedDir: path.join(base, 'managed'), decisionSocketDir: path.join(base, 'dec'),
    adminSocketDir: path.join(base, 'adm'), rootFingerprint: org.rootKeyId, mode: 'enforce', hostExes: [NODE], rootUid: process.getuid!(), nofileLimit: 275,
  });
  await assert.rejects(low.start(), /too low/u);
});

test('proc: zombie and dead states are not live (parser fixture)', () => {
  const doc = (state: string) => `Name:\tx\nState:\t${state}\nTgid:\t42\nNSpid:\t42\nUid:\t1000\t1000\t1000\t1000\n`;
  assert.equal(parseStatus(doc('S (sleeping)'), 42), 1000);
  for (const st of ['Z (zombie)', 'X (dead)']) assert.throws(() => parseStatus(doc(st), 42), NotLiveError);
});

test('proc: a real unreaped zombie child is not live', { skip: LINUX_ONLY }, async (t) => {
  // The parent blocks its event loop (Atomics.wait), so libuv cannot reap the child that exits at once.
  const parent = spawn(NODE, ['-e', `
    const c = require('node:child_process').spawn(process.execPath, ['-e', ''], { stdio: 'ignore' });
    require('node:fs').writeSync(1, c.pid + '\\n');
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 20000);`], { stdio: ['ignore', 'pipe', 'ignore'] });
  t.after(() => { parent.kill('SIGKILL'); });
  const pid = Number(await new Promise<string>((resolve) => parent.stdout!.once('data', (d: Buffer) => resolve(d.toString().trim()))));
  let state = '';
  for (let i = 0; i < 60 && !state.startsWith('Z'); i++) {
    await sleep(50);
    state = (await readFile(`/proc/${pid}/status`, 'utf8')).match(/^State:\s+(\S+)/mu)?.[1] ?? '';
  }
  assert.equal(state, 'Z', 'child did not become a zombie');
  await assert.rejects(realFacts(pid), NotLiveError);
});

test('an answered connection frees its slot even if the client never closes; a legitimate client still gets answers', { skip: LINUX_ONLY }, async (t) => {
  const f = await fixture(t, { maxConnections: 50 });
  const flood = spawn(NODE, ['-e', `
    const net = require('node:net'); const sock = process.argv[1]; let n = 0;
    const line = () => JSON.stringify({ v: 1, request_id: 'f' + (++n), event: 'session-start', session: process.argv[2] }) + '\\n';
    const open = () => { const c = net.connect({ path: sock, allowHalfOpen: true }); c.on('error', () => {}); c.on('data', () => {}); c.write(line()); }; // sends one valid request, never ends its write side, never closes
    setInterval(open, 5); // about 200 connects per second, far above the cap of 50 held for 5 s
    setInterval(() => {}, 1000);`, f.svc.sockets.decision, HOST], { stdio: 'ignore' });
  t.after(() => { flood.kill('SIGKILL'); });
  await sleep(500);
  let good = 0;
  for (let i = 0; i < 40; i++) {
    const out = await talk(f.svc.sockets.decision, `${req('session-start', HOST)}\n`);
    if (out && (JSON.parse(out) as { kind: string }).kind === 'ack') good++;
    await sleep(10);
  }
  assert.ok(good >= 36, `only ${good}/40 legitimate requests answered`);
});

test('per-uid in-flight cap: the 9th concurrent request from one uid is refused, another uid is served', { skip: LINUX_ONLY }, async (t) => {
  const other = host(t);
  await new Promise((r) => other.once('spawn', r));
  const OTHER_UID = process.getuid!() + 12345;
  let armed = false; let arrived = 0; let open!: () => void;
  const barrier = new Promise<void>((r) => { open = r; });
  const f = await fixture(t, {
    processInfo: async (pid) => {
      const info = await processInfo(pid);
      if (pid === other.pid) info.uid = OTHER_UID;
      if (armed) { if (++arrived === 21) open(); await barrier; } // all 21 requests are in flight together
      return info;
    },
  });
  await f.install('alpha', await writeSkill(f.work, 'alpha'));
  assert.equal((await decide(f.svc, 'session-start', HOST)).kind, 'ack');
  assert.equal((await decide(f.svc, 'session-start', `pid:${other.pid}`)).kind, 'ack');
  armed = true;
  const ask = (session: string) => f.svc.handleDecision({ v: 1, request_id: `q${++seq}`, event: 'skill-invoke', session, skill: 'alpha' });
  const same = Array.from({ length: 20 }, () => ask(HOST));
  const others = ask(`pid:${other.pid}`);
  const results = await Promise.all(same);
  assert.equal(results.filter((r) => r.kind === 'verdict').length, 8);
  assert.equal(results.filter((r) => r.kind === 'gate-error' && r.code === 'internal').length, 12);
  assert.equal((await others).kind, 'verdict');
  armed = false;
  assert.equal((await ask(HOST)).kind, 'verdict'); // the counter was released
});

test('verdict cache: repeated checks are served from cache for 1 s; an accepted revocation applies to the very next check', { skip: LINUX_ONLY }, async (t) => {
  const f = await fixture(t);
  const digest = await f.install('alpha', await writeSkill(f.work, 'alpha'));
  await decide(f.svc, 'session-start', HOST);
  assert.equal((await decide(f.svc, 'skill-invoke', HOST, 'alpha')).verdict, 'VERIFIED');
  const certDir = path.join(f.state, 'certs', 'alpha', digest.slice('sha256:'.length));
  for (const file of await readdir(certDir)) await unlink(path.join(certDir, file)); // only a cache can still say VERIFIED
  assert.equal((await decide(f.svc, 'skill-invoke', HOST, 'alpha')).verdict, 'VERIFIED');
  await f.revoke(digest);
  assert.equal((await decide(f.svc, 'skill-invoke', HOST, 'alpha')).verdict, 'NO_CERTIFICATE'); // recomputed (the cert is gone), not served from cache
  await sleep(1100);
  assert.equal((await decide(f.svc, 'skill-invoke', HOST, 'alpha')).verdict, 'NO_CERTIFICATE');
});

test('the decision cap is lowered to somaxconn', { skip: LINUX_ONLY }, async (t) => {
  const f = await fixture(t, { somaxconn: async () => 100 });
  assert.equal(f.svc.decisionCap, 100);
  const g = await fixture(t, { somaxconn: async () => { throw new Error('unreadable'); } });
  assert.equal(g.svc.decisionCap, 1024);
});

test('a transient error opening the admission store: not ready until it loads, then it recovers', { skip: LINUX_ONLY }, async (t) => {
  let fault: string | undefined = 'EMFILE';
  const f = await fixture(t, { admissionFault: (op) => (op === 'read' ? fault : undefined) });
  const ask = async () => JSON.parse(await talk(f.svc.sockets.admin, `${JSON.stringify({ v: 1, cmd: 'status' })}\n`)) as { ready: boolean; admission: string };
  assert.deepEqual(await ask().then((r) => [r.ready, r.admission]), [false, 'unloaded']);
  assert.equal((await decide(f.svc, 'session-start', HOST)).code, 'internal');
  fault = undefined;
  assert.deepEqual(await ask().then((r) => [r.ready, r.admission]), [true, 'ready']);
  assert.equal((await decide(f.svc, 'session-start', HOST)).kind, 'ack');
});

test('a slow sweep does not block a concurrent skill decision', { skip: LINUX_ONLY }, async (t) => {
  let slow = false;
  const f = await fixture(t, { maxSessionsPerUid: 1, sweepMinIntervalMs: 0, processFacts: async (pid) => { if (slow) await sleep(800); return realFacts(pid); } });
  await f.install('alpha', await writeSkill(f.work, 'alpha'));
  assert.equal((await decide(f.svc, 'session-start', HOST)).kind, 'ack');
  slow = true;
  const kid = host(t);
  await new Promise((r) => kid.once('spawn', r));
  const sweeping = decide(f.svc, 'session-start', `pid:${kid.pid}`); // at the cap: triggers a slow sweep
  await sleep(100);
  const t0 = Date.now();
  assert.equal((await decide(f.svc, 'skill-invoke', HOST, 'alpha')).verdict, 'VERIFIED');
  assert.ok(Date.now() - t0 < 500, 'the decision waited for the sweep');
  await sweeping;
});
