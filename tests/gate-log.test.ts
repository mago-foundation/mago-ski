import assert from 'node:assert/strict';
import { chmod, mkdir, mkdtemp, readdir, readFile, rm, stat, symlink, truncate, writeFile } from 'node:fs/promises';
import { realpathSync } from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import test, { type TestContext } from 'node:test';
import { openDecisionLog, type LogInput } from '../src/gate/decision-log.ts';
import { processInfo } from '../src/gate/proc.ts';
import { createGateService, type GateServiceConfig } from '../src/gate/service.ts';
import { approve, LINUX_ONLY, setupOrg, tempDir, writeSkill } from './helpers.ts';

const NODE = realpathSync(process.execPath);
const HOST = `pid:${process.pid}`;
const uid = process.getuid!();
let seq = 0;
const FIELDS = ['seq', 'boot_ms', 'at', 'mode', 'action', 'event', 'session', 'skill', 'digests', 'trust_root_version', 'revocations_version', 'result', 'build', 'elapsed_ms', 'prev', 'chain_break', 'supersedes'].sort();

async function dir(t: TestContext): Promise<string> {
  const d = realpathSync(await mkdtemp(path.join(os.tmpdir(), 'mago-ski-log-')));
  t.after(async () => { // generations are read-only by design
    for (const e of await readdir(d, { recursive: true, withFileTypes: true }).catch(() => []))
      if (e.isDirectory()) await chmod(path.join(e.parentPath, e.name), 0o755).catch(() => {});
    await rm(d, { recursive: true, force: true });
  });
  return d;
}
const input = (n = 0, over: Partial<LogInput> = {}): LogInput => ({
  bootMs: 1000 + n, mode: 'enforce', action: 'allow', event: 'skill-invoke', session: 'abcd', skill: 'alpha', digests: [`sha256:${'a'.repeat(64)}`],
  trustRootVersion: 1, revocationsVersion: 1, result: 'VERIFIED', build: 'test/1', elapsedMs: 1, ...over,
});
const segs = async (d: string) => (await readdir(d)).filter((n) => n.startsWith('segment-')).sort();
const lines = async (d: string, f: string) => (await readFile(path.join(d, f), 'utf8')).split('\n').filter(Boolean);
const all = async (d: string) => { const out: Record<string, unknown>[] = []; for (const f of await segs(d)) for (const l of await lines(d, f)) out.push(JSON.parse(l)); return out; };

test('log: chain, exact key set, no extras, fresh sequence', async (t) => {
  const d = await dir(t);
  const log = await openDecisionLog(d, { rootUid: uid });
  await log.append({ ...input(0), path: '/etc/passwd', prompt: 'secret' } as LogInput, true);
  await log.append(input(1), false);
  const recs = await all(d);
  assert.deepEqual(Object.keys(recs[0]!).sort(), FIELDS);
  assert.doesNotMatch(JSON.stringify(recs), /passwd|secret/u);
  assert.deepEqual([recs[0]!['seq'], recs[1]!['seq'], recs[0]!['prev']], [1, 2, null]);
  assert.match(String(recs[1]!['prev']), /^[0-9a-f]{64}$/u);
  assert.equal((await stat(d)).mode & 0o777, 0o700);
  assert.equal((await stat(path.join(d, (await segs(d))[0]!))).mode & 0o777, 0o600);
});

test('log: restart continues the chain and sequence; clean close writes a checkpoint', async (t) => {
  const d = await dir(t);
  const a = await openDecisionLog(d, { rootUid: uid });
  await a.append(input(0), true); await a.append(input(1), true); await a.close();
  const b = await openDecisionLog(d, { rootUid: uid });
  assert.deepEqual(b.status(), { segment: 'segment-0000000001.jsonl', lastSeq: 2, chainBreaks: 0 });
  await b.append(input(2), true);
  const recs = await all(d);
  assert.deepEqual(recs.map((r) => r['seq']), [1, 2, 3]);
  assert.equal(recs[2]!['chain_break'], null);
  assert.equal(JSON.parse(await readFile(path.join(d, 'checkpoint.json'), 'utf8')).seq, 2);
});

async function seeded(t: TestContext, n = 4) {
  const d = await dir(t);
  const log = await openDecisionLog(d, { rootUid: uid });
  for (let i = 0; i < n; i++) await log.append(input(i), true);
  await log.close();
  return d;
}
async function breaksAfter(d: string, expectedSeq: number) {
  const log = await openDecisionLog(d, { rootUid: uid });
  assert.equal(log.status().chainBreaks, 1);
  await log.append(input(9), true);
  const files = await segs(d);
  assert.equal(files.length, 2);
  const first = JSON.parse((await lines(d, files[1]!))[0]!);
  assert.equal(first.prev, null);
  assert.equal(first.chain_break, files[0]);
  assert.equal(first.seq, expectedSeq); // strictly increasing across the break
}

test('log: an edited line is a break', async (t) => {
  const d = await seeded(t);
  const f = path.join(d, 'segment-0000000001.jsonl');
  const ls = await lines(d, 'segment-0000000001.jsonl');
  ls[1] = ls[1]!.replace('"skill":"alpha"', '"skill":"omega"');
  await writeFile(f, `${ls.join('\n')}\n`);
  await breaksAfter(d, 5); // checkpoint (seq 4) is ahead of the valid prefix (2), so the sequence continues from the checkpoint
});

test('log: a deleted line is a break', async (t) => {
  const d = await seeded(t);
  const f = path.join(d, 'segment-0000000001.jsonl');
  const ls = await lines(d, 'segment-0000000001.jsonl');
  ls.splice(1, 1);
  await writeFile(f, `${ls.join('\n')}\n`);
  await breaksAfter(d, 5);
});

test('log: a truncated last line (partial write) is a break', async (t) => {
  const d = await seeded(t);
  const f = path.join(d, 'segment-0000000001.jsonl');
  await truncate(f, (await stat(f)).size - 20);
  await breaksAfter(d, 5);
});

test('log: checkpoint mismatch (tail deleted cleanly) is a break', async (t) => {
  const d = await seeded(t);
  const f = path.join(d, 'segment-0000000001.jsonl');
  const ls = await lines(d, 'segment-0000000001.jsonl');
  await writeFile(f, `${ls.slice(0, 2).join('\n')}\n`); // valid chain, but the checkpoint says seq 4
  await breaksAfter(d, 5);
});

test('log: rotation chains across files and keeps at most K segments', async (t) => {
  const d = await dir(t);
  const log = await openDecisionLog(d, { rootUid: uid, maxSegmentBytes: 5000, maxSegments: 3 });
  for (let i = 0; i < 40; i++) await log.append(input(i), false);
  const files = await segs(d);
  assert.equal(files.length, 3);
  assert.notEqual(files[0], 'segment-0000000001.jsonl');
  const recs = await all(d);
  for (let i = 1; i < recs.length; i++) assert.equal(recs[i]!['seq'], (recs[i - 1]!['seq'] as number) + 1);
  const firstOfLast = JSON.parse((await lines(d, files[2]!))[0]!);
  assert.match(firstOfLast.prev, /^[0-9a-f]{64}$/u); // chained to the previous segment, not a break
  assert.equal(firstOfLast.chain_break, null);
  await log.close();
  const again = await openDecisionLog(d, { rootUid: uid, maxSegmentBytes: 5000, maxSegments: 3 });
  assert.equal(again.status().chainBreaks, 0);
  assert.equal(again.status().lastSeq, 40);
});

test('log: refuses a symlinked, loose or foreign directory, and a symlinked or loose segment', async (t) => {
  const d = await dir(t);
  const real = path.join(d, 'real'); const link = path.join(d, 'link');
  await openDecisionLog(real, { rootUid: uid });
  await symlink(real, link);
  await assert.rejects(openDecisionLog(link, { rootUid: uid }));
  await chmod(real, 0o770);
  await assert.rejects(openDecisionLog(real, { rootUid: uid }));
  await chmod(real, 0o700);
  await assert.rejects(openDecisionLog(real, { rootUid: uid + 1 }));
  await symlink('/etc/hostname', path.join(real, 'segment-0000000007.jsonl'));
  await assert.rejects(openDecisionLog(real, { rootUid: uid }));
  await rm(path.join(real, 'segment-0000000007.jsonl'));
  await writeFile(path.join(real, 'segment-0000000007.jsonl'), '', { mode: 0o666 });
  await chmod(path.join(real, 'segment-0000000007.jsonl'), 0o666);
  await assert.rejects(openDecisionLog(real, { rootUid: uid }));
});

// ---- service level ----
async function fixture(t: TestContext, extra: Partial<GateServiceConfig> = {}) {
  const org = await setupOrg(t, { now: new Date() });
  const base = await dir(t);
  const cfg: GateServiceConfig = {
    stateDir: path.join(base, 'state'), generationsDir: path.join(base, 'gens'), managedDir: path.join(base, 'managed'), decisionSocketDir: path.join(base, 'dec'),
    adminSocketDir: path.join(base, 'adm'), rootFingerprint: org.rootKeyId, mode: 'enforce', hostExes: [NODE], rootUid: uid, buildId: 'test/9', ...extra,
  };
  const svc = createGateService(cfg);
  await svc.start();
  t.after(() => svc.stop());
  const b64 = async (f: string) => (await readFile(f)).toString('base64');
  assert.equal((await svc.handleAdmin({ v: 1, cmd: 'accept-trust', trust_root_b64: await b64(org.trustRoot), revocations_b64: await b64(org.revocations) })).ok, true);
  const work = await tempDir(t);
  const skill = await writeSkill(work, 'alpha');
  const issued = await approve(org, skill, { now: new Date(), out: path.join(work, 'cert.json') });
  const r = await svc.handleAdmin({ v: 1, cmd: 'install', skill_name: 'alpha', source_dir: skill, certificate_b64: await b64(issued.path) });
  assert.equal(r.ok, true, JSON.stringify(r));
  return { svc, cfg, log: path.join(base, 'state', 'log'), digest: issued.digest };
}
const ask = (svc: { handleDecision: Function }, event: string, skill?: string) =>
  svc.handleDecision({ v: 1, request_id: `r${++seq}`, event, session: HOST, ...(skill ? { skill } : {}) }) as Promise<{ kind: string; verdict?: string; code?: string }>;

test('service: records are minimal, carry versions and digests, and are on disk before an enforce allow is returned', { skip: LINUX_ONLY }, async (t) => {
  const f = await fixture(t, { logFault: undefined });
  assert.equal((await ask(f.svc, 'session-start')).kind, 'ack');
  const r = await ask(f.svc, 'skill-invoke', 'alpha');
  assert.equal(r.verdict, 'VERIFIED');
  const recs = await all(f.log); // already durable: read right after the answer
  assert.equal(recs.length, 2);
  for (const rec of recs) assert.deepEqual(Object.keys(rec).sort(), FIELDS);
  assert.deepEqual([recs[0]!['action'], recs[0]!['event'], recs[0]!['result']], ['ack', 'session-start', 'ack']);
  const a = recs[1]!;
  assert.deepEqual([a['action'], a['mode'], a['skill'], a['result'], a['build'], a['digests']], ['allow', 'enforce', 'alpha', 'VERIFIED', 'test/9', [f.digest]]);
  assert.equal(typeof a['trust_root_version'], 'number');
  assert.match(String(a['session']), /^[0-9a-f]{16}$/u);
  assert.equal(recs[0]!['session'], a['session']); // stable within one instance
  assert.doesNotMatch(JSON.stringify(recs), new RegExp(`${process.pid}|${os.tmpdir().replaceAll('/', '\\/')}`, 'u'));
  const st = await f.svc.handleAdmin({ v: 1, cmd: 'status' }) as { log?: { state: string; lastSeq: number; chainBreaks: number; degradedCount: number } };
  assert.deepEqual([st.log?.state, st.log?.lastSeq, st.log?.chainBreaks, st.log?.degradedCount], ['ready', 2, 0, 0]);
});

test('service: the pseudonymous session differs across instances; unusual request values are not logged', { skip: LINUX_ONLY }, async (t) => {
  const f1 = await fixture(t); const f2 = await fixture(t);
  for (const f of [f1, f2]) await ask(f.svc, 'session-start');
  const [a, b] = await Promise.all([all(f1.log), all(f2.log)]);
  assert.notEqual(a[0]!['session'], b[0]!['session']);
  const r = await f1.svc.handleDecision({ v: 1, request_id: '/etc/shadow', event: 'skill-invoke', session: HOST, skill: '/etc/../prompt text' });
  assert.equal(r.kind === 'verdict' ? r.verdict : r.kind, 'NO_CERTIFICATE');
  const recs = await all(f1.log);
  assert.equal(recs.at(-1)!['skill'], null);
  assert.doesNotMatch(JSON.stringify(recs), /shadow|prompt text|etc/u);
});

test('service: a log write failure turns an enforce allow into internal, does not block denies, degrades status', { skip: LINUX_ONLY }, async (t) => {
  let fail = false;
  const f = await fixture(t, { logFault: () => fail });
  await ask(f.svc, 'session-start');
  fail = true;
  const allow = await ask(f.svc, 'skill-invoke', 'alpha');
  assert.deepEqual([allow.kind, allow.code], ['gate-error', 'internal']);
  const deny = await ask(f.svc, 'skill-invoke', 'missing-skill'); // NO_CERTIFICATE: deny stays deny
  assert.equal(deny.verdict, 'NO_CERTIFICATE');
  const st = await f.svc.handleAdmin({ v: 1, cmd: 'status' }) as { log?: { state: string; degradedCount: number } };
  assert.deepEqual([st.log?.state, st.log?.degradedCount], ['degraded', 2]);
  fail = false;
  assert.equal((await ask(f.svc, 'skill-invoke', 'alpha')).verdict, 'VERIFIED'); // recovers
  assert.equal(((await f.svc.handleAdmin({ v: 1, cmd: 'status' })) as { log?: { state: string } }).log?.state, 'ready');
});

test('service: shadow mode never blocks on a log failure and counts it', { skip: LINUX_ONLY }, async (t) => {
  const f = await fixture(t, { mode: 'shadow', logFault: () => true });
  await ask(f.svc, 'session-start');
  assert.equal((await ask(f.svc, 'skill-invoke', 'alpha')).verdict, 'VERIFIED');
  const st = await f.svc.handleAdmin({ v: 1, cmd: 'status' }) as { log?: { state: string; degradedCount: number } };
  assert.deepEqual([st.log?.state, st.log?.degradedCount], ['degraded', 2]);
});

test('service: sequence continues across a restart; a loose log directory degrades and an enforce allow is denied', { skip: LINUX_ONLY }, async (t) => {
  const f = await fixture(t);
  await ask(f.svc, 'session-start'); await ask(f.svc, 'skill-invoke', 'alpha');
  await f.svc.stop(); // clean shutdown: checkpoint written
  const second = createGateService({ ...f.cfg, decisionSocketDir: `${f.cfg.decisionSocketDir}2`, adminSocketDir: `${f.cfg.adminSocketDir}2` });
  await second.start();
  assert.equal(((await second.handleAdmin({ v: 1, cmd: 'status' })) as { log?: { lastSeq: number; chainBreaks: number } }).log?.lastSeq, 2);
  await ask(second, 'session-start');
  await second.stop();
  assert.deepEqual((await all(f.log)).map((r) => r['seq']), [1, 2, 3]);
  await chmod(f.log, 0o770);
  const third = createGateService({ ...f.cfg, decisionSocketDir: `${f.cfg.decisionSocketDir}3`, adminSocketDir: `${f.cfg.adminSocketDir}3` });
  await third.start(); t.after(() => third.stop());
  assert.equal((await ask(third, 'session-start')).kind, 'ack'); // best-effort
  assert.equal((await ask(third, 'skill-invoke', 'alpha')).code, 'internal'); // enforce allow needs its record
  assert.equal(((await third.handleAdmin({ v: 1, cmd: 'status' })) as { log?: { state: string } }).log?.state, 'degraded');
});

test('log: a failed fsync is followed by a correction record that supersedes the allow', async (t) => {
  const d = await dir(t);
  let bad = false;
  const log = await openDecisionLog(d, { rootUid: uid, syncFault: () => bad });
  await log.append(input(0), true);
  bad = true;
  await assert.rejects(log.append(input(1), true));
  bad = false;
  await log.append(input(2, { action: 'observe' }), false);
  const recs = await all(d);
  assert.deepEqual(recs.map((r) => [r['seq'], r['action'], r['result'], r['supersedes']]),
    [[1, 'allow', 'VERIFIED', null], [2, 'allow', 'VERIFIED', null], [3, 'deny', 'internal', 2], [4, 'observe', 'VERIFIED', null]]);
});

test('log: recovery is rate-limited to one attempt per second and refuses a loose directory', async (t) => {
  const d = await dir(t);
  const log = await openDecisionLog(d, { rootUid: uid, syncFault: () => true });
  await assert.rejects(log.append(input(0), true)); // dirty
  await chmod(d, 0o755);
  await assert.rejects(log.append(input(1), false)); // recovery attempt: unsafe directory
  await chmod(d, 0o700);
  await assert.rejects(log.append(input(2), false), /rate-limited/u); // fixed, but inside the same second
  await new Promise((r) => setTimeout(r, 1100));
  await log.append(input(3), false);
  assert.equal(log.status().chainBreaks, 0);
});

test('service: a deleted and recreated log directory starts a new segment with chain_break; a loose one is refused', { skip: LINUX_ONLY }, async (t) => {
  const f = await fixture(t);
  await ask(f.svc, 'session-start');
  assert.equal((await ask(f.svc, 'skill-invoke', 'alpha')).verdict, 'VERIFIED');
  await rm(f.log, { recursive: true });
  await mkdir(f.log, { mode: 0o700 });
  assert.equal((await ask(f.svc, 'skill-invoke', 'alpha')).verdict, 'VERIFIED');
  const recs = await all(f.log);
  assert.equal(recs.length, 1);
  assert.deepEqual([recs[0]!['chain_break'], recs[0]!['prev'], recs[0]!['action']], ['segment-0000000001.jsonl', null, 'allow']);
  assert.deepEqual(await segs(f.log), ['segment-0000000002.jsonl']);
  const st = await f.svc.handleAdmin({ v: 1, cmd: 'status' }) as { log?: { chainBreaks: number } };
  assert.equal(st.log?.chainBreaks, 1);
  await new Promise((r) => setTimeout(r, 1100)); // clear any recovery rate limit before the second case
  await rm(f.log, { recursive: true });
  await mkdir(f.log, { mode: 0o755 });
  await chmod(f.log, 0o755);
  assert.equal((await ask(f.svc, 'skill-invoke', 'alpha')).code, 'internal');
});

test('service: unattributed requests are counted, not logged, and cannot evict real records', { skip: LINUX_ONLY }, async (t) => {
  const f = await fixture(t, { logMaxSegmentBytes: 5000, logMaxSegments: 2 });
  await ask(f.svc, 'session-start');
  assert.equal((await ask(f.svc, 'skill-invoke', 'alpha')).verdict, 'VERIFIED');
  const before = await all(f.log);
  for (let i = 0; i < 1000; i++) {
    const r = await f.svc.handleDecision({ v: 1, request_id: `b${i}`, event: 'skill-invoke', session: 'pid:1', skill: 'alpha' });
    assert.equal(r.kind === 'gate-error' ? r.code : r.kind, 'no-session-record');
  }
  assert.deepEqual(await all(f.log), before);
  const st = await f.svc.handleAdmin({ v: 1, cmd: 'status' }) as { log?: { unattributed: Record<string, number>; lastSeq: number } };
  assert.deepEqual([st.log?.unattributed, st.log?.lastSeq], [{ 'no-session-record': 1000 }, 2]);
});

test('service: a flooding uid is rate-limited; refused requests are counted, not logged, and cannot evict real records', { skip: LINUX_ONLY }, async (t) => {
  const f = await fixture(t, { logMaxSegmentBytes: 64 * 1024, logMaxSegments: 2, maxRequestsPerSecPerUid: 2 }); // the flood unthrottled: ~400 KiB
  await ask(f.svc, 'session-start');
  assert.equal((await ask(f.svc, 'skill-invoke', 'alpha')).verdict, 'VERIFIED');
  let refused = 0;
  for (let i = 0; i < 1000; i++) if ((await ask(f.svc, 'skill-invoke', 'alpha')).code === 'internal') refused++;
  const recs = await all(f.log);
  assert.equal(recs[0]!['seq'], 1); // the first segment was not rotated away
  assert.ok(recs.length <= 12, `logged ${recs.length}`); // burst (6) plus refill during the loop, never the flood
  const st = await f.svc.handleAdmin({ v: 1, cmd: 'status' }) as { log?: { rateLimited: number } };
  assert.equal(st.log?.rateLimited, refused);
  assert.ok(refused >= 990);
});

test('service: a connection destroyed at its processing deadline cancels the remaining work on the real socket', { skip: LINUX_ONLY }, async (t) => {
  const f = await fixture(t, { processingMs: 100, processInfo: async (pid) => { await new Promise((r) => setTimeout(r, 300)); return processInfo(pid); } });
  const c = net.connect(f.svc.sockets.decision);
  await new Promise((r) => c.once('connect', r));
  c.write(`${JSON.stringify({ v: 1, request_id: 'gone', event: 'skill-invoke', session: HOST, skill: 'alpha' })}\n`);
  const reply = await new Promise<string>((r) => { let out = ''; c.on('data', (d) => { out += d; }); c.on('close', () => r(out)); });
  assert.equal(reply, ''); // the deadline (100 ms) destroyed it while the service was still reading /proc (300 ms)
  await new Promise((r) => setTimeout(r, 500));
  // Not cancelled, it would have gone on to the admission check and logged no-session-record.
  assert.equal((await all(f.log)).at(-1)!['result'], 'internal');
});
