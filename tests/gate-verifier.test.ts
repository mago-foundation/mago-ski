import assert from 'node:assert/strict';
import { readdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { updateRevocations } from '../src/admin.ts';
import { runVerifier, type VerifierRequest } from '../src/gate/run-verifier.ts';
import { approve, setupOrg, tempDir, writeSkill, type Org } from './helpers.ts';

const nodePath = process.execPath;
const now      = () => new Date();
const request  = (org: Org, skillDir: string, name: string): VerifierRequest =>
  ({ request_id: 'r1', skill_dir: skillDir, skill_name: name, policy_path: org.policyPath });

async function snapshot(dir: string): Promise<Record<string, string>> {
  const out: Record<string, string> = {};
  for (const entry of await readdir(dir, { recursive: true, withFileTypes: true }))
    if (entry.isFile()) {
      const file = path.join(entry.parentPath, entry.name);
      out[file] = (await readFile(file)).toString('base64');
    }
  return out;
}

test('real worker: VERIFIED, NO_CERTIFICATE, UNAPPROVED_CHANGE, REVOKED, name mismatch', async (t) => {
  const org  = await setupOrg(t, { now: now() });
  const work = await tempDir(t);
  const options = { nodePath, deadlineMs: 20_000 };

  const good = await writeSkill(work, 'good');
  const issued = await approve(org, good, { now: now() });
  const before = await snapshot(path.dirname(org.policyPath));
  const verified = await runVerifier(request(org, good, 'good'), options);
  assert.deepEqual(verified, { kind: 'verdict', verdict: 'VERIFIED', digest: issued.digest });
  assert.deepEqual(await snapshot(path.dirname(org.policyPath)), before, 'worker wrote a file');

  const bare = await writeSkill(work, 'bare');
  const noCert = await runVerifier(request(org, bare, 'bare'), options);
  assert.equal(noCert.kind === 'verdict' && noCert.verdict, 'NO_CERTIFICATE');

  const changed = await writeSkill(work, 'changed');
  await approve(org, changed, { now: now() });
  await writeFile(path.join(changed, 'extra.md'), 'new bytes');
  const unapproved = await runVerifier(request(org, changed, 'changed'), options);
  assert.equal(unapproved.kind === 'verdict' && unapproved.verdict, 'UNAPPROVED_CHANGE');

  const mismatch = await runVerifier(request(org, good, 'other'), options);
  assert.equal(mismatch.kind === 'verdict' && mismatch.verdict, 'UNVERIFIABLE');
  assert.equal((mismatch as { digest?: string }).digest, undefined);

  await updateRevocations({ rootKeyPath: org.rootKey, revocationsPath: org.revocations, now: now(), revokeDigest: issued.digest, reason: 'test' });
  const revoked = await runVerifier(request(org, good, 'good'), options);
  assert.equal(revoked.kind === 'verdict' && revoked.verdict, 'REVOKED');
});

test('real worker rejects malformed requests with a gate-error, never a verdict', async (t) => {
  const org = await setupOrg(t, { now: now() });
  const ok  = request(org, '/tmp/skill', 'good');
  const cases: Array<Record<string, unknown>> = [
    { ...ok, skill_dir: 'relative/dir' },
    { ...ok, policy_path: 'policy.json' },
    { ...ok, skill_dir: '/tmp/../etc' },
    { ...ok, skill_dir: '/tmp/a\0b' },
    { ...ok, skill_name: 'Bad Name!' },
    { ...ok, request_id: 'bad id' },
    { ...ok, extra: 1 },
  ];
  for (const bad of cases) {
    const outcome = await runVerifier(bad as unknown as VerifierRequest, { nodePath, deadlineMs: 20_000 });
    assert.deepEqual(outcome, { kind: 'gate-error', code: 'verifier-failed' }, JSON.stringify(bad));
  }
});

async function fake(t: test.TestContext, body: string): Promise<string> {
  const file = path.join(await tempDir(t), 'fake.mjs');
  await writeFile(file, body);
  return file;
}
const dummy: VerifierRequest = { request_id: 'r1', skill_dir: '/x', skill_name: 'x', policy_path: '/p' };
const run = async (t: test.TestContext, body: string, deadlineMs = 5_000) =>
  await runVerifier(dummy, { nodePath, deadlineMs, workerPathForTests: await fake(t, body) });
const D = 'sha256:' + 'a'.repeat(64);
const line = (extra = `,digest:'${D}'`) => `process.stdout.write(JSON.stringify({v:1,request_id:'r1',verdict:'VERIFIED'${extra}})+'\\n');`;

test('runner maps every child fault to a gate-error', async (t) => {
  const failed = { kind: 'gate-error', code: 'verifier-failed' };
  assert.deepEqual(await run(t, line()), { kind: 'verdict', verdict: 'VERIFIED', digest: D });
  assert.deepEqual(await run(t, `${line()} process.exit(3);`), failed);
  assert.deepEqual(await run(t, `process.stdout.write('x'.repeat(40000));setTimeout(()=>{},9999)`), failed);
  assert.deepEqual(await run(t, `${line()}${line()}`), failed);
  assert.deepEqual(await run(t, `process.stdout.write(JSON.stringify({v:1,request_id:'zz',verdict:'VERIFIED'})+'\\n');`), failed);
  assert.deepEqual(await run(t, `process.stdout.write(JSON.stringify({v:1,request_id:'r1',status:'VERIFIED'})+'\\n');`), failed);
  assert.deepEqual(await run(t, `process.stdout.write(JSON.stringify({v:1,request_id:'r1',verdict:'VERIFIED',x:1})+'\\n');`), failed);
  assert.deepEqual(await run(t, `process.stdout.write('{"v":1,"request_id":"r1","verdict":"VERIF')`), failed);
  assert.deepEqual(await run(t, ``), failed);
  assert.deepEqual(await run(t, `process.kill(process.pid, 'SIGKILL')`), failed);
  assert.deepEqual(await runVerifier(dummy, { nodePath: '/nonexistent/node', deadlineMs: 1000 }), failed);
  assert.throws(() => runVerifier(dummy, { nodePath: 'node', deadlineMs: 1000 }));
});

test('deadline kills the whole process group, including a hung grandchild', async (t) => {
  const pidFile = path.join(await tempDir(t), 'grandchild.pid');
  const body = `
    import { spawn } from 'node:child_process';
    import { writeFileSync } from 'node:fs';
    const g = spawn(process.execPath, ['-e', 'setInterval(()=>{},1000)'], { stdio: 'inherit' });
    writeFileSync(${JSON.stringify(pidFile)}, String(g.pid));
    setInterval(()=>{},1000);`;
  const started = Date.now();
  const outcome = await run(t, body, 1_500);
  assert.deepEqual(outcome, { kind: 'gate-error', code: 'verifier-timeout' });
  assert.ok(Date.now() - started < 5_000);
  const pid = Number(await readFile(pidFile, 'utf8'));
  // The runner resolves right after SIGKILL; give the kernel a moment to reap the group.
  const gone = async () => {
    for (let i = 0; i < 40; i++) {
      try { process.kill(pid, 0); } catch (error) { if ((error as NodeJS.ErrnoException).code === 'ESRCH') return true; }
      await new Promise((r) => setTimeout(r, 50));
    }
    return false;
  };
  assert.ok(await gone(), 'grandchild still alive 2 s after the deadline');
});

test('child does not inherit NODE_OPTIONS, LD_PRELOAD or any parent environment', async (t) => {
  const saved = { ...process.env };
  process.env['NODE_OPTIONS'] = '--require=/tmp/evil.js';
  process.env['LD_PRELOAD'] = '/tmp/evil.so';
  t.after(() => { process.env = saved; });
  // The fake reports its env keys through the verdict field, which the runner would reject; use a file instead.
  const out = path.join(await tempDir(t), 'env.json');
  const outcome = await run(t, `
    import { writeFileSync } from 'node:fs';
    writeFileSync(${JSON.stringify(out)}, JSON.stringify(Object.keys(process.env)));
    ${line()}`);
  assert.equal(outcome.kind, 'verdict');
  const keys = JSON.parse(await readFile(out, 'utf8')) as string[];
  assert.ok(!keys.includes('NODE_OPTIONS') && !keys.includes('LD_PRELOAD'), keys.join());
  assert.deepEqual(keys, []);
});

test('deadline resolves even when an escaped descendant holds the stdout pipe', async (t) => {
  const pidFile = path.join(await tempDir(t), 'stray.pid');
  const body = `
    import { spawn } from 'node:child_process';
    import { writeFileSync } from 'node:fs';
    const g = spawn(process.execPath, ['-e', 'setInterval(()=>{},1000)'], { detached: true, stdio: ['ignore', 'inherit', 'inherit'] });
    writeFileSync(${JSON.stringify(pidFile)}, String(g.pid));
    ${line()}`;
  t.after(async () => {
    try { process.kill(Number(await readFile(pidFile, 'utf8')), 'SIGKILL'); } catch { /* already gone */ }
  });
  const started = Date.now();
  const outcome = await run(t, body, 1_500);
  assert.deepEqual(outcome, { kind: 'gate-error', code: 'verifier-timeout' });
  assert.ok(Date.now() - started < 3_000, `took ${Date.now() - started} ms`);
});

test('a VERIFIED line without a digest is a gate-error; other verdicts may omit it', async (t) => {
  const bare = (verdict: string) => `process.stdout.write(JSON.stringify({v:1,request_id:'r1',verdict:'${verdict}'})+'\\n');`;
  assert.deepEqual(await run(t, line('')), { kind: 'gate-error', code: 'verifier-failed' });
  assert.deepEqual(await run(t, bare('REVOKED')), { kind: 'verdict', verdict: 'REVOKED' });
});
