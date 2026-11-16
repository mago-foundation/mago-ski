// Moving a gate instance to a new root (design docs/design/gate-new-root.md). The trust store lives in one folder per root,
// so a new root starts with empty memory instead of reading the old root's state as corrupt, and `gate init` refuses a
// changed root fingerprint unless --new-root is given.
import assert from 'node:assert/strict';
import { chmod, copyFile, mkdtemp, readdir, readFile, rm } from 'node:fs/promises';
import { realpathSync } from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import test, { type TestContext } from 'node:test';
import { runCli, type GateCliSeams } from '../src/cli.ts';
import { instancePaths, readInstanceConfig } from '../src/gate/instance.ts';
import { createGateService, trustStoreDir, type GateServiceConfig } from '../src/gate/service.ts';
import { applyInit, planInit, type InitOptions } from '../src/gate/setup.ts';
import { generateKeyPair } from '../src/keys.ts';
import { adoptTrustDocuments } from '../src/recovery-admin.ts';
import { approve, LINUX_ONLY, setupOrg, tempDir, writeSkill } from './helpers.ts';
import { mkdir, writeFile } from 'node:fs/promises';

const NODE = realpathSync(process.execPath);
const HOST = `pid:${process.pid}`;
const UID = process.getuid!();
const hex = (fp: string): string => fp.slice('sha256:'.length);
let seq = 0;

function talk(sock: string, data: string): Promise<string> {
  return new Promise((resolve) => {
    const c = net.connect(sock);
    let out = '';
    c.on('data', (d) => { out += d; });
    c.on('close', () => resolve(out));
    c.on('error', () => resolve(out));
    c.write(data);
  });
}
const decide = async (svc: { sockets: { decision: string } }, event: string, skill?: string) =>
  JSON.parse(await talk(svc.sockets.decision, `${JSON.stringify({ v: 1, request_id: `n${++seq}`, event, session: HOST, ...(skill ? { skill } : {}) })}\n`)) as { kind: string; verdict?: string; code?: string };

async function scratch(t: TestContext): Promise<string> {
  const dir = realpathSync(await mkdtemp(path.join(os.tmpdir(), 'mago-ski-newroot-')));
  t.after(async () => {
    for (const e of await readdir(dir, { recursive: true, withFileTypes: true }).catch(() => []))
      if (e.isDirectory()) await chmod(path.join(e.parentPath, e.name), 0o755).catch(() => {});
    await rm(dir, { recursive: true, force: true });
  });
  return dir;
}

test('trustStoreDir: one folder per root, named by the fingerprint; a malformed fingerprint is refused', () => {
  const fp = `sha256:${'0f'.repeat(32)}`;
  assert.equal(trustStoreDir('/s', fp), `/s/trust/${'0f'.repeat(32)}`);
  for (const bad of ['unused', `sha256:${'0F'.repeat(32)}`, `sha256:${'0f'.repeat(31)}`, `sha256:../${'0f'.repeat(31)}`, `${'0f'.repeat(32)}`])
    assert.throws(() => trustStoreDir('/s', bad), /root fingerprint/u);
});

test('a rotated root: the new root starts empty (not corrupt), accepts the adopted documents and serves the installed Skill; the old root\'s state is kept', { skip: LINUX_ONLY }, async (t) => {
  const org = await setupOrg(t, { now: new Date() });
  const base = await scratch(t);
  const dirs = { stateDir: path.join(base, 'state'), generationsDir: path.join(base, 'gens'), managedDir: path.join(base, 'managed'), decisionSocketDir: path.join(base, 'dec'), adminSocketDir: path.join(base, 'adm') };
  const service = (rootFingerprint: string, extra: Partial<GateServiceConfig> = {}) =>
    createGateService({ ...dirs, rootFingerprint, mode: 'enforce', hostExes: [NODE], rootUid: UID, reconcileIntervalMs: 3_600_000, ...extra });
  const b64 = async (file: string) => (await readFile(file)).toString('base64');
  const status = async (svc: ReturnType<typeof service>) => (await svc.handleAdmin({ v: 1, cmd: 'status' })) as Record<string, unknown>;
  const linked = async (name: string) => (await readdir(dirs.managedDir)).includes(name);

  // Under the old root: trust accepted, one Skill installed and served.
  const old = service(org.rootKeyId);
  await old.start();
  assert.equal((await old.handleAdmin({ v: 1, cmd: 'accept-trust', trust_root_b64: await b64(org.trustRoot), revocations_b64: await b64(org.revocations) })).ok, true);
  const work = await tempDir(t);
  const skill = await writeSkill(work, 'alpha');
  const issued = await approve(org, skill, { now: new Date(), out: path.join(work, 'alpha.cert.json') });
  assert.equal((await old.handleAdmin({ v: 1, cmd: 'install', skill_name: 'alpha', source_dir: skill, certificate_b64: await b64(issued.path) })).ok, true);
  assert.equal((await decide(old, 'session-start')).kind, 'ack');
  assert.equal((await decide(old, 'skill-invoke', 'alpha')).verdict, 'VERIFIED');
  await old.stop();

  // The rotation: a new root key re-signs the same approvers and revocations (root adopt).
  const next = await generateKeyPair(path.join(work, 'new-root.pem'), path.join(work, 'new-root.pub'));
  const trustRoot = path.join(work, 'trust-root.json');
  const revocations = path.join(work, 'revocations.json');
  await copyFile(org.trustRoot, trustRoot);
  await copyFile(org.revocations, revocations);
  await adoptTrustDocuments({ rootKeyPath: next.privatePath, fromRootKeyId: org.rootKeyId, trustRootPath: trustRoot, revocationsPath: revocations, now: new Date() });

  // The same instance, restarted with the new root: empty memory, and fail closed until the new documents arrive.
  const moved = service(next.keyId);
  await moved.start();
  assert.equal((await status(moved))['trust'], 'no-state');
  assert.equal((await status(moved))['root_fingerprint'], next.keyId);
  assert.equal((await decide(moved, 'session-start')).kind, 'ack');
  assert.equal((await decide(moved, 'skill-invoke', 'alpha')).code, 'trust-unavailable');
  // The old root's documents are refused: the new store checks signatures against the new root.
  const stale = await moved.handleAdmin({ v: 1, cmd: 'accept-trust', trust_root_b64: await b64(org.trustRoot), revocations_b64: await b64(org.revocations) });
  assert.equal(stale.ok, false);
  assert.equal((await status(moved))['trust'], 'no-state');
  // The adopted documents are accepted, and the Skill installed before the rotation verifies again: its approver is unchanged.
  const accepted = await moved.handleAdmin({ v: 1, cmd: 'accept-trust', trust_root_b64: await b64(trustRoot), revocations_b64: await b64(revocations) });
  assert.equal(accepted.ok, true, JSON.stringify(accepted));
  assert.equal((await status(moved))['trust'], 'ready');
  assert.equal((await decide(moved, 'skill-invoke', 'alpha')).verdict, 'VERIFIED');
  assert.equal(await linked('alpha'), true);
  await moved.stop();

  // Both roots have their own folder, and the old root's state was neither read as corrupt nor changed.
  assert.deepEqual((await readdir(path.join(dirs.stateDir, 'trust'))).sort(), [hex(org.rootKeyId), hex(next.keyId)].sort());
  const back = service(org.rootKeyId);
  await back.start();
  t.after(() => back.stop());
  assert.equal((await status(back))['trust'], 'ready');
});

test('enforce mode: after the move, reconcile hides installed Skills until the new root\'s documents are accepted, then restores them', { skip: LINUX_ONLY }, async (t) => {
  const org = await setupOrg(t, { now: new Date() });
  const base = await scratch(t);
  const dirs = { stateDir: path.join(base, 'state'), generationsDir: path.join(base, 'gens'), managedDir: path.join(base, 'managed'), decisionSocketDir: path.join(base, 'dec'), adminSocketDir: path.join(base, 'adm') };
  const b64 = async (file: string) => (await readFile(file)).toString('base64');
  const linked = async () => (await readdir(dirs.managedDir)).includes('alpha');
  const old = createGateService({ ...dirs, rootFingerprint: org.rootKeyId, mode: 'enforce', hostExes: [NODE], rootUid: UID, reconcileIntervalMs: 3_600_000 });
  await old.start();
  assert.equal((await old.handleAdmin({ v: 1, cmd: 'accept-trust', trust_root_b64: await b64(org.trustRoot), revocations_b64: await b64(org.revocations) })).ok, true);
  const work = await tempDir(t);
  const skill = await writeSkill(work, 'alpha');
  const issued = await approve(org, skill, { now: new Date(), out: path.join(work, 'alpha.cert.json') });
  assert.equal((await old.handleAdmin({ v: 1, cmd: 'install', skill_name: 'alpha', source_dir: skill, certificate_b64: await b64(issued.path) })).ok, true);
  assert.equal(await linked(), true);
  await old.stop();

  const next = await generateKeyPair(path.join(work, 'new-root.pem'), path.join(work, 'new-root.pub'));
  const trustRoot = path.join(work, 'trust-root.json');
  const revocations = path.join(work, 'revocations.json');
  await copyFile(org.trustRoot, trustRoot);
  await copyFile(org.revocations, revocations);
  await adoptTrustDocuments({ rootKeyPath: next.privatePath, fromRootKeyId: org.rootKeyId, trustRootPath: trustRoot, revocationsPath: revocations, now: new Date() });

  const moved = createGateService({ ...dirs, rootFingerprint: next.keyId, mode: 'enforce', hostExes: [NODE], rootUid: UID, reconcileIntervalMs: 40 });
  await moved.start();
  t.after(() => moved.stop());
  const until = async (want: boolean) => { for (let i = 0; i < 100 && (await linked()) !== want; i++) await new Promise((r) => setTimeout(r, 30)); return linked(); };
  assert.equal(await until(false), false); // hidden: nothing can be verified under the new root yet
  assert.equal((await moved.handleAdmin({ v: 1, cmd: 'accept-trust', trust_root_b64: await b64(trustRoot), revocations_b64: await b64(revocations) })).ok, true);
  assert.equal(await until(true), true); // restored without a re-install
});

/* ------------------------------------------------------------------------------------------------ gate init */

const FP_A = `sha256:${'ab'.repeat(32)}`;
const FP_B = `sha256:${'cd'.repeat(32)}`;

async function world(t: TestContext) {
  const base = await tempDir(t, 'mago-ski-gate-');
  const installRoot = path.join(base, 'usr/lib/node_modules/@mago-foundation/mago-ski');
  const adapters = path.join(installRoot, 'dist', 'src', 'gate', 'adapters');
  await mkdir(adapters, { recursive: true });
  for (const f of ['claude-code-hook.js', 'codex-hook.js']) await writeFile(path.join(adapters, f), '// hook\n');
  await writeFile(path.join(installRoot, 'dist', 'src', 'cli.js'), '// cli\n');
  await writeFile(path.join(installRoot, 'package.json'), '{}\n');
  const bin = path.join(base, 'usr', 'bin');
  await mkdir(bin, { recursive: true });
  const exe = path.join(bin, 'claude');
  await writeFile(exe, Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0, 0, 0, 0]));
  await writeFile(path.join(bin, 'node'), '');
  const seams: GateCliSeams = { base, rootUid: UID, uid: UID, installRoot, nodePath: path.join(bin, 'node'), envPath: path.join(bin, 'env'), checkExec: false, platform: 'linux' };
  const opts = (rootFingerprint: string, extra: Partial<InitOptions> = {}): InitOptions =>
    ({ host: 'claude-code', rootFingerprint, hostExes: [exe], base, rootUid: UID, platform: 'linux', installRoot, nodePath: seams.nodePath!, envPath: seams.envPath!, checkExec: false, ...extra });
  return { base, exe, seams, opts };
}

async function capture(fn: () => Promise<number>): Promise<{ result: number; stdout: string; stderr: string }> {
  const out: string[] = [];
  const err: string[] = [];
  const o = process.stdout.write.bind(process.stdout);
  const e = process.stderr.write.bind(process.stderr);
  process.stdout.write = ((s: string | Uint8Array) => { out.push(String(s)); return true; }) as typeof process.stdout.write;
  process.stderr.write = ((s: string | Uint8Array) => { err.push(String(s)); return true; }) as typeof process.stderr.write;
  try { return { result: await fn(), stdout: out.join(''), stderr: err.join('') }; } finally { process.stdout.write = o; process.stderr.write = e; }
}

test('planInit: a changed root fingerprint is a problem without --new-root and a root change with it; --new-root alone is refused', async (t) => {
  const w = await world(t);
  // No instance yet: --new-root has nothing to move.
  const early = await planInit(w.opts(FP_A, { newRoot: true }));
  assert.match(early.problems.join('\n'), /--new-root was given, but no claude-code gate is set up/u);
  await applyInit(await planInit(w.opts(FP_A)), { base: w.base, rootUid: UID });
  const instance = instancePaths('claude-code', w.base).instance;

  // The same root again: an ordinary re-run; --new-root is refused.
  const same = await planInit(w.opts(FP_A));
  assert.deepEqual([same.problems, same.rootChange], [[], undefined]);
  assert.match((await planInit(w.opts(FP_A, { newRoot: true }))).problems.join('\n'), /already uses root sha256:abab/u);

  // A different root without the flag: refused, nothing written, the installed root stays.
  const silent = await planInit(w.opts(FP_B));
  assert.match(silent.problems.join('\n'), /this gate is set up for root sha256:abab.*not sha256:cdcd.*--new-root/u);
  assert.equal(silent.rootChange, undefined);
  await assert.rejects(applyInit(silent, { base: w.base, rootUid: UID }), /--new-root/u);
  assert.equal((await readInstanceConfig(instance, UID)).root_fingerprint, FP_A);

  // With the flag: planned as a root change, written, and the next step names the new root's documents.
  const move = await planInit(w.opts(FP_B, { newRoot: true }));
  assert.deepEqual([move.problems, move.rootChange], [[], { from: FP_A, to: FP_B }]);
  assert.match(move.next.join('\n'), /gate trust .*documents signed by the new root/u);
  await applyInit(move, { base: w.base, rootUid: UID });
  assert.equal((await readInstanceConfig(instance, UID)).root_fingerprint, FP_B);
  // The move is done: a further run with the new root is an ordinary re-run.
  assert.deepEqual((await planInit(w.opts(FP_B))).problems, []);
});

test('gate init --new-root through the CLI: refusal text, --print note, the summary line, and the flag is init-only', async (t) => {
  const w = await world(t);
  const run = (argv: string[]) => capture(() => runCli(argv, new Date(), w.seams));
  const init = (fp: string, ...more: string[]) => ['gate', 'init', '--host', 'claude-code', '--root-fingerprint', fp, '--host-exe', w.exe, ...more];
  assert.equal((await run(init(FP_A))).result, 0);
  await assert.rejects(run(init(FP_B)), /this gate is set up for root sha256:abab.*pass --new-root/u);
  const printed = await run(init(FP_B, '--new-root', '--print'));
  assert.equal(printed.result, 0);
  assert.match(printed.stderr, /init would move this gate from root sha256:abab[0-9a-f]* to sha256:cdcd/u);
  const refusedPrint = await run(init(FP_B, '--print'));
  assert.equal(refusedPrint.result, 1);
  assert.match(refusedPrint.stderr, /warning: this gate is set up for root/u);
  const moved = await run(init(FP_B, '--new-root', '--mode', 'enforce'));
  assert.equal(moved.result, 0);
  assert.match(moved.stdout, /root: moved from sha256:abab[0-9a-f]* to sha256:cdcd[0-9a-f]*\. The old root's stored documents are kept and no longer used\..*until then every Skill is blocked/u);
  assert.match(moved.stdout, /systemctl restart mago-ski-gate@claude-code/u);
  const json = await run(init(FP_A, '--new-root', '--json'));
  assert.deepEqual((JSON.parse(json.stdout) as { root_change: unknown }).root_change, { from: FP_B, to: FP_A });
  await assert.rejects(run(['gate', 'status', '--host', 'claude-code', '--new-root']), /--new-root/u);
});
