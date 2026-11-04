import assert from 'node:assert/strict';
import { spawn, type ChildProcess } from 'node:child_process';
import { chmod, mkdtemp, readdir, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { realpathSync } from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import test, { type TestContext } from 'node:test';
import { updateRevocations } from '../src/admin.ts';
import { findHostPid } from '../src/gate/adapters/host-pid.ts';
import { askService } from '../src/gate/adapters/client.ts';
import { loadConfig } from '../src/gate/adapters/claude-code.ts';
import { claudeCodeManagedSettings } from '../src/gate/adapters/claude-code-settings.ts';
import { createGateService } from '../src/gate/service.ts';
import { approve, LINUX_ONLY, setupOrg, tempDir, writeSkill } from './helpers.ts';

const UID = String(process.getuid!());
const NODE = realpathSync(process.execPath);
const ENTRY = path.resolve('tests/fixtures/claude-code-hook-test-entry.ts'); // takes the owner uid from argv (tests only)
const PROD_ENTRY = path.resolve('src/gate/adapters/claude-code-hook.ts');
const MSG_APPROVED = /not approved by your organisation \(mago-ski: (\w+)\)/u;
const MSG_UNVERIFIED = /could not verify this Skill/u;

// A fake host: an allowlisted-exe process that runs the hook entry as its child (so the parent-chain walk finds it).
const HOST_SCRIPT = `
const { spawn } = require('node:child_process');
let buf = '';
process.stdin.on('data', (d) => { buf += d; let i; while ((i = buf.indexOf('\\n')) >= 0) { const l = buf.slice(0, i); buf = buf.slice(i + 1); run(JSON.parse(l)); } });
function run({ args, stdin }) {
  const c = spawn(process.execPath, [process.argv[1], ...args], { stdio: ['pipe', 'pipe', 'pipe'] });
  let o = '', e = '';
  c.stdout.on('data', (d) => { o += d; }); c.stderr.on('data', (d) => { e += d; });
  c.on('close', (code) => console.log(JSON.stringify({ code, stdout: o, stderr: e })));
  c.stdin.on('error', () => {}); c.stdin.end(stdin);
}`;

interface Out { code: number; stdout: string; stderr: string }
function fakeHost(t: TestContext, entry = ENTRY) {
  const child: ChildProcess = spawn(NODE, ['-e', HOST_SCRIPT, entry], { stdio: ['pipe', 'pipe', 'ignore'] });
  t.after(() => { child.kill('SIGKILL'); });
  let buf = '';
  const waiting: ((o: Out) => void)[] = [];
  child.stdout!.on('data', (d) => {
    buf += d;
    let i: number;
    while ((i = buf.indexOf('\n')) >= 0) { const l = buf.slice(0, i); buf = buf.slice(i + 1); waiting.shift()!(JSON.parse(l)); }
  });
  const hook = (args: string[], stdin: string): Promise<Out> =>
    new Promise((resolve) => { waiting.push(resolve); child.stdin!.write(`${JSON.stringify({ args, stdin })}\n`); });
  return { pid: child.pid!, hook };
}

const pre = (skill: unknown, extra: object = {}) => JSON.stringify({ hook_event_name: 'PreToolUse', tool_name: 'Skill', tool_input: { skill }, session_id: 'x', cwd: '/', ...extra });
const upe = (command_name: unknown) => JSON.stringify({ hook_event_name: 'UserPromptExpansion', command_name, session_id: 'x' });
const START = JSON.stringify({ hook_event_name: 'SessionStart', source: 'startup' });

async function configFile(t: TestContext, socket: string, extra: object = {}, mode = 'enforce'): Promise<string> {
  const file = path.join(await tempDir(t), 'claude-code.json');
  await writeFile(file, JSON.stringify({ v: 1, socket, mode, host_exes: [NODE], client_deadline_ms: 500, self_deadline_ms: 2000, ...extra }), { mode: 0o600 });
  return file;
}

async function service(t: TestContext) {
  const org = await setupOrg(t, { now: new Date() });
  const dir = realpathSync(await mkdtemp(path.join(os.tmpdir(), 'mago-ski-adp-')));
  t.after(async () => {
    for (const e of await readdir(dir, { recursive: true, withFileTypes: true }).catch(() => []))
      if (e.isDirectory()) await chmod(path.join(e.parentPath, e.name), 0o755).catch(() => {});
    await rm(dir, { recursive: true, force: true });
  });
  const svc = createGateService({
    stateDir: path.join(dir, 'state'), generationsDir: path.join(dir, 'gens'),
    decisionSocketDir: path.join(dir, 'dec'), adminSocketDir: path.join(dir, 'adm'),
    rootFingerprint: org.rootKeyId, mode: 'enforce', hostExes: [NODE], rootUid: process.getuid!(),
  });
  await svc.start();
  t.after(() => svc.stop());
  const b64 = async (f: string) => (await readFile(f)).toString('base64');
  assert.equal((await svc.handleAdmin({ v: 1, cmd: 'accept-trust', trust_root_b64: await b64(org.trustRoot), revocations_b64: await b64(org.revocations) })).ok, true);
  const work = await tempDir(t);
  const install = async (name: string) => {
    const skillDir = await writeSkill(work, name);
    const issued = await approve(org, skillDir, { now: new Date(), out: path.join(work, `c-${name}.json`) });
    const r = await svc.handleAdmin({ v: 1, cmd: 'install', skill_name: name, source_dir: skillDir, certificate_b64: await b64(issued.path) });
    assert.equal(r.ok, true);
    return issued.digest;
  };
  const revoke = async (digest: string) => {
    const out = path.join(work, 'rev.json');
    await updateRevocations({ rootKeyPath: org.rootKey, revocationsPath: org.revocations, out, now: new Date(), revokeDigest: digest, reason: 'test' });
    assert.equal((await svc.handleAdmin({ v: 1, cmd: 'accept-trust', trust_root_b64: await b64(org.trustRoot), revocations_b64: await b64(out) })).ok, true);
  };
  return { svc, install, revoke };
}

/** A socket server that answers each request line with `reply(line)`; undefined = say nothing. */
async function fakeServer(t: TestContext, reply: (req: { request_id: string }) => string | undefined): Promise<string> {
  const file = path.join(await tempDir(t), 's.sock');
  const server = net.createServer((c) => {
    let buf = '';
    c.on('error', () => {});
    c.on('data', (d) => { buf += d; if (buf.includes('\n')) { const r = reply(JSON.parse(buf)); if (r !== undefined) c.write(`${r}\n`); } });
  });
  await new Promise<void>((r) => server.listen(file, r));
  t.after(() => { server.close(); });
  return file;
}

const denied = (o: Out, kind: 'PreToolUse' | 'UserPromptExpansion', msg: RegExp) => {
  assert.equal(o.code, 0);
  const j = JSON.parse(o.stdout);
  const text = kind === 'PreToolUse' ? (assert.equal(j.hookSpecificOutput.permissionDecision, 'deny'), j.hookSpecificOutput.permissionDecisionReason)
    : (assert.equal(j.decision, 'block'), j.reason);
  assert.match(text, msg);
};
const silent = (o: Out) => assert.deepEqual(o, { code: 0, stdout: '', stderr: '' });

test('claude hook: real service, allow, revoke, unapproved, both routes, session-start', { skip: LINUX_ONLY }, async (t) => {
  const { svc, install, revoke } = await service(t);
  const alpha = await install('alpha');
  const cfg = await configFile(t, svc.sockets.decision);
  const host = fakeHost(t);
  const run = (stdin: string) => host.hook([cfg, 'enforce', UID], stdin);
  silent(await run(START));
  silent(await run(pre('alpha')));
  silent(await run(pre('alpha', { transcript_path: '/x', permission_mode: 'default' })));
  silent(await run(upe('/alpha')));
  silent(await run(upe('alpha')));
  denied(await run(pre('nope')), 'PreToolUse', MSG_APPROVED);
  denied(await run(upe('/nope')), 'UserPromptExpansion', MSG_APPROVED);
  await revoke(alpha);
  denied(await run(pre('alpha')), 'PreToolUse', MSG_APPROVED);
  denied(await run(upe('/alpha')), 'UserPromptExpansion', /restart the session/u);
});

test('claude hook: unknown session is denied by the service (no session-start sent)', { skip: LINUX_ONLY }, async (t) => {
  const { svc, install } = await service(t);
  await install('alpha');
  const host = fakeHost(t);
  denied(await host.hook([await configFile(t, svc.sockets.decision), 'enforce', UID], pre('alpha')), 'PreToolUse', MSG_UNVERIFIED);
});

test('claude hook: malformed input denies in enforce, is silent in shadow', { skip: LINUX_ONLY }, async (t) => {
  const { svc } = await service(t);
  const sock = svc.sockets.decision;
  const cases: [string, string, 'PreToolUse' | 'UserPromptExpansion' | undefined][] = [
    ['unknown event', JSON.stringify({ hook_event_name: 'PostToolUse', tool_name: 'Skill' }), undefined],
    ['duplicate keys', '{"hook_event_name":"PreToolUse","tool_name":"Skill","tool_name":"Skill","tool_input":{"skill":"alpha"}}', 'PreToolUse'],
    ['duplicate keys upe', '{"hook_event_name":"UserPromptExpansion","command_name":"a","command_name":"b"}', 'UserPromptExpansion'],
    ['not json', 'nope', undefined],
    ['empty', '', undefined],
    ['wrong type', pre(42), 'PreToolUse'],
    ['missing skill', JSON.stringify({ hook_event_name: 'PreToolUse', tool_name: 'Skill', tool_input: {} }), 'PreToolUse'],
    ['other tool', JSON.stringify({ hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { skill: 'alpha' } }), 'PreToolUse'],
    ['namespaced', pre('plug:alpha'), 'PreToolUse'],
    ['traversal', upe('../alpha'), 'UserPromptExpansion'],
    ['no name', JSON.stringify({ hook_event_name: 'UserPromptExpansion' }), 'UserPromptExpansion'],
    ['oversized', pre('alpha', { pad: 'x'.repeat(300 * 1024) }), undefined],
  ];
  const host = fakeHost(t);
  const enforce = await configFile(t, sock);
  const shadow = await configFile(t, sock, {}, 'shadow');
  for (const [name, stdin, kind] of cases) {
    const o = await host.hook([enforce, 'enforce', UID], stdin);
    if (kind) denied(o, kind, MSG_UNVERIFIED);
    else { assert.equal(o.code, 2, name); assert.match(o.stderr, MSG_UNVERIFIED); assert.equal(o.stdout, ''); }
    silent(await host.hook([shadow, 'shadow', UID], stdin));
  }
});

test('claude hook: service down, hang, bad answers; each denies in enforce and is silent in shadow', async (t) => {
  const dir = await tempDir(t);
  const hang = await fakeServer(t, () => undefined);
  const garbage = await fakeServer(t, () => 'not json');
  const empty = await fakeServer(t, () => '');
  const wrongId = await fakeServer(t, () => JSON.stringify({ v: 1, request_id: 'other', kind: 'verdict', verdict: 'VERIFIED', mode: 'enforce' }));
  const ack = await fakeServer(t, (r) => JSON.stringify({ v: 1, request_id: r.request_id, kind: 'ack', mode: 'shadow' }));
  const gateErr = await fakeServer(t, (r) => JSON.stringify({ v: 1, request_id: r.request_id, kind: 'gate-error', code: 'internal', mode: 'shadow' }));
  const host = fakeHost(t);
  for (const sock of [path.join(dir, 'missing.sock'), hang, garbage, empty, wrongId, ack, gateErr]) {
    denied(await host.hook([await configFile(t, sock), 'enforce', UID], pre('alpha')), 'PreToolUse', MSG_UNVERIFIED);
    silent(await host.hook([await configFile(t, sock, {}, 'shadow'), 'shadow', UID], pre('alpha')));
  }
  // the self-deadline alone (client deadline longer) also denies, and in time
  const started = Date.now();
  denied(await host.hook([await configFile(t, hang, { client_deadline_ms: 20_000, self_deadline_ms: 400 }), 'enforce', UID], upe('/alpha')), 'UserPromptExpansion', MSG_UNVERIFIED);
  assert.ok(Date.now() - started < 3000);
});

test('claude hook: config unreadable or weaker than argv', { skip: LINUX_ONLY }, async (t) => {
  const { svc, install } = await service(t);
  await install('alpha');
  const host = fakeHost(t);
  const missing = path.join(await tempDir(t), 'none.json');
  denied(await host.hook([missing, 'enforce', UID], pre('alpha')), 'PreToolUse', MSG_UNVERIFIED);
  denied(await host.hook([missing, 'bogus', UID], pre('alpha')), 'PreToolUse', MSG_UNVERIFIED); // anything but "shadow" is enforce
  silent(await host.hook([missing, 'shadow', UID], pre('alpha')));
  const bad = path.join(await tempDir(t), 'bad.json');
  await writeFile(bad, JSON.stringify({ v: 1, socket: svc.sockets.decision, mode: 'enforce', host_exes: [NODE], extra: 1 }), { mode: 0o600 });
  denied(await host.hook([bad, 'enforce', UID], pre('alpha')), 'PreToolUse', MSG_UNVERIFIED);
  const weak = await configFile(t, path.join(await tempDir(t), 'down.sock'), {}, 'shadow');
  denied(await host.hook([weak, 'enforce', UID], pre('alpha')), 'PreToolUse', MSG_UNVERIFIED); // argv enforce beats config shadow
  await chmod(weak, 0o666);
  silent(await host.hook([weak, 'shadow', UID], pre('alpha'))); // writable config is invalid; argv shadow stays shadow
  denied(await host.hook([weak, 'enforce', UID], pre('alpha')), 'PreToolUse', MSG_UNVERIFIED);
});

test('claude hook: no allowlisted host ancestor denies', { skip: LINUX_ONLY }, async (t) => {
  const { svc } = await service(t);
  const host = fakeHost(t);
  denied(await host.hook([await configFile(t, svc.sockets.decision, { host_exes: ['/nonexistent/claude'] }), 'enforce', UID], pre('alpha')), 'PreToolUse', MSG_UNVERIFIED);
});

test('host pid discovery uses the real /proc; client reports a closed failure for a missing socket', { skip: LINUX_ONLY }, async () => {
  assert.equal(await findHostPid([NODE], process.pid), process.pid);
  await assert.rejects(findHostPid(['/nonexistent'], process.pid));
  const r = await askService('/nonexistent/s.sock', { v: 1, request_id: 'a', event: 'session-start', session: 'pid:1' }, 200);
  assert.deepEqual(r, { ok: false, failure: 'connect-failed' });
});

test('claude managed settings: shadow only hooks, enforce adds block-on-failure and the native locks', () => {
  const input = { nodePath: '/usr/bin/node', hookEntry: '/opt/mago-ski/dist/src/gate/adapters/claude-code-hook.js', configPath: '/etc/mago-ski/gate/claude-code.json', hookTimeoutSec: 5, selfDeadlineMs: 3000 };
  const shadow = claudeCodeManagedSettings({ ...input, mode: 'shadow' });
  assert.deepEqual(Object.keys(shadow), ['hooks']);
  assert.ok(!JSON.stringify(shadow).includes('onFailure'));
  const enforce = claudeCodeManagedSettings({ ...input, mode: 'enforce' }) as Record<string, any>;
  assert.deepEqual(enforce.strictKnownMarketplaces, []);
  assert.equal(enforce.disableSideloadFlags, true);
  assert.ok(enforce.strictPluginOnlyCustomization.includes('skills'));
  assert.equal(enforce.hooks.PreToolUse[0].matcher, 'Skill');
  assert.equal(enforce.hooks.PreToolUse[0].hooks[0].onFailure, 'block');
  assert.equal(enforce.hooks.UserPromptExpansion[0].hooks[0].onFailure, 'block');
  assert.equal(enforce.hooks.SessionStart[0].hooks[0].onFailure, undefined);
  assert.equal(enforce.hooks.PreToolUse[0].hooks[0].command, `/usr/bin/env -i /usr/bin/node --no-addons ${input.hookEntry} ${input.configPath} enforce`);
  assert.equal(enforce.disableBundledSkills, true);
  assert.equal(enforce.skillOverrides.design, 'off');
  assert.equal(enforce.enabledPlugins['cc-plugin-telemetry@builtin'], false);
  for (const k of ['disableBundledSkills', 'skillOverrides', 'enabledPlugins']) assert.ok(!(k in shadow), k);
  assert.throws(() => claudeCodeManagedSettings({ ...input, mode: 'enforce', nodePath: 'node' }));
  assert.throws(() => claudeCodeManagedSettings({ ...input, mode: 'enforce', envPath: 'env' }));
  assert.throws(() => claudeCodeManagedSettings({ ...input, mode: 'enforce', hookTimeoutSec: 3 })); // 3000 < 3000 + 1000
  assert.doesNotThrow(() => claudeCodeManagedSettings({ ...input, mode: 'enforce', hookTimeoutSec: 4 }));
  assert.throws(() => claudeCodeManagedSettings({ ...input, mode: 'enforce', configPath: '/etc/x y.json' }));
});

test('claude hook command: NODE_OPTIONS and NODE_PATH in the parent env cannot hijack it', async (t) => {
  const dir = await tempDir(t);
  const evil = path.join(dir, 'evil.js');
  await writeFile(evil, 'process.exit(0);');
  const settings = claudeCodeManagedSettings({ mode: 'enforce', nodePath: NODE, hookEntry: PROD_ENTRY, configPath: path.join(dir, 'missing.json'), hookTimeoutSec: 5, selfDeadlineMs: 3000 }) as any;
  const command: string = settings.hooks.PreToolUse[0].hooks[0].command;
  const child = spawn('/bin/sh', ['-c', command], { env: { ...process.env, NODE_OPTIONS: `--require=${evil}`, NODE_PATH: dir }, stdio: ['pipe', 'pipe', 'ignore'] });
  let out = '';
  child.stdout.on('data', (d) => { out += d; });
  child.stdin.end(pre('alpha'));
  await new Promise((r) => child.on('close', r));
  assert.equal(JSON.parse(out).hookSpecificOutput.permissionDecision, 'deny');
});

test('claude hook: config and socket ownership/permissions are authenticated', { skip: LINUX_ONLY }, async (t) => {
  const { svc } = await service(t);
  const host = fakeHost(t);
  const sockDir = await tempDir(t);
  const sock = path.join(sockDir, 's.sock');
  const server = net.createServer((c) => { c.on('error', () => {}); c.on('data', () => c.end()); });
  await new Promise<void>((r) => server.listen(sock, r));
  t.after(() => { server.close(); });
  const cfg = await configFile(t, sock);
  await loadConfig(cfg, process.getuid!()); // baseline valid
  await assert.rejects(loadConfig(cfg, process.getuid!() + 1), /root-owned/u); // config with the wrong owner
  await chmod(sockDir, 0o777);
  await assert.rejects(loadConfig(cfg, process.getuid!()), /socket directory/u); // group/other-writable dir
  denied(await host.hook([cfg, 'enforce', UID], pre('alpha')), 'PreToolUse', MSG_UNVERIFIED);
  silent(await host.hook([cfg, 'shadow', UID], pre('alpha')));
  await chmod(sockDir, 0o700);
  const link = path.join(await tempDir(t), 'link');
  await symlink(sockDir, link);
  await assert.rejects(loadConfig(await configFile(t, path.join(link, 's.sock')), process.getuid!()), /socket directory/u); // symlinked dir
  // wrong config owner at hook level: the config is ignored, argv decides
  denied(await host.hook([await configFile(t, svc.sockets.decision, {}, 'shadow'), 'enforce', String(process.getuid!() + 1)], pre('alpha')), 'PreToolUse', MSG_UNVERIFIED);
  silent(await host.hook([await configFile(t, svc.sockets.decision), 'shadow', String(process.getuid!() + 1)], pre('alpha')));
  // the client refuses a socket owned by another uid, and a non-socket file
  const req = { v: 1, request_id: 'a', event: 'session-start', session: 'pid:1' } as const;
  assert.deepEqual(await askService(sock, req, 300, process.getuid!() + 1), { ok: false, failure: 'connect-failed' });
  const plain = path.join(sockDir, 'plain');
  await writeFile(plain, '');
  assert.deepEqual(await askService(plain, req, 300, process.getuid!()), { ok: false, failure: 'connect-failed' });
});

test('claude hook: long prompt (70 KB) and command_args (20 KB) are not denied for size', { skip: LINUX_ONLY }, async (t) => {
  const { svc, install } = await service(t);
  await install('alpha');
  const host = fakeHost(t);
  const run = (stdin: string) => host.hook([cfgPath, 'enforce', UID], stdin);
  const cfgPath = await configFile(t, svc.sockets.decision);
  silent(await run(START));
  silent(await run(pre('alpha', { prompt: 'p'.repeat(70 * 1024) })));
  silent(await run(JSON.stringify({ hook_event_name: 'UserPromptExpansion', command_name: '/alpha', command_args: 'a'.repeat(20 * 1024), prompt: 'p'.repeat(70 * 1024) })));
});

test('claude hook: a broken stdout exits 2 with a stderr reason instead of the intended code', async (t) => {
  const cfg = await configFile(t, '/nonexistent/s.sock');
  const child = spawn(NODE, [ENTRY, cfg, 'enforce', UID], { stdio: ['pipe', 'pipe', 'pipe'] });
  child.stdout.destroy(); // the reader is gone: the write fails with EPIPE
  let err = '';
  child.stderr.on('data', (d) => { err += d; });
  child.stdin.on('error', () => {});
  child.stdin.end(pre('alpha'));
  const code = await new Promise((r) => child.on('close', r));
  assert.equal(code, 2);
  assert.match(err, /could not deliver/u);
});

test('claude hook: the production entry ignores a uid passed in argv (config and socket must be root-owned)', { skip: LINUX_ONLY }, async (t) => {
  const { svc, install } = await service(t);
  await install('alpha');
  const cfg = await configFile(t, svc.sockets.decision);
  const prod = fakeHost(t, PROD_ENTRY);
  // Same config, service and approved Skill that the test entry allows: the production entry must still deny,
  // because the files are owned by the test user, not root, and argv[2] is not read.
  silent(await prod.hook([cfg, 'enforce', UID], START)); // session start never blocks
  denied(await prod.hook([cfg, 'enforce', UID], pre('alpha')), 'PreToolUse', MSG_UNVERIFIED);
  const control = fakeHost(t);
  silent(await control.hook([cfg, 'enforce', UID], START));
  silent(await control.hook([cfg, 'enforce', UID], pre('alpha')));
});

test('claude hook: an unparseable input with a second hook_event_name falls back to exit 2', async (t) => {
  const host = fakeHost(t);
  const cfg = await configFile(t, '/nonexistent/s.sock');
  const tricky = `{"tool_input":{"a":{"hook_event_name":"UserPromptExpansion"},"x":"${'y'.repeat(130 * 1024)}"},"hook_event_name":"PreToolUse","tool_name":"Skill"}`;
  const o = await host.hook([cfg, 'enforce', UID], tricky);
  assert.equal(o.code, 2);
  assert.equal(o.stdout, '');
  // A single, unambiguous event name still gets that event's deny body.
  denied(await host.hook([cfg, 'enforce', UID], `{"hook_event_name":"PreToolUse","tool_name":"Skill","tool_input":{"skill":"a","skill":"b"}}`), 'PreToolUse', MSG_UNVERIFIED);
});
