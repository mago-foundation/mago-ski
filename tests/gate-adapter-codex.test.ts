import assert from 'node:assert/strict';
import { spawn, type ChildProcess } from 'node:child_process';
import { chmod, mkdir, mkdtemp, readdir, readFile, rm, symlink, unlink, writeFile } from 'node:fs/promises';
import { realpathSync } from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import test, { type TestContext } from 'node:test';
import { updateRevocations } from '../src/admin.ts';
import { extractMentions, readProcEnviron, runHook } from '../src/gate/adapters/codex.ts';
import { codexRequirementsToml } from '../src/gate/adapters/codex-requirements.ts';
import { createGateService } from '../src/gate/service.ts';
import { approve, LINUX_ONLY, setupOrg, tempDir, writeSkill } from './helpers.ts';

const UID = String(process.getuid!());
const NODE = realpathSync(process.execPath);
const ENTRY = path.resolve('tests/fixtures/codex-hook-test-entry.ts');
const PROD_ENTRY = path.resolve('src/gate/adapters/codex-hook.ts');
const MSG_APPROVED = /not approved by your organisation \(mago-ski: (\w+)\)/u;
const MSG_UNVERIFIED = /could not verify this Skill/u;
const MSG_MASKED = /also exists outside/u;
const MSG_NOT_ADMIN = /not one of your organisation's approved Skills/u;

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
// The host's environment is what the adapter reads (CODEX_HOME/HOME): hermetic by default (absolute, nonexistent HOME).
function fakeHost(t: TestContext, entry = ENTRY, env: Record<string, string> = {}) {
  const child: ChildProcess = spawn(NODE, ['-e', HOST_SCRIPT, entry], { stdio: ['pipe', 'pipe', 'ignore'], env: { HOME: '/nonexistent-home', ...env } });
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

async function service(t: TestContext) {
  const org = await setupOrg(t, { now: new Date() });
  const dir = realpathSync(await mkdtemp(path.join(os.tmpdir(), 'mago-ski-adp-')));
  t.after(async () => {
    for (const e of await readdir(dir, { recursive: true, withFileTypes: true }).catch(() => []))
      if (e.isDirectory()) await chmod(path.join(e.parentPath, e.name), 0o755).catch(() => {});
    await rm(dir, { recursive: true, force: true });
  });
  const svc = createGateService({
    stateDir: path.join(dir, 'state'), generationsDir: path.join(dir, 'gens'), managedDir: path.join(dir, 'managed'),
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
  return { svc, install, revoke, managed: path.join(dir, 'managed') };
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


const submit = (prompt: unknown, extra: object = {}) => JSON.stringify({ hook_event_name: 'UserPromptSubmit', prompt, cwd: '/', session_id: 'x', model: 'm', ...extra });
const bash = (command: unknown, extra: object = {}) => JSON.stringify({ hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command }, cwd: '/', session_id: 'x', ...extra });
const START = JSON.stringify({ hook_event_name: 'SessionStart', source: 'startup' });

const silent = (o: Out) => assert.deepEqual(o, { code: 0, stdout: '', stderr: '' });
const denied = (o: Out, msg: RegExp) => { assert.equal(o.code, 2); assert.equal(o.stdout, ''); assert.match(o.stderr, msg); };

interface Roots { admin: string; user: string }
async function roots(t: TestContext, adminNames: string[] = ['alpha'], userNames: string[] = ['rogue']): Promise<Roots> {
  const base = await tempDir(t);
  const admin = path.join(base, 'etc-codex-skills');
  const user = path.join(base, 'home', '.agents', 'skills');
  for (const [dir, names] of [[admin, adminNames], [user, userNames]] as const)
    for (const n of names) {
      await mkdir(path.join(dir, n), { recursive: true });
      await writeFile(path.join(dir, n, 'SKILL.md'), `---\nname: ${n}\ndescription: Test ${n}.\n---\nbody\n`);
    }
  return { admin, user };
}

async function configFile(t: TestContext, socket: string, r: Roots, extra: object = {}, mode = 'enforce'): Promise<string> {
  const file = path.join(await tempDir(t), 'codex.json');
  await writeFile(file, JSON.stringify({ v: 1, socket, mode, host_exes: [NODE], client_deadline_ms: 500, self_deadline_ms: 2000, admin_root: r.admin, skill_roots: [r.user], ...extra }), { mode: 0o600 });
  return file;
}

test('codex mention grammar follows mentions.rs', () => {
  const m = (s: string) => [...extractMentions(s)].sort();
  assert.deepEqual(m('use $alpha and $beta-2, $a_b:c.'), ['a_b:c', 'alpha', 'beta-2']);
  assert.deepEqual(m('$HOME $path $5x $ $$ cost $'), ['5x']);
  assert.deepEqual(m('[$alpha](skill://alpha) [$x](app://y) [$ok] ( /s/SKILL.md ) [$ok] (/s/rogue/SKILL.md)'), ['alpha', 'ok', 'rogue', 's']);
  assert.deepEqual(m('[$home](/x/SKILL.md)'), []);
});

test('codex hook: real service; mentions, bash, revoke', { skip: LINUX_ONLY }, async (t) => {
  const { svc, install, revoke } = await service(t);
  const alpha = await install('alpha');
  const r = await roots(t);
  const cfg = await configFile(t, svc.sockets.decision, r);
  const host = fakeHost(t);
  const run = (stdin: string) => host.hook([cfg, 'enforce', UID], stdin);
  silent(await run(START));
  denied(await run(submit('please use $alpha now')), MSG_MASKED); // a user Skill exists: bare admin names are masked
  denied(await run(submit('[$alpha](skill://alpha)')), MSG_NOT_ADMIN);
  silent(await run(submit(`[$alpha](${r.admin}/alpha/SKILL.md)`)));
  denied(await run(submit('use $rogue')), MSG_APPROVED);
  denied(await run(submit('use $ROGUE')), MSG_APPROVED); // case-insensitive file systems
  for (const p of ['echo $HOME', 'no mention at all']) silent(await run(submit(p)));
  denied(await run(bash(`cat ${r.user}/rogue/SKILL.md`)), MSG_NOT_ADMIN);
  denied(await run(bash('cat ~/.agents/skills/rogue/SKILL.md')), MSG_NOT_ADMIN);
  denied(await run(bash('ls ./.codex/skills')), MSG_NOT_ADMIN);
  silent(await run(bash(`cat ${r.admin}/alpha/SKILL.md`)));
  silent(await run(bash('ls -la && echo hi')));
  silent(await run(JSON.stringify({ hook_event_name: 'PreToolUse', tool_name: 'apply_patch', tool_input: { x: 1 } })));
  await revoke(alpha);
  denied(await run(submit(`use [$alpha](${r.admin}/alpha/SKILL.md)`)), /restart the session/u);
  denied(await run(bash(`cat ${r.admin}/alpha/SKILL.md`)), MSG_APPROVED);
  silent(await run(bash(`ls ${r.admin}`))); // no Skill named
});

test('codex hook: a repo Skill under cwd is found; a symlinked root fails closed', { skip: LINUX_ONLY }, async (t) => {
  const { svc } = await service(t);
  const r = await roots(t, ['alpha'], []);
  const repo = await tempDir(t);
  await mkdir(path.join(repo, 'sub'), { recursive: true });
  await mkdir(path.join(repo, '.codex', 'skills', 'repo-skill'), { recursive: true });
  await writeFile(path.join(repo, '.codex', 'skills', 'repo-skill', 'SKILL.md'), '---\nname: repo-skill\n---\n');
  await mkdir(path.join(repo, '.git'));
  const host = fakeHost(t);
  const cfg = await configFile(t, svc.sockets.decision, r);
  denied(await host.hook([cfg, 'enforce', UID], submit('$repo-skill', { cwd: path.join(repo, 'sub') })), MSG_UNVERIFIED); // not an admin Skill: not verifiable
  silent(await host.hook([cfg, 'enforce', UID], submit('$repo-skill')));  // other cwd: not a Skill here
  silent(await host.hook([await configFile(t, '/nonexistent/s.sock', r, {}, 'shadow'), 'shadow', UID], submit('$repo-skill', { cwd: repo })));
  const linked = await tempDir(t);
  await mkdir(path.join(linked, '.codex'));
  await symlink(path.join(repo, '.codex', 'skills'), path.join(linked, '.codex', 'skills'));
  denied(await host.hook([cfg, 'enforce', UID], submit('$whatever', { cwd: linked })), MSG_UNVERIFIED);
  silent(await host.hook([cfg, 'enforce', UID], submit('nothing', { cwd: linked }))); // no mention: roots not scanned
});

test('codex hook: service down, hang, bad answers; deny in enforce, silent in shadow; ordinary input never asks', { skip: LINUX_ONLY }, async (t) => {
  const dir = await tempDir(t);
  const r = await roots(t, ['alpha'], []);
  const hang = await fakeServer(t, () => undefined);
  const garbage = await fakeServer(t, () => 'not json');
  const empty = await fakeServer(t, () => '');
  const wrongId = await fakeServer(t, () => JSON.stringify({ v: 1, request_id: 'other', kind: 'verdict', verdict: 'VERIFIED', mode: 'enforce' }));
  const ack = await fakeServer(t, (q) => JSON.stringify({ v: 1, request_id: q.request_id, kind: 'ack', mode: 'shadow' }));
  let asked = 0;
  const counting = await fakeServer(t, () => { asked += 1; return undefined; });
  const host = fakeHost(t);
  for (const sock of [path.join(dir, 'missing.sock'), hang, garbage, empty, wrongId, ack]) {
    denied(await host.hook([await configFile(t, sock, r), 'enforce', UID], submit('$alpha')), MSG_UNVERIFIED);
    denied(await host.hook([await configFile(t, sock, r), 'enforce', UID], bash(`cat ${r.admin}/alpha/SKILL.md`)), MSG_UNVERIFIED);
    silent(await host.hook([await configFile(t, sock, r, {}, 'shadow'), 'shadow', UID], submit('$alpha')));
    silent(await host.hook([await configFile(t, sock, r, {}, 'shadow'), 'shadow', UID], bash(`cat ${r.admin}/alpha/SKILL.md`)));
    silent(await host.hook([await configFile(t, sock, r), 'enforce', UID], START)); // session start never blocks
  }
  const cfg = await configFile(t, counting, await roots(t, ['alpha'], [])); // clean machine: no user Skill
  silent(await host.hook([cfg, 'enforce', UID], bash('ls')));
  silent(await host.hook([cfg, 'enforce', UID], submit('$HOME $5 $unknown')));
  assert.equal(asked, 0);
  const started = Date.now();
  denied(await host.hook([await configFile(t, hang, r, { client_deadline_ms: 20_000, self_deadline_ms: 400 }), 'enforce', UID], submit('$alpha')), MSG_UNVERIFIED);
  assert.ok(Date.now() - started < 3000);
});

test('codex hook: malformed input denies (exit 2) in enforce, is silent in shadow', { skip: LINUX_ONLY }, async (t) => {
  const { svc } = await service(t);
  const r = await roots(t);
  const cases: [string, string][] = [
    ['unknown event', JSON.stringify({ hook_event_name: 'PostToolUse', tool_name: 'Bash' })],
    ['duplicate keys', '{"hook_event_name":"UserPromptSubmit","prompt":"a","prompt":"$alpha"}'],
    ['not json', 'nope'], ['empty', ''],
    ['prompt type', submit(7)], ['no prompt', JSON.stringify({ hook_event_name: 'UserPromptSubmit' })],
    ['bad cwd', submit('x', { cwd: 5 })],
    ['no tool', JSON.stringify({ hook_event_name: 'PreToolUse' })],
    ['no command', JSON.stringify({ hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: {} })],
    ['oversized', submit('x', { pad: 'x'.repeat(300 * 1024) })],
  ];
  const host = fakeHost(t);
  const enforce = await configFile(t, svc.sockets.decision, r);
  const shadow = await configFile(t, svc.sockets.decision, r, {}, 'shadow');
  for (const [name, stdin] of cases) {
    denied(await host.hook([enforce, 'enforce', UID], stdin), MSG_UNVERIFIED);
    silent(await host.hook([shadow, 'shadow', UID], stdin));
    void name;
  }
  denied(await host.hook([path.join(await tempDir(t), 'none.json'), 'enforce', UID], submit('hi')), MSG_UNVERIFIED);
  const bad = await configFile(t, svc.sockets.decision, r, { skill_roots: ['relative'] });
  denied(await host.hook([bad, 'enforce', UID], submit('hi')), MSG_UNVERIFIED);
});

test('codex hook: the production entry ignores a uid in argv', { skip: LINUX_ONLY || (process.getuid?.() === 0 && 'as root the test files are root-owned, which the production entry rightly accepts') }, async (t) => {
  const { svc, install } = await service(t);
  await install('alpha');
  const r = await roots(t, ['alpha'], []);
  const cfg = await configFile(t, svc.sockets.decision, r);
  const prod = fakeHost(t, PROD_ENTRY);
  silent(await prod.hook([cfg, 'enforce', UID], START));
  denied(await prod.hook([cfg, 'enforce', UID], submit('$alpha')), MSG_UNVERIFIED); // files are not root-owned
  const control = fakeHost(t);
  silent(await control.hook([cfg, 'enforce', UID], START));
  silent(await control.hook([cfg, 'enforce', UID], submit('$alpha')));
});

test('codex hook command: NODE_OPTIONS and NODE_PATH cannot turn a block into exit 0', async (t) => {
  const dir = await tempDir(t);
  const evil = path.join(dir, 'evil.js');
  await writeFile(evil, 'process.exit(0);');
  const toml = codexRequirementsToml({ mode: 'enforce', nodePath: NODE, hookEntry: PROD_ENTRY, configPath: path.join(dir, 'missing.json'), hookTimeoutSec: 5, selfDeadlineMs: 3000, userSkillRoots: [] });
  const command = /^command = "(.*)"$/mu.exec(toml)![1]!;
  const child = spawn('/bin/sh', ['-c', command], { env: { ...process.env, NODE_OPTIONS: `--require=${evil}`, NODE_PATH: dir }, stdio: ['pipe', 'ignore', 'pipe'] });
  let err = '';
  child.stderr.on('data', (d) => { err += d; });
  child.stdin.end(submit('$alpha'));
  const code = await new Promise((res) => child.on('close', res));
  assert.equal(code, 2);
  assert.match(err, MSG_UNVERIFIED);
});

test('codex requirements: shadow has only hooks; enforce has every setting; inputs are validated', () => {
  const input = { nodePath: '/usr/bin/node', hookEntry: '/opt/mago-ski/dist/src/gate/adapters/codex-hook.js', configPath: '/etc/mago-ski/gate/codex.json', hookTimeoutSec: 5, selfDeadlineMs: 3000, userSkillRoots: ['/home/a/.agents/skills', '/home/a/.codex/skills'] };
  const code = (s: string) => s.split('\n').filter((l) => !l.startsWith('#') && l !== '');
  const shadow = code(codexRequirementsToml({ ...input, mode: 'shadow' }));
  for (const banned of ['allow_managed_hooks_only', '[features]', 'allowed_sandbox_modes', 'deny_read', 'onFailure']) assert.ok(!shadow.join('\n').includes(banned), banned);
  assert.ok(shadow.includes('[hooks]') && shadow.includes('[[hooks.PreToolUse]]') && shadow.includes('matcher = "*"'));
  const cmd = 'command = "/usr/bin/env -i /usr/bin/node --no-addons /opt/mago-ski/dist/src/gate/adapters/codex-hook.js /etc/mago-ski/gate/codex.json ';
  assert.equal(shadow.filter((l) => l === `${cmd}shadow"`).length, 3);
  const enforce = code(codexRequirementsToml({ ...input, mode: 'enforce' }));
  for (const line of ['allow_managed_hooks_only = true', 'allowed_sandbox_modes = ["read-only", "workspace-write"]', '[features]', 'hooks = true', 'plugins = false',
    'remote_plugin = false', 'apps = false', 'executor_capability_discovery = false', 'executor_capability_discovery_v2 = false', '[permissions.filesystem]', 'deny_read = ["/home/a/.agents/skills/**", "/home/a/.codex/skills/**"]',
    'managed_dir = "/opt/mago-ski/dist/src/gate/adapters"', '[[hooks.SessionStart]]', '[[hooks.UserPromptSubmit]]', 'timeout = 5'])
    assert.ok(enforce.includes(line), line);
  assert.equal(enforce.filter((l) => l === `${cmd}enforce"`).length, 3);
  assert.ok(codexRequirementsToml({ ...input, mode: 'enforce' }).startsWith('# mago-ski Codex requirements'));
  assert.match(codexRequirementsToml({ ...input, mode: 'enforce' }), /repo-scope Skills cannot be hidden/u);
  for (const bad of [{ nodePath: 'node' }, { envPath: 'env' }, { configPath: '/etc/x y.toml' }, { hookEntry: '/a"b' }, { userSkillRoots: ['/home/a\nb'] },
    { userSkillRoots: ['/home/a/'] }, { userSkillRoots: ['rel'] }, { hookTimeoutSec: 3 }, { hookTimeoutSec: 0 }, { hookTimeoutSec: 601, selfDeadlineMs: 3000 }, { hookTimeoutSec: 5.5 }, { mode: 'x' }])
    assert.throws(() => codexRequirementsToml({ ...input, mode: 'enforce', ...bad } as any), Error, JSON.stringify(bad));
  assert.doesNotThrow(() => codexRequirementsToml({ ...input, mode: 'enforce', hookTimeoutSec: 4 }));
  assert.doesNotThrow(() => codexRequirementsToml({ ...input, mode: 'enforce', hookTimeoutSec: 600 }));
});

// --- Codex-shaped discovery of non-admin roots (existence only) ---------------------------------------------------------
async function sk(dir: string, content: string | Buffer, file = 'SKILL.md'): Promise<void> {
  await mkdir(dir, { recursive: true });
  await writeFile(path.join(dir, file), content);
}
const fm = (name: string) => `---\nname: ${name}\ndescription: d\n---\n`;
const blocked = (o: Out) => { assert.equal(o.code, 2); assert.notEqual(o.stderr, ''); };

// The fake service never answers, so any token that is asked of it ends as "could not verify" (exit 2).
async function adapter(t: TestContext, extra: object = {}) {
  const r = await roots(t, ['alpha'], []);
  const cfg = await configFile(t, await fakeServer(t, () => undefined), r, extra);
  const host = fakeHost(t);
  return { r, run: (stdin: string) => host.hook([cfg, 'enforce', UID], stdin) };
}

test('codex hook: any SKILL.md in a non-admin root (depth 6, through symlinks, any name) makes every token asked', { skip: LINUX_ONLY }, async (t) => {
  const places: [string, string[], boolean][] = [ // [label, path below the root, expected to be found]
    ['top', ['x'], true], ['nested', ['grp', 'deep', 'y'], true], ['depth6', ['a', 'b', 'c', 'd', 'e', 'f'], true],
    ['depth7', ['a', 'b', 'c', 'd', 'e', 'f', 'g'], false],
  ];
  for (const [label, parts, found] of places) {
    const { r, run } = await adapter(t);
    await sk(path.join(r.user, ...parts), fm('whatever'));
    const o = await run(submit('use $5'));
    if (found) blocked(o); else silent(o);
    void label;
  }
  const { r, run } = await adapter(t);
  const target = path.join(await tempDir(t), 'real-dir');
  await sk(target, fm('linked'));
  await mkdir(r.user, { recursive: true });
  await symlink(target, path.join(r.user, 'lnk'));
  await symlink(r.user, path.join(r.user, 'loop')); // a symlink loop terminates
  blocked(await run(submit('use $anything')));
  silent(await run(submit('no mention')));
  blocked(await run(submit(`[$zzz](${path.join(r.user, 'lnk', 'SKILL.md')})`))); // linked path inside a non-admin root
  });

test('codex hook: rogue Skills with exotic frontmatter or a plugin namespace are blocked without parsing names', async (t) => {
  const repoWith = async (content: string, plugin?: string) => {
    const { run } = await adapter(t);
    const repo = await tempDir(t);
    await mkdir(path.join(repo, '.git'));
    await sk(path.join(repo, '.agents', 'skills', 'd'), content);
    if (plugin) await sk(path.join(repo, plugin), '{"name":"acme"}', 'plugin.json');
    return (prompt: string) => run(submit(prompt, { cwd: repo }));
  };
  for (const plugin of ['.codex-plugin', '.claude-plugin', '.cursor-plugin']) {
    const run = await repoWith(fm('foo'), plugin);
    denied(await run('use $acme:foo'), MSG_NOT_ADMIN); // T1: namespaced token
    blocked(await run('use $foo'));
  }
  for (const content of ['---\n{name: rogue}\n---\n', '---\nname: "ro\\x67ue"\n---\n', '---\nname: &a rogue\n---\n', '---\rname: rogue\r---\r', '---\n? name\n: rogue\n---\n']) {
    const run = await repoWith(content);
    blocked(await run('use $rogue'));
  }
});

test('codex hook: an approved admin Skill still passes when rogue Skills exist; $5 prose follows the machine state', { skip: LINUX_ONLY }, async (t) => {
  const { svc, install } = await service(t);
  await install('alpha');
  const dirty = await roots(t); // has a user Skill
  const clean = await roots(t, ['alpha'], []);
  const host = fakeHost(t);
  const d = await configFile(t, svc.sockets.decision, dirty);
  const c = await configFile(t, svc.sockets.decision, clean);
  silent(await host.hook([d, 'enforce', UID], START));
  denied(await host.hook([d, 'enforce', UID], submit('use $alpha')), MSG_MASKED);
  silent(await host.hook([d, 'enforce', UID], submit(`use [$alpha](${dirty.admin}/alpha/SKILL.md)`)));
  silent(await host.hook([c, 'enforce', UID], submit('use $alpha')));
  denied(await host.hook([d, 'enforce', UID], submit('use $rogue')), MSG_APPROVED);
  silent(await host.hook([c, 'enforce', UID], submit('costs $5 and $foo')));
  denied(await host.hook([d, 'enforce', UID], submit('costs $5')), MSG_APPROVED); // documented over-blocking
  silent(await host.hook([await configFile(t, '/nonexistent/s.sock', dirty, {}, 'shadow'), 'shadow', UID], submit('costs $5')));
});

test('codex hook: dot-prefixed Skill folders count toward found in non-admin roots (F7.5); the admin root skips them', { skip: LINUX_ONLY }, async (t) => {
  const base = await tempDir(t);
  const user = path.join(base, '.codex', 'skills');
  await sk(path.join(user, '.hid', 'h'), fm('hidden-skill'));
  const r = await roots(t, ['alpha'], []);
  const host = fakeHost(t);
  const cfg = await configFile(t, await fakeServer(t, () => undefined), r, { skill_roots: [user] });
  blocked(await host.hook([cfg, 'enforce', UID], submit('$hidden-skill'))); // counted: every token is asked, nobody answers
  const clean = await configFile(t, await fakeServer(t, () => undefined), r, { skill_roots: [path.join(base, 'empty')] });
  silent(await host.hook([clean, 'enforce', UID], submit('$hidden-skill')));
  // an explicitly listed hidden root (.system) is scanned
  const system = path.join(base, 'x', '.system');
  await sk(path.join(system, 'skill-installer'), fm('skill-installer'));
  blocked(await host.hook([await configFile(t, await fakeServer(t, () => undefined), r, { skill_roots: [system] }), 'enforce', UID], submit('$skill-installer')));
  // a dot entry in the admin root (the service's own files) is never an admin Skill
  await mkdir(path.join(r.admin, '.alpha.123.tmp'), { recursive: true });
  silent(await host.hook([clean, 'enforce', UID], submit('$5')));
});

test('codex hook: unreadable entries, symlinked SKILL.md and the directory cap fail closed; mention-free prompts pass', { skip: LINUX_ONLY }, async (t) => {
  const { r, run } = await adapter(t);
  await mkdir(path.join(r.user, 'u'), { recursive: true });
  if (process.getuid!() !== 0) {
    await chmod(path.join(r.user, 'u'), 0o000);
    blocked(await run(submit('use $unrelated'))); // incomplete, no SKILL.md seen
    silent(await run(submit('use nothing, $HOME')));
    await chmod(path.join(r.user, 'u'), 0o755);
  }
  await rm(path.join(r.user, 'u'), { recursive: true, force: true });
  silent(await run(submit('use $unrelated'))); // back to a clean root
  await mkdir(path.join(r.user, 'sl'), { recursive: true });
  await symlink('/etc/hostname', path.join(r.user, 'sl', 'SKILL.md'));
  blocked(await run(submit('use $unrelated')));
  silent(await run(submit('no mention')));
  await rm(path.join(r.user, 'sl'), { recursive: true, force: true });
  for (let i = 0; i < 2001; i += 1) await mkdir(path.join(r.user, `e${i}`), { recursive: true });
  blocked(await run(submit('use $unrelated')));
});

test('codex hook: every cwd ancestor is scanned (an employee-set marker hides nothing); a file at a repo root location fails closed', { skip: LINUX_ONLY }, async (t) => {
  const { run } = await adapter(t);
  const top = await tempDir(t);
  const repo = path.join(top, 'repo');
  const sub = path.join(repo, 'a', 'b');
  await mkdir(sub, { recursive: true });
  await mkdir(path.join(repo, '.git'));
  silent(await run(submit('$above', { cwd: sub }))); // control: nothing anywhere
  await sk(path.join(top, '.agents', 'skills', 'above'), fm('above')); // above the repo root: still scanned
  blocked(await run(submit('$above', { cwd: sub })));
  await sk(path.join(repo, '.agents', 'skills', 'inrepo'), fm('inrepo'));
  blocked(await run(submit('$inrepo', { cwd: sub })));
  const evil = path.join(await tempDir(t), 'ws', 'proj', 'sub'); // employee marker `.mk` in the project, Skill two levels up
  await mkdir(evil, { recursive: true });
  await writeFile(path.join(evil, '..', '.mk'), '');
  silent(await run(submit('$evil', { cwd: evil })));
  await sk(path.join(evil, '..', '..', '.codex', 'skills', 'evil'), fm('evil'));
  blocked(await run(submit('$evil', { cwd: evil })));
  const nomark = path.join(top, 'plain', 'deeper');
  await sk(path.join(top, 'plain', '.agents', 'skills', 'parent-skill'), fm('parent-skill'));
  await mkdir(nomark, { recursive: true });
  blocked(await run(submit('$parent-skill', { cwd: nomark })));
  await rm(path.join(top, 'plain', '.agents'), { recursive: true });
  await mkdir(path.join(nomark, '.agents'));
  await writeFile(path.join(nomark, '.agents', 'skills'), 'not a directory');
  blocked(await run(submit('$x', { cwd: nomark })));
  silent(await run(submit('nothing', { cwd: nomark })));
});

test('codex hook: project_root_markers is no longer a config key (config rejected, enforce blocks)', async (t) => {
  const { r, run } = await adapter(t, { project_root_markers: ['.mk'] });
  blocked(await run(submit('use $5')));
  denied(await run(submit('use $5')), MSG_UNVERIFIED);
  void r;
});

test('codex hook: user roots follow the host environment (CODEX_HOME, HOME); bad or unreadable environment fails closed', { skip: LINUX_ONLY }, async (t) => {
  const r = await roots(t, ['alpha'], []);
  const cfg = await configFile(t, await fakeServer(t, () => undefined), r, { skill_roots: [] });
  const codexHome = await tempDir(t);
  const home = await tempDir(t);
  await sk(path.join(codexHome, 'skills', 'evil'), fm('evil'));
  await sk(path.join(home, '.agents', 'skills', 'evil2'), fm('evil2'));
  await sk(path.join(home, 'other', 'skills', 'x'), fm('x')); // not a Skill root
  const clean = await tempDir(t);
  const run = (env: Record<string, string>, prompt: string) => fakeHost(t, ENTRY, env).hook([cfg, 'enforce', UID], submit(prompt));
  silent(await run({ HOME: clean }, '$evil'));
  blocked(await run({ HOME: clean, CODEX_HOME: codexHome }, '$evil')); // not in any configured root
  blocked(await run({ HOME: home }, '$evil2'));
  silent(await run({ HOME: clean, CODEX_HOME: '' }, '$evil')); // empty = unset, as Codex
  await sk(path.join(clean, '.codex', 'skills', 'sys', 'z'), fm('z'));
  blocked(await run({ HOME: clean }, '$z'));
  blocked(await run({ HOME: 'relative' }, '$5'));
  blocked(await run({ HOME: clean, CODEX_HOME: 'relative' }, '$5'));
  // In-process: an injected reader that fails, and one that returns a clean environment.
  const fresh = await tempDir(t);
  const deps = (readHostEnv: () => Promise<{ home?: string; codexHome?: string }>) => ({
    readStdin: async () => Buffer.from(submit('$5')), findHost: async () => process.pid, rootUid: process.getuid!(), readHostEnv,
  });
  const failing = await runHook([cfg, 'enforce'], deps(async () => { throw new Error('EACCES'); }));
  assert.equal(failing.code, 2);
  assert.equal((await runHook([cfg, 'enforce'], deps(async () => ({ home: fresh })))).code, 0);
  assert.equal((await runHook([cfg, 'enforce'], deps(async () => ({})))).code, 2); // no HOME
  assert.equal((await runHook([cfg, 'enforce'], deps(async () => ({ home: clean, codexHome: codexHome })))).code, 2);
  // Codex's <codex_home>/.env can set HOME after exec (load_dotenv): a .env naming HOME, or not a plain file, fails closed.
  const dot = await tempDir(t);
  await mkdir(path.join(dot, '.codex'));
  const withEnv = deps(async () => ({ home: dot }));
  assert.equal((await runHook([cfg, 'enforce'], withEnv)).code, 0); // no .env
  await writeFile(path.join(dot, '.codex', '.env'), 'OPENAI_BASE_URL=x\n');
  assert.equal((await runHook([cfg, 'enforce'], withEnv)).code, 0); // .env without HOME
  await writeFile(path.join(dot, '.codex', '.env'), 'OPENAI_BASE_URL=x\nexport HOME=/tmp/h\n');
  assert.equal((await runHook([cfg, 'enforce'], withEnv)).code, 2);
  await rm(path.join(dot, '.codex', '.env'));
  await symlink('/dev/null', path.join(dot, '.codex', '.env'));
  assert.equal((await runHook([cfg, 'enforce'], withEnv)).code, 2);
  assert.equal((await runHook([cfg, 'enforce'], deps(async () => ({ home: fresh, codexHome: path.join(dot, '.codex') })))).code, 2); // CODEX_HOME's .env
  // CODEX_HOME is canonicalised like Codex: `link/../cx` resolves physically to base/deep/cx, not base/cx.
  const base = await tempDir(t);
  await mkdir(path.join(base, 'deep', 'a'), { recursive: true });
  await symlink(path.join(base, 'deep', 'a'), path.join(base, 'link'));
  await sk(path.join(base, 'deep', 'cx', 'skills', 'evil'), fm('evil'));
  assert.equal((await runHook([cfg, 'enforce'], deps(async () => ({ home: fresh, codexHome: `${base}/link/../cx` })))).code, 2);
  // A lossily decoded (non-UTF-8) HOME, CODEX_HOME or cwd names a path that does not exist: fail closed.
  assert.equal((await runHook([cfg, 'enforce'], deps(async () => ({ home: `${fresh}�` })))).code, 2);
  assert.equal((await runHook([cfg, 'enforce'], deps(async () => ({ home: fresh, codexHome: `${fresh}�` })))).code, 2);
  assert.equal((await runHook([cfg, 'enforce'], { ...deps(async () => ({ home: fresh })),
    readStdin: async () => Buffer.from(submit('$5', { cwd: `${fresh}/proj�` })) })).code, 2);
  // Non-UTF-8 bytes on disk: a CODEX_HOME link to a 0xFF-named dir, and a 0xFF-named Skill folder, both fail closed.
  const raw = await tempDir(t);
  const bad = Buffer.concat([Buffer.from(`${raw}/cx`), Buffer.from([0xff])]);
  await mkdir(bad);
  await mkdir(Buffer.concat([bad, Buffer.from('/skills/evil')]), { recursive: true });
  await writeFile(Buffer.concat([bad, Buffer.from('/skills/evil/SKILL.md')]), fm('evil'));
  await symlink(bad, path.join(raw, 'link'));
  assert.equal((await runHook([cfg, 'enforce'], deps(async () => ({ home: fresh, codexHome: path.join(raw, 'link') })))).code, 2);
  const h2 = await tempDir(t);
  const skills = Buffer.from(`${h2}/.agents/skills/ev`);
  await mkdir(Buffer.concat([skills, Buffer.from([0xff])]), { recursive: true });
  await writeFile(Buffer.concat([skills, Buffer.from([0xff]), Buffer.from('/SKILL.md')]), fm('evil'));
  assert.equal((await runHook([cfg, 'enforce'], deps(async () => ({ home: h2 })))).code, 2);
  // Two links to different non-UTF-8 targets (x\xff empty, x\xfe with the Skill) must not collapse into one "seen" key.
  const h3 = await tempDir(t);
  const tg = await tempDir(t);
  await mkdir(path.join(h3, '.agents', 'skills'), { recursive: true });
  const ff = Buffer.concat([Buffer.from(`${tg}/x`), Buffer.from([0xff])]);
  const fe = Buffer.concat([Buffer.from(`${tg}/x`), Buffer.from([0xfe])]);
  await mkdir(ff);
  await mkdir(Buffer.concat([fe, Buffer.from('/evil')]), { recursive: true });
  await writeFile(Buffer.concat([fe, Buffer.from('/evil/SKILL.md')]), fm('evil'));
  await symlink(ff, path.join(h3, '.agents', 'skills', 'a'));
  await symlink(fe, path.join(h3, '.agents', 'skills', 'b'));
  assert.equal((await runHook([cfg, 'enforce'], deps(async () => ({ home: h3 })))).code, 2);
  // The production reader on a real procfs entry.
  const env = await readProcEnviron(process.pid);
  assert.equal(env.home, process.env['HOME']);
});

test('codex hook: a same-name admin Skill is masked by a repo Skill; only the admin link passes', { skip: LINUX_ONLY }, async (t) => {
  const { svc, install } = await service(t);
  await install('alpha');
  const r = await roots(t, ['alpha'], []);
  const repo = await tempDir(t);
  await sk(path.join(repo, '.agents', 'skills', 'alpha'), fm('alpha'));
  const cfg = await configFile(t, svc.sockets.decision, r);
  const host = fakeHost(t);
  const run = (prompt: string) => host.hook([cfg, 'enforce', UID], submit(prompt, { cwd: repo }));
  silent(await host.hook([cfg, 'enforce', UID], START)); // the service admits the session
  denied(await run('use $alpha'), MSG_MASKED);
  denied(await run('use $ALPHA'), MSG_MASKED);
  denied(await run(`use [$alpha](skill://alpha)`), MSG_NOT_ADMIN);
  denied(await run(`use [$alpha](${r.admin}/alpha/SKILL.md) and $alpha`), MSG_MASKED); // one plain mention is enough
  denied(await run(`use [$alpha](${path.join(repo, '.agents/skills/alpha/SKILL.md')})`), MSG_NOT_ADMIN); // link into a non-admin root
  denied(await run(`use [$alpha](/nonexistent/alpha/SKILL.md)`), MSG_NOT_ADMIN);
  silent(await run(`use [$alpha](skill://${r.admin}/alpha/SKILL.md)`)); // L2: absolute skill:// link to the admin file is asked and verified
  silent(await run(`use [$alpha](${r.admin}/alpha/SKILL.md)`));
  // Review of commit 1: the link text must name the admin Skill it points at; env-var names and odd schemes are links too.
  denied(await run(`use [$rogue](${r.admin}/alpha/SKILL.md)`), MSG_NOT_ADMIN);
  denied(await run(`use [$acme:search](${r.admin}/alpha/SKILL.md)`), MSG_NOT_ADMIN);
  denied(await run(`use [$HOME](${path.join(repo, '.agents/skills/alpha/SKILL.md')})`), MSG_NOT_ADMIN);
  denied(await run('use [$rogue](Mcp://x)'), MSG_NOT_ADMIN);
  denied(await host.hook([cfg, 'enforce', UID], bash(`cat /home/u/cx/rogue${r.admin}/alpha/SKILL.md`, { cwd: repo })), MSG_NOT_ADMIN);
  denied(await host.hook([cfg, 'enforce', UID], bash(`gcc -I${r.admin}/alpha/include m.c`, { cwd: repo })), MSG_NOT_ADMIN);
  denied(await host.hook([cfg, 'enforce', UID], JSON.stringify({ hook_event_name: 'PreToolUse', tool_name: 'shell', tool_input: { command: ['cat', `${repo}/.agents/skills/alpha/SKILL.md`] }, cwd: repo, session_id: 'x' })), MSG_NOT_ADMIN);
  silent(await host.hook([cfg, 'enforce', UID], submit('use $alpha', { cwd: await tempDir(t) }))); // no non-admin Skill: bare name checked and allowed
  silent(await host.hook([await configFile(t, svc.sockets.decision, r, {}, 'shadow'), 'shadow', UID], submit('use $alpha', { cwd: repo })));
});

test('codex hook: a missing or relative cwd fails closed for mentions only', async (t) => {
  const { run } = await adapter(t);
  blocked(await run(submit('use $x', { cwd: undefined })));
  blocked(await run(submit('use $x', { cwd: 'rel/dir' })));
  silent(await run(submit('no mention', { cwd: undefined })));
});

test('codex hook: a cwd deeper than the ancestor cap with no marker fails closed (mentions only)', { skip: LINUX_ONLY }, async (t) => {
  const { run } = await adapter(t);
  const deep = path.join(await tempDir(t), ...Array.from({ length: 70 }, (_, i) => `d${i}`));
  await mkdir(deep, { recursive: true });
  blocked(await run(submit('use $x', { cwd: deep })));
  silent(await run(submit('no mention', { cwd: deep })));
  const shallow = path.join(await tempDir(t), 'a');
  await mkdir(shallow, { recursive: true });
  silent(await run(submit('use $x', { cwd: shallow }))); // reaches "/" without a marker: cwd only, complete
});

test('codex hook: a repo Skill named like a just-revoked admin Skill is not reachable', { skip: LINUX_ONLY }, async (t) => {
  const { svc, install, revoke } = await service(t);
  const alpha = await install('alpha');
  const r = await roots(t, [], []);
  const repo = await tempDir(t);
  await mkdir(path.join(repo, '.git'));
  await sk(path.join(repo, '.agents', 'skills', 'whatever'), fm('alpha'));
  const cfg = await configFile(t, svc.sockets.decision, r);
  const host = fakeHost(t);
  silent(await host.hook([cfg, 'enforce', UID], START));
  await revoke(alpha);
  denied(await host.hook([cfg, 'enforce', UID], submit('$alpha', { cwd: repo })), MSG_APPROVED);
});

test('codex hook: admin Skills the service publishes (links to generations) are checked by their linked mention', { skip: LINUX_ONLY }, async (t) => {
  const { svc, install, revoke, managed } = await service(t);
  const digest = await install('alpha');
  const r = { ...(await roots(t, [], ['rogue'])), admin: managed }; // a user Skill exists, so plain mentions are masked
  const cfg = await configFile(t, svc.sockets.decision, r);
  const host = fakeHost(t);
  silent(await host.hook([cfg, 'enforce', UID], START));
  silent(await host.hook([cfg, 'enforce', UID], submit(`use [$alpha](${managed}/alpha/SKILL.md)`)));
  denied(await host.hook([cfg, 'enforce', UID], submit('use $alpha')), MSG_MASKED);
  await revoke(digest); // enforce: the service removes the link, so the Skill is gone from the admin root
  assert.deepEqual((await readdir(managed)).filter((e) => !e.startsWith('.')), []);
  assert.ok((await readdir(managed)).includes('.mago-ski-removed-names.json')); // the service records what it removed (C3)
});

test('codex hook: commit 1 security rules hold with an empty walk (H1, H2) and for every tool with a command', async (t) => {
  const { r, run } = await adapter(t); // no non-admin Skill anywhere; the fake service never answers
  const cwd = await tempDir(t);
  denied(await run(submit('use $acme:search', { cwd })), MSG_NOT_ADMIN); // H2: plugin-namespaced token
  denied(await run(submit('[$x](skill:///some/unscanned/path/s/SKILL.md)', { cwd })), MSG_NOT_ADMIN); // H1
  denied(await run(submit(`[$alpha](skill://${r.admin}/alpha/SKILL.md)`, { cwd })), MSG_UNVERIFIED); // L2: asked (the fake service never answers)
  // T6: a trailing colon is not an admin key. Off Linux the host environment (/proc) cannot be read, so the walk is
  // incomplete and the invalid token is blocked instead (fail closed).
  if (process.platform === 'linux') silent(await run(submit('use $alpha: now', { cwd })));
  else denied(await run(submit('use $alpha: now', { cwd })), MSG_NOT_ADMIN);
  silent(await run(submit('[$x](mcp://srv/tool) [$y](app://z)', { cwd }))); // L1
  const other = (command: string) => JSON.stringify({ hook_event_name: 'PreToolUse', tool_name: 'shell', tool_input: { command }, cwd: '/' });
  denied(await run(other('cat .agents//skills/x/SKILL.md')), MSG_NOT_ADMIN);
  denied(await run(other('cat ./a/SKILL.md')), MSG_NOT_ADMIN);
  silent(await run(other('ls /tmp')));
  silent(await run(JSON.stringify({ hook_event_name: 'PreToolUse', tool_name: 'Read', tool_input: { file_path: '/x' }, cwd: '/' })));
  blocked(await run(JSON.stringify({ hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: {}, cwd: '/' }))); // Bash without a command
});

// --- Codex profile: keying admin Skills by every name Codex can give them (C2, D2, E4, F3, F4) -------------------------------
const HEX = 'a'.repeat(64);
/** An admin root whose entries are links to generation-like folders `<gens>/<hex>`, as the service publishes them. */
async function keyed(t: TestContext, entries: Record<string, { hex?: string; skillMd?: string }>) {
  const base = await tempDir(t);
  const admin = path.join(base, 'admin');
  const gens = path.join(base, 'gens');
  await mkdir(admin, { recursive: true });
  const real: Record<string, string> = {};
  for (const [n, e] of Object.entries(entries)) {
    const dir = path.join(gens, n, e.hex ?? HEX);
    await sk(dir, e.skillMd ?? fm(n));
    await symlink(dir, path.join(admin, n));
    real[n] = dir;
  }
  const r: Roots = { admin, user: path.join(base, 'nothing') };
  const host = fakeHost(t);
  const run = async (stdin: string, extra: object = {}, sock?: string) => {
    const c = await configFile(t, sock ?? await fakeServer(t, () => undefined), r, { skill_roots: [], ...extra });
    return host.hook([c, 'enforce', UID], stdin.startsWith('{') ? stdin : submit(stdin));
  };
  return { admin, base, gens, real, r, run, host };
}

test('codex hook: an admin Skill is keyed by its directory, its digest folder and its plain name (D2)', { skip: LINUX_ONLY }, async (t) => {
  const k = await keyed(t, { alpha: { hex: HEX, skillMd: fm('real-name') } });
  denied(await k.run('use $alpha'), MSG_UNVERIFIED); // directory key: asked (the fake service never answers)
  denied(await k.run(`use $${HEX}`), MSG_UNVERIFIED); // digest key
  denied(await k.run(`use $${HEX.toUpperCase()}`), MSG_UNVERIFIED);
  denied(await k.run('use $real-name'), MSG_UNVERIFIED); // plain `name:` key
  silent(await k.run('use $other-thing'));
});

test('codex hook: a digest mention is asked as the install name, and blocked once that Skill is gone (C2.1)', { skip: LINUX_ONLY }, async (t) => {
  const { svc, install, revoke, managed } = await service(t);
  const digest = await install('alpha');
  const r: Roots = { admin: managed, user: path.join(await tempDir(t), 'none') };
  const host = fakeHost(t);
  const cfg = await configFile(t, svc.sockets.decision, r, { skill_roots: [] });
  const run = (s: string) => host.hook([cfg, 'enforce', UID], s.startsWith('{') ? s : submit(s));
  silent(await run(START));
  silent(await run(`use $${digest.slice('sha256:'.length)}`)); // digest folder name: asked as `alpha`, VERIFIED
  await revoke(digest);
  assert.deepEqual((await readdir(managed)).filter((e) => !e.startsWith('.')), []);
  denied(await run(`use $${digest.slice('sha256:'.length)}`), MSG_NOT_ADMIN); // the removed digest is never asked
  denied(await run('use $alpha'), MSG_NOT_ADMIN); // nor the removed name
});

test('codex hook: a SKILL.md that is not plain, unreadable or colliding makes the walk incomplete (E4)', { skip: LINUX_ONLY }, async (t) => {
  for (const bad of ['---\nname: "alpha"\ndescription: d\n---\n', '---\nname: alpha\n---\n', 'no frontmatter\n', `---\nname: alpha\ndescription: ${'x'.repeat(70_000)}\n---\n`]) {
    const k = await keyed(t, { alpha: { skillMd: bad } });
    blocked(await k.run('use $unrelated'));
  }
  const k = await keyed(t, { alpha: {}, beta: { skillMd: fm('alpha') } }); // beta's plain name collides with alpha's directory
  blocked(await k.run('use $unrelated'));
  const dup = await keyed(t, { alpha: {}, Alpha: {} }); // equal ignoring case
  blocked(await dup.run('use $unrelated'));
  const dangling = await keyed(t, { alpha: {} });
  await symlink('/nonexistent/x', path.join(dangling.admin, 'gone'));
  blocked(await dangling.run('use $unrelated'));
  const ok = await keyed(t, { alpha: {} });
  silent(await ok.run('use $unrelated'));
});

test('codex hook: removed names never ask; a bad or oversized removed-names file fails closed (C2.2, D7)', { skip: LINUX_ONLY }, async (t) => {
  const file = (entries: unknown[], type = 'mago-ski.gate.removed-names.v1') => JSON.stringify({ type, entries });
  const entry = (name: string, digest = 'b'.repeat(64)) => ({ name, digest, kind: 'revoked', at: '2026-11-01T00:00:00Z' });
  const k = await keyed(t, { alpha: {} });
  const removed = path.join(k.admin, '.mago-ski-removed-names.json');
  let asked = 0;
  const counting = await fakeServer(t, () => { asked += 1; return undefined; });
  await writeFile(removed, file([entry('gone')]));
  denied(await k.run('use $gone', {}, counting), MSG_NOT_ADMIN);
  denied(await k.run(`use $${'b'.repeat(64)}`, {}, counting), MSG_NOT_ADMIN);
  denied(await k.run('use $GONE', {}, counting), MSG_NOT_ADMIN);
  silent(await k.run('use $fine', {}, counting));
  assert.equal(asked, 0);
  await writeFile(removed, file([entry('alpha')]));
  denied(await k.run('use $alpha', {}, counting), MSG_UNVERIFIED); // a name that is linked again is a normal admin Skill
  for (const bad of ['{', file([], 'other'), file([{ name: 1 }]), file(Array.from({ length: 4097 }, (_, i) => entry(`n${i}`)))]) {
    await writeFile(removed, bad);
    blocked(await k.run('use $unrelated'));
  }
  await writeFile(removed, file(Array.from({ length: 4096 }, (_, i) => entry(`n${i}`, i.toString(16).padStart(64, '0')))));
  silent(await k.run('use $unrelated'));
  denied(await k.run('use $n4095'), MSG_NOT_ADMIN);
});

test('codex hook: a linked mention is asked only for the current admin entry of that exact file (F3)', { skip: LINUX_ONLY }, async (t) => {
  const k = await keyed(t, { alpha: {}, beta: {} });
  const old = path.join(k.gens, 'alpha', 'c'.repeat(64));
  await sk(old, fm('alpha'));
  await sk(path.join(k.base, 'unlisted', 'alpha'), fm('alpha'));
  const link = (name: string, p: string) => `use [$${name}](${p})`;
  denied(await k.run(link('alpha', `${k.admin}/alpha/SKILL.md`)), MSG_UNVERIFIED); // asked
  denied(await k.run(link('alpha', `${k.real['alpha']}/SKILL.md`)), MSG_UNVERIFIED); // same file by its real path
  denied(await k.run(link('alpha', `${old}/SKILL.md`)), MSG_NOT_ADMIN); // an old generation
  denied(await k.run(link('alpha', `${k.base}/unlisted/alpha/SKILL.md`)), MSG_NOT_ADMIN); // an unlisted Skill
  denied(await k.run(link('alpha', `${k.admin}/beta/SKILL.md`)), MSG_NOT_ADMIN); // the text does not select the Skill
  await symlink(k.real['beta']!, path.join(k.admin, '.beta.hidden')); // a hidden entry is no admin entry
  await unlink(path.join(k.admin, 'beta'));
  denied(await k.run(link('beta', `${k.admin}/.beta.hidden/SKILL.md`)), MSG_NOT_ADMIN);
});

test('codex hook: a HOME or CODEX_HOME that the instance does not list makes the walk incomplete (F4)', { skip: LINUX_ONLY }, async (t) => {
  const k = await keyed(t, { alpha: {} });
  silent(await k.run('use $other', { user_homes: ['/nonexistent-home'] })); // the fake host's HOME is listed
  blocked(await k.run('use $other', { user_homes: ['/home/someone-else'] }));
  blocked(await k.run('use $other', { user_homes: [] }));
  const codexHome = await tempDir(t);
  const cfg = async (extra: object) => configFile(t, await fakeServer(t, () => undefined), k.r, { skill_roots: [], ...extra });
  const host = fakeHost(t, ENTRY, { CODEX_HOME: codexHome });
  blocked(await host.hook([await cfg({ user_homes: ['/nonexistent-home'] }), 'enforce', UID], submit('use $other')));
  silent(await host.hook([await cfg({ user_homes: ['/nonexistent-home'], codex_homes: [codexHome] }), 'enforce', UID], submit('use $other')));
});
