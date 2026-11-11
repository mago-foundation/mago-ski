import assert from 'node:assert/strict';
import { chmod, lstat, mkdir, readdir, readFile, stat, writeFile } from 'node:fs/promises';
import net from 'node:net';
import path from 'node:path';
import test, { type TestContext } from 'node:test';
import { runCli, type GateCliSeams } from '../src/cli.ts';
import { codexManagedConfigToml, codexRequirementsToml } from '../src/gate/adapters/codex-requirements.ts';
import { instancePaths } from '../src/gate/instance.ts';
import { applyInit, doctor, planInit, type InitOptions } from '../src/gate/setup.ts';
import { LINUX_ONLY, tempDir } from './helpers.ts';

const UID = process.getuid!();
const FP = `sha256:${'ab'.repeat(32)}`;
const ELF = Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0, 0, 0, 0]);

async function world(t: TestContext) {
  const base = await tempDir(t, 'mago-ski-cpx-');
  const installRoot = path.join(base, 'pkg');
  const adapters = path.join(installRoot, 'dist', 'src', 'gate', 'adapters');
  await mkdir(adapters, { recursive: true });
  for (const f of ['claude-code-hook.js', 'codex-hook.js']) await writeFile(path.join(adapters, f), '// hook\n');
  await writeFile(path.join(installRoot, 'dist', 'src', 'cli.js'), '// cli\n');
  await writeFile(path.join(installRoot, 'package.json'), '{}\n');
  const bin = path.join(base, 'usr', 'bin');
  await mkdir(bin, { recursive: true });
  const exe = path.join(bin, 'codex');
  await writeFile(exe, ELF);
  await writeFile(path.join(bin, 'node'), '');
  const seams: GateCliSeams = { base, rootUid: UID, uid: UID, installRoot, nodePath: path.join(bin, 'node'), envPath: path.join(bin, 'env'), checkExec: false, platform: 'linux' };
  const opts = (extra: Partial<InitOptions> = {}): InitOptions => ({ host: 'codex', rootFingerprint: FP, hostExes: [exe], base, rootUid: UID, platform: 'linux', installRoot, nodePath: seams.nodePath!, envPath: seams.envPath!, checkExec: false, ...extra });
  const home = async (name: string) => { const h = path.join(base, 'home', name); await mkdir(h, { recursive: true }); return h; };
  return { base, installRoot, exe, seams, opts, home, p: instancePaths('codex', base) };
}

const dopts = (w: Awaited<ReturnType<typeof world>>, extra: object = {}) => ({
  base: w.base, rootUid: UID, installRoot: w.installRoot, nodePath: w.seams.nodePath!, envPath: w.seams.envPath!, checkExec: false,
  somaxconn: async () => 4096, procMounts: async () => 'proc /proc proc rw 0 0\n', codexVersion: async () => 'codex-cli 0.166.0', isImmutable: async () => false, ...extra,
});
const by = (cs: Awaited<ReturnType<typeof doctor>>) => Object.fromEntries(cs.map((c) => [c.check, c]));
const exists = (p: string) => lstat(p).then(() => true, () => false);

test('generators: managed_config.toml is exact; requirements pin the executor features and keep deny_read (C1)', () => {
  assert.equal(codexManagedConfigToml(), `# mago-ski Codex profile (generated). Evidence: codex-cli 0.166.0 / Linux.
# Outranks user config, project config, profiles and -c. It removes Skill sources; it does not block by itself.
# project_root_markers = []: the repo Skill scan covers the working directory only.
project_root_markers = []

# Skill descriptions are not injected into the prompt.
[skills]
include_instructions = false

# No bundled (.system) Skills.
[skills.bundled]
enabled = false

# No cloud Skills.
[cloud.skills]
enabled = false
`);
  const hookEntry = '/usr/lib/node_modules/@mago-foundation/mago-ski/dist/src/gate/adapters/codex-hook.js'; // a scoped @ path
  const toml = codexRequirementsToml({ mode: 'enforce', nodePath: '/usr/bin/node', hookEntry, configPath: '/etc/mago-ski/gate/codex-hook.json', hookTimeoutSec: 5, selfDeadlineMs: 3000, userSkillRoots: ['/home/a/.codex/skills', '/home/a/.agents/skills'] });
  assert.match(toml, /\[features\]\nhooks = true\nplugins = false\nremote_plugin = false\napps = false\nexecutor_capability_discovery = false\nexecutor_capability_discovery_v2 = false/u);
  assert.match(toml, /deny_read = \["\/home\/a\/\.codex\/skills\/\*\*", "\/home\/a\/\.agents\/skills\/\*\*"\]/u);
  assert.match(toml, /@mago-foundation/u);
  assert.doesNotMatch(toml, /does not hide|0\.163\.0 only/u);
  assert.match(codexRequirementsToml({ mode: 'shadow', nodePath: '/usr/bin/node', hookEntry, configPath: '/c.json', hookTimeoutSec: 5, selfDeadlineMs: 3000, userSkillRoots: [] }), /^# mago-ski Codex requirements/u);
});

test('planInit codex: --user-home and --codex-home give the deny_read roots, the hook config homes and the .system move (C5, F5, F7.6)', async (t) => {
  const w = await world(t);
  const a = await w.home('alice');
  const b = await w.home('bob');
  const ch = path.join(w.base, 'codex-alice');
  await mkdir(path.join(a, '.codex', 'skills', '.system', 'x'), { recursive: true });
  await mkdir(path.join(ch, 'skills', '.system'), { recursive: true });
  const plan = await planInit(w.opts({ userHomes: [a, b], codexHomes: [ch], mode: 'enforce', now: () => new Date('2026-11-11T10:20:30Z') }));
  assert.deepEqual(plan.problems, []);
  assert.deepEqual(plan.homes, { userHomes: [a, b], codexHomes: [ch] });
  assert.deepEqual(plan.denyRoots, [`${a}/.codex/skills`, `${a}/.codex/skills/.system`, `${a}/.agents/skills`, `${b}/.codex/skills`, `${b}/.codex/skills/.system`, `${b}/.agents/skills`, `${ch}/skills`, `${ch}/skills/.system`]);
  const host = plan.files.find((f) => f.role === 'host')!.content;
  for (const r of plan.denyRoots) assert.ok(host.includes(`"${r}/**"`), r);
  const hook = JSON.parse(plan.files.find((f) => f.role === 'hook')!.content);
  assert.deepEqual([hook.user_homes, hook.codex_homes], [[a, b], [ch]]);
  assert.deepEqual(plan.actions, [
    { kind: 'move-system', from: `${a}/.codex/skills/.system`, to: `${a}/.codex/mago-ski-backup/system-20261111T102030Z` },
    { kind: 'move-system', from: `${ch}/skills/.system`, to: `${ch}/mago-ski-backup/system-20261111T102030Z` },
  ]);
  assert.deepEqual(plan.files.map((f) => f.role).slice(4, 6), ['host', 'managed-config']);
  // --no-deny-read leaves the roots out; a relative or unsafe home is a problem
  const none = await planInit(w.opts({ userHomes: [a], noDenyRead: true, mode: 'enforce' }));
  assert.doesNotMatch(none.files.find((f) => f.role === 'host')!.content, /^deny_read = /mu);
  assert.match((await planInit(w.opts({ userHomes: ['rel/home'] }))).problems.join('\n'), /--user-home rel\/home must be an absolute folder/u);
  await assert.rejects(planInit({ ...w.opts({ userHomes: [a] }), host: 'claude-code', hostExes: [w.exe] }), /are for --host codex/u);
});

test('planInit codex: without --user-home the homes come from passwd (uid 1000+, login shell)', async (t) => {
  const w = await world(t);
  await mkdir(path.join(w.base, 'etc'), { recursive: true });
  await writeFile(path.join(w.base, 'etc', 'passwd'), [
    'root:x:0:0:root:/root:/bin/bash', 'daemon:x:1:1::/usr/sbin:/usr/sbin/nologin', 'alice:x:1000:1000::/home/alice:/bin/bash',
    'svc:x:1001:1001::/var/lib/svc:/usr/sbin/nologin', 'bob:x:1002:1002::/home/bob:/bin/zsh', 'nobody:x:65534:65534::/nonexistent:/bin/sh', 'f:x:1003:1003::/home/f:/bin/false', '',
  ].join('\n'));
  const plan = await planInit(w.opts());
  assert.deepEqual(plan.homes.userHomes, ['/home/alice', '/home/bob']);
  assert.ok(plan.denyRoots.includes('/home/bob/.agents/skills'));
});

test('gate init moves .system to a backup outside every Skill root, and doctor then passes the .system check (F5)', { skip: LINUX_ONLY }, async (t) => {
  const w = await world(t);
  const a = await w.home('alice');
  await mkdir(path.join(a, '.codex', 'skills', '.system', 'skill-installer'), { recursive: true });
  await writeFile(path.join(a, '.codex', 'skills', '.system', 'skill-installer', 'SKILL.md'), 'x');
  const plan = await planInit(w.opts({ userHomes: [a], now: () => new Date('2026-11-11T10:20:30Z') }));
  const before = by(await doctor('codex', dopts(w))); // not initialised yet
  assert.equal(before['instance config']!.result, 'FAIL');
  const result = await applyInit(plan, { base: w.base, rootUid: UID });
  assert.deepEqual(result.movedSystem, [{ from: `${a}/.codex/skills/.system`, to: `${a}/.codex/mago-ski-backup/system-20261111T102030Z` }]);
  assert.equal(await exists(`${a}/.codex/skills/.system`), false);
  assert.equal(await readFile(`${a}/.codex/mago-ski-backup/system-20261111T102030Z/skill-installer/SKILL.md`, 'utf8'), 'x');
  const checks = by(await doctor('codex', dopts(w)));
  assert.equal(checks['.system folder']!.result, 'PASS');
  assert.equal(checks['user Skills']!.result, 'PASS'); // the backup is outside the Skill roots
  assert.equal(checks['managed config']!.result, 'PASS');
  assert.equal(checks['host config']!.result, 'PASS', checks['host config']!.detail);
  assert.equal(checks['hook config']!.result, 'PASS', checks['hook config']!.detail);
  assert.equal(checks['codex version']!.result, 'PASS');
  assert.equal(checks['Skill folder lock']!.result, 'WARN');
  assert.equal(await readFile(w.p.managedConfig!, 'utf8'), codexManagedConfigToml());
});

test('doctor codex: a listed home with Skills or a stale .system FAILs; edited managed config FAILs; untested version WARNs (D1, D3, C5)', { skip: LINUX_ONLY }, async (t) => {
  const w = await world(t);
  const a = await w.home('alice');
  const ch = path.join(w.base, 'codex-home');
  await applyInit(await planInit(w.opts({ userHomes: [a], codexHomes: [ch] })), { base: w.base, rootUid: UID });
  assert.equal(by(await doctor('codex', dopts(w)))['user Skills']!.result, 'PASS');
  await mkdir(path.join(a, '.agents', 'skills', 'evil'), { recursive: true });
  await writeFile(path.join(a, '.agents', 'skills', 'evil', 'SKILL.md'), 'x');
  let c = by(await doctor('codex', dopts(w)));
  assert.equal(c['user Skills']!.result, 'FAIL');
  assert.match(c['user Skills']!.detail, /alice\/\.agents\/skills/u);
  await mkdir(path.join(ch, 'skills', '.hidden', 'deep'), { recursive: true }); // a dot folder under CODEX_HOME counts
  await writeFile(path.join(ch, 'skills', '.hidden', 'deep', 'skill.md'), 'x');
  await mkdir(path.join(ch, 'skills', '.system'), { recursive: true });
  c = by(await doctor('codex', dopts(w)));
  assert.match(c['user Skills']!.detail, /codex-home\/skills/u);
  assert.equal(c['.system folder']!.result, 'FAIL');
  await writeFile(w.p.managedConfig!, 'project_root_markers = [".git"]\n');
  assert.equal(by(await doctor('codex', dopts(w)))['managed config']!.result, 'FAIL');
  assert.equal(by(await doctor('codex', dopts(w, { codexVersion: async () => 'codex-cli 0.170.2' })))['codex version']!.result, 'WARN');
  assert.match(by(await doctor('codex', dopts(w, { codexVersion: async () => { throw new Error('no'); } })))['codex version']!.detail, /untested Codex version/u);
});

test('doctor codex: nameMismatch FAILs, a full removed-names file WARNs (C4, E6, D6)', { skip: LINUX_ONLY }, async (t) => {
  const w = await world(t);
  const a = await w.home('alice');
  await applyInit(await planInit(w.opts({ userHomes: [a] })), { base: w.base, rootUid: UID });
  const status = (extra: object) => async () => ({ v: 1 as const, ok: true as const, ready: true, mode: 'shadow', trust: 'ready', root_fingerprint: FP, log: { state: 'ready' }, nameMismatch: [], removedNames: { count: 0, full: false, evicted: 0, error: null }, ...extra });
  const runDir = path.join(w.base, 'run', 'mago-ski', 'gate', 'codex');
  await mkdir(path.join(runDir, 'admin'), { recursive: true, mode: 0o700 });
  await chmod(runDir, 0o755);
  await chmod(path.join(runDir, 'admin'), 0o700);
  for (const sock of [path.join(runDir, 'decision.sock'), path.join(runDir, 'admin', 'admin.sock')]) {
    const server = net.createServer();
    await new Promise<void>((r) => server.listen(sock, r));
    t.after(() => { server.close(); });
    if (sock.endsWith('admin.sock')) await chmod(sock, 0o600);
  }
  const ok = by(await doctor('codex', dopts(w, { ask: status({}), uid: UID })));
  assert.equal(ok['service']!.result, 'PASS');
  assert.equal(ok['name mismatch']!.result, 'PASS');
  assert.equal(ok['removed names'], undefined);
  const bad = by(await doctor('codex', dopts(w, { ask: status({ nameMismatch: ['alpha'], removedNames: { count: 4096, full: true, evicted: 3, error: null } }), uid: UID })));
  assert.equal(bad['name mismatch']!.result, 'FAIL');
  assert.match(bad['name mismatch']!.detail, /alpha/u);
  assert.equal(bad['removed names']!.result, 'WARN');
  assert.match(bad['removed names']!.detail, /prune-removed --host codex --older-than-days 90/u);
});

test('--lock-user-skill-folders: the plan, the order, idempotence, refusals, and a failing chattr stops the command (E1)', { skip: LINUX_ONLY }, async (t) => {
  const w = await world(t);
  const a = await w.home('alice');
  const locked = new Set<string>();
  const chattr = async (p: string) => { locked.add(p); };
  const isImmutable = async (p: string) => locked.has(p);
  const plan = await planInit(w.opts({ userHomes: [a], lockUserSkillFolders: true, chattr, isImmutable }));
  assert.deepEqual(plan.problems, []);
  assert.deepEqual(plan.actions.map((x) => x.kind), ['lock']);
  const res = await applyInit(plan, { base: w.base, rootUid: UID, chattr, isImmutable });
  assert.deepEqual(res.locked, [`${a}/.agents/skills`, `${a}/.codex/skills`, `${a}/.agents`]);
  for (const d of [`${a}/.agents/skills`, `${a}/.codex/skills`, `${a}/.agents`, `${a}/.codex`]) assert.equal((await stat(d)).isDirectory(), true, d);
  assert.deepEqual(await readdir(`${a}/.agents/skills`), []);
  assert.equal((await stat(`${a}/.agents/skills`)).mode & 0o777, 0o755);
  assert.equal(by(await doctor('codex', dopts(w, { isImmutable })))['Skill folder lock']!.result, 'PASS');
  assert.equal(by(await doctor('codex', dopts(w)))['Skill folder lock']!.result, 'WARN');
  // a re-run does not touch what is locked
  const again = await planInit(w.opts({ userHomes: [a], lockUserSkillFolders: true, chattr, isImmutable }));
  assert.deepEqual((await applyInit(again, { base: w.base, rootUid: UID, force: true, chattr, isImmutable })).locked, [`${a}/.agents/skills`, `${a}/.codex/skills`, `${a}/.agents`]);
  // a non-empty folder is refused in the plan; no home at all is refused
  const b = await w.home('bob');
  await mkdir(path.join(b, '.agents', 'skills', 'mine'), { recursive: true });
  assert.match((await planInit(w.opts({ userHomes: [b], lockUserSkillFolders: true }))).problems.join('\n'), /\.agents\/skills already holds mine/u);
  assert.match((await planInit(w.opts({ lockUserSkillFolders: true }))).problems.join('\n'), /needs at least one home/u);
  // an unsupported file system: chattr fails, the command stops with that message
  const c = await w.home('carol');
  const failing = async () => { throw new Error('chattr +i failed: Operation not supported'); };
  await assert.rejects(applyInit(await planInit(w.opts({ userHomes: [c], lockUserSkillFolders: true, chattr: failing, isImmutable: async () => false })), { base: w.base, rootUid: UID, force: true, chattr: failing, isImmutable: async () => false }), /Operation not supported/u);
});

test('gate init / prune-removed through the CLI: flags, the enforce note, and the admin command (F6.6)', { skip: LINUX_ONLY }, async (t) => {
  const w = await world(t);
  const a = await w.home('alice');
  const cap = async (argv: string[], extra: Partial<GateCliSeams> = {}) => {
    const out: string[] = [];
    const o = process.stdout.write.bind(process.stdout);
    process.stdout.write = ((s: string | Uint8Array) => { out.push(String(s)); return true; }) as typeof process.stdout.write;
    try { const result = await runCli(argv, new Date(), { ...w.seams, ...extra }); return { result, stdout: out.join('') }; } finally { process.stdout.write = o; }
  };
  const init = await cap(['gate', 'init', '--host', 'codex', '--root-fingerprint', FP, '--host-exe', w.exe, '--mode', 'enforce', '--user-home', a, '--user-home', path.join(w.base, 'other'), '--print', '--json']);
  assert.equal(init.result, 0);
  const files = JSON.parse(init.stdout) as { path: string; content: string }[];
  assert.ok(files.some((f) => f.path.endsWith('managed_config.toml')));
  assert.ok(files.find((f) => f.path.endsWith('requirements.toml'))!.content.includes(`${a}/.codex/skills/**`));
  const real = await cap(['gate', 'init', '--host', 'codex', '--root-fingerprint', FP, '--host-exe', w.exe, '--mode', 'enforce', '--user-home', a]);
  assert.equal(real.result, 0);
  assert.ok(real.stdout.includes('Codex enforcement depends on organisation controls; read docs/hosts/codex.md before enabling enforce'));
  assert.ok(real.stdout.includes(`wrote ${w.p.managedConfig!}`));

  const sent: Record<string, unknown>[] = [];
  const ask = async (_s: string, command: Record<string, unknown>) => { sent.push(command); return { v: 1 as const, ok: true as const, pruned: 2, remaining: 5 }; };
  const pr = await cap(['gate', 'prune-removed', '--host', 'codex', '--older-than-days', '30'], { ask });
  assert.equal(pr.result, 0);
  assert.deepEqual(sent, [{ cmd: 'prune-removed', older_than_days: 30 }]);
  assert.match(pr.stdout, /pruned 2 removed name\(s\); 5 remain/u);
  await cap(['gate', 'prune-removed', '--host', 'codex'], { ask });
  assert.deepEqual(sent[1], { cmd: 'prune-removed' });
  const refused = await cap(['gate', 'prune-removed', '--host', 'codex', '--older-than-days', '3'], { ask: async () => ({ v: 1 as const, ok: false as const, error: 'older_than_days must be at least 7' }) });
  assert.equal(refused.result, 1);
  assert.match((await cap(['gate', 'prune-removed', '--help'])).stdout, /Usage: mago-ski gate prune-removed/u);
});
