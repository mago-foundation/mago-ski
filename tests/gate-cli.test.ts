// `mago-ski gate ...` (design docs/design/gate-cli.md). Planning tests run on every platform (planInit takes `platform`);
// anything that starts the service or reads /proc is LINUX_ONLY. The tree is a temporary `base`, the owner the test user.
import assert from 'node:assert/strict';
import { chmod, lstat, mkdir, readdir, readFile, rm, stat, symlink, writeFile } from 'node:fs/promises';
import net from 'node:net';
import path from 'node:path';
import test, { type TestContext } from 'node:test';
import { runCli, type GateCliSeams } from '../src/cli.ts';
import { serializeCanonicalJson } from '../src/canonical-json.ts';
import { claudeCodeManagedSettings } from '../src/gate/adapters/claude-code-settings.ts';
import { codexRequirementsToml } from '../src/gate/adapters/codex-requirements.ts';
import { askAdmin, TIMEOUT_MESSAGE, type AskAdmin } from '../src/gate/admin-client.ts';
import { instancePaths, instanceToServiceConfig, parseInstanceConfig, readInstanceConfig, type Host } from '../src/gate/instance.ts';
import { createGateService } from '../src/gate/service.ts';
import { applyInit, checkRootOwnedChain, checkRootOwnedTree, defaultHostExe, doctor, planInit, type InitOptions } from '../src/gate/setup.ts';
import { approve, LINUX_ONLY, setupOrg, tempDir, writeSkill } from './helpers.ts';

const UID = process.getuid!();
const FP = `sha256:${'ab'.repeat(32)}`;
const PKG = 'usr/lib/node_modules/@mago-foundation/mago-ski';

interface World { base: string; installRoot: string; opts: (host: Host, extra?: Partial<InitOptions>) => InitOptions; seams: GateCliSeams; exe: string }

/** A temporary base with a fake installed package (hooks, cli), a fake ELF host binary and a fake node. */
async function world(t: TestContext): Promise<World> {
  const base = await tempDir(t, 'mago-ski-gate-');
  const installRoot = path.join(base, PKG);
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
  return {
    base, installRoot, exe, seams,
    opts: (host, extra = {}) => ({ host, rootFingerprint: FP, hostExes: [exe], base, rootUid: UID, platform: 'linux', installRoot, nodePath: seams.nodePath!, envPath: seams.envPath!, checkExec: false, ...extra }),
  };
}

async function capture<T>(fn: () => Promise<T>): Promise<{ result: T; stdout: string; stderr: string }> {
  const out: string[] = [];
  const err: string[] = [];
  const o = process.stdout.write.bind(process.stdout);
  const e = process.stderr.write.bind(process.stderr);
  process.stdout.write = ((s: string | Uint8Array) => { out.push(String(s)); return true; }) as typeof process.stdout.write;
  process.stderr.write = ((s: string | Uint8Array) => { err.push(String(s)); return true; }) as typeof process.stderr.write;
  try { return { result: await fn(), stdout: out.join(''), stderr: err.join('') }; } finally { process.stdout.write = o; process.stderr.write = e; }
}

const exists = (p: string): Promise<boolean> => lstat(p).then(() => true, () => false);
const run = (w: World, argv: string[], extra: Partial<GateCliSeams> = {}) => capture(() => runCli(argv, new Date(), { ...w.seams, ...extra }));

/* ------------------------------------------------------------------------------------------- golden contents */

test('planInit claude-code: golden file contents, order, modes and folders', async (t) => {
  const w = await world(t);
  const plan = await planInit(w.opts('claude-code'));
  const p = instancePaths('claude-code', w.base);
  assert.deepEqual(plan.problems, []);
  assert.deepEqual(plan.foreign, []);
  assert.deepEqual(plan.files.map((f) => f.role), ['instance', 'hook', 'unit', 'dropin', 'host', 'manifest', 'shared-manifest']);
  assert.ok(plan.files.every((f) => f.mode === 0o644));
  const by = Object.fromEntries(plan.files.map((f) => [f.role, f]));

  assert.equal(by['instance']!.path, `${w.base}/etc/mago-ski/gate/claude-code.json`);
  assert.equal(by['instance']!.content, `{"admin_socket_dir":"${w.base}/run/mago-ski/gate/claude-code/admin","build_id":"mago-ski 0.2.0","decision_socket_dir":"${w.base}/run/mago-ski/gate/claude-code","generations_dir":"${w.base}/var/lib/mago-ski/gate/claude-code/generations","host":"claude-code","host_exes":["${w.exe}"],"inbox_dir":null,"managed_dir":"${w.base}/etc/claude-code/.claude/skills","mode":"shadow","root_fingerprint":"${FP}","state_dir":"${w.base}/var/lib/mago-ski/gate/claude-code/state","v":1}\n`);
  assert.equal(by['hook']!.content, `{"client_deadline_ms":1500,"host_exes":["${w.exe}"],"mode":"shadow","self_deadline_ms":3000,"socket":"${w.base}/run/mago-ski/gate/claude-code/decision.sock","v":1}\n`);
  assert.equal(by['unit']!.path, `${w.base}/etc/systemd/system/mago-ski-gate@.service`);
  assert.equal(by['unit']!.content, `[Unit]
Description=mago-ski gate for %i
After=local-fs.target

[Service]
Type=simple
ExecStart=${w.seams.nodePath} ${w.installRoot}/dist/src/cli.js gate run --host %i
Restart=on-failure
RuntimeDirectory=mago-ski/gate/%i
RuntimeDirectoryMode=0755
LimitNOFILE=4096
ProtectSystem=strict
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
`);
  assert.equal(by['dropin']!.path, `${w.base}/etc/systemd/system/mago-ski-gate@claude-code.service.d/paths.conf`);
  assert.equal(by['dropin']!.content, `[Service]\nReadWritePaths=${w.base}/var/lib/mago-ski/gate/claude-code ${w.base}/etc/claude-code/.claude/skills\nReadOnlyPaths=/etc/mago-ski\n`);

  const hookEntry = `${w.installRoot}/dist/src/gate/adapters/claude-code-hook.js`;
  assert.equal(by['host']!.path, `${w.base}/etc/claude-code/managed-settings.json`);
  assert.equal(by['host']!.content, `${JSON.stringify(claudeCodeManagedSettings({
    mode: 'shadow', nodePath: w.seams.nodePath!, hookEntry, configPath: p.hook, hookTimeoutSec: 5, selfDeadlineMs: 3000, envPath: w.seams.envPath!,
  }), null, 2)}\n`);
  const settings = JSON.parse(by['host']!.content);
  assert.equal(settings.hooks.PreToolUse[0].hooks[0].command, `${w.seams.envPath} -i ${w.seams.nodePath} --no-addons ${hookEntry} ${p.hook} shadow`);
  assert.equal(settings.allowManagedHooksOnly, undefined); // shadow: no native locks

  // manifests: host files (not the unit) in the host manifest, the unit in the shared one; the manifest itself is not listed
  const host = JSON.parse(by['manifest']!.content);
  assert.deepEqual(host.files.map((f: { path: string }) => f.path), [by['dropin']!.path, by['hook']!.path, by['instance']!.path, by['host']!.path].sort());
  assert.deepEqual(JSON.parse(by['shared-manifest']!.content).files.map((f: { path: string }) => f.path), [by['unit']!.path]);

  assert.deepEqual(plan.dirs.map((d) => [path.relative(w.base, d.path), d.mode.toString(8)]), [
    ['etc/mago-ski/gate', '755'], ['var/lib/mago-ski/gate/claude-code', '755'], ['var/lib/mago-ski/gate/claude-code/state', '700'],
    ['var/lib/mago-ski/gate/claude-code/generations', '755'], ['etc/claude-code/.claude/skills', '755'], ['etc/systemd/system/mago-ski-gate@claude-code.service.d', '755'],
  ]);
  assert.match(plan.next[0]!, /enable --now mago-ski-gate@claude-code/u);

  const enforce = await planInit(w.opts('claude-code', { mode: 'enforce' }));
  assert.equal(JSON.parse(enforce.files.find((f) => f.role === 'host')!.content).allowManagedHooksOnly, true);
});

test('planInit codex: golden requirements.toml, Codex hook keys, and the enforce refusal (G9)', async (t) => {
  const w = await world(t);
  const plan = await planInit(w.opts('codex', { inbox: `${w.base}/inbox` }));
  const p = instancePaths('codex', w.base);
  const by = Object.fromEntries(plan.files.map((f) => [f.role, f]));
  assert.equal(by['host']!.path, `${w.base}/etc/codex/requirements.toml`);
  assert.equal(by['host']!.content, codexRequirementsToml({
    mode: 'shadow', nodePath: w.seams.nodePath!, hookEntry: `${w.installRoot}/dist/src/gate/adapters/codex-hook.js`, configPath: p.hook,
    hookTimeoutSec: 5, selfDeadlineMs: 3000, envPath: w.seams.envPath!, userSkillRoots: [],
  }));
  assert.match(by['host']!.content, /command = ".* --no-addons .*codex-hook\.js .*codex-hook\.json shadow"/u);
  assert.equal(by['hook']!.content, `{"admin_root":"${w.base}/etc/codex/skills","client_deadline_ms":1500,"host_exes":["${w.exe}"],"mode":"shadow","self_deadline_ms":3000,"skill_roots":[],"socket":"${w.base}/run/mago-ski/gate/codex/decision.sock","v":1}\n`);
  assert.equal(JSON.parse(by['instance']!.content).inbox_dir, `${w.base}/inbox`);
  assert.equal(JSON.parse(by['instance']!.content).managed_dir, `${w.base}/etc/codex/skills`);
  await assert.rejects(planInit(w.opts('codex', { mode: 'enforce' })), /Codex enforcement is not complete yet \(see docs\/hosts\/codex\.md\); use --mode shadow/u);
  await assert.rejects(planInit(w.opts('claude-code', { platform: 'darwin' })), /Linux only/u);
  await assert.rejects(planInit(w.opts('claude-code', { rootFingerprint: 'sha256:xyz' })), /root-fingerprint/u);
});

test('generators accept an @ in a path (scoped npm install) and still refuse spaces and quotes', () => {
  const hookEntry = '/usr/lib/node_modules/@mago-foundation/mago-ski/dist/src/gate/adapters/claude-code-hook.js';
  const base = { mode: 'enforce' as const, nodePath: '/usr/bin/node', hookEntry, configPath: '/etc/mago-ski/gate/claude-code-hook.json', hookTimeoutSec: 5, selfDeadlineMs: 3000 };
  const settings = claudeCodeManagedSettings(base) as { hooks: { PreToolUse: { hooks: { command: string }[] }[] } };
  assert.equal(settings.hooks.PreToolUse[0]!.hooks[0]!.command, `/usr/bin/env -i /usr/bin/node --no-addons ${hookEntry} /etc/mago-ski/gate/claude-code-hook.json enforce`);
  const toml = codexRequirementsToml({ ...base, hookEntry: hookEntry.replace('claude-code', 'codex'), userSkillRoots: [] });
  assert.match(toml, /command = "\/usr\/bin\/env -i \/usr\/bin\/node --no-addons \/usr\/lib\/node_modules\/@mago-foundation\/mago-ski\/dist\/src\/gate\/adapters\/codex-hook\.js /u);
  assert.match(toml, /managed_dir = "\/usr\/lib\/node_modules\/@mago-foundation\/mago-ski\/dist\/src\/gate\/adapters"/u);
  for (const bad of ['/opt/a b/hook.js', '/opt/a"b/hook.js', '/opt/a$b/hook.js'])
    assert.throws(() => claudeCodeManagedSettings({ ...base, hookEntry: bad }));
});

/* ------------------------------------------------------------------------------------------ apply and manifest */

test('applyInit writes the files with their modes, then a re-run is clean and the shared unit is not foreign to the other host', async (t) => {
  const w = await world(t);
  const plan = await planInit(w.opts('claude-code'));
  const r = await applyInit(plan, { base: w.base, rootUid: UID });
  assert.deepEqual(r.written, plan.files.map((f) => f.path)); // the host config is written after the other configs, the manifests last
  assert.ok(r.written.indexOf(plan.files.find((f) => f.role === 'host')!.path) < r.written.indexOf(plan.files.find((f) => f.role === 'manifest')!.path));
  for (const f of plan.files) assert.equal((await stat(f.path)).mode & 0o777, 0o644, f.path);
  const p = instancePaths('claude-code', w.base);
  assert.equal((await stat(p.stateDir)).mode & 0o777, 0o700);
  assert.equal((await stat(p.generationsDir)).mode & 0o777, 0o755);
  assert.equal((await stat(p.managedDir)).mode & 0o777, 0o755);
  assert.equal((await stat(path.join(w.base, 'etc', 'claude-code'))).mode & 0o777, 0o755); // a created parent
  assert.equal(await exists(p.decisionSocketDir), false); // systemd and start() create the run folders
  // what was written reads back as a valid instance config
  const cfg = await readInstanceConfig(p.instance, UID);
  assert.equal(cfg.mode, 'shadow');

  const again = await planInit(w.opts('claude-code', { mode: 'enforce' }));
  assert.deepEqual(again.foreign, []); // all ours by manifest
  assert.equal(again.rerun, true);
  assert.match(again.next[0]!, /systemctl restart mago-ski-gate@claude-code/u);

  const codex = await planInit(w.opts('codex'));
  assert.deepEqual(codex.foreign, []); // the unit is in the shared manifest
  assert.equal(codex.rerun, false);
  await applyInit(codex, { base: w.base, rootUid: UID });
  assert.deepEqual((await planInit(w.opts('claude-code'))).foreign, []);
});

test('a foreign host file is refused before any write, named, and --force moves it aside', async (t) => {
  const w = await world(t);
  const p = instancePaths('claude-code', w.base);
  await mkdir(path.dirname(p.hostConfig), { recursive: true });
  await writeFile(p.hostConfig, '{"theirs":true}\n');
  await mkdir(path.dirname(p.hook), { recursive: true });
  await writeFile(p.hook, 'mine\n');
  const plan = await planInit(w.opts('claude-code'));
  assert.deepEqual(plan.foreign.sort(), [p.hook, p.hostConfig].sort());
  await assert.rejects(applyInit(plan, { base: w.base, rootUid: UID }), (e: Error) =>
    e.message.includes(`${p.hostConfig} exists and was not written by mago-ski; merge it by hand (mago-ski gate init --print) or pass --force`) && e.message.includes(p.hook));
  assert.equal(await exists(p.instance), false); // nothing was written
  assert.equal(await readFile(p.hostConfig, 'utf8'), '{"theirs":true}\n');

  const r = await applyInit(plan, { force: true, base: w.base, rootUid: UID, now: () => new Date('2026-11-11T10:20:30Z') });
  assert.equal(r.backups.length, 2);
  assert.ok(r.backups.some((b) => b.from === p.hostConfig && b.to === `${p.hostConfig}.mago-ski-bak-20261111T102030Z`));
  assert.equal(await readFile(`${p.hostConfig}.mago-ski-bak-20261111T102030Z`, 'utf8'), '{"theirs":true}\n');
  assert.match(await readFile(p.hostConfig, 'utf8'), /hooks/u);
  assert.equal(await readFile(`${p.hook}.mago-ski-bak-20261111T102030Z`, 'utf8'), 'mine\n');
  assert.equal(await readFile(p.hook, 'utf8'), plan.files.find((f) => f.path === p.hook)!.content);
  assert.equal(await readFile(p.hostConfig, 'utf8'), plan.files.find((f) => f.path === p.hostConfig)!.content);

  // an edited file that mago-ski wrote is no longer ours either
  await writeFile(p.hostConfig, '{"edited":true}\n');
  assert.deepEqual((await planInit(w.opts('claude-code'))).foreign, [p.hostConfig]);
});

test('a failed --force run keeps the host config in place, restores what it did not write and says which is which', async (t) => {
  const w = await world(t);
  const p = instancePaths('claude-code', w.base);
  await mkdir(path.dirname(p.hostConfig), { recursive: true });
  await writeFile(p.hostConfig, 'theirs\n');
  await mkdir(path.dirname(p.dropinDir), { recursive: true });
  await writeFile(p.dropinDir, 'a file where a folder must go\n');
  const plan = await planInit(w.opts('claude-code'));
  await assert.rejects(applyInit(plan, { force: true, base: w.base, rootUid: UID }), /gate init failed.*Original put back, not changed: .*managed-settings\.json/su);
  assert.equal(await readFile(p.hostConfig, 'utf8'), 'theirs\n');
  assert.equal(await exists(p.manifest), false);
  assert.equal((await readdir(path.dirname(p.hostConfig))).some((n) => n.includes('mago-ski-bak')), false);
});

test('a failure after the host config was replaced keeps the new content, keeps the backup and lists new, restored and kept files', async (t) => {
  const w = await world(t);
  const p = instancePaths('claude-code', w.base);
  await mkdir(path.dirname(p.hostConfig), { recursive: true });
  await writeFile(p.hostConfig, 'theirs\n');
  await mkdir(path.dirname(p.hook), { recursive: true });
  await writeFile(p.hook, 'hook theirs\n');
  const plan = await planInit(w.opts('claude-code'));
  // the manifests are written last: a folder where the shared manifest goes makes the run fail after the host config was replaced
  await mkdir(p.sharedManifest);
  const bad = await planInit(w.opts('claude-code'));
  assert.ok(bad.foreign.includes(p.sharedManifest)); // an existing manifest that is not a regular file is foreign too
  assert.deepEqual(plan.foreign.sort(), [p.hook, p.hostConfig].sort());
  await assert.rejects(applyInit({ ...plan, foreign: [...plan.foreign] }, { force: true, base: w.base, rootUid: UID, now: () => new Date('2026-11-11T10:20:30Z') }), (e: Error) =>
    /gate init failed/u.test(e.message) && /New files written/u.test(e.message) && /Replaced by new content; the original stays as a backup/u.test(e.message) && !/put back/u.test(e.message));
  assert.equal(await readFile(`${p.hostConfig}.mago-ski-bak-20261111T102030Z`, 'utf8'), 'theirs\n');
  assert.equal(await readFile(p.hostConfig, 'utf8'), plan.files.find((f) => f.path === p.hostConfig)!.content);
  assert.equal(await readFile(`${p.hook}.mago-ski-bak-20261111T102030Z`, 'utf8'), 'hook theirs\n');
  assert.equal(await readFile(p.hook, 'utf8'), plan.files.find((f) => f.path === p.hook)!.content);
});

test('applyInit checks every planned folder and its ancestors before it renames or writes anything', async (t) => {
  const w = await world(t);
  const p = instancePaths('claude-code', w.base);
  await mkdir(path.dirname(p.hostConfig), { recursive: true });
  await writeFile(p.hostConfig, 'theirs\n');
  const plan = await planInit(w.opts('claude-code'));
  assert.deepEqual(plan.foreign, [p.hostConfig]);
  // a chain owned by another uid: refused, the foreign file is not touched, no backup, nothing written
  await assert.rejects(applyInit(plan, { force: true, base: w.base, rootUid: UID + 1 }), /must be owned by root/u);
  assert.equal(await readFile(p.hostConfig, 'utf8'), 'theirs\n');
  assert.equal((await readdir(path.dirname(p.hostConfig))).some((n) => n.includes('mago-ski-bak')), false);
  assert.equal(await exists(p.instance), false);
  // a user-owned (here: group-writable) existing folder: refused before any write, and not chmodded
  await mkdir(p.configDir, { recursive: true });
  await chmod(p.configDir, 0o775);
  await assert.rejects(applyInit(plan, { force: true, base: w.base, rootUid: UID }), /etc\/mago-ski\/gate must be owned by root/u);
  assert.equal((await stat(p.configDir)).mode & 0o777, 0o775);
  assert.equal(await readFile(p.hostConfig, 'utf8'), 'theirs\n');
  assert.equal(await exists(p.instance), false);
  assert.equal(await exists(path.join(p.stateRoot, 'state')), false);
  // a writable ancestor of a folder that does not exist yet
  await chmod(p.configDir, 0o755);
  await mkdir(path.join(w.base, 'var', 'lib'), { recursive: true });
  await chmod(path.join(w.base, 'var', 'lib'), 0o777);
  await assert.rejects(applyInit(plan, { force: true, base: w.base, rootUid: UID }), /var\/lib must be owned by root/u);
  assert.equal(await exists(p.instance), false);
});

test('an existing state folder at 0755 becomes 0700 (fchmod)', async (t) => {
  const w = await world(t);
  const p = instancePaths('claude-code', w.base);
  await mkdir(p.stateDir, { recursive: true });
  await chmod(p.stateDir, 0o755);
  await applyInit(await planInit(w.opts('claude-code')), { base: w.base, rootUid: UID });
  assert.equal((await stat(p.stateDir)).mode & 0o777, 0o700);
});

test('the shared manifest merges entries and an unreadable manifest counts as foreign', async (t) => {
  const w = await world(t);
  const p = instancePaths('claude-code', w.base);
  await mkdir(p.configDir, { recursive: true });
  await writeFile(p.sharedManifest, JSON.stringify({ v: 1, files: [{ path: '/other/unit', sha256: `sha256:${'00'.repeat(32)}` }] }));
  const plan = await planInit(w.opts('claude-code'));
  assert.ok(plan.foreign.includes(p.sharedManifest)); // not canonical JSON: not ours
  await writeFile(p.sharedManifest, serializeCanonicalJson({ v: 1, files: [{ path: '/other/unit', sha256: `sha256:${'00'.repeat(32)}` }] }));
  const merged = await planInit(w.opts('claude-code'));
  const entry = JSON.parse(merged.files.find((f) => f.role === 'shared-manifest')!.content) as { files: { path: string }[] };
  assert.deepEqual(entry.files.map((f) => f.path).sort(), ['/other/unit', p.unit].sort());
});

test('host binary choice: root PATH only, name must start with the host, ELF and root-owned; the summary prints host_exes', async (t) => {
  const w = await world(t);
  // a `claude` that is really python3 (a symlink to a differently named ELF): refused without --host-exe
  const dir = path.join(w.base, 'usr', 'sbin');
  await mkdir(dir, { recursive: true });
  const python = path.join(dir, 'python3');
  await writeFile(python, Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0, 0, 0, 0]));
  const link = path.join(dir, 'claude');
  await symlink(python, link);
  const refused = await planInit(w.opts('claude-code', { hostExes: undefined as never, resolveHostExe: () => link }));
  assert.match(refused.problems.join('\n'), /python3.*is not named claude\*.*--host-exe/u);
  // given explicitly, the same binary is accepted
  const explicit = await planInit(w.opts('claude-code', { hostExes: [link] }));
  assert.deepEqual(explicit.problems, []);
  assert.deepEqual(explicit.hostExes, [python]);
  // a versioned name is fine by default
  const versioned = path.join(dir, 'claude-2.1');
  await writeFile(versioned, Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0, 0, 0, 0]));
  assert.deepEqual((await planInit(w.opts('claude-code', { hostExes: undefined as never, resolveHostExe: () => versioned }))).problems, []);
  // the default lookup uses root's PATH, never SUDO_USER
  const oldPath = process.env['PATH'];
  const oldSudo = process.env['SUDO_USER'];
  process.env['PATH'] = '/nonexistent-dir';
  process.env['SUDO_USER'] = 'nobody';
  try { assert.throws(() => defaultHostExe('codex'), /was not found on root's PATH; pass --host-exe PATH/u); }
  finally { process.env['PATH'] = oldPath; if (oldSudo === undefined) delete process.env['SUDO_USER']; else process.env['SUDO_USER'] = oldSudo; }
  // the CLI prints the chosen binaries, in text and in JSON
  const text = await run(w, ['gate', 'init', '--host', 'claude-code', '--root-fingerprint', FP, '--host-exe', w.exe]);
  assert.ok(text.stdout.includes(`host binaries: ${w.exe}`));
  const json = await run(w, ['gate', 'init', '--host', 'codex', '--root-fingerprint', FP, '--host-exe', w.exe, '--json']);
  assert.deepEqual(JSON.parse(json.stdout).host_exes, [w.exe]);
});

/* --------------------------------------------------------------------------------------- trust of the install */

test('checkRootOwnedTree names the first bad path; symlinks, writable entries and the wrong owner are refused', async (t) => {
  const w = await world(t);
  const dist = path.join(w.installRoot, 'dist');
  await checkRootOwnedTree(dist, UID, w.base);
  await checkRootOwnedChain(path.join(w.installRoot, 'package.json'), UID, w.base);
  const hook = path.join(dist, 'src', 'gate', 'adapters', 'claude-code-hook.js');
  await chmod(hook, 0o666);
  await assert.rejects(checkRootOwnedTree(dist, UID, w.base), new RegExp(`${hook.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&')} must be owned by root and not writable by others: an editable hook file would let a user bypass the gate`, 'u'));
  await chmod(hook, 0o644);
  await symlink(hook, path.join(dist, 'link.js'));
  await assert.rejects(checkRootOwnedTree(dist, UID, w.base), /link\.js is a symlink/u);
  await assert.rejects(checkRootOwnedTree(w.installRoot, UID + 1, w.base), /must be owned by root/u);
  await chmod(path.join(w.base, 'usr', 'lib'), 0o775); // a writable parent folder
  await assert.rejects(checkRootOwnedChain(w.installRoot, UID, w.base), /usr\/lib must be owned by root/u);
  await chmod(path.join(w.base, 'usr', 'lib'), 0o755);
});

test('planInit reports an editable install and a script host binary as problems, and applyInit refuses them', async (t) => {
  const w = await world(t);
  await chmod(path.join(w.installRoot, 'dist', 'src', 'cli.js'), 0o666);
  const script = path.join(w.base, 'usr', 'bin', 'script');
  await writeFile(script, '#!/bin/sh\n');
  const plan = await planInit(w.opts('claude-code', { hostExes: [script] }));
  assert.equal(plan.problems.length, 2);
  assert.match(plan.problems.join('\n'), /cli\.js must be owned by root and not writable by others: an editable hook file/u);
  assert.match(plan.problems.join('\n'), /not an ELF executable.*pass --host-exe PATH/u);
  await assert.rejects(applyInit(plan, { base: w.base, rootUid: UID }), /cli\.js/u);
  assert.equal(await exists(instancePaths('claude-code', w.base).instance), false);
  await assert.rejects(planInit(w.opts('claude-code', { hostExes: [w.exe], installRoot: path.join(w.base, 'a b') })), /not allowed/u);
});

/* ----------------------------------------------------------------------------------------- instance config */

test('instance config validation: unknown keys, wrong types, permissions', async (t) => {
  const w = await world(t);
  const plan = await planInit(w.opts('claude-code'));
  const good = JSON.parse(plan.files[0]!.content);
  assert.equal(parseInstanceConfig(good).host, 'claude-code');
  for (const [mutate, re] of [
    [(c: any) => { c.extra = 1; }, /unknown keys: extra/u], [(c: any) => { delete c.mode; }, /missing keys: mode/u],
    [(c: any) => { c.mode = 'audit'; }, /mode/u], [(c: any) => { c.host = 'pi'; }, /host/u], [(c: any) => { c.v = 2; }, /v must be 1/u],
    [(c: any) => { c.root_fingerprint = 'abc'; }, /root_fingerprint/u], [(c: any) => { c.host_exes = []; }, /host_exes/u],
    [(c: any) => { c.state_dir = 'relative'; }, /state_dir/u], [(c: any) => { c.inbox_dir = 5; }, /inbox_dir/u], [(c: any) => { c.build_id = 5; }, /build_id/u],
  ] as const) {
    const bad = structuredClone(good);
    mutate(bad);
    assert.throws(() => parseInstanceConfig(bad), re);
  }
  assert.throws(() => parseInstanceConfig([]), /object/u);
  const p = instancePaths('claude-code', w.base);
  await applyInit(plan, { base: w.base, rootUid: UID });
  const cfg = await readInstanceConfig(p.instance, UID);
  assert.deepEqual(instanceToServiceConfig(cfg, UID), {
    stateDir: p.stateDir, generationsDir: p.generationsDir, managedDir: p.managedDir, decisionSocketDir: p.decisionSocketDir, adminSocketDir: p.adminSocketDir,
    rootFingerprint: FP, mode: 'shadow', hostExes: [w.exe], rootUid: UID, buildId: 'mago-ski 0.2.0',
  });
  assert.equal(instanceToServiceConfig({ ...cfg, inbox_dir: '/in' }, UID).inboxDir, '/in');
  await assert.rejects(readInstanceConfig(p.instance, UID + 1), /owned by root/u);
  await chmod(p.instance, 0o664);
  await assert.rejects(readInstanceConfig(p.instance, UID), /not writable by group or others/u);
});

/* -------------------------------------------------------------------------------------------------- the CLI */

test('gate CLI: help, usage errors, non-Linux and non-root refusals, --print writes nothing', async (t) => {
  const w = await world(t);
  const help = await run(w, ['gate', '--help']);
  assert.equal(help.result, 0);
  assert.match(help.stdout, /mago-ski gate <command>/u);
  assert.equal((await run(w, ['gate'])).stdout, help.stdout);
  assert.match((await run(w, ['help', 'gate', 'init'])).stdout, /Usage: mago-ski gate init/u);
  for (const sub of ['init', 'run', 'trust', 'install', 'uninstall', 'refresh', 'status', 'doctor'])
    assert.match((await run(w, ['gate', sub, '--help'])).stdout, new RegExp(`Usage: mago-ski gate ${sub}`, 'u'));
  assert.match((await run(w, ['--help'])).stdout, /COMPANY GATE \(Linux, run as root\)/u);

  await assert.rejects(run(w, ['gate', 'nope']), /Unknown gate command/u);
  await assert.rejects(run(w, ['gate', 'init', '--root-fingerprint', FP]), /--host is required/u);
  await assert.rejects(run(w, ['gate', 'init', '--host', 'pi', '--root-fingerprint', FP]), /--host must be claude-code or codex/u);
  await assert.rejects(run(w, ['gate', 'init', '--host', 'codex', '--root-fingerprint', FP, '--mode', 'loud']), /--mode must be/u);
  await assert.rejects(run(w, ['gate', 'status', '--host', 'codex', '--force']), /Unsupported option --force/u);
  await assert.rejects(run(w, ['gate', 'doctor', '--host', 'codex'], { platform: 'darwin' }), /Linux only/u);
  await assert.rejects(run(w, ['gate', 'init', '--host', 'claude-code', '--root-fingerprint', FP, '--host-exe', w.exe], { uid: UID + 1 }), /administered as root; run this with sudo/u);
  await assert.rejects(run(w, ['gate', 'init', '--host', 'codex', '--root-fingerprint', FP, '--mode', 'enforce', '--host-exe', w.exe]), /Codex enforcement is not complete yet/u);

  // --print: no root needed, every file shown, nothing written
  const printed = await run(w, ['gate', 'init', '--host', 'claude-code', '--root-fingerprint', FP, '--host-exe', w.exe, '--print'], { uid: UID + 1 });
  assert.equal(printed.result, 0);
  assert.match(printed.stdout, /# .*\/etc\/claude-code\/managed-settings\.json \(mode 0644\)/u);
  assert.match(printed.stdout, /# .*claude-code\.manifest\.json/u);
  assert.equal(await exists(path.join(w.base, 'etc')), false);
  // --print with a plan that init would refuse: everything is printed, then exit 1
  const script = path.join(w.base, 'usr', 'bin', 'script');
  await writeFile(script, '#!/bin/sh\n');
  const bad = await run(w, ['gate', 'init', '--host', 'claude-code', '--root-fingerprint', FP, '--host-exe', script, '--print']);
  assert.equal(bad.result, 1);
  assert.match(bad.stdout, /# .*managed-settings\.json/u);
  assert.match(bad.stderr, /warning: .*not an ELF/u);
  // --force and --print belong to gate init only
  for (const flag of ['--force', '--print']) {
    await assert.rejects(run(w, ['gate', 'doctor', '--host', 'codex', flag]), new RegExp(`Unsupported option ${flag}`, 'u'));
    await assert.rejects(run(w, ['gate', 'run', '--host', 'codex', flag]), new RegExp(`Unsupported option ${flag}`, 'u'));
    await assert.rejects(runCli(['verify-all', flag]), new RegExp(`Unsupported option ${flag}`, 'u'));
  }
  const asJson = await run(w, ['gate', 'init', '--host', 'codex', '--root-fingerprint', FP, '--host-exe', w.exe, '--print', '--json']);
  assert.equal(JSON.parse(asJson.stdout).length, 7);
  assert.equal(await exists(path.join(w.base, 'etc')), false);
});

test('gate init through the CLI writes, refuses a foreign file, and --force keeps a backup', async (t) => {
  const w = await world(t);
  const args = ['gate', 'init', '--host', 'claude-code', '--root-fingerprint', FP, '--host-exe', w.exe];
  const first = await run(w, args);
  assert.equal(first.result, 0);
  assert.match(first.stdout, /wrote .*claude-code\.json/u);
  assert.match(first.stdout, /systemctl daemon-reload && systemctl enable --now mago-ski-gate@claude-code/u);
  const settings = instancePaths('claude-code', w.base).hostConfig;
  await writeFile(settings, 'x\n');
  await assert.rejects(run(w, args), /was not written by mago-ski/u);
  const forced = await run(w, [...args, '--force', '--mode', 'enforce']);
  assert.match(forced.stdout, /moved .*managed-settings\.json -> .*mago-ski-bak-/u);
  assert.match(forced.stdout, /systemctl restart mago-ski-gate@claude-code/u);
  assert.match(await readFile(settings, 'utf8'), /allowManagedHooksOnly/u);
});

/** An admin client stub that records requests. */
function stub(reply: (cmd: Record<string, unknown>) => unknown): { ask: AskAdmin; seen: Record<string, unknown>[] } {
  const seen: Record<string, unknown>[] = [];
  return { seen, ask: async (_s, cmd) => { seen.push(cmd); return reply(cmd) as never; } };
}

test('gate trust, install, uninstall, refresh and status send the right requests and map replies to exit codes', async (t) => {
  const w = await world(t);
  await run(w, ['gate', 'init', '--host', 'claude-code', '--root-fingerprint', FP, '--host-exe', w.exe, '--inbox', `${w.base}/inbox`]);
  const dir = await tempDir(t);
  const trust = path.join(dir, 't.json');
  const rev = path.join(dir, 'r.json');
  const cert = path.join(dir, 'c.json');
  await writeFile(trust, 'T'); await writeFile(rev, 'R'); await writeFile(cert, 'C');
  const skill = path.join(dir, 'my-skill');
  await mkdir(skill);
  const p = instancePaths('claude-code', w.base);

  const ok = stub((c) => (c['cmd'] === 'status'
    ? { v: 1, ok: true, mode: 'shadow', ready: true, trust: 'ready', revocationsExpiresAt: '2027-01-01T00:00:00Z', log: { state: 'ready' } }
    : c['cmd'] === 'install' ? { v: 1, ok: true, digest: `sha256:${'cd'.repeat(32)}`, created: true } : { v: 1, ok: true, changed: true, result: 'unchanged' }));
  const go = (argv: string[]) => run(w, ['gate', ...argv, '--host', 'claude-code'], { ask: ok.ask });
  assert.equal((await go(['trust', '--trust-root', trust, '--revocations', rev])).result, 0);
  assert.deepEqual(ok.seen.at(-1), { cmd: 'accept-trust', trust_root_b64: Buffer.from('T').toString('base64'), revocations_b64: Buffer.from('R').toString('base64') });
  const inst = await go(['install', skill, '--certificate', cert]);
  assert.equal(inst.result, 0);
  assert.deepEqual(ok.seen.at(-1), { cmd: 'install', skill_name: 'my-skill', source_dir: skill, certificate_b64: Buffer.from('C').toString('base64') });
  assert.match(inst.stdout, new RegExp(`installed my-skill digest=sha256:${'cd'.repeat(32)} path=${p.managedDir}/my-skill`, 'u'));
  await go(['install', skill, '--certificate', cert, '--name', 'other']);
  assert.equal(ok.seen.at(-1)!['skill_name'], 'other');
  assert.equal((await go(['uninstall', 'my-skill'])).result, 0);
  assert.deepEqual(ok.seen.at(-1), { cmd: 'uninstall', skill_name: 'my-skill' });
  assert.match((await go(['refresh'])).stdout, /refresh: unchanged/u);
  const status = await go(['status']);
  assert.match(status.stdout, /mode: shadow\nready: true\ntrust: ready/u);
  assert.equal(JSON.parse((await go(['status', '--json'])).stdout).trust, 'ready');
  assert.equal(status.result, 0);
  const notReady = stub(() => ({ v: 1, ok: true, mode: 'shadow', ready: false, trust: 'unavailable', revocationsExpiresAt: null, log: { state: 'degraded' } }));
  const down = await run(w, ['gate', 'status', '--host', 'claude-code'], { ask: notReady.ask });
  assert.equal(down.result, 1);
  assert.match(down.stdout, /ready: false/u);
  assert.equal((await run(w, ['gate', 'status', '--host', 'claude-code', '--json'], { ask: notReady.ask })).result, 1);
  await assert.rejects(run(w, ['gate', 'status', '--host', 'claude-code'], { ask: ok.ask, uid: UID + 1 }), /needs root/u);
  await assert.rejects(run(w, ['gate', 'trust', '--host', 'claude-code', '--trust-root', trust, '--revocations', rev], { ask: ok.ask, uid: UID + 1 }), /run this with sudo/u);

  // the gate refusing is exit 1 with its reason; no inbox is exit 2; transport errors throw (exit 2)
  const refusing = stub(() => ({ v: 1, ok: false, error: 'trust-root: nope' }));
  const refused = await run(w, ['gate', 'trust', '--host', 'claude-code', '--trust-root', trust, '--revocations', rev], { ask: refusing.ask });
  assert.equal(refused.result, 1);
  assert.match(refused.stderr, /the gate refused: trust-root: nope/u);
  const noInbox = stub(() => ({ v: 1, ok: false, error: 'no inbox configured' }));
  const r2 = await run(w, ['gate', 'refresh', '--host', 'claude-code'], { ask: noInbox.ask });
  assert.equal(r2.result, 2);
  assert.match(r2.stderr, /no inbox configured/u);
  await assert.rejects(run(w, ['gate', 'refresh', '--host', 'claude-code'], { ask: async () => { throw new Error('cannot reach the gate'); } }), /cannot reach the gate/u);
  await assert.rejects(run(w, ['gate', 'refresh', '--host', 'codex'], { ask: ok.ask }), /no gate instance for codex; run mago-ski gate init --host codex/u); // no instance config for that host
});

/* ------------------------------------------------------------------------------------ the service round trips */

/** init into the temporary base, then make the run folder (systemd does that in production). */
async function installed(t: TestContext, host: Host = 'claude-code'): Promise<World & { p: ReturnType<typeof instancePaths> }> {
  const w = await world(t);
  await applyInit(await planInit(w.opts(host)), { base: w.base, rootUid: UID });
  const p = instancePaths(host, w.base);
  await mkdir(p.decisionSocketDir, { recursive: true, mode: 0o755 });
  return Object.assign(w, { p });
}

const accept = async (svc: { handleAdmin: (c: unknown) => Promise<{ ok: boolean }> }, org: { trustRoot: string; revocations: string }) =>
  assert.equal((await svc.handleAdmin({ v: 1, cmd: 'accept-trust', trust_root_b64: (await readFile(org.trustRoot)).toString('base64'), revocations_b64: (await readFile(org.revocations)).toString('base64') })).ok, true);

test('askAdmin round trip against a started service; errors and the deadline', { skip: LINUX_ONLY }, async (t) => {
  const w = await installed(t);
  const org = await setupOrg(t, { now: new Date() });
  const cfg = await readInstanceConfig(w.p.instance, UID);
  const svc = createGateService({ ...instanceToServiceConfig(cfg, UID), rootFingerprint: org.rootKeyId, hostExes: [process.execPath] });
  await svc.start();
  t.after(() => svc.stop());
  const sock = path.join(cfg.admin_socket_dir, 'admin.sock');
  const status = await askAdmin(sock, { cmd: 'status' }, 5000);
  assert.equal(status.ok, true);
  assert.equal((status as { mode?: string }).mode, 'shadow');
  const bad = await askAdmin(sock, { cmd: 'frobnicate' }, 5000);
  assert.deepEqual(bad, { v: 1, ok: false, error: 'unknown command' });
  // install through the client
  await accept(svc, org);
  const work = await tempDir(t);
  const dir = await writeSkill(work, 'alpha');
  const issued = await approve(org, dir, { now: new Date(), out: path.join(work, 'c.json') });
  const inst = await askAdmin(sock, { cmd: 'install', skill_name: 'alpha', source_dir: dir, certificate_b64: (await readFile(issued.path)).toString('base64') }, 20_000);
  assert.equal(inst.ok, true);
  assert.equal((inst as { digest?: string }).digest, issued.digest);

  await assert.rejects(askAdmin(path.join(w.base, 'nothing.sock'), { cmd: 'status' }, 1000), /cannot reach the gate/u);
  const silent = path.join(w.base, 's.sock');
  const server = net.createServer(() => {});
  await new Promise<void>((r) => server.listen(silent, r));
  t.after(() => { server.close(); });
  await assert.rejects(askAdmin(silent, { cmd: 'status' }, 100), new RegExp(TIMEOUT_MESSAGE, 'u'));
});

test('doctor against a started test layout: PASS, then each kind of FAIL and the SKIPs', { skip: LINUX_ONLY }, async (t) => {
  const w = await installed(t);
  const org = await setupOrg(t, { now: new Date() });
  await applyInit(await planInit(w.opts('claude-code', { rootFingerprint: org.rootKeyId })), { base: w.base, rootUid: UID }); // the instance names this org's root
  const dopts = { base: w.base, rootUid: UID, installRoot: w.installRoot, nodePath: w.seams.nodePath!, envPath: w.seams.envPath!, checkExec: false, somaxconn: async () => 4096, procMounts: async () => 'proc /proc proc rw 0 0\n' };
  const byName = (cs: Awaited<ReturnType<typeof doctor>>) => Object.fromEntries(cs.map((c) => [c.check, c]));

  // service not running: the folders and files pass, the service fails
  const down = byName(await doctor('claude-code', dopts));
  assert.equal(down['instance config']!.result, 'PASS');
  assert.equal(down['host config']!.result, 'PASS');
  assert.equal(down['hook config']!.result, 'PASS');
  assert.equal(down['service']!.result, 'FAIL');
  assert.equal(down['trust']!.result, 'SKIP');
  assert.equal(down['mode']!.result, 'WARN'); // shadow is a note, not a failure

  const cfg = await readInstanceConfig(w.p.instance, UID);
  const svc = createGateService({ ...instanceToServiceConfig(cfg, UID), rootFingerprint: org.rootKeyId, hostExes: [process.execPath] });
  await svc.start();
  t.after(() => svc.stop());
  const up = byName(await doctor('claude-code', dopts));
  assert.equal(up['service']!.result, 'PASS', up['service']!.detail);
  assert.equal(up['trust']!.result, 'FAIL'); // not accepted yet
  await accept(svc, org);
  const trusted = byName(await doctor('claude-code', dopts));
  assert.equal(trusted['trust']!.result, 'PASS');
  assert.ok(Object.values(trusted).every((c) => c.result !== 'FAIL'), JSON.stringify(trusted));
  assert.equal(trusted['node']!.result, 'SKIP');
  for (const name of ['unit', 'drop-in', 'hook config', 'root fingerprint', 'host config'])
    assert.equal(trusted[name]!.result, 'PASS', name);

  // another owner: every ownership check FAILs (rootUid + 1), and the service queries are skipped when the admin socket is not trusted
  const foreign = byName(await doctor('claude-code', { ...dopts, rootUid: UID + 1 }));
  assert.equal(foreign['instance config']!.result, 'FAIL');
  assert.equal(foreign['managed folder']!.result, 'SKIP');
  const owned = byName(await doctor('claude-code', { ...dopts, rootUid: UID + 1, uid: UID + 1 }));
  assert.equal(owned['instance config']!.result, 'FAIL');
  assert.match(owned['instance config']!.detail, /must be owned by root/u);
  const adminDir = cfg.admin_socket_dir;
  await chmod(adminDir, 0o750);
  const loose = byName(await doctor('claude-code', dopts));
  assert.equal(loose['admin socket']!.result, 'FAIL');
  assert.match(loose['admin socket']!.detail, /mode 0700/u);
  assert.equal(loose['service']!.result, 'SKIP');
  assert.equal(loose['trust']!.result, 'SKIP');
  await chmod(adminDir, 0o700);

  // the unit, the drop-in and the hook config are compared with the plan; a symlink is not a root-owned regular file
  const sourceUnit = await readFile(w.p.unit, 'utf8');
  await writeFile(w.p.unit, `${sourceUnit}# edited\n`);
  await writeFile(w.p.dropin, '[Service]\nReadWritePaths=/\n');
  const edited = byName(await doctor('claude-code', dopts));
  assert.equal(edited['unit']!.result, 'FAIL');
  assert.equal(edited['drop-in']!.result, 'FAIL');
  await writeFile(w.p.unit, sourceUnit);
  await applyInit(await planInit(w.opts('claude-code', { rootFingerprint: org.rootKeyId })), { base: w.base, rootUid: UID, force: true });
  const hookText = await readFile(w.p.hook, 'utf8');
  await rm(w.p.hook);
  await symlink(path.join(w.base, 'elsewhere.json'), w.p.hook);
  await writeFile(path.join(w.base, 'elsewhere.json'), hookText);
  const linked = byName(await doctor('claude-code', dopts));
  assert.equal(linked['hook config']!.result, 'FAIL');
  assert.match(linked['hook config']!.detail, /symlink/u);
  await rm(w.p.hook);
  await writeFile(w.p.hook, hookText);

  // the service's root fingerprint must match the instance config
  const wrongRoot = await doctor('claude-code', { ...dopts, ask: async () => ({ v: 1, ok: true, ready: true, mode: 'shadow', trust: 'ready', root_fingerprint: FP, log: { state: 'ready' } }) });
  assert.equal(byName(wrongRoot)['root fingerprint']!.result, 'FAIL');
  assert.match(byName(wrongRoot)['root fingerprint']!.detail, /instance config says/u);

  // not root: the service checks are skipped
  const user = byName(await doctor('claude-code', { ...dopts, uid: UID + 1 }));
  assert.equal(user['service']!.result, 'SKIP');
  assert.equal(user['trust']!.result, 'SKIP');
  assert.match(user['service']!.detail, /needs root/u);

  // an edited host file, a world-writable managed folder, a status in another mode, kernel warnings
  await writeFile(w.p.hostConfig, '{}\n');
  await chmod(cfg.managed_dir, 0o777);
  const broken = byName(await doctor('claude-code', { ...dopts, somaxconn: async () => 128, procMounts: async () => 'proc /proc proc rw,hidepid=2 0 0\n' }));
  assert.equal(broken['host config']!.result, 'FAIL');
  assert.equal(broken['managed folder']!.result, 'FAIL');
  assert.equal(broken['somaxconn']!.result, 'WARN');
  assert.equal(broken['proc mount']!.result, 'WARN');
  await chmod(cfg.managed_dir, 0o755);

  const other = await doctor('claude-code', { ...dopts, ask: async () => ({ v: 1, ok: true, ready: true, mode: 'enforce', trust: 'ready', root_fingerprint: org.rootKeyId, log: { state: 'ready' } }) });
  assert.equal(byName(other)['mode']!.result, 'FAIL');
  assert.match(byName(other)['mode']!.detail, /service runs in enforce/u);

  // the CLI: exit 1 on a FAIL, 0 otherwise; json shape
  const failing = await run(w, ['gate', 'doctor', '--host', 'claude-code', '--json'], { checkExec: false, ...{ doctor: { somaxconn: async () => 4096, procMounts: async () => '' } } });
  assert.equal(failing.result, 1);
  assert.ok(JSON.parse(failing.stdout).every((c: Record<string, unknown>) => typeof c['check'] === 'string' && typeof c['detail'] === 'string'));
  const missing = await run(w, ['gate', 'doctor', '--host', 'codex'], { checkExec: false });
  assert.equal(missing.result, 1);
  assert.match(missing.stdout, /^FAIL instance config:/mu);
  assert.match(missing.stdout, /^SKIP service: no usable instance config/mu);
});

test('doctor refuses a non-Linux platform in one line', async (t) => {
  const w = await world(t);
  const checks = await doctor('codex', { base: w.base, rootUid: UID, platform: 'darwin' });
  assert.equal(checks.length, 1);
  assert.equal(checks[0]!.result, 'FAIL');
  assert.match(checks[0]!.detail, /Linux only/u);
});

test('gate run: serves the admin socket and stops on request; start errors are reported by status and on stderr (G6)', { skip: LINUX_ONLY }, async (t) => {
  const w = await installed(t);
  const sock = path.join(w.p.adminSocketDir, 'admin.sock');
  const until = async (fn: () => Promise<boolean>): Promise<void> => { for (let i = 0; i < 100 && !(await fn()); i++) await new Promise((r) => setTimeout(r, 50)); };

  // a healthy instance
  let stop!: () => void;
  const stopped = new Promise<void>((r) => { stop = r; });
  const running = run(w, ['gate', 'run', '--host', 'claude-code'], { stop: stopped });
  await until(() => exists(sock));
  const ok = await askAdmin(sock, { cmd: 'status' }, 5000);
  assert.equal(ok.ok, true);
  stop();
  const done = await running;
  assert.equal(done.result, 0);
  assert.match(done.stderr, /listening on .*decision\.sock/u);
  assert.equal(done.stderr.includes('not ready'), false);

  // a state folder with unsafe permissions: the service stays up and not ready, and says why
  await chmod(w.p.stateDir, 0o755);
  let stop2!: () => void;
  const stopped2 = new Promise<void>((r) => { stop2 = r; });
  const running2 = run(w, ['gate', 'run', '--host', 'claude-code'], { stop: stopped2 });
  await until(() => exists(sock));
  const bad = await askAdmin(sock, { cmd: 'status' }, 5000);
  assert.equal(bad.ok, false);
  assert.match((bad as { error: string }).error, /^service is not ready: .*unsafe permissions/u);
  stop2();
  const done2 = await running2;
  assert.equal(done2.result, 0);
  assert.match(done2.stderr, /running but not ready: .*unsafe permissions/u);

  // an instance config that is not there: refused before anything starts
  await assert.rejects(run(w, ['gate', 'run', '--host', 'codex'], { stop: Promise.resolve() }), /no gate instance for codex; run mago-ski gate init --host codex/u);
});

test('gate run: when start() throws, the service is stopped and the exit code is 1', { skip: LINUX_ONLY }, async (t) => {
  const w = await world(t);
  await applyInit(await planInit(w.opts('claude-code')), { base: w.base, rootUid: UID }); // no run folder: the service cannot create its socket folders
  const done = await run(w, ['gate', 'run', '--host', 'claude-code'], { stop: new Promise<void>(() => {}) });
  assert.equal(done.result, 1);
  assert.match(done.stderr, /cannot start/u);
});
