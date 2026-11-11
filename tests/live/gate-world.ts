// Shared parts of the gate's live tests (tests/live/*.live.ts): a private mount namespace, a throwaway organisation,
// and the real gate service with the admin commands an administrator would use. Host-specific parts (the host's
// managed configuration, the faux model, the scenarios) stay in each live test.
//
// The gate is installed with the shipped commands' own functions: `planInit` and `applyInit` write the instance config, hook
// config, unit, drop-in, the host's settings and the manifests into a temporary `base` folder (inside the private mount
// namespace; each live test bind-mounts `<base>/etc/<host>` over the host's own /etc folder), and the service is started
// from the instance config that `init` wrote. The installed package is a root-owned copy of the repository's built `dist`
// and package.json under `<base>`, so the whole-tree ownership check of `init` is met without weakening it. `checkExec: false`
// applies only to the node binary and /usr/bin/env, which live outside `<base>` (they are the machine's own). Run
// `npm run build` first. Codex enforcement is refused by `init` (audit-level in this release), so the Codex live test
// plans in shadow mode and puts the live mode on the service and the hook config by hand.
import { execFileSync, spawn } from 'node:child_process';
import { existsSync, realpathSync } from 'node:fs';
import { chmod, cp, mkdir, mkdtemp, readdir, readFile, rm, rmdir, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { addApprover, approveSkill, initRoot, updateRevocations } from '../../src/admin.ts';
import { instancePaths, instanceToServiceConfig, readInstanceConfig, type Host } from '../../src/gate/instance.ts';
import { applyInit, hookConfigText, planInit } from '../../src/gate/setup.ts';
import { createGateService, type GateService } from '../../src/gate/service.ts';
import { generateKeyPair } from '../../src/keys.ts';
import type { Mode } from '../../src/policy.ts';

export const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
export const NODE = realpathSync(process.execPath);
export const MARK = (name: string): string => `SECRET-BODY-${name}`;

/**
 * MAGO_LIVE_USER runs the host (claude, codex) and so its hooks as that unprivileged user, as in a real deployment;
 * the gate service stays root. Unset: the host runs as root too.
 */
export const HOST_USER = process.env.MAGO_LIVE_USER || null;

/** The command and arguments that start `cmd` as HOST_USER (through setpriv), or unchanged. */
export function asHostUser(cmd: string, args: string[]): [string, string[]] {
  if (!HOST_USER) return [cmd, args];
  return ['setpriv', [`--reuid=${HOST_USER}`, `--regid=${HOST_USER}`, '--init-groups', '--', cmd, ...args]];
}

/** Gives the host user the folders it works in (its home and project). */
export function handOver(...paths: string[]): void {
  if (HOST_USER) for (const p of paths) execFileSync('chown', ['-R', `${HOST_USER}:${HOST_USER}`, p]);
}

/**
 * Runs `main` inside a private mount namespace (re-running the script under `unshare --mount`), so bind mounts over
 * /etc/<host> never reach the rest of the machine. Without root, prints a skip report and exits 0.
 */
export async function inPrivateMountNamespace(scriptUrl: string, main: () => Promise<void>): Promise<void> {
  if (process.env.MAGO_LIVE_NS === '1') return await main();
  if (process.getuid?.() !== 0) {
    console.log(JSON.stringify({ skipped: 'needs root (the host reads its managed configuration from /etc)' }));
    return;
  }
  const child = spawn('unshare', ['--mount', '--propagation', 'private', NODE, fileURLToPath(scriptUrl), ...process.argv.slice(2)], {
    stdio: 'inherit', env: { ...process.env, MAGO_LIVE_NS: '1' },
  });
  process.exitCode = await new Promise<number>((resolve) => child.on('close', (code) => resolve(code ?? 1)));
}

/** Bind-mounts a fresh folder over `target` (this namespace only). Returns the cleanup. */
export async function overlay(target: string, source: string): Promise<() => Promise<void>> {
  await mkdir(source, { recursive: true, mode: 0o755 });
  const created = !existsSync(target);
  await mkdir(target, { recursive: true });
  execFileSync('mount', ['--bind', source, target]);
  return async () => {
    execFileSync('umount', [target]);
    if (created) await rmdir(target).catch(() => {}); // the empty mount point this run created
  };
}

export async function writeSkill(dir: string, name: string): Promise<string> {
  const skill = path.join(dir, name);
  await mkdir(skill, { recursive: true });
  await writeFile(path.join(skill, 'SKILL.md'), `---\nname: ${name}\ndescription: Live-test Skill ${name}.\n---\n# ${name}\n${MARK(name)}\n`);
  return skill;
}

export interface HostSetup {
  host: Host;
  /** The host's real binary, as /proc/<pid>/exe shows it. */
  hostExe: string;
}

/** The temporary `base` of a live root: what `gate init` writes under, and what each live test bind-mounts the host's /etc folder from. */
export const liveBase = (root: string): string => path.join(root, 'base');

/** A root-owned copy of the built package under `base` (the install root `init` checks). */
async function installPackage(base: string): Promise<string> {
  const installRoot = path.join(base, 'usr', 'lib', 'node_modules', '@mago-foundation', 'mago-ski');
  if (!existsSync(path.join(REPO, 'dist', 'src', 'cli.js'))) throw new Error('dist/ is missing: run npm run build first');
  await mkdir(installRoot, { recursive: true });
  await cp(path.join(REPO, 'dist'), path.join(installRoot, 'dist'), { recursive: true });
  await cp(path.join(REPO, 'package.json'), path.join(installRoot, 'package.json'));
  execFileSync('chmod', ['-R', 'go-w', installRoot]);
  return installRoot;
}

export interface GateWorld {
  root: string;
  mode: Mode;
  service: GateService | null;
  start: (mode: Mode) => Promise<void>;
  stop: () => Promise<void>;
  /** `<base>/etc/<host>`-relative paths of this instance (config, hook config, managed folder). */
  paths: ReturnType<typeof instancePaths>;
  /** The installed hook entry (a copy of dist/ under the base), which the host settings name. */
  hookEntry: string;
  install: (name: string) => Promise<string>;
  revoke: (name: string) => Promise<unknown>;
  status: () => Promise<unknown>;
}

/** A throwaway organisation (root key, one approver) and a gate service started per mode. */
export async function gateWorld(root: string, host: HostSetup): Promise<GateWorld> {
  const keys = path.join(root, 'keys');
  await mkdir(keys, { mode: 0o700 });
  const rootPair = await generateKeyPair(path.join(keys, 'root.pem'), path.join(keys, 'root.pub'));
  const approver = await generateKeyPair(path.join(keys, 'approver.pem'), path.join(keys, 'approver.pub'));
  const trustRoot = path.join(root, 'trust-root.json');
  const revocations = path.join(root, 'revocations.json');
  const now = new Date();
  await initRoot({ rootKeyPath: rootPair.privatePath, trustRootOut: trustRoot, revocationsOut: revocations, now });
  await addApprover({ rootKeyPath: rootPair.privatePath, trustRootPath: trustRoot, now, publicKeyPath: approver.publicPath, name: 'Live reviewer', scopes: ['*'], expires: '30d' });
  const sources = path.join(root, 'sources');
  const digests = new Map<string, string>();
  const b64 = async (file: string) => (await readFile(file)).toString('base64');
  const base = liveBase(root);
  await mkdir(base, { recursive: true, mode: 0o755 });
  const installRoot = await installPackage(base);
  const paths = instancePaths(host.host, base);

  const w: GateWorld = {
    root, mode: 'enforce', service: null, paths, hookEntry: path.join(installRoot, 'dist', 'src', 'gate', 'adapters', `${host.host}-hook.js`),
    async start(mode) {
      // A fresh gate per start (as before): no state, generations or Skill links of an earlier start.
      await rm(paths.stateRoot, { recursive: true, force: true });
      await rm(paths.hostConfig, { force: true });
      if (existsSync(paths.managedDir)) for (const name of await readdir(paths.managedDir)) await rm(path.join(paths.managedDir, name), { recursive: true, force: true });
      w.mode = mode;
      const plan = await planInit({
        host: host.host, rootFingerprint: rootPair.keyId, mode: host.host === 'codex' ? 'shadow' : mode, hostExes: [host.hostExe],
        base, rootUid: 0, installRoot, nodePath: NODE, checkExec: false,
      });
      await applyInit(plan, { base, rootUid: 0 });
      const cfg = await readInstanceConfig(paths.instance, 0);
      if (host.host === 'codex') await writeFile(paths.hook, hookConfigText('codex', { ...cfg, mode }), { mode: 0o644 }); // init refuses codex enforce
      await mkdir(paths.decisionSocketDir, { recursive: true, mode: 0o755 }); // systemd's RuntimeDirectory in production
      w.service = createGateService({ ...instanceToServiceConfig(cfg, 0), mode });
      await w.service.start();
      const accepted = await w.service.handleAdmin({ v: 1, cmd: 'accept-trust', trust_root_b64: await b64(trustRoot), revocations_b64: await b64(revocations) });
      if (!accepted.ok) throw new Error(`accept-trust: ${accepted.error}`);
    },
    async stop() {
      await w.service?.stop();
      w.service = null;
    },
    async install(name) {
      const dir = await writeSkill(sources, name);
      const out = path.join(root, `${name}.cert.json`);
      const issued = await approveSkill({ skillDir: dir, approverKeyPath: approver.privatePath, now: new Date(), expires: '7d', reason: 'live test', out });
      digests.set(name, issued.digest);
      const r = await w.service!.handleAdmin({ v: 1, cmd: 'install', skill_name: name, source_dir: dir, certificate_b64: await b64(out) });
      if (!r.ok) throw new Error(`install ${name}: ${r.error}`);
      return issued.digest;
    },
    async revoke(name) {
      await updateRevocations({ rootKeyPath: rootPair.privatePath, revocationsPath: revocations, now: new Date(), revokeDigest: digests.get(name)!, reason: 'live test revoke' });
      return await w.service!.handleAdmin({ v: 1, cmd: 'accept-trust', trust_root_b64: await b64(trustRoot), revocations_b64: await b64(revocations) });
    },
    async status() {
      return await w.service?.handleAdmin({ v: 1, cmd: 'status' });
    },
  };
  return w;
}

/** A root-owned temporary folder that other users can enter (hosts and hooks run as root here, but keep it realistic). */
export async function liveRoot(prefix: string): Promise<string> {
  const root = realpathSync(await mkdtemp(path.join(os.tmpdir(), prefix)));
  await chmod(root, 0o755);
  return root;
}
