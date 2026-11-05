// Shared parts of the gate's live tests (tests/live/*.live.ts): a private mount namespace, a throwaway organisation,
// and the real gate service with the admin commands an administrator would use. Host-specific parts (the host's
// managed configuration, the faux model, the scenarios) stay in each live test.
import { execFileSync, spawn } from 'node:child_process';
import { existsSync, realpathSync } from 'node:fs';
import { chmod, mkdir, mkdtemp, readFile, rmdir, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { addApprover, approveSkill, initRoot, updateRevocations } from '../../src/admin.ts';
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
  /** The host's real binary, as /proc/<pid>/exe shows it. */
  hostExe: string;
  /** The folder the host loads admin Skills from: the gate's managedDir. */
  managedDir: string;
  /** Writes the hook config and the host's managed configuration for this service. */
  configure: (service: GateService, mode: Mode, stateDir: string) => Promise<void>;
}

export interface GateWorld {
  root: string;
  mode: Mode;
  service: GateService | null;
  start: (mode: Mode) => Promise<void>;
  stop: () => Promise<void>;
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
  let generation = 0;

  const w: GateWorld = {
    root, mode: 'enforce', service: null,
    async start(mode) {
      generation += 1;
      const state = path.join(root, `gate-${generation}`);
      await mkdir(state, { mode: 0o755 });
      w.mode = mode;
      w.service = createGateService({
        stateDir: path.join(state, 'state'), generationsDir: path.join(state, 'gens'), managedDir: host.managedDir,
        decisionSocketDir: path.join(state, 'dec'), adminSocketDir: path.join(state, 'adm'),
        rootFingerprint: rootPair.keyId, mode, hostExes: [host.hostExe], rootUid: 0,
      });
      await w.service.start();
      const accepted = await w.service.handleAdmin({ v: 1, cmd: 'accept-trust', trust_root_b64: await b64(trustRoot), revocations_b64: await b64(revocations) });
      if (!accepted.ok) throw new Error(`accept-trust: ${accepted.error}`);
      await host.configure(w.service, mode, state);
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
