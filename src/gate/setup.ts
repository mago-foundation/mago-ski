// `mago-ski gate init` and `gate doctor` (design docs/design/gate-cli.md: v1 sections 3-6, G2-G7, G9-G10, v3 decisions).
// planInit computes everything an installation writes without touching the disk; applyInit writes it in a fixed order and
// puts a moved-aside file back if a write fails; doctor reads and reports. All functions take their environment as
// parameters (`base`, `rootUid`, `platform`, ...) so tests can run them against a temporary tree and the current user.
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { chmod, lstat, mkdir, readdir, readFile, realpath, rename } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { isRecord, parseCanonicalJsonBytes, serializeCanonicalJson } from '../canonical-json.ts';
import { readRegularFile, writeFileAtomic } from '../fs-safe.ts';
import { validateKeyId } from '../keys.ts';
import type { Mode } from '../policy.ts';
import { claudeCodeManagedSettings } from './adapters/claude-code-settings.ts';
import { codexRequirementsToml } from './adapters/codex-requirements.ts';
import { askAdmin, type AskAdmin } from './admin-client.ts';
import { MODES } from './contract.ts';
import { buildId, HOSTS, instancePaths, isHost, readInstanceConfig, type Host, type InstanceConfig } from './instance.ts';
import { assertGatePlatform } from './proc.ts';

/** What the hook may and the service must do within these limits (the values the live tests ran with). */
export const HOOK_TIMEOUT_SEC = 5;
export const SELF_DEADLINE_MS = 3000;
export const CLIENT_DEADLINE_MS = 1500;

export const CODEX_ENFORCE_REFUSAL = 'Codex enforcement is not complete yet (see docs/hosts/codex.md); use --mode shadow';

/** Same set as the two generators' SAFE_PATH: these paths go unquoted into a shell command, a TOML string and a unit file. */
const SAFE_PATH = /^\/[A-Za-z0-9._/@-]+$/u;

const sha256 = (data: string | Uint8Array): string => `sha256:${createHash('sha256').update(data).digest('hex')}`;
const errnoCode = (e: unknown): string | undefined => (e as NodeJS.ErrnoException)?.code;

/* ---------------------------------------------------------------------------------------------- trust of files */

const BYPASS = 'an editable hook file would let a user bypass the gate';
const NOT_ROOT = (p: string): string => `${p} must be owned by root and not writable by others: ${BYPASS}`;

/**
 * `target` itself and every parent folder up to and including `stopAt` must be owned by `uid`, a real folder (a parent) and
 * not writable by group or others. Not recursive: use it for folders whose contents are checked elsewhere (the managed
 * folder holds symlinks by design). Throws with the first bad path.
 */
export async function checkRootOwnedChain(target: string, uid: number, stopAt = '/'): Promise<void> {
  const stop = path.resolve(stopAt);
  let p = path.resolve(target);
  for (;;) {
    const info = await lstat(p);
    if (info.isSymbolicLink()) throw new Error(`${p} is a symlink; ${NOT_ROOT(p)}`);
    if (info.uid !== uid || (info.mode & 0o022) !== 0) throw new Error(NOT_ROOT(p));
    if (p === stop || p === path.dirname(p)) return;
    p = path.dirname(p);
  }
}

/**
 * Whole-tree check (G4): every entry under `target` (a folder or a file), and every parent up to `stopAt`, is owned by `uid`
 * and not writable by group or others. A symlink inside the tree is refused. Throws with the first bad path.
 */
export async function checkRootOwnedTree(target: string, uid: number, stopAt = '/'): Promise<void> {
  const walk = async (p: string): Promise<void> => {
    const info = await lstat(p);
    if (info.isSymbolicLink()) throw new Error(`${p} is a symlink; ${NOT_ROOT(p)}`);
    if (info.uid !== uid || (info.mode & 0o022) !== 0) throw new Error(NOT_ROOT(p));
    if (info.isDirectory()) for (const name of (await readdir(p)).sort()) await walk(path.join(p, name));
  };
  const top = path.resolve(target);
  await walk(top);
  if (top !== path.resolve(stopAt) && top !== path.dirname(top)) await checkRootOwnedChain(path.dirname(top), uid, stopAt);
}

const message = (e: unknown): string => (e instanceof Error ? e.message : String(e));

/** A host binary: a regular ELF executable (a script would allowlist its interpreter), root-owned along its whole chain. */
export async function checkHostExe(exe: string, uid: number, stopAt = '/'): Promise<void> {
  const info = await lstat(exe);
  if (!info.isFile()) throw new Error(`${exe} is not a regular file`);
  const head = (await readRegularFile(exe, 'host binary', Number.MAX_SAFE_INTEGER).then((b) => b.subarray(0, 4)));
  if (!head.equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46]))) throw new Error(`${exe} is not an ELF executable (a script would allowlist its interpreter)`);
  await checkRootOwnedChain(exe, uid, stopAt);
}

/* ------------------------------------------------------------------------------------------------ the toolchain */

export interface Toolchain {
  installRoot: string;
  /** `<install>/dist/src/gate/adapters/<host>-hook.js` */
  hookEntry: string;
  cliPath: string;
  nodePath: string;
  envPath: string;
}

export interface Seams {
  /** Root of everything the command reads and writes (`/` in production). */
  base?: string;
  /** The uid that must own everything (0 in production). */
  rootUid?: number;
  platform?: NodeJS.Platform;
  /** Root of the installed package; default: found from this module's location. */
  installRoot?: string;
  /** The node that runs the hooks and the service; default `realpath(process.execPath)`. */
  nodePath?: string;
  envPath?: string;
  /** false skips the node and env chain checks (tests: those live outside the temporary base). */
  checkExec?: boolean;
}

function findInstallRoot(): string {
  let dir = path.dirname(fileURLToPath(import.meta.url));
  while (!existsSync(path.join(dir, 'package.json'))) {
    const up = path.dirname(dir);
    if (up === dir) throw new Error('cannot find the mago-ski package root');
    dir = up;
  }
  return dir;
}

async function realOr(p: string): Promise<string> {
  return await realpath(p).catch(() => p);
}

export async function resolveToolchain(host: Host, seams: Seams): Promise<Toolchain> {
  const installRoot = await realOr(seams.installRoot ?? findInstallRoot());
  const dist = path.join(installRoot, 'dist', 'src');
  return {
    installRoot,
    hookEntry: path.join(dist, 'gate', 'adapters', `${host}-hook.js`),
    cliPath: await realOr(path.join(dist, 'cli.js')),
    nodePath: await realOr(seams.nodePath ?? process.execPath),
    envPath: seams.envPath ?? '/usr/bin/env',
  };
}

/** Every check of the install itself (G4, G12). Returns the failures as messages. */
async function toolchainProblems(host: Host, tc: Toolchain, seams: Seams): Promise<string[]> {
  const uid = seams.rootUid ?? 0;
  const stop = seams.base ?? '/';
  const out: string[] = [];
  const run = async (fn: () => Promise<void>, what: string): Promise<void> => {
    try { await fn(); } catch (e) { out.push(errnoCode(e) === 'ENOENT' ? `${what} not found (${message(e)}); run from a built, installed package` : message(e)); }
  };
  await run(() => checkRootOwnedTree(path.join(tc.installRoot, 'dist'), uid, stop), `${path.join(tc.installRoot, 'dist')}`);
  if (!existsSync(tc.hookEntry)) out.push(`${tc.hookEntry} not found for host ${host}`);
  if (seams.checkExec !== false) {
    await run(() => checkRootOwnedTree(tc.nodePath, uid, stop), tc.nodePath);
    await run(() => checkRootOwnedChain(path.join(tc.installRoot, 'package.json'), uid, stop), path.join(tc.installRoot, 'package.json'));
    await run(() => checkRootOwnedChain(tc.envPath, uid, stop), tc.envPath);
  }
  return out;
}

/* --------------------------------------------------------------------------------------------- host binaries */

function loginPath(): string {
  const user = process.env['SUDO_USER'];
  if (user && /^[A-Za-z_][A-Za-z0-9_.-]{0,31}$/u.test(user) && user !== 'root') {
    try { return execFileSync('su', ['-l', user, '-c', 'printf %s "$PATH"'], { encoding: 'utf8', timeout: 5000, stdio: ['ignore', 'pipe', 'ignore'] }); } catch { /* root's PATH */ }
  }
  return process.env['PATH'] ?? '';
}

/** The host's default binary: its name on the invoking user's login PATH (SUDO_USER) when present, else root's PATH. */
export function defaultHostExe(host: Host): string {
  const name = host === 'claude-code' ? 'claude' : 'codex';
  for (const dir of loginPath().split(':')) {
    if (dir === '' || !path.isAbsolute(dir)) continue;
    const candidate = path.join(dir, name);
    if (existsSync(candidate)) return candidate;
  }
  throw new Error(`${name} was not found on PATH; pass --host-exe PATH`);
}

/* ---------------------------------------------------------------------------------------------------- planning */

export interface InitOptions extends Seams {
  host: Host;
  rootFingerprint: string;
  mode?: Mode;
  /** Absolute paths of the real host binaries; default: the host's binary on PATH. */
  hostExes?: string[];
  inbox?: string;
  /** Tests: replaces the PATH lookup of the default host binary. */
  resolveHostExe?: (host: Host) => string;
}

export type FileRole = 'instance' | 'hook' | 'unit' | 'dropin' | 'host' | 'manifest' | 'shared-manifest';
export interface PlannedFile { path: string; content: string; mode: number; role: FileRole }
export interface PlannedDir { path: string; mode: number }

export interface InitPlan {
  host: Host;
  mode: Mode;
  /** In write order: instance config, hook config, unit, drop-in, the host config, then the two manifests. */
  files: PlannedFile[];
  /** Leaf folders to create (parents first); missing parents are created `0755`. */
  dirs: PlannedDir[];
  /** Existing files that mago-ski did not write (not in either manifest). */
  foreign: string[];
  /** Refusals found while planning (untrusted install or host binary). `init` refuses to write while any remain. */
  problems: string[];
  /** True when a manifest of this host already exists (a re-run). */
  rerun: boolean;
  next: string[];
}

export function unitText(tc: Pick<Toolchain, 'nodePath' | 'cliPath'>): string {
  return [
    '[Unit]', 'Description=mago-ski gate for %i', 'After=local-fs.target', '',
    '[Service]', 'Type=simple', `ExecStart=${tc.nodePath} ${tc.cliPath} gate run --host %i`, 'Restart=on-failure',
    'RuntimeDirectory=mago-ski/gate/%i', 'RuntimeDirectoryMode=0755', 'LimitNOFILE=4096', 'ProtectSystem=strict', 'NoNewPrivileges=yes', '',
    '[Install]', 'WantedBy=multi-user.target', '',
  ].join('\n');
}

export function dropinText(cfg: Pick<InstanceConfig, 'managed_dir'>, stateRoot: string): string {
  return ['[Service]', `ReadWritePaths=${stateRoot} ${cfg.managed_dir}`, 'ReadOnlyPaths=/etc/mago-ski', ''].join('\n');
}

/** Hook config (G10): exactly these keys, plus Codex's two. */
export function hookConfigText(host: Host, cfg: InstanceConfig): string {
  return serializeCanonicalJson({
    v: 1, socket: path.join(cfg.decision_socket_dir, 'decision.sock'), mode: cfg.mode, host_exes: cfg.host_exes,
    client_deadline_ms: CLIENT_DEADLINE_MS, self_deadline_ms: SELF_DEADLINE_MS,
    ...(host === 'codex' ? { admin_root: cfg.managed_dir, skill_roots: [] } : {}),
  });
}

/** The host's own configuration file for this instance. */
export function hostConfigText(host: Host, mode: Mode, tc: Toolchain, hookConfigPath: string): string {
  const common = { mode, nodePath: tc.nodePath, hookEntry: tc.hookEntry, configPath: hookConfigPath, hookTimeoutSec: HOOK_TIMEOUT_SEC, selfDeadlineMs: SELF_DEADLINE_MS, envPath: tc.envPath };
  if (host === 'claude-code') return `${JSON.stringify(claudeCodeManagedSettings(common), null, 2)}\n`;
  return codexRequirementsToml({ ...common, userSkillRoots: [] }); // stream 2 decides the per-user roots
}

export function instanceFromOptions(o: { host: Host; mode: Mode; rootFingerprint: string; hostExes: string[]; inbox?: string | undefined; base?: string | undefined }): InstanceConfig {
  const p = instancePaths(o.host, o.base ?? '/');
  return {
    v: 1, host: o.host, mode: o.mode, root_fingerprint: o.rootFingerprint, host_exes: o.hostExes,
    state_dir: p.stateDir, generations_dir: p.generationsDir, managed_dir: p.managedDir,
    decision_socket_dir: p.decisionSocketDir, admin_socket_dir: p.adminSocketDir,
    inbox_dir: o.inbox ?? null, build_id: buildId(),
  };
}

function manifestText(files: PlannedFile[]): string {
  return serializeCanonicalJson({ v: 1, files: files.map((f) => ({ path: f.path, sha256: sha256(f.content) })).sort((a, b) => (a.path < b.path ? -1 : 1)) });
}

async function readManifest(file: string): Promise<Map<string, string> | undefined> {
  let raw: unknown;
  try { raw = parseCanonicalJsonBytes(await readRegularFile(file, 'manifest', 1024 * 1024), 'manifest'); } catch { return undefined; }
  if (!isRecord(raw) || raw['v'] !== 1 || !Array.isArray(raw['files'])) return undefined;
  const out = new Map<string, string>();
  for (const f of raw['files']) if (isRecord(f) && typeof f['path'] === 'string' && typeof f['sha256'] === 'string') out.set(f['path'], f['sha256']);
  return out;
}

/** Everything `gate init` would write and create. Reads the disk (existing files, manifests, the install's ownership); writes nothing. */
export async function planInit(opts: InitOptions): Promise<InitPlan> {
  assertGatePlatform(opts.platform ?? process.platform);
  const { host } = opts;
  if (!isHost(host)) throw new Error(`--host must be one of ${HOSTS.join(', ')}`);
  validateKeyId(opts.rootFingerprint, '--root-fingerprint');
  const mode = opts.mode ?? 'shadow';
  if (!MODES.includes(mode)) throw new Error('--mode must be shadow or enforce');
  if (host === 'codex' && mode === 'enforce') throw new Error(CODEX_ENFORCE_REFUSAL);
  if (opts.inbox !== undefined && (!path.isAbsolute(opts.inbox) || !SAFE_PATH.test(opts.inbox))) throw new Error('--inbox must be an absolute path');
  const uid = opts.rootUid ?? 0;
  const stop = opts.base ?? '/';
  const p = instancePaths(host, opts.base ?? '/');
  const tc = await resolveToolchain(host, opts);
  const problems = await toolchainProblems(host, tc, opts);

  // Host binaries: resolved to their real path (that is what /proc/<pid>/exe shows), then required to be trusted ELF files.
  const requested = opts.hostExes && opts.hostExes.length > 0 ? opts.hostExes : [undefined];
  const hostExes: string[] = [];
  for (const given of requested) {
    let exe: string;
    try {
      exe = given ?? (opts.resolveHostExe ?? defaultHostExe)(host);
      if (!path.isAbsolute(exe)) throw new Error(`${exe} must be an absolute path`);
      exe = await realpath(exe);
      await checkHostExe(exe, uid, stop);
    } catch (e) {
      const fallback = given ?? `/usr/bin/${host === 'claude-code' ? 'claude' : 'codex'}`;
      problems.push(`${message(e)}; host binaries must be root-owned (not in a user's home): pass --host-exe PATH`);
      exe = fallback;
    }
    if (!hostExes.includes(exe)) hostExes.push(exe);
  }

  for (const q of [tc.nodePath, tc.hookEntry, tc.cliPath, tc.envPath, p.hook, p.managedDir, p.stateRoot, ...hostExes])
    if (!SAFE_PATH.test(q)) throw new Error(`${q} contains characters that are not allowed in a unit or hook command (only letters, digits and . _ / @ - are accepted)`);

  const cfg = instanceFromOptions({ host, mode, rootFingerprint: opts.rootFingerprint, hostExes, inbox: opts.inbox, base: opts.base });
  const files: PlannedFile[] = [
    { path: p.instance, content: serializeCanonicalJson(cfg), mode: 0o644, role: 'instance' },
    { path: p.hook, content: hookConfigText(host, cfg), mode: 0o644, role: 'hook' },
    { path: p.unit, content: unitText(tc), mode: 0o644, role: 'unit' },
    { path: p.dropin, content: dropinText(cfg, p.stateRoot), mode: 0o644, role: 'dropin' },
    { path: p.hostConfig, content: hostConfigText(host, mode, tc, p.hook), mode: 0o644, role: 'host' }, // last of the configs
  ];
  const hostOwn = files.filter((f) => f.role !== 'unit');
  const shared = files.filter((f) => f.role === 'unit');

  // Ownership by manifest (G5, N1): a file is ours when its hash equals its entry in this host's or the shared manifest.
  const own = await readManifest(p.manifest);
  const sharedOwn = await readManifest(p.sharedManifest);
  const foreign: string[] = [];
  for (const f of files) {
    const info = await lstat(f.path).catch((e: unknown) => { if (errnoCode(e) === 'ENOENT' || errnoCode(e) === 'ENOTDIR') return undefined; throw e; });
    if (!info) continue;
    let ours = false;
    if (info.isFile()) {
      const h = sha256(await readFile(f.path));
      ours = own?.get(f.path) === h || sharedOwn?.get(f.path) === h;
    }
    if (!ours) foreign.push(f.path);
  }
  files.push({ path: p.manifest, content: manifestText(hostOwn), mode: 0o644, role: 'manifest' },
    { path: p.sharedManifest, content: manifestText(shared), mode: 0o644, role: 'shared-manifest' });

  const dirs: PlannedDir[] = [
    { path: p.configDir, mode: 0o755 }, { path: p.stateRoot, mode: 0o755 }, { path: p.stateDir, mode: 0o700 },
    { path: p.generationsDir, mode: 0o755 }, { path: p.managedDir, mode: 0o755 }, { path: p.dropinDir, mode: 0o755 },
  ];
  const rerun = own !== undefined;
  const next = [
    rerun ? `systemctl daemon-reload && systemctl restart mago-ski-gate@${host}` : `systemctl daemon-reload && systemctl enable --now mago-ski-gate@${host}`,
    `mago-ski gate trust --host ${host} --trust-root FILE --revocations FILE`,
    `mago-ski gate doctor --host ${host}`,
  ];
  return { host, mode, files, dirs, foreign, problems, rerun, next };
}

/* ----------------------------------------------------------------------------------------------------- applying */

export interface ApplyOptions { force?: boolean; base?: string; rootUid?: number; now?: () => Date }
export interface ApplyResult { written: string[]; backups: { from: string; to: string }[]; dirs: string[] }

const stamp = (d: Date): string => d.toISOString().replace(/[-:]/gu, '').replace(/\.\d+Z$/u, 'Z');

async function ensureDir(dir: string, mode: number): Promise<boolean> {
  const missing: string[] = [];
  for (let d = dir; ; d = path.dirname(d)) {
    const info = await lstat(d).catch((e: unknown) => { if (errnoCode(e) === 'ENOENT') return undefined; throw e; });
    if (info) {
      if (!info.isDirectory()) throw new Error(`${d} must be a real directory`);
      break;
    }
    missing.unshift(d);
    if (d === path.dirname(d)) break;
  }
  for (const m of missing) {
    const want = m === dir ? mode : 0o755; // parents are root-owned 0755, the leaf has its stated mode (umask must not change it)
    await mkdir(m, { mode: want });
    await chmod(m, want);
  }
  if (missing.length === 0) await chmod(dir, mode);
  return missing.length > 0;
}

/**
 * Writes the plan (G5, v3 decision 3). Refuses first (problems, foreign files without `force`); with `force` renames each
 * foreign file to `<path>.mago-ski-bak-<stamp>` before writing; creates the folders; writes each file atomically in plan
 * order (the host config after the other configs, the manifests last). A failed write puts every moved-aside file back.
 */
export async function applyInit(plan: InitPlan, opts: ApplyOptions = {}): Promise<ApplyResult> {
  if (plan.problems.length > 0) throw new Error(plan.problems.join('\n'));
  if (plan.foreign.length > 0 && !opts.force)
    throw new Error(plan.foreign.map((f) => `${f} exists and was not written by mago-ski; merge it by hand (mago-ski gate init --print) or pass --force`).join('\n'));
  const result: ApplyResult = { written: [], backups: [], dirs: [] };
  const suffix = `.mago-ski-bak-${stamp((opts.now ?? (() => new Date()))())}`;
  try {
    for (const f of plan.foreign) { // a failed rename stops the command before anything is written
      const to = `${f}${suffix}`;
      await rename(f, to);
      result.backups.push({ from: f, to });
    }
    for (const d of plan.dirs) if (await ensureDir(d.path, d.mode)) result.dirs.push(d.path);
    for (const f of plan.files) {
      await writeFileAtomic(f.path, Buffer.from(f.content, 'utf8'), f.mode);
      await chmod(f.path, f.mode);
      result.written.push(f.path);
    }
  } catch (e) {
    const failed: string[] = [];
    for (const b of result.backups.reverse()) { try { await rename(b.to, b.from); } catch { failed.push(b.to); } }
    const restored = failed.length > 0 ? ` Could not move back: ${failed.join(', ')}.` : result.backups.length > 0 ? ' Moved-aside files were put back.' : '';
    const partial = result.written.length > 0 ? ` Files already written (not in the manifest, so the next run treats them as foreign; check them and use --force): ${result.written.join(', ')}.` : '';
    throw new Error(`gate init failed: ${message(e)}.${restored}${partial}`);
  }
  return result;
}

/* ----------------------------------------------------------------------------------------------------- doctor */

export type CheckResult = 'PASS' | 'FAIL' | 'SKIP' | 'WARN';
export interface DoctorCheck { check: string; result: CheckResult; detail: string }
export interface DoctorOptions extends Seams {
  /** The calling uid; default `process.getuid()`. Below root the service checks are skipped. */
  uid?: number;
  /** Admin client seam. */
  ask?: AskAdmin;
  /** Tests: replace the two kernel settings read for warnings. */
  somaxconn?: () => Promise<number>;
  procMounts?: () => Promise<string>;
}

/** Read-only checks, in the order of the design (v1 section 6, G6, G12). Never throws. */
export async function doctor(host: Host, opts: DoctorOptions = {}): Promise<DoctorCheck[]> {
  const out: DoctorCheck[] = [];
  const add = (check: string, result: CheckResult, detail: string): void => { out.push({ check, result, detail }); };
  const attempt = async (check: string, ok: string, fn: () => Promise<string | void>): Promise<boolean> => {
    try { add(check, 'PASS', (await fn()) || ok); return true; } catch (e) { add(check, 'FAIL', message(e)); return false; }
  };
  const uid = opts.rootUid ?? 0;
  const stop = opts.base ?? '/';
  try { assertGatePlatform(opts.platform ?? process.platform); add('platform', 'PASS', 'Linux'); } catch (e) { add('platform', 'FAIL', message(e)); return out; }
  const p = instancePaths(host, opts.base ?? '/');

  let cfg: InstanceConfig | undefined;
  await attempt('instance config', p.instance, async () => {
    cfg = await readInstanceConfig(p.instance, uid);
    if (cfg.host !== host) throw new Error(`${p.instance} is for host ${cfg.host}`);
    return `${p.instance} (mode ${cfg.mode})`;
  });
  if (!cfg) { for (const c of ['host binaries', 'hook entry', 'node', 'managed folder', 'host config', 'service', 'trust', 'mode']) add(c, 'SKIP', 'no usable instance config'); return out; }
  const c: InstanceConfig = cfg;

  for (const exe of c.host_exes) await attempt('host binaries', exe, async () => { await checkHostExe(exe, uid, stop); return exe; });

  const tc = await resolveToolchain(host, opts);
  await attempt('hook entry', tc.hookEntry, async () => {
    if (!existsSync(tc.hookEntry)) throw new Error(`${tc.hookEntry} not found`);
    await checkRootOwnedTree(path.join(tc.installRoot, 'dist'), uid, stop);
    return `${path.join(tc.installRoot, 'dist')} is root-owned`;
  });
  if (opts.checkExec === false) add('node', 'SKIP', 'not checked in this environment');
  else await attempt('node', tc.nodePath, async () => {
    await checkRootOwnedTree(tc.nodePath, uid, stop);
    await checkRootOwnedChain(path.join(tc.installRoot, 'package.json'), uid, stop);
    await checkRootOwnedChain(tc.envPath, uid, stop);
    return `${tc.nodePath}, package.json and ${tc.envPath} are root-owned`;
  });

  for (const [label, dir, must] of [['config folder', p.configDir, true], ['managed folder', c.managed_dir, true], ['state folder', c.state_dir, true],
    ['generations folder', c.generations_dir, true], ['decision socket folder', c.decision_socket_dir, false], ['admin socket folder', c.admin_socket_dir, false]] as const) {
    if (!must && !existsSync(dir)) { add(label, 'SKIP', `${dir} does not exist yet (the service creates it)`); continue; }
    await attempt(label, dir, async () => { await checkRootOwnedChain(dir, uid, stop); return `${dir} is root-owned`; });
  }

  // Host config and hook config: exact content of what `gate init` would write now.
  const hookExpected = hookConfigText(host, c);
  let hostFileMode: Mode | undefined;
  try {
    const expected = hostConfigText(host, c.mode, tc, p.hook);
    const info = await lstat(p.hostConfig);
    if (!info.isFile() || info.uid !== uid || (info.mode & 0o022) !== 0) throw new Error(`${p.hostConfig} must be a regular file owned by root and not writable by others`);
    const have = sha256(await readFile(p.hostConfig));
    if (have === sha256(expected)) { hostFileMode = c.mode; add('host config', 'PASS', `${p.hostConfig} matches what gate init writes`); }
    else {
      const other = c.mode === 'shadow' ? 'enforce' : 'shadow';
      let otherMatches = false;
      try { otherMatches = have === sha256(hostConfigText(host, other, tc, p.hook)); } catch { /* codex enforce is not generated */ }
      if (otherMatches) hostFileMode = other;
      throw new Error(otherMatches ? `${p.hostConfig} is the ${other} configuration but the instance is ${c.mode}; run gate init again` : `${p.hostConfig} differs from what gate init would write now; run gate init again (it keeps a backup with --force)`);
    }
  } catch (e) { add('host config', 'FAIL', message(e)); }
  try {
    if (sha256(await readFile(p.hook)) !== sha256(hookExpected)) throw new Error(`${p.hook} differs from what gate init would write now; run gate init again`);
    add('hook config', 'PASS', `${p.hook} matches what gate init writes`);
  } catch (e) { add('hook config', 'FAIL', message(e)); }

  // Service, trust, mode: need the admin socket (root).
  const callerUid = opts.uid ?? process.getuid?.() ?? -1;
  let status: Record<string, unknown> | undefined;
  if (callerUid !== uid) {
    for (const k of ['service', 'trust']) add(k, 'SKIP', 'needs root');
  } else {
    const decision = path.join(c.decision_socket_dir, 'decision.sock');
    const sock = await lstat(decision).then((s) => s.isSocket(), () => false);
    if (!sock) add('service', 'FAIL', `${decision} does not exist; is the service running? (systemctl status mago-ski-gate@${host})`);
    else {
      try {
        const r = await (opts.ask ?? askAdmin)(path.join(c.admin_socket_dir, 'admin.sock'), { cmd: 'status' }, 10_000);
        if (!r.ok) add('service', 'FAIL', r.error);
        else {
          status = r;
          const log = isRecord(r['log']) ? r['log'] : {};
          if (r['ready'] === true && log['state'] === 'ready') add('service', 'PASS', 'answers status; ready; decision log ready');
          else add('service', 'FAIL', `answers status but is not fully ready (ready=${String(r['ready'])}, admission=${String(r['admission'])}, log=${String(log['state'])})`);
        }
      } catch (e) { add('service', 'FAIL', message(e)); }
    }
    if (!status) add('trust', 'SKIP', 'no status from the service');
    else if (status['trust'] === 'ready') add('trust', 'PASS', `trust accepted; revocation list valid until ${String(status['revocationsExpiresAt'])}`);
    else add('trust', 'FAIL', `trust is not accepted: ${String(status['trust'])}; run mago-ski gate trust --host ${host}`);
  }

  const mismatches: string[] = [];
  if (status && status['mode'] !== c.mode) mismatches.push(`the service runs in ${String(status['mode'])} but the instance config says ${c.mode}; restart the service`);
  if (hostFileMode && hostFileMode !== c.mode) mismatches.push(`the host config is for ${hostFileMode}`);
  if (mismatches.length > 0) add('mode', 'FAIL', mismatches.join('; '));
  else if (c.mode === 'shadow') add('mode', 'WARN', 'shadow: decisions are logged, nothing is blocked (a trial mode; use gate init --mode enforce to enforce)');
  else add('mode', 'PASS', 'enforce');

  // Kernel settings the service header names as deployment requirements.
  try {
    const n = await (opts.somaxconn ?? (async () => Number((await readFile('/proc/sys/net/core/somaxconn', 'utf8')).trim())))();
    if (Number.isFinite(n) && n < 1024) add('somaxconn', 'WARN', `net.core.somaxconn is ${n}; at least 1024 is advised (the service lowers its connection cap to it)`);
  } catch { /* unreadable: no warning */ }
  try {
    const mounts = await (opts.procMounts ?? (() => readFile('/proc/mounts', 'utf8')))();
    if (mounts.split('\n').some((l) => /^\S+ \/proc /u.test(l) && /hidepid=(?!0|off)/u.test(l))) add('proc mount', 'WARN', '/proc is mounted with hidepid: other users\' sessions stay open longer before they are reaped');
  } catch { /* unreadable: no warning */ }
  return out;
}
