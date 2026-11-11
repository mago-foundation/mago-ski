// `mago-ski gate init` and `gate doctor` (design docs/design/gate-cli.md: v1 sections 3-6, G2-G7, G9-G10, v3 decisions).
// planInit computes everything an installation writes without touching the disk; applyInit writes it in a fixed order and
// puts a moved-aside file back if a write fails; doctor reads and reports. All functions take their environment as
// parameters (`base`, `rootUid`, `platform`, ...) so tests can run them against a temporary tree and the current user.
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { chmod, chown, link, lstat, mkdir, open, readdir, readFile, realpath, rename, stat, unlink } from 'node:fs/promises';
import { constants as fsConstants, existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { isRecord, parseCanonicalJsonBytes, serializeCanonicalJson } from '../canonical-json.ts';
import { readRegularFile, writeFileAtomic } from '../fs-safe.ts';
import { validateKeyId } from '../keys.ts';
import type { Mode } from '../policy.ts';
import { claudeCodeManagedSettings } from './adapters/claude-code-settings.ts';
import { codexManagedConfigToml, codexRequirementsToml } from './adapters/codex-requirements.ts';
import { askAdmin, checkAdminSocket, type AskAdmin } from './admin-client.ts';
import { MODES } from './contract.ts';
import { buildId, HOSTS, instancePaths, isHost, missingInstanceMessage, readInstanceConfig, type Host, type InstanceConfig, type InstancePaths } from './instance.ts';
import { assertGatePlatform } from './proc.ts';
import { parseStrictJson } from './strict-json.ts';

/** What the hook may and the service must do within these limits (the values the live tests ran with). */
export const HOOK_TIMEOUT_SEC = 5;
export const SELF_DEADLINE_MS = 3000;
export const CLIENT_DEADLINE_MS = 1500;

export const CODEX_ENFORCE_NOTE = 'Codex enforcement depends on organisation controls; read docs/hosts/codex.md before enabling enforce';

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

/**
 * A host binary: a regular ELF executable (a script would allowlist its interpreter), root-owned along its whole chain.
 * It is opened without following a link; the type and owner are checked on the descriptor, and only then are its first 4 bytes read.
 */
export async function checkHostExe(exe: string, uid: number, stopAt = '/'): Promise<void> {
  const info = await lstat(exe);
  if (!info.isFile()) throw new Error(`${exe} is not a regular file`);
  const handle = await open(exe, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK);
  try {
    const fd = await handle.stat();
    if (!fd.isFile()) throw new Error(`${exe} is not a regular file`);
    if (fd.uid !== uid || (fd.mode & 0o022) !== 0) throw new Error(NOT_ROOT(exe));
    const head = Buffer.alloc(4);
    const { bytesRead } = await handle.read(head, 0, 4, 0);
    if (bytesRead !== 4 || !head.equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46]))) throw new Error(`${exe} is not an ELF executable (a script would allowlist its interpreter)`);
  } finally { await handle.close(); }
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

/** The host's default binary: its name on root's own PATH (the invoking user's PATH is never consulted). */
export function defaultHostExe(host: Host): string {
  const name = hostBinaryName(host);
  for (const dir of (process.env['PATH'] ?? '').split(':')) {
    if (dir === '' || !path.isAbsolute(dir)) continue;
    const candidate = path.join(dir, name);
    if (existsSync(candidate)) return candidate;
  }
  throw new Error(`${name} was not found on root's PATH; pass --host-exe PATH`);
}

const hostBinaryName = (host: Host): string => (host === 'claude-code' ? 'claude' : 'codex');


/* ------------------------------------------------------------------------------------------ Codex homes (C5, D3, E1) */

function cleanDir(value: string, flag: string, problems: string[]): string | undefined {
  const v = value.replace(/(?<=.)\/+$/u, '');
  if (!path.isAbsolute(v) || !SAFE_PATH.test(v) || v === '/') { problems.push(`${flag} ${value} must be an absolute folder (letters, digits and . _ / @ - only)`); return undefined; }
  return v;
}

/** `--user-home` (repeatable) or else every passwd home with uid 1000 or above and a login shell. */
async function chooseHomes(opts: InitOptions, problems: string[]): Promise<string[]> {
  if (opts.userHomes && opts.userHomes.length > 0)
    return [...new Set(opts.userHomes.map((h) => cleanDir(h, '--user-home', problems)).filter((h): h is string => h !== undefined))];
  const out: string[] = [];
  const text = await readFile(path.join(opts.base ?? '/', 'etc', 'passwd'), 'utf8').catch(() => '');
  for (const line of text.split('\n')) {
    const f = line.split(':');
    const uid = Number(f[2]);
    if (f.length < 7 || !Number.isInteger(uid) || uid < 1000 || uid === 65534) continue;
    if (/(^|\/)(nologin|false|sync|halt|shutdown)$/u.test(f[6]!) || f[6] === '') continue;
    const home = cleanDir(f[5]!, `the home of ${f[0]}`, problems);
    if (home && !out.includes(home)) out.push(home);
  }
  return out;
}

const defaultChattr = (target: string): Promise<void> => new Promise((resolve, reject) => {
  execFile('chattr', ['+i', target], { timeout: 10_000 }, (e, _o, stderr) => (e ? reject(new Error(`chattr +i ${target} failed: ${String(stderr).trim() || e.message}`)) : resolve()));
});
const defaultIsImmutable = (target: string): Promise<boolean> => new Promise((resolve) => {
  execFile('lsattr', ['-d', target], { timeout: 10_000 }, (e, out) => resolve(!e && /^\S*i\S*\s/u.test(String(out))));
});

/** `.system` moves (F5, F7.6) and, with `--lock-user-skill-folders`, the lock of each listed home (E1). Refusals go to `problems`. */
async function planHomeActions(homes: CodexHomes, opts: InitOptions, problems: string[]): Promise<PlannedAction[]> {
  const out: PlannedAction[] = [];
  const stampNow = stamp((opts.now ?? (() => new Date()))());
  const isDir = async (d: string): Promise<boolean> => (await lstat(d).catch(() => undefined))?.isDirectory() === true;
  for (const [root, backupParent] of [...homes.userHomes.map((h) => [`${h}/.codex`, `${h}/.codex`] as const), ...homes.codexHomes.map((h) => [h, h] as const)])
    if (await isDir(`${root}/skills/.system`)) out.push({ kind: 'move-system', from: `${root}/skills/.system`, to: `${backupParent}/mago-ski-backup/system-${stampNow}` });
  if (opts.lockUserSkillFolders) {
    if (homes.userHomes.length === 0) problems.push('--lock-user-skill-folders needs at least one home (--user-home DIR)');
    for (const home of homes.userHomes) {
      const info = await lstat(home).catch(() => undefined);
      if (!info?.isDirectory()) { problems.push(`${home} is not a folder; cannot lock its Skill folders`); continue; }
      for (const dir of [`${home}/.agents/skills`, `${home}/.codex/skills`]) {
        const entries = await readdir(dir).catch(() => [] as string[]);
        const left = entries.filter((e) => !(dir.endsWith('/.codex/skills') && e === '.system'));
        if (left.length > 0) problems.push(`${dir} already holds ${left.slice(0, 3).join(', ')}${left.length > 3 ? ', ...' : ''}; move or remove it before locking (a locked folder is created empty)`);
      }
      out.push({ kind: 'lock', home, owner: { uid: info.uid, gid: info.gid } });
    }
  }
  return out;
}

/** Plan: moves first, then locks. Each move needs the target folder free. */
async function runHomeActions(actions: readonly PlannedAction[], opts: ApplyOptions, rootUid: number): Promise<{ moved: { from: string; to: string }[]; locked: string[] }> {
  const moved: { from: string; to: string }[] = [];
  const locked: string[] = [];
  for (const a of actions) {
    if (a.kind !== 'move-system') continue;
    await mkdir(path.dirname(a.to), { recursive: true, mode: 0o755 });
    await rename(a.from, a.to);
    moved.push({ from: a.from, to: a.to });
  }
  const chattr = opts.chattr ?? defaultChattr;
  const isImmutable = opts.isImmutable ?? defaultIsImmutable;
  const gid = rootUid === 0 ? 0 : (process.getgid?.() ?? 0);
  for (const a of actions) {
    if (a.kind !== 'lock') continue;
    const codex = `${a.home}/.codex`;
    if (!(await lstat(codex).catch(() => undefined))) { // Codex writes here, so it stays the user's own folder
      await mkdir(codex, { mode: 0o700 });
      if (a.owner) await chown(codex, a.owner.uid, a.owner.gid).catch(() => {});
    }
    const agents = `${a.home}/.agents`;
    for (const dir of [agents, `${agents}/skills`, `${codex}/skills`]) {
      if (await isImmutable(dir)) continue; // a re-run
      await mkdir(dir, { mode: 0o755 }).catch((e: unknown) => { if (errnoCode(e) !== 'EEXIST') throw e; });
      const info = await lstat(dir);
      if (info.isSymbolicLink() || !info.isDirectory()) throw new Error(`${dir} must be a real folder to be locked`);
      await chown(dir, rootUid, gid);
      await chmod(dir, 0o755);
    }
    for (const dir of [`${agents}/skills`, `${codex}/skills`, agents]) { // children first: an immutable parent would still allow it, but the order is the plan's
      if (await isImmutable(dir)) { locked.push(dir); continue; }
      await chattr(dir); // a failure (an unsupported file system) stops the command
      locked.push(dir);
    }
  }
  return { moved, locked };
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
  /** Codex: `--user-home DIR` (repeatable). Default: every home in `<base>/etc/passwd` with uid 1000 or above and a login shell. */
  userHomes?: string[];
  /** Codex: `--codex-home DIR` (repeatable), a non-default CODEX_HOME. */
  codexHomes?: string[];
  /** Codex: `--no-deny-read` leaves deny_read out of requirements.toml. */
  noDenyRead?: boolean;
  /** Codex: `--lock-user-skill-folders`, see planLock. */
  lockUserSkillFolders?: boolean;
  /** Tests: sets the immutable attribute on a path (default `chattr +i`). A failure stops the command. */
  chattr?: (target: string) => Promise<void>;
  /** Tests: reads the immutable attribute (default `lsattr -d`). */
  isImmutable?: (target: string) => Promise<boolean>;
  now?: () => Date;
}

export type FileRole = 'instance' | 'hook' | 'unit' | 'dropin' | 'host' | 'managed-config' | 'manifest' | 'shared-manifest';
export interface PlannedFile { path: string; content: string; mode: number; role: FileRole }
export interface PlannedDir { path: string; mode: number }

/** Work on user homes that `gate init --host codex` does after the files are written (printed in the plan). */
export type PlannedAction =
  | { kind: 'move-system'; from: string; to: string }
  | { kind: 'lock'; home: string; owner: { uid: number; gid: number } | undefined };

export interface InitPlan {
  host: Host;
  /** Codex: the homes and CODEX_HOMEs the profile covers (also in the hook config), and the roots deny_read lists. */
  homes: CodexHomes;
  denyRoots: string[];
  actions: PlannedAction[];
  mode: Mode;
  /** The real host binaries the gate will allow (shown by `gate init`). */
  hostExes: string[];
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
export interface CodexHomes { userHomes: string[]; codexHomes: string[] }

export function hookConfigText(host: Host, cfg: InstanceConfig, homes: CodexHomes = { userHomes: [], codexHomes: [] }): string {
  return serializeCanonicalJson({
    v: 1, socket: path.join(cfg.decision_socket_dir, 'decision.sock'), mode: cfg.mode, host_exes: cfg.host_exes,
    client_deadline_ms: CLIENT_DEADLINE_MS, self_deadline_ms: SELF_DEADLINE_MS,
    ...(host === 'codex' ? { admin_root: cfg.managed_dir, skill_roots: [], user_homes: homes.userHomes, codex_homes: homes.codexHomes } : {}),
  });
}

/** The fixed user Skill roots the requirements file denies reads of (D3: the roots of every listed home and CODEX_HOME). */
export function codexDenyRoots(homes: CodexHomes): string[] {
  return [
    ...homes.userHomes.flatMap((h) => [`${h}/.codex/skills`, `${h}/.codex/skills/.system`, `${h}/.agents/skills`]),
    ...homes.codexHomes.flatMap((h) => [`${h}/skills`, `${h}/skills/.system`]),
  ];
}

/** The host's own configuration file for this instance. */
export function hostConfigText(host: Host, mode: Mode, tc: Toolchain, hookConfigPath: string, denyRoots: string[] = []): string {
  const common = { mode, nodePath: tc.nodePath, hookEntry: tc.hookEntry, configPath: hookConfigPath, hookTimeoutSec: HOOK_TIMEOUT_SEC, selfDeadlineMs: SELF_DEADLINE_MS, envPath: tc.envPath };
  if (host === 'claude-code') return `${JSON.stringify(claudeCodeManagedSettings(common), null, 2)}\n`;
  return codexRequirementsToml({ ...common, userSkillRoots: denyRoots });
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

/** `previous` entries stay unless a planned file has the same path (the shared manifest is written by both hosts). */
function manifestText(files: PlannedFile[], previous?: Map<string, string>): string {
  const entries = new Map(previous ?? []);
  for (const f of files) entries.set(f.path, sha256(f.content));
  return serializeCanonicalJson({ v: 1, files: [...entries].map(([p, h]) => ({ path: p, sha256: h })).sort((a, b) => (a.path < b.path ? -1 : 1)) });
}

/** A manifest is read only if it is a root-owned regular file that others cannot write. */
async function readManifest(file: string, uid: number): Promise<Map<string, string> | undefined> {
  let raw: unknown;
  try {
    const info = await lstat(file);
    if (!info.isFile() || info.uid !== uid || (info.mode & 0o022) !== 0) return undefined;
    raw = parseCanonicalJsonBytes(await readRegularFile(file, 'manifest', 1024 * 1024), 'manifest');
  } catch { return undefined; }
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
      // A binary found by itself must look like the host's (a `claude` symlink to python3 is refused); an explicit --host-exe may be named anything.
      if (given === undefined && !path.basename(exe).startsWith(hostBinaryName(host)))
        throw new Error(`${exe} (the real path of the ${hostBinaryName(host)} found on PATH) is not named ${hostBinaryName(host)}*; check it, then pass it with --host-exe`);
      await checkHostExe(exe, uid, stop);
    } catch (e) {
      const fallback = given ?? `/usr/bin/${hostBinaryName(host)}`;
      problems.push(`${message(e)}; host binaries must be root-owned (not in a user's home): pass --host-exe PATH`);
      exe = fallback;
    }
    if (!hostExes.includes(exe)) hostExes.push(exe);
  }

  for (const q of [tc.nodePath, tc.hookEntry, tc.cliPath, tc.envPath, p.hook, p.managedDir, p.stateRoot, ...hostExes])
    if (!SAFE_PATH.test(q)) throw new Error(`${q} contains characters that are not allowed in a unit or hook command (only letters, digits and . _ / @ - are accepted)`);

  const cfg = instanceFromOptions({ host, mode, rootFingerprint: opts.rootFingerprint, hostExes, inbox: opts.inbox, base: opts.base });
  const homes: CodexHomes = { userHomes: [], codexHomes: [] };
  const actions: PlannedAction[] = [];
  if (host === 'codex') {
    homes.userHomes = await chooseHomes(opts, problems);
    homes.codexHomes = (opts.codexHomes ?? []).map((h) => cleanDir(h, '--codex-home', problems)).filter((h): h is string => h !== undefined);
    actions.push(...await planHomeActions(homes, opts, problems));
  } else if (opts.userHomes?.length || opts.codexHomes?.length || opts.noDenyRead || opts.lockUserSkillFolders)
    throw new Error('--user-home, --codex-home, --no-deny-read and --lock-user-skill-folders are for --host codex');
  const denyRoots = host === 'codex' && !opts.noDenyRead ? codexDenyRoots(homes) : [];
  const files: PlannedFile[] = [
    { path: p.instance, content: serializeCanonicalJson(cfg), mode: 0o644, role: 'instance' },
    { path: p.hook, content: hookConfigText(host, cfg, homes), mode: 0o644, role: 'hook' },
    { path: p.unit, content: unitText(tc), mode: 0o644, role: 'unit' },
    { path: p.dropin, content: dropinText(cfg, p.stateRoot), mode: 0o644, role: 'dropin' },
    { path: p.hostConfig, content: hostConfigText(host, mode, tc, p.hook, denyRoots), mode: 0o644, role: 'host' }, // last of the configs
    ...(p.managedConfig ? [{ path: p.managedConfig, content: codexManagedConfigToml(), mode: 0o644, role: 'managed-config' as const }] : []),
  ];
  const hostOwn = files.filter((f) => f.role !== 'unit');
  const shared = files.filter((f) => f.role === 'unit');

  // Ownership by manifest (G5, N1): a file is ours when its hash equals its entry in this host's or the shared manifest.
  const own = await readManifest(p.manifest, uid);
  const sharedOwn = await readManifest(p.sharedManifest, uid);
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
  // The manifests themselves: an existing one that is not a root-owned regular manifest is foreign too.
  for (const [m, read] of [[p.manifest, own], [p.sharedManifest, sharedOwn]] as const)
    if (read === undefined && await lstat(m).then(() => true, (e: unknown) => { if (errnoCode(e) === 'ENOENT' || errnoCode(e) === 'ENOTDIR') return false; throw e; })) foreign.push(m);
  files.push({ path: p.manifest, content: manifestText(hostOwn), mode: 0o644, role: 'manifest' },
    { path: p.sharedManifest, content: manifestText(shared, sharedOwn), mode: 0o644, role: 'shared-manifest' });

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
  return { host, mode, homes, denyRoots, actions, hostExes, files, dirs, foreign, problems, rerun, next };
}

/* ----------------------------------------------------------------------------------------------------- applying */

export interface ApplyOptions { force?: boolean; base?: string; rootUid?: number; now?: () => Date; chattr?: (target: string) => Promise<void>; isImmutable?: (target: string) => Promise<boolean> }
export interface ApplyResult { written: string[]; backups: { from: string; to: string }[]; dirs: string[]; movedSystem: { from: string; to: string }[]; locked: string[] }

const stamp = (d: Date): string => d.toISOString().replace(/[-:]/gu, '').replace(/\.\d+Z$/u, 'Z');

/** Sets the mode through an open descriptor (no path race), after checking that the descriptor is a folder owned by `uid`. */
async function fchmodDir(dir: string, mode: number, uid: number): Promise<void> {
  const handle = await open(dir, fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW);
  try {
    const info = await handle.stat();
    if (!info.isDirectory() || info.uid !== uid) throw new Error(`${dir} must be a real folder owned by root`);
    await handle.chmod(mode);
  } finally { await handle.close(); }
}

async function ensureDir(dir: string, mode: number, uid: number): Promise<boolean> {
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
    await fchmodDir(m, want, uid);
  }
  if (missing.length === 0) await fchmodDir(dir, mode, uid);
  return missing.length > 0;
}

/** Every planned folder that exists, or else its nearest existing ancestor, up to `stop`: root-owned, not writable by others. */
async function checkPlannedFolders(plan: InitPlan, uid: number, stop: string): Promise<void> {
  for (const d of plan.dirs) {
    let existing = path.resolve(d.path);
    while (!(await lstat(existing).then(() => true, (e: unknown) => { if (errnoCode(e) === 'ENOENT') return false; throw e; }))) {
      const up = path.dirname(existing);
      if (up === existing) break;
      existing = up;
    }
    await checkRootOwnedChain(existing, uid, stop);
  }
}

const sameFile = (a: { dev: number; ino: number }, b: { dev: number; ino: number }): boolean => a.dev === b.dev && a.ino === b.ino;

/**
 * Writes the plan (G5, v3 decision 3, v4 items 2-3). First it refuses (problems, foreign files without `force`, any planned
 * folder or ancestor not owned by root or writable by others), before any rename or write. Then each foreign file is hard-linked
 * to `<path>.mago-ski-bak-<stamp>` (the original stays in place), the folders are made, and each file is written with an atomic
 * rename that replaces the original in one step: the host never lacks a config file. After a failure, a backup is put back
 * only over a path this run did not write, and the message lists what is new, what was restored and what stays as a backup.
 */
export async function applyInit(plan: InitPlan, opts: ApplyOptions = {}): Promise<ApplyResult> {
  if (plan.problems.length > 0) throw new Error(plan.problems.join('\n'));
  if (plan.foreign.length > 0 && !opts.force)
    throw new Error(plan.foreign.map((f) => `${f} exists and was not written by mago-ski; merge it by hand (mago-ski gate init --print) or pass --force`).join('\n'));
  const uid = opts.rootUid ?? 0;
  await checkPlannedFolders(plan, uid, opts.base ?? '/');
  const result: ApplyResult = { written: [], backups: [], dirs: [], movedSystem: [], locked: [] };
  const suffix = `.mago-ski-bak-${stamp((opts.now ?? (() => new Date()))())}`;
  try {
    for (const f of plan.foreign) { // a failed link stops the command before anything is written
      const to = `${f}${suffix}`;
      await link(f, to);
      result.backups.push({ from: f, to });
    }
    for (const d of plan.dirs) if (await ensureDir(d.path, d.mode, uid)) result.dirs.push(d.path);
    for (const f of plan.files) {
      await writeFileAtomic(f.path, Buffer.from(f.content, 'utf8'), f.mode);
      const handle = await open(f.path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK);
      try { await handle.chmod(f.mode); } finally { await handle.close(); }
      result.written.push(f.path);
    }
    const home = await runHomeActions(plan.actions, opts, uid); // after every file: a refused plan or a failed write never moves user data
    result.movedSystem = home.moved; result.locked = home.locked;
  } catch (e) {
    const written = new Set(result.written);
    const restored: string[] = [];
    const kept: string[] = [];
    for (const b of result.backups) {
      if (written.has(b.from)) { kept.push(`${b.from} (original kept as ${b.to})`); continue; }
      try {
        const [now, bak] = await Promise.all([lstat(b.from).catch(() => undefined), lstat(b.to)]);
        if (now && sameFile(now, bak)) await unlink(b.to); // untouched: the original is still in place, the extra link goes
        else if (!now) await rename(b.to, b.from);
        else { kept.push(`${b.from} (original kept as ${b.to})`); continue; }
        restored.push(b.from);
      } catch { kept.push(`${b.from} (original kept as ${b.to})`); }
    }
    const fresh = result.written.filter((w) => !result.backups.some((b) => b.from === w));
    const lines = [`gate init failed: ${message(e)}.`];
    if (fresh.length > 0) lines.push(`New files written (not in the manifest, so the next run treats them as foreign; check them and use --force): ${fresh.join(', ')}.`);
    if (restored.length > 0) lines.push(`Original put back, not changed: ${restored.join(', ')}.`);
    if (kept.length > 0) lines.push(`Replaced by new content; the original stays as a backup: ${kept.join(', ')}.`);
    throw new Error(lines.join(' '));
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
  /** Codex: the output of `codex --version` for a host binary (default: runs it). */
  codexVersion?: (exe: string) => Promise<string>;
  /** Codex: the immutable attribute of a path (default `lsattr -d`). */
  isImmutable?: (target: string) => Promise<boolean>;
}

/** lstat: a regular file (not a symlink) owned by `uid` and not writable by group or others. */
async function trustedRegularFile(file: string, uid: number): Promise<void> {
  const info = await lstat(file);
  if (info.isSymbolicLink() || !info.isFile()) throw new Error(`${file} must be a regular file, not a symlink`);
  if (info.uid !== uid || (info.mode & 0o022) !== 0) throw new Error(NOT_ROOT(file));
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
    try { cfg = await readInstanceConfig(p.instance, uid); } catch (e) { throw errnoCode(e) === 'ENOENT' ? new Error(missingInstanceMessage(host)) : e; } // lstat: a root-owned regular file, not a symlink
    if (cfg.host !== host) throw new Error(`${p.instance} is for host ${cfg.host}`);
    return `${p.instance} (mode ${cfg.mode})`;
  });
  if (!cfg) { for (const c of ['host binaries', 'hook entry', 'node', 'managed folder', 'host config', 'unit', 'drop-in', 'service', 'trust', 'mode']) add(c, 'SKIP', 'no usable instance config'); return out; }
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
  // Codex: the listed homes live in the hook config (the instance config does not know them); deny_read is present or not as written.
  const homes: CodexHomes = (host === 'codex' ? await readHookHomes(p.hook) : undefined) ?? { userHomes: [], codexHomes: [] };
  const denyRoots = host === 'codex' && /^deny_read = /mu.test(await readFile(p.hostConfig, 'utf8').catch(() => '')) ? codexDenyRoots(homes) : [];
  const hookExpected = hookConfigText(host, c, homes);
  let hostFileMode: Mode | undefined;
  try {
    const expected = hostConfigText(host, c.mode, tc, p.hook, denyRoots);
    const info = await lstat(p.hostConfig);
    if (!info.isFile() || info.uid !== uid || (info.mode & 0o022) !== 0) throw new Error(`${p.hostConfig} must be a regular file owned by root and not writable by others`);
    const have = sha256(await readFile(p.hostConfig));
    if (have === sha256(expected)) { hostFileMode = c.mode; add('host config', 'PASS', `${p.hostConfig} matches what gate init writes`); }
    else {
      const other = c.mode === 'shadow' ? 'enforce' : 'shadow';
      let otherMatches = false;
      try { otherMatches = have === sha256(hostConfigText(host, other, tc, p.hook, denyRoots)); } catch { /* not generated */ }
      if (otherMatches) hostFileMode = other;
      throw new Error(otherMatches ? `${p.hostConfig} is the ${other} configuration but the instance is ${c.mode}; run gate init again` : `${p.hostConfig} differs from what gate init would write now; run gate init again (it keeps a backup with --force)`);
    }
  } catch (e) { add('host config', 'FAIL', message(e)); }
  // The unit and the drop-in: root-owned regular files with the content the plan would write.
  for (const [label, file, expected] of [['unit', p.unit, unitText(tc)], ['drop-in', p.dropin, dropinText(c, p.stateRoot)]] as const) {
    try {
      await trustedRegularFile(file, uid);
      if (sha256(await readFile(file)) !== sha256(expected)) throw new Error(`${file} differs from what gate init would write now; run gate init again`);
      add(label, 'PASS', `${file} matches what gate init writes`);
    } catch (e) { add(label, 'FAIL', message(e)); }
  }
  try {
    await trustedRegularFile(p.hook, uid);
    if (sha256(await readFile(p.hook)) !== sha256(hookExpected)) throw new Error(`${p.hook} differs from what gate init would write now; run gate init again`);
    add('hook config', 'PASS', `${p.hook} matches what gate init writes`);
  } catch (e) { add('hook config', 'FAIL', message(e)); }

  if (host === 'codex') await codexDoctor(c, p, homes, uid, opts, add);

  // Service, trust, mode: need the admin socket (root).
  const callerUid = opts.uid ?? process.getuid?.() ?? -1;
  let status: Record<string, unknown> | undefined;
  if (callerUid !== uid) {
    for (const k of ['service', 'trust']) add(k, 'SKIP', 'needs root');
  } else {
    const decision = path.join(c.decision_socket_dir, 'decision.sock');
    const sock = await lstat(decision).then((s) => s.isSocket(), () => false);
    let adminTrusted = true;
    if (sock && existsSync(c.admin_socket_dir)) {
      try { await checkAdminSocket(c.admin_socket_dir, uid); } catch (e) { adminTrusted = false; add('admin socket', 'FAIL', message(e)); }
    }
    if (!sock) add('service', 'FAIL', `${decision} does not exist; is the service running? (systemctl status mago-ski-gate@${host})`);
    else if (!adminTrusted) add('service', 'SKIP', 'the admin socket is not trusted (see the admin socket check)');
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

  if (status) {
    if (status['root_fingerprint'] === c.root_fingerprint) add('root fingerprint', 'PASS', `the service uses ${c.root_fingerprint}`);
    else add('root fingerprint', 'FAIL', `the service uses ${String(status['root_fingerprint'])} but the instance config says ${c.root_fingerprint}; restart the service`);
  }
  if (host === 'codex' && status) {
    const mism = Array.isArray(status['nameMismatch']) ? status['nameMismatch'] : [];
    if (mism.length > 0) add('name mismatch', 'FAIL', `installed Skills whose SKILL.md does not start with one plain "name:" line equal to the install name (hidden in enforce): ${mism.join(', ')}`);
    else add('name mismatch', 'PASS', 'every installed Skill has a plain name line equal to its install name');
    const removed = isRecord(status['removedNames']) ? status['removedNames'] : {};
    if (removed['full'] === true) add('removed names', 'WARN', `the removed-names file is full (${String(removed['evicted'])} oldest entries evicted); run: mago-ski gate prune-removed --host codex --older-than-days 90`);
    else if (typeof removed['error'] === 'string') add('removed names', 'WARN', `the removed-names file could not be written: ${removed['error']}`);
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

/* ---------------------------------------------------------------------------------------------- Codex doctor checks */

async function readHookHomes(file: string): Promise<CodexHomes | undefined> {
  try {
    const raw = parseStrictJson(await readFile(file));
    if (!isRecord(raw)) return undefined;
    const list = (v: unknown): string[] | undefined => (Array.isArray(v) && v.every((x) => typeof x === 'string') ? (v as string[]) : undefined);
    const userHomes = list(raw['user_homes']);
    const codexHomes = list(raw['codex_homes']);
    return userHomes && codexHomes ? { userHomes, codexHomes } : undefined;
  } catch { return undefined; }
}

/** True when a SKILL.md (any case) exists under `root`, entering dot folders and following links; bounded. */
async function hasSkillFile(root: string, skip: (rel: string) => boolean = () => false): Promise<boolean> {
  const queue: { dir: string; depth: number }[] = [{ dir: root, depth: 0 }];
  let dirs = 0;
  for (let i = 0; i < queue.length && dirs < 5000; i++) {
    const { dir, depth } = queue[i]!;
    dirs++;
    for (const name of await readdir(dir).catch(() => [] as string[])) {
      if (skip(path.relative(root, path.join(dir, name)))) continue;
      if (/^skill\.md$/iu.test(name)) return true;
      if (depth < 8 && (await stat(path.join(dir, name)).catch(() => undefined))?.isDirectory()) queue.push({ dir: path.join(dir, name), depth: depth + 1 });
    }
  }
  return false;
}

const defaultCodexVersion = (exe: string): Promise<string> => new Promise((resolve, reject) => {
  execFile(exe, ['--version'], { timeout: 5000, env: {} }, (e, out) => (e ? reject(e) : resolve(String(out))));
});

async function codexDoctor(c: InstanceConfig, p: InstancePaths, homes: CodexHomes, uid: number, opts: DoctorOptions,
  add: (check: string, result: CheckResult, detail: string) => void): Promise<void> {
  // managed_config.toml: exact content, root-owned.
  try {
    const file = p.managedConfig!;
    const info = await lstat(file);
    if (!info.isFile() || info.uid !== uid || (info.mode & 0o022) !== 0) throw new Error(`${file} must be a regular file owned by root and not writable by others`);
    if (sha256(await readFile(file)) !== sha256(codexManagedConfigToml())) throw new Error(`${file} differs from what gate init would write now; run gate init again`);
    add('managed config', 'PASS', `${file} matches what gate init writes`);
  } catch (e) { add('managed config', 'FAIL', errnoCode(e) === 'ENOENT' ? `${p.managedConfig} does not exist; run gate init again` : message(e)); }
  // The hook config must list the homes (an unlisted HOME blocks bare mentions).
  const listed = homes.userHomes.length > 0 || homes.codexHomes.length > 0;
  if (!listed) add('user homes', 'WARN', 'no home is listed (gate init --user-home DIR): the hook cannot recognise any HOME, so bare mentions are blocked');
  // Non-admin Skills in a listed home (the menu route, D1): FAIL.
  const withSkills: string[] = [];
  const withSystem: string[] = [];
  for (const h of homes.userHomes) {
    for (const d of [`${h}/.agents/skills`, `${h}/.codex/skills`]) if (await hasSkillFile(d, (rel) => rel === '.system' || rel.startsWith('.system/'))) withSkills.push(d);
    if (await lstat(`${h}/.codex/skills/.system`).then(() => true, () => false)) withSystem.push(`${h}/.codex/skills/.system`);
  }
  for (const h of homes.codexHomes) {
    if (await hasSkillFile(`${h}/skills`, (rel) => rel === '.system' || rel.startsWith('.system/'))) withSkills.push(`${h}/skills`);
    if (await lstat(`${h}/skills/.system`).then(() => true, () => false)) withSystem.push(`${h}/skills/.system`);
  }
  if (withSkills.length > 0) add('user Skills', 'FAIL', `a listed home has Skills that Codex would list (a menu pick reaches the model with no hook): ${withSkills.join(', ')}`);
  else add('user Skills', 'PASS', 'no SKILL.md under the listed homes');
  if (withSystem.length > 0) add('.system folder', 'FAIL', `${withSystem.join(', ')} exists; the profile turns bundled Skills off, so move it away (gate init does, into <home>/.codex/mago-ski-backup/)`);
  else add('.system folder', 'PASS', 'no .system folder under the listed homes');
  // The optional lock (E1).
  if (homes.userHomes.length > 0) {
    const isImmutable = opts.isImmutable ?? defaultIsImmutable;
    const open: string[] = [];
    for (const h of homes.userHomes) for (const d of [`${h}/.agents/skills`, `${h}/.codex/skills`]) if (!(await isImmutable(d))) open.push(d);
    if (open.length > 0) add('Skill folder lock', 'WARN', `not locked (gate init --lock-user-skill-folders): ${open.join(', ')}`);
    else add('Skill folder lock', 'PASS', 'the user Skill folders are locked (immutable)');
  }
  // The Codex version the profile was verified on.
  try {
    const out = await (opts.codexVersion ?? defaultCodexVersion)(c.host_exes[0]!);
    const m = /(\d+)\.(\d+)\.(\d+)/u.exec(out);
    if (m && m[1] === '0' && m[2] === '166') add('codex version', 'PASS', `codex ${m[0]}`);
    else add('codex version', 'WARN', `untested Codex version${m ? ` ${m[0]}` : ''}: the profile was verified on 0.166.x`);
  } catch { add('codex version', 'WARN', 'untested Codex version: codex --version could not be run'); }
}
