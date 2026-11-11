// One gate instance per host (design docs/design/gate-cli.md, section 1, G1, G7). This module is the single place that knows
// where an instance keeps its files, what its config file holds and how that maps to the service's own config.
import { lstat, readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import path from 'node:path';
import { isRecord } from '../canonical-json.ts';
import { validateKeyId } from '../keys.ts';
import type { Mode } from '../policy.ts';
import { MODES } from './contract.ts';
import type { GateServiceConfig } from './service.ts';
import { parseStrictJson } from './strict-json.ts';

export const HOSTS = ['claude-code', 'codex'] as const;
export type Host = (typeof HOSTS)[number];

export const isHost = (value: unknown): value is Host => typeof value === 'string' && (HOSTS as readonly string[]).includes(value);

/** The instance config file (canonical JSON), exactly these keys. */
export interface InstanceConfig {
  v: 1;
  host: Host;
  mode: Mode;
  root_fingerprint: string;
  host_exes: string[];
  state_dir: string;
  generations_dir: string;
  managed_dir: string;
  /** Holds `decision.sock`; the unit's RuntimeDirectory (systemd creates it). */
  decision_socket_dir: string;
  /** Holds `admin.sock`; `start()` creates it at 0700. */
  admin_socket_dir: string;
  inbox_dir: string | null;
  build_id: string;
}

export interface InstancePaths {
  /** `<base>/etc/mago-ski/gate` */
  configDir: string;
  instance: string;
  hook: string;
  manifest: string;
  sharedManifest: string;
  /** `<base>/var/lib/mago-ski/gate/<host>`, the parent of the state and generations folders. */
  stateRoot: string;
  stateDir: string;
  generationsDir: string;
  decisionSocketDir: string;
  adminSocketDir: string;
  /** The folder the host loads admin Skills from. */
  managedDir: string;
  /** The host's own configuration file (Claude Code managed-settings.json, Codex requirements.toml). */
  hostConfig: string;
  /** The shared systemd template unit. */
  unit: string;
  dropinDir: string;
  dropin: string;
}

/** Every path of one instance. `base` is `/` in production; tests pass a temporary folder. */
export function instancePaths(host: Host, base = '/'): InstancePaths {
  const at = (...parts: string[]): string => path.join(base, ...parts);
  const configDir = at('etc', 'mago-ski', 'gate');
  const stateRoot = at('var', 'lib', 'mago-ski', 'gate', host);
  const decisionSocketDir = at('run', 'mago-ski', 'gate', host);
  const dropinDir = at('etc', 'systemd', 'system', `mago-ski-gate@${host}.service.d`);
  return {
    configDir,
    instance: path.join(configDir, `${host}.json`),
    hook: path.join(configDir, `${host}-hook.json`),
    manifest: path.join(configDir, `${host}.manifest.json`),
    sharedManifest: path.join(configDir, 'shared.manifest.json'),
    stateRoot,
    stateDir: path.join(stateRoot, 'state'),
    generationsDir: path.join(stateRoot, 'generations'),
    decisionSocketDir,
    adminSocketDir: path.join(decisionSocketDir, 'admin'),
    managedDir: host === 'claude-code' ? at('etc', 'claude-code', '.claude', 'skills') : at('etc', 'codex', 'skills'),
    hostConfig: host === 'claude-code' ? at('etc', 'claude-code', 'managed-settings.json') : at('etc', 'codex', 'requirements.toml'),
    unit: at('etc', 'systemd', 'system', 'mago-ski-gate@.service'),
    dropinDir,
    dropin: path.join(dropinDir, 'paths.conf'),
  };
}

const require = createRequire(import.meta.url);
/** `mago-ski <version>` from package.json, not a constant. */
export function buildId(): string {
  const version = (require('#package.json') as { version?: unknown }).version; // throws when package.json cannot be read
  if (typeof version !== 'string' || version === '') throw new Error('cannot read the version from package.json');
  return `mago-ski ${version}`;
}

export const missingInstanceMessage = (host: Host): string => `no gate instance for ${host}; run mago-ski gate init --host ${host}`;

const KEYS = ['v', 'host', 'mode', 'root_fingerprint', 'host_exes', 'state_dir', 'generations_dir', 'managed_dir',
  'decision_socket_dir', 'admin_socket_dir', 'inbox_dir', 'build_id'];

const abs = (v: unknown): v is string => typeof v === 'string' && path.isAbsolute(v) && !v.includes('\0');

/** Strict validation of a parsed instance config: unknown keys, missing keys and wrong types are refused. */
export function parseInstanceConfig(raw: unknown): InstanceConfig {
  if (!isRecord(raw)) throw new Error('instance config must be an object');
  const extra = Object.keys(raw).filter((k) => !KEYS.includes(k));
  if (extra.length > 0) throw new Error(`instance config has unknown keys: ${extra.join(', ')}`);
  const missing = KEYS.filter((k) => !Object.hasOwn(raw, k));
  if (missing.length > 0) throw new Error(`instance config is missing keys: ${missing.join(', ')}`);
  if (raw['v'] !== 1) throw new Error('instance config v must be 1');
  if (!isHost(raw['host'])) throw new Error(`instance config host must be one of ${HOSTS.join(', ')}`);
  if (!MODES.includes(raw['mode'] as Mode)) throw new Error('instance config mode must be shadow or enforce');
  validateKeyId(raw['root_fingerprint'], 'instance config root_fingerprint');
  const exes = raw['host_exes'];
  if (!Array.isArray(exes) || exes.length === 0 || !exes.every(abs)) throw new Error('instance config host_exes must be a non-empty list of absolute paths');
  for (const k of ['state_dir', 'generations_dir', 'managed_dir', 'decision_socket_dir', 'admin_socket_dir'])
    if (!abs(raw[k])) throw new Error(`instance config ${k} must be an absolute path`);
  if (raw['inbox_dir'] !== null && !abs(raw['inbox_dir'])) throw new Error('instance config inbox_dir must be an absolute path or null');
  if (typeof raw['build_id'] !== 'string' || raw['build_id'] === '') throw new Error('instance config build_id must be a string');
  return raw as unknown as InstanceConfig;
}

/** Reads the instance config. It must be a regular file owned by `rootUid` and not writable by group or others. */
export async function readInstanceConfig(file: string, rootUid = 0): Promise<InstanceConfig> {
  const info = await lstat(file);
  if (!info.isFile()) throw new Error(`${file} must be a regular file`);
  if (info.uid !== rootUid || (info.mode & 0o022) !== 0) throw new Error(`${file} must be owned by root and not writable by group or others`);
  return parseInstanceConfig(parseStrictJson(await readFile(file)));
}

/** The service's own config for an instance. */
export function instanceToServiceConfig(cfg: InstanceConfig, rootUid = 0): GateServiceConfig {
  return {
    stateDir: cfg.state_dir, generationsDir: cfg.generations_dir, managedDir: cfg.managed_dir,
    decisionSocketDir: cfg.decision_socket_dir, adminSocketDir: cfg.admin_socket_dir,
    rootFingerprint: cfg.root_fingerprint, mode: cfg.mode, hostExes: cfg.host_exes, rootUid, buildId: cfg.build_id,
    ...(cfg.inbox_dir !== null ? { inboxDir: cfg.inbox_dir } : {}),
  };
}
