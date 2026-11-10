import { chmod, mkdir, mkdtemp, realpath, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import type { TestContext } from 'node:test';
import { addApprover, approveSkill, initRoot } from '../src/admin.ts';
import { generateKeyPair } from '../src/keys.ts';
import { loadPolicy, type Policy } from '../src/policy.ts';
import { buildRecoverySet, initRootEventLog } from '../src/recovery-admin.ts';

export const T0 = new Date('2026-10-01T00:00:00Z');

/**
 * Skip option for tests that need the Linux kernel (/proc, a Linux-only gate service, generation store or
 * decision log). The gate is Linux only; on other platforms these tests are reported as skipped, not failed.
 */
export const LINUX_ONLY: false | string = process.platform === 'linux' ? false : 'Linux only: needs /proc';

export function daysAfter(base: Date, days: number): Date {
  return new Date(base.getTime() + days * 86_400_000);
}

export async function tempDir(t: TestContext, prefix = 'mago-ski-test-'): Promise<string> {
  // Resolved, because macOS temp dirs sit under /var, a symlink to /private/var.
  const directory = await realpath(await mkdtemp(path.join(os.tmpdir(), prefix)));
  t.after(async () => await rm(directory, { recursive: true, force: true }));
  return directory;
}

export async function writeSkill(directory: string, name: string, files: Record<string, string> = {}): Promise<string> {
  const skillDir = path.join(directory, name);
  await mkdir(skillDir, { recursive: true });
  const all: Record<string, string> = {
    'SKILL.md': `---\nname: ${name}\ndescription: Test Skill ${name}.\n---\n# ${name}\n\nFollow the steps.\n`,
    ...files,
  };
  for (const [relative, content] of Object.entries(all)) {
    const target = path.join(skillDir, relative);
    await mkdir(path.dirname(target), { recursive: true });
    await writeFile(target, content);
  }
  return skillDir;
}

export interface Org {
  dir: string;
  rootKey: string;
  rootPub: string;
  rootKeyId: string;
  approverKey: string;
  approverPub: string;
  approverKeyId: string;
  trustRoot: string;
  revocations: string;
  policyPath: string;
  statePath: string;
  logPath: string;
  certDir: string;
}

/** Root key, one approver scoped to `scopes`, trust root, revocations and a shadow-mode policy. */
export async function setupOrg(t: TestContext, options: { scopes?: string[]; mode?: 'shadow' | 'enforce'; now?: Date } = {}): Promise<Org> {
  const now = options.now ?? T0;
  const dir = await tempDir(t, 'mago-ski-org-');
  const keys = path.join(dir, 'keys');
  await mkdir(keys);
  const root = await generateKeyPair(path.join(keys, 'root.pem'), path.join(keys, 'root.pub'));
  const approver = await generateKeyPair(path.join(keys, 'approver.pem'), path.join(keys, 'approver.pub'));
  const policyDir = path.join(dir, 'policy');
  await mkdir(policyDir);
  const certDir = path.join(policyDir, 'certs');
  await mkdir(certDir);
  const trustRoot = path.join(policyDir, 'trust-root.json');
  const revocations = path.join(policyDir, 'revocations.json');
  await initRoot({ rootKeyPath: root.privatePath, trustRootOut: trustRoot, revocationsOut: revocations, now });
  await addApprover({
    rootKeyPath: root.privatePath, trustRootPath: trustRoot, now, publicKeyPath: approver.publicPath,
    name: 'Reviewer One', scopes: options.scopes ?? ['*'], expires: '180d',
  });
  const policyPath = path.join(policyDir, 'policy.json');
  const statePath = path.join(policyDir, 'state.json');
  const logPath = path.join(policyDir, 'decisions.jsonl');
  await writeFile(policyPath, JSON.stringify({
    policy_version: 'mago.policy/v1',
    mode: options.mode ?? 'shadow',
    root_fingerprint: root.keyId,
    trust_root: 'trust-root.json',
    revocations: 'revocations.json',
    certificate_dirs: ['certs'],
    state_file: 'state.json',
    decision_log: 'decisions.jsonl',
  }, null, 2));
  return {
    dir, rootKey: root.privatePath, rootPub: root.publicPath, rootKeyId: root.keyId,
    approverKey: approver.privatePath, approverPub: approver.publicPath, approverKeyId: approver.keyId,
    trustRoot, revocations, policyPath, statePath, logPath, certDir,
  };
}

export async function approve(org: Org, skillDir: string, options: { now?: Date; expires?: string; key?: string; out?: string } = {}) {
  return await approveSkill({
    skillDir, approverKeyPath: options.key ?? org.approverKey, now: options.now ?? T0,
    expires: options.expires ?? '90d', reason: 'reviewed for test', ...(options.out ? { out: options.out } : {}),
  });
}

export async function makeExecutable(filePath: string, executable: boolean): Promise<void> {
  await chmod(filePath, executable ? 0o755 : 0o644);
}

export interface Key { priv: string; pub: string; keyId: string }

export interface RecoveryOrg {
  dir: string;
  policyDir: string;
  policyPath: string;
  statePath: string;
  logPath: string;
  eventsPath: string;
  timestampPath: string;
  trustRoot: string;
  revocations: string;
  root: Key;
  approver: Key;
  recovery: Key[];
  timestamp: Key;
  key: (name: string) => Promise<Key>;
  policy: () => Promise<Policy>;
  writePolicy: (changes: Record<string, unknown>) => Promise<void>;
}

export async function setupRecoveryOrg(t: TestContext, options: { mode?: 'shadow' | 'enforce'; freshness?: boolean; rotate?: number; revoke?: number } = {}): Promise<RecoveryOrg> {
  const dir = await tempDir(t, 'mago-ski-recovery-');
  const keys = path.join(dir, 'keys');
  await mkdir(keys);
  const key = async (name: string): Promise<Key> => {
    const pair = await generateKeyPair(path.join(keys, `${name}.pem`), path.join(keys, `${name}.pub`));
    return { priv: pair.privatePath, pub: pair.publicPath, keyId: pair.keyId };
  };
  const root = await key('root');
  const approver = await key('approver');
  const recovery = [await key('a'), await key('b'), await key('c')];
  const timestamp = await key('timestamp');
  const policyDir = path.join(dir, 'policy');
  await mkdir(policyDir);
  const trustRoot = path.join(policyDir, 'trust-root.json');
  const revocations = path.join(policyDir, 'revocations.json');
  const eventsPath = path.join(policyDir, 'root-events.json');
  const timestampPath = path.join(policyDir, 'timestamp.json');
  await initRoot({ rootKeyPath: root.priv, trustRootOut: trustRoot, revocationsOut: revocations, now: T0 });
  await addApprover({ rootKeyPath: root.priv, trustRootPath: trustRoot, now: T0, publicKeyPath: approver.pub, name: 'Reviewer', scopes: ['*'], expires: '180d' });
  await initRootEventLog(eventsPath);
  const set = await buildRecoverySet({ publicKeyPaths: recovery.map((item) => item.pub), rotateThreshold: options.rotate ?? 2, revokeThreshold: options.revoke ?? 1 });
  const policyPath = path.join(policyDir, 'policy.json');
  let document: Record<string, unknown> = {
    policy_version: 'mago.policy/v2',
    mode: options.mode ?? 'shadow',
    root_fingerprint: root.keyId,
    recovery: { key_ids: set.keyIds, rotate_threshold: set.rotateThreshold, revoke_threshold: set.revokeThreshold },
    root_events: 'root-events.json',
    trust_root: 'trust-root.json',
    revocations: 'revocations.json',
    state_file: 'state.json',
    decision_log: 'decisions.jsonl',
    ...(options.freshness ? { freshness: { timestamp: 'timestamp.json', key_id: timestamp.keyId, max_lifetime: '24h' } } : {}),
  };
  const writePolicy = async (changes: Record<string, unknown>) => {
    document = { ...document, ...changes };
    for (const [name, value] of Object.entries(changes)) if (value === undefined) delete document[name];
    await writeFile(policyPath, JSON.stringify(document, null, 2));
  };
  await writePolicy({});
  return {
    dir, policyDir, policyPath, statePath: path.join(policyDir, 'state.json'), logPath: path.join(policyDir, 'decisions.jsonl'),
    eventsPath, timestampPath, trustRoot, revocations, root, approver, recovery, timestamp, key,
    policy: async () => await loadPolicy(policyPath), writePolicy,
  };
}
