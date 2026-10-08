import { chmod, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import type { TestContext } from 'node:test';
import { addApprover, approveSkill, initRoot } from '../src/admin.ts';
import { generateKeyPair } from '../src/keys.ts';

export const T0 = new Date('2026-10-01T00:00:00Z');

export function daysAfter(base: Date, days: number): Date {
  return new Date(base.getTime() + days * 86_400_000);
}

export async function tempDir(t: TestContext, prefix = 'mago-ski-test-'): Promise<string> {
  const directory = await mkdtemp(path.join(os.tmpdir(), prefix));
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
