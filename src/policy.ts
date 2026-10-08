import { appendFile, lstat, opendir } from 'node:fs/promises';
import { hostname } from 'node:os';
import path from 'node:path';
import { canonicalBytes, exactKeys, isRecord, parseCanonicalJsonBytes, requireArray, requireString } from './canonical-json.ts';
import { readRegularFile, writeFileAtomic } from './fs-safe.ts';
import { validateKeyId } from './keys.ts';
import { CERTIFICATE_FILENAME } from './tree-digest.ts';
import {
  loadTrustContext, unverifiable, verifySkill, type CertificateSource, type MinimumVersions,
  type TrustContext, type TrustContextResult, type VerificationResult,
} from './verify.ts';

export const POLICY_VERSION = 'mago.policy/v1';
export const STATE_TYPE = 'mago.host-state/v1';
export const DEFAULT_POLICY_PATH = path.join('.mago-ski', 'policy.json');
const MAX_CERTIFICATE_BYTES = 8 * 1024 * 1024;

export type Mode = 'shadow' | 'enforce';

export interface Policy {
  path: string;
  mode: Mode;
  rootKeyId: string;
  trustRootPath: string;
  revocationsPath: string;
  certificateDirs: string[];
  skillDirs: string[];
  statePath: string | null;
  decisionLogPath: string | null;
}

const POLICY_KEYS = ['policy_version', 'mode', 'root_fingerprint', 'trust_root', 'revocations', 'certificate_dirs', 'skill_dirs', 'state_file', 'decision_log'];
const REQUIRED_POLICY_KEYS = ['policy_version', 'mode', 'root_fingerprint', 'trust_root', 'revocations'];

/** Policy files are hand-edited JSON; paths are relative to the policy file's directory. */
export async function loadPolicy(policyPath: string): Promise<Policy> {
  const absolute = path.resolve(policyPath);
  const bytes = await readRegularFile(absolute, 'Policy file', 256 * 1024);
  let value: unknown;
  try {
    value = JSON.parse(bytes.toString('utf8'));
  } catch {
    throw new Error(`Policy file ${absolute} is not valid JSON`);
  }
  if (!isRecord(value)) throw new Error('Policy file must contain a JSON object');
  for (const key of Object.keys(value)) if (!POLICY_KEYS.includes(key)) throw new Error(`Policy file has unsupported field "${key}"`);
  for (const key of REQUIRED_POLICY_KEYS) if (!(key in value)) throw new Error(`Policy file is missing "${key}"`);
  if (value.policy_version !== POLICY_VERSION) throw new Error(`Policy file must declare policy_version "${POLICY_VERSION}"`);
  if (value.mode !== 'shadow' && value.mode !== 'enforce') throw new Error('Policy mode must be "shadow" or "enforce"');
  const base = path.dirname(absolute);
  const resolvePath = (item: unknown, label: string) => path.resolve(base, requireString(item, `Policy ${label}`, 4096));
  const optionalList = (item: unknown, label: string) => item === undefined ? [] : requireArray(item, `Policy ${label}`, 256).map((entry, index) => resolvePath(entry, `${label}[${index}]`));
  return {
    path: absolute,
    mode: value.mode,
    rootKeyId: validateKeyId(value.root_fingerprint, 'Policy root_fingerprint'),
    trustRootPath: resolvePath(value.trust_root, 'trust_root'),
    revocationsPath: resolvePath(value.revocations, 'revocations'),
    certificateDirs: optionalList(value.certificate_dirs, 'certificate_dirs'),
    skillDirs: optionalList(value.skill_dirs, 'skill_dirs'),
    statePath: value.state_file === undefined || value.state_file === null ? null : resolvePath(value.state_file, 'state_file'),
    decisionLogPath: value.decision_log === undefined || value.decision_log === null ? null : resolvePath(value.decision_log, 'decision_log'),
  };
}

interface RootState {
  trust_root_version: number;
  revocations_version: number;
}

async function readState(statePath: string): Promise<Record<string, RootState>> {
  let bytes: Buffer;
  try {
    bytes = await readRegularFile(statePath, 'Host state file', 1024 * 1024);
  } catch (error) {
    if ((error as NodeJS.ErrnoException)?.code === 'ENOENT') return {};
    throw error;
  }
  const value = exactKeys(parseCanonicalJsonBytes(bytes, 'host state'), ['type', 'roots'], 'host state');
  if (value.type !== STATE_TYPE || !isRecord(value.roots)) throw new Error('host state file has an unsupported format');
  const roots: Record<string, RootState> = {};
  for (const [rootKeyId, entry] of Object.entries(value.roots)) {
    const fields = exactKeys(entry, ['trust_root_version', 'revocations_version'], 'host state root');
    roots[validateKeyId(rootKeyId, 'host state root key')] = {
      trust_root_version: Number(fields.trust_root_version), revocations_version: Number(fields.revocations_version),
    };
  }
  return roots;
}

/** Loads trust documents for a policy, enforcing rollback protection through the state file. */
export async function loadPolicyTrust(policy: Policy, now: Date): Promise<TrustContextResult> {
  let trustRootBytes: Buffer;
  let revocationsBytes: Buffer;
  let roots: Record<string, RootState> = {};
  try {
    trustRootBytes = await readRegularFile(policy.trustRootPath, 'Trust root', 4 * 1024 * 1024);
    revocationsBytes = await readRegularFile(policy.revocationsPath, 'Revocation list', 8 * 1024 * 1024);
    if (policy.statePath) roots = await readState(policy.statePath);
  } catch (error) {
    return { ok: false, verdict: 'UNVERIFIABLE', reason: (error as Error).message };
  }
  const seen = roots[policy.rootKeyId];
  const minimum: MinimumVersions | undefined = seen ? { trustRootVersion: seen.trust_root_version, revocationsVersion: seen.revocations_version } : undefined;
  const result = loadTrustContext({ trustRootBytes, revocationsBytes, rootKeyId: policy.rootKeyId, now, minimum });
  if (result.ok && policy.statePath) {
    const next = { trust_root_version: result.context.trustRoot.version, revocations_version: result.context.revocations.version };
    if (!seen || next.trust_root_version > seen.trust_root_version || next.revocations_version > seen.revocations_version) {
      roots[policy.rootKeyId] = {
        trust_root_version: Math.max(next.trust_root_version, seen?.trust_root_version ?? 0),
        revocations_version: Math.max(next.revocations_version, seen?.revocations_version ?? 0),
      };
      try {
        await writeFileAtomic(policy.statePath, canonicalBytes({ type: STATE_TYPE, roots }), 0o600);
      } catch (error) {
        return { ok: false, verdict: 'UNVERIFIABLE', reason: `cannot record trust versions in ${policy.statePath}: ${(error as Error).message}` };
      }
    }
  }
  return result;
}

async function readOptional(filePath: string, label: string): Promise<Buffer | undefined> {
  try {
    return await readRegularFile(filePath, label, MAX_CERTIFICATE_BYTES);
  } catch (error) {
    if ((error as NodeJS.ErrnoException)?.code === 'ENOENT') return undefined;
    throw error;
  }
}

/** Certificate lookup order: explicit file, policy certificate directories (<name>.cert.json), then the in-Skill certificate. */
export async function discoverCertificates(skillName: string, skillRoot: string, certificateDirs: string[], explicit?: string): Promise<CertificateSource[]> {
  const sources: CertificateSource[] = [];
  if (explicit) {
    const bytes = await readRegularFile(path.resolve(explicit), 'Certificate', MAX_CERTIFICATE_BYTES);
    sources.push({ source: path.resolve(explicit), bytes });
  }
  for (const directory of certificateDirs) {
    const candidate = path.join(directory, `${skillName}.cert.json`);
    const bytes = await readOptional(candidate, 'Certificate');
    if (bytes) sources.push({ source: candidate, bytes });
  }
  const inSkill = path.join(skillRoot, CERTIFICATE_FILENAME);
  const bytes = await readOptional(inSkill, 'Certificate');
  if (bytes) sources.push({ source: inSkill, bytes });
  return sources;
}

/** Finds Skill directories (directories containing SKILL.md) under the given roots. */
export async function findSkillDirs(roots: string[], maxDepth = 6): Promise<string[]> {
  const found: string[] = [];
  async function walk(directory: string, depth: number): Promise<void> {
    try {
      const entry = await lstat(path.join(directory, 'SKILL.md'));
      if (entry.isFile()) {
        found.push(directory);
        return;
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException)?.code !== 'ENOENT') throw error;
    }
    if (depth >= maxDepth) return;
    let dir;
    try {
      dir = await opendir(directory);
    } catch (error) {
      if ((error as NodeJS.ErrnoException)?.code === 'ENOENT') return;
      throw error;
    }
    for await (const child of dir) {
      if (!child.isDirectory() || child.name === '.git' || child.name === 'node_modules') continue;
      await walk(path.join(directory, child.name), depth + 1);
    }
  }
  for (const root of roots) await walk(path.resolve(root), 0);
  return found.sort();
}

export interface DecisionRecord {
  timestamp: string;
  host: string;
  mode: Mode;
  action: 'allow' | 'block' | 'would-block';
  event: string;
  skill: string;
  skill_dir: string;
  digest: string | null;
  certificate_id: string | null;
  verdict: string;
  reason: string;
}

export function actionFor(mode: Mode, verified: boolean): DecisionRecord['action'] {
  if (verified) return 'allow';
  return mode === 'enforce' ? 'block' : 'would-block';
}

export async function appendDecision(logPath: string | null, record: DecisionRecord): Promise<void> {
  if (!logPath) return;
  await appendFile(logPath, `${JSON.stringify(record)}\n`, { encoding: 'utf8', mode: 0o600 });
}

export function decisionRecord(result: VerificationResult, mode: Mode, event: string, host = `${hostname()}`): DecisionRecord {
  return {
    timestamp: result.checkedAt,
    host,
    mode,
    action: actionFor(mode, result.verdict === 'VERIFIED'),
    event,
    skill: result.skillName,
    skill_dir: result.skillDir,
    digest: result.digest,
    certificate_id: result.certificateId,
    verdict: result.verdict,
    reason: result.reason,
  };
}

/** Verifies one Skill under a policy, including trust loading. */
export async function verifyWithPolicy(policy: Policy, skillDir: string, options: { now: Date; skillName?: string; certificate?: string; context?: TrustContext }): Promise<VerificationResult> {
  let context = options.context;
  if (!context) {
    const loaded = await loadPolicyTrust(policy, options.now);
    if (!loaded.ok) return unverifiable(path.resolve(skillDir), options.skillName ?? path.basename(path.resolve(skillDir)), loaded.reason, options.now, loaded.verdict);
    context = loaded.context;
  }
  return verifySkill({
    skillDir,
    skillName: options.skillName,
    context,
    now: options.now,
    certificates: (name, root) => discoverCertificates(name, root, policy.certificateDirs, options.certificate),
  });
}

