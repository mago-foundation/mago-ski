import { lstat, opendir, stat } from 'node:fs/promises';
import { homedir, hostname } from 'node:os';
import path from 'node:path';
import { canonicalBytes, exactKeys, isRecord, parseCanonicalJsonBytes, requireArray, requireString } from './canonical-json.ts';
import { appendToRegularFile, isInside, readRegularFile, realpathAllowingMissing, resolveInsideDirectory, writeFileAtomic } from './fs-safe.ts';
import { validateKeyId } from './keys.ts';
import { CERTIFICATE_FILENAME } from './tree-digest.ts';
import {
  loadTrustContext, unverifiable, verifySkill, type CertificateSource, type MinimumVersions,
  type TrustContext, type TrustContextResult, type VerificationResult,
} from './verify.ts';

export const POLICY_VERSION   = 'mago.policy/v1';
export const STATE_TYPE       = 'mago.host-state/v1';

const MAX_CERTIFICATE_BYTES               = 8 * 1024 * 1024;
/** Per-Skill budget across all certificate candidates (explicit file, policy directories, in-Skill file). */
export const MAX_CERTIFICATE_CANDIDATES   = 64;
export const MAX_CERTIFICATE_TOTAL_BYTES  = 32 * 1024 * 1024;
export type Mode = 'shadow' | 'enforce';

const POLICY_KEYS          = ['policy_version', 'mode', 'root_fingerprint', 'trust_root', 'revocations', 'certificate_dirs', 'skill_dirs', 'state_file', 'decision_log'];
const REQUIRED_POLICY_KEYS = ['policy_version', 'mode', 'root_fingerprint', 'trust_root', 'revocations'];

interface RootState {
  trust_root_version: number;
  revocations_version: number;
}

/*
 * Where hosts and the CLI read policy when none is given: $MAGO_SKI_POLICY (absolute, or "~/..."), else ~/.mago-ski/policy.json.
 * Never a path in the current directory, because the project being checked may be controlled by the code under review.
 */
export function defaultPolicyPath(
  env: NodeJS.ProcessEnv = process.env, 
  home: string = homedir()
): string {
  const configured = env.MAGO_SKI_POLICY;
  if (!configured) 
    return path.join(home, '.mago-ski', 'policy.json');
  
  if (configured === '~' || configured.startsWith('~/')) 
    return path.join(home, configured.slice(2));
  
  if (!path.isAbsolute(configured)) 
    throw new Error(`MAGO_SKI_POLICY must be an absolute path (or start with "~/"); got "${configured}"`);
  
  return configured;
}

export interface Policy {
  path:             string;
  mode:             Mode;
  rootKeyId:        string;
  trustRootPath:    string;
  revocationsPath:  string;
  certificateDirs:  string[];
  skillDirs:        string[];
  statePath:        string | null;
  decisionLogPath:  string | null;
}

/** Policy files are hand-edited JSON; paths are relative to the policy file's directory. */
export async function loadPolicy(policyPath: string): Promise<Policy> {
  const absolute  = path.resolve(policyPath);
  const bytes     = await readRegularFile(absolute, 'Policy file', 256 * 1024);
  let value: unknown;
  try {
    value = JSON.parse(bytes.toString('utf8'));
  } catch {
    throw new Error(`Policy file ${absolute} is not valid JSON`);
  }

  if (!isRecord(value)) 
    throw new Error('Policy file must contain a JSON object');

  for (const key of Object.keys(value)) 
    if (!POLICY_KEYS.includes(key)) 
      throw new Error(`Policy file has unsupported field "${key}"`);
  
  for (const key of REQUIRED_POLICY_KEYS) 
    if (!(key in value)) 
      throw new Error(`Policy file is missing "${key}"`);
  
  if (value.policy_version !== POLICY_VERSION) 
    throw new Error(`Policy file must declare policy_version "${POLICY_VERSION}"`);

  if (value.mode !== 'shadow' && value.mode !== 'enforce') 
    throw new Error('Policy mode must be "shadow" or "enforce"');
  
  const base = path.dirname(absolute);
  const resolvePath = (item: unknown, label: string) => 
    path.resolve(base, requireString(item, `Policy ${label}`, 4096));
  // decision_log and state_file are files this tool writes, so the policy may only place them in its own directory.
  const writablePath = async (item: unknown, label: string) =>
    item === undefined || item === null ? null : await resolveInsideDirectory(base, requireString(item, `Policy ${label}`, 4096), `Policy ${label}`);
  const optionalList = (item: unknown, label: string) => item === undefined ? [] : requireArray(item, `Policy ${label}`, 256).map((entry, index) => resolvePath(entry, `${label}[${index}]`));
  const policy: Policy = {
    path:             absolute,
    mode:             value.mode,
    rootKeyId:        validateKeyId(value.root_fingerprint, 'Policy root_fingerprint'),
    trustRootPath:    resolvePath(value.trust_root, 'trust_root'),
    revocationsPath:  resolvePath(value.revocations, 'revocations'),
    certificateDirs:  optionalList(value.certificate_dirs, 'certificate_dirs'),
    skillDirs:        optionalList(value.skill_dirs, 'skill_dirs'),
    statePath:        await writablePath(value.state_file, 'state_file'),
    decisionLogPath:  await writablePath(value.decision_log, 'decision_log'),
  };
  await rejectWriteTargetsThatOverlapInputs(policy);
  
  return policy;
}

/** A path with symlinks resolved where possible; falls back to the lexical path (the read itself will fail later). */
async function canonicalOrLexical(target: string): Promise<string> {
  try {
    return await realpathAllowingMissing(target);
  } catch {
    return path.resolve(target);
  }
}

/** decision_log and state_file are overwritten or appended to, so they must not be a file the policy reads. */
async function rejectWriteTargetsThatOverlapInputs(policy: Policy): Promise<void> {
  const inputs: Array<[string, string]>         = [
    ['the policy file', policy.path], ['trust_root', policy.trustRootPath], ['revocations', policy.revocationsPath],
  ];
  const directories                             = await Promise.all(policy.certificateDirs.map(canonicalOrLexical));
  const targets: Array<[string, string | null]> = [['state_file', policy.statePath], ['decision_log', policy.decisionLogPath]];
  const seen: Array<[string, string]>           = [];
  
  for (const [label, target] of targets) {
    if (!target) 
      continue;
    
    const canonical = await canonicalOrLexical(target);
    for (const [name, input] of inputs) {
      if (canonical === await canonicalOrLexical(input)) 
        throw new Error(`Policy ${label} must not be ${name}`);
    }
    
    if (directories.some((directory) => isInside(directory, canonical))) 
      throw new Error(`Policy ${label} must not be inside a certificate_dirs directory`);
    
    for (const [other, otherPath] of seen) 
      if (canonical === otherPath) 
        throw new Error(`Policy ${label} must not be the same file as ${other}`);
    
    seen.push([label, canonical]);
  }
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
  if (value.type !== STATE_TYPE || !isRecord(value.roots)) 
    throw new Error('host state file has an unsupported format');
  
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
    trustRootBytes              = await readRegularFile(policy.trustRootPath, 'Trust root', 4 * 1024 * 1024);
    revocationsBytes            = await readRegularFile(policy.revocationsPath, 'Revocation list', 8 * 1024 * 1024);
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
        trust_root_version:   Math.max(next.trust_root_version, seen?.trust_root_version ?? 0),
        revocations_version:  Math.max(next.revocations_version, seen?.revocations_version ?? 0),
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
    if ((error as NodeJS.ErrnoException)?.code === 'ENOENT') 
      return undefined;
    throw error;
  }
}

/*
 * Certificate lookup order: explicit file, policy certificate directories (<name>.cert.json), then the in-Skill certificate.
 * Candidates are read lazily, one at a time, so a caller that stops early never reads the rest and none are retained here.
 * Candidates come from the checkout under review, so a Skill may have at most MAX_CERTIFICATE_CANDIDATES candidate files
 * totalling MAX_CERTIFICATE_TOTAL_BYTES; going over throws (the Skill is UNVERIFIABLE) instead of reading further.
 */
export async function* iterateCertificates(skillName: string, skillRoot: string, certificateDirs: string[], explicit?: string): AsyncGenerator<CertificateSource> {
  let count = 0;
  let totalBytes = 0;
  const seen = new Set<string>();
  const account = (source: string, bytes: Buffer): CertificateSource => {
    count += 1;
    totalBytes += bytes.length;
    if (count > MAX_CERTIFICATE_CANDIDATES) throw new Error(`more than ${MAX_CERTIFICATE_CANDIDATES} certificate candidates for this Skill; reduce certificate_dirs or remove stray certificates`);
    if (totalBytes > MAX_CERTIFICATE_TOTAL_BYTES) throw new Error(`certificate candidates for this Skill exceed ${MAX_CERTIFICATE_TOTAL_BYTES} bytes in total`);
    return { source, bytes };
  };
  if (explicit) {
    const candidate = path.resolve(explicit);
    seen.add(candidate);
    yield account(candidate, await readRegularFile(candidate, 'Certificate', MAX_CERTIFICATE_BYTES));
  }
  for (const directory of certificateDirs) {
    const candidate = path.join(directory, `${skillName}.cert.json`);
    if (seen.has(candidate)) continue;
    seen.add(candidate);
    const bytes = await readOptional(candidate, 'Certificate');
    if (bytes) yield account(candidate, bytes);
  }
  const inSkill = path.join(skillRoot, CERTIFICATE_FILENAME);
  if (!seen.has(inSkill)) {
    const bytes = await readOptional(inSkill, 'Certificate');
    if (bytes) yield account(inSkill, bytes);
  }
}

/** Collects every candidate (within the same budget). Prefer `iterateCertificates`, which retains nothing. */
export async function discoverCertificates(skillName: string, skillRoot: string, certificateDirs: string[], explicit?: string): Promise<CertificateSource[]> {
  const sources: CertificateSource[] = [];
  for await (const source of iterateCertificates(skillName, skillRoot, certificateDirs, explicit)) sources.push(source);
  return sources;
}

/**
 * Finds Skill directories (directories containing SKILL.md) under the given roots.
 * Symbolic links are never skipped silently: hosts such as Pi follow them, so a linked Skill
 * directory or a linked SKILL.md is returned as a Skill, and verification then rejects it.
 */
export const MAX_DISCOVERY_DEPTH = 16;
/** Work budget for one discovery run over untrusted trees; exceeding either throws DiscoveryBudgetError. */
export const MAX_DISCOVERED_SKILLS = 1_000;
export const MAX_DISCOVERY_ENTRIES = 50_000;

export interface DiscoveryLimits {
  /** Maximum Skills (including directories reported as too deep) found. */
  maxSkills?: number;
  /** Maximum directory entries visited across all roots. */
  maxEntries?: number;
}

/** Discovery stopped because the tree is larger than the budget. It never returns a partial list: callers must fail closed. */
export class DiscoveryBudgetError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'DiscoveryBudgetError';
  }
}

export interface SkillDiscovery {
  skillDirs: string[];
  /** Directories at the depth limit that have subdirectories; Skills below them were not searched. */
  tooDeep: string[];
}

export async function findSkillDirs(roots: string[], maxDepth = MAX_DISCOVERY_DEPTH, limits: DiscoveryLimits = {}): Promise<SkillDiscovery> {
  const maxSkills = limits.maxSkills ?? MAX_DISCOVERED_SKILLS;
  const maxEntries = limits.maxEntries ?? MAX_DISCOVERY_ENTRIES;
  const found = new Set<string>();
  const tooDeep = new Set<string>();
  let entries = 0;
  const checkSkills = () => {
    if (found.size + tooDeep.size > maxSkills) throw new DiscoveryBudgetError(`more than ${maxSkills} Skills found under skill_dirs; narrow skill_dirs or split the repository`);
  };
  async function walk(directory: string, depth: number): Promise<void> {
    try {
      await lstat(path.join(directory, 'SKILL.md'));
      found.add(directory);
      checkSkills();
      return;
    } catch (error) {
      if ((error as NodeJS.ErrnoException)?.code !== 'ENOENT') throw error;
    }
    let dir;
    try {
      dir = await opendir(directory);
    } catch (error) {
      if ((error as NodeJS.ErrnoException)?.code === 'ENOENT') return;
      throw error;
    }
    for await (const child of dir) {
      entries += 1;
      if (entries > maxEntries) throw new DiscoveryBudgetError(`more than ${maxEntries} directory entries under skill_dirs; narrow skill_dirs or split the repository`);
      const childPath = path.join(directory, child.name);
      if (child.isSymbolicLink()) {
        try {
          if ((await stat(childPath)).isDirectory()) found.add(childPath);
        } catch {
          // A dangling link has nothing a host could load.
        }
        checkSkills();
        continue;
      }
      if (!child.isDirectory() || child.name === '.git' || child.name === 'node_modules') continue;
      // Hosts such as Pi search without a depth limit, so never skip deeper directories silently.
      if (depth + 1 > maxDepth) {
        tooDeep.add(childPath);
        checkSkills();
        continue;
      }
      await walk(childPath, depth + 1);
    }
  }
  for (const root of roots) await walk(path.resolve(root), 0);
  return { skillDirs: [...found].sort(), tooDeep: [...tooDeep].sort() };
}

/** Result for a directory discovery could not search; it fails in enforce mode and is reported in shadow mode. */
export function tooDeepResult(directory: string, now: Date): VerificationResult {
  return unverifiable(directory, path.basename(directory),
    `directory is deeper than the discovery limit (${MAX_DISCOVERY_DEPTH} levels below skill_dirs); Skills below it were not checked. Point skill_dirs closer to the Skills`, now);
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
  // One JSON object per line. JSON.stringify escapes newlines and control characters; also escape the Unicode
  // line separators some JSON Lines readers split on, plus C1 controls, DEL and bidi controls. The text is data, not shell syntax: never source a log.
  const line = JSON.stringify(record).replace(/[\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]/gu, (char) => `\\u${char.charCodeAt(0).toString(16).padStart(4, '0')}`);
  await appendToRegularFile(logPath, `${line}\n`, 'Decision log');
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
    certificates: (name, root) => iterateCertificates(name, root, policy.certificateDirs, options.certificate),
  });
}

