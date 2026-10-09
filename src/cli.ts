#!/usr/bin/env node
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { addApprover, approveSkill, initRoot, removeApprover, updateRevocations } from './admin.ts';
import { parseCertificate } from './certificate.ts';
import { diffSkillTrees } from './diff.ts';
import { readRegularFile } from './fs-safe.ts';
import { generateKeyPair, validateKeyId } from './keys.ts';
import {
  appendDecision, decisionRecord, DEFAULT_POLICY_PATH, findSkillDirs, loadPolicy, loadPolicyTrust, tooDeepResult, verifyWithPolicy,
} from './policy.ts';
import { formatTimestamp } from './time.ts';
import { collectSkillTree, TREE_PROFILE } from './tree-digest.ts';
import { verifyTrustRoot } from './trust-root.ts';
import { unverifiable, type VerificationResult } from './verify.ts';

const usage = `mago-ski: organization-approved Skill certificates, enforced on the agent host.

Keys and trust (run by the organization's root key holder):
  mago-ski keygen --private-key FILE --public-key FILE
  mago-ski root init --root-key FILE --trust-root OUT --revocations OUT [--trust-root-expires 365d] [--revocations-expires 30d]
  mago-ski root add-approver --root-key FILE --trust-root FILE --public-key FILE --name LABEL --scope PATTERN [--scope ...] --expires 180d [--out FILE] [--trust-root-expires 365d]
  mago-ski root remove-approver --root-key FILE --trust-root FILE --key-id ID [--out FILE]
  mago-ski root show --trust-root FILE --root-fingerprint ID
  mago-ski revoke key --root-key FILE --revocations FILE --key-id ID --reason TEXT [--expires 30d] [--out FILE]
  mago-ski revoke digest --root-key FILE --revocations FILE --digest sha256:... --reason TEXT [--expires 30d] [--out FILE]
  mago-ski revoke refresh --root-key FILE --revocations FILE [--expires 30d] [--out FILE]

Approving Skills (run by a reviewer with an approver key):
  mago-ski approve SKILL_DIR --key FILE --expires 90d --reason TEXT [--name NAME] [--previous CERT|DIGEST] [--out FILE]

Checking Skills (uses .mago-ski/policy.json unless --policy is given):
  mago-ski verify SKILL_DIR [--policy FILE] [--name NAME] [--certificate FILE] [--json]
  mago-ski verify-all [--policy FILE] [--json]
  mago-ski digest SKILL_DIR [--explain]
  mago-ski diff --base DIR --candidate DIR
  mago-ski inspect CERTIFICATE

Verdicts: VERIFIED, UNAPPROVED_CHANGE, NO_CERTIFICATE, UNTRUSTED_SIGNER, REVOKED, EXPIRED, UNVERIFIABLE.
Exit codes: 0 success or VERIFIED; 1 any other verdict or a required re-certification; 2 usage or input error.

A certificate records who approved an exact Skill version. It does not certify that the Skill is safe.`;

class UsageError extends Error {}

interface Parsed {
  positional: string[];
  flags: Map<string, string[]>;
  booleans: Set<string>;
}

const BOOLEAN_FLAGS = new Set(['--json', '--explain', '--help']);

function parseArgs(args: string[]): Parsed {
  const parsed: Parsed = { positional: [], flags: new Map(), booleans: new Set() };
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index]!;
    if (BOOLEAN_FLAGS.has(arg)) {
      parsed.booleans.add(arg);
    } else if (arg.startsWith('--')) {
      const value = args[index + 1];
      if (value === undefined || value.startsWith('--') || value === '') throw new UsageError(`Missing value for ${arg}`);
      parsed.flags.set(arg, [...(parsed.flags.get(arg) ?? []), value]);
      index += 1;
    } else {
      parsed.positional.push(arg);
    }
  }
  return parsed;
}

function allow(parsed: Parsed, allowed: string[], positional: number, repeatable: string[] = []): void {
  for (const [flag, values] of parsed.flags) {
    if (!allowed.includes(flag)) throw new UsageError(`Unsupported option ${flag}`);
    if (values.length > 1 && !repeatable.includes(flag)) throw new UsageError(`${flag} may be given only once`);
  }
  for (const flag of parsed.booleans) if (flag !== '--json' && flag !== '--explain' && !allowed.includes(flag)) throw new UsageError(`Unsupported option ${flag}`);
  if (parsed.positional.length !== positional) throw new UsageError(`Expected ${positional} positional argument(s), got ${parsed.positional.length}`);
}

function one(parsed: Parsed, flag: string): string {
  const value = parsed.flags.get(flag)?.[0];
  if (!value) throw new UsageError(`${flag} is required`);
  return value;
}

function optional(parsed: Parsed, flag: string): string | undefined {
  return parsed.flags.get(flag)?.[0];
}

function print(value: unknown): void {
  process.stdout.write(`${JSON.stringify(value, null, 2)}\n`);
}

function printResult(result: VerificationResult, json: boolean): void {
  if (json) {
    const { files: _files, ...rest } = result;
    process.stdout.write(`${JSON.stringify(rest)}\n`);
    return;
  }
  const mark = result.verdict === 'VERIFIED' ? 'ok' : 'FAIL';
  process.stdout.write(`${mark.padEnd(4)} ${result.verdict.padEnd(17)} ${result.skillName}  ${result.reason}\n`);
}

async function runRoot(sub: string | undefined, parsed: Parsed, now: Date): Promise<number> {
  if (sub === 'init') {
    allow(parsed, ['--root-key', '--trust-root', '--revocations', '--trust-root-expires', '--revocations-expires'], 0);
    const result = await initRoot({
      rootKeyPath: one(parsed, '--root-key'), trustRootOut: one(parsed, '--trust-root'), revocationsOut: one(parsed, '--revocations'), now,
      trustRootExpires: optional(parsed, '--trust-root-expires'), revocationsExpires: optional(parsed, '--revocations-expires'),
    });
    print({ status: 'ROOT_INITIALIZED', root_fingerprint: result.rootKeyId, trust_root: result.trustRoot, revocations: result.revocations,
      next: 'Store the root private key offline. Put root_fingerprint in each host policy.' });
    return 0;
  }
  if (sub === 'add-approver') {
    allow(parsed, ['--root-key', '--trust-root', '--out', '--public-key', '--name', '--scope', '--expires', '--trust-root-expires'], 0, ['--scope']);
    const result = await addApprover({
      rootKeyPath: one(parsed, '--root-key'), trustRootPath: one(parsed, '--trust-root'), out: optional(parsed, '--out'), now,
      trustRootExpires: optional(parsed, '--trust-root-expires'), publicKeyPath: one(parsed, '--public-key'),
      name: one(parsed, '--name'), scopes: parsed.flags.get('--scope') ?? [], expires: one(parsed, '--expires'),
    });
    print({ status: 'APPROVER_ADDED', key_id: result.keyId, trust_root_version: result.version, trust_root: result.path });
    return 0;
  }
  if (sub === 'remove-approver') {
    allow(parsed, ['--root-key', '--trust-root', '--out', '--key-id', '--trust-root-expires'], 0);
    const result = await removeApprover({
      rootKeyPath: one(parsed, '--root-key'), trustRootPath: one(parsed, '--trust-root'), out: optional(parsed, '--out'), now,
      trustRootExpires: optional(parsed, '--trust-root-expires'), keyId: validateKeyId(one(parsed, '--key-id'), '--key-id'),
    });
    print({ status: 'APPROVER_REMOVED', trust_root_version: result.version, trust_root: result.path });
    return 0;
  }
  if (sub === 'show') {
    allow(parsed, ['--trust-root', '--root-fingerprint'], 0);
    const trustRoot = verifyTrustRoot(await readRegularFile(one(parsed, '--trust-root'), 'Trust root', 4 * 1024 * 1024),
      validateKeyId(one(parsed, '--root-fingerprint'), '--root-fingerprint'), now);
    print({
      version: trustRoot.version, issued_at: formatTimestamp(trustRoot.issuedAt), expires_at: formatTimestamp(trustRoot.expiresAt),
      root_fingerprint: trustRoot.root.keyId,
      approvers: trustRoot.approvers.map((entry) => ({ name: entry.name, key_id: entry.keyId, scopes: entry.scopes, expires_at: formatTimestamp(entry.expiresAt) })),
    });
    return 0;
  }
  throw new UsageError('Unknown root command; use init, add-approver, remove-approver or show');
}

async function runRevoke(sub: string | undefined, parsed: Parsed, now: Date): Promise<number> {
  const common = ['--root-key', '--revocations', '--out', '--expires'];
  const base = { rootKeyPath: '', revocationsPath: '', now } as const;
  if (sub !== 'key' && sub !== 'digest' && sub !== 'refresh') throw new UsageError('Unknown revoke command; use key, digest or refresh');
  if (sub === 'key') allow(parsed, [...common, '--key-id', '--reason'], 0);
  if (sub === 'digest') allow(parsed, [...common, '--digest', '--reason'], 0);
  if (sub === 'refresh') allow(parsed, common, 0);
  const result = await updateRevocations({
    ...base,
    rootKeyPath: one(parsed, '--root-key'),
    revocationsPath: one(parsed, '--revocations'),
    ...(optional(parsed, '--out') ? { out: one(parsed, '--out') } : {}),
    ...(optional(parsed, '--expires') ? { expires: one(parsed, '--expires') } : {}),
    ...(sub === 'key' ? { revokeKey: validateKeyId(one(parsed, '--key-id'), '--key-id'), reason: one(parsed, '--reason') } : {}),
    ...(sub === 'digest' ? { revokeDigest: one(parsed, '--digest'), reason: one(parsed, '--reason') } : {}),
  });
  print({ status: sub === 'refresh' ? 'REVOCATIONS_REFRESHED' : 'REVOKED', revocations_version: result.version, expires_at: formatTimestamp(result.expiresAt), revocations: result.path });
  return 0;
}

async function runVerify(parsed: Parsed, now: Date): Promise<number> {
  allow(parsed, ['--policy', '--name', '--certificate'], 1);
  const policy = await loadPolicy(optional(parsed, '--policy') ?? DEFAULT_POLICY_PATH);
  const skillDir = parsed.positional[0]!;
  const result = await verifyWithPolicy(policy, skillDir, {
    now, ...(optional(parsed, '--name') ? { skillName: one(parsed, '--name') } : {}),
    ...(optional(parsed, '--certificate') ? { certificate: one(parsed, '--certificate') } : {}),
  });
  await appendDecision(policy.decisionLogPath, decisionRecord(result, policy.mode, 'cli-verify'));
  printResult(result, parsed.booleans.has('--json'));
  return result.verdict === 'VERIFIED' ? 0 : 1;
}

async function runVerifyAll(parsed: Parsed, now: Date): Promise<number> {
  allow(parsed, ['--policy'], 0);
  const policy = await loadPolicy(optional(parsed, '--policy') ?? DEFAULT_POLICY_PATH);
  if (policy.skillDirs.length === 0) throw new UsageError('Policy has no skill_dirs to scan');
  const { skillDirs, tooDeep } = await findSkillDirs(policy.skillDirs);
  const trust = await loadPolicyTrust(policy, now);
  let failures = 0;
  const results: VerificationResult[] = [];
  for (const skillDir of skillDirs) {
    results.push(trust.ok
      ? await verifyWithPolicy(policy, skillDir, { now, context: trust.context })
      : unverifiable(skillDir, path.basename(skillDir), trust.reason, now, trust.verdict));
  }
  for (const directory of tooDeep) results.push(tooDeepResult(directory, now));
  for (const result of results) {
    if (result.verdict !== 'VERIFIED') failures += 1;
    await appendDecision(policy.decisionLogPath, decisionRecord(result, policy.mode, 'cli-verify-all'));
    printResult(result, parsed.booleans.has('--json'));
  }
  if (!parsed.booleans.has('--json')) {
    process.stdout.write(`${results.length - failures}/${results.length} Skills verified (mode: ${policy.mode})\n`);
  }
  return failures === 0 ? 0 : 1;
}

export async function runCli(argv: string[] = process.argv.slice(2), now: Date = new Date()): Promise<number> {
  if (argv.length === 0 || argv[0] === '--help' || argv[0] === '-h' || argv[0] === 'help') {
    process.stdout.write(`${usage}\n`);
    return 0;
  }
  const [command, maybeSub] = argv;
  const hasSub = command === 'root' || command === 'revoke';
  const parsed = parseArgs(argv.slice(hasSub ? 2 : 1));
  switch (command) {
    case 'keygen': {
      allow(parsed, ['--private-key', '--public-key'], 0);
      const pair = await generateKeyPair(one(parsed, '--private-key'), one(parsed, '--public-key'));
      print({ status: 'KEY_CREATED', key_id: pair.keyId, private_key: pair.privatePath, public_key: pair.publicPath });
      process.stderr.write('Keep the private key secret and outside any Skill directory.\n');
      return 0;
    }
    case 'root':
      return await runRoot(maybeSub, parsed, now);
    case 'revoke':
      return await runRevoke(maybeSub, parsed, now);
    case 'approve': {
      allow(parsed, ['--key', '--expires', '--reason', '--name', '--previous', '--out'], 1);
      const result = await approveSkill({
        skillDir: parsed.positional[0]!, approverKeyPath: one(parsed, '--key'), now, expires: one(parsed, '--expires'),
        reason: one(parsed, '--reason'),
        ...(optional(parsed, '--name') ? { name: one(parsed, '--name') } : {}),
        ...(optional(parsed, '--previous') ? { previous: one(parsed, '--previous') } : {}),
        ...(optional(parsed, '--out') ? { out: one(parsed, '--out') } : {}),
      });
      print({ status: 'CERTIFICATE_ISSUED', skill: result.skillName, digest: result.digest, certificate_id: result.certificateId,
        expires_at: formatTimestamp(result.expiresAt), certificate: result.path });
      return 0;
    }
    case 'verify':
      return await runVerify(parsed, now);
    case 'verify-all':
      return await runVerifyAll(parsed, now);
    case 'digest': {
      allow(parsed, [], 1);
      const tree = await collectSkillTree(parsed.positional[0]!);
      if (parsed.booleans.has('--explain')) {
        print({ profile: TREE_PROFILE, digest: tree.digest, root: tree.root, total_bytes: tree.totalBytes, files: tree.files, excluded: tree.excluded });
      } else {
        process.stdout.write(`${tree.digest}\n`);
      }
      return 0;
    }
    case 'diff': {
      allow(parsed, ['--base', '--candidate'], 0);
      const result = await diffSkillTrees(one(parsed, '--base'), one(parsed, '--candidate'));
      print(result);
      return result.recertification_required ? 1 : 0;
    }
    case 'inspect': {
      allow(parsed, [], 1);
      const certificate = parseCertificate(await readRegularFile(parsed.positional[0]!, 'Certificate', 8 * 1024 * 1024));
      print({
        certificate_id: certificate.id, skill: certificate.skillName, digest: certificate.digest, approver_key_id: certificate.approverKeyId,
        issued_at: formatTimestamp(certificate.issuedAt), expires_at: formatTimestamp(certificate.expiresAt), reason: certificate.reason,
        previous_digest: certificate.previousDigest, file_count: certificate.files.length,
        note: 'Structure only. Run mago-ski verify to check the signature against your trust root.',
      });
      return 0;
    }
    default:
      throw new UsageError(`Unknown command: ${command}`);
  }
}

const invokedPath = process.argv[1] ? path.resolve(process.argv[1]) : '';
if (invokedPath === fileURLToPath(import.meta.url)) {
  runCli().then((code) => {
    process.exitCode = code;
  }, (error: unknown) => {
    process.stderr.write(`mago-ski: ${(error as Error)?.message ?? 'operation failed'}\n`);
    if (error instanceof UsageError) process.stderr.write('Run "mago-ski --help" for usage.\n');
    process.exitCode = 2;
  });
}
