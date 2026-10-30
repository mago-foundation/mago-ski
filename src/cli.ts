#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { addApprover, approveSkill, initRoot, removeApprover, updateRevocations } from './admin.ts';
import { parseCertificate } from './certificate.ts';
import { diffSkillTrees } from './diff.ts';
import { readRegularFile } from './fs-safe.ts';
import { generateKeyPair, validateKeyId } from './keys.ts';
import {
  appendDecision, decisionRecord, defaultPolicyPath, findSkillDirs, loadPolicy, loadPolicyTrust, tooDeepResult, verifyWithPolicy,
} from './policy.ts';
import { isMainModule } from './main-module.ts';
import { formatTimestamp } from './time.ts';
import { collectSkillTree, TREE_PROFILE } from './tree-digest.ts';
import { verifyTrustRoot } from './trust-root.ts';
import { unverifiable, type VerificationResult } from './verify.ts';
import { createRequire } from 'node:module';

const usage = `mago-ski — organization-approved Skill certificates,
           enforced on the agent host

USAGE
  mago-ski <command> [options]

KEYS AND TRUST  (root key holder)
  keygen                 Create an Ed25519 key pair
  root init              Create the trust root and revocation list
  root add-approver      Add or replace an approver
  root remove-approver   Remove an approver
  root show              Verify and print a trust root
  revoke key             Revoke an approver key
  revoke digest          Revoke one approved Skill version
  revoke refresh         Re-sign the revocation list

APPROVING SKILLS  (reviewer)
  approve SKILL_DIR      Issue a certificate for a Skill

CHECKING SKILLS
  verify SKILL_DIR       Check one Skill, print its verdict
  verify-all             Check every Skill in the policy
  digest SKILL_DIR       Print a Skill's tree digest
  diff                   Compare two versions of a Skill
  inspect CERTIFICATE    Print a certificate's contents

POLICY
  --policy FILE, else $MAGO_SKI_POLICY, else
  ~/.mago-ski/policy.json (never the current directory)

VERDICTS
  VERIFIED  UNAPPROVED_CHANGE  NO_CERTIFICATE
  UNTRUSTED_SIGNER  REVOKED  EXPIRED  UNVERIFIABLE

EXIT CODES
  0  success, or VERIFIED
  1  any other verdict, or re-certification required
  2  usage or input error

Run "mago-ski <command> --help" for a command's options,
and "mago-ski --version" for the version.

A certificate records who approved an exact Skill
version. It does not certify that the Skill is safe.`;

const DURATION_NOTE = 'Durations are a number plus d, h or m, for example 90d, 12h or 30m.';


/* ******************************************************************************************  */
/** Per-command help: `mago-ski <command> --help`. Keys are "command" or "command subcommand". */
/* ******************************************************************************************  */
const COMMAND_HELP: Record<string, string> = {
  keygen: `Usage: mago-ski keygen --private-key FILE --public-key FILE

Creates an Ed25519 key pair for a root key or an approver key.

  --private-key 	FILE	where to write the private key (created with mode 600; must not exist yet)
  --public-key 		FILE	where to write the public key

Keep private keys secret and outside every Skill directory; keygen refuses to write inside one.
Prints the key id (sha256:...), which identifies the key in trust roots and revocations.`,

/* ******************************************************************************************  */
/** Per-command: root                                                                          */
/* ******************************************************************************************  */
  root: `Usage: mago-ski root <init | add-approver | remove-approver | show> [options]

Manages the organization's signed trust root (who may approve which Skills).
Run "mago-ski root <subcommand> --help" for details.`,

  /* *************************************** */
  /* 		Per-command "root" -> "root init"    */
  /* *************************************** */
  'root init': `Usage: mago-ski root init --root-key FILE --trust-root OUT --revocations OUT [options]

Creates version 1 of the signed trust root (no approvers yet) and an empty signed revocation list.

  --root-key FILE              the root private key (keep it offline)
  --trust-root OUT             where to write trust-root.json (must not exist yet)
  --revocations OUT            where to write revocations.json (must not exist yet)
  --trust-root-expires DUR     trust root lifetime (default 365d)
  --revocations-expires DUR    revocation list lifetime (default 30d; republish before it expires)

Prints root_fingerprint: put it in every host policy as "root_fingerprint".
${DURATION_NOTE}`,

  /* ******************************************** */
  /* 		Per-command "root" -> "root add-approver  */
  /* ******************************************** */
  'root add-approver': `Usage: mago-ski root add-approver --root-key FILE --trust-root FILE --public-key FILE --name LABEL --scope PATTERN [--scope ...] --expires DUR [options]

Adds (or replaces) an approver and re-signs the trust root with the next version.

  --root-key FILE              the root private key
  --trust-root FILE            the current trust root (updated in place unless --out is given)
  --public-key FILE            the approver's public key
  --name LABEL                 a readable name, shown in verdicts
  --scope PATTERN              Skill names this approver may approve; repeat for several.
                               "*" = every Skill, "docs-*" = names starting with docs-, otherwise an exact name
  --expires DUR                how long the approver key stays valid
  --out FILE                   write the new trust root here instead
  --trust-root-expires DUR     also set a new trust root lifetime
${DURATION_NOTE}`,

  /* ************************************************* */
  /*		Per-command "root" -> "root remove-approver"   */
    /* *********************************************** */
  'root remove-approver': `Usage: mago-ski root remove-approver --root-key FILE --trust-root FILE --key-id ID [--out FILE] [--trust-root-expires DUR]

Removes an approver and re-signs the trust root. Certificates from that approver stop verifying once hosts read
the new trust root. If the key may be compromised, also revoke it with "mago-ski revoke key".`,

  /* ************************************** */
  /*		Per-command "root" -> "root show"   */
  /* ************************************** */
  'root show': `Usage: mago-ski root show --trust-root FILE --root-fingerprint ID

Verifies a trust root against the pinned root fingerprint and prints its version, expiry and approvers.`,

/* ******************************************************************************************  */
/** Per-command: revoke                                                                        */
/* ******************************************************************************************  */
  revoke: `Usage: mago-ski revoke <key | digest | refresh> [options]

Updates the organization's signed revocation list. Run "mago-ski revoke <subcommand> --help" for details.`,

  /* *************************************** */
  /*		Per-command "revoke" -> "revoke key" */
  /* *************************************** */
  'revoke key': `Usage: mago-ski revoke key --root-key FILE --revocations FILE --key-id ID --reason TEXT [--expires DUR] [--out FILE]

Revokes an approver key: every certificate it signed stops verifying once hosts read the new list.

  --key-id ID       the approver's key id (sha256:...)
  --reason TEXT     shown in verdicts
  --expires DUR     lifetime of the new list (default 30d)
${DURATION_NOTE}`,

  /* ****************************************** */
  /*		Per-command "revoke" -> "revoke digest" */
  /* ****************************************** */
  'revoke digest': `Usage: mago-ski revoke digest --root-key FILE --revocations FILE --digest sha256:... --reason TEXT [--expires DUR] [--out FILE]

Revokes one approved Skill version (its tree digest), whoever signed it.
${DURATION_NOTE}`,

  /* ******************************************* */
  /*		Per-command "revoke" -> "revoke refresh" */
  /* ******************************************* */
  'revoke refresh': `Usage: mago-ski revoke refresh --root-key FILE --revocations FILE [--expires DUR] [--out FILE]

Re-signs the revocation list with the next version and a new expiry, without changing its entries.
Hosts refuse an expired list, so refresh it before it expires (default lifetime 30d).`,

/* ******************************************************************************************  */
/** Per-command: approve                                                                       */
/* ******************************************************************************************  */
  approve: `Usage: mago-ski approve SKILL_DIR --key FILE --expires DUR --reason TEXT [options]

Issues a certificate for the exact current bytes of a Skill, signed with your approver key.

  --key FILE           your approver private key (must be outside the Skill directory)
  --expires DUR        how long the approval is valid
  --reason TEXT        what you reviewed; stored in the certificate
  --name NAME          Skill name (default: "name" in SKILL.md, else the directory name)
  --previous CERT|DIG  the previously approved certificate or digest, for the update history
  --out FILE           where to write the certificate (default: SKILL_DIR/.mago-ski-cert.json)
  --expect-digest DIG  the digest you reviewed (sha256:...); refuses to sign if the Skill changed since

Refuses a Skill that contains a private key. A certificate records who approved which exact version;
it does not certify that the Skill is safe.
${DURATION_NOTE}`,

/* ******************************************************************************************  */
/** Per-command: verify                                                                        */
/* ******************************************************************************************  */
  verify: `Usage: mago-ski verify SKILL_DIR [--policy FILE] [--name NAME] [--certificate FILE] [--json]

Checks one Skill against the policy's trust root and revocation list, and prints its verdict.

  --policy FILE        policy file (default: $MAGO_SKI_POLICY, which must be absolute, else ~/.mago-ski/policy.json;
                       never a file in the current directory, which the code under review may control)
  --name NAME          Skill name to check (default: "name" in SKILL.md, else the directory name)
  --certificate FILE   also try this certificate
  --json               print the result as JSON

Exit code 0 when VERIFIED, 1 for any other verdict, 2 for usage or input errors.`,
  
  /* ******************************************* */
  /*		Per-command "verify" -> "verify-all"     */
  /* ******************************************* */
  'verify-all': `Usage: mago-ski verify-all [--policy FILE] [--json]

Checks every Skill found under the policy's skill_dirs and prints one line per Skill and a summary.
Exits 1 if any Skill is not VERIFIED, in shadow mode too (shadow mode affects hosts, not this exit code).`,

/* ******************************************************************************************  */
/** Per-command: digest                                                                        */
/* ******************************************************************************************  */
  digest: `Usage: mago-ski digest SKILL_DIR [--explain]

Prints the Skill's tree digest (sha256:...). --explain also lists every covered file, its hash and
executable bit, and the paths excluded from the digest.`,

/* ******************************************************************************************  */
/** Per-command: diff                                                                          */
/* ******************************************************************************************  */
  diff: `Usage: mago-ski diff --base DIR --candidate DIR

Compares two versions of a Skill: changed files and Markdown sections, executable-bit changes, and added
or removed network origins. Exits 1 when the digest changed, since that always needs a new certificate.`,

/* ******************************************************************************************  */
/** Per-command: inspect                                                                       */
/* ******************************************************************************************  */
  inspect: `Usage: mago-ski inspect CERTIFICATE

Prints a certificate's Skill, digest, approver, dates and reason. Checks structure only; use
"mago-ski verify" to check its signature against your trust root.`,
};

/* ******************************************************************************************  */
/* Utility functions for the CLI. */
const require = createRequire(import.meta.url);
type PackageJson = { version?: string };
function readVersion(): string {
    try {
      const pkg = require('#package.json') as PackageJson;
      return pkg.version ?? 'unknown';
    } 
    catch {
      return 'unknown';
    }
  }

/* Usage error thrown for when users misuse the CLI. */
class UsageError extends Error { }

/* Parsed command-line arguments. */
interface Parsed {
  positional: string[];             /// Positional arguments, in order.
  flags: Map<string, string[]>;     /// Flags with values.
  booleans: Set<string>;            /// Boolean flags with no value.
}

/* The actual boolean flags that should take no value. */
const BOOLEAN_FLAGS = new Set(['--json', '--explain', '--help']);

/* flags Map: A map of flags to their values. */
function addFlag(flags: Map<string, string[]>, flag: string, value: string): void {
  const values = flags.get(flag) ?? [];
  values.push(value);
  flags.set(flag, values);
}

/* Parses command-line arguments into a Parsed object. */
function parseArgs(args: string[]): Parsed {
  const parsed : Parsed = {
    positional: [],
    flags: new Map(),
    booleans: new Set()
  };

  for (let index = 0; index < args.length; index++) {
    const arg = args[index]!;

    /* 1. If it's a boolean flag, add it to the set of booleans. */
    if (BOOLEAN_FLAGS.has(arg))
      parsed.booleans.add(arg);

    /* 2. If it starts with --, it's a flag with a value. */
    else if (arg.startsWith('--')) {
      const value = args[index + 1];
      
      /* 3. If the value is missing or starts with --, throw an error. */
      if (value === undefined || value.startsWith('--') || value === '')
        throw new UsageError(`Missing value for ${arg}`);

      addFlag(parsed.flags, arg, value);
      index += 1;
    }
    else
      parsed.positional.push(arg);
  }
  
  return parsed;
}

/* Validation function */
function allow(
  parsed: Parsed, 
  allowed: string[] = [], 
  positional: number | { min?: number; max?: number } = 0, 
  repeatable: string[] = []
): void {

  /* Check flags for validity and repeatability. */
  for (const [flag, values] of parsed.flags) {
    if (!allowed.includes(flag))
      throw new UsageError(`Unsupported option ${flag}`);

    if (values.length > 1 && !repeatable.includes(flag))
      throw new UsageError(`${flag} may be given only once`);
  }

  /* Check boolean flags for validity. */
  for (const flag of parsed.booleans)
    if (!BOOLEAN_FLAGS.has(flag) && !allowed.includes(flag))
      throw new UsageError(`Unsupported option ${flag}`);

  /* Check positional arguments count. */
  const count = parsed.positional.length;
  const { min, max } = typeof positional === 'number'
    ? {
      min: positional,
      max: positional
    } : positional;
    
    /* Exact? */
    if (min !== undefined && min === max && count !== min)
      throw new UsageError(`Expected exactly ${min} positional argument(s), got ${count}`);
    /* Under minimum? */
    if (min !== undefined && count < min)
      throw new UsageError(`Expected at least ${min} positional argument(s), got ${count}`);
    /* Over maximum? */
    if (max !== undefined && count > max)
      throw new UsageError(`Expected at most ${max} positional argument(s), got ${count}`);
  }

/* First value of a flag, or throw if missing. */
function one(parsed: Parsed, flag: string): string {
  const value = parsed.flags.get(flag)?.[0];

  if (!value) 
    throw new UsageError(`${flag} is required`);

  return value;
}

/* ******************************************************************************************  */
/* Optional first value of a flag, or undefined if missing. */
function optional(parsed: Parsed, flag: string): string | undefined {
  return parsed.flags.get(flag)?.[0];
}

/* Prints a value as JSON to stdout. */
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
/* ******************************************************************************************  */

async function runRoot(
  sub: string | undefined, 
  parsed: Parsed, 
  now: Date
): Promise<number> {
  if (sub === 'init') {
    allow(parsed, ['--root-key', '--trust-root', '--revocations', '--trust-root-expires', '--revocations-expires'], 0);
    const result = await initRoot({
      rootKeyPath: one(parsed, '--root-key'), 
      trustRootOut: one(parsed, '--trust-root'), 
      revocationsOut: one(parsed, '--revocations'), 
      now,
      trustRootExpires: optional(parsed, '--trust-root-expires'), 
      revocationsExpires: optional(parsed, '--revocations-expires'),
    });

    print({
      status: 'ROOT_INITIALIZED', 
      root_fingerprint: result.rootKeyId, 
      trust_root: result.trustRoot, 
      revocations: result.revocations,
      next: 'Store the root private key offline. Put root_fingerprint in each host policy.'
    });
    return 0;
  }

  if (sub === 'add-approver') {
    allow(parsed, ['--root-key', '--trust-root', '--out', '--public-key', '--name', '--scope', '--expires', '--trust-root-expires'], 0, ['--scope']);
    const result = await addApprover({
      rootKeyPath: one(parsed, '--root-key'), 
      trustRootPath: one(parsed, '--trust-root'), 
      out: optional(parsed, '--out'), 
      now,
      trustRootExpires: optional(parsed, '--trust-root-expires'), 
      publicKeyPath: one(parsed, '--public-key'),
      name: one(parsed, '--name'), 
      scopes: parsed.flags.get('--scope') ?? [], 
      expires: one(parsed, '--expires'),
    });
    
    print({ 
      status: 'APPROVER_ADDED', 
      key_id: result.keyId, 
      trust_root_version: result.version, 
      trust_root: result.path 
    });
    return 0;
  }

  if (sub === 'remove-approver') {
    allow(parsed, ['--root-key', '--trust-root', '--out', '--key-id', '--trust-root-expires'], 0);
    const result = await removeApprover({
      rootKeyPath: one(parsed, '--root-key'), 
      trustRootPath: one(parsed, '--trust-root'), 
      out: optional(parsed, '--out'), 
      now,
      trustRootExpires: optional(parsed, '--trust-root-expires'), 
      keyId: validateKeyId(one(parsed, '--key-id'), '--key-id'),
    });
    print({ 
      status: 'APPROVER_REMOVED', 
      trust_root_version: result.version, 
      trust_root: result.path 
    });
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

async function runRevoke(
  sub: string | undefined, 
  parsed: Parsed, now: Date
): Promise<number> {
  
  const common = ['--root-key', '--revocations', '--out', '--expires'];
  const base = { rootKeyPath: '', revocationsPath: '', now } as const;
  
  if (sub !== 'key' && sub !== 'digest' && sub !== 'refresh') 
    throw new UsageError('Unknown revoke command; use key, digest or refresh');

  if (sub === 'key') 
    allow(parsed, [...common, '--key-id', '--reason'], 0);

  if (sub === 'digest') 
    allow(parsed, [...common, '--digest', '--reason'], 0);

  if (sub === 'refresh') 
    allow(parsed, common, 0);
  
  const result = await updateRevocations({
    ...base,
    rootKeyPath: one(parsed, '--root-key'),
    revocationsPath: one(parsed, '--revocations'),
    ...(optional(parsed, '--out') ? { out: one(parsed, '--out') } : {}),
    ...(optional(parsed, '--expires') ? { expires: one(parsed, '--expires') } : {}),
    ...(sub === 'key' ? { revokeKey: validateKeyId(one(parsed, '--key-id'), '--key-id'), reason: one(parsed, '--reason') } : {}),
    ...(sub === 'digest' ? { revokeDigest: one(parsed, '--digest'), reason: one(parsed, '--reason') } : {}),
  });
  
  print({ 
    status: sub === 'refresh' ? 'REVOCATIONS_REFRESHED' : 'REVOKED', 
    revocations_version: result.version, 
    expires_at: formatTimestamp(result.expiresAt), 
    revocations: result.path 
  });
  return 0;
}

/** Loads the policy named by --policy, else the host default. The checkout being verified never chooses its own root. */
async function loadCliPolicy(
  parsed: Parsed
) {
  
  const explicit = optional(parsed, '--policy');
  let policyPath: string;
  
  try {
    policyPath = explicit ?? defaultPolicyPath();
  } 
  catch (error) {
    throw new UsageError((error as Error).message);
  }
  
  try {
    return await loadPolicy(policyPath);
  } 
  catch (error) {
    if (!explicit && (error as NodeJS.ErrnoException)?.code === 'ENOENT') {
      throw new UsageError(`No policy at ${policyPath}. Pass --policy FILE, or set MAGO_SKI_POLICY to an absolute path`);
    }
    throw error;
  }
}

async function runVerify(
  parsed: Parsed, 
  now: Date
): Promise<number> {
  
  allow(parsed, ['--policy', '--name', '--certificate'], 1);
  
  const policy = await loadCliPolicy(parsed);
  const skillDir = parsed.positional[0]!;
  const result = await verifyWithPolicy(policy, skillDir, {
    now,
    ...(optional(parsed, '--name') ? { skillName: one(parsed, '--name') } : {}),
    ...(optional(parsed, '--certificate') ? { certificate: one(parsed, '--certificate') } : {}),
  });

  await appendDecision(policy.decisionLogPath, decisionRecord(result, policy.mode, 'cli-verify'));
  printResult(result, parsed.booleans.has('--json'));
  return result.verdict === 'VERIFIED' ? 0 : 1;
}

async function runVerifyAll(
  parsed: Parsed, 
  now: Date
): Promise<number> {
  
  allow(parsed, ['--policy'], 0);
  const policy = await loadCliPolicy(parsed);
  
  if (policy.skillDirs.length === 0) 
    throw new UsageError('Policy has no skill_dirs to scan');
  
  const { skillDirs, tooDeep } = await findSkillDirs(policy.skillDirs);
  const trust = await loadPolicyTrust(policy, now);
  
  let failures = 0;
  const results: VerificationResult[] = [];
  for (const skillDir of skillDirs) {
    results.push(trust.ok
      ? await verifyWithPolicy(policy, skillDir, { now, context: trust.context })
      : unverifiable(skillDir, path.basename(skillDir), trust.reason, now, trust.verdict));
  }
  
  for (const directory of tooDeep) 
    results.push(tooDeepResult(directory, now));
  
  for (const result of results) {
    if (result.verdict !== 'VERIFIED')
      failures += 1;

    await appendDecision(policy.decisionLogPath, decisionRecord(result, policy.mode, 'cli-verify-all'));
    printResult(result, parsed.booleans.has('--json'));
  }
  
  if (!parsed.booleans.has('--json'))
    process.stdout.write(`${results.length - failures}/${results.length} Skills verified (mode: ${policy.mode})\n`);
  
  return failures === 0 ? 0 : 1;
}

export async function runCli(
  argv: string[] = process.argv.slice(2), 
  now: Date = new Date()
): Promise<number> {

  if (argv[0] === '--version' || argv[0] === '-V' || argv[0] === 'version') {
    process.stdout.write(`mago-ski ${readVersion()}\n`);
    return 0;
  }
  
  // "mago-ski help verify" is the same as "mago-ski verify --help".
  if (argv[0] === 'help' && argv.length > 1) 
    argv = [...argv.slice(1), '--help'];
  
  if (argv.length === 0 || argv[0] === '--help' || argv[0] === '-h' || argv[0] === 'help') {
    process.stdout.write(`${usage}\n`);
    return 0;
  }
  
  const [command, maybeSub] = argv;
  if (argv.slice(1).some((arg) => arg === '--help' || arg === '-h')) {
    const sub = maybeSub && !maybeSub.startsWith('-') ? `${command} ${maybeSub}` : undefined;
    const text = (sub && COMMAND_HELP[sub]) ?? COMMAND_HELP[command!];
    
    if (!text) 
      throw new UsageError(`Unknown command: ${command}`);
    
    process.stdout.write(`${text}\n`);
    return 0;
  }

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
      allow(parsed, ['--key', '--expires', '--reason', '--name', '--previous', '--out', '--expect-digest'], 1);
      const result = await approveSkill({
        skillDir: parsed.positional[0]!, 
        approverKeyPath: one(parsed, '--key'), 
        now, 
        expires: one(parsed, '--expires'),
        reason: one(parsed, '--reason'),
        ...(optional(parsed, '--name') ? { name: one(parsed, '--name') } : {}),
        ...(optional(parsed, '--previous') ? { previous: one(parsed, '--previous') } : {}),
        ...(optional(parsed, '--out') ? { out: one(parsed, '--out') } : {}),
        ...(optional(parsed, '--expect-digest') ? { expectDigest: one(parsed, '--expect-digest') } : {}),
      });

      print({
        status: 'CERTIFICATE_ISSUED', 
        skill: result.skillName, 
        digest: result.digest, 
        certificate_id: result.certificateId,
        expires_at: formatTimestamp(result.expiresAt), 
        certificate: result.path
      });

      return 0;
    }
    
    case 'verify':
      return await runVerify(parsed, now);
    case 'verify-all':
      return await runVerifyAll(parsed, now);
    case 'digest': {
      allow(parsed, [], 1);
      
      const tree = await collectSkillTree(parsed.positional[0]!);
      if (parsed.booleans.has('--explain'))
        print({ profile: TREE_PROFILE, digest: tree.digest, root: tree.root, total_bytes: tree.totalBytes, files: tree.files, excluded: tree.excluded });
      else
        process.stdout.write(`${tree.digest}\n`);
      return 0;
    }
    
    case 'diff': {
      if (parsed.positional.length > 0)
        throw new UsageError(`diff takes the two directories as options: mago-ski diff --base ${parsed.positional[0]} --candidate ${parsed.positional[1] ?? 'DIR'}`);
      allow(parsed, ['--base', '--candidate'], 0);
      
      const result = await diffSkillTrees(one(parsed, '--base'), one(parsed, '--candidate'));
      print(result);
      
      return result.recertification_required ? 1 : 0;
    }
    case 'inspect': {
      allow(parsed, [], 1);
      
      const certificate = parseCertificate(await readRegularFile(parsed.positional[0]!, 'Certificate', 8 * 1024 * 1024));
      print({
        certificate_id: certificate.id, 
        skill: certificate.skillName, 
        digest: certificate.digest, 
        approver_key_id: certificate.approverKeyId,
        issued_at: formatTimestamp(certificate.issuedAt), 
        expires_at: formatTimestamp(certificate.expiresAt), 
        reason: certificate.reason,
        previous_digest: certificate.previousDigest, 
        file_count: certificate.files.length,
        note: 'Structure only. Run mago-ski verify to check the signature against your trust root.',
      });
      return 0;
    }
    default:
      throw new UsageError(`Unknown command: ${command}`);
  }
}

if (isMainModule(import.meta.url)) {
  runCli().then((code) => {
    process.exitCode = code;
  }, 
  (error: unknown) => {
    process.stderr.write(`mago-ski: ${(error as Error)?.message ?? 'operation failed'}\n`);
    
    if (error instanceof UsageError) 
      process.stderr.write('Run "mago-ski --help" for usage.\n');
    process.exitCode = 2;
  });
}
