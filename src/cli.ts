#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { addApprover, approveSkill, initRoot, removeApprover, renewTrustRoot, updateRevocations } from './admin.ts';
import { parseCertificate } from './certificate.ts';
import { diffSkillTrees } from './diff.ts';
import { readRegularFile } from './fs-safe.ts';
import { generateKeyPair, validateKeyId } from './keys.ts';
import {
  appendDecision, decisionRecord, defaultPolicyPath, effectiveMode, findSkillDirs, forbiddenApproverKeys, loadPolicy, loadPolicyTrust, tooDeepResult,
  trustFailureEvent, trustFailureRecord, verifyWithPolicy, type Policy,
} from './policy.ts';
import {
  adoptTrustDocuments, appendRootEvent, buildRecoverySet, currentRootState, describeRootEvent, initRootEventLog, prepareRootEvent,
  recoverySetJson, showRootEvent, signPolicyTimestamp, signRootEvent,
} from './recovery-admin.ts';
import { isMainModule } from './main-module.ts';
import { formatTimestamp } from './time.ts';
import { collectSkillTree, TREE_PROFILE } from './tree-digest.ts';
import { verifyTrustRoot } from './trust-root.ts';
import { resolveSkillName, unverifiable, type VerificationResult } from './verify.ts';
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
  root renew             Extend the trust root's lifetime
  root show              Verify and print a trust root
  root adopt             Re-sign trust documents with a new root key
  revoke key             Revoke an approver key
  revoke digest          Revoke one approved Skill version
  revoke refresh         Re-sign the revocation list

ROOT RECOVERY  (recovery key holders, timestamp job)
  recovery init          Build the policy's recovery set
  root-events init|prepare-revoke|prepare-rotate|show|sign|append
                         Propose, check, sign and append root events
  timestamp sign         Sign the freshness timestamp

APPROVING SKILLS  (reviewer)
  approve SKILL_DIR      Issue a certificate for a Skill

CHECKING SKILLS
  verify SKILL_DIR       Check one Skill, print its verdict
  verify-all             Check every Skill in the policy
  digest SKILL_DIR       Print a Skill's tree digest
  diff                   Compare two versions of a Skill
  inspect CERTIFICATE    Print a certificate's contents
  policy check           Check a policy the way a host does

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
  root: `Usage: mago-ski root <init | add-approver | remove-approver | renew | show> [options]

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
  --policy FILE                refuse keys that hold or held another role in this organisation (recommended)
${DURATION_NOTE}`,

  /* ************************************************* */
  /*		Per-command "root" -> "root remove-approver"   */
    /* *********************************************** */
  'root remove-approver': `Usage: mago-ski root remove-approver --root-key FILE --trust-root FILE --key-id ID [--out FILE] [--trust-root-expires DUR]

Removes an approver and re-signs the trust root. Certificates from that approver stop verifying once hosts read
the new trust root. If the key may be compromised, also revoke it with "mago-ski revoke key".`,

  /*		Per-command "root" -> "root renew"   */
  'root renew': `Usage: mago-ski root renew --root-key FILE --trust-root FILE --expires DUR [--out FILE]

Re-signs the trust root with a new expiry and the same approvers.`,

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

/* ******************************************************************************************  */
/** Per-command: root recovery                                                                 */
/* ******************************************************************************************  */
  'root adopt': `Usage: mago-ski root adopt --root-key FILE --from-root-fingerprint ID --trust-root FILE --revocations FILE [options]

After a rotate root event: re-signs the trust root and revocation list with the new root key. Every approver and
revocation entry is kept, and each document gets the next version. Both files are updated in place.

  --root-key FILE                the new root private key (the rotate event's new root)
  --from-root-fingerprint ID     the root key the current documents are signed by
  --trust-root-expires DUR       new trust root lifetime (default 365d)
  --revocations-expires DUR      new revocation list lifetime (default 30d)

The current documents may have been signed by a leaked key: review the printed approvers before publishing.
${DURATION_NOTE}`,

  recovery: `Usage: mago-ski recovery init --public-key FILE [--public-key ...] --rotate-threshold N --revoke-threshold N

Prints the "recovery" block for a mago.policy/v2 policy: the recovery keys' fingerprints and both thresholds.
Recovery keys only sign root events. Keep each one offline, with a different person, never next to the root key.
1 <= revoke-threshold <= rotate-threshold <= number of keys; 3 keys, rotate 2, revoke 1 is a good default.`,

  'recovery init': `Usage: mago-ski recovery init --public-key FILE [--public-key ...] --rotate-threshold N --revoke-threshold N

Prints the "recovery" block for a mago.policy/v2 policy: the recovery keys' fingerprints and both thresholds.
Recovery keys only sign root events. Keep each one offline, with a different person, never next to the root key.
1 <= revoke-threshold <= rotate-threshold <= number of keys; 3 keys, rotate 2, revoke 1 is a good default.`,

  'root-events': `Usage: mago-ski root-events <init | prepare-revoke | prepare-rotate | show | sign | append> [options]

Manages the root event log: signed, numbered events that revoke or replace the root key.
Run "mago-ski root-events <subcommand> --help" for details.`,

  'root-events init': `Usage: mago-ski root-events init --out FILE

Writes an empty root event log. Publish it next to the trust root: a policy with "recovery" needs the file to exist.`,

  'root-events prepare-revoke': `Usage: mago-ski root-events prepare-revoke --policy FILE --signer-public FILE [--signer-public ...] --reason TEXT --out FILE

Writes an unsigned proposal to revoke the active root key. Hosts that read the event block every Skill, in shadow
mode too, until a rotate event. List every recovery key that will sign (at least revoke_threshold of them).

  --policy FILE          the organization's policy (names the root event log)
  --signer-public FILE   public key of a recovery key that will sign; repeat for several
  --reason TEXT          shown in every host's block message (at most 1024 characters)
  --out FILE             the proposal file (must not exist yet)`,

  'root-events prepare-rotate': `Usage: mago-ski root-events prepare-rotate --policy FILE --new-root-public FILE --signer-public FILE [...] --reason TEXT --out FILE [options]

Writes an unsigned proposal to replace the root key, and optionally the recovery set or the timestamp key.
It must be signed by rotate_threshold keys of the current recovery set, the new set's rotate_threshold keys,
the new root key, and the new timestamp key if one is given.

  --policy FILE                  the organization's policy (names the root event log)
  --new-root-public FILE         the new root public key (may be the current root to change only the other keys)
  --signer-public FILE           public key of a recovery key that will sign; repeat for several
  --new-recovery-public FILE     a key of the new recovery set; repeat for each (default: keep the current set)
  --rotate-threshold N           the new set's rotate threshold (required with --new-recovery-public)
  --revoke-threshold N           the new set's revoke threshold (required with --new-recovery-public)
  --new-timestamp-public FILE    a new timestamp key
  --reason TEXT                  why (at most 1024 characters)
  --out FILE                     the proposal file (must not exist yet)`,

  'root-events show': `Usage: mago-ski root-events show PROPOSAL [--policy FILE]

Prints what a proposal does (action, number, root key, new keys, reason), who has signed and who still must.
With --policy, also checks that it is the next event of the published log. Run it before you sign, and compare
the output with what was agreed through a channel other than the one that delivered the proposal.`,

  'root-events sign': `Usage: mago-ski root-events sign PROPOSAL --key FILE [--policy FILE]

Adds your signature to a proposal, in place, and prints the event you signed and who still has to sign. Refuses a
key the event does not list. With --policy, refuses a proposal that is not the next event of the published log.
Check the event with "mago-ski root-events show" first: your signature covers everything in it.`,

  'root-events append': `Usage: mago-ski root-events append PROPOSAL --policy FILE

Adds a fully signed proposal to the policy's root event log, after checking the whole new log exactly as a host
would. Prepare proposals against the published log, never a private copy: two events with the same number are a
fork, and hosts fail closed on a fork.`,

  timestamp: `Usage: mago-ski timestamp sign --policy FILE --key FILE [--expires DUR] [--version N]

Signs the policy's freshness timestamp: the digests of the root event log, trust root and revocation list as they
are now, with the next version. Run it from an automated job every 6 hours with a 24h lifetime, and publish the
timestamp together with the documents it names.

  --key FILE       the active timestamp private key (keep it away from the root key)
  --expires DUR    lifetime (default 24h; at most the policy's freshness max_lifetime)
  --version N      the version to use, when the current timestamp file cannot be read`,

  'timestamp sign': `Usage: mago-ski timestamp sign --policy FILE --key FILE [--expires DUR] [--version N]

Signs the policy's freshness timestamp: the digests of the root event log, trust root and revocation list as they
are now, with the next version. Run it from an automated job every 6 hours with a 24h lifetime, and publish the
timestamp together with the documents it names.

  --key FILE       the active timestamp private key (keep it away from the root key)
  --expires DUR    lifetime (default 24h; at most the policy's freshness max_lifetime)
  --version N      the version to use, when the current timestamp file cannot be read`,

  policy: `Usage: mago-ski policy check [--policy FILE] [--json]

Loads the policy, walks the root event log, checks the timestamp if "freshness" is set, verifies the trust root and
revocation list against the active root, and prints the active keys and thresholds. Never writes the host state.
Exits 0 when everything checks, 1 otherwise: use it to gate a policy rollout.`,

  'policy check': `Usage: mago-ski policy check [--policy FILE] [--json]

Loads the policy, walks the root event log, checks the timestamp if "freshness" is set, verifies the trust root and
revocation list against the active root, and prints the active keys and thresholds. Never writes the host state.
Exits 0 when everything checks, 1 otherwise: use it to gate a policy rollout.`,
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
    allow(parsed, ['--root-key', '--trust-root', '--out', '--public-key', '--name', '--scope', '--expires', '--trust-root-expires', '--policy'], 0, ['--scope']);
    const policyFile = optional(parsed, '--policy');
    const forbidden = policyFile === undefined ? undefined : await forbiddenApproverKeys(await loadPolicy(policyFile), now);
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
      ...(forbidden ? { forbidden } : {}),
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
  
  if (sub === 'renew') {
    allow(parsed, ['--root-key', '--trust-root', '--out', '--expires'], 0);
    const result = await renewTrustRoot({
      rootKeyPath: one(parsed, '--root-key'),
      trustRootPath: one(parsed, '--trust-root'),
      out: optional(parsed, '--out'),
      now,
      expires: one(parsed, '--expires'),
    });
    print({
      status: 'TRUST_ROOT_RENEWED',
      trust_root_version: result.version,
      trust_root: result.path,
      expires_at: formatTimestamp(result.expiresAt),
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

  if (sub === 'adopt') {
    allow(parsed, ['--root-key', '--from-root-fingerprint', '--trust-root', '--revocations', '--trust-root-expires', '--revocations-expires'], 0);
    const result = await adoptTrustDocuments({
      rootKeyPath:        one(parsed, '--root-key'),
      fromRootKeyId:      validateKeyId(one(parsed, '--from-root-fingerprint'), '--from-root-fingerprint'),
      trustRootPath:      one(parsed, '--trust-root'),
      revocationsPath:    one(parsed, '--revocations'),
      now,
      trustRootExpires:   optional(parsed, '--trust-root-expires'),
      revocationsExpires: optional(parsed, '--revocations-expires'),
    });
    print({
      status: 'TRUST_DOCUMENTS_ADOPTED',
      root_key_id: result.trustRoot.root.keyId,
      trust_root_version: result.trustRootVersion,
      revocations_version: result.revocationsVersion,
      approvers: result.trustRoot.approvers.map((entry) => ({ name: entry.name, key_id: entry.keyId, scopes: entry.scopes, expires_at: formatTimestamp(entry.expiresAt) })),
      next: 'Review the approvers above (the old key may have been misused), then publish both files.',
    });
    return 0;
  }

  throw new UsageError('Unknown root command; use init, add-approver, remove-approver, renew, show or adopt');
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
    const missing = error as NodeJS.ErrnoException;
    if (!explicit && missing?.code === 'ENOENT') {
      throw new UsageError(`No policy at ${policyPath}. Pass --policy FILE, or set MAGO_SKI_POLICY to an absolute path`);
    }
    // Only when the policy file itself is missing; a missing trust root or other input keeps its own error.
    if (missing?.code === 'ENOENT' && missing.path === path.resolve(policyPath)) {
      throw new UsageError(`Policy file not found: ${path.resolve(policyPath)}`);
    }
    throw error;
  }
}

function integerFlag(parsed: Parsed, flag: string): number | undefined {
  const value = optional(parsed, flag);
  if (value === undefined) return undefined;
  if (!/^[0-9]{1,6}$/u.test(value)) throw new UsageError(`${flag} must be a positive integer`);
  return Number(value);
}

async function requiredPolicy(parsed: Parsed): Promise<Policy> {
  one(parsed, '--policy');
  return await loadCliPolicy(parsed);
}

async function runRecovery(sub: string | undefined, parsed: Parsed): Promise<number> {
  if (sub !== 'init') throw new UsageError('Unknown recovery command; use init');
  allow(parsed, ['--public-key', '--rotate-threshold', '--revoke-threshold'], 0, ['--public-key']);
  const rotate = integerFlag(parsed, '--rotate-threshold');
  const revoke = integerFlag(parsed, '--revoke-threshold');
  if (rotate === undefined || revoke === undefined) throw new UsageError('--rotate-threshold and --revoke-threshold are required');
  const keys = parsed.flags.get('--public-key') ?? [];
  if (keys.length === 0) throw new UsageError('--public-key is required');
  const set = await buildRecoverySet({ publicKeyPaths: keys, rotateThreshold: rotate, revokeThreshold: revoke });
  print({ recovery: recoverySetJson(set), next: 'Put "recovery" in each host policy (policy_version "mago.policy/v2"), with "root_events" naming an empty log.' });
  return 0;
}

async function runRootEvents(sub: string | undefined, parsed: Parsed, now: Date): Promise<number> {
  if (sub === 'init') {
    allow(parsed, ['--out'], 0);
    print({ status: 'ROOT_EVENTS_INITIALIZED', root_events: await initRootEventLog(one(parsed, '--out')) });
    return 0;
  }
  if (sub === 'prepare-revoke' || sub === 'prepare-rotate') {
    const common = ['--policy', '--signer-public', '--reason', '--out'];
    if (sub === 'prepare-revoke') allow(parsed, common, 0, ['--signer-public']);
    else allow(parsed, [...common, '--new-root-public', '--new-recovery-public', '--rotate-threshold', '--revoke-threshold', '--new-timestamp-public'], 0, ['--signer-public', '--new-recovery-public']);
    const policy = await requiredPolicy(parsed);
    const prepared = await prepareRootEvent({
      policy,
      action:                 sub === 'prepare-revoke' ? 'revoke' : 'rotate',
      reason:                 one(parsed, '--reason'),
      signerPublicPaths:      parsed.flags.get('--signer-public') ?? [],
      out:                    one(parsed, '--out'),
      now,
      newRootPublicPath:      optional(parsed, '--new-root-public'),
      newRecoveryPublicPaths: parsed.flags.get('--new-recovery-public'),
      rotateThreshold:        integerFlag(parsed, '--rotate-threshold'),
      revokeThreshold:        integerFlag(parsed, '--revoke-threshold'),
      newTimestampPublicPath: optional(parsed, '--new-timestamp-public'),
    });
    print({
      status: 'ROOT_EVENT_PREPARED', proposal: prepared.path, sequence: prepared.event.sequence, action: prepared.event.action,
      root_key_id: prepared.event.rootKeyId, must_be_signed_by: prepared.required,
      next: 'Each listed key holder runs "mago-ski root-events sign PROPOSAL --key FILE"; then "mago-ski root-events append".',
    });
    return 0;
  }
  if (sub === 'show') {
    allow(parsed, ['--policy'], 1);
    const policy = optional(parsed, '--policy') ? await loadCliPolicy(parsed) : undefined;
    const result = await showRootEvent({ proposalPath: parsed.positional[0]!, policy, now });
    print({ event: describeRootEvent(result.event), signatures: result.signed, still_missing: result.missing, ...(policy ? { extends_log: true } : {}) });
    return 0;
  }
  if (sub === 'sign') {
    allow(parsed, ['--key', '--policy'], 1);
    const policy = optional(parsed, '--policy') ? await loadCliPolicy(parsed) : undefined;
    const result = await signRootEvent({ proposalPath: parsed.positional[0]!, keyPath: one(parsed, '--key'), policy, now });
    print({ status: 'ROOT_EVENT_SIGNED', signed_by: result.keyId, event: describeRootEvent(result.event), signatures: result.signed, still_missing: result.missing });
    return 0;
  }
  if (sub === 'append') {
    allow(parsed, ['--policy'], 1);
    const policy = await requiredPolicy(parsed);
    const result = await appendRootEvent({ policy, proposalPath: parsed.positional[0]!, now });
    print({
      status: 'ROOT_EVENT_APPENDED', root_events: result.path, sequence: result.event.sequence, action: result.event.action,
      active_root_key_id: result.walk.activeRootKeyId, root_revoked: result.walk.revoked !== null,
      next: result.walk.revoked
        ? 'Publish the log now. Hosts that read it block every Skill until a rotate event.'
        : 'Publish the log. Then sign a trust root and revocation list with the active root ("mago-ski root adopt") and re-sign the timestamp.',
    });
    return 0;
  }
  throw new UsageError('Unknown root-events command; use init, prepare-revoke, prepare-rotate, show, sign or append');
}

async function runTimestamp(sub: string | undefined, parsed: Parsed, now: Date): Promise<number> {
  if (sub !== 'sign') throw new UsageError('Unknown timestamp command; use sign');
  allow(parsed, ['--policy', '--key', '--expires', '--version'], 0);
  const policy = await requiredPolicy(parsed);
  const result = await signPolicyTimestamp({
    policy, keyPath: one(parsed, '--key'), now, expires: optional(parsed, '--expires'), version: integerFlag(parsed, '--version'),
  });
  print({
    status: 'TIMESTAMP_SIGNED', timestamp: result.path, version: result.timestamp.version,
    expires_at: formatTimestamp(result.timestamp.expiresAt), root_events_count: result.timestamp.rootEvents.count,
    trust_root_version: result.timestamp.trustRoot.version, revocations_version: result.timestamp.revocations.version,
  });
  return 0;
}

async function runPolicyCheck(sub: string | undefined, parsed: Parsed, now: Date): Promise<number> {
  if (sub !== 'check') throw new UsageError('Unknown policy command; use check');
  allow(parsed, ['--policy'], 0);
  const policy = await loadCliPolicy(parsed);
  const trust  = await loadPolicyTrust(policy, now, { recordVersions: false });
  const root   = policy.recovery ? await currentRootState(policy, now).catch(() => null) : null;
  const report: Record<string, unknown> = {
    status:           trust.ok ? 'OK' : trust.rootRevoked ? 'ROOT_REVOKED' : 'TRUST_UNAVAILABLE',
    policy:           policy.path,
    mode:             policy.mode,
    effective_mode:   effectiveMode(policy.mode, trust),
    root_fingerprint: policy.rootKeyId,
    recovery:         policy.recovery !== null,
  };
  if (root) {
    report.active_root_key_id = root.activeRootKeyId;
    report.root_events        = root.count;
    report.recovery_set       = recoverySetJson(root.recovery);
    report.timestamp_key_id   = root.timestampKeyId;
    if (root.revoked) report.revoked_by_event = root.revoked.sequence;
  }
  if (trust.ok) {
    report.trust_root_version  = trust.context.trustRoot.version;
    report.revocations_version = trust.context.revocations.version;
    report.trust_root_expires_at = formatTimestamp(trust.context.trustRoot.expiresAt);
    report.revocations_expires_at = formatTimestamp(trust.context.revocations.expiresAt);
    report.approvers = trust.context.trustRoot.approvers.length;
    if (trust.context.root?.timestamp) {
      report.timestamp_version    = trust.context.root.timestamp.version;
      report.timestamp_expires_at = formatTimestamp(trust.context.root.timestamp.expiresAt);
    }
  } else {
    report.verdict = trust.verdict;
    report.reason  = trust.reason;
  }
  print(report);
  return trust.ok ? 0 : 1;
}

async function runVerify(
  parsed: Parsed, 
  now: Date
): Promise<number> {
  
  allow(parsed, ['--policy', '--name', '--certificate'], 1);
  
  const policy = await loadCliPolicy(parsed);
  const skillDir = parsed.positional[0]!;
  const trust = await loadPolicyTrust(policy, now);
  if (!trust.ok) {
    // A trust failure affects every Skill: one record for the host, not one per Skill.
    const name = optional(parsed, '--name') ?? await resolveSkillName(skillDir).catch(() => path.basename(path.resolve(skillDir)));
    await appendDecision(policy.decisionLogPath, trustFailureRecord(trust, policy.mode, now));
    printResult(unverifiable(path.resolve(skillDir), name, trust.reason, now, trust.verdict), parsed.booleans.has('--json'));
    return 1;
  }
  const result = await verifyWithPolicy(policy, skillDir, {
    now,
    context: trust.context,
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
  if (!trust.ok) {
    // Reported once for the host instead of once per Skill, so it is not buried among identical lines.
    const event = trustFailureEvent(trust);
    await appendDecision(policy.decisionLogPath, trustFailureRecord(trust, policy.mode, now));
    if (parsed.booleans.has('--json'))
      process.stdout.write(`${JSON.stringify({ event, verdict: trust.verdict, reason: trust.reason, skills: skillDirs.length + tooDeep.length })}\n`);
    else
      process.stdout.write(`FAIL ${event.toUpperCase()}  ${trust.reason}\n0/${skillDirs.length + tooDeep.length} Skills verified (mode: ${effectiveMode(policy.mode, trust)})\n`);
    return 1;
  }
  
  let failures = 0;
  const results: VerificationResult[] = [];
  for (const skillDir of skillDirs) {
    results.push(await verifyWithPolicy(policy, skillDir, { now, context: trust.context }));
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

  const hasSub = ['root', 'revoke', 'recovery', 'root-events', 'timestamp', 'policy'].includes(command!);
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
    case 'recovery':
      return await runRecovery(maybeSub, parsed);
    case 'root-events':
      return await runRootEvents(maybeSub, parsed, now);
    case 'timestamp':
      return await runTimestamp(maybeSub, parsed, now);
    case 'policy':
      return await runPolicyCheck(maybeSub, parsed, now);
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
