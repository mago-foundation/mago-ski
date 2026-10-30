import path from 'node:path';
import { parseCertificate, type Certificate } from './certificate.ts';
import { verifyEnvelopeSignature } from './dsse.ts';
import { readRegularFile } from './fs-safe.ts';
import { scopeMatches, skillNameFromFrontmatter, validateDigest, validateSkillName } from './names.ts';
import { verifyRevocations, type Revocations } from './revocations.ts';
import { CLOCK_SKEW_MS, formatTimestamp, requireValidDate } from './time.ts';
import { collectSkillTree, MAX_FILE_BYTES, SKILL_FILENAME, type SkillTree, type TreeFile } from './tree-digest.ts';
import { TrustDocumentError, verifyTrustRoot, type TrustRoot } from './trust-root.ts';

export const VERDICTS = [
  'VERIFIED',
  'UNAPPROVED_CHANGE',
  'NO_CERTIFICATE',
  'UNTRUSTED_SIGNER',
  'REVOKED',
  'EXPIRED',
  'UNVERIFIABLE',
] as const;

export type Verdict = (typeof VERDICTS)[number];

/**
 * Precedence rank for candidate selection (lower rank wins):
 * VERIFIED (0) beats all failures, followed by the failure priority order.
 */
const VERDICT_RANK: Readonly<Record<Verdict, number>> = {
  VERIFIED: 0,
  REVOKED: 1,
  UNAPPROVED_CHANGE: 2,
  EXPIRED: 3,
  UNTRUSTED_SIGNER: 4,
  UNVERIFIABLE: 5,
  NO_CERTIFICATE: 6,
};

const utf8Decoder = new TextDecoder('utf-8', { fatal: true });

export interface TrustContext {
  trustRoot: TrustRoot;
  revocations: Revocations;
}

export interface MinimumVersions {
  trustRootVersion: number;
  revocationsVersion: number;
}

export type TrustContextResult =
  | { ok: true; context: TrustContext }
  | { ok: false; verdict: 'EXPIRED' | 'UNVERIFIABLE'; reason: string };

export interface CertificateEvaluation {
  verdict: Verdict;
  reason: string;
  certificate?: Certificate;
}

export interface CertificateSource {
  source: string;
  bytes: Uint8Array;
}

export interface VerificationResult {
  verdict: Verdict;
  reason: string;
  skillName: string;
  skillDir: string;
  digest: string | null;
  /** Per-file hashes of the approved version; present only when VERIFIED. */
  files: TreeFile[] | null;
  certificateId: string | null;
  certificateSource: string | null;
  approverKeyId: string | null;
  excluded: string[];
  checkedAt: string;
}

type Decision = Pick<
  VerificationResult,
  'verdict' | 'reason' | 'files' | 'certificateId' | 'certificateSource' | 'approverKeyId'
>;

interface Candidate {
  source: CertificateSource;
  evaluation: CertificateEvaluation;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function requireValidMinimumVersion(value: number, label: string): void {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1) {
    throw new Error(`${label} must be a positive integer`);
  }
}

/** Verifies the trust root and revocation list once; every Skill check reuses the result. */
export function loadTrustContext(options: {
  trustRootBytes: Uint8Array;
  revocationsBytes: Uint8Array;
  rootKeyId: string;
  now: Date;
  minimum?: MinimumVersions | undefined;
}): TrustContextResult {
  try {
    // Inside the try, so a bad clock or minimum version becomes an UNVERIFIABLE result like any other failure here.
    requireValidDate(options.now, 'Verification time');

    if (options.minimum !== undefined) {
      requireValidMinimumVersion(options.minimum.trustRootVersion, 'Minimum trust root version');
      requireValidMinimumVersion(options.minimum.revocationsVersion, 'Minimum revocation list version');
    }

    const trustRoot = verifyTrustRoot(options.trustRootBytes, options.rootKeyId, options.now);
    const revocations = verifyRevocations(options.revocationsBytes, trustRoot, options.now);

    if (options.minimum && trustRoot.version < options.minimum.trustRootVersion) {
      return {
        ok: false,
        verdict: 'UNVERIFIABLE',
        reason: `trust root version ${trustRoot.version} is older than version ${options.minimum.trustRootVersion} already seen (rollback)`,
      };
    }

    if (options.minimum && revocations.version < options.minimum.revocationsVersion) {
      return {
        ok: false,
        verdict: 'UNVERIFIABLE',
        reason: `revocation list version ${revocations.version} is older than version ${options.minimum.revocationsVersion} already seen (rollback)`,
      };
    }

    return { ok: true, context: { trustRoot, revocations } };
  } catch (error) {
    if (error instanceof TrustDocumentError) {
      return { ok: false, verdict: error.code, reason: error.message };
    }
    return { ok: false, verdict: 'UNVERIFIABLE', reason: errorMessage(error) };
  }
}

/** Checks one certificate for one Skill: trust chain, scope, signature, expiry, revocation, then bytes. */
export function evaluateCertificate(
  bytes: Uint8Array,
  skillName: string,
  digest: string,
  context: TrustContext,
  now: Date,
): CertificateEvaluation {
  // The issued-in-the-future and expiry checks compare against `now`; an invalid Date would pass them all.
  requireValidDate(now, 'Verification time');

  let certificate: Certificate;
  try {
    validateSkillName(skillName, 'Skill name');
    validateDigest(digest, 'Skill tree digest');
    certificate = parseCertificate(bytes);
  } catch (error) {
    return { verdict: 'UNVERIFIABLE', reason: `malformed certificate: ${errorMessage(error)}` };
  }

  if (certificate.skillName !== skillName) {
    return {
      verdict: 'NO_CERTIFICATE',
      reason: `certificate is for Skill "${certificate.skillName}", not "${skillName}"`,
      certificate,
    };
  }

  const { trustRoot, revocations } = context;

  const revokedKey = revocations.keys.find((entry) => entry.keyId === certificate.approverKeyId);
  if (revokedKey) {
    return {
      verdict: 'REVOKED',
      reason: `approver key ${certificate.approverKeyId} is revoked: ${revokedKey.reason}`,
      certificate,
    };
  }

  const approver = trustRoot.approvers.find((entry) => entry.keyId === certificate.approverKeyId);
  if (!approver) {
    return {
      verdict: 'UNTRUSTED_SIGNER',
      reason: `signer ${certificate.approverKeyId} is not an approver in trust root v${trustRoot.version}`,
      certificate,
    };
  }

  if (!approver.scopes.some((scope) => scopeMatches(scope, skillName))) {
    return {
      verdict: 'UNTRUSTED_SIGNER',
      reason: `approver "${approver.name}" is not authorized for Skill "${skillName}" (scopes: ${approver.scopes.join(', ')})`,
      certificate,
    };
  }

  if (!verifyEnvelopeSignature(certificate.envelope, approver.publicKey)) {
    return {
      verdict: 'UNVERIFIABLE',
      reason: 'certificate signature is invalid',
      certificate,
    };
  }

  if (certificate.issuedAt.getTime() > now.getTime() + CLOCK_SKEW_MS) {
    return {
      verdict: 'UNVERIFIABLE',
      reason: `certificate is issued in the future (${formatTimestamp(certificate.issuedAt)})`,
      certificate,
    };
  }

  if (certificate.issuedAt >= approver.expiresAt) {
    return {
      verdict: 'UNTRUSTED_SIGNER',
      reason: `certificate was issued after approver "${approver.name}" expired`,
      certificate,
    };
  }

  if (approver.expiresAt <= now) {
    return {
      verdict: 'EXPIRED',
      reason: `approver "${approver.name}" expired at ${formatTimestamp(approver.expiresAt)}`,
      certificate,
    };
  }

  if (certificate.expiresAt <= now) {
    return {
      verdict: 'EXPIRED',
      reason: `certificate expired at ${formatTimestamp(certificate.expiresAt)}`,
      certificate,
    };
  }

  const revokedDigest = revocations.digests.find((entry) => entry.digest === certificate.digest);
  if (revokedDigest) {
    return {
      verdict: 'REVOKED',
      reason: `approved version ${certificate.digest} is revoked: ${revokedDigest.reason}`,
      certificate,
    };
  }

  if (certificate.digest !== digest) {
    return {
      verdict: 'UNAPPROVED_CHANGE',
      reason: `Skill bytes changed since approval (approved ${certificate.digest}, found ${digest}); a new certificate is required`,
      certificate,
    };
  }

  return {
    verdict: 'VERIFIED',
    reason: `approved by "${approver.name}" until ${formatTimestamp(certificate.expiresAt)}`,
    certificate,
  };
}

/**
 * The Skill name from SKILL.md's bytes: an explicit name, else frontmatter "name", else the directory name.
 * Pure, so a caller that hashes and signs those bytes can derive the name from the very same buffer.
 */
export function skillNameFromSkillFile(skillDir: string, skillFile: Uint8Array | undefined, explicit?: string): string {
  if (explicit) {
    return validateSkillName(explicit);
  }

  let text: string | undefined;
  if (skillFile !== undefined) {
    try {
      text = utf8Decoder.decode(skillFile);
    } catch {
      throw new Error(`${SKILL_FILENAME} is not valid UTF-8`);
    }
  }

  const fromFrontmatter = text === undefined ? undefined : skillNameFromFrontmatter(text);
  if (fromFrontmatter) {
    return validateSkillName(fromFrontmatter, `${SKILL_FILENAME} name`);
  }

  return validateSkillName(path.basename(path.resolve(skillDir)), 'Skill directory name');
}

/**
 * Resolves the Skill name. SKILL.md comes from an untrusted checkout, so it is read only if it is a regular,
 * non-symlink file no larger than the tree collector's per-file limit; anything else throws (UNVERIFIABLE).
 */
export async function resolveSkillName(skillDir: string, explicit?: string): Promise<string> {
  if (explicit) {
    return validateSkillName(explicit);
  }

  let rawBytes: Buffer | undefined;
  try {
    rawBytes = await readRegularFile(path.join(skillDir, SKILL_FILENAME), SKILL_FILENAME, MAX_FILE_BYTES);
  } catch (error) {
    if ((error as NodeJS.ErrnoException)?.code !== 'ENOENT') {
      throw error;
    }
  }
  return skillNameFromSkillFile(skillDir, rawBytes);
}

/** Keeps the best candidate seen so far: VERIFIED beats any failure, then VERDICT_RANK; the first of equals wins. */
function selectBetterCandidate(current: Candidate | undefined, next: Candidate): Candidate {
  if (!current) {
    return next;
  }

  const currentRank = VERDICT_RANK[current.evaluation.verdict];
  const nextRank = VERDICT_RANK[next.evaluation.verdict];
  return nextRank < currentRank ? next : current;
}

function buildDecision(chosen: Candidate | undefined): Decision {
  if (!chosen) {
    return {
      verdict: 'NO_CERTIFICATE',
      reason: 'no certificate found for this Skill',
      files: null,
      certificateId: null,
      certificateSource: null,
      approverKeyId: null,
    };
  }

  const { evaluation, source } = chosen;
  const certificate = evaluation.certificate;
  const verifiedFiles =
    evaluation.verdict === 'VERIFIED' && certificate
      ? certificate.files.map((file) => ({ ...file }))
      : null;

  return {
    verdict: evaluation.verdict,
    reason: evaluation.reason,
    files: verifiedFiles,
    certificateId: certificate?.id ?? null,
    certificateSource: source.source,
    approverKeyId: certificate?.approverKeyId ?? null,
  };
}

const MAX_NAMED_PATHS = 3;

/**
 * Paths come from the Skill (untrusted): quoted, so a name cannot imitate the reason's own wording, and with DEL, C1 controls
 * and bidi or invisible characters escaped, which tree paths may contain and terminals and annotations would apply.
 */
function quotePath(file: string): string {
  return JSON.stringify(file).replace(/[\u007f-\u009f\u200b-\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069\ufeff]/gu,
    (char) => `\\u${char.charCodeAt(0).toString(16).padStart(4, '0')}`);
}

function namePaths(paths: string[]): string {
  const shown = paths.slice(0, MAX_NAMED_PATHS).join(', ');
  return paths.length > MAX_NAMED_PATHS ? `${shown} and ${paths.length - MAX_NAMED_PATHS} more` : shown;
}

/** Says what differs between the approved file list and the tree on disk, e.g. an executable bit with no byte changed. */
export function describeTreeChange(approved: readonly TreeFile[], found: readonly TreeFile[]): string {
  const before = new Map(approved.map((file) => [file.path, file]));
  const content: string[] = [];
  const mode: string[] = [];
  const added: string[] = [];
  for (const file of found) {
    const old = before.get(file.path);
    before.delete(file.path);
    if (!old) {
      added.push(file.exec ? `${quotePath(file.path)} (executable)` : quotePath(file.path));
      continue;
    }
    if (old.sha256 !== file.sha256 || old.size !== file.size) content.push(quotePath(file.path));
    // Reported even when the content changed too: a file becoming executable matters on its own.
    if (old.exec !== file.exec) mode.push(`${quotePath(file.path)} (${file.exec ? 'now executable' : 'no longer executable'})`);
  }
  const removed = [...before.keys()].map(quotePath);
  const parts = [
    content.length ? `content changed in ${namePaths(content)}` : '',
    mode.length ? `executable bit changed on ${namePaths(mode)}` : '',
    added.length ? `added ${namePaths(added)}` : '',
    removed.length ? `removed ${namePaths(removed)}` : '',
  ].filter(Boolean);
  return parts.length ? parts.join('; ') : 'files changed';
}

/** Replaces the generic UNAPPROVED_CHANGE reason with one naming the changed files, when the certificate lists them. */
function explainChange(decision: Decision, best: Candidate | undefined, tree: SkillTree): Decision {
  const certificate = best?.evaluation.certificate;
  if (decision.verdict !== 'UNAPPROVED_CHANGE' || !certificate) return decision;
  return {
    ...decision,
    reason: `Skill changed since approval: ${describeTreeChange(certificate.files, tree.files)} (approved ${certificate.digest}, found ${tree.digest}); a new certificate is required`,
  };
}

function buildBaseResult(options: { tree: SkillTree; skillName: string; now: Date }) {
  return {
    skillName: options.skillName,
    skillDir: options.tree.root,
    digest: options.tree.digest,
    excluded: [...options.tree.excluded],
    checkedAt: formatTimestamp(options.now),
  };
}

export function decide(options: {
  skillDir: string;
  skillName: string;
  tree: SkillTree;
  certificates: readonly CertificateSource[];
  context: TrustContext;
  now: Date;
}): VerificationResult {
  requireValidDate(options.now, 'Verification time');

  let best: Candidate | undefined;
  for (const source of options.certificates) {
    const evaluation = evaluateCertificate(
      source.bytes,
      options.skillName,
      options.tree.digest,
      options.context,
      options.now,
    );
    best = selectBetterCandidate(best, { source, evaluation });
    if (evaluation.verdict === 'VERIFIED') {
      break;
    }
  }

  return { ...buildBaseResult(options), ...explainChange(buildDecision(best), best, options.tree) };
}

/**
 * Same verdict as `decide`, but candidates are evaluated one at a time as they are produced, so only the best
 * one is retained and the first VERIFIED candidate ends the scan (later candidates are never read).
 */
export async function decideStreaming(options: {
  skillDir: string;
  skillName: string;
  tree: SkillTree;
  certificates: AsyncIterable<CertificateSource> | Iterable<CertificateSource>;
  context: TrustContext;
  now: Date;
}): Promise<VerificationResult> {
  requireValidDate(options.now, 'Verification time');

  let best: Candidate | undefined;
  for await (const source of options.certificates) {
    const evaluation = evaluateCertificate(
      source.bytes,
      options.skillName,
      options.tree.digest,
      options.context,
      options.now,
    );
    best = selectBetterCandidate(best, { source, evaluation });
    if (evaluation.verdict === 'VERIFIED') {
      break;
    }
  }

  return { ...buildBaseResult(options), ...explainChange(buildDecision(best), best, options.tree) };
}

/** Full check of one Skill directory against an already-verified trust context. */
export async function verifySkill(options: {
  skillDir: string;
  skillName?: string | undefined;
  certificates:
    | readonly CertificateSource[]
    | ((skillName: string, root: string) => Promise<readonly CertificateSource[]> | AsyncIterable<CertificateSource>);
  context: TrustContext;
  now: Date;
}): Promise<VerificationResult> {
  // Before the try: its catch builds an UNVERIFIABLE result, which needs a valid time for `checkedAt`.
  requireValidDate(options.now, 'Verification time');

  const skillDir = path.resolve(options.skillDir);
  let skillName = options.skillName ?? path.basename(skillDir);

  try {
    skillName = await resolveSkillName(skillDir, options.skillName);
    const tree = await collectSkillTree(skillDir);
    const provided =
      typeof options.certificates === 'function'
        ? options.certificates(skillName, tree.root)
        : options.certificates;
    const certificates = Symbol.asyncIterator in provided ? provided : await provided;

    return await decideStreaming({
      skillDir,
      skillName,
      tree,
      certificates,
      context: options.context,
      now: options.now,
    });
  } catch (error) {
    return unverifiable(skillDir, skillName, errorMessage(error), options.now);
  }
}

export function unverifiable(
  skillDir: string,
  skillName: string,
  reason: string,
  now: Date,
  verdict: Exclude<Verdict, 'VERIFIED'> = 'UNVERIFIABLE',
): VerificationResult {
  requireValidDate(now, 'Verification time');

  const safeVerdict: Exclude<Verdict, 'VERIFIED'> =
    verdict === ('VERIFIED' as string) || !(verdict in VERDICT_RANK) ? 'UNVERIFIABLE' : verdict;

  return {
    verdict: safeVerdict,
    reason,
    skillName,
    skillDir,
    digest: null,
    files: null,
    certificateId: null,
    certificateSource: null,
    approverKeyId: null,
    excluded: [],
    checkedAt: formatTimestamp(now),
  };
}
