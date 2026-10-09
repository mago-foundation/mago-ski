import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { parseCertificate, type Certificate } from './certificate.ts';
import { verifyEnvelopeSignature } from './dsse.ts';
import { scopeMatches, skillNameFromFrontmatter, validateSkillName } from './names.ts';
import { verifyRevocations, type Revocations } from './revocations.ts';
import { CLOCK_SKEW_MS, formatTimestamp } from './time.ts';
import { collectSkillTree, type SkillTree, type TreeFile } from './tree-digest.ts';
import { TrustDocumentError, verifyTrustRoot, type TrustRoot } from './trust-root.ts';

export const VERDICTS = ['VERIFIED', 'UNAPPROVED_CHANGE', 'NO_CERTIFICATE', 'UNTRUSTED_SIGNER', 'REVOKED', 'EXPIRED', 'UNVERIFIABLE'] as const;
export type Verdict = (typeof VERDICTS)[number];

/** When no certificate verifies, the most informative failure is reported. */
const FAILURE_PRIORITY: Verdict[] = ['REVOKED', 'UNAPPROVED_CHANGE', 'EXPIRED', 'UNTRUSTED_SIGNER', 'UNVERIFIABLE', 'NO_CERTIFICATE'];

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

/** Verifies the trust root and revocation list once; every Skill check reuses the result. */
export function loadTrustContext(options: {
  trustRootBytes: Uint8Array;
  revocationsBytes: Uint8Array;
  rootKeyId: string;
  now: Date;
  minimum?: MinimumVersions | undefined;
}): TrustContextResult {
  try {
    const trustRoot = verifyTrustRoot(options.trustRootBytes, options.rootKeyId, options.now);
    const revocations = verifyRevocations(options.revocationsBytes, trustRoot, options.now);
    if (options.minimum && trustRoot.version < options.minimum.trustRootVersion) {
      return { ok: false, verdict: 'UNVERIFIABLE', reason: `trust root version ${trustRoot.version} is older than version ${options.minimum.trustRootVersion} already seen (rollback)` };
    }
    if (options.minimum && revocations.version < options.minimum.revocationsVersion) {
      return { ok: false, verdict: 'UNVERIFIABLE', reason: `revocation list version ${revocations.version} is older than version ${options.minimum.revocationsVersion} already seen (rollback)` };
    }
    return { ok: true, context: { trustRoot, revocations } };
  } catch (error) {
    if (error instanceof TrustDocumentError) return { ok: false, verdict: error.code, reason: error.message };
    return { ok: false, verdict: 'UNVERIFIABLE', reason: (error as Error).message };
  }
}

export interface CertificateEvaluation {
  verdict: Verdict;
  reason: string;
  certificate?: Certificate;
}

/** Checks one certificate for one Skill: trust chain, scope, signature, expiry, revocation, then bytes. */
export function evaluateCertificate(bytes: Uint8Array, skillName: string, digest: string, context: TrustContext, now: Date): CertificateEvaluation {
  let certificate: Certificate;
  try {
    certificate = parseCertificate(bytes);
  } catch (error) {
    return { verdict: 'UNVERIFIABLE', reason: `malformed certificate: ${(error as Error).message}` };
  }
  if (certificate.skillName !== skillName) {
    return { verdict: 'NO_CERTIFICATE', reason: `certificate is for Skill "${certificate.skillName}", not "${skillName}"`, certificate };
  }
  const { trustRoot, revocations } = context;
  const revokedKey = revocations.keys.find((entry) => entry.keyId === certificate.approverKeyId);
  if (revokedKey) return { verdict: 'REVOKED', reason: `approver key ${certificate.approverKeyId} is revoked: ${revokedKey.reason}`, certificate };
  const approver = trustRoot.approvers.find((entry) => entry.keyId === certificate.approverKeyId);
  if (!approver) return { verdict: 'UNTRUSTED_SIGNER', reason: `signer ${certificate.approverKeyId} is not an approver in trust root v${trustRoot.version}`, certificate };
  if (!approver.scopes.some((scope) => scopeMatches(scope, skillName))) {
    return { verdict: 'UNTRUSTED_SIGNER', reason: `approver "${approver.name}" is not authorized for Skill "${skillName}" (scopes: ${approver.scopes.join(', ')})`, certificate };
  }
  if (!verifyEnvelopeSignature(certificate.envelope, approver.publicKey)) {
    return { verdict: 'UNVERIFIABLE', reason: 'certificate signature is invalid', certificate };
  }
  if (certificate.issuedAt.getTime() > now.getTime() + CLOCK_SKEW_MS) {
    return { verdict: 'UNVERIFIABLE', reason: `certificate is issued in the future (${formatTimestamp(certificate.issuedAt)})`, certificate };
  }
  if (certificate.issuedAt >= approver.expiresAt) {
    return { verdict: 'UNTRUSTED_SIGNER', reason: `certificate was issued after approver "${approver.name}" expired`, certificate };
  }
  if (approver.expiresAt <= now) return { verdict: 'EXPIRED', reason: `approver "${approver.name}" expired at ${formatTimestamp(approver.expiresAt)}`, certificate };
  if (certificate.expiresAt <= now) return { verdict: 'EXPIRED', reason: `certificate expired at ${formatTimestamp(certificate.expiresAt)}`, certificate };
  const revokedDigest = revocations.digests.find((entry) => entry.digest === certificate.digest);
  if (revokedDigest) return { verdict: 'REVOKED', reason: `approved version ${certificate.digest} is revoked: ${revokedDigest.reason}`, certificate };
  if (certificate.digest !== digest) {
    return { verdict: 'UNAPPROVED_CHANGE', reason: `Skill bytes changed since approval (approved ${certificate.digest}, found ${digest}); a new certificate is required`, certificate };
  }
  return { verdict: 'VERIFIED', reason: `approved by "${approver.name}" until ${formatTimestamp(certificate.expiresAt)}`, certificate };
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

export async function resolveSkillName(skillDir: string, explicit?: string): Promise<string> {
  if (explicit) return validateSkillName(explicit);
  let text: string | undefined;
  try {
    text = await readFile(path.join(skillDir, 'SKILL.md'), 'utf8');
  } catch (error) {
    if ((error as NodeJS.ErrnoException)?.code !== 'ENOENT') throw error;
  }
  const fromFrontmatter = text === undefined ? undefined : skillNameFromFrontmatter(text);
  if (fromFrontmatter) return validateSkillName(fromFrontmatter, 'SKILL.md name');
  return validateSkillName(path.basename(path.resolve(skillDir)), 'Skill directory name');
}

export function decide(options: {
  skillDir: string;
  skillName: string;
  tree: SkillTree;
  certificates: CertificateSource[];
  context: TrustContext;
  now: Date;
}): VerificationResult {
  const base = {
    skillName: options.skillName, skillDir: options.tree.root, digest: options.tree.digest,
    excluded: options.tree.excluded, checkedAt: formatTimestamp(options.now),
  };
  if (options.certificates.length === 0) {
    return { ...base, verdict: 'NO_CERTIFICATE', reason: 'no certificate found for this Skill', files: null, certificateId: null, certificateSource: null, approverKeyId: null };
  }
  const evaluations = options.certificates.map((source) => ({
    source, evaluation: evaluateCertificate(source.bytes, options.skillName, options.tree.digest, options.context, options.now),
  }));
  const verified = evaluations.find((entry) => entry.evaluation.verdict === 'VERIFIED');
  const chosen = verified ?? evaluations.sort((a, b) =>
    FAILURE_PRIORITY.indexOf(a.evaluation.verdict) - FAILURE_PRIORITY.indexOf(b.evaluation.verdict))[0]!;
  const certificate = chosen.evaluation.certificate;
  return {
    ...base,
    verdict: chosen.evaluation.verdict,
    reason: chosen.evaluation.reason,
    files: chosen.evaluation.verdict === 'VERIFIED' ? certificate!.files : null,
    certificateId: certificate?.id ?? null,
    certificateSource: chosen.source.source,
    approverKeyId: certificate?.approverKeyId ?? null,
  };
}

/** Full check of one Skill directory against an already-verified trust context. */
export async function verifySkill(options: {
  skillDir: string;
  skillName?: string | undefined;
  certificates: CertificateSource[] | ((skillName: string, root: string) => Promise<CertificateSource[]>);
  context: TrustContext;
  now: Date;
}): Promise<VerificationResult> {
  const skillDir = path.resolve(options.skillDir);
  let skillName = options.skillName ?? path.basename(skillDir);
  try {
    skillName = await resolveSkillName(skillDir, options.skillName);
    const tree = await collectSkillTree(skillDir);
    const certificates = typeof options.certificates === 'function' ? await options.certificates(skillName, tree.root) : options.certificates;
    return decide({ skillDir, skillName, tree, certificates, context: options.context, now: options.now });
  } catch (error) {
    return unverifiable(skillDir, skillName, (error as Error).message, options.now);
  }
}

export function unverifiable(skillDir: string, skillName: string, reason: string, now: Date, verdict: Verdict = 'UNVERIFIABLE'): VerificationResult {
  return {
    verdict, reason, skillName, skillDir, digest: null, files: null, certificateId: null,
    certificateSource: null, approverKeyId: null, excluded: [], checkedAt: formatTimestamp(now),
  };
}
