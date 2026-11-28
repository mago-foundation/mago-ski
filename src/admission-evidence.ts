// Collects the facts an admission decision is made from (admission.ts). Everything is recomputed or verified here:
// the profile and declaration from the bytes, reviews against the organisation's trust root, published-by bundles
// with the pinned Cosign against a local trusted root. Nothing is fetched. The facts can be logged and replayed.
import { parseCertificate } from './certificate.ts';
import { readRegularFile } from './fs-safe.ts';
import { verifyWithPolicy, type Policy } from './policy.ts';
import { describeSkill, publisherOf, verifyPublishedBy } from './published-by.ts';
import type { Review, SkillFacts } from './admission.ts';
import type { TrustContext } from './verify.ts';
import { resolveSkillName } from './verify.ts';
import path from 'node:path';

export interface SigstoreInputs { trustedRootPath: string; cosignPath: string }

export interface SkillEvidence {
  /** Organisation policy (mago.policy) whose trust root vouches for reviews; without it no review counts. */
  policy?: Policy;
  trust?: TrustContext;
  /** A published-by bundle for these bytes. */
  publishedBy?: string;
}

async function review(policy: Policy, trust: TrustContext | undefined, skillDir: string, now: Date): Promise<(Review & { digest: string }) | null> {
  const result = await verifyWithPolicy(policy, skillDir, { now, ...(trust ? { context: trust } : {}) });
  if (result.verdict !== 'VERIFIED' || !result.certificateSource || !result.certificateId || !result.approverKeyId) return null;
  // The dates come from the certificate that was verified: its id is the hash of its bytes, so a swapped file is refused.
  const certificate = parseCertificate(await readRegularFile(result.certificateSource, 'Certificate', 8 * 1024 * 1024));
  if (certificate.id !== result.certificateId) throw new Error('the certificate changed while it was being read');
  return { approver_key_id: result.approverKeyId, certificate_id: result.certificateId, issued_at: certificate.issuedAt.toISOString(), expires_at: certificate.expiresAt.toISOString(), digest: certificate.digest };
}

export async function collectSkillFacts(skillDir: string, evidence: SkillEvidence, sigstore: SigstoreInputs | undefined, now: Date): Promise<SkillFacts> {
  const record = await describeSkill(skillDir, path.dirname(path.resolve(skillDir)));
  let published_by = null;
  let publishedDigest = record.digest;
  if (evidence.publishedBy !== undefined) {
    if (!sigstore) throw new RangeError('a published-by bundle needs --trusted-root and --cosign');
    const facts = await verifyPublishedBy(skillDir, { bundlePath: evidence.publishedBy, ...sigstore });
    // A record that does not match the bytes is not evidence for them.
    if (facts.differences.length > 0) throw new Error(`the published-by record does not match these bytes: ${facts.differences.join('; ')}`);
    published_by = publisherOf(facts.publisher);
    publishedDigest = facts.digest;
  }
  const reviewed = evidence.policy ? await review(evidence.policy, evidence.trust, skillDir, now) : null;
  // Every source read the bytes separately: they must all have seen the same version.
  const check = await describeSkill(skillDir, path.dirname(path.resolve(skillDir)));
  if (check.digest !== record.digest || publishedDigest !== record.digest || (reviewed && reviewed.digest !== record.digest)) throw new Error('the Skill changed while its facts were collected');
  return {
    name: await resolveSkillName(skillDir),
    digest: record.digest,
    profile: record.profile,
    declaration: record.declaration,
    declaration_error: record.declaration_error,
    reviewed_by: reviewed && { approver_key_id: reviewed.approver_key_id, certificate_id: reviewed.certificate_id, issued_at: reviewed.issued_at, expires_at: reviewed.expires_at },
    published_by,
  };
}
