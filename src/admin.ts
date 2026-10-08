import path from 'node:path';
import { issueCertificate, parseCertificate } from './certificate.ts';
import { readRegularFile, resolveOutside, writeFileAtomic, writeNewFile } from './fs-safe.ts';
import { loadPrivateKey, loadPublicKey } from './keys.ts';
import { validateDigest, validateScope } from './names.ts';
import { readRevocationsForUpdate, signRevocations, type Revocations } from './revocations.ts';
import { addDuration, truncateToSecond } from './time.ts';
import { CERTIFICATE_FILENAME, collectSkillTree } from './tree-digest.ts';
import { readTrustRootForUpdate, signTrustRoot, type TrustRoot } from './trust-root.ts';
import { resolveSkillName } from './verify.ts';

export const DEFAULT_TRUST_ROOT_EXPIRY = '365d';
export const DEFAULT_REVOCATIONS_EXPIRY = '30d';

export async function initRoot(options: {
  rootKeyPath: string;
  trustRootOut: string;
  revocationsOut: string;
  now: Date;
  trustRootExpires?: string;
  revocationsExpires?: string;
}): Promise<{ rootKeyId: string; trustRoot: string; revocations: string }> {
  const root = await loadPrivateKey(options.rootKeyPath);
  const issuedAt = truncateToSecond(options.now);
  const trustRoot: TrustRoot = {
    version: 1, issuedAt, expiresAt: addDuration(issuedAt, options.trustRootExpires ?? DEFAULT_TRUST_ROOT_EXPIRY, 'trust root expiry'),
    root, approvers: [],
  };
  const revocations: Revocations = {
    version: 1, issuedAt, expiresAt: addDuration(issuedAt, options.revocationsExpires ?? DEFAULT_REVOCATIONS_EXPIRY, 'revocation list expiry'),
    rootKeyId: root.keyId, keys: [], digests: [],
  };
  const trustRootPath = await writeNewFile(options.trustRootOut, signTrustRoot(trustRoot, root.privateKey));
  const revocationsPath = await writeNewFile(options.revocationsOut, signRevocations(revocations, root.privateKey));
  return { rootKeyId: root.keyId, trustRoot: trustRootPath, revocations: revocationsPath };
}

async function updateTrustRoot(options: { rootKeyPath: string; trustRootPath: string; out?: string | undefined; now: Date; expires?: string | undefined },
  change: (trustRoot: TrustRoot) => void): Promise<{ version: number; path: string; trustRoot: TrustRoot }> {
  const root = await loadPrivateKey(options.rootKeyPath);
  const current = readTrustRootForUpdate(await readRegularFile(options.trustRootPath, 'Trust root', 4 * 1024 * 1024), root.keyId);
  const issuedAt = truncateToSecond(options.now);
  const next: TrustRoot = {
    ...current,
    version: current.version + 1,
    issuedAt,
    expiresAt: options.expires ? addDuration(issuedAt, options.expires, 'trust root expiry') : current.expiresAt,
    approvers: current.approvers.map((approver) => ({ ...approver, scopes: [...approver.scopes] })),
  };
  change(next);
  if (next.expiresAt <= issuedAt) throw new Error('The trust root would already be expired; pass --expires to extend it');
  const written = await writeFileAtomic(options.out ?? options.trustRootPath, signTrustRoot(next, root.privateKey));
  return { version: next.version, path: written, trustRoot: next };
}

export async function addApprover(options: {
  rootKeyPath: string; trustRootPath: string; out?: string; now: Date; trustRootExpires?: string;
  publicKeyPath: string; name: string; scopes: string[]; expires: string;
}): Promise<{ version: number; path: string; keyId: string }> {
  const approverKey = await loadPublicKey(options.publicKeyPath);
  if (options.scopes.length === 0) throw new Error('At least one --scope is required');
  const scopes = [...new Set(options.scopes.map((scope) => validateScope(scope)))].sort();
  const result = await updateTrustRoot({ rootKeyPath: options.rootKeyPath, trustRootPath: options.trustRootPath, out: options.out, now: options.now, expires: options.trustRootExpires }, (trustRoot) => {
    if (approverKey.keyId === trustRoot.root.keyId) throw new Error('The root key cannot be an approver; generate a separate approver key');
    trustRoot.approvers = trustRoot.approvers.filter((entry) => entry.keyId !== approverKey.keyId);
    trustRoot.approvers.push({ ...approverKey, name: options.name, scopes, expiresAt: addDuration(truncateToSecond(options.now), options.expires, 'approver expiry') });
  });
  return { version: result.version, path: result.path, keyId: approverKey.keyId };
}

export async function removeApprover(options: {
  rootKeyPath: string; trustRootPath: string; out?: string; now: Date; trustRootExpires?: string; keyId: string;
}): Promise<{ version: number; path: string }> {
  return await updateTrustRoot({ rootKeyPath: options.rootKeyPath, trustRootPath: options.trustRootPath, out: options.out, now: options.now, expires: options.trustRootExpires }, (trustRoot) => {
    const before = trustRoot.approvers.length;
    trustRoot.approvers = trustRoot.approvers.filter((entry) => entry.keyId !== options.keyId);
    if (trustRoot.approvers.length === before) throw new Error(`No approver with key id ${options.keyId}`);
  });
}

export async function updateRevocations(options: {
  rootKeyPath: string; revocationsPath: string; out?: string; now: Date; expires?: string;
  revokeKey?: string; revokeDigest?: string; reason?: string;
}): Promise<{ version: number; path: string; expiresAt: Date }> {
  const root = await loadPrivateKey(options.rootKeyPath);
  const current = readRevocationsForUpdate(await readRegularFile(options.revocationsPath, 'Revocation list', 8 * 1024 * 1024), root.keyId, root.publicKey);
  const issuedAt = truncateToSecond(options.now);
  const next: Revocations = {
    ...current, version: current.version + 1, issuedAt,
    expiresAt: addDuration(issuedAt, options.expires ?? DEFAULT_REVOCATIONS_EXPIRY, 'revocation list expiry'),
    keys: [...current.keys], digests: [...current.digests],
  };
  if (options.revokeKey) {
    if (next.keys.some((entry) => entry.keyId === options.revokeKey)) throw new Error(`Key ${options.revokeKey} is already revoked`);
    next.keys.push({ keyId: options.revokeKey, reason: options.reason ?? 'revoked', revokedAt: issuedAt });
  }
  if (options.revokeDigest) {
    const digest = validateDigest(options.revokeDigest);
    if (next.digests.some((entry) => entry.digest === digest)) throw new Error(`Digest ${digest} is already revoked`);
    next.digests.push({ digest, reason: options.reason ?? 'revoked', revokedAt: issuedAt });
  }
  const written = await writeFileAtomic(options.out ?? options.revocationsPath, signRevocations(next, root.privateKey));
  return { version: next.version, path: written, expiresAt: next.expiresAt };
}

export async function approveSkill(options: {
  skillDir: string; approverKeyPath: string; now: Date; expires: string; reason: string;
  name?: string; previous?: string; out?: string;
}): Promise<{ path: string; skillName: string; digest: string; certificateId: string; expiresAt: Date }> {
  const skillDir = path.resolve(options.skillDir);
  const approver = await loadPrivateKey(options.approverKeyPath);
  await resolveOutside(options.approverKeyPath, skillDir, 'Approver private key');
  const skillName = await resolveSkillName(skillDir, options.name);
  const tree = await collectSkillTree(skillDir);
  let previousDigest: string | null = null;
  if (options.previous) {
    previousDigest = options.previous.startsWith('sha256:')
      ? validateDigest(options.previous, 'previous digest')
      : parseCertificate(await readRegularFile(options.previous, 'Previous certificate', 8 * 1024 * 1024)).digest;
  }
  const issuedAt = truncateToSecond(options.now);
  const expiresAt = addDuration(issuedAt, options.expires, 'certificate expiry');
  const bytes = issueCertificate({
    skillName, digest: tree.digest, files: tree.files, approver, issuedAt, expiresAt, reason: options.reason, previousDigest,
  });
  const out = options.out ?? path.join(tree.root, CERTIFICATE_FILENAME);
  const written = await writeFileAtomic(out, bytes);
  return { path: written, skillName, digest: tree.digest, certificateId: parseCertificate(bytes).id, expiresAt };
}
