import { unlink } from 'node:fs/promises';
import path from 'node:path';
import { requireString } from './canonical-json.ts';
import { issueCertificate, parseCertificate } from './certificate.ts';
import { readRegularFile, realpathAllowingMissing, resolveOutside, writeFileAtomic, writeNewFile } from './fs-safe.ts';
import { loadPrivateKey, loadPublicKey, validateKeyId } from './keys.ts';
import { validateDigest, validateScope } from './names.ts';
import { readRevocationsForUpdate, signRevocations, type Revocations } from './revocations.ts';
import { addDuration, truncateToSecond } from './time.ts';
import { CERTIFICATE_FILENAME, collectSkillTree } from './tree-digest.ts';
import { MAX_APPROVERS, MAX_SCOPES, readTrustRootForUpdate, signTrustRoot, type TrustRoot } from './trust-root.ts';
import { resolveSkillName } from './verify.ts';

export const DEFAULT_TRUST_ROOT_EXPIRY  = '365d';
export const DEFAULT_REVOCATIONS_EXPIRY = '30d';

const MAX_TRUST_ROOT_BYTES    = 4 * 1024 * 1024;
const MAX_REVOCATIONS_BYTES   = 8 * 1024 * 1024;
const MAX_CERTIFICATE_BYTES   = 8 * 1024 * 1024;
const MAX_APPROVER_NAME_LEN   = 128;
const MAX_REVOCATION_REASON   = 512;
const DEFAULT_REVOKE_REASON   = 'revoked';

const latin1Decoder = new TextDecoder('latin1');

/**
 * Private-key encodings `approve` refuses to certify (a certified file can reach the model through Pi):
 * PEM/OpenSSH/PKCS#8/SSH2 armor ("BEGIN [RSA |EC |DSA |ENCRYPTED |OPENSSH |...]PRIVATE KEY"), OpenPGP armor
 * ("BEGIN PGP PRIVATE KEY BLOCK"), PuTTY .ppk files, and age secret keys. Public keys and PGP PUBLIC KEY
 * BLOCKs do not match. This is a best-effort guard, not a secret scanner.
 */
// Every quantifier is bounded, so scanning is linear in the input (no backtracking blow-up on long runs of
// dashes, spaces or "BEGIN "). Three dashes are enough to anchor the header; "---- BEGIN SSH2 ..." contains them.
const PRIVATE_KEY_PATTERNS: readonly RegExp[] = [
  /-{3}\s{0,4}BEGIN [A-Z0-9 ]{0,64}PRIVATE KEY/iu,
  /PuTTY-User-Key-File-\d{1,4}:/u,
  /AGE-SECRET-KEY-1[0-9A-Z]{20,200}/iu,
];

/** True if the bytes contain recognizable private-key material. */
export function containsPrivateKey(content: Uint8Array): boolean {
  const text = latin1Decoder.decode(content);
  return PRIVATE_KEY_PATTERNS.some((pattern) => pattern.test(text));
}

export async function initRoot(options: {
  rootKeyPath: string;
  trustRootOut: string;
  revocationsOut: string;
  now: Date;
  trustRootExpires?: string;
  revocationsExpires?: string;
}): Promise<{ rootKeyId: string; trustRoot: string; revocations: string }> {
  const trustRootTarget   = path.resolve(options.trustRootOut);
  const revocationsTarget = path.resolve(options.revocationsOut);
  const canonicalTrust    = await realpathAllowingMissing(trustRootTarget);
  const canonicalRevoke   = await realpathAllowingMissing(revocationsTarget);

  if (trustRootTarget === revocationsTarget || canonicalTrust === canonicalRevoke) {
    throw new Error('Trust root and revocation list output paths must differ');
  }

  const root     = await loadPrivateKey(options.rootKeyPath);
  const issuedAt = truncateToSecond(options.now);

  const trustRoot: TrustRoot = {
    version: 1,
    issuedAt,
    expiresAt: addDuration(
      issuedAt,
      options.trustRootExpires ?? DEFAULT_TRUST_ROOT_EXPIRY,
      'trust root expiry',
    ),
    root,
    approvers: [],
  };

  const revocations: Revocations = {
    version: 1,
    issuedAt,
    expiresAt: addDuration(
      issuedAt,
      options.revocationsExpires ?? DEFAULT_REVOCATIONS_EXPIRY,
      'revocation list expiry',
    ),
    rootKeyId: root.keyId,
    keys: [],
    digests: [],
  };

  const trustRootBytes   = signTrustRoot(trustRoot, root.privateKey);
  const revocationsBytes = signRevocations(revocations, root.privateKey);
  const trustRootPath    = await writeNewFile(trustRootTarget, trustRootBytes);

  try {
    const revocationsPath = await writeNewFile(revocationsTarget, revocationsBytes);
    return {
      rootKeyId: root.keyId,
      trustRoot: trustRootPath,
      revocations: revocationsPath,
    };
  } catch (error) {
    await unlink(trustRootPath).catch(() => {});
    throw error;
  }
}

async function updateTrustRoot(
  options: {
    rootKeyPath: string;
    trustRootPath: string;
    out?: string | undefined;
    now: Date;
    expires?: string | undefined;
  },
  change: (trustRoot: TrustRoot) => void,
): Promise<{ version: number; path: string; trustRoot: TrustRoot }> {
  const root      = await loadPrivateKey(options.rootKeyPath);
  const rawBytes  = await readRegularFile(options.trustRootPath, 'Trust root', MAX_TRUST_ROOT_BYTES);
  const current   = readTrustRootForUpdate(rawBytes, root.keyId);
  const issuedAt  = truncateToSecond(options.now);
  const expiresAt = options.expires
    ? addDuration(issuedAt, options.expires, 'trust root expiry')
    : current.expiresAt;

  const next: TrustRoot = {
    ...current,
    version: current.version + 1,
    issuedAt,
    expiresAt,
    approvers: current.approvers.map((approver) => ({
      ...approver,
      scopes: [...approver.scopes],
    })),
  };

  change(next);

  if (next.expiresAt <= issuedAt) {
    throw new Error('The trust root would already be expired; pass --expires to extend it');
  }

  const targetPath = options.out ?? options.trustRootPath;
  const written    = await writeFileAtomic(targetPath, signTrustRoot(next, root.privateKey));

  return { version: next.version, path: written, trustRoot: next };
}

export async function addApprover(options: {
  rootKeyPath: string;
  trustRootPath: string;
  out?: string;
  now: Date;
  trustRootExpires?: string;
  publicKeyPath: string;
  name: string;
  scopes: string[];
  expires: string;
}): Promise<{ version: number; path: string; keyId: string }> {
  const approverName = requireString(options.name, 'Approver name', MAX_APPROVER_NAME_LEN);
  const approverKey  = await loadPublicKey(options.publicKeyPath);

  if (options.scopes.length === 0) {
    throw new Error('At least one --scope is required');
  }

  const scopes = [...new Set(options.scopes.map((scope) => validateScope(scope)))].sort();
  if (scopes.length > MAX_SCOPES) {
    throw new Error(`Approver scopes cannot exceed ${MAX_SCOPES}`);
  }

  const issuedAt  = truncateToSecond(options.now);
  const expiresAt = addDuration(issuedAt, options.expires, 'approver expiry');

  const result = await updateTrustRoot(
    {
      rootKeyPath: options.rootKeyPath,
      trustRootPath: options.trustRootPath,
      out: options.out,
      now: options.now,
      expires: options.trustRootExpires,
    },
    (trustRoot) => {
      if (approverKey.keyId === trustRoot.root.keyId) {
        throw new Error('The root key cannot be an approver; generate a separate approver key');
      }

      const remaining = trustRoot.approvers.filter((entry) => entry.keyId !== approverKey.keyId);
      if (remaining.length >= MAX_APPROVERS) {
        throw new Error(`Trust root cannot exceed ${MAX_APPROVERS} approvers`);
      }

      remaining.push({
        ...approverKey,
        name: approverName,
        scopes,
        expiresAt,
      });
      trustRoot.approvers = remaining;
    },
  );

  return { version: result.version, path: result.path, keyId: approverKey.keyId };
}

export async function removeApprover(options: {
  rootKeyPath: string;
  trustRootPath: string;
  out?: string;
  now: Date;
  trustRootExpires?: string;
  keyId: string;
}): Promise<{ version: number; path: string }> {
  const targetKeyId = validateKeyId(options.keyId, 'Approver key id');

  return await updateTrustRoot(
    {
      rootKeyPath: options.rootKeyPath,
      trustRootPath: options.trustRootPath,
      out: options.out,
      now: options.now,
      expires: options.trustRootExpires,
    },
    (trustRoot) => {
      const beforeCount = trustRoot.approvers.length;
      trustRoot.approvers = trustRoot.approvers.filter((entry) => entry.keyId !== targetKeyId);
      if (trustRoot.approvers.length === beforeCount) {
        throw new Error(`No approver with key id ${targetKeyId}`);
      }
    },
  );
}

export async function updateRevocations(options: {
  rootKeyPath: string;
  revocationsPath: string;
  out?: string;
  now: Date;
  expires?: string;
  revokeKey?: string;
  revokeDigest?: string;
  reason?: string;
}): Promise<{ version: number; path: string; expiresAt: Date }> {
  const root      = await loadPrivateKey(options.rootKeyPath);
  const rawBytes  = await readRegularFile(options.revocationsPath, 'Revocation list', MAX_REVOCATIONS_BYTES);
  const current   = readRevocationsForUpdate(rawBytes, root.keyId, root.publicKey);
  const issuedAt  = truncateToSecond(options.now);
  const expiresAt = addDuration(
    issuedAt,
    options.expires ?? DEFAULT_REVOCATIONS_EXPIRY,
    'revocation list expiry',
  );
  const reason = requireString(
    options.reason ?? DEFAULT_REVOKE_REASON,
    'Revocation reason',
    MAX_REVOCATION_REASON,
  );

  const next: Revocations = {
    ...current,
    version: current.version + 1,
    issuedAt,
    expiresAt,
    keys: [...current.keys],
    digests: [...current.digests],
  };

  if (options.revokeKey !== undefined) {
    const keyId = validateKeyId(options.revokeKey, 'Revoked key id');
    if (next.keys.some((entry) => entry.keyId === keyId)) {
      throw new Error(`Key ${keyId} is already revoked`);
    }
    next.keys.push({ keyId, reason, revokedAt: issuedAt });
  }

  if (options.revokeDigest !== undefined) {
    const digest = validateDigest(options.revokeDigest);
    if (next.digests.some((entry) => entry.digest === digest)) {
      throw new Error(`Digest ${digest} is already revoked`);
    }
    next.digests.push({ digest, reason, revokedAt: issuedAt });
  }

  const targetPath = options.out ?? options.revocationsPath;
  const written    = await writeFileAtomic(targetPath, signRevocations(next, root.privateKey));

  return { version: next.version, path: written, expiresAt: next.expiresAt };
}

export async function approveSkill(options: {
  skillDir: string;
  approverKeyPath: string;
  now: Date;
  expires: string;
  reason: string;
  name?: string;
  previous?: string;
  out?: string;
}): Promise<{ path: string; skillName: string; digest: string; certificateId: string; expiresAt: Date }> {
  const skillDir = path.resolve(options.skillDir);

  // Verify the key path is outside the Skill directory before reading the private key.
  await resolveOutside(options.approverKeyPath, skillDir, 'Approver private key');
  const approver  = await loadPrivateKey(options.approverKeyPath);
  const skillName = await resolveSkillName(skillDir, options.name);
  const tree      = await collectSkillTree(skillDir, { includeContents: true });

  for (const [filePath, content] of tree.contents!) {
    if (containsPrivateKey(content)) {
      throw new Error(
        `Refusing to approve: ${filePath} contains a private key. Remove it from the Skill and rotate that key.`,
      );
    }
  }

  let previousDigest: string | null = null;
  if (options.previous) {
    if (options.previous.startsWith('sha256:')) {
      previousDigest = validateDigest(options.previous, 'previous digest');
    } else {
      const prevBytes = await readRegularFile(options.previous, 'Previous certificate', MAX_CERTIFICATE_BYTES);
      previousDigest  = parseCertificate(prevBytes).digest;
    }
  }

  const issuedAt  = truncateToSecond(options.now);
  const expiresAt = addDuration(issuedAt, options.expires, 'certificate expiry');
  const bytes     = issueCertificate({
    skillName,
    digest: tree.digest,
    files: tree.files,
    approver,
    issuedAt,
    expiresAt,
    reason: options.reason,
    previousDigest,
  });

  const targetPath = options.out ?? path.join(tree.root, CERTIFICATE_FILENAME);
  const written    = await writeFileAtomic(targetPath, bytes);
  const parsed     = parseCertificate(bytes);

  return {
    path: written,
    skillName,
    digest: tree.digest,
    certificateId: parsed.id,
    expiresAt,
  };
}
