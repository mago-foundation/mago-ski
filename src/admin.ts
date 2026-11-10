import type { KeyObject } from 'node:crypto';
import { unlink } from 'node:fs/promises';
import path from 'node:path';
import { requireString } from './canonical-json.ts';
import { issueCertificate, parseCertificate } from './certificate.ts';
import { readRegularFile, realpathAllowingMissing, resolveOutside, writeFileAtomic, writeNewFile } from './fs-safe.ts';
import { loadPrivateKey, loadPublicKey, validateKeyId, type PrivateKeyInfo, type PublicKeyInfo } from './keys.ts';
import { validateDigest, validateScope } from './names.ts';
import type { ForbiddenKey } from './policy.ts';
import { isDisplaySafeText } from './root-events.ts';
import { readRevocationsForUpdate, signRevocations, type Revocations } from './revocations.ts';
import { addDuration, truncateToSecond } from './time.ts';
import { CERTIFICATE_FILENAME, collectSkillTree, sha256Hex, requireSkillRoot, SKILL_FILENAME } from './tree-digest.ts';
import { MAX_APPROVERS, MAX_SCOPES, readTrustRootForUpdate, signTrustRoot, type TrustRoot } from './trust-root.ts';
import { skillNameFromSkillFile } from './verify.ts';

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

/** A document was older than the lowest version this computer's memory allows. The GUI maps it by class. */
export class StaleDocumentError extends Error {
  constructor(label: string, version: number, minimum: number) {
    super(`${label} version ${version} is older than version ${minimum} this computer has seen`);
    this.name = 'StaleDocumentError';
  }
}

/** A document changed between prepare and commit. The GUI maps it, and `FileChangedError`, by class. */
export class DocumentChangedError extends Error {
  constructor(label: string) {
    super(`${label} changed after it was prepared; prepare again`);
    this.name = 'DocumentChangedError';
  }
}

const sha256Of = (bytes: Uint8Array): string => `sha256:${sha256Hex(bytes)}`;

/** `sha256:<hex>` of the regular file at `filePath`, or `null` when it does not exist. */
async function fileSha256OrNull(filePath: string, label: string, maxBytes: number): Promise<string | null> {
  try {
    return sha256Of(await readRegularFile(filePath, label, maxBytes));
  } catch (error) {
    if ((error as NodeJS.ErrnoException)?.code === 'ENOENT')
      return null;
    throw error;
  }
}

const FORBIDDEN_WHY: Record<ForbiddenKey['why'], string> = {
  root:           'the root key',
  recovery:       'a recovery key',
  timestamp:      'the timestamp key',
  retired:        'a key that held the root or timestamp role',
  formerRecovery: 'a former recovery key',
  revoked:        'a revoked key',
};

export type TrustRootChange =
  | { kind: 'add'; publicKey: PublicKeyInfo; name: string; scopes: string[]; expires: string; trustRootExpires?: string }
  | { kind: 'remove'; keyId: string; trustRootExpires?: string }
  | { kind: 'renew'; trustRootExpires: string };

export interface PreparedTrustRoot {
  kind:          'trust-root';
  /** The trust root read. */
  source:        string;
  /** Where commit writes: `out` or the source. */
  target:        string;
  /** `sha256:<hex>` of `source` as read. */
  baseSha256:    string;
  /** When `target` differs from `source`: its `sha256:<hex>` at prepare, or null when absent. */
  targetBase:    string | null;
  rootKeyId:     string;
  current:       TrustRoot;
  /** Exactly what commit signs. */
  payload:       TrustRoot;
  change:        TrustRootChange;
  replaces:      TrustRoot['approvers'][number] | null;
}

/** Reads the trust root once, applies the change and returns the unsigned result. Never signs or writes. */
export async function prepareTrustRootChange(o: {
  rootKeyId:       string;
  trustRootPath:   string;
  out?:            string | undefined;
  now:             Date;
  change:          TrustRootChange;
  forbidden?:      ForbiddenKey[] | undefined;
  minimumVersion?: number | undefined;
}): Promise<PreparedTrustRoot> {
  const change = o.change;
  let approverEntry: TrustRoot['approvers'][number] | null = null;
  const issuedAt = truncateToSecond(o.now);
  if (change.kind === 'add') {
    const approverName = requireString(change.name, 'Approver name', MAX_APPROVER_NAME_LEN);
    if (!isDisplaySafeText(approverName))
      throw new Error('Approver name contains characters that cannot be shown safely');
    if (change.scopes.length === 0)
      throw new Error('At least one --scope is required');
    const scopes = [...new Set(change.scopes.map((scope) => validateScope(scope)))].sort();
    if (scopes.length > MAX_SCOPES)
      throw new Error(`Approver scopes cannot exceed ${MAX_SCOPES}`);
    approverEntry = {
      ...change.publicKey,
      name: approverName,
      scopes,
      expiresAt: addDuration(issuedAt, change.expires, 'approver expiry'),
    };
  }
  const removeId = change.kind === 'remove' ? validateKeyId(change.keyId, 'Approver key id') : null;

  const source     = o.trustRootPath;
  const rawBytes   = await readRegularFile(source, 'Trust root', MAX_TRUST_ROOT_BYTES);
  const current    = readTrustRootForUpdate(rawBytes, o.rootKeyId);
  if (o.minimumVersion !== undefined && current.version < o.minimumVersion)
    throw new StaleDocumentError('Trust root', current.version, o.minimumVersion);

  const expiresAt = change.trustRootExpires
    ? addDuration(issuedAt, change.trustRootExpires, 'trust root expiry')
    : current.expiresAt;
  const next: TrustRoot = {
    ...current,
    version: current.version + 1,
    issuedAt,
    expiresAt,
    approvers: current.approvers.map((approver) => ({ ...approver, scopes: [...approver.scopes] })),
  };

  let replaces: TrustRoot['approvers'][number] | null = null;
  if (change.kind === 'add') {
    if (change.publicKey.keyId === next.root.keyId)
      throw new Error('The root key cannot be an approver; generate a separate approver key');
    replaces = next.approvers.find((entry) => entry.keyId === change.publicKey.keyId) ?? null;
    const remaining = next.approvers.filter((entry) => entry.keyId !== change.publicKey.keyId);
    if (remaining.length >= MAX_APPROVERS)
      throw new Error(`Trust root cannot exceed ${MAX_APPROVERS} approvers`);
    remaining.push(approverEntry!);
    next.approvers = remaining;
  } else if (change.kind === 'remove') {
    const beforeCount = next.approvers.length;
    next.approvers = next.approvers.filter((entry) => entry.keyId !== removeId);
    if (next.approvers.length === beforeCount)
      throw new Error(`No approver with key id ${removeId}`);
  }

  if (next.expiresAt <= issuedAt)
    throw new Error('The trust root would already be expired; pass --expires to extend it');

  for (const entry of o.forbidden ?? []) {
    if (next.approvers.some((approver) => approver.keyId === entry.keyId))
      throw new Error(`Approver ${entry.keyId} cannot stay or be added: it is ${FORBIDDEN_WHY[entry.why]}`);
  }

  const target = o.out ?? source;
  return {
    kind: 'trust-root',
    source,
    target,
    baseSha256: sha256Of(rawBytes),
    targetBase: path.resolve(target) === path.resolve(source) ? null : await fileSha256OrNull(target, 'Trust root output', MAX_TRUST_ROOT_BYTES),
    rootKeyId: o.rootKeyId,
    current,
    payload: next,
    change,
    replaces,
  };
}

function requireKey(p: { rootKeyId: string }, key: PrivateKeyInfo): void {
  if (key.keyId !== p.rootKeyId)
    throw new Error('Key does not match the prepared root key');
}

/** Pure: signs `p.payload` and nothing else. The preview and commit use this one code path. */
export function signPreparedTrustRoot(p: PreparedTrustRoot, key: PrivateKeyInfo): Buffer {
  return signTrustRoot(p.payload, key.privateKey);
}

export async function commitTrustRoot(
  p: PreparedTrustRoot,
  rootKey: PrivateKeyInfo,
  o: { beforeWrite?: () => void | Promise<void> } = {},
): Promise<{ version: number; path: string; sha256: string }> {
  requireKey(p, rootKey);
  const again = await readRegularFile(p.source, 'Trust root', MAX_TRUST_ROOT_BYTES);
  if (sha256Of(again) !== p.baseSha256)
    throw new DocumentChangedError('Trust root');
  const bytes = signPreparedTrustRoot(p, rootKey);
  await o.beforeWrite?.();
  const sameFile = path.resolve(p.target) === path.resolve(p.source);
  const written  = await writeFileAtomic(p.target, bytes, 0o644, { expectSha256: sameFile ? p.baseSha256 : p.targetBase });
  return { version: p.payload.version, path: written, sha256: sha256Of(bytes) };
}

async function updateTrustRoot(
  options: {
    rootKeyPath: string;
    trustRootPath: string;
    out?: string | undefined;
    now: Date;
    expires?: string | undefined;
  },
  change: (expires: string | undefined) => TrustRootChange,
  forbidden?: ForbiddenKey[] | undefined,
): Promise<{ version: number; path: string; trustRoot: TrustRoot }> {
  const root     = await loadPrivateKey(options.rootKeyPath);
  const prepared = await prepareTrustRootChange({
    rootKeyId: root.keyId, trustRootPath: options.trustRootPath, out: options.out, now: options.now,
    change: change(options.expires), forbidden,
  });
  const written  = await commitTrustRoot(prepared, root);
  return { version: written.version, path: written.path, trustRoot: prepared.payload };
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
  /** Keys that must not be approvers (see `forbiddenApproverKeys`); the CLI passes them with `--policy`. */
  forbidden?: ForbiddenKey[];
}): Promise<{ version: number; path: string; keyId: string }> {
  requireString(options.name, 'Approver name', MAX_APPROVER_NAME_LEN);
  const approverKey = await loadPublicKey(options.publicKeyPath);

  const result = await updateTrustRoot(
    { ...options, expires: options.trustRootExpires },
    (trustRootExpires) => ({
      kind: 'add', publicKey: approverKey, name: options.name, scopes: options.scopes, expires: options.expires,
      ...(trustRootExpires ? { trustRootExpires } : {}),
    }),
    options.forbidden,
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
    { ...options, expires: options.trustRootExpires },
    (trustRootExpires) => ({ kind: 'remove', keyId: targetKeyId, ...(trustRootExpires ? { trustRootExpires } : {}) }),
  );
}

/** Re-signs the trust root with a new expiry and the same approvers. */
export async function renewTrustRoot(options: {
  rootKeyPath: string;
  trustRootPath: string;
  out?: string;
  now: Date;
  expires: string;
}): Promise<{ version: number; path: string; expiresAt: Date }> {
  const result = await updateTrustRoot(
    { ...options, expires: options.expires },
    (expires) => ({ kind: 'renew', trustRootExpires: expires! }),
  );
  return { version: result.version, path: result.path, expiresAt: result.trustRoot.expiresAt };
}

export type RevocationChange =
  | { kind: 'key'; keyId: string; reason: string }
  | { kind: 'digest'; digest: string; reason: string }
  | { kind: 'both'; keyId: string; digest: string; reason: string }
  | { kind: 'refresh' };

export interface PreparedRevocations {
  kind:       'revocations';
  source:     string;
  target:     string;
  baseSha256: string;
  targetBase: string | null;
  rootKeyId:  string;
  current:    Revocations;
  payload:    Revocations;
  change:     RevocationChange;
}

export async function prepareRevocationsChange(o: {
  rootKeyId:       string;
  rootPublicKey:   KeyObject;
  revocationsPath: string;
  out?:            string | undefined;
  now:             Date;
  expires:         string;
  change:          RevocationChange;
  minimumVersion?: number | undefined;
}): Promise<PreparedRevocations> {
  const change   = o.change;
  const issuedAt = truncateToSecond(o.now);
  let reason = '';
  if (change.kind !== 'refresh') {
    reason = requireString(change.reason, 'Revocation reason', MAX_REVOCATION_REASON);
    if (!isDisplaySafeText(reason))
      throw new Error('Revocation reason contains characters that cannot be shown safely');
  }
  const keyId  = change.kind === 'key' || change.kind === 'both' ? validateKeyId(change.keyId, 'Revoked key id') : null;
  const digest = change.kind === 'digest' || change.kind === 'both' ? validateDigest(change.digest) : null;

  const source   = o.revocationsPath;
  const rawBytes = await readRegularFile(source, 'Revocation list', MAX_REVOCATIONS_BYTES);
  const current  = readRevocationsForUpdate(rawBytes, o.rootKeyId, o.rootPublicKey);
  if (o.minimumVersion !== undefined && current.version < o.minimumVersion)
    throw new StaleDocumentError('Revocation list', current.version, o.minimumVersion);
  const expiresAt = addDuration(issuedAt, o.expires, 'revocation list expiry');

  const next: Revocations = {
    ...current,
    version: current.version + 1,
    issuedAt,
    expiresAt,
    keys: [...current.keys],
    digests: [...current.digests],
  };

  if (keyId !== null) {
    if (next.keys.some((entry) => entry.keyId === keyId))
      throw new Error(`Key ${keyId} is already revoked`);
    next.keys.push({ keyId, reason, revokedAt: issuedAt });
  }

  if (digest !== null) {
    if (next.digests.some((entry) => entry.digest === digest))
      throw new Error(`Digest ${digest} is already revoked`);
    next.digests.push({ digest, reason, revokedAt: issuedAt });
  }

  const target = o.out ?? source;
  return {
    kind: 'revocations',
    source,
    target,
    baseSha256: sha256Of(rawBytes),
    targetBase: path.resolve(target) === path.resolve(source) ? null : await fileSha256OrNull(target, 'Revocation list output', MAX_REVOCATIONS_BYTES),
    rootKeyId: o.rootKeyId,
    current,
    payload: next,
    change,
  };
}

export function signPreparedRevocations(p: PreparedRevocations, key: PrivateKeyInfo): Buffer {
  return signRevocations(p.payload, key.privateKey);
}

export async function commitRevocations(
  p: PreparedRevocations,
  rootKey: PrivateKeyInfo,
  o: { beforeWrite?: () => void | Promise<void> } = {},
): Promise<{ version: number; path: string; sha256: string; expiresAt: Date }> {
  requireKey(p, rootKey);
  const again = await readRegularFile(p.source, 'Revocation list', MAX_REVOCATIONS_BYTES);
  if (sha256Of(again) !== p.baseSha256)
    throw new DocumentChangedError('Revocation list');
  const bytes = signPreparedRevocations(p, rootKey);
  await o.beforeWrite?.();
  const sameFile = path.resolve(p.target) === path.resolve(p.source);
  const written  = await writeFileAtomic(p.target, bytes, 0o644, { expectSha256: sameFile ? p.baseSha256 : p.targetBase });
  return { version: p.payload.version, path: written, sha256: sha256Of(bytes), expiresAt: p.payload.expiresAt };
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
  const root   = await loadPrivateKey(options.rootKeyPath);
  const reason = requireString(
    options.reason ?? DEFAULT_REVOKE_REASON,
    'Revocation reason',
    MAX_REVOCATION_REASON,
  );
  const change: RevocationChange =
    options.revokeKey !== undefined && options.revokeDigest !== undefined ? { kind: 'both', keyId: options.revokeKey, digest: options.revokeDigest, reason }
    : options.revokeKey !== undefined ? { kind: 'key', keyId: options.revokeKey, reason }
    : options.revokeDigest !== undefined ? { kind: 'digest', digest: options.revokeDigest, reason }
    : { kind: 'refresh' };

  const prepared = await prepareRevocationsChange({
    rootKeyId: root.keyId, rootPublicKey: root.publicKey, revocationsPath: options.revocationsPath, out: options.out,
    now: options.now, expires: options.expires ?? DEFAULT_REVOCATIONS_EXPIRY, change,
  });
  const written = await commitRevocations(prepared, root);
  return { version: written.version, path: written.path, expiresAt: written.expiresAt };
}

export async function approveSkill(options: {
  skillDir: string;
  /** The approver's private key file; or pass `approverKey`, already loaded (exactly one of the two). */
  approverKeyPath?: string;
  approverKey?: PrivateKeyInfo;
  now: Date;
  expires: string;
  reason: string;
  name?: string;
  previous?: string;
  out?: string;
  /** The digest the approver reviewed; issuance is refused if the bytes on disk differ. */
  expectDigest?: string;
  /** The Skill name the approver reviewed; issuance is refused if the signed SKILL.md yields a different name. */
  expectName?: string;
  /** Write to `<outDir>/<signed name>.cert.json` instead of next to the Skill; exclusive with `out`. */
  outDir?: string;
  /** Awaited after the certificate is built and just before it is written; a throw writes nothing. */
  beforeSign?: (info: { skillName: string; digest: string }) => void | Promise<void>;
}): Promise<{ path: string; skillName: string; digest: string; certificateId: string; expiresAt: Date }> {
  const skillDir = path.resolve(options.skillDir);
  const expected = options.expectDigest === undefined ? null : validateDigest(options.expectDigest, 'expected digest');

  if ((options.approverKeyPath === undefined) === (options.approverKey === undefined)) {
    throw new Error('Pass exactly one of approverKeyPath and approverKey');
  }
  if (options.out !== undefined && options.outDir !== undefined) {
    throw new Error('Pass at most one of out and outDir');
  }

  await requireSkillRoot(skillDir);
  let approver: PrivateKeyInfo;
  if (options.approverKeyPath !== undefined) {
    // Verify the key path is outside the Skill directory before reading the private key.
    await resolveOutside(options.approverKeyPath, skillDir, 'Approver private key');
    approver = await loadPrivateKey(options.approverKeyPath);
  } else {
    approver = options.approverKey!;
  }
  const tree      = await collectSkillTree(skillDir, { includeContents: true });
  // Taken from the same SKILL.md bytes that are hashed and signed, so the name cannot differ from the reviewed version.
  const skillName = skillNameFromSkillFile(skillDir, tree.contents!.get(SKILL_FILENAME), options.name);

  // Checked against the same bytes that are signed, so a change after review can never be certified.
  if (expected !== null && tree.digest !== expected) {
    throw new Error(
      `Refusing to approve: the Skill changed since it was reviewed (expected ${expected}, found ${tree.digest}). Review the current version and approve again.`,
    );
  }

  if (options.expectName !== undefined && skillName !== options.expectName) {
    throw new Error(
      `Refusing to approve: the Skill name is "${skillName}", not the reviewed "${options.expectName}"`,
    );
  }

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

  await options.beforeSign?.({ skillName, digest: tree.digest });

  const targetPath = options.out
    ?? (options.outDir === undefined ? path.join(tree.root, CERTIFICATE_FILENAME) : path.join(options.outDir, `${skillName}.cert.json`));
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
