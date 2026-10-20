import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, type KeyObject } from 'node:crypto';
import { lstat, unlink } from 'node:fs/promises';
import path from 'node:path';
import { readRegularFile, realpathAllowingMissing, writeNewFile } from './fs-safe.ts';
import { SKILL_FILENAME } from './tree-digest.ts';

export const KEY_ID_PATTERN = /^sha256:[0-9a-f]{64}$/u;
const BASE64_PATTERN        = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u;
const MAX_SPKI_BASE64_LEN   = 256;
const MAX_KEY_FILE_BYTES    = 64 * 1024;
const PRIVATE_KEY_MODE      = 0o600;
const PUBLIC_KEY_MODE       = 0o644;
const GROUP_OTHER_PERMS     = 0o077;

export interface PublicKeyInfo {
  keyId:      string;
  publicKey:  KeyObject;
  /** Canonical base64 of the DER SubjectPublicKeyInfo. */
  spki:       string;
}

export interface PrivateKeyInfo extends PublicKeyInfo {
  privateKey: KeyObject;
}

export function keyIdFromSpkiDer(der: Uint8Array): string {
  return `sha256:${createHash('sha256').update(der).digest('hex')}`;
}

function describePublicKey(publicKey: KeyObject): PublicKeyInfo {
  if (publicKey.asymmetricKeyType !== 'ed25519')
    throw new Error('Key is not Ed25519');

  const der = publicKey.export({ format: 'der', type: 'spki' });
  return {
    keyId: keyIdFromSpkiDer(der),
    publicKey,
    spki: der.toString('base64'),
  };
}

export function validateKeyId(value: unknown, label: string): string {
  if (typeof value !== 'string' || !KEY_ID_PATTERN.test(value)) 
    throw new Error(`${label} must be a sha256:<64 hex> key identifier`);
  return value;
}

/** Parses a canonical base64 Ed25519 SPKI and, if given, checks it hashes to `expectedKeyId`. */
export function parseSpki(
  spki: unknown,
  label: string,
  expectedKeyId?: string,
): PublicKeyInfo {
  let publicKey: KeyObject;

  if (expectedKeyId !== undefined)
    validateKeyId(expectedKeyId, `${label} expectedKeyId`);

  if (
    typeof spki !== 'string' ||
    spki.length === 0 ||
    spki.length > MAX_SPKI_BASE64_LEN ||
    !BASE64_PATTERN.test(spki)
  ) {
    throw new Error(`${label} must be canonical base64 SubjectPublicKeyInfo`);
  }

  const der = Buffer.from(spki, 'base64');
  if (der.toString('base64') !== spki)
    throw new Error(`${label} must be canonical base64 SubjectPublicKeyInfo`);

  try {
    publicKey = createPublicKey({ key: der, format: 'der', type: 'spki' });
  } catch {
    throw new Error(`${label} is not a valid public key`);
  }

  const info = describePublicKey(publicKey);
  if (info.spki !== spki)
    throw new Error(`${label} is not in canonical DER form`);

  if (expectedKeyId !== undefined && info.keyId !== expectedKeyId)
    throw new Error(`${label} does not match key id ${expectedKeyId}`);

  return info;
}

async function refuseInsideSkillAt(targetPath: string): Promise<void> {
  let directory = path.dirname(targetPath);

  while (true) {
    let hasSkillMd = false;
    try {
      await lstat(path.join(directory, SKILL_FILENAME));
      hasSkillMd = true;
    } catch (error) {
      const code = (error as NodeJS.ErrnoException)?.code;
      if (code !== 'ENOENT' && code !== 'ENOTDIR')
        throw error;
    }

    if (hasSkillMd) {
      throw new Error(
        `Refusing to write a private key inside a Skill directory (${directory}); keep keys outside every Skill tree`,
      );
    }

    const parent = path.dirname(directory);
    if (parent === directory)
      return;
    directory = parent;
  }
}

/** Private keys must never be written where a Skill (and so its certificate and hosts) could include them. */
async function refuseInsideSkill(filePath: string): Promise<void> {
  const lexicalTarget = path.resolve(filePath);
  const canonicalTarget = await realpathAllowingMissing(lexicalTarget);

  await refuseInsideSkillAt(lexicalTarget);
  if (canonicalTarget !== lexicalTarget)
    await refuseInsideSkillAt(canonicalTarget);
}

export async function generateKeyPair(
  privatePath: string,
  publicPath: string,
): Promise<PublicKeyInfo & { privatePath: string; publicPath: string }> {
  const privateTarget = path.resolve(privatePath);
  const publicTarget = path.resolve(publicPath);
  const canonicalPrivate = await realpathAllowingMissing(privateTarget);
  const canonicalPublic = await realpathAllowingMissing(publicTarget);

  if (privateTarget === publicTarget || canonicalPrivate === canonicalPublic)
    throw new Error('Private and public key paths must differ');

  await refuseInsideSkill(privateTarget);

  const pair = generateKeyPairSync('ed25519');
  const privatePem = Buffer.from(pair.privateKey.export({ type: 'pkcs8', format: 'pem' }));
  const publicPem = Buffer.from(pair.publicKey.export({ type: 'spki', format: 'pem' }));

  try {
    await writeNewFile(privateTarget, privatePem, PRIVATE_KEY_MODE);
    try {
      await writeNewFile(publicTarget, publicPem, PUBLIC_KEY_MODE);
    } catch (error) {
      await unlink(privateTarget).catch(() => {});
      throw error;
    }
  } finally {
    privatePem.fill(0);
  }

  return {
    ...describePublicKey(pair.publicKey),
    privatePath: privateTarget,
    publicPath: publicTarget,
  };
}

export async function loadPrivateKey(filePath: string): Promise<PrivateKeyInfo> {
  const entry = await lstat(filePath);
  if (entry.isSymbolicLink() || !entry.isFile())
    throw new Error('Private key must be a regular, non-symlink file');
  
  if (process.platform !== 'win32' && (entry.mode & GROUP_OTHER_PERMS) !== 0)
    throw new Error('Private key permissions must deny group and other access (chmod 600)');
  
  const pem = await readRegularFile(filePath, 'Private key', MAX_KEY_FILE_BYTES);
  let privateKey: KeyObject;

  try {
    try {
      privateKey = createPrivateKey({ key: pem, format: 'pem', type: 'pkcs8' });
    } catch {
      throw new Error('Private key is not a valid PKCS#8 key');
    }

    if (privateKey.asymmetricKeyType !== 'ed25519')
      throw new Error('Private key is not Ed25519');

    return {
      ...describePublicKey(createPublicKey(privateKey)),
      privateKey,
    };
  } finally {
    pem.fill(0);
  }
}

export async function loadPublicKey(filePath: string): Promise<PublicKeyInfo> {
  const pem = await readRegularFile(filePath, 'Public key', MAX_KEY_FILE_BYTES);
  let publicKey: KeyObject;

  try {
    publicKey = createPublicKey({ key: pem, format: 'pem', type: 'spki' });
  } catch {
    throw new Error('Public key is not a valid SPKI PEM key');
  }

  return describePublicKey(publicKey);
}
