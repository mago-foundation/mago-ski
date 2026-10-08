import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, type KeyObject } from 'node:crypto';
import { lstat } from 'node:fs/promises';
import path from 'node:path';
import { readRegularFile, writeNewFile } from './fs-safe.ts';

export const KEY_ID_PATTERN = /^sha256:[0-9a-f]{64}$/u;
const BASE64_PATTERN = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u;

export interface PublicKeyInfo {
  keyId: string;
  publicKey: KeyObject;
  /** Canonical base64 of the DER SubjectPublicKeyInfo. */
  spki: string;
}

export interface PrivateKeyInfo extends PublicKeyInfo {
  privateKey: KeyObject;
}

export function keyIdFromSpkiDer(der: Uint8Array): string {
  return `sha256:${createHash('sha256').update(der).digest('hex')}`;
}

function describe(publicKey: KeyObject): PublicKeyInfo {
  if (publicKey.asymmetricKeyType !== 'ed25519') throw new Error('Key is not Ed25519');
  const der = publicKey.export({ format: 'der', type: 'spki' });
  return { keyId: keyIdFromSpkiDer(der), publicKey, spki: der.toString('base64') };
}

export function validateKeyId(value: unknown, label: string): string {
  if (typeof value !== 'string' || !KEY_ID_PATTERN.test(value)) throw new Error(`${label} must be a sha256:<64 hex> key identifier`);
  return value;
}

/** Parses a canonical base64 Ed25519 SPKI and, if given, checks it hashes to `expectedKeyId`. */
export function parseSpki(spki: unknown, label: string, expectedKeyId?: string): PublicKeyInfo {
  if (typeof spki !== 'string' || spki.length === 0 || spki.length > 256 || !BASE64_PATTERN.test(spki)) {
    throw new Error(`${label} must be canonical base64 SubjectPublicKeyInfo`);
  }
  const der = Buffer.from(spki, 'base64');
  if (der.toString('base64') !== spki) throw new Error(`${label} must be canonical base64 SubjectPublicKeyInfo`);
  let publicKey: KeyObject;
  try {
    publicKey = createPublicKey({ key: der, format: 'der', type: 'spki' });
  } catch {
    throw new Error(`${label} is not a valid public key`);
  }
  const info = describe(publicKey);
  if (info.spki !== spki) throw new Error(`${label} is not in canonical DER form`);
  if (expectedKeyId !== undefined && info.keyId !== expectedKeyId) throw new Error(`${label} does not match key id ${expectedKeyId}`);
  return info;
}

export async function generateKeyPair(privatePath: string, publicPath: string): Promise<PublicKeyInfo & { privatePath: string; publicPath: string }> {
  const privateTarget = path.resolve(privatePath);
  const publicTarget = path.resolve(publicPath);
  if (privateTarget === publicTarget) throw new Error('Private and public key paths must differ');
  const pair = generateKeyPairSync('ed25519');
  const privatePem = pair.privateKey.export({ type: 'pkcs8', format: 'pem' });
  const publicPem = pair.publicKey.export({ type: 'spki', format: 'pem' });
  await writeNewFile(privateTarget, Buffer.from(privatePem), 0o600);
  try {
    await writeNewFile(publicTarget, Buffer.from(publicPem), 0o644);
  } catch (error) {
    const { unlink } = await import('node:fs/promises');
    await unlink(privateTarget).catch(() => {});
    throw error;
  }
  return { ...describe(pair.publicKey), privatePath: privateTarget, publicPath: publicTarget };
}

export async function loadPrivateKey(filePath: string): Promise<PrivateKeyInfo> {
  const entry = await lstat(filePath);
  if (process.platform !== 'win32' && (entry.mode & 0o077) !== 0) {
    throw new Error('Private key permissions must deny group and other access (chmod 600)');
  }
  const pem = await readRegularFile(filePath, 'Private key', 64 * 1024);
  let privateKey: KeyObject;
  try {
    privateKey = createPrivateKey(pem);
  } catch {
    throw new Error('Private key is not a valid PKCS#8 key');
  }
  if (privateKey.asymmetricKeyType !== 'ed25519') throw new Error('Private key is not Ed25519');
  return { ...describe(createPublicKey(privateKey)), privateKey };
}

export async function loadPublicKey(filePath: string): Promise<PublicKeyInfo> {
  const pem = await readRegularFile(filePath, 'Public key', 64 * 1024);
  let publicKey: KeyObject;
  try {
    publicKey = createPublicKey(pem);
  } catch {
    throw new Error('Public key is not a valid SPKI PEM key');
  }
  return describe(publicKey);
}
