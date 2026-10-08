import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import { chmod, lstat, open, realpath, unlink } from 'node:fs/promises';
import path from 'node:path';
import {
  parseCanonicalJsonBytes,
  SIGNATURE_VERSION,
} from './manifest.mjs';
import { readRegularFile, resolveExternalFile } from './tree-digest.mjs';
import { trustedEd25519Key } from './trust.mjs';

const KEY_ID_PATTERN = /^sha256:[0-9a-f]{64}$/u;
const BASE64_PATTERN = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u;

function keyIdentifier(publicKeyDer) {
  return `sha256:${createHash('sha256').update(publicKeyDer).digest('hex')}`;
}

async function outputPath(filePath, label) {
  const target = path.resolve(filePath);
  const parent = await lstat(path.dirname(target));
  if (!parent.isDirectory()) throw new Error(`${label} parent must be a real directory`);
  const parentReal = await realpath(path.dirname(target));
  const canonical = path.join(parentReal, path.basename(target));
  try {
    await lstat(canonical);
    throw new Error(`${label} already exists; refusing to overwrite`);
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
  }
  return canonical;
}

async function writeExclusive(filePath, bytes, mode) {
  let handle;
  try {
    handle = await open(filePath, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL, mode);
    await handle.writeFile(bytes);
    await handle.sync();
  } catch (error) {
    await handle?.close();
    if (handle) await unlink(filePath).catch(() => {});
    throw error;
  }
  await handle.close();
  if (process.platform !== 'win32') await chmod(filePath, mode);
}

export async function generateEd25519KeyPair(privatePath, publicPath) {
  const privateFile = await outputPath(privatePath, 'Private-key path');
  const publicFile = await outputPath(publicPath, 'Public-key path');
  if (privateFile === publicFile) throw new Error('Private and public key paths must differ');

  const pair = generateKeyPairSync('ed25519');
  const privatePem = pair.privateKey.export({ type: 'pkcs8', format: 'pem' });
  const publicDer = pair.publicKey.export({ type: 'spki', format: 'der' });
  const publicPem = pair.publicKey.export({ type: 'spki', format: 'pem' });
  await writeExclusive(privateFile, privatePem, 0o600);
  try {
    await writeExclusive(publicFile, publicPem, 0o644);
  } catch (error) {
    await unlink(privateFile).catch(() => {});
    throw error;
  }
  return {
    privateKeyPath: privateFile,
    publicKeyPath: publicFile,
    keyId: keyIdentifier(publicDer),
    publicKey: publicDer.toString('base64'),
  };
}

export async function signEd25519Payload(payload, privateKeyPath, skillRoot) {
  const canonicalPrivatePath = await resolveExternalFile(privateKeyPath, skillRoot, 'Private key');
  const keyStat = await lstat(canonicalPrivatePath);
  if (process.platform !== 'win32' && (keyStat.mode & 0o077) !== 0) {
    throw new Error('Private key permissions must deny group and other access (mode 0600)');
  }
  const privatePem = await readRegularFile(canonicalPrivatePath, 'Private key', 64 * 1024);
  let privateKey;
  try {
    privateKey = createPrivateKey(privatePem);
  } catch {
    throw new Error('Private key is not a valid Ed25519 PKCS#8 key');
  }
  if (privateKey.asymmetricKeyType !== 'ed25519') throw new Error('Private key is not Ed25519');
  const publicKeyDer = createPublicKey(privateKey).export({ type: 'spki', format: 'der' });
  const keyId = keyIdentifier(publicKeyDer);
  const signature = sign(null, payload, privateKey);
  return {
    signature_version: SIGNATURE_VERSION,
    profile: 'ed25519',
    key_id: keyId,
    signature: signature.toString('base64'),
  };
}

export function parseEd25519SignatureBytes(bytes, label = 'Ed25519 signature') {
  const value = parseCanonicalJsonBytes(bytes, label);
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be a JSON object`);
  }
  const keys = Object.keys(value).sort();
  const expected = ['key_id', 'profile', 'signature', 'signature_version'].sort();
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) {
    throw new Error(`${label} has missing or unsupported fields`);
  }
  if (value.signature_version !== SIGNATURE_VERSION || value.profile !== 'ed25519') {
    throw new Error(`${label} has an unsupported signature profile`);
  }
  if (typeof value.key_id !== 'string' || !KEY_ID_PATTERN.test(value.key_id)) {
    throw new Error(`${label} has an invalid key_id`);
  }
  if (typeof value.signature !== 'string' || !BASE64_PATTERN.test(value.signature)) {
    throw new Error(`${label} has an invalid base64 signature`);
  }
  const signature = Buffer.from(value.signature, 'base64');
  if (signature.length !== 64 || signature.toString('base64') !== value.signature) {
    throw new Error(`${label} has an invalid Ed25519 signature length or encoding`);
  }
  return { keyId: value.key_id, signature };
}

export async function verifyEd25519Payload(payload, signaturePath, trust) {
  const bytes = await readRegularFile(signaturePath, 'Ed25519 signature');
  const signature = parseEd25519SignatureBytes(bytes);
  const trusted = trustedEd25519Key(trust, signature.keyId);
  if (!trusted) return { valid: false, reason: 'untrusted-signer', keyId: signature.keyId };
  return {
    valid: verify(null, payload, trusted.publicKey, signature.signature),
    reason: 'invalid-signature',
    keyId: signature.keyId,
  };
}
