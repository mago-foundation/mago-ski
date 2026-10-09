// DSSE (Dead Simple Signing Envelope) v1 with exactly one Ed25519 signature.
// https://github.com/secure-systems-lab/dsse/blob/master/protocol.md
import { sign, verify, type KeyObject } from 'node:crypto';
import { canonicalBytes, exactKeys, parseCanonicalJsonBytes, requireArray, requireString } from './canonical-json.ts';
import { validateKeyId } from './keys.ts';

export interface Envelope {
  payloadType: string;
  payload: string;
  signatures: [{ keyid: string; sig: string }];
}

const BASE64_PATTERN = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u;

/** Pre-Authentication Encoding: "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body, lengths in bytes. */
export function preAuthEncoding(payloadType: string, payload: Uint8Array): Buffer {
  const type = Buffer.from(payloadType, 'utf8');
  return Buffer.concat([
    Buffer.from(`DSSEv1 ${type.length} `, 'ascii'), type,
    Buffer.from(` ${payload.length} `, 'ascii'), Buffer.from(payload),
  ]);
}

export function signEnvelope(payloadType: string, payload: Uint8Array, keyId: string, privateKey: KeyObject): Envelope {
  const sig = sign(null, preAuthEncoding(payloadType, payload), privateKey).toString('base64');
  return { payloadType, payload: Buffer.from(payload).toString('base64'), signatures: [{ keyid: keyId, sig }] };
}

export function envelopeBytes(envelope: Envelope): Buffer {
  return canonicalBytes(envelope);
}

function decodeBase64(value: unknown, label: string, maxLength: number): Buffer {
  if (typeof value !== 'string' || value.length === 0 || value.length > maxLength || !BASE64_PATTERN.test(value)) {
    throw new Error(`${label} must be canonical base64`);
  }
  const bytes = Buffer.from(value, 'base64');
  if (bytes.toString('base64') !== value) throw new Error(`${label} must be canonical base64`);
  return bytes;
}

/** Parses an envelope file. Does not check the signature. */
export function parseEnvelope(bytes: Uint8Array, label: string): Envelope & { payloadBytes: Buffer; sigBytes: Buffer } {
  const value = exactKeys(parseCanonicalJsonBytes(bytes, label), ['payloadType', 'payload', 'signatures'], label);
  const payloadType = requireString(value.payloadType, `${label} payloadType`, 256);
  const payloadBytes = decodeBase64(value.payload, `${label} payload`, 6 * 1024 * 1024);
  const signatures = requireArray(value.signatures, `${label} signatures`, 1);
  if (signatures.length !== 1) throw new Error(`${label} must carry exactly one signature`);
  const signature = exactKeys(signatures[0], ['keyid', 'sig'], `${label} signature`);
  const keyid = validateKeyId(signature.keyid, `${label} signature keyid`);
  const sigBytes = decodeBase64(signature.sig, `${label} signature`, 128);
  if (sigBytes.length !== 64) throw new Error(`${label} signature must be a 64-byte Ed25519 signature`);
  return {
    payloadType, payload: value.payload as string, signatures: [{ keyid, sig: signature.sig as string }], payloadBytes, sigBytes,
  };
}

export function verifyEnvelopeSignature(envelope: { payloadType: string; payloadBytes: Buffer; sigBytes: Buffer }, publicKey: KeyObject): boolean {
  try {
    return verify(null, preAuthEncoding(envelope.payloadType, envelope.payloadBytes), publicKey, envelope.sigBytes);
  } catch {
    return false;
  }
}
