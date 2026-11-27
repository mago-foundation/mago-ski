import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import test from 'node:test';
import { canonicalBytes, parseCanonicalJsonBytes } from '../src/canonical-json.ts';
import { envelopeBytes, parseEnvelope, preAuthEncoding, signEnvelope, verifyEnvelopeSignature } from '../src/dsse.ts';
import { keyIdFromSpkiDer } from '../src/keys.ts';

test('PAE matches the DSSE specification example', () => {
  assert.equal(
    preAuthEncoding('http://example.com/HelloWorld', Buffer.from('hello world')).toString(),
    'DSSEv1 29 http://example.com/HelloWorld 11 hello world',
  );
});

test('envelopes round-trip and reject a changed payload type or payload', () => {
  const pair = generateKeyPairSync('ed25519');
  const keyId = keyIdFromSpkiDer(pair.publicKey.export({ format: 'der', type: 'spki' }));
  const payload = canonicalBytes({ hello: 'world' });
  const parsed = parseEnvelope(envelopeBytes(signEnvelope('application/test', payload, keyId, pair.privateKey)), 'test');
  assert.equal(verifyEnvelopeSignature(parsed, pair.publicKey), true);
  assert.equal(verifyEnvelopeSignature({ ...parsed, payloadType: 'application/other' }, pair.publicKey), false);
  assert.equal(verifyEnvelopeSignature({ ...parsed, payloadBytes: canonicalBytes({ hello: 'there' }) }, pair.publicKey), false);
});

test('canonical JSON rejects duplicate keys, reordering and floats', () => {
  assert.throws(() => parseCanonicalJsonBytes(Buffer.from('{"a":1,"a":2}\n')), /not canonical/u);
  assert.throws(() => parseCanonicalJsonBytes(Buffer.from('{"b":1,"a":2}\n')), /not canonical/u);
  assert.throws(() => parseCanonicalJsonBytes(Buffer.from('{"a":1.5}\n')), /safe integers/u);
  assert.throws(() => parseCanonicalJsonBytes(Buffer.from('{"a":1}')), /trailing LF/u);
  assert.deepEqual(parseCanonicalJsonBytes(Buffer.from('{"a":1,"b":[true,null]}\n')), { a: 1, b: [true, null] });
});

test('an envelope too large to be read back is refused when it is made, not after it is written', () => {
  const pair = generateKeyPairSync('ed25519');
  const keyId = keyIdFromSpkiDer(pair.publicKey.export({ format: 'der', type: 'spki' }));
  const fits = signEnvelope('application/test', Buffer.alloc(3 * 1024 * 1024 - 1024, 0x61), keyId, pair.privateKey);
  assert.equal(parseEnvelope(envelopeBytes(fits), 'test').payloadBytes.length, 3 * 1024 * 1024 - 1024);
  const tooLarge = signEnvelope('application/test', Buffer.alloc(3 * 1024 * 1024 + 4096, 0x61), keyId, pair.privateKey); // over 4 MiB as base64
  assert.throws(() => envelopeBytes(tooLarge), /the limit for a document is 4194304 bytes\. Nothing was written/u);
});
