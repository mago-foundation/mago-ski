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
