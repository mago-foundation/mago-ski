import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync } from 'node:crypto';
import test from 'node:test';
import {
  createManifest,
  parseCanonicalJsonBytes,
  parseManifestBytes,
  serializeCanonicalJson,
} from '../src/manifest.mjs';
import {
  APPROVAL_VERSION,
  TRUST_VERSION,
  hasExactApproval,
  parseApprovalConfigBytes,
  parseTrustConfigBytes,
} from '../src/trust.mjs';

function keyEntry() {
  const { publicKey } = generateKeyPairSync('ed25519');
  const der = publicKey.export({ type: 'spki', format: 'der' });
  return {
    key_id: `sha256:${createHash('sha256').update(der).digest('hex')}`,
    public_key: der.toString('base64'),
  };
}

test('canonical JSON sorts object keys and requires one trailing LF', () => {
  assert.equal(serializeCanonicalJson({ z: 'last', a: 'first' }), '{"a":"first","z":"last"}\n');
  assert.deepEqual(parseCanonicalJsonBytes(Buffer.from('{"a":"first","z":"last"}\n')), { a: 'first', z: 'last' });
});

test('canonical parser rejects duplicate keys, order/whitespace and alternate encodings', () => {
  for (const input of [
    '{"a":1,"a":1}\n',
    '{"b":2,"a":1}\n',
    '{ "a":1}\n',
    '{"a":"\\u0061"}\n',
    '{"a":1.0}\n',
    '{"a":1}',
    '\ufeff{"a":1}\n',
  ]) {
    assert.throws(() => parseCanonicalJsonBytes(Buffer.from(input)), /canonical|trailing LF/u);
  }
});

test('manifest parser accepts only the exact versioned schema and digest profile', () => {
  const manifest = createManifest('sample-skill', {
    digest: `sha256:${'a'.repeat(64)}`,
    profile: 'mago.skill-tree/v1',
  });
  assert.deepEqual(parseManifestBytes(Buffer.from(serializeCanonicalJson(manifest))), manifest);
  assert.throws(() => parseManifestBytes(Buffer.from(serializeCanonicalJson({ ...manifest, author: 'untrusted' }))), /unsupported fields/u);
  assert.throws(() => parseManifestBytes(Buffer.from(serializeCanonicalJson({ ...manifest, tree_profile: 'other/v1' }))), /unsupported tree_profile/u);
  assert.throws(() => createManifest('../skill', { digest: manifest.tree_digest, profile: manifest.tree_profile }), /skill name/u);
});

test('trust parsing validates Ed25519 key identity and explicit Sigstore issuer pairs', () => {
  const key = keyEntry();
  const trust = {
    trust_version: TRUST_VERSION,
    ed25519: [key],
    sigstore: [{
      certificate_identity: 'keyless@projectsigstore.iam.gserviceaccount.com',
      certificate_oidc_issuer: 'https://accounts.google.com',
      trusted_root: 'trusted-root.json',
    }],
  };
  const parsed = parseTrustConfigBytes(Buffer.from(serializeCanonicalJson(trust)));
  assert.equal(parsed.ed25519[0].keyId, key.key_id);
  assert.equal(parsed.sigstore[0].certificate_oidc_issuer, 'https://accounts.google.com');

  const wrongId = { ...key, key_id: `sha256:${'0'.repeat(64)}` };
  assert.throws(() => parseTrustConfigBytes(Buffer.from(serializeCanonicalJson({ ...trust, ed25519: [wrongId] }))), /does not match public_key/u);
  assert.throws(() => parseTrustConfigBytes(Buffer.from(serializeCanonicalJson({
    ...trust,
    sigstore: [{ ...trust.sigstore[0], certificate_oidc_issuer: 'http://accounts.google.com' }],
  }))), /HTTPS/u);
  assert.throws(() => parseTrustConfigBytes(Buffer.from(serializeCanonicalJson({
    ...trust,
    sigstore: [{ ...trust.sigstore[0], trusted_root: '../trusted-root.json' }],
  }))), /beside the trust configuration/u);
});

test('approvals bind an exact skill name and digest', () => {
  const digest = `sha256:${'b'.repeat(64)}`;
  const approval = parseApprovalConfigBytes(Buffer.from(serializeCanonicalJson({
    approval_version: APPROVAL_VERSION,
    approvals: [{ skill_name: 'sample-skill', digest }],
  })));
  assert.equal(hasExactApproval(approval, 'sample-skill', digest), true);
  assert.equal(hasExactApproval(approval, 'sample-skill', `sha256:${'c'.repeat(64)}`), false);
  assert.equal(hasExactApproval(approval, 'other-skill', digest), false);
  assert.throws(() => parseApprovalConfigBytes(Buffer.from(serializeCanonicalJson({
    approval_version: APPROVAL_VERSION,
    approvals: [
      { skill_name: 'sample-skill', digest },
      { skill_name: 'sample-skill', digest },
    ],
  }))), /unique and sorted/u);
});
