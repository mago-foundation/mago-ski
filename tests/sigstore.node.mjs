import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile, copyFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import {
  assertPinnedCosignBinary,
  buildCosignSignArgs,
  buildCosignVerifyArgs,
  COSIGN_BINARY_SHA256,
  COSIGN_PINNED_VERSION,
  CosignVerificationError,
  verifySigstoreBlob,
} from '../src/sigstore.mjs';
import { serializeCanonicalJson } from '../src/manifest.mjs';
import { TRUST_VERSION, loadTrustConfig, trustedSigstoreIdentity } from '../src/trust.mjs';

const fixtureDirectory = fileURLToPath(new URL('./fixtures/', import.meta.url));
const checksumFixture = path.join(fixtureDirectory, 'cosign_checksums.txt');
const bundleFixture = path.join(fixtureDirectory, 'cosign_checksums.txt.sigstore.json');
const trustedRootFixture = path.join(fixtureDirectory, 'cosign-trusted-root.json');
const fixtureIdentity = 'keyless@projectsigstore.iam.gserviceaccount.com';
const fixtureIssuer = 'https://accounts.google.com';

async function temporaryDirectory(t) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'mago-ski-sigstore-'));
  t.after(async () => await rm(directory, { recursive: true, force: true }));
  return directory;
}

test('Cosign adapter builds official v3.1.3 blob arguments and does not use deprecated offline flags', () => {
  assert.equal(COSIGN_PINNED_VERSION, 'v3.1.3');
  assert.deepEqual(buildCosignSignArgs('/tmp/out.bundle', '/tmp/payload'), [
    'sign-blob', '--yes', '--bundle', '/tmp/out.bundle', '/tmp/payload',
  ]);
  assert.deepEqual(buildCosignVerifyArgs('/tmp/bundle', '/tmp/root.json', 'id', 'https://issuer', '/tmp/payload'), [
    'verify-blob',
    '--bundle', '/tmp/bundle',
    '--trusted-root', '/tmp/root.json',
    '--certificate-identity', 'id',
    '--certificate-oidc-issuer', 'https://issuer',
    '/tmp/payload',
  ]);
  assert.equal(buildCosignVerifyArgs('b', 'r', 'i', 'u', 'p').includes('--offline'), false);
});

test('pinned Cosign checksums match the signed public release checksum fixture', async () => {
  const checksumText = await readFile(checksumFixture, 'utf8');
  const filenameByPlatform = {
    'darwin-arm64': 'cosign-darwin-arm64',
    'darwin-x64': 'cosign-darwin-amd64',
    'linux-arm': 'cosign-linux-arm',
    'linux-arm64': 'cosign-linux-arm64',
    'linux-ppc64le': 'cosign-linux-ppc64le',
    'linux-riscv64': 'cosign-linux-riscv64',
    'linux-s390x': 'cosign-linux-s390x',
    'linux-x64': 'cosign-linux-amd64',
    'win32-x64': 'cosign-windows-amd64.exe',
  };
  const lines = new Set(checksumText.split(/\r?\n/u));
  for (const [platform, digest] of Object.entries(COSIGN_BINARY_SHA256)) {
    assert.ok(lines.has(`${digest}  ${filenameByPlatform[platform]}`), `checksum pin must match ${platform}`);
  }
  const checksumDigest = createHash('sha256').update(checksumText).digest('hex');
  assert.equal(checksumDigest, 'aec2a6f68d307b09ae196e388dc691a146fa8bdba7fcce9ca4ca41b918adfa63');
});

test('public Sigstore bundle and trusted-root fixture hashes are pinned', async () => {
  const bundleHash = createHash('sha256').update(await readFile(bundleFixture)).digest('hex');
  const rootHash = createHash('sha256').update(await readFile(trustedRootFixture)).digest('hex');
  assert.equal(bundleHash, '976bcb216e45ed0274e464e2e16d81e84cc85a69b3ed6e3488c1e7cda116379a');
  assert.equal(rootHash, '6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66');
});

test('pinned official Cosign binary rejects an unpinned executable', async (t) => {
  const directory = await temporaryDirectory(t);
  const fakeBinary = path.join(directory, 'cosign');
  await writeFile(fakeBinary, '#!/bin/sh\necho GitVersion: v3.1.3\n', { mode: 0o755 });
  await assert.rejects(assertPinnedCosignBinary(fakeBinary), /checksum does not match/u);
});

test('authentic public keyless Cosign release fixture verifies with the pinned adapter', {
  skip: process.env.MAGO_COSIGN_BIN ? false : 'set MAGO_COSIGN_BIN to the official Cosign v3.1.3 binary',
}, async (t) => {
  const binaryPath = process.env.MAGO_COSIGN_BIN;
  await assertPinnedCosignBinary(binaryPath);
  const directory = await temporaryDirectory(t);
  const rootPath = path.join(directory, 'trusted-root.json');
  const trustPath = path.join(directory, 'trust.json');
  await copyFile(trustedRootFixture, rootPath);
  await writeFile(trustPath, serializeCanonicalJson({
    trust_version: TRUST_VERSION,
    ed25519: [],
    sigstore: [{
      certificate_identity: fixtureIdentity,
      certificate_oidc_issuer: fixtureIssuer,
      trusted_root: 'trusted-root.json',
    }],
  }));
  const trust = await loadTrustConfig(trustPath);
  const signer = trustedSigstoreIdentity(trust, fixtureIdentity, fixtureIssuer);
  assert.ok(signer, 'the fixture identity and issuer must be explicitly configured as trusted');
  await verifySigstoreBlob({
    binaryPath,
    payloadPath: checksumFixture,
    bundlePath: bundleFixture,
    trustedRootPath: signer.trustedRootPath,
    certificateIdentity: signer.certificate_identity,
    certificateOidcIssuer: signer.certificate_oidc_issuer,
  });
  await assert.rejects(verifySigstoreBlob({
    binaryPath,
    payloadPath: checksumFixture,
    bundlePath: bundleFixture,
    trustedRootPath: signer.trustedRootPath,
    certificateIdentity: 'attacker@example.invalid',
    certificateOidcIssuer: signer.certificate_oidc_issuer,
  }), (error) => error instanceof CosignVerificationError && error.exitCode === 1);
});
