import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  assertPinnedCosignBinary, buildCosignSignArgs, buildCosignVerifyArgs, COSIGN_BINARY_SHA256,
  COSIGN_PINNED_VERSION, CosignVerificationError, verifySigstoreBlob,
} from '../src/experimental/sigstore.ts';
import { tempDir } from './helpers.ts';

const fixtures = fileURLToPath(new URL('./fixtures/', import.meta.url));
const checksumFixture = path.join(fixtures, 'cosign_checksums.txt');
const bundleFixture = path.join(fixtures, 'cosign_checksums.txt.sigstore.json');
const trustedRootFixture = path.join(fixtures, 'cosign-trusted-root.json');

test('Cosign adapter builds v3.1.3 blob arguments without deprecated offline flags', () => {
  assert.equal(COSIGN_PINNED_VERSION, 'v3.1.3');
  assert.deepEqual(buildCosignSignArgs('/tmp/out.bundle', '/tmp/payload'), ['sign-blob', '--yes', '--bundle', '/tmp/out.bundle', '/tmp/payload']);
  assert.deepEqual(buildCosignVerifyArgs('/tmp/bundle', '/tmp/root.json', 'id', 'https://issuer', '/tmp/payload'), [
    'verify-blob', '--bundle', '/tmp/bundle', '--trusted-root', '/tmp/root.json',
    '--certificate-identity', 'id', '--certificate-oidc-issuer', 'https://issuer', '/tmp/payload',
  ]);
});

test('pinned Cosign checksums match the signed public release checksum fixture', async () => {
  const checksumText = await readFile(checksumFixture, 'utf8');
  const filenames: Record<string, string> = {
    'darwin-arm64': 'cosign-darwin-arm64', 'darwin-x64': 'cosign-darwin-amd64', 'linux-arm': 'cosign-linux-arm',
    'linux-arm64': 'cosign-linux-arm64', 'linux-ppc64le': 'cosign-linux-ppc64le', 'linux-riscv64': 'cosign-linux-riscv64',
    'linux-s390x': 'cosign-linux-s390x', 'linux-x64': 'cosign-linux-amd64', 'win32-x64': 'cosign-windows-amd64.exe',
  };
  const lines = new Set(checksumText.split(/\r?\n/u));
  for (const [platform, digest] of Object.entries(COSIGN_BINARY_SHA256)) {
    assert.ok(lines.has(`${digest}  ${filenames[platform]}`), `checksum pin must match ${platform}`);
  }
  assert.equal(createHash('sha256').update(checksumText).digest('hex'), 'aec2a6f68d307b09ae196e388dc691a146fa8bdba7fcce9ca4ca41b918adfa63');
});

test('public Sigstore bundle and trusted-root fixture hashes are pinned', async () => {
  assert.equal(createHash('sha256').update(await readFile(bundleFixture)).digest('hex'), '976bcb216e45ed0274e464e2e16d81e84cc85a69b3ed6e3488c1e7cda116379a');
  assert.equal(createHash('sha256').update(await readFile(trustedRootFixture)).digest('hex'), '6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66');
});

test('an unpinned executable is rejected', async (t) => {
  const fake = path.join(await tempDir(t), 'cosign');
  await writeFile(fake, '#!/bin/sh\necho GitVersion: v3.1.3\n', { mode: 0o755 });
  await assert.rejects(assertPinnedCosignBinary(fake), /checksum does not match/u);
});

test('authentic public keyless release fixture verifies with the pinned adapter', {
  skip: process.env.MAGO_COSIGN_BIN ? false : 'set MAGO_COSIGN_BIN to the official Cosign v3.1.3 binary',
}, async () => {
  const binaryPath = process.env.MAGO_COSIGN_BIN!;
  const options = {
    binaryPath, payloadPath: checksumFixture, bundlePath: bundleFixture, trustedRootPath: trustedRootFixture,
    certificateIdentity: 'keyless@projectsigstore.iam.gserviceaccount.com', certificateOidcIssuer: 'https://accounts.google.com',
  };
  await verifySigstoreBlob(options);
  await assert.rejects(verifySigstoreBlob({ ...options, certificateIdentity: 'attacker@example.invalid' }),
    (error) => error instanceof CosignVerificationError && error.exitCode === 1);
});
