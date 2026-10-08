// Sigstore/Cosign adapter, kept from the skill-pki preview. Not on the Phase 1 critical path:
// the certificate verifier does not use it. It verifies blobs with a checksum-pinned Cosign binary.
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import { endianness } from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';

export const COSIGN_PINNED_VERSION = 'v3.1.3';
// Pins come from the release checksum file, whose authentic public Sigstore bundle is tested offline.
export const COSIGN_BINARY_SHA256: Readonly<Record<string, string>> = Object.freeze({
  'darwin-arm64': '5cf948c2f4dfe59687bdd0b8523709067383e03982cc543475c8a7dc70e92a76',
  'darwin-x64': '2347488e5d5b25336644024dfeca5601b190e91197a71a917bda44744aff106c',
  'linux-arm': '3275e61b43a45aa56a6242b49475d8a01874a07469c08fc32d027ba554996e4c',
  'linux-arm64': 'c5d324e091826b0d7a78eb16fef316450b4eb9aaec045611c08ba06f5e73220a',
  'linux-ppc64le': '15619e924681c97e0fb4f79c0eb8ef5d29665a06fe6a25078500985aed79321b',
  'linux-riscv64': '9736177c6be33e4493304fc34feb8aa29209d531b3d40142d7e2a40bbe2f542f',
  'linux-s390x': '253b571ef9e1aef72ef56d74f464ef9fe5182dc83b1ab430bbffbc4c8e43e7fd',
  'linux-x64': '4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71',
  'win32-x64': '9fe59be0eca1271873ce019061335eb1ac419b7059202e797828467ddabe33be',
});

const execFileAsync = promisify(execFile);
const noFollow = fsConstants.O_NOFOLLOW ?? 0;
const MAX_BINARY_BYTES = 256n * 1024n * 1024n;

export class CosignVerificationError extends Error {
  readonly exitCode = 1;
  constructor(message = 'Cosign verification failed') {
    super(message);
    this.name = 'CosignVerificationError';
  }
}

function platformKey(platform: string = process.platform, arch: string = process.arch): string {
  if (platform === 'linux' && arch === 'ppc64' && endianness() === 'LE') return 'linux-ppc64le';
  return `${platform}-${arch}`;
}

async function hashFile(filePath: string): Promise<string> {
  const handle = await open(filePath, fsConstants.O_RDONLY | noFollow);
  try {
    const initial = await handle.stat({ bigint: true });
    if (!initial.isFile()) throw new Error('Cosign binary must be a regular file');
    if (initial.size > MAX_BINARY_BYTES) throw new Error('Cosign binary exceeds the supported size limit');
    const hash = createHash('sha256');
    const buffer = Buffer.allocUnsafe(1024 * 1024);
    let total = 0n;
    while (true) {
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, null);
      if (bytesRead === 0) break;
      total += BigInt(bytesRead);
      if (total > MAX_BINARY_BYTES) throw new Error('Cosign binary exceeds the supported size limit');
      hash.update(buffer.subarray(0, bytesRead));
    }
    const final = await handle.stat({ bigint: true });
    if (total !== initial.size || initial.dev !== final.dev || initial.ino !== final.ino ||
      initial.size !== final.size || initial.mtimeNs !== final.mtimeNs || initial.ctimeNs !== final.ctimeNs) {
      throw new Error('Cosign binary changed while being checked');
    }
    return hash.digest('hex');
  } finally {
    await handle.close();
  }
}

async function runProcess(binaryPath: string, args: string[], timeout: number): Promise<{ stdout: string; stderr: string }> {
  try {
    const { stdout, stderr } = await execFileAsync(binaryPath, args, {
      timeout, maxBuffer: 1024 * 1024, windowsHide: true, encoding: 'utf8', shell: false, env: process.env,
    });
    return { stdout, stderr };
  } catch (error) {
    const code = (error as { code?: unknown })?.code;
    throw new CosignVerificationError(`Pinned Cosign process failed (exit ${typeof code === 'number' ? code : 'unavailable'})`);
  }
}

export async function assertPinnedCosignBinary(binaryPath: string): Promise<string> {
  const platform = platformKey();
  const expected = COSIGN_BINARY_SHA256[platform];
  if (!expected) throw new Error(`Cosign ${COSIGN_PINNED_VERSION} has no pinned official checksum for ${platform}`);
  const requested = await lstat(binaryPath);
  if (requested.isSymbolicLink() || !requested.isFile()) throw new Error('Cosign binary must be a regular, non-symlink file');
  if (process.platform !== 'win32' && (requested.mode & 0o111) === 0) throw new Error('Cosign binary is not executable');
  const canonical = await realpath(binaryPath);
  if (await hashFile(canonical) !== expected) throw new Error(`Cosign binary checksum does not match the official ${COSIGN_PINNED_VERSION} pin`);
  const version = await runProcess(canonical, ['version'], 15_000);
  if (!/^GitVersion:\s+v3\.1\.3\s*$/mu.test(`${version.stdout}\n${version.stderr}`)) {
    throw new Error(`Cosign binary is not the pinned ${COSIGN_PINNED_VERSION} version`);
  }
  if (await hashFile(canonical) !== expected) throw new Error('Cosign binary changed during version validation');
  return canonical;
}

async function requireRegularFile(filePath: string, label: string): Promise<string> {
  const stats = await lstat(filePath);
  if (stats.isSymbolicLink() || !stats.isFile()) throw new Error(`${label} must be a regular, non-symlink file`);
  return await realpath(filePath);
}

export function buildCosignSignArgs(bundlePath: string, payloadPath: string): string[] {
  return ['sign-blob', '--yes', '--bundle', bundlePath, payloadPath];
}

export function buildCosignVerifyArgs(bundlePath: string, trustedRootPath: string, identity: string, issuer: string, payloadPath: string): string[] {
  return [
    'verify-blob', '--bundle', bundlePath, '--trusted-root', trustedRootPath,
    '--certificate-identity', identity, '--certificate-oidc-issuer', issuer, payloadPath,
  ];
}

async function runCosign(binaryPath: string, args: string[], timeout: number): Promise<void> {
  const canonical = await assertPinnedCosignBinary(binaryPath);
  await runProcess(canonical, args, timeout);
  if (await hashFile(canonical) !== COSIGN_BINARY_SHA256[platformKey()]) {
    throw new CosignVerificationError('Pinned Cosign binary changed during the operation');
  }
}

async function newOutputPath(filePath: string): Promise<string> {
  const target = path.resolve(filePath);
  const output = path.join(await realpath(path.dirname(target)), path.basename(target));
  try {
    await lstat(output);
    throw new Error('Sigstore bundle output already exists; refusing to overwrite');
  } catch (error) {
    if ((error as NodeJS.ErrnoException)?.code !== 'ENOENT') throw error;
  }
  return output;
}

export async function signSigstoreBlob(options: { binaryPath: string; payloadPath: string; bundlePath: string }): Promise<{ bundlePath: string }> {
  const payload = await requireRegularFile(options.payloadPath, 'Sigstore payload');
  const bundle = await newOutputPath(options.bundlePath);
  await runCosign(options.binaryPath, buildCosignSignArgs(bundle, payload), 120_000);
  return { bundlePath: bundle };
}

export async function verifySigstoreBlob(options: {
  binaryPath: string;
  payloadPath: string;
  bundlePath: string;
  trustedRootPath: string;
  certificateIdentity: string;
  certificateOidcIssuer: string;
}): Promise<{ valid: true }> {
  const payload = await requireRegularFile(options.payloadPath, 'Sigstore payload');
  const bundle = await requireRegularFile(options.bundlePath, 'Sigstore bundle');
  const trustedRoot = await requireRegularFile(options.trustedRootPath, 'Sigstore trusted root');
  if (!options.certificateIdentity) throw new Error('A configured Sigstore certificate identity is required');
  if (!options.certificateOidcIssuer) throw new Error('A configured Sigstore OIDC issuer is required');
  await runCosign(options.binaryPath, buildCosignVerifyArgs(bundle, trustedRoot, options.certificateIdentity, options.certificateOidcIssuer, payload), 60_000);
  return { valid: true };
}
