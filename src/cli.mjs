import { mkdtemp, open, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createManifest, createAttestationPayload, readManifest, writeNewCanonicalFile } from './manifest.mjs';
import { computeTreeDigest, resolveExternalFile } from './tree-digest.mjs';
import { generateEd25519KeyPair, signEd25519Payload, verifyEd25519Payload } from './ed25519.mjs';
import { signSigstoreBlob, verifySigstoreBlob, CosignVerificationError } from './sigstore.mjs';
import { compareSkillTrees } from './diff.mjs';
import { hasExactApproval, loadApprovalConfig, loadTrustConfig, trustedSigstoreIdentity } from './trust.mjs';

const usage = `Usage:
  mago-ski init --skill DIR --manifest FILE [--name NAME]
  mago-ski keygen --private-key FILE --public-key FILE
  mago-ski sign --skill DIR --manifest FILE --profile ed25519 --signature FILE --private-key FILE
  mago-ski sign --skill DIR --manifest FILE --profile sigstore --signature BUNDLE --cosign FILE
  mago-ski verify --skill DIR --manifest FILE --profile ed25519 --signature FILE --trust FILE --approvals FILE
  mago-ski verify --skill DIR --manifest FILE --profile sigstore --signature BUNDLE --trust FILE --approvals FILE --identity ID --issuer URL --cosign FILE
  mago-ski diff --base DIR --candidate DIR --base-manifest FILE --manifest FILE --approvals FILE

Exit codes: 0 success or exact approval; 1 invalid/untrusted/unapproved signature or changed content requiring approval; 2 usage, malformed input, filesystem or tool setup error.

Signatures establish integrity/provenance only. Verification requires an explicit trusted signer and an exact externally configured approval for the current digest. Keyless signing needs online Sigstore/OIDC services; Ed25519 verification is offline.`;

const valueFlags = new Set([
  '--skill', '--manifest', '--name', '--private-key', '--public-key', '--profile', '--signature',
  '--cosign', '--trust', '--approvals', '--identity', '--issuer', '--base', '--candidate', '--base-manifest',
]);

function parseFlags(args, allowed) {
  const options = new Map();
  for (let index = 0; index < args.length; index += 1) {
    const flag = args[index];
    if (!valueFlags.has(flag) || !allowed.has(flag)) throw new Error(`Unsupported argument: ${flag}`);
    if (options.has(flag)) throw new Error(`Argument may be provided only once: ${flag}`);
    const value = args[index + 1];
    if (value === undefined || value.startsWith('--') || value.length === 0) throw new Error(`Missing value for ${flag}`);
    options.set(flag, value);
    index += 1;
  }
  return options;
}

function required(options, flag) {
  const value = options.get(flag);
  if (!value) throw new Error(`Required argument is missing: ${flag}`);
  return value;
}

function assertAllowedProfile(profile) {
  if (profile !== 'ed25519' && profile !== 'sigstore') throw new Error('Profile must be ed25519 or sigstore');
  return profile;
}

async function sidecarOutsideRoots(filePath, roots, label) {
  let canonical = filePath;
  for (const root of roots) canonical = await resolveExternalFile(canonical, root, label);
  return canonical;
}

async function checkedManifest(skillRoot, manifestPath) {
  const manifestFile = await resolveExternalFile(manifestPath, skillRoot, 'Manifest');
  const manifest = await readManifest(manifestFile);
  const tree = await computeTreeDigest(skillRoot);
  if (manifest.tree_digest !== tree.digest || manifest.tree_profile !== tree.profile) {
    throw new Error('Manifest digest does not match the current Skill directory bytes');
  }
  return { manifestFile, manifest, tree };
}

async function createPayloadFile(payload) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'mago-ski-payload-'));
  const payloadPath = path.join(directory, 'attestation.json');
  let handle;
  try {
    handle = await open(payloadPath, 'wx', 0o600);
    await handle.writeFile(payload);
    await handle.sync();
    return { directory, payloadPath };
  } catch (error) {
    await rm(directory, { recursive: true, force: true });
    throw error;
  } finally {
    await handle?.close();
  }
}

async function runInit(options) {
  const skillRoot = required(options, '--skill');
  const tree = await computeTreeDigest(skillRoot);
  const name = options.get('--name') ?? path.basename(path.resolve(skillRoot));
  const manifest = createManifest(name, tree);
  const output = await resolveExternalFile(required(options, '--manifest'), skillRoot, 'Manifest output', { allowMissing: true });
  await writeNewCanonicalFile(output, manifest, 0o644, 'Manifest');
  process.stdout.write(`${JSON.stringify({ status: 'INITIALIZED', skill_name: name, tree_digest: tree.digest, tree_profile: tree.profile, manifest: output })}\n`);
}

async function runKeygen(options) {
  const pair = await generateEd25519KeyPair(required(options, '--private-key'), required(options, '--public-key'));
  process.stderr.write('Warning: keep private keys outside Skill roots.\n');
  process.stdout.write(`${JSON.stringify({
    status: 'KEY_CREATED',
    private_key: pair.privateKeyPath,
    public_key: pair.publicKeyPath,
    key_id: pair.keyId,
    public_key_spki_base64: pair.publicKey,
  })}\n`);
}

async function runSign(options) {
  const profile = assertAllowedProfile(required(options, '--profile'));
  const skillRoot = path.resolve(required(options, '--skill'));
  const { manifest, tree } = await checkedManifest(skillRoot, required(options, '--manifest'));
  const signaturePath = await resolveExternalFile(required(options, '--signature'), skillRoot, 'Signature output', { allowMissing: true });
  const payload = createAttestationPayload(manifest);
  if (profile === 'ed25519') {
    if (options.has('--cosign')) throw new Error('--cosign is only valid for the Sigstore profile');
    const signature = await signEd25519Payload(payload, required(options, '--private-key'), skillRoot);
    await writeNewCanonicalFile(signaturePath, signature, 0o644, 'Signature');
    process.stdout.write(`${JSON.stringify({ status: 'SIGNED', profile, skill_name: manifest.skill_name, tree_digest: tree.digest, key_id: signature.key_id, signature: signaturePath })}\n`);
    return;
  }

  if (options.has('--private-key')) throw new Error('--private-key is only valid for the Ed25519 profile');
  const { directory, payloadPath } = await createPayloadFile(payload);
  try {
    await signSigstoreBlob({
      binaryPath: required(options, '--cosign'),
      payloadPath,
      bundlePath: signaturePath,
    });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
  process.stdout.write(`${JSON.stringify({ status: 'SIGNED', profile, skill_name: manifest.skill_name, tree_digest: tree.digest, bundle: signaturePath })}\n`);
}

function outputRejected(status, profile, manifest, digest, extra = {}) {
  process.stdout.write(`${JSON.stringify({ status, profile, skill_name: manifest.skill_name, tree_digest: digest, ...extra })}\n`);
  process.exitCode = 1;
}

async function runVerify(options) {
  const profile = assertAllowedProfile(required(options, '--profile'));
  const skillRoot = path.resolve(required(options, '--skill'));
  const { manifest, tree } = await checkedManifest(skillRoot, required(options, '--manifest'));
  const signaturePath = await resolveExternalFile(required(options, '--signature'), skillRoot, 'Signature');
  const trustPath = await resolveExternalFile(required(options, '--trust'), skillRoot, 'Trust configuration');
  const approvalsPath = await resolveExternalFile(required(options, '--approvals'), skillRoot, 'Approval configuration');
  const [trust, approvals] = await Promise.all([
    loadTrustConfig(trustPath, { skillRoot }),
    loadApprovalConfig(approvalsPath),
  ]);
  const payload = createAttestationPayload(manifest);
  let signatureValid = false;
  let signer = {};

  if (profile === 'ed25519') {
    for (const flag of ['--cosign', '--identity', '--issuer', '--private-key']) {
      if (options.has(flag)) throw new Error(`${flag} is only valid for the Sigstore profile`);
    }
    const result = await verifyEd25519Payload(payload, signaturePath, trust);
    signatureValid = result.valid;
    signer = { key_id: result.keyId };
    if (!signatureValid) {
      outputRejected('REJECTED', profile, manifest, tree.digest, { reason: result.reason, signature_valid: false });
      return;
    }
  } else {
    if (options.has('--private-key')) throw new Error('--private-key is only valid for the Ed25519 profile');
    const identity = required(options, '--identity');
    const issuer = required(options, '--issuer');
    const trusted = trustedSigstoreIdentity(trust, identity, issuer);
    if (!trusted) {
      outputRejected('REJECTED', profile, manifest, tree.digest, { reason: 'untrusted-signer-or-issuer', signature_valid: false });
      return;
    }
    const { directory, payloadPath } = await createPayloadFile(payload);
    try {
      await verifySigstoreBlob({
        binaryPath: required(options, '--cosign'),
        payloadPath,
        bundlePath: signaturePath,
        trustedRootPath: trusted.trustedRootPath,
        certificateIdentity: trusted.certificate_identity,
        certificateOidcIssuer: trusted.certificate_oidc_issuer,
      });
      signatureValid = true;
      signer = { certificate_identity: identity, certificate_oidc_issuer: issuer };
    } catch (error) {
      if (!(error instanceof CosignVerificationError)) throw error;
      outputRejected('REJECTED', profile, manifest, tree.digest, { reason: 'signature-or-certificate-verification-failed', signature_valid: false, signer });
      return;
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  }

  const approved = hasExactApproval(approvals, manifest.skill_name, tree.digest);
  if (!approved) {
    outputRejected('VERIFIED_UNAPPROVED', profile, manifest, tree.digest, { signature_valid: true, approval_valid: false, signer });
    return;
  }
  process.stdout.write(`${JSON.stringify({
    status: 'VERIFIED_APPROVED',
    profile,
    skill_name: manifest.skill_name,
    tree_digest: tree.digest,
    signature_valid: signatureValid,
    approval_valid: true,
    signer,
  })}\n`);
}

async function runDiff(options) {
  const baseRoot = path.resolve(required(options, '--base'));
  const candidateRoot = path.resolve(required(options, '--candidate'));
  const roots = [baseRoot, candidateRoot];
  const baseManifestPath = await sidecarOutsideRoots(required(options, '--base-manifest'), roots, 'Base manifest');
  const manifestPath = await sidecarOutsideRoots(required(options, '--manifest'), roots, 'Candidate manifest');
  const approvalsPath = await sidecarOutsideRoots(required(options, '--approvals'), roots, 'Approval configuration');
  const [baseManifest, candidateManifest, approvals] = await Promise.all([
    readManifest(baseManifestPath),
    readManifest(manifestPath),
    loadApprovalConfig(approvalsPath),
  ]);
  const result = await compareSkillTrees({
    baseRoot,
    candidateRoot,
    baseManifest,
    candidateManifest,
    approvals,
  });
  process.stdout.write(`${JSON.stringify(result)}\n`);
  if (result.review_required) process.exitCode = 1;
}

export async function runCli(argv = process.argv.slice(2)) {
  if (argv.length === 0 || argv[0] === '--help' || argv[0] === '-h') {
    process.stdout.write(`${usage}\n`);
    return;
  }
  const command = argv[0];
  const commandFlags = {
    init: new Set(['--skill', '--manifest', '--name']),
    keygen: new Set(['--private-key', '--public-key']),
    sign: new Set(['--skill', '--manifest', '--profile', '--signature', '--private-key', '--cosign']),
    verify: new Set(['--skill', '--manifest', '--profile', '--signature', '--trust', '--approvals', '--identity', '--issuer', '--cosign', '--private-key']),
    diff: new Set(['--base', '--candidate', '--base-manifest', '--manifest', '--approvals']),
  };
  const allowed = commandFlags[command];
  if (!allowed) throw new Error(`Unknown command: ${command}`);
  const options = parseFlags(argv.slice(1), allowed);
  if (command === 'init') return await runInit(options);
  if (command === 'keygen') return await runKeygen(options);
  if (command === 'sign') return await runSign(options);
  if (command === 'verify') return await runVerify(options);
  return await runDiff(options);
}

const invokedPath = process.argv[1] ? path.resolve(process.argv[1]) : '';
if (invokedPath === fileURLToPath(import.meta.url)) {
  runCli().catch((error) => {
    process.stderr.write(`mago-ski: ${error?.message ?? 'operation failed'}\n`);
    process.exitCode = error?.exitCode ?? 2;
  });
}
