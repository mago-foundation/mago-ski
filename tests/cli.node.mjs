import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { APPROVAL_VERSION, TRUST_VERSION } from '../src/trust.mjs';
import { serializeCanonicalJson } from '../src/manifest.mjs';

const cliPath = fileURLToPath(new URL('../bin/mago-ski.mjs', import.meta.url));

function invoke(args) {
  return spawnSync(process.execPath, [cliPath, ...args], { encoding: 'utf8', env: process.env });
}

async function temporaryDirectory(t) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'mago-ski-cli-'));
  t.after(async () => await rm(directory, { recursive: true, force: true }));
  return directory;
}

test('CLI init writes an external canonical manifest and refuses sidecars inside the Skill root', async (t) => {
  const directory = await temporaryDirectory(t);
  const skill = path.join(directory, 'skill');
  await mkdir(skill);
  await writeFile(path.join(skill, 'SKILL.md'), '# Sample\nUse the tool.\n');
  const manifestPath = path.join(directory, 'skill.manifest.json');
  const result = invoke(['init', '--skill', skill, '--manifest', manifestPath, '--name', 'sample-skill']);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout).status, 'INITIALIZED');
  const manifestBytes = await readFile(manifestPath);
  assert.equal(manifestBytes.at(-1), 0x0a);
  assert.equal(manifestBytes.includes(Buffer.from(' ')), false);

  const inside = invoke(['init', '--skill', skill, '--manifest', path.join(skill, 'manifest.json')]);
  assert.equal(inside.status, 2);
  assert.match(inside.stderr, /outside the Skill directory/u);
});

test('CLI keygen warns to keep private keys outside Skill roots and preserves public JSON output', async (t) => {
  const directory = await temporaryDirectory(t);
  const privatePath = path.join(directory, 'synthetic-test.key');
  const publicPath = path.join(directory, 'synthetic-test.pub');
  const result = invoke(['keygen', '--private-key', privatePath, '--public-key', publicPath]);

  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stderr, 'Warning: keep private keys outside Skill roots.\n');
  assert.doesNotMatch(result.stdout, /keep private keys outside/u);
  assert.doesNotMatch(result.stdout, /-----BEGIN (?:ENCRYPTED )?PRIVATE KEY-----/u);
  assert.equal(result.stdout.endsWith('\n'), true);
  const output = JSON.parse(result.stdout);
  assert.deepEqual(Object.keys(output).sort(), [
    'key_id', 'private_key', 'public_key', 'public_key_spki_base64', 'status',
  ]);
  assert.equal(output.status, 'KEY_CREATED');
  assert.equal(output.private_key, privatePath);
  assert.equal(output.public_key, publicPath);
  assert.equal(typeof output.key_id, 'string');
  assert.equal(typeof output.public_key_spki_base64, 'string');
});

test('CLI Ed25519 sign/verify separates trusted signer from exact digest approval', async (t) => {
  const directory = await temporaryDirectory(t);
  const skill = path.join(directory, 'skill');
  await mkdir(skill);
  await writeFile(path.join(skill, 'SKILL.md'), '# Sample\nUse https://api.example.test\n');
  const manifestPath = path.join(directory, 'manifest.json');
  const privatePath = path.join(directory, 'signer.key');
  const publicPath = path.join(directory, 'signer.pub');
  const signaturePath = path.join(directory, 'signature.json');
  const trustPath = path.join(directory, 'trust.json');
  const approvalsPath = path.join(directory, 'approvals.json');

  assert.equal(invoke(['init', '--skill', skill, '--manifest', manifestPath, '--name', 'sample-skill']).status, 0);
  const keyResult = invoke(['keygen', '--private-key', privatePath, '--public-key', publicPath]);
  assert.equal(keyResult.status, 0, keyResult.stderr);
  assert.equal(keyResult.stdout.includes('-----BEGIN PRIVATE KEY-----'), false);
  const key = JSON.parse(keyResult.stdout);
  const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
  await writeFile(trustPath, serializeCanonicalJson({
    trust_version: TRUST_VERSION,
    ed25519: [{ key_id: key.key_id, public_key: key.public_key_spki_base64 }],
    sigstore: [],
  }));
  await writeFile(approvalsPath, serializeCanonicalJson({
    approval_version: APPROVAL_VERSION,
    approvals: [{ skill_name: 'sample-skill', digest: manifest.tree_digest }],
  }));
  const signed = invoke([
    'sign', '--skill', skill, '--manifest', manifestPath, '--profile', 'ed25519',
    '--signature', signaturePath, '--private-key', privatePath,
  ]);
  assert.equal(signed.status, 0, signed.stderr);
  assert.equal(JSON.parse(signed.stdout).status, 'SIGNED');

  const verified = invoke([
    'verify', '--skill', skill, '--manifest', manifestPath, '--profile', 'ed25519',
    '--signature', signaturePath, '--trust', trustPath, '--approvals', approvalsPath,
  ]);
  assert.equal(verified.status, 0, verified.stderr);
  assert.equal(JSON.parse(verified.stdout).status, 'VERIFIED_APPROVED');

  await writeFile(path.join(skill, 'SKILL.md'), '# Sample\nUse https://api.example.test and explain the result.\n');
  const updatedManifestPath = path.join(directory, 'updated.manifest.json');
  const updatedSignaturePath = path.join(directory, 'updated.signature.json');
  assert.equal(invoke(['init', '--skill', skill, '--manifest', updatedManifestPath, '--name', 'sample-skill']).status, 0);
  const updatedSign = invoke([
    'sign', '--skill', skill, '--manifest', updatedManifestPath, '--profile', 'ed25519',
    '--signature', updatedSignaturePath, '--private-key', privatePath,
  ]);
  assert.equal(updatedSign.status, 0, updatedSign.stderr);
  const unapproved = invoke([
    'verify', '--skill', skill, '--manifest', updatedManifestPath, '--profile', 'ed25519',
    '--signature', updatedSignaturePath, '--trust', trustPath, '--approvals', approvalsPath,
  ]);
  assert.equal(unapproved.status, 1);
  const unapprovedResult = JSON.parse(unapproved.stdout);
  assert.equal(unapprovedResult.status, 'VERIFIED_UNAPPROVED');
  assert.equal(unapprovedResult.signature_valid, true);
  assert.equal(unapprovedResult.approval_valid, false);
});

test('CLI diff reports changed prose as inconclusive until its exact digest is approved', async (t) => {
  const directory = await temporaryDirectory(t);
  const base = path.join(directory, 'base');
  const candidate = path.join(directory, 'candidate');
  await mkdir(base);
  await mkdir(candidate);
  await writeFile(path.join(base, 'SKILL.md'), '# Instructions\nSend to https://api.example.test\n');
  await writeFile(path.join(candidate, 'SKILL.md'), '# Instructions\nSend to https://api.example.test and explain the result.\n');
  const baseManifestPath = path.join(directory, 'base.manifest.json');
  const candidateManifestPath = path.join(directory, 'candidate.manifest.json');
  assert.equal(invoke(['init', '--skill', base, '--manifest', baseManifestPath, '--name', 'sample-skill']).status, 0);
  assert.equal(invoke(['init', '--skill', candidate, '--manifest', candidateManifestPath, '--name', 'sample-skill']).status, 0);
  const baseManifest = JSON.parse(await readFile(baseManifestPath, 'utf8'));
  const candidateManifest = JSON.parse(await readFile(candidateManifestPath, 'utf8'));
  const approvalsPath = path.join(directory, 'approvals.json');
  const approvals = [
    { skill_name: 'sample-skill', digest: baseManifest.tree_digest },
  ];
  await writeFile(approvalsPath, serializeCanonicalJson({ approval_version: APPROVAL_VERSION, approvals }));

  const args = [
    'diff', '--base', base, '--candidate', candidate,
    '--base-manifest', baseManifestPath, '--manifest', candidateManifestPath,
    '--approvals', approvalsPath,
  ];
  const review = invoke(args);
  assert.equal(review.status, 1);
  const reviewResult = JSON.parse(review.stdout);
  assert.equal(reviewResult.verdict, 'INCONCLUSIVE');
  assert.equal(reviewResult.capability_evidence.status, 'no-detected-delta');
  assert.equal(reviewResult.review_required, true);

  approvals.push({ skill_name: 'sample-skill', digest: candidateManifest.tree_digest });
  approvals.sort((left, right) => left.digest < right.digest ? -1 : left.digest > right.digest ? 1 : 0);
  await writeFile(approvalsPath, serializeCanonicalJson({ approval_version: APPROVAL_VERSION, approvals }));
  const explicitlyApproved = invoke(args);
  assert.equal(explicitlyApproved.status, 0);
  assert.equal(JSON.parse(explicitlyApproved.stdout).verdict, 'INCONCLUSIVE');
  assert.equal(JSON.parse(explicitlyApproved.stdout).review_required, false);
});

test('CLI reports usage and malformed arguments with exit 2', () => {
  const unknown = invoke(['wat']);
  assert.equal(unknown.status, 2);
  assert.match(unknown.stderr, /Unknown command/u);
  const duplicate = invoke(['init', '--skill', 'a', '--skill', 'b', '--manifest', 'm']);
  assert.equal(duplicate.status, 2);
  assert.match(duplicate.stderr, /only once/u);
  assert.equal(invoke(['--help']).status, 0);
});
