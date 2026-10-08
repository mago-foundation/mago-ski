import assert from 'node:assert/strict';
import { createPublicKey } from 'node:crypto';
import { chmod, mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
  createAttestationPayload,
  createManifest,
  serializeCanonicalJson,
} from '../src/manifest.mjs';
import {
  generateEd25519KeyPair,
  signEd25519Payload,
  verifyEd25519Payload,
} from '../src/ed25519.mjs';
import { computeTreeDigest } from '../src/tree-digest.mjs';
import { compareSkillTrees } from '../src/diff.mjs';
import {
  APPROVAL_VERSION,
  TRUST_VERSION,
  hasExactApproval,
  loadTrustConfig,
  makeEd25519TrustEntry,
  parseApprovalConfigBytes,
} from '../src/trust.mjs';

async function setup(t) {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'mago-ski-crypto-'));
  t.after(async () => await rm(dir, { recursive: true, force: true }));
  return dir;
}

async function writeManifestFile(filePath, name, root) {
  const tree = await computeTreeDigest(root);
  const manifest = createManifest(name, tree);
  await writeFile(filePath, serializeCanonicalJson(manifest), { flag: 'wx', mode: 0o644 });
  return manifest;
}

function approvalsFor(entries) {
  const sorted = [...entries].sort((left, right) => {
    const a = `${left.skill_name}\0${left.digest}`;
    const b = `${right.skill_name}\0${right.digest}`;
    return a < b ? -1 : a > b ? 1 : 0;
  });
  return parseApprovalConfigBytes(Buffer.from(serializeCanonicalJson({ approval_version: APPROVAL_VERSION, approvals: sorted })));
}

test('Ed25519 keygen, signature verification, and signer trust are separate', async (t) => {
  const dir = await setup(t);
  const skill = path.join(dir, 'skill');
  await mkdir(skill);
  await writeFile(path.join(skill, 'SKILL.md'), 'Use https://example.test\n');
  const manifest = await writeManifestFile(path.join(dir, 'skill.manifest.json'), 'sample-skill', skill);
  const key = await generateEd25519KeyPair(path.join(dir, 'signer.key'), path.join(dir, 'signer.pub'));
  assert.equal(key.keyId.startsWith('sha256:'), true);
  assert.equal((await import('node:fs/promises').then(({ stat }) => stat(key.privateKeyPath))).mode & 0o077, 0);

  const payload = createAttestationPayload(manifest);
  const signature = await signEd25519Payload(payload, key.privateKeyPath, skill);
  const signaturePath = path.join(dir, 'skill.sig.json');
  await writeFile(signaturePath, serializeCanonicalJson(signature), { flag: 'wx' });
  const trustPath = path.join(dir, 'trust.json');
  await writeFile(trustPath, serializeCanonicalJson({
    trust_version: TRUST_VERSION,
    ed25519: [makeEd25519TrustEntry(key.keyId, Buffer.from(key.publicKey, 'base64'))],
    sigstore: [],
  }));
  const trust = await loadTrustConfig(trustPath, { skillRoot: skill });

  assert.deepEqual(await verifyEd25519Payload(payload, signaturePath, trust), {
    valid: true,
    reason: 'invalid-signature',
    keyId: key.keyId,
  });
  assert.equal((await verifyEd25519Payload(Buffer.from('tampered'), signaturePath, trust)).valid, false);

  const other = await generateEd25519KeyPair(path.join(dir, 'other.key'), path.join(dir, 'other.pub'));
  const untrusted = {
    ed25519: [{ keyId: other.keyId, publicKey: createPublicKey(await readFile(other.publicKeyPath)) }],
  };
  const rejected = await verifyEd25519Payload(payload, signaturePath, untrusted);
  assert.equal(rejected.valid, false);
  assert.equal(rejected.reason, 'untrusted-signer');
});

test('Ed25519 refuses permissive private keys and keys inside the Skill root', async (t) => {
  const dir = await setup(t);
  const skill = path.join(dir, 'skill');
  await mkdir(skill);
  await writeFile(path.join(skill, 'SKILL.md'), 'A prompt.\n');
  const key = await generateEd25519KeyPair(path.join(dir, 'private.key'), path.join(dir, 'public.pem'));
  const payload = Buffer.from('signed payload');
  await chmod(key.privateKeyPath, 0o644);
  await assert.rejects(signEd25519Payload(payload, key.privateKeyPath, skill), /permissions/u);
  await chmod(key.privateKeyPath, 0o600);
  const inside = path.join(skill, 'private.key');
  await writeFile(inside, await readFile(key.privateKeyPath), { mode: 0o600 });
  await assert.rejects(signEd25519Payload(payload, inside, skill), /outside the Skill directory/u);
});

test('a changed prompt with no detected network-origin delta remains inconclusive and needs exact approval', async (t) => {
  const dir = await setup(t);
  const base = path.join(dir, 'base');
  const candidate = path.join(dir, 'candidate');
  await mkdir(base);
  await mkdir(candidate);
  await writeFile(path.join(base, 'SKILL.md'), '# Instructions\nUse https://api.example.test for requests.\n');
  await writeFile(path.join(candidate, 'SKILL.md'), '# Instructions\nUse https://api.example.test for requests, and explain the result clearly.\n');
  const baseManifest = createManifest('sample-skill', await computeTreeDigest(base));
  const candidateManifest = createManifest('sample-skill', await computeTreeDigest(candidate));
  const baseOnlyApproval = approvalsFor([{ skill_name: 'sample-skill', digest: baseManifest.tree_digest }]);
  const result = await compareSkillTrees({ baseRoot: base, candidateRoot: candidate, baseManifest, candidateManifest, approvals: baseOnlyApproval });
  assert.equal(result.verdict, 'INCONCLUSIVE');
  assert.equal(result.content_changed, true);
  assert.equal(result.capability_evidence.status, 'no-detected-delta');
  assert.equal(result.review_required, true);
  assert.equal(result.candidate_approval, 'not-approved');
  assert.deepEqual(result.files[0].changed_sections, ['Instructions']);

  const exactCandidateApproval = approvalsFor([
    { skill_name: 'sample-skill', digest: baseManifest.tree_digest },
    { skill_name: 'sample-skill', digest: candidateManifest.tree_digest },
  ]);
  const explicitlyApproved = await compareSkillTrees({
    baseRoot: base,
    candidateRoot: candidate,
    baseManifest,
    candidateManifest,
    approvals: exactCandidateApproval,
  });
  assert.equal(explicitlyApproved.verdict, 'INCONCLUSIVE');
  assert.equal(explicitlyApproved.review_required, false);
  assert.equal(explicitlyApproved.candidate_approval, 'approved-exact-digest');
  assert.equal(hasExactApproval(exactCandidateApproval, 'sample-skill', candidateManifest.tree_digest), true);
});

test('diff distinguishes observed origin changes and exact unchanged approved bytes', async (t) => {
  const dir = await setup(t);
  const base = path.join(dir, 'base');
  const changed = path.join(dir, 'changed');
  const identical = path.join(dir, 'identical');
  await mkdir(base);
  await mkdir(changed);
  await mkdir(identical);
  const content = '# Instructions\nSend to https://api.example.test\n';
  await writeFile(path.join(base, 'SKILL.md'), content);
  await writeFile(path.join(identical, 'SKILL.md'), content);
  await writeFile(path.join(changed, 'SKILL.md'), '# Instructions\nSend to https://new.example.test\n');
  const baseManifest = createManifest('sample-skill', await computeTreeDigest(base));
  const changedManifest = createManifest('sample-skill', await computeTreeDigest(changed));
  const identicalManifest = createManifest('sample-skill', await computeTreeDigest(identical));
  const approvedBase = approvalsFor([{ skill_name: 'sample-skill', digest: baseManifest.tree_digest }]);

  const capabilityChange = await compareSkillTrees({
    baseRoot: base,
    candidateRoot: changed,
    baseManifest,
    candidateManifest: changedManifest,
    approvals: approvedBase,
  });
  assert.equal(capabilityChange.verdict, 'CAPABILITY_CHANGED');
  assert.equal(capabilityChange.review_required, true);
  assert.deepEqual(capabilityChange.capability_evidence.added_network_origins, ['https://new.example.test']);
  assert.deepEqual(capabilityChange.capability_evidence.removed_network_origins, ['https://api.example.test']);

  const unchanged = await compareSkillTrees({
    baseRoot: base,
    candidateRoot: identical,
    baseManifest,
    candidateManifest: identicalManifest,
    approvals: approvedBase,
  });
  assert.equal(unchanged.verdict, 'VERIFIED_UNCHANGED');
  assert.equal(unchanged.review_required, false);
  assert.equal(unchanged.base_digest, unchanged.candidate_digest);
});
