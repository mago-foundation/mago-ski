import assert from 'node:assert/strict';
import { readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { preparePublish } from '../hosts/github/publish.ts';
import { describeSkill, fulcioIdentity, PUBLISHED_BY_PREDICATE_TYPE, subjectChecksums, verifyPublishedBy } from '../src/published-by.ts';
import { tempDir, writeSkill } from './helpers.ts';

// A real, public Sigstore bundle: the SLSA provenance that actions/attest made for gh 2.106.0 (cli/cli).
const REAL_BUNDLE = path.join(import.meta.dirname, 'fixtures', 'sigstore', 'cli-cli-v2.106.0-provenance.sigstore.json');

test('reads the Fulcio identity of a real GitHub Actions signing certificate', async () => {
  const bundle = JSON.parse(await readFile(REAL_BUNDLE, 'utf8'));
  const identity = fulcioIdentity(Buffer.from(bundle.verificationMaterial.certificate.rawBytes, 'base64'));
  assert.equal(identity.issuer, 'https://token.actions.githubusercontent.com');
  assert.equal(identity.source_repository_uri, 'https://github.com/cli/cli');
  assert.equal(identity.source_repository_id, '212613049');
  assert.equal(identity.build_config_uri, 'https://github.com/cli/cli/.github/workflows/deployment.yml@refs/heads/trunk');
  assert.equal(identity.source_repository_digest, '529111a21612ff1e29dc45e567a157df24e0e243');
  assert.equal(identity.runner_environment, 'github-hosted');
});

test('truncated or malformed certificates are refused, never misread', () => {
  assert.throws(() => fulcioIdentity(Buffer.from([0x30, 0x82, 0xff, 0xff, 0x00])), /truncated/u);
  assert.throws(() => fulcioIdentity(Buffer.from([0x30])), /truncated/u);
});

test('subject lines: one per Skill, and a path with a line break is refused', async (t) => {
  const root = await tempDir(t);
  const skill = await describeSkill(await writeSkill(path.join(root, 'skills'), 'demo'), root);
  assert.equal(skill.path, 'skills/demo');
  assert.equal(subjectChecksums([skill]), `${skill.digest.slice(7)}  skill:skills/demo\n`);
  assert.throws(() => subjectChecksums([{ ...skill, path: 'a\nb' }]), /control character/u);
});

test('publish: writes the statement only when every Skill passes the check', async (t) => {
  const workspace = await tempDir(t);
  await writeSkill(path.join(workspace, 'skills'), 'good', {
    'SKILL.md': '---\nname: good\ndescription: d\npermissions:\n  network:\n    allow: [api.example.com]\n---\nCall https://api.example.com/x\n',
  });
  await writeSkill(path.join(workspace, 'skills'), 'plain', { 'SKILL.md': '---\nname: plain\ndescription: "no\n  declaration"\n---\nUse https://x.example\n' });
  const out = path.join(await tempDir(t), 'out');
  const ok = await preparePublish(workspace, '.', out, false);
  assert.equal(ok.exitCode, 0);
  const predicate = JSON.parse(await readFile(path.join(out, 'predicate.json'), 'utf8'));
  assert.equal(predicate.generator.name, 'mago-ski');
  assert.deepEqual(predicate.skills.map((s: { path: string }) => s.path), ['skills/good', 'skills/plain']);
  assert.deepEqual(predicate.skills[0].declaration.network.allow, ['api.example.com']);
  assert.equal(predicate.skills[1].declaration, null);
  assert.deepEqual(predicate.skills[1].profile.web_hosts, ['x.example']);
  assert.equal((await readFile(path.join(out, 'subjects.txt'), 'utf8')).split('\n').filter(Boolean).length, 2);
  assert.equal(((await stat(path.join(out, 'predicate.json'))).mode & 0o777), 0o600);

  await writeSkill(path.join(workspace, 'skills'), 'bad', { 'SKILL.md': '---\nname: bad\ndescription: d\npermissions:\n  shell: false\n---\nhttps://y.example\n' });
  const out2 = path.join(await tempDir(t), 'out');
  const refused = await preparePublish(workspace, '.', out2, false);
  assert.equal(refused.exitCode, 1);
  assert.match(refused.summary, /Nothing was signed/u);
  await assert.rejects(stat(out2), { code: 'ENOENT' });
});

test('verify: bad arguments are refused before anything runs', async (t) => {
  const dir = await writeSkill(await tempDir(t), 'demo');
  const base = { bundlePath: REAL_BUNDLE, trustedRootPath: REAL_BUNDLE, cosignPath: '/nonexistent', repository: 'cli/cli' };
  await assert.rejects(verifyPublishedBy(dir, { ...base, repository: 'cli' }), RangeError);
  await assert.rejects(verifyPublishedBy(dir, { ...base, workflow: '../x.yml' }), RangeError);
  await assert.rejects(verifyPublishedBy(dir, { ...base, repositoryId: '12a' }), RangeError);
  // A real bundle for other bytes never gets as far as the statement: Cosign must run (and here cannot).
  await assert.rejects(verifyPublishedBy(dir, base), (error: Error) => !(error instanceof RangeError));
  assert.equal(PUBLISHED_BY_PREDICATE_TYPE, 'https://magofoundation.dev/attestation/published-by/v1');
});
