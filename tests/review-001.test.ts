// Regression tests for security review 001 (.agent/reviews/mago-ski-phase1-security-review-001.md).
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { cp, mkdir, readFile, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { canonicalBytes } from '../src/canonical-json.ts';
import { CERTIFICATE_PREDICATE_TYPE, STATEMENT_PAYLOAD_TYPE, STATEMENT_TYPE, SUBJECT_DIGEST_ALGORITHM } from '../src/certificate.ts';
import { envelopeBytes, signEnvelope } from '../src/dsse.ts';
import { loadPrivateKey } from '../src/keys.ts';
import { loadPolicy, verifyWithPolicy } from '../src/policy.ts';
import { CERTIFICATE_FILENAME, collectSkillTree, digestFileList, parseIgnoreFile, TREE_PROFILE } from '../src/tree-digest.ts';
import { runGitHubCheck } from '../hosts/github/run.ts';
import { approve, setupOrg, T0, tempDir, writeSkill } from './helpers.ts';

const cli = fileURLToPath(new URL('../src/cli.ts', import.meta.url));

test('F1: .skilldigestignore cannot exclude SKILL.md', () => {
  assert.throws(() => parseIgnoreFile('SKILL.md\n'), /unsupported pattern/u);
});

test('F1: a Skill tree must contain SKILL.md', async (t) => {
  const dir = await tempDir(t);
  await mkdir(path.join(dir, 'no-skill-md'));
  await writeFile(path.join(dir, 'no-skill-md', 'notes.md'), 'x\n');
  await assert.rejects(collectSkillTree(path.join(dir, 'no-skill-md')), /SKILL\.md/u);
});

test('F1: a certificate whose file list lacks SKILL.md is UNVERIFIABLE', async (t) => {
  const org = await setupOrg(t);
  const skill = await writeSkill(await tempDir(t), 'sneaky', { 'other.md': 'other\n' });
  const tree = await collectSkillTree(skill);
  const files = tree.files.filter((file) => file.path !== 'SKILL.md');
  const approver = await loadPrivateKey(org.approverKey);
  const statement = {
    _type: STATEMENT_TYPE,
    subject: [{ name: 'sneaky', digest: { [SUBJECT_DIGEST_ALGORITHM]: digestFileList(files).slice(7) } }],
    predicateType: CERTIFICATE_PREDICATE_TYPE,
    predicate: {
      tree_profile: TREE_PROFILE, files, previous_digest: null,
      approval: { approver_key_id: approver.keyId, issued_at: '2026-10-01T00:00:00Z', expires_at: '2026-12-01T00:00:00Z', reason: 'x' },
    },
  };
  await writeFile(path.join(skill, CERTIFICATE_FILENAME), envelopeBytes(signEnvelope(STATEMENT_PAYLOAD_TYPE, canonicalBytes(statement), approver.keyId, approver.privateKey)));
  const result = await verifyWithPolicy(await loadPolicy(org.policyPath), skill, { now: T0 });
  assert.equal(result.verdict, 'UNVERIFIABLE');
  assert.match(result.reason, /SKILL\.md/u);
});

async function actionRepo(t: Parameters<typeof setupOrg>[0]) {
  const org = await setupOrg(t);
  const base = await tempDir(t, 'mago-ski-base-');
  await mkdir(path.join(base, '.mago-ski'));
  await cp(org.trustRoot, path.join(base, '.mago-ski', 'trust-root.json'));
  await cp(org.revocations, path.join(base, '.mago-ski', 'revocations.json'));
  await writeFile(path.join(base, '.mago-ski', 'policy.json'), JSON.stringify({
    policy_version: 'mago.policy/v1', mode: 'enforce', root_fingerprint: org.rootKeyId,
    trust_root: 'trust-root.json', revocations: 'revocations.json', skill_dirs: ['../skills'],
  }));
  await approve(org, await writeSkill(path.join(base, 'skills'), 'good'));
  const pr = await tempDir(t, 'mago-ski-pr-');
  await cp(base, pr, { recursive: true });
  return { org, base, pr };
}

test('F2: a symlinked Skill directory in a PR fails the Action instead of being skipped', async (t) => {
  const { base, pr } = await actionRepo(t);
  const outside = await writeSkill(await tempDir(t), 'evil');
  await symlink(outside, path.join(pr, 'skills', 'evil'));
  const result = await runGitHubCheck({ policyRoot: base, workspace: pr, policy: '.mago-ski/policy.json', now: T0 });
  assert.equal(result.exitCode, 1);
  const evil = result.results.find((entry) => entry.skillDir.endsWith(`${path.sep}evil`));
  assert.equal(evil?.verdict, 'UNVERIFIABLE');
});

test('F2: a symlinked SKILL.md fails instead of being skipped', async (t) => {
  const { base, pr } = await actionRepo(t);
  const outside = await writeSkill(await tempDir(t), 'elsewhere');
  await mkdir(path.join(pr, 'skills', 'linked'));
  await symlink(path.join(outside, 'SKILL.md'), path.join(pr, 'skills', 'linked', 'SKILL.md'));
  const result = await runGitHubCheck({ policyRoot: base, workspace: pr, policy: '.mago-ski/policy.json', now: T0 });
  assert.equal(result.exitCode, 1);
  assert.ok(result.results.some((entry) => entry.verdict === 'UNVERIFIABLE'));
});

test('F2: a skill_dirs root that is a symlink leaving the workspace is rejected', async (t) => {
  const { base, pr } = await actionRepo(t);
  const outside = await tempDir(t);
  await writeSkill(outside, 'outside-skill');
  await (await import('node:fs/promises')).rm(path.join(pr, 'skills'), { recursive: true });
  await symlink(outside, path.join(pr, 'skills'));
  await assert.rejects(runGitHubCheck({ policyRoot: base, workspace: pr, policy: '.mago-ski/policy.json', now: T0 }), /must stay inside/u);
});

test('F7: approve refuses a Skill that contains a private key', async (t) => {
  const org = await setupOrg(t);
  const skill = await writeSkill(await tempDir(t), 'leaky');
  await writeFile(path.join(skill, 'key.pem'), await readFile(org.rootKey));
  await assert.rejects(approve(org, skill), /private key/u);
});

test('F7: keygen refuses to write a key inside a Skill directory tree', async (t) => {
  const dir = await tempDir(t);
  const skill = await writeSkill(dir, 'demo');
  await mkdir(path.join(skill, 'nested'));
  const result = spawnSync(process.execPath, [cli, 'keygen', '--private-key', path.join(skill, 'nested', 'k.pem'), '--public-key', path.join(dir, 'k.pub')], { encoding: 'utf8' });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /inside a Skill directory/u);
});

test('R1: Skills deeper than the discovery limit fail the check instead of being skipped', async (t) => {
  const { base, pr } = await actionRepo(t);
  let deep = path.join(pr, 'skills');
  for (let level = 0; level < 20; level += 1) deep = path.join(deep, `d${level}`);
  await writeSkill(deep, 'deep-skill');
  await assert.rejects(runGitHubCheck({ policyRoot: base, workspace: pr, policy: '.mago-ski/policy.json', now: T0 }), /depth limit/u);
});
