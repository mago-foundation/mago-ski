import assert from 'node:assert/strict';
import { cp, mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import test, { type TestContext } from 'node:test';
import { addApprover } from '../src/admin.ts';
import { generateKeyPair } from '../src/keys.ts';
import { runGitHubCheck } from '../hosts/github/run.ts';
import { approve, setupOrg, T0, tempDir, writeSkill, type Org } from './helpers.ts';

/** A repository with .mago-ski/{policy,trust-root,revocations} and skills/ ; returns base and PR checkouts. */
async function repo(t: TestContext, org: Org, mode: 'shadow' | 'enforce' = 'enforce') {
  const base = await tempDir(t, 'mago-ski-base-');
  await mkdir(path.join(base, '.mago-ski'));
  await cp(org.trustRoot, path.join(base, '.mago-ski', 'trust-root.json'));
  await cp(org.revocations, path.join(base, '.mago-ski', 'revocations.json'));
  await writeFile(path.join(base, '.mago-ski', 'policy.json'), JSON.stringify({
    policy_version: 'mago.policy/v1', mode, root_fingerprint: org.rootKeyId,
    trust_root: 'trust-root.json', revocations: 'revocations.json', skill_dirs: ['../skills'],
  }));
  const skill = await writeSkill(path.join(base, 'skills'), 'repo-skill');
  await approve(org, skill);
  const pr = await tempDir(t, 'mago-ski-pr-');
  await cp(base, pr, { recursive: true });
  return { base, pr };
}

const check = (base: string, pr: string) => runGitHubCheck({ policyRoot: base, workspace: pr, policy: '.mago-ski/policy.json', now: T0 });

test('an unchanged approved Skill passes', async (t) => {
  const org = await setupOrg(t);
  const { base, pr } = await repo(t, org);
  const result = await check(base, pr);
  assert.equal(result.exitCode, 0);
  assert.equal(result.results[0]?.verdict, 'VERIFIED');
  assert.match(result.summary, /1\/1 Skills verified \(enforce mode\)/u);
});

test('a PR that edits a Skill without a new certificate fails', async (t) => {
  const org = await setupOrg(t);
  const { base, pr } = await repo(t, org);
  await writeFile(path.join(pr, 'skills', 'repo-skill', 'SKILL.md'), `${await readFile(path.join(pr, 'skills', 'repo-skill', 'SKILL.md'), 'utf8')}\nNew step.\n`);
  const result = await check(base, pr);
  assert.equal(result.exitCode, 1);
  assert.equal(result.results[0]?.verdict, 'UNAPPROVED_CHANGE');
});

test('a PR cannot trust itself by adding its own approver to the trust root', async (t) => {
  const org = await setupOrg(t);
  const { base, pr } = await repo(t, org);
  // The attacker controls the PR tree, but not the root key, so they add a self-signed root and approver.
  const dir = await tempDir(t);
  const attackerRoot = await generateKeyPair(path.join(dir, 'root.pem'), path.join(dir, 'root.pub'));
  const attacker = await generateKeyPair(path.join(dir, 'a.pem'), path.join(dir, 'a.pub'));
  const fakeTrust = path.join(dir, 'trust-root.json');
  const fakeRevocations = path.join(dir, 'revocations.json');
  const { initRoot } = await import('../src/admin.ts');
  await initRoot({ rootKeyPath: attackerRoot.privatePath, trustRootOut: fakeTrust, revocationsOut: fakeRevocations, now: T0 });
  await addApprover({ rootKeyPath: attackerRoot.privatePath, trustRootPath: fakeTrust, now: T0, publicKeyPath: attacker.publicPath, name: 'me', scopes: ['*'], expires: '30d' });
  await cp(fakeTrust, path.join(pr, '.mago-ski', 'trust-root.json'));
  const policy = JSON.parse(await readFile(path.join(pr, '.mago-ski', 'policy.json'), 'utf8'));
  policy.root_fingerprint = attackerRoot.keyId;
  await writeFile(path.join(pr, '.mago-ski', 'policy.json'), JSON.stringify(policy));
  const skill = path.join(pr, 'skills', 'repo-skill');
  await writeFile(path.join(skill, 'SKILL.md'), 'malicious\n');
  await approve(org, skill, { key: attacker.privatePath });
  const result = await check(base, pr);
  assert.equal(result.exitCode, 1);
  assert.equal(result.results[0]?.verdict, 'UNTRUSTED_SIGNER');
});

test('shadow mode reports failures without failing the check', async (t) => {
  const org = await setupOrg(t);
  const { base, pr } = await repo(t, org, 'shadow');
  await writeSkill(path.join(pr, 'skills'), 'new-skill');
  const result = await check(base, pr);
  assert.equal(result.exitCode, 0);
  assert.match(result.summary, /Shadow mode/u);
  assert.ok(result.results.some((entry) => entry.verdict === 'NO_CERTIFICATE'));
});

test('policy paths may not escape the policy checkout', async (t) => {
  const org = await setupOrg(t);
  const { base, pr } = await repo(t, org);
  await assert.rejects(runGitHubCheck({ policyRoot: base, workspace: pr, policy: '../outside.json', now: T0 }), /must stay inside/u);
});
