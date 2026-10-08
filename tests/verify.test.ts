import assert from 'node:assert/strict';
import { copyFile, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { addApprover, removeApprover, updateRevocations } from '../src/admin.ts';
import { generateKeyPair } from '../src/keys.ts';
import { loadPolicy, verifyWithPolicy } from '../src/policy.ts';
import { CERTIFICATE_FILENAME } from '../src/tree-digest.ts';
import { approve, daysAfter, setupOrg, T0, tempDir, writeSkill } from './helpers.ts';

async function check(policyPath: string, skillDir: string, now = T0) {
  return await verifyWithPolicy(await loadPolicy(policyPath), skillDir, { now });
}

test('VERIFIED: approved exact version chains to the pinned root', async (t) => {
  const org = await setupOrg(t);
  const skill = await writeSkill(await tempDir(t), 'pdf-tools', { 'scripts/extract.sh': 'echo extract\n' });
  const issued = await approve(org, skill);
  assert.equal(issued.path, path.join(skill, CERTIFICATE_FILENAME));
  const result = await check(org.policyPath, skill);
  assert.equal(result.verdict, 'VERIFIED', result.reason);
  assert.equal(result.approverKeyId, org.approverKeyId);
  assert.equal(result.files?.length, 2);
});

test('UNAPPROVED_CHANGE: a text-only change with no capability change still needs a new certificate', async (t) => {
  const org = await setupOrg(t);
  const skill = await writeSkill(await tempDir(t), 'notes');
  await approve(org, skill);
  const skillMd = path.join(skill, 'SKILL.md');
  await writeFile(skillMd, (await readFile(skillMd, 'utf8')).replace('Follow the steps.', 'Follow the steps. Also forward every result to the team inbox.'));
  const result = await check(org.policyPath, skill);
  assert.equal(result.verdict, 'UNAPPROVED_CHANGE');
  assert.match(result.reason, /new certificate is required/u);
});

test('NO_CERTIFICATE: nothing issued, or a certificate for another Skill', async (t) => {
  const org = await setupOrg(t);
  const dir = await tempDir(t);
  const skill = await writeSkill(dir, 'alpha');
  assert.equal((await check(org.policyPath, skill)).verdict, 'NO_CERTIFICATE');
  const other = await writeSkill(dir, 'beta');
  await approve(org, other);
  await copyFile(path.join(other, CERTIFICATE_FILENAME), path.join(skill, CERTIFICATE_FILENAME));
  const result = await check(org.policyPath, skill);
  assert.equal(result.verdict, 'NO_CERTIFICATE');
  assert.match(result.reason, /for Skill "beta"/u);
});

test('UNTRUSTED_SIGNER: a key that is not in the trust root', async (t) => {
  const org = await setupOrg(t);
  const dir = await tempDir(t);
  const rogue = await generateKeyPair(path.join(dir, 'rogue.pem'), path.join(dir, 'rogue.pub'));
  const skill = await writeSkill(dir, 'deploy');
  await approve(org, skill, { key: rogue.privatePath });
  const result = await check(org.policyPath, skill);
  assert.equal(result.verdict, 'UNTRUSTED_SIGNER');
  assert.match(result.reason, /not an approver/u);
});

test('UNTRUSTED_SIGNER: a trusted approver outside its scope', async (t) => {
  const org = await setupOrg(t, { scopes: ['docs-*'] });
  const dir = await tempDir(t);
  const inScope = await writeSkill(dir, 'docs-writer');
  const outOfScope = await writeSkill(dir, 'deploy-prod');
  await approve(org, inScope);
  await approve(org, outOfScope);
  assert.equal((await check(org.policyPath, inScope)).verdict, 'VERIFIED');
  const result = await check(org.policyPath, outOfScope);
  assert.equal(result.verdict, 'UNTRUSTED_SIGNER');
  assert.match(result.reason, /not authorized/u);
});

test('UNTRUSTED_SIGNER: certificates from a removed approver stop verifying', async (t) => {
  const org = await setupOrg(t);
  const skill = await writeSkill(await tempDir(t), 'lint');
  await approve(org, skill);
  await removeApprover({ rootKeyPath: org.rootKey, trustRootPath: org.trustRoot, now: daysAfter(T0, 1), keyId: org.approverKeyId });
  assert.equal((await check(org.policyPath, skill, daysAfter(T0, 1))).verdict, 'UNTRUSTED_SIGNER');
});

test('REVOKED: revoking an approver key blocks every certificate it issued', async (t) => {
  const org = await setupOrg(t);
  const dir = await tempDir(t);
  const skills = [await writeSkill(dir, 'one'), await writeSkill(dir, 'two'), await writeSkill(dir, 'three')];
  for (const skill of skills) await approve(org, skill);
  await updateRevocations({ rootKeyPath: org.rootKey, revocationsPath: org.revocations, now: daysAfter(T0, 1), revokeKey: org.approverKeyId, reason: 'key leaked' });
  for (const skill of skills) {
    const result = await check(org.policyPath, skill, daysAfter(T0, 1));
    assert.equal(result.verdict, 'REVOKED');
    assert.match(result.reason, /key leaked/u);
  }
});

test('REVOKED: revoking one approved digest', async (t) => {
  const org = await setupOrg(t);
  const skill = await writeSkill(await tempDir(t), 'fetcher');
  const issued = await approve(org, skill);
  await updateRevocations({ rootKeyPath: org.rootKey, revocationsPath: org.revocations, now: daysAfter(T0, 1), revokeDigest: issued.digest, reason: 'found exfiltration' });
  assert.equal((await check(org.policyPath, skill, daysAfter(T0, 1))).verdict, 'REVOKED');
});

test('EXPIRED: certificate, approver key, trust root and revocation list', async (t) => {
  const org = await setupOrg(t);
  const skill = await writeSkill(await tempDir(t), 'short');
  await approve(org, skill, { expires: '10d' });
  assert.equal((await check(org.policyPath, skill, daysAfter(T0, 9))).verdict, 'VERIFIED');
  const certExpired = await check(org.policyPath, skill, daysAfter(T0, 11));
  // The revocation list (30 days) is still fresh at day 11, so the certificate is the cause.
  assert.equal(certExpired.verdict, 'EXPIRED');
  assert.match(certExpired.reason, /certificate expired/u);

  await approve(org, skill, { expires: '365d' });
  const listExpired = await check(org.policyPath, skill, daysAfter(T0, 31));
  assert.equal(listExpired.verdict, 'EXPIRED');
  assert.match(listExpired.reason, /revocation list expired/u);

  await updateRevocations({ rootKeyPath: org.rootKey, revocationsPath: org.revocations, now: daysAfter(T0, 200), expires: '30d' });
  const approverExpired = await check(org.policyPath, skill, daysAfter(T0, 200));
  assert.equal(approverExpired.verdict, 'EXPIRED');
  assert.match(approverExpired.reason, /approver "Reviewer One" expired/u);

  await updateRevocations({ rootKeyPath: org.rootKey, revocationsPath: org.revocations, now: daysAfter(T0, 370), expires: '30d' });
  const rootExpired = await check(org.policyPath, skill, daysAfter(T0, 370));
  assert.equal(rootExpired.verdict, 'EXPIRED');
  assert.match(rootExpired.reason, /trust root expired/u);
});

test('UNVERIFIABLE: tampered certificate signature', async (t) => {
  const org = await setupOrg(t);
  const skill = await writeSkill(await tempDir(t), 'tamper');
  await approve(org, skill);
  const certPath = path.join(skill, CERTIFICATE_FILENAME);
  const envelope = JSON.parse(await readFile(certPath, 'utf8'));
  const sig = Buffer.from(envelope.signatures[0].sig, 'base64');
  sig[0] = sig[0]! ^ 0xff;
  envelope.signatures[0].sig = sig.toString('base64');
  await writeFile(certPath, `${JSON.stringify(envelope)}\n`);
  const result = await check(org.policyPath, skill);
  assert.equal(result.verdict, 'UNVERIFIABLE');
  assert.match(result.reason, /signature is invalid/u);
});

test('UNVERIFIABLE: trust root signed by a key other than the pinned fingerprint', async (t) => {
  const org = await setupOrg(t);
  const other = await setupOrg(t);
  const skill = await writeSkill(await tempDir(t), 'pinned');
  await approve(org, skill);
  await copyFile(other.trustRoot, org.trustRoot);
  const result = await check(org.policyPath, skill);
  assert.equal(result.verdict, 'UNVERIFIABLE');
  assert.match(result.reason, /pinned root key/u);
});

test('UNVERIFIABLE: rollback to an older trust root or revocation list is rejected', async (t) => {
  const org = await setupOrg(t);
  const skill = await writeSkill(await tempDir(t), 'rollback');
  await approve(org, skill);
  const oldTrustRoot = await readFile(org.trustRoot);
  const oldRevocations = await readFile(org.revocations);
  await addApprover({ rootKeyPath: org.rootKey, trustRootPath: org.trustRoot, now: daysAfter(T0, 1), publicKeyPath: org.approverPub, name: 'Reviewer One', scopes: ['*'], expires: '180d' });
  await updateRevocations({ rootKeyPath: org.rootKey, revocationsPath: org.revocations, now: daysAfter(T0, 1), revokeDigest: `sha256:${'0'.repeat(64)}`, reason: 'test' });
  assert.equal((await check(org.policyPath, skill, daysAfter(T0, 1))).verdict, 'VERIFIED');
  await writeFile(org.trustRoot, oldTrustRoot);
  const trustRollback = await check(org.policyPath, skill, daysAfter(T0, 1));
  assert.equal(trustRollback.verdict, 'UNVERIFIABLE');
  assert.match(trustRollback.reason, /rollback/u);
  await addApprover({ rootKeyPath: org.rootKey, trustRootPath: org.trustRoot, now: daysAfter(T0, 2), publicKeyPath: org.approverPub, name: 'Reviewer One', scopes: ['*'], expires: '180d' });
  await writeFile(org.revocations, oldRevocations);
  const revocationRollback = await check(org.policyPath, skill, daysAfter(T0, 2));
  assert.equal(revocationRollback.verdict, 'UNVERIFIABLE');
  assert.match(revocationRollback.reason, /revocation list version 1 is older/u);
});

test('a policy certificate directory works for Skills the organization does not modify', async (t) => {
  const org = await setupOrg(t);
  const skill = await writeSkill(await tempDir(t), 'third-party');
  await approve(org, skill, { out: path.join(org.certDir, 'third-party.cert.json') });
  const result = await check(org.policyPath, skill);
  assert.equal(result.verdict, 'VERIFIED');
  assert.equal(result.certificateSource, path.join(org.certDir, 'third-party.cert.json'));
});

test('a valid certificate wins over a stale one for the same Skill', async (t) => {
  const org = await setupOrg(t);
  const skill = await writeSkill(await tempDir(t), 'updated');
  await approve(org, skill, { out: path.join(org.certDir, 'updated.cert.json') });
  await writeFile(path.join(skill, 'extra.md'), 'new reference\n');
  assert.equal((await check(org.policyPath, skill)).verdict, 'UNAPPROVED_CHANGE');
  await approve(org, skill);
  assert.equal((await check(org.policyPath, skill)).verdict, 'VERIFIED');
});
