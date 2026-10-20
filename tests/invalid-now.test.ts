import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test, { type TestContext } from 'node:test';
import { verifyRevocations } from '../src/revocations.ts';
import { collectSkillTree } from '../src/tree-digest.ts';
import { verifyTrustRoot } from '../src/trust-root.ts';
import {
  decide, decideStreaming, evaluateCertificate, loadTrustContext, unverifiable, verifySkill,
} from '../src/verify.ts';
import { approve, daysAfter, setupOrg, T0, tempDir, writeSkill } from './helpers.ts';

/*
 * An invalid Date holds NaN, and every comparison with NaN is false, so each "reject if expired"
 * check would pass. These are three common ways a host ends up with one.
 */
const INVALID_CLOCKS: Array<[string, Date]> = [
  ['NaN', new Date(Number.NaN)],
  ['an impossible date string', new Date('2026-13-01')],
  ['an unset environment variable', new Date(undefined as unknown as string)],
];

const BAD_CLOCK = /Verification time must be a valid date/u;

/** One organisation and one approved Skill, every document issued at T0. */
async function fixture(t: TestContext) {
  const org = await setupOrg(t);
  const skillDir = await writeSkill(await tempDir(t), 'demo');
  const certificatePath = (await approve(org, skillDir)).path;

  const trustRootBytes   = await readFile(org.trustRoot);
  const revocationsBytes = await readFile(org.revocations);
  const certificate      = { source: certificatePath, bytes: await readFile(certificatePath) };
  const tree             = await collectSkillTree(skillDir);

  /** Loads the trust documents as a host would at time `now`. */
  const loadTrust = (now: Date) =>
    loadTrustContext({ trustRootBytes, revocationsBytes, rootKeyId: org.rootKeyId, now });

  // A context loaded with a valid clock, so each function below is tested on its own.
  const loaded = loadTrust(daysAfter(T0, 1));
  assert.ok(loaded.ok);

  return {
    org, skillDir, trustRootBytes, revocationsBytes, certificate, tree, loadTrust,
    context: loaded.context,
  };
}

test('every check against the current time refuses an invalid clock', async (t) => {
  const f = await fixture(t);
  const certificates = [f.certificate];

  for (const [source, now] of INVALID_CLOCKS) {
    const trust = f.loadTrust(now);
    assert.equal(trust.ok, false, source);
    if (!trust.ok) {
      assert.equal(trust.verdict, 'UNVERIFIABLE', source);
      assert.match(trust.reason, BAD_CLOCK, source);
    }

    const trustRootCheck = () => verifyTrustRoot(f.trustRootBytes, f.org.rootKeyId, now);
    assert.throws(trustRootCheck, BAD_CLOCK, source);

    const revocationsCheck = () => verifyRevocations(f.revocationsBytes, f.context.trustRoot, now);
    assert.throws(revocationsCheck, BAD_CLOCK, source);

    const certificateCheck = () =>
      evaluateCertificate(f.certificate.bytes, 'demo', f.tree.digest, f.context, now);
    assert.throws(certificateCheck, BAD_CLOCK, source);

    const options = {
      skillDir: f.skillDir, skillName: 'demo', tree: f.tree, certificates, context: f.context, now,
    };
    assert.throws(() => decide(options), BAD_CLOCK, source);
    await assert.rejects(decideStreaming(options), BAD_CLOCK, source);

    const fullCheck = verifySkill({ skillDir: f.skillDir, certificates, context: f.context, now });
    await assert.rejects(fullCheck, BAD_CLOCK, source);

    assert.throws(() => unverifiable(f.skillDir, 'demo', 'reason', now), BAD_CLOCK, source);
  }
});

test('a valid clock still verifies on time and expires on time', async (t) => {
  const f = await fixture(t);
  const certificates = [f.certificate];

  const verified = await verifySkill({
    skillDir: f.skillDir, certificates, context: f.context, now: daysAfter(T0, 1),
  });
  assert.equal(verified.verdict, 'VERIFIED');

  // The certificate lasts 90 days. The context loaded at T0 + 1 day is reused on purpose.
  const day91 = daysAfter(T0, 91);
  const expired = evaluateCertificate(f.certificate.bytes, 'demo', f.tree.digest, f.context, day91);
  assert.equal(expired.verdict, 'EXPIRED');

  // 400 days on, the trust root (365 days) has expired too.
  const late = f.loadTrust(daysAfter(T0, 400));
  assert.equal(late.ok, false);
  if (!late.ok)
    assert.equal(late.verdict, 'EXPIRED');
});
