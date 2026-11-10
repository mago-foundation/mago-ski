// Administration rack phase 2b (docs/design/gui-admin-phase2.md, v12 P1-P8): Revoke, Refresh revocation list and Sign
// timestamp end to end against the real engine. No Electron: dialogs are fakes; races use handlers, not sleeps.
import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { updateRevocations } from '../../src/admin.ts';
import { readHostState, recordDocumentVersions } from '../../src/policy.ts';
import { adoptTrustDocuments, appendRootEvent, prepareRootEvent, signRootEvent } from '../../src/recovery-admin.ts';
import { addApprover } from '../../src/admin.ts';
import { approve, daysAfter, T0, writeSkill, type Key } from '../../tests/helpers.ts';
import { signDialog } from '../src/main/dialog-text.ts';
import { t as text } from '../src/i18n/messages.ts';
import { armTimestamp, armRoot, doc, failure, fileBytes, trust, world, NOW, type World } from './p2-world.ts';

const en = (key: Parameters<typeof text>[1], params?: Record<string, string | number>): string => text('en', key, params);
const KEY_A = `sha256:${'11'.repeat(32)}`;

async function rootEvent(w: World, action: 'revoke' | 'rotate', signers: Key[], extra: { newRoot?: Key } = {}): Promise<void> {
  const out = path.join(w.base, `event-${action}.json`);
  const eventNow = new Date(T0.getTime() + 60_000);
  await prepareRootEvent({
    policy: await w.policyOf(), action, reason: `${action} for test`, out, now: eventNow, signerPublicPaths: signers.map((k) => k.pub),
    ...(extra.newRoot ? { newRootPublicPath: extra.newRoot.pub } : {}),
  });
  for (const key of [...signers, ...(extra.newRoot ? [extra.newRoot] : [])]) await signRootEvent({ proposalPath: out, keyPath: key.priv });
  await appendRootEvent({ policy: await w.policyOf(), proposalPath: out, now: eventNow });
}

const revoke = (w: World, target: Parameters<World['session']['revoke']>[0]['target'], reason = 'lost laptop', lifetime: '7d' | '30d' = '30d') => w.session.revoke({ target, reason, lifetime });

test('revoke a current approver: targets, dialog, permanence, version, memory, verdicts', async (t) => {
  const w = await world(t, { lang: 'en' });
  await armRoot(w);
  const approverName = (await trust(w)).approvers[0]!.name;
  assert.deepEqual(await w.session.revocationTargets(), [{ kind: 'key', keyId: w.approverKeyId, label: approverName }]);
  const before = await w.session.revocations();
  assert.equal(before.ok, true);
  const result = await revoke(w, { kind: 'key', keyId: w.approverKeyId });
  assert.equal(result.ok, true, JSON.stringify(result));
  const summary = doc(w.calls.sign[0]);
  assert.equal(summary.action, 'revoke-key');
  assert.equal(summary.action === 'revoke-key' && summary.certificates, null);
  assert.equal(summary.consequence.changed, 4, 'every Skill in the pin, host and discovery folders loses its approver');
  assert.equal(summary.consequence.lines[0]!.to, 'REVOKED');
  const dialog = signDialog('en', summary);
  assert.equal(dialog.action, 'Revoke');
  assert.equal(dialog.detail.split('\n').at(-1), 'Revocation cannot be undone. Every certificate this key signed will permanently fail verification.');
  assert.ok(dialog.detail.includes(`Key to revoke: ${approverName} ${w.approverKeyId}`) && dialog.detail.includes('Reason: lost laptop'));
  const after = await w.session.revocations();
  assert.ok(before.ok && after.ok);
  if (before.ok && after.ok) {
    assert.equal(after.version, before.version + 1);
    assert.deepEqual(after.keys.map((k) => [k.keyId, k.reason]), [[w.approverKeyId, 'lost laptop']]);
    assert.equal(summary.document.versionTo, after.version);
  }
  assert.equal((await readHostState(w.stateFile)).roots[w.rootKeyId]?.revocations_version, after.ok ? after.version : -1, 'the new version is in this computer\'s memory');
  assert.deepEqual((await w.session.verifyAll()).counts, { REVOKED: 4 });
  assert.deepEqual(await w.session.revocationTargets(), [], 'an already revoked approver is no longer a target');
  assert.equal(failure(await revoke(w, { kind: 'key', keyId: w.approverKeyId })), en('admin.p2.err.alreadyRevoked'));
  assert.equal(w.calls.sign.length, 1, 'refused before any dialog');
});

test('revoke reasons are limited to 512 with the same message, and lifetimes are checked', async (t) => {
  const w = await world(t, { lang: 'en' });
  await armRoot(w);
  const before = await fileBytes(w.revocations);
  assert.equal(failure(await revoke(w, { kind: 'key', keyId: w.approverKeyId }, 'x'.repeat(513))), en('admin.err.reasonTooLong', { max: 512 }));
  assert.equal(failure(await revoke(w, { kind: 'key', keyId: w.approverKeyId }, '  ')), en('admin.err.needReason'));
  assert.match(failure(await revoke(w, { kind: 'key', keyId: w.approverKeyId }, 'a\nb c')), /without control characters/u);
  assert.equal(failure(await revoke(w, { kind: 'key', keyId: w.approverKeyId }, 'fine reason', '90d' as '7d')), en('admin.p2.err.badInput'));
  assert.equal(w.calls.sign.length, 0);
  assert.deepEqual(await fileBytes(w.revocations), before);
  // 512 exactly is accepted.
  assert.equal((await revoke(w, { kind: 'key', keyId: w.approverKeyId }, 'r'.repeat(512))).ok, true);
});

test('only the root role revokes, and a key that is not a current approver is refused', async (t) => {
  const w = await world(t, { lang: 'en' });
  assert.equal(failure(await revoke(w, { kind: 'key', keyId: w.approverKeyId })), en('admin.p2.why.needRoot'));
  assert.equal((await w.session.arm(w.approverKey)).ok, true);
  assert.match(failure(await revoke(w, { kind: 'key', keyId: w.approverKeyId })), /Only the root key may use this|root/u);
  await armRoot(w);
  assert.equal(failure(await revoke(w, { kind: 'key', keyId: KEY_A })), en('admin.p2.err.notATarget'));
  assert.equal(failure(await revoke(w, { kind: 'key', keyId: w.rootKeyId })), en('admin.p2.err.notATarget'), 'the root is not an approver, so it is no target at all');
  assert.equal(w.calls.sign.length, 0);
});

test('revoking a digest needs a review by the armed key; cancel and a refused commit give the record back; success consumes it', async (t) => {
  const w = await world(t, { lang: 'en' });
  await armRoot(w);
  const rows = await w.session.revocationSkills();
  assert.deepEqual(rows.map((r) => [r.name, r.instanceId, r.reviewed, r.error]), [['docs-helper', 'docs', false, null], ['pdf-tools', 'pdf', false, null]]);
  const digest = rows[0]!.digest!;
  assert.match(digest, /^sha256:[0-9a-f]{64}$/u);
  const target = { kind: 'digest' as const, digest, instanceId: 'docs' };
  assert.equal(failure(await revoke(w, target)), en('admin.err.needReview'));
  assert.equal((await w.session.review('docs')).ok, true);
  assert.equal((await w.session.revocationSkills())[0]!.reviewed, true);
  assert.deepEqual((await w.session.revocationTargets()).filter((x) => x.kind === 'digest'), [{ kind: 'digest', digest, skillName: 'docs-helper', instanceId: 'docs' }]);

  // Cancel: the record stays.
  w.handlers.sign = async () => false;
  assert.equal((await revoke(w, target)).ok, false);
  assert.equal((await w.session.revocationTargets()).filter((x) => x.kind === 'digest').length, 1);
  // The commit is refused after the confirm (the list changed during the dialog): the record is restored.
  w.handlers.sign = async () => { await updateRevocations({ rootKeyPath: w.rootPriv, revocationsPath: w.revocations, now: NOW, revokeKey: KEY_A, reason: 'other change' }); return true; };
  assert.equal(failure(await revoke(w, target)), en('admin.p2.err.changed'));
  assert.equal((await w.session.revocationTargets()).filter((x) => x.kind === 'digest').length, 1, 'restored after a refused commit');
  // The digest revoked is the reviewed one, and success consumes the record.
  w.handlers.sign = async () => true;
  const done = await revoke(w, target, 'bad release');
  assert.equal(done.ok, true, JSON.stringify(done));
  const summary = doc(w.calls.sign.at(-1));
  assert.equal(summary.action, 'revoke-digest');
  assert.equal(summary.action === 'revoke-digest' && summary.digest, digest);
  assert.equal(signDialog('en', summary).detail.split('\n').at(-1), 'Revocation cannot be undone. Every certificate for this version will permanently fail verification.');
  assert.deepEqual((await w.session.revocationTargets()).filter((x) => x.kind === 'digest'), []);
  assert.equal(failure(await revoke(w, target)), en('admin.err.needReview'), 'consumed');
  const view = await w.session.revocations();
  assert.ok(view.ok && view.digests.some((d) => d.digest === digest));
  const counts = (await w.session.verifyAll()).counts;
  assert.equal(counts.REVOKED, 1, 'only that Skill is revoked');
});

test('a review by another key is not usable, and a disarm during the dialog writes nothing and keeps no record', async (t) => {
  const w = await world(t, { lang: 'en' });
  assert.equal((await w.session.arm(w.approverKey)).ok, true);
  assert.equal((await w.session.review('docs')).ok, true);
  await armRoot(w);
  const digest = (await w.session.revocationSkills())[0]!.digest!;
  assert.equal((await w.session.revocationSkills())[0]!.reviewed, false, 'the approver\'s review does not count for the root');
  assert.equal(failure(await revoke(w, { kind: 'digest', digest, instanceId: 'docs' })), en('admin.err.needReview'));
  assert.equal((await w.session.review('docs')).ok, true);
  const before = await fileBytes(w.revocations);
  w.handlers.sign = async () => { w.session.disarm(); return true; };
  assert.equal((await revoke(w, { kind: 'digest', digest, instanceId: 'docs' })).ok, false);
  assert.deepEqual(await fileBytes(w.revocations), before);
  await armRoot(w);
  assert.deepEqual((await w.session.revocationTargets()).filter((x) => x.kind === 'digest'), [], 'the record died with the key');
});

test('approve gives its claimed record back when the commit is refused after the confirm', async (t) => {
  const w = await world(t, { lang: 'en' });
  assert.equal((await w.session.arm(w.approverKey)).ok, true);
  assert.equal((await w.session.review('docs')).ok, true);
  const digest = (await w.session.inspect('docs')).digest;
  w.handlers.sign = async () => { await writeFile(path.join(w.skills, 'docs-helper', 'SKILL.md'), '---\nname: docs-helper\ndescription: changed.\n---\nchanged\n'); return true; };
  const refused = await w.session.approve('docs', digest, '30d', 'reviewed carefully');
  assert.equal(refused.ok, false);
  w.handlers.sign = async () => true;
  assert.equal((await w.session.inspect('docs')).inspected, false, 'the new version is not the reviewed one');
  // The record is back for the old digest: approve fails on the changed version, not on a missing review.
  assert.notEqual(failure(await w.session.approve('docs', digest, '30d', 'reviewed carefully')), en('admin.err.needReview'));
});

test('another key chosen with the picker: label, certificate count, refusals, cancel writes nothing', async (t) => {
  const w = await world(t, { lang: 'en' });
  await armRoot(w);
  const stranger = await w.newKey('stranger');
  const extra = await writeSkill(w.skills, 'extra-skill');
  await approve({ approverKey: stranger.priv } as never, extra, { key: stranger.priv, out: path.join(w.certDir, 'extra-skill.cert.json'), now: T0 });
  const before = await fileBytes(w.revocations);

  w.handlers.pick = async () => ({ ok: false, reason: 'cancelled' });
  assert.equal(failure(await revoke(w, { kind: 'other' })), en('admin.p2.err.cancelled'));
  w.handlers.pick = async () => ({ ok: false, reason: 'unreadable' });
  assert.equal(failure(await revoke(w, { kind: 'other' })), en('admin.p2.err.publicKeyUnreadable'));
  assert.equal(w.calls.sign.length, 0);
  assert.deepEqual(await fileBytes(w.revocations), before);
  assert.equal(w.calls.pick, 2);

  w.pick({ pub: w.rootPub });
  assert.equal(failure(await revoke(w, { kind: 'other' })), en('admin.p2.err.cannotRevokeRole'), 'the active root');
  w.pick(stranger);
  const result = await revoke(w, { kind: 'other' });
  assert.equal(result.ok, true, JSON.stringify(result));
  const summary = doc(w.calls.sign.at(-1));
  assert.equal(summary.action === 'revoke-key' && summary.certificates, 1, 'one certificate names the picked key');
  assert.equal(summary.action === 'revoke-key' && summary.label, `${stranger.keyId} · not a current approver`);
  const detail = signDialog('en', summary).detail.split('\n');
  assert.equal(detail[4], `Key to revoke: ${stranger.keyId} · not a current approver ${stranger.keyId}`);
  assert.ok(detail.includes('Certificates naming this key: 1'));
  assert.equal(failure(await revoke(w, { kind: 'other' })), en('admin.p2.err.alreadyRevoked'));
  const view = await w.session.revocations();
  assert.ok(view.ok && view.keys.some((k) => k.keyId === stranger.keyId));
  // A current approver picked this way is named as one and has no certificate count.
  w.pick({ pub: w.approverPub });
  assert.equal((await revoke(w, { kind: 'other' })).ok, true);
  const named = doc(w.calls.sign.at(-1));
  assert.equal(named.action === 'revoke-key' && named.certificates, null);
  assert.notEqual(named.action === 'revoke-key' && named.label, `${w.approverKeyId} · not a current approver`);
});

test('recovery and timestamp keys cannot be revoked through the picker either', async (t) => {
  const w = await world(t, { recovery: true, freshness: true, lang: 'en' });
  await armRoot(w);
  for (const key of [w.recovery[0]!, w.timestamp!]) {
    w.pick(key);
    assert.equal(failure(await revoke(w, { kind: 'other' })), en('admin.p2.err.cannotRevokeRole'));
  }
  assert.equal(w.calls.sign.length, 0);
});

test('a forged certificate (bad signature) is never offered as a target, and a key it names cannot be revoked by id', async (t) => {
  const w = await world(t, { lang: 'en' });
  await armRoot(w);
  const original = JSON.parse(await readFile(path.join(w.certDir, 'docs-pin.cert.json'), 'utf8')) as { payload: string };
  const payload = JSON.parse(Buffer.from(original.payload, 'base64').toString('utf8')) as Record<string, unknown>;
  const forgedKey = `sha256:${'ee'.repeat(32)}`;
  payload.approver_key_id = forgedKey;
  await writeFile(path.join(w.certDir, 'docs-forged.cert.json'), JSON.stringify({ ...original, payload: Buffer.from(JSON.stringify(payload)).toString('base64') }));
  const targets = await w.session.revocationTargets();
  assert.equal(JSON.stringify(targets).includes(forgedKey), false);
  assert.equal(failure(await revoke(w, { kind: 'key', keyId: forgedKey })), en('admin.p2.err.notATarget'));
  assert.equal(w.calls.sign.length, 0);
});

test('refresh: an expired list is accepted, the dialog shows the previous expiry, the new list is current', async (t) => {
  const w = await world(t, { lang: 'en', now: daysAfter(T0, 40) });
  await armRoot(w);
  const before = await w.session.revocations();
  assert.ok(before.ok && before.expired);
  assert.equal((await w.session.verifyAll()).trustOk, false, 'an expired list stops the trust documents loading');
  const result = await w.session.refreshRevocations('7d');
  assert.equal(result.ok, true, JSON.stringify(result));
  const summary = doc(w.calls.sign[0]);
  assert.equal(summary.action, 'refresh-revocations');
  assert.equal(summary.action === 'refresh-revocations' && summary.expiresFrom, before.ok ? before.expiresAt : '');
  assert.equal(summary.consequence.fromFailed !== null, true, 'the current documents do not verify');
  assert.equal(summary.consequence.changed, 0);
  assert.deepEqual(summary.consequence.lines, []);
  assert.equal(summary.consequence.afterCounts.VERIFIED, 4, 'the dialog shows what signing restores');
  const lines = signDialog('en', summary).detail.split('\n');
  assert.ok(lines.some((l) => l.startsWith('The current documents do not verify: ')));
  assert.ok(lines.includes('VERIFIED 4 · other 0'));
  assert.equal(lines.some((l) => l.startsWith('Skills affected')), false, 'no head when the current documents do not verify');
  const after = await w.session.revocations();
  assert.ok(after.ok && !after.expired && before.ok && after.version === before.version + 1);
  assert.equal((await w.session.verifyAll()).trustOk, true);
  assert.equal(failure(await w.session.refreshRevocations('90d' as '7d')), en('admin.p2.err.badInput'));
});

test('refresh with the wrong role or a cancelled dialog writes nothing', async (t) => {
  const w = await world(t, { lang: 'en' });
  assert.equal((await w.session.arm(w.approverKey)).ok, true);
  assert.match(failure(await w.session.refreshRevocations('30d')), /root/u);
  await armRoot(w);
  const before = await fileBytes(w.revocations);
  w.handlers.sign = async () => false;
  assert.equal((await w.session.refreshRevocations('30d')).ok, false);
  assert.deepEqual(await fileBytes(w.revocations), before);
});

test('freshness organisation: a revoke blocks every Skill until Sign timestamp; the stale-timestamp dialog shows what signing restores', async (t) => {
  const w = await world(t, { recovery: true, freshness: true, lang: 'en' });
  await armRoot(w);
  const view = await w.session.timestamp();
  assert.ok(view.ok && view.configured && view.matches && view.readable && view.version === 1 && view.lifetimes.join() === '6h,12h,24h' && view.disabled === null && view.maxLifetime === '1d');
  const revoked = await revoke(w, { kind: 'key', keyId: w.approverKeyId });
  assert.equal(revoked.ok && revoked.needsTimestamp, true);
  const summary = doc(w.calls.sign[0]);
  assert.equal(summary.freshnessBlock, true);
  assert.ok(signDialog('en', summary).detail.includes('This organisation uses timestamps: hosts in enforce mode block every Skill until a new timestamp is signed.'));
  assert.equal(summary.consequence.lines[0]!.to, 'BLOCKED_UNTIL_TIMESTAMP');
  const check = await w.session.verifyAll();
  assert.equal(check.trustOk, false);
  assert.equal(check.timestampMismatch, true, 'POLICY CHECK reports the mismatch until Sign timestamp');
  const stale = await w.session.timestamp();
  assert.ok(stale.ok && stale.configured && !stale.matches);

  // The timestamp key is a different session: arming it drops the root key.
  await armTimestamp(w);
  assert.equal((await w.session.status()).armed?.role, 'timestamp');
  const trustBefore = await trust(w).catch(() => null);
  assert.ok(trustBefore);
  const signed = await w.session.signTimestamp('12h');
  assert.equal(signed.ok, true, JSON.stringify(signed));
  assert.equal(signed.ok && signed.needsTimestamp, false);
  const stamp = doc(w.calls.sign[1]);
  assert.equal(stamp.action, 'sign-timestamp');
  assert.equal(stamp.freshnessBlock, false, 'no freshness line in a timestamp dialog');
  assert.match(stamp.consequence.fromFailed ?? '', /freshness/u);
  assert.equal(stamp.consequence.changed, 0);
  assert.deepEqual(stamp.consequence.lines, []);
  assert.equal(stamp.consequence.afterCounts.REVOKED, 4);
  if (stamp.action === 'sign-timestamp') {
    assert.equal(stamp.documents.rootEvents.counter, 0, 'the walk\'s last sequence number');
    assert.equal(stamp.documents.trustRoot.counter, trustBefore.version);
    assert.equal(stamp.documents.revocations.counter, 2);
    assert.match(stamp.documents.revocations.sha256, /^sha256:[0-9a-f]{64}$/u);
    assert.equal(stamp.document.versionFrom, 1);
    assert.equal(stamp.document.versionTo, 2);
  }
  const dialog = signDialog('en', stamp).detail;
  assert.ok(dialog.includes('The current documents do not verify: freshness') && dialog.includes('REVOKED 4'));
  assert.equal(dialog.includes('This organisation uses timestamps'), false);
  assert.equal(dialog.includes('Skills affected'), false);
  const done = await w.session.timestamp();
  assert.ok(done.ok && done.configured && done.matches && done.version === 2);
  assert.equal((await w.session.verifyAll()).timestampMismatch, false);
  assert.equal((await readHostState(w.stateFile)).timestamps[w.timestamp!.keyId]?.version, 2, 'the timestamp version is in memory');
});

test('a timestamp that follows a root event marks the log as first seen, then records its progress (U3)', async (t) => {
  const w = await world(t, { recovery: true, freshness: true, lang: 'en' });
  await armTimestamp(w);
  const r1 = await w.keyFn!('r1');
  await rootEvent(w, 'rotate', [w.recovery[0]!, w.recovery[1]!], { newRoot: r1 });
  await adoptTrustDocuments({ rootKeyPath: r1.priv, fromRootKeyId: w.rootKeyId, trustRootPath: w.trustRoot, revocationsPath: w.revocations, now: new Date(T0.getTime() + 120_000) });
  assert.equal((await readHostState(w.stateFile)).rootEvents[w.rootKeyId], undefined, 'nothing has recorded the event yet');
  const result = await w.session.signTimestamp('24h');
  assert.equal(result.ok, true, JSON.stringify(result));
  const stamp = doc(w.calls.sign[0]);
  assert.ok(stamp.action === 'sign-timestamp' && stamp.documents.rootEvents.counter === 1 && stamp.documents.rootEvents.firstSeen === true);
  assert.ok(signDialog('en', stamp).detail.includes('(first seen by this computer)'));
  assert.equal(result.ok && result.memoryWarning, false);
  assert.equal((await readHostState(w.stateFile)).rootEvents[w.rootKeyId]?.sequence, 1, 'the progress is recorded with the ordinary rule');
});

test('sign timestamp refusals run in design order', async (t) => {
  // 1. The armed key: none, then the root.
  const w = await world(t, { recovery: true, freshness: true, lang: 'en' });
  assert.equal(failure(await w.session.signTimestamp('6h')), en('admin.err.needKey'));
  await armRoot(w);
  assert.match(failure(await w.session.signTimestamp('6h')), /needs the timestamp role; the armed key is root/u);
  // 2. No freshness: the view says so (the method is unreachable: only a freshness pin has a timestamp role).
  const plain = await world(t, { recovery: true, lang: 'en' });
  assert.deepEqual(await plain.session.timestamp(), { ok: true, configured: false });
  assert.equal(failure(await plain.session.signTimestamp('6h')), en('admin.err.needKey'));
  assert.equal(w.calls.sign.length, 0);
});

test('sign timestamp: revoked root, expired trust root, expired list, short maximum, stale, unreadable and to-failed, each before any dialog', async (t) => {
  // 3 beats 4: a revoked root with an expired trust root.
  const revoked = await world(t, { recovery: true, freshness: true, lang: 'en', now: daysAfter(T0, 400) });
  await rootEvent(revoked, 'revoke', [revoked.recovery[0]!]);
  await armTimestamp(revoked);
  const view = await revoked.session.timestamp();
  assert.ok(view.ok && view.configured && view.disabled === en('admin.p2.err.rootRevoked'));
  assert.equal(failure(await revoked.session.signTimestamp('6h')), en('admin.p2.err.rootRevoked'));

  // 4 beats 5: both documents expired.
  const both = await world(t, { recovery: true, freshness: true, lang: 'en', now: daysAfter(T0, 400) });
  await armTimestamp(both);
  assert.equal(failure(await both.session.signTimestamp('6h')), en('admin.p2.err.trustRootExpiredRenew'));
  // 5: only the revocation list.
  const list = await world(t, { recovery: true, freshness: true, lang: 'en', now: daysAfter(T0, 40) });
  await armTimestamp(list);
  assert.equal(failure(await list.session.signTimestamp('6h')), en('admin.p2.err.revocationsExpiredRefresh'));

  // 6: no allowed lifetime; and a lifetime above the maximum.
  const short = await world(t, { recovery: true, freshness: true, lang: 'en', maxLifetime: '1h' });
  await armTimestamp(short);
  const shortView = await short.session.timestamp();
  assert.ok(shortView.ok && shortView.configured && shortView.lifetimes.length === 0 && shortView.disabled === en('admin.p2.err.maxLifetimeShort'));
  assert.equal(failure(await short.session.signTimestamp('6h')), en('admin.p2.err.maxLifetimeShort'));
  const half = await world(t, { recovery: true, freshness: true, lang: 'en', maxLifetime: '12h' });
  await armTimestamp(half);
  const halfView = await half.session.timestamp();
  assert.ok(halfView.ok && halfView.configured && halfView.lifetimes.join() === '6h,12h');
  assert.equal(failure(await half.session.signTimestamp('24h')), en('admin.p2.err.badInput'));

  // 7: older than this computer's memory, and an unreadable current timestamp.
  const stale = await world(t, { recovery: true, freshness: true, lang: 'en' });
  await armTimestamp(stale);
  await recordDocumentVersions(stale.stateFile, { rootKeyId: stale.rootKeyId, revocations: 99 });
  assert.equal(failure(await stale.session.signTimestamp('6h')), en('admin.p2.err.stale'));
  const unreadable = await world(t, { recovery: true, freshness: true, lang: 'en' });
  await armTimestamp(unreadable);
  await writeFile(unreadable.timestampPath, 'not a timestamp');
  const unreadableView = await unreadable.session.timestamp();
  assert.ok(unreadableView.ok && unreadableView.configured && !unreadableView.readable && unreadableView.version === null);
  assert.equal(failure(await unreadable.session.signTimestamp('6h')), en('admin.p2.err.timestampUnreadable'));

  // 8: documents that a timestamp does not fix (a retired root key re-enrolled as an approver).
  const bad = await world(t, { recovery: true, freshness: true, lang: 'en' });
  await armTimestamp(bad);
  const r1 = await bad.keyFn!('r1');
  await rootEvent(bad, 'rotate', [bad.recovery[0]!, bad.recovery[1]!], { newRoot: r1 });
  await adoptTrustDocuments({ rootKeyPath: r1.priv, fromRootKeyId: bad.rootKeyId, trustRootPath: bad.trustRoot, revocationsPath: bad.revocations, now: new Date(T0.getTime() + 120_000) });
  await addApprover({ rootKeyPath: r1.priv, trustRootPath: bad.trustRoot, now: new Date(T0.getTime() + 180_000), publicKeyPath: bad.rootPub, name: 'Old root', scopes: ['*'], expires: '30d' });
  const refused = failure(await bad.session.signTimestamp('6h'));
  assert.ok(refused.startsWith('After signing, the documents would not verify: trust root lists approver'), refused);

  for (const x of [revoked, both, list, short, half, stale, unreadable, bad]) assert.equal(x.calls.sign.length, 0, 'no dialog opened');
});

test('previews and refused writes leave admin-state.json byte-identical (only reads record)', async (t) => {
  const w = await world(t, { recovery: true, freshness: true, lang: 'en' });
  await armRoot(w);
  await w.session.status();
  const snapshot = await fileBytes(w.stateFile);
  // A refused write, a cancelled dialog (which runs the whole preview), and the views.
  assert.equal((await revoke(w, { kind: 'key', keyId: w.approverKeyId }, 'x')).ok, false);
  w.handlers.sign = async () => false;
  assert.equal((await revoke(w, { kind: 'key', keyId: w.approverKeyId })).ok, false);
  assert.equal((await w.session.refreshRevocations('30d')).ok, false);
  await w.session.revocations(); await w.session.revocationTargets(); await w.session.revocationSkills(); await w.session.timestamp(); await w.session.verifyAll();
  assert.deepEqual(await fileBytes(w.stateFile), snapshot);
  await armTimestamp(w);
  await w.session.status();
  const second = await fileBytes(w.stateFile);
  assert.equal((await w.session.signTimestamp('6h')).ok, false, 'cancelled');
  assert.equal(failure(await w.session.signTimestamp('48h' as '6h')) !== '', true);
  assert.deepEqual(await fileBytes(w.stateFile), second);
});

test('a failure to record the version after a revoke or a timestamp is a memory warning, and the signature stands', async (t) => {
  const w = await world(t, { recovery: true, freshness: true, lang: 'en' });
  await armRoot(w);
  w.hooks.afterCommit = async () => { throw new Error('disk full'); };
  const result = await revoke(w, { kind: 'key', keyId: w.approverKeyId });
  assert.ok(result.ok && result.memoryWarning);
  const view = await w.session.revocations();
  assert.ok(view.ok && view.keys.length === 1);
  await armTimestamp(w);
  const stamped = await w.session.signTimestamp('6h');
  assert.ok(stamped.ok && stamped.memoryWarning);
});

test('cancel, timeout and a disarm during the signing dialog write nothing, for every 2b write', async (t) => {
  const w = await world(t, { recovery: true, freshness: true, lang: 'en', dialogTimeoutMs: 30 });
  await armRoot(w);
  const list = await fileBytes(w.revocations);
  let late!: Promise<boolean>;
  w.handlers.sign = async () => { late = new Promise<boolean>((resolve) => setTimeout(() => resolve(true), 120)); return await late; };
  assert.equal((await w.session.refreshRevocations('30d')).ok, false, 'timeout');
  assert.deepEqual(await fileBytes(w.revocations), list);
  await late;
  assert.deepEqual(await fileBytes(w.revocations), list, 'the late answer is ignored');
  await armTimestamp(w);
  const stamp = await fileBytes(w.timestampPath);
  w.handlers.sign = async () => { w.session.disarm(); return true; };
  assert.equal((await w.session.signTimestamp('6h')).ok, false);
  assert.deepEqual(await fileBytes(w.timestampPath), stamp);
});

test('the revocations view reads the list under the active root and reports stale versions', async (t) => {
  const w = await world(t, { lang: 'en' });
  const view = await w.session.revocations();
  assert.ok(view.ok && view.keys.length === 0 && view.digests.length === 0 && !view.stale && !view.expired && /^sha256:/u.test(view.sha256));
  await recordDocumentVersions(w.stateFile, { rootKeyId: w.rootKeyId, revocations: 50 });
  const stale = await w.session.revocations();
  assert.ok(stale.ok && stale.stale);
  assert.equal(failure(await armRoot(w).then(() => w.session.refreshRevocations('30d'))), en('admin.p2.err.stale'));
});
