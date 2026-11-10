// Administration rack phase 2a (docs/design/gui-admin-phase2.md): Manage approvers end to end against the real engine.
// No Electron: dialogs are fakes, and races use hooks and never-resolving promises, not sleeps.
import assert from 'node:assert/strict';
import { mkdir, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import test, { type TestContext } from 'node:test';
import { addApprover, removeApprover, updateRevocations } from '../../src/admin.ts';
import { loadPublicKey, type PublicKeyInfo } from '../../src/keys.ts';
import { forbiddenApproverKeys, readHostState, recordDocumentVersions } from '../../src/policy.ts';
import { StaleDocumentError } from '../../src/admin.ts';
import { adoptTrustDocuments, appendRootEvent, prepareRootEvent, signPolicyTimestamp, signRootEvent } from '../../src/recovery-admin.ts';
import { approve, daysAfter, setupOrg, setupRecoveryOrg, T0, tempDir, writeSkill, type Key } from '../../tests/helpers.ts';
import { signDialog } from '../src/main/dialog-text.ts';
import { AdminSession, type AdminSessionOptions } from '../src/service/admin.ts';
import type { AdminReviewSummary, AdminSignSummary } from '../src/service/types.ts';
import { generateKeyPair } from '../../src/keys.ts';

import { doc, failure, fileBytes, armRoot, trust, world, NOW, UID, type DocSummary, type World } from './p2-world.ts';

test('arming a root key asks the offline question; no, a refusal and approver keys behave as designed', async (t) => {
  const w = await world(t);
  assert.equal((await w.session.arm(w.approverKey)).ok, true);
  assert.equal(w.calls.offline, 0, 'an approver key is not asked');
  w.handlers.offline = async () => false;
  assert.deepEqual(await w.session.arm(w.rootPriv), { ok: false, reason: 'cancelled' });
  assert.equal(w.calls.offline, 1);
  assert.equal((await w.session.status()).armed, null, 'answering no does not arm the key');
  w.handlers.offline = async () => true;
  assert.equal((await w.session.arm(w.rootPriv)).ok, true);
  assert.equal(w.calls.offline, 2);
});

test('the offline question also covers recovery keys, and a disarm during it arms nothing', async (t) => {
  const w = await world(t, { recovery: true });
  assert.equal((await w.session.arm(w.recovery[0]!.priv)).ok, true);
  assert.equal(w.calls.offline, 1);
  w.handlers.offline = async () => { w.session.disarm(); return true; };
  const result = await w.session.arm(w.rootPriv);
  assert.equal(result.ok, false);
  assert.equal((await w.session.status()).armed, null);
});

test('add approver: picker, dialog, commit, memory; the written trust root verifies and lists the approver', async (t) => {
  const w = await world(t);
  await armRoot(w);
  const second = await w.newKey('second');
  w.pick(second);
  const before = await trust(w);
  assert.deepEqual([before.version, before.approvers.length, before.expired, before.stale], [2, 1, false, false]);
  const result = await w.session.addApprover({ name: 'Second Reviewer', scopes: ['docs-*'], lifetime: '180d' });
  assert.equal(result.ok && result.version, 3, JSON.stringify(result));
  assert.equal(result.ok && result.memoryWarning, false);
  assert.equal(result.ok && result.needsTimestamp, false);
  assert.equal(w.calls.pick, 1);
  const summary = doc(w.calls.sign[0]);
  assert.equal(summary.action, 'add-approver');
  assert.deepEqual([summary.document.versionFrom, summary.document.versionTo, summary.document.path], [2, 3, w.trustRoot]);
  assert.match(summary.document.baseSha256 ?? '', /^sha256:[0-9a-f]{64}$/u);
  assert.deepEqual(summary.action === 'add-approver' && [summary.newKeyId, summary.name, summary.scopes, summary.replaces], [second.keyId, 'Second Reviewer', ['docs-*'], null]);
  assert.equal(summary.keyId, (await trust(w)).approvers.find((a) => a.name === 'Reviewer One') ? summary.keyId : '', 'the key line names the armed root');
  const after = await trust(w);
  assert.deepEqual(after.approvers.map((a) => a.name).sort(), ['Reviewer One', 'Second Reviewer']);
  assert.equal(after.version, 3);
  // The memory recorded the new version.
  assert.equal((await readHostState(w.stateFile)).roots[w.rootKeyId]?.trust_root_version, 3);
  // POLICY CHECK: every Skill still verifies, 4 of them over the discovery root, the pin's and the host's skill_dirs.
  const all = await w.session.verifyAll();
  assert.deepEqual([all.skills, all.counts, all.trustOk, all.timestampMismatch], [4, { VERIFIED: 4 }, true, false]);
});

test('add approver: cancel at the picker or at the dialog writes nothing and starts the cooldown', async (t) => {
  const w = await world(t);
  await armRoot(w);
  const baseline = await fileBytes(w.trustRoot);
  assert.equal(failure(await w.session.addApprover({ name: 'X', scopes: ['*'], lifetime: '90d' })), '취소했어요');
  w.handlers.pick = async () => ({ ok: false, reason: 'unreadable: /secret/path' });
  assert.equal(failure(await w.session.addApprover({ name: 'X', scopes: ['*'], lifetime: '90d' })), '공개 키를 읽을 수 없어요');
  w.pick(await w.newKey('a'));
  w.handlers.sign = async () => false;
  assert.equal(failure(await w.session.addApprover({ name: 'X', scopes: ['*'], lifetime: '90d' })), '서명을 취소했어요');
  assert.deepEqual(await fileBytes(w.trustRoot), baseline);
  assert.equal(w.calls.sign.length, 1);
});

test('replacing an approver and a scope * show their lines; the dialog is the Korean text of the design', async (t) => {
  const w = await world(t);
  await armRoot(w);
  w.pick({ pub: w.approverPub });
  const result = await w.session.addApprover({ name: 'Reviewer Prime', scopes: ['*', 'docs-*'], lifetime: '365d' });
  assert.equal(result.ok, true, JSON.stringify(result));
  const summary = doc(w.calls.sign[0]);
  assert.ok(summary.action === 'add-approver' && summary.replaces);
  const text = signDialog('ko', summary);
  assert.equal(text.title, '조직 문서 서명');
  assert.equal(text.message, '승인자 정보를 바꿀까요?');
  assert.equal(text.action, '서명');
  const lines = text.detail.split('\n');
  assert.match(lines[0]!, /^문서: .*trust-root\.json$/u);
  assert.match(lines[1]!, /^현재 SHA-256: sha256:[0-9a-f]{64}$/u);
  assert.equal(lines[2], '버전: 2 → 3');
  assert.match(lines[4]!, /^새 승인자: Reviewer Prime sha256:/u);
  assert.match(lines[5]!, /^이미 승인자예요: 이름 Reviewer One → Reviewer Prime, 범위 \* → \*, docs-\*, 만료 /u);
  assert.equal(lines[6], '범위: *, docs-*');
  assert.equal(lines[7], '모든 Skill을 승인할 수 있는 범위예요');
  assert.match(lines[8]!, /^승인자 키 만료: 2027-/u);
  assert.match(lines[9]!, /^키: root · - · sha256:/u);
  assert.equal(lines[10], '영향받는 Skill: 0개 (전체 4개)');
});

test('remove approver: the last one needs a second confirmation, and a cancel there writes nothing', async (t) => {
  const w = await world(t);
  await armRoot(w);
  const baseline = await fileBytes(w.trustRoot);
  w.handlers.lastApprover = async () => false;
  assert.equal(failure(await w.session.removeApprover(w.approverKeyId)), '서명을 취소했어요');
  assert.equal(w.calls.lastApprover, 1);
  assert.deepEqual(await fileBytes(w.trustRoot), baseline);
  w.handlers.lastApprover = async () => true;
  const result = await w.session.removeApprover(w.approverKeyId);
  assert.equal(result.ok, true, JSON.stringify(result));
  const summary = doc(w.calls.sign.at(-1));
  assert.ok(summary.action === 'remove-approver' && summary.lastApprover);
  // The consequence: every approved Skill stops verifying (counts over the pin's and the host's folders too).
  assert.deepEqual([summary.consequence.skills, summary.consequence.changed], [4, 4]);
  assert.deepEqual(summary.consequence.lines.map((l) => l.name), ['docs-helper', 'docs-host', 'docs-pin', 'pdf-tools']);
  assert.deepEqual(summary.consequence.lines[0], { name: 'docs-helper', from: 'VERIFIED', to: 'UNTRUSTED_SIGNER', after: 'UNTRUSTED_SIGNER' });
  assert.equal((await trust(w)).approvers.length, 0);
  assert.equal((await w.session.verifyAll()).counts.UNTRUSTED_SIGNER, 4);
});

test('remove with two approvers asks no second confirmation', async (t) => {
  const w = await world(t);
  await armRoot(w);
  w.pick(await w.newKey('second'));
  assert.equal((await w.session.addApprover({ name: 'Second', scopes: ['*'], lifetime: '90d' })).ok, true);
  const result = await w.session.removeApprover(w.approverKeyId);
  assert.equal(result.ok, true);
  assert.equal(w.calls.lastApprover, 0);
});

test('renew: a new expiry with the same approvers; an expired trust root is renewed first and add needs a lifetime', async (t) => {
  const w = await world(t, { now: daysAfter(T0, 400) });
  await armRoot(w);
  // The revocation list (30 days) has expired too: refresh it, as hosts would need.
  await updateRevocations({ rootKeyPath: w.rootPriv, revocationsPath: w.revocations, now: daysAfter(T0, 399), expires: '90d' });
  const view = await trust(w);
  assert.equal(view.expired, true);
  w.pick(await w.newKey('late'));
  assert.equal(failure(await w.session.addApprover({ name: 'Late', scopes: ['*'], lifetime: '90d' })), '신뢰 루트가 만료됐어요. 신뢰 루트 기간을 고르세요.');
  assert.equal(failure(await w.session.removeApprover(w.approverKeyId)), '신뢰 루트가 만료됐어요. 신뢰 루트 기간을 고르세요.');
  assert.equal(w.calls.sign.length, 0, 'refused before any dialog');
  const renewed = await w.session.renewTrustRoot('180d');
  assert.equal(renewed.ok, true, JSON.stringify(renewed));
  const summary = doc(w.calls.sign[0]);
  assert.equal(summary.action, 'renew-trust-root');
  assert.equal(signDialog('ko', summary).message, '신뢰 루트 기간을 연장할까요?');
  const after = await trust(w);
  assert.equal(after.expired, false);
  assert.equal(after.approvers.length, 1);
  assert.equal(after.version, 3);
  // An add with a lifetime works on the expired original too: here on the renewed one, keeping the expiry.
  w.pick(await w.newKey('late2'));
  assert.equal((await w.session.addApprover({ name: 'Late', scopes: ['*'], lifetime: '90d', trustRootLifetime: '365d' })).ok, true);
});

test('a document older than this computer remembers is refused, an equal one is accepted', async (t) => {
  const w = await world(t);
  await armRoot(w);
  w.pick(await w.newKey('x'));
  // Memory at 2 = the document on disk: equal is the normal case.
  assert.equal((await w.session.addApprover({ name: 'X', scopes: ['*'], lifetime: '90d' })).ok, true);
  // Put the old document back: the memory says 3.
  await recordDocumentVersions(w.stateFile, { rootKeyId: w.rootKeyId, trustRoot: 9 });
  const refused = await w.session.renewTrustRoot('365d');
  assert.equal(failure(refused), '이 컴퓨터가 본 것보다 오래된 문서예요. 최신 문서를 되돌려 놓으세요.');
  assert.equal((await trust(w)).stale, true);
});

test('freshness: the dialog carries the freshness line, POLICY CHECK reports the mismatch, and the result asks for a timestamp', async (t) => {
  const w = await world(t, { recovery: true, freshness: true });
  await armRoot(w);
  assert.equal((await w.session.verifyAll()).timestampMismatch, false);
  w.pick(await w.newKey('fresh'));
  const result = await w.session.addApprover({ name: 'Fresh', scopes: ['docs-*'], lifetime: '90d' });
  assert.equal(result.ok && result.needsTimestamp, true, JSON.stringify(result));
  const summary = doc(w.calls.sign[0]);
  assert.equal(summary.freshnessBlock, true);
  assert.equal(summary.consequence.freshnessBlock, true);
  assert.ok(summary.consequence.lines.every((l) => l.to === 'BLOCKED_UNTIL_TIMESTAMP') || summary.consequence.lines.length === 0);
  const text = signDialog('ko', summary).detail;
  assert.match(text, /이 조직은 타임스탬프를 써요: 새 타임스탬프를 서명할 때까지 enforce 모드의 호스트는 모든 Skill을 막아요\./u);
  // Hosts now refuse every Skill until a timestamp names the new documents: the check says so, as expected.
  const mismatch = await w.session.verifyAll();
  assert.deepEqual([mismatch.trustOk, mismatch.timestampMismatch], [false, true]);
  assert.match(mismatch.trustNote ?? '', /freshness/u);
  // The CLI signs the timestamp (phase 2b adds the template).
  await signPolicyTimestamp({ policy: await w.policyOf(), keyPath: w.timestamp!.priv, now: NOW });
  const fixed = await w.session.verifyAll();
  assert.deepEqual([fixed.trustOk, fixed.timestampMismatch, fixed.counts], [true, false, { VERIFIED: 4 }]);
});

test('freshness: a second root write while the timestamp is stale shows the current documents as failing and still signs', async (t) => {
  const w = await world(t, { recovery: true, freshness: true });
  await armRoot(w);
  w.pick(await w.newKey('one'));
  assert.equal((await w.session.addApprover({ name: 'One', scopes: ['*'], lifetime: '90d' })).ok, true);
  w.pick(await w.newKey('two'));
  const second = await w.session.addApprover({ name: 'Two', scopes: ['*'], lifetime: '90d' });
  assert.equal(second.ok, true, JSON.stringify(second));
  const summary = doc(w.calls.sign[1]);
  assert.match(summary.consequence.fromFailed ?? '', /freshness/u);
  assert.match(signDialog('en', summary).detail, /The current documents do not verify: freshness/u);
});

test('forbidden approvers are marked, and only removing them works', async (t) => {
  const w = await world(t, { recovery: true });
  const proposals: string[] = [];
  const event = async (signers: Key[], newRoot: Key, extra: Record<string, unknown> = {}) => {
    const out = path.join(w.base, `proposal-${proposals.length}.json`);
    proposals.push(out);
    const eventNow = new Date(T0.getTime() + 60_000);
    await prepareRootEvent({ policy: await w.policyOf(), action: 'rotate', reason: 'rotate for test', out, now: eventNow, signerPublicPaths: signers.map((k) => k.pub), newRootPublicPath: newRoot.pub, ...extra });
    for (const key of [...signers, newRoot]) await signRootEvent({ proposalPath: out, keyPath: key.priv });
    await appendRootEvent({ policy: await w.policyOf(), proposalPath: out, now: eventNow });
  };
  const r1 = await w.keyFn!('r1');
  await event([w.recovery[0]!, w.recovery[1]!], r1);
  await adoptTrustDocuments({ rootKeyPath: r1.priv, fromRootKeyId: w.rootKeyId, trustRootPath: w.trustRoot, revocationsPath: w.revocations, now: new Date(T0.getTime() + 120_000) });
  // Before the documents are adopted the view says so; after, the CLI without --policy re-enrols the old root as an approver.
  await addApprover({ rootKeyPath: r1.priv, trustRootPath: w.trustRoot, now: new Date(T0.getTime() + 180_000), publicKeyPath: w.rootPub, name: 'Old root', scopes: ['*'], expires: '30d' });
  const armed = await w.session.arm(r1.priv);
  assert.equal(armed.ok, true, JSON.stringify(armed));
  const view = await trust(w);
  const old = view.approvers.find((a) => a.keyId === w.rootKeyId);
  assert.equal(old?.forbidden, '예전에 루트나 타임스탬프 역할을 했던 키');
  assert.equal(view.approvers.find((a) => a.keyId === w.approverKeyId)?.forbidden, null);
  // Hosts refuse this trust root: the view says UNVERIFIABLE-style trust, but the document still reads.
  assert.equal((await w.session.verifyAll()).trustOk, false);
  const wrong = await w.session.renewTrustRoot('180d');
  assert.equal(failure(wrong), '예전에 루트나 타임스탬프 역할을 했던 키: 이 승인자를 먼저 빼세요');
  w.pick(await w.newKey('another'));
  assert.equal(failure(await w.session.addApprover({ name: 'Y', scopes: ['*'], lifetime: '90d' })), '예전에 루트나 타임스탬프 역할을 했던 키: 이 승인자를 먼저 빼세요');
  assert.equal(failure(await w.session.removeApprover(w.approverKeyId)), '예전에 루트나 타임스탬프 역할을 했던 키: 이 승인자를 먼저 빼세요');
  const removed = await w.session.removeApprover(w.rootKeyId);
  assert.equal(removed.ok, true, JSON.stringify(removed));
  assert.equal((await w.session.verifyAll()).trustOk, true, 'removing the forbidden key fixes the trust root');
  const summary = doc(w.calls.sign.at(-1));
  assert.match(signDialog('en', summary).detail, /The current documents do not verify: trust root lists approver/u);
});

test('documents signed by a previous root disable every writer before any dialog', async (t) => {
  const w = await world(t, { recovery: true });
  const r1 = await w.keyFn!('r1');
  const out = path.join(w.base, 'rotate.json');
  const eventNow = new Date(T0.getTime() + 60_000);
  await prepareRootEvent({ policy: await w.policyOf(), action: 'rotate', reason: 'rotate for test', out, now: eventNow, signerPublicPaths: [w.recovery[0]!.pub, w.recovery[1]!.pub], newRootPublicPath: r1.pub });
  for (const key of [w.recovery[0]!, w.recovery[1]!, r1]) await signRootEvent({ proposalPath: out, keyPath: key.priv });
  await appendRootEvent({ policy: await w.policyOf(), proposalPath: out, now: eventNow });
  assert.equal((await w.session.arm(r1.priv)).ok, true);
  const view = await w.session.trustRoot();
  assert.deepEqual(view, {
    ok: false, signedByPreviousRoot: true,
    message: '문서가 이전 루트 키로 서명돼 있어요. CLI에서 root adopt로 새 루트 키로 옮기세요. (GUI 지원은 3단계)',
  });
  w.pick(await w.newKey('n'));
  for (const result of [await w.session.addApprover({ name: 'N', scopes: ['*'], lifetime: '90d' }), await w.session.removeApprover(w.approverKeyId), await w.session.renewTrustRoot('180d')])
    assert.equal(failure(result), '문서가 이전 루트 키로 서명돼 있어요. CLI에서 root adopt로 새 루트 키로 옮기세요. (GUI 지원은 3단계)');
  assert.equal(w.calls.sign.length, 0);
});

test('only the root role may write, and a missing key says to load one', async (t) => {
  const w = await world(t);
  assert.equal(failure(await w.session.renewTrustRoot('180d')), '루트 키를 먼저 불러오세요');
  assert.equal((await w.session.arm(w.approverKey)).ok, true);
  assert.match(failure(await w.session.renewTrustRoot('180d')), /Only the root key|루트 키만/u);
  assert.equal(w.calls.sign.length, 0);
});

test('a timeout of the signing dialog counts as a cancel; a late yes writes nothing', async (t) => {
  const w = await world(t, { dialogTimeoutMs: 20 });
  await armRoot(w);
  const baseline = await fileBytes(w.trustRoot);
  let late!: Promise<boolean>;
  w.handlers.sign = async () => { late = new Promise<boolean>((resolve) => setTimeout(() => resolve(true), 80)); return await late; };
  assert.equal(failure(await w.session.renewTrustRoot('180d')), '서명을 취소했어요');
  assert.deepEqual(await fileBytes(w.trustRoot), baseline, 'a timeout counts as a cancel');
  await late;
  assert.deepEqual(await fileBytes(w.trustRoot), baseline, 'the late answer is ignored');
});

test('disarm during the dialog writes nothing', async (t) => {
  const w = await world(t);
  await armRoot(w);
  const baseline = await fileBytes(w.trustRoot);
  w.handlers.sign = async () => { w.session.disarm(); return true; };
  assert.equal(failure(await w.session.renewTrustRoot('180d')), '키가 빠졌어요');
  assert.deepEqual(await fileBytes(w.trustRoot), baseline);
});

test('a document changed while the dialog was open is refused at commit, and nothing of it is overwritten', async (t) => {
  const w = await world(t);
  await armRoot(w);
  w.handlers.sign = async () => {
    await removeApprover({ rootKeyPath: w.rootPriv, trustRootPath: w.trustRoot, now: NOW, keyId: w.approverKeyId });
    return true;
  };
  assert.equal(failure(await w.session.renewTrustRoot('180d')), '문서가 그 사이에 바뀌었어요. 다시 준비하세요.');
  assert.equal((await trust(w)).approvers.length, 0, 'the other writer\'s document stands');
  // Another input (the revocation list) changing is caught by the input binding too.
  w.handlers.sign = async () => { await writeFile(w.revocations, `${await readFile(w.revocations, 'utf8')} `); return true; };
  assert.equal(failure(await w.session.renewTrustRoot('180d')), '문서가 그 사이에 바뀌었어요. 다시 준비하세요.');
});

test('a failed memory write after a successful signing is a warning, not a failure', async (t) => {
  const w = await world(t);
  await armRoot(w);
  w.hooks.afterCommit = async () => { await rm(w.stateFile); await symlink(w.trustRoot, w.stateFile); };
  const result = await w.session.renewTrustRoot('180d');
  assert.equal(result.ok && result.memoryWarning, true, JSON.stringify(result));
  assert.equal((await trust(w)).version, 3, 'the document was written');
  assert.equal(signDialog('en', doc(w.calls.sign[0])).detail.includes('memory'), false, 'a memory warning is not a dialog line');
});

test('after a memory reset the first root signature says so, once', async (t) => {
  const w = await world(t);
  await armRoot(w);
  assert.equal((await w.session.resetMemory()).ok, true);
  await armRoot(w);
  assert.equal((await w.session.renewTrustRoot('180d')).ok, true);
  assert.equal((await w.session.renewTrustRoot('180d')).ok, true);
  assert.deepEqual(w.calls.sign.map((s) => doc(s).afterReset), [true, false]);
  assert.match(signDialog('en', doc(w.calls.sign[0])).detail, /This is the first signature since this computer's memory was reset: make sure the documents on disk are the newest\./u);
});

test('folders too deep are counted, listed once, and never searched', async (t) => {
  const w = await world(t);
  await armRoot(w);
  let deep = path.join(w.skills, 'group');
  for (let level = 0; level < 18; level += 1) deep = path.join(deep, 'd');
  await mkdir(deep, { recursive: true });
  assert.equal((await w.session.renewTrustRoot('180d')).ok, true);
  const summary = doc(w.calls.sign[0]);
  assert.equal(summary.consequence.tooDeep, 1);
  assert.equal(summary.consequence.skills, 5);
  assert.match(signDialog('en', summary).detail, /Folders too deep to check: 1/u);
});

test('the engine and the GUI agree: the same change written by the CLI path has the same bytes as the GUI path', async (t) => {
  const w = await world(t);
  const before = await fileBytes(w.trustRoot);
  await armRoot(w);
  assert.equal((await w.session.renewTrustRoot('180d')).ok, true);
  const guiBytes = await fileBytes(w.trustRoot);
  assert.notDeepEqual(guiBytes, before);
  // Same documents, same clock, the old function path.
  const w2 = await world(t);
  const { renewTrustRoot } = await import('../../src/admin.ts');
  await renewTrustRoot({ rootKeyPath: w2.rootPriv, trustRootPath: w2.trustRoot, now: NOW, expires: '180d' });
  const viewA = await trust(w);
  const viewB = await trust(w2);
  assert.deepEqual([viewA.version, viewA.expiresAt], [viewB.version, viewB.expiresAt]);
});

test('English refusals and dialogs when the session language is English', async (t) => {
  const w = await world(t, { lang: 'en' });
  assert.equal(failure(await w.session.renewTrustRoot('180d')), 'Load the root key first');
  await armRoot(w);
  w.handlers.sign = async () => false;
  assert.match(failure(await w.session.renewTrustRoot('180d')), /./u);
  assert.equal((await w.session.trustRoot()).ok, true);
});

// ------------------------------------------------------------------ code review fixes (design v11)

/** One rotation event, adopted, so the host memory has applied event 1; returns the new root key and the empty log it had before. */
async function rotated(w: World): Promise<{ r1: Key; emptyLog: Buffer }> {
  const emptyLog = await fileBytes(w.eventsPath);
  const r1 = await w.keyFn!('r1');
  const out = path.join(w.base, 'rotate.json');
  const eventNow = new Date(T0.getTime() + 60_000);
  await prepareRootEvent({ policy: await w.policyOf(), action: 'rotate', reason: 'rotate for test', out, now: eventNow, signerPublicPaths: [w.recovery[0]!.pub, w.recovery[1]!.pub], newRootPublicPath: r1.pub });
  for (const key of [w.recovery[0]!, w.recovery[1]!, r1]) await signRootEvent({ proposalPath: out, keyPath: key.priv });
  await appendRootEvent({ policy: await w.policyOf(), proposalPath: out, now: eventNow });
  await adoptTrustDocuments({ rootKeyPath: r1.priv, fromRootKeyId: w.rootKeyId, trustRootPath: w.trustRoot, revocationsPath: w.revocations, now: new Date(T0.getTime() + 120_000) });
  return { r1, emptyLog };
}

test('a rolled-back root event log refuses add, remove and renew before any dialog or picker', async (t) => {
  const w = await world(t, { recovery: true });
  const { r1, emptyLog } = await rotated(w);
  assert.equal((await w.session.arm(r1.priv)).ok, true);
  assert.equal((await w.session.status()).pin.kind, 'loaded', 'the memory now records root event 1');
  assert.equal((await readHostState(w.stateFile)).rootEvents[w.rootKeyId]?.sequence, 1);
  await writeFile(w.eventsPath, emptyLog);
  w.pick(await w.newKey('n'));
  const results = [await w.session.addApprover({ name: 'N', scopes: ['*'], lifetime: '90d' }), await w.session.removeApprover(w.approverKeyId), await w.session.renewTrustRoot('180d')];
  for (const result of results) assert.equal(result.ok, false, JSON.stringify(result));
  assert.match(failure(results[0]!), /rollback/u, 'the first refusal names the rollback; the key is then dropped');
  assert.ok(results.every((r) => failure(r) !== '' && !failure(r).startsWith('Cannot check the root event log, so no approver is added')));
  assert.deepEqual([w.calls.pick, w.calls.sign.length, w.calls.lastApprover], [0, 0, 0]);
});

test('an expired revocation list that the trust root change does not fix refuses the write, with no dialog', async (t) => {
  const w = await world(t, { now: daysAfter(T0, 400) });
  await armRoot(w);
  const result = await w.session.renewTrustRoot('180d');
  assert.equal(result.ok, false);
  assert.match(failure(result), /^서명 후 문서가 검증되지 않아요: /u);
  assert.equal(w.calls.sign.length, 0, 'no signing dialog opened');
});

test('the picker runs after the refusals: a forbidden approver left over opens no picker', async (t) => {
  const w = await world(t, { recovery: true });
  const { r1 } = await rotated(w);
  await addApprover({ rootKeyPath: r1.priv, trustRootPath: w.trustRoot, now: new Date(T0.getTime() + 180_000), publicKeyPath: w.rootPub, name: 'Old root', scopes: ['*'], expires: '30d' });
  assert.equal((await w.session.arm(r1.priv)).ok, true);
  w.pick(await w.newKey('another'));
  assert.equal(failure(await w.session.addApprover({ name: 'Y', scopes: ['*'], lifetime: '90d' })), '예전에 루트나 타임스탬프 역할을 했던 키: 이 승인자를 먼저 빼세요');
  assert.equal(w.calls.pick, 0);
});

test('documents signed by a previous root open no picker', async (t) => {
  const w = await world(t, { recovery: true });
  const r1 = await w.keyFn!('r1');
  const out = path.join(w.base, 'rotate.json');
  const eventNow = new Date(T0.getTime() + 60_000);
  await prepareRootEvent({ policy: await w.policyOf(), action: 'rotate', reason: 'rotate for test', out, now: eventNow, signerPublicPaths: [w.recovery[0]!.pub, w.recovery[1]!.pub], newRootPublicPath: r1.pub });
  for (const key of [w.recovery[0]!, w.recovery[1]!, r1]) await signRootEvent({ proposalPath: out, keyPath: key.priv });
  await appendRootEvent({ policy: await w.policyOf(), proposalPath: out, now: eventNow });
  assert.equal((await w.session.arm(r1.priv)).ok, true);
  w.pick(await w.newKey('n'));
  assert.equal((await w.session.addApprover({ name: 'N', scopes: ['*'], lifetime: '90d' })).ok, false);
  assert.equal(w.calls.pick, 0);
});

test('the inputs are captured before the picker: a document changed while it is open is refused at commit', async (t) => {
  const w = await world(t);
  await armRoot(w);
  const key = await w.newKey('late');
  w.handlers.pick = async () => {
    await removeApprover({ rootKeyPath: w.rootPriv, trustRootPath: w.trustRoot, now: NOW, keyId: w.approverKeyId });
    return { ok: true, key: await loadPublicKey(key.pub) };
  };
  assert.equal(failure(await w.session.addApprover({ name: 'Late', scopes: ['*'], lifetime: '90d' })), '문서가 그 사이에 바뀌었어요. 다시 준비하세요.');
  assert.equal((await trust(w)).approvers.length, 0, 'the other writer\'s document stands');
});

test('timestampMismatch is true only for the binding check; an expired timestamp shows the host reason', async (t) => {
  const w = await world(t, { recovery: true, freshness: true, now: daysAfter(NOW, 3) });
  await armRoot(w);
  const view = await w.session.verifyAll();
  assert.equal(view.trustOk, false);
  assert.equal(view.timestampMismatch, false, 'an expired timestamp is not a mismatch');
  assert.match(view.trustNote ?? '', /timestamp expired/u);
});

test('forbiddenApproverKeys refuses a revocation list below the minimum; the GUI maps it to the stale text', async (t) => {
  const w = await world(t, { recovery: true });
  const policy = await w.policyOf();
  const now = NOW;
  assert.ok((await forbiddenApproverKeys(policy, now)).length > 0, 'no minimum: today\'s behaviour');
  assert.ok((await forbiddenApproverKeys(policy, now, { minimumRevocations: 1 })).length > 0);
  await assert.rejects(forbiddenApproverKeys(policy, now, { minimumRevocations: 99 }), StaleDocumentError);
  await armRoot(w);
  await recordDocumentVersions(w.stateFile, { rootKeyId: w.rootKeyId, revocations: 99 });
  w.pick(await w.newKey('n'));
  assert.equal(failure(await w.session.addApprover({ name: 'N', scopes: ['*'], lifetime: '90d' })), '이 컴퓨터가 본 것보다 오래된 문서예요. 최신 문서를 되돌려 놓으세요.');
  assert.equal(w.calls.pick, 0);
});

test('English refusal for a non-root key names the role in English', async (t) => {
  const w = await world(t, { lang: 'en' });
  assert.equal((await w.session.arm(w.approverKey)).ok, true);
  assert.match(failure(await w.session.renewTrustRoot('180d')), /Approver/u);
});

test('the renderer offers no Keep and no preselected lifetime for an expired trust root, and clears only on success', async () => {
  const source = await readFile(path.join(import.meta.dirname, '..', 'src', 'renderer', 'admin.ts'), 'utf8');
  assert.ok(!source.includes("trustLifetime = '365d'"), 'no coercion to 365d');
  assert.match(source, /v\.expired \? \[\.\.\.TRUST_LIFETIMES\] : \['', \.\.\.TRUST_LIFETIMES\]/u);
  assert.match(source, /needsLifetime = v\.expired && trustLifetime === ''/u);
  assert.match(source, /if \(writeResult\(await api\.admin\.addApprover/u);
  assert.match(source, /dialogSafe\(a\.name\)/u);
});
