// The native dialog texts: Korean is exactly what the dialogs always showed; English has no Hangul and still states every
// value that is inserted (digest, key id, reason, ...). Nothing here needs Electron.
import assert from 'node:assert/strict';
import test from 'node:test';
import {
  cancelLabel, consequenceLines, keyPickerAllFiles, keyPickerTitle, lastApproverDialog, notificationGrouped, offlineDialog, publicKeyPickerTitle, notificationImmediate, resetDialog, reviewDialog,
  rootPickerTitle, signDialog, startFailure,
} from '../src/main/dialog-text.ts';
import type { AdminConsequence, AdminReviewSummary, AdminSignSummary } from '../src/service/types.ts';

const HANGUL = /[ᄀ-ᇿ㄰-㆏가-힯]/u;
const DIGEST = `sha256:${'ab'.repeat(32)}`;
const OTHER = `sha256:${'cd'.repeat(32)}`;
const KEY_ID = `sha256:${'ef'.repeat(32)}`;

const review: AdminReviewSummary = { skillName: 'docs-helper', skillPath: '/home/u/skills/docs-helper', digest: DIGEST, files: 7 };
const sign: AdminSignSummary = {
  action: 'approve', skillName: 'docs-helper', skillPath: '/home/u/skills/docs-helper', reviewedDigest: DIGEST, digest: OTHER, lifetime: '90d',
  expiresAt: '2027-02-10T00:00:00Z', reason: 'read every file, no network calls', role: 'approver', keyName: 'alice', keyId: KEY_ID,
};

test('review dialog: Korean is the original text', () => {
  assert.deepEqual(reviewDialog('ko', review), {
    title: 'Skill 검토 확인', message: '이 정확한 버전의 파일을 모두 검토했나요?', action: '검토함',
    detail: ['Skill: docs-helper', '폴더: /home/u/skills/docs-helper', `버전: ${DIGEST}`, '파일: 7개'].join('\n'),
  });
  assert.equal(cancelLabel('ko'), '취소');
});

test('review dialog: English has no Hangul and states every value', () => {
  const d = reviewDialog('en', review);
  for (const text of [d.title, d.message, d.detail, d.action]) assert.doesNotMatch(text, HANGUL);
  assert.equal(d.action, 'Reviewed');
  for (const value of ['docs-helper', '/home/u/skills/docs-helper', DIGEST, '7']) assert.ok(d.detail.includes(value), value);
  assert.equal(cancelLabel('en'), 'Cancel');
});

test('sign dialog: Korean is the original text', () => {
  assert.deepEqual(signDialog('ko', sign), {
    title: '인증서 서명', message: '이 Skill 버전에 인증서를 서명할까요?', action: '서명',
    detail: [
      'Skill: docs-helper', '폴더: /home/u/skills/docs-helper', `검토한 버전: ${DIGEST}`, `서명할 버전: ${OTHER}`,
      '기간: 90d (만료 2027-02-10T00:00:00Z)', '이유: read every file, no network calls', `키: approver · alice · ${KEY_ID}`,
    ].join('\n'),
  });
  assert.equal(signDialog('ko', { ...sign, keyName: null }).detail.split('\n').at(-1), `키: approver · - · ${KEY_ID}`);
});

test('sign dialog: English has no Hangul and states the reviewed and the signed digest, the lifetime, the reason and the key', () => {
  const d = signDialog('en', sign);
  for (const text of [d.title, d.message, d.detail, d.action]) assert.doesNotMatch(text, HANGUL);
  assert.equal(d.action, 'Sign');
  assert.match(d.message, /certificate/u);
  for (const value of [DIGEST, OTHER, KEY_ID, 'read every file, no network calls', '90d', '2027-02-10T00:00:00Z', 'approver', 'alice', 'docs-helper', '/home/u/skills/docs-helper'])
    assert.ok(d.detail.includes(value), value);
  // The reviewed and the signed version are labelled differently, so a mismatch is visible.
  assert.match(d.detail, /Reviewed version: sha256:abab/u);
  assert.match(d.detail, /Version to sign: sha256:cdcd/u);
});

test('dialogs insert untrusted values through dialogSafe in both languages', () => {
  const hostile = { ...sign, skillName: 'a\nb‮c', skillPath: '/x\u0085y', reason: 'ok​go', keyName: 'k\nm' };
  for (const lang of ['ko', 'en'] as const) {
    const d = signDialog(lang, hostile);
    assert.equal(d.detail.split('\n').length, 7, lang);
    assert.ok(d.detail.includes('a⟨U+000A⟩b⟨U+202E⟩c'), lang);
    assert.ok(d.detail.includes('/x⟨U+0085⟩y'), lang);
    assert.ok(d.detail.includes('ok⟨U+200B⟩go'), lang);
    assert.ok(d.detail.includes('k⟨U+000A⟩m'), lang);
  }
});

test('reset dialog, pickers, notifications and the start failure', () => {
  assert.deepEqual(resetDialog('ko'), {
    title: '기록 초기화', message: '이 컴퓨터가 기억하는 조직 문서 버전을 지울까요? 오래된 문서를 다시 받아들일 수 있게 돼요.',
    detail: '초기화하면 루트 문서를 쓸 때 지금 디스크에 있는 문서를 기준으로 삼아요.', action: '초기화',
  });
  const en = resetDialog('en');
  for (const text of [en.title, en.message, en.detail, en.action]) assert.doesNotMatch(text, HANGUL);
  assert.equal(en.title, 'Reset memory');
  assert.match(en.message, /older documents/u);
  assert.equal(en.detail, 'After a reset, root document writes take the documents now on disk as their base.');

  assert.equal(keyPickerTitle('ko'), '서명 키 불러오기 (개인 키 PEM)');
  assert.equal(keyPickerAllFiles('ko'), '모든 파일');
  assert.equal(rootPickerTitle('ko'), 'Skill 폴더 추가');
  assert.deepEqual(notificationImmediate('ko', 'docs-helper'), { title: 'docs-helper: 기록한 버전에서 내용이 바뀌었어요', body: '변경 내용을 확인할 수 있어요. 관찰 모드는 실행을 막지 않아요.' });
  assert.deepEqual(notificationGrouped('ko', ['a', 'b']), { title: 'Skill 2개의 내용이 바뀌었어요', body: 'a, b · 변경 내용을 확인할 수 있어요.' });
  assert.equal(startFailure('ko', 'boom'), '시작하지 못했어요: boom');

  for (const text of [
    keyPickerTitle('en'), keyPickerAllFiles('en'), rootPickerTitle('en'), notificationImmediate('en', 'docs-helper').title, notificationImmediate('en', 'docs-helper').body,
    notificationGrouped('en', ['a', 'b']).title, notificationGrouped('en', ['a', 'b']).body, startFailure('en', 'boom'),
  ]) assert.doesNotMatch(text, HANGUL);
  assert.ok(notificationImmediate('en', 'docs-helper').title.includes('docs-helper'));
  assert.ok(notificationGrouped('en', ['a', 'b']).body.includes('a, b'));
  assert.ok(startFailure('en', 'boom').includes('boom'));
});

// ---- phase 2 dialogs (design V13, W10, R4, S3, T8)


const emptyConsequence: AdminConsequence = { skills: 3, changed: 0, lines: [], tooDeep: 0, freshnessBlock: false, fromFailed: null, toFailed: null, afterCounts: {} };
const common = {
  role: 'root' as const, keyName: null, keyId: KEY_ID, freshnessBlock: false, afterReset: false, consequence: emptyConsequence,
  document: { path: '/org/trust-root.json', baseSha256: DIGEST, versionFrom: 3 as number | null, versionTo: 4, expiresAt: '2027-10-01T00:00:00Z' },
};
const docLines = (lang: 'ko' | 'en') => lang === 'ko'
  ? ['문서: /org/trust-root.json', `현재 SHA-256: ${DIGEST}`, '버전: 3 → 4', '만료: 2027-10-01T00:00:00Z']
  : ['Document: /org/trust-root.json', `Current SHA-256: ${DIGEST}`, 'Version: 3 → 4', 'Expires: 2027-10-01T00:00:00Z'];

test('add approver: Korean lines in the design order, English with every value', () => {
  const add: AdminSignSummary = {
    ...common, action: 'add-approver', newKeyId: OTHER, name: 'Eve', scopes: ['docs-*', '*'], approverExpiresAt: '2027-01-01T00:00:00Z',
    replaces: null,
  };
  const ko = signDialog('ko', add);
  assert.equal(ko.title, '조직 문서 서명');
  assert.equal(ko.message, '승인자를 추가할까요?');
  assert.equal(ko.action, '서명');
  assert.equal(ko.detail, [
    ...docLines('ko'), `새 승인자: Eve ${OTHER}`, '범위: docs-*, *', '모든 Skill을 승인할 수 있는 범위예요', '승인자 키 만료: 2027-01-01T00:00:00Z',
    `키: root · - · ${KEY_ID}`, '영향받는 Skill: 0개 (전체 3개)',
  ].join('\n'));
  const en = signDialog('en', add);
  assert.deepEqual([en.title, en.message, en.action], ['Sign an organisation document', 'Add this approver?', 'Sign']);
  assert.equal(en.detail, [
    ...docLines('en'), `New approver: Eve ${OTHER}`, 'Scopes: docs-*, *', 'This scope lets the approver approve every Skill', 'Approver key expires: 2027-01-01T00:00:00Z',
    `Key: root · - · ${KEY_ID}`, 'Skills affected: 0 (of 3)',
  ].join('\n'));
  for (const text of [en.title, en.message, en.detail, en.action]) assert.doesNotMatch(text, HANGUL);
});

test('replace, remove and renew dialogs', () => {
  const replace: AdminSignSummary = {
    ...common, action: 'add-approver', newKeyId: OTHER, name: 'Eve 2', scopes: ['docs'], approverExpiresAt: '2027-01-01T00:00:00Z',
    replaces: { name: 'Eve', scopes: ['*'], expiresAt: '2026-12-01T00:00:00Z' },
  };
  const ko = signDialog('ko', replace);
  assert.equal(ko.message, '승인자 정보를 바꿀까요?');
  assert.ok(ko.detail.split('\n').includes('이미 승인자예요: 이름 Eve → Eve 2, 범위 * → docs, 만료 2026-12-01T00:00:00Z → 2027-01-01T00:00:00Z'));
  assert.ok(signDialog('en', replace).detail.split('\n').includes('Already an approver: name Eve → Eve 2, scopes * → docs, expiry 2026-12-01T00:00:00Z → 2027-01-01T00:00:00Z'));
  assert.equal(signDialog('en', replace).message, 'Change this approver?');

  const remove: AdminSignSummary = { ...common, action: 'remove-approver', removedKeyId: OTHER, name: 'Eve', lastApprover: false };
  assert.equal(signDialog('ko', remove).message, '승인자를 뺄까요?');
  assert.ok(signDialog('ko', remove).detail.split('\n').includes(`뺄 승인자: Eve ${OTHER}`));
  assert.ok(signDialog('en', remove).detail.split('\n').includes(`Approver to remove: Eve ${OTHER}`));
  assert.equal(signDialog('en', remove).message, 'Remove this approver?');

  const renew: AdminSignSummary = { ...common, action: 'renew-trust-root', expiresFrom: '2026-12-31T00:00:00Z' };
  assert.equal(signDialog('ko', renew).message, '신뢰 루트 기간을 연장할까요?');
  assert.ok(signDialog('ko', renew).detail.split('\n').includes('이전 만료: 2026-12-31T00:00:00Z'));
  assert.equal(signDialog('en', renew).message, "Extend the trust root's lifetime?");
  assert.ok(signDialog('en', renew).detail.split('\n').includes('Previous expiry: 2026-12-31T00:00:00Z'));
  // A missing base and version: none.
  const first: AdminSignSummary = { ...renew, document: { ...common.document, baseSha256: null, versionFrom: null } } as AdminSignSummary;
  assert.ok(signDialog('ko', first).detail.includes('현재 SHA-256: 없음\n버전: 없음 → 4'));
  assert.ok(signDialog('en', first).detail.includes('Current SHA-256: none\nVersion: none → 4'));
});

test('consequence block, freshness line, reset line, permanence lines (exact English and Korean)', () => {
  const blocked: AdminConsequence = {
    skills: 9, changed: 7, freshnessBlock: true, tooDeep: 2, fromFailed: null, toFailed: null, afterCounts: {},
    lines: ['a', 'b', 'c', 'd', 'e'].map((name) => ({ name, from: 'VERIFIED' as const, to: 'BLOCKED_UNTIL_TIMESTAMP' as const, after: 'UNTRUSTED_SIGNER' as const })),
  };
  assert.deepEqual(consequenceLines('en', blocked), [
    'Skills affected: 7 (of 9)',
    ...['a', 'b', 'c', 'd', 'e'].map((n) => `${n}: VERIFIED → blocked until a timestamp (after the timestamp: UNTRUSTED_SIGNER)`),
    'and 2 more', 'Folders too deep to check: 2',
  ]);
  assert.deepEqual(consequenceLines('ko', blocked).slice(0, 2), ['영향받는 Skill: 7개 (전체 9개)', 'a: VERIFIED → 타임스탬프 전까지 차단 (타임스탬프 뒤 UNTRUSTED_SIGNER)']);
  assert.deepEqual(consequenceLines('ko', blocked).slice(-2), ['외 2개', '너무 깊어서 확인하지 않은 폴더: 2개']);
  assert.deepEqual(consequenceLines('en', { ...emptyConsequence, fromFailed: 'freshness: stale' }), ['The current documents do not verify: freshness: stale', 'VERIFIED 0 · other 0']);
  assert.deepEqual(consequenceLines('ko', { ...emptyConsequence, fromFailed: 'x' }), ['현재 문서로는 검증할 수 없어요: x', 'VERIFIED 0개 · 그 외 0개']);
  assert.deepEqual(consequenceLines('en', { ...emptyConsequence, toFailed: 'bad' }), ['After signing, the documents would not verify: bad']);
  assert.deepEqual(consequenceLines('ko', { ...emptyConsequence, toFailed: 'bad' }), ['서명 후 문서가 검증되지 않아요: bad']);
  // When the current documents do not verify, every dialog shows what signing produces and no head or lines (P8.4).
  assert.deepEqual(consequenceLines('en', { ...emptyConsequence, fromFailed: 'f', changed: 4, lines: blocked.lines, tooDeep: 1, afterCounts: { VERIFIED: 3, REVOKED: 1, UNVERIFIABLE: 1 } }),
    ['The current documents do not verify: f', 'VERIFIED 3 · other 2', 'REVOKED 1', 'UNVERIFIABLE 1']);
  assert.deepEqual(consequenceLines('ko', { ...emptyConsequence, fromFailed: 'f', afterCounts: { VERIFIED: 3, REVOKED: 1 } }),
    ['현재 문서로는 검증할 수 없어요: f', 'VERIFIED 3개 · 그 외 1개', 'REVOKED 1개']);

  const renew: AdminSignSummary = { ...common, action: 'renew-trust-root', expiresFrom: 'x', freshnessBlock: true, afterReset: true };
  const ko = signDialog('ko', renew).detail.split('\n');
  assert.deepEqual(ko.slice(-2), [
    '이 조직은 타임스탬프를 써요: 새 타임스탬프를 서명할 때까지 enforce 모드의 호스트는 모든 Skill을 막아요.',
    '이 컴퓨터의 기록을 초기화한 뒤 첫 서명이에요: 디스크의 문서가 최신인지 확인하세요.',
  ]);
  assert.deepEqual(signDialog('en', renew).detail.split('\n').slice(-2), [
    'This organisation uses timestamps: hosts in enforce mode block every Skill until a new timestamp is signed.',
    "This is the first signature since this computer's memory was reset: make sure the documents on disk are the newest.",
  ]);

  const revokeKey: AdminSignSummary = { ...common, action: 'revoke-key', targetKeyId: OTHER, label: 'Eve', reason: 'lost laptop', certificates: null };
  const revokeDigest: AdminSignSummary = { ...common, action: 'revoke-digest', digest: OTHER, skillName: 'docs', reason: 'bad' };
  assert.deepEqual(signDialog('ko', revokeKey).detail.split('\n').slice(4, 6), [`폐기할 키: Eve ${OTHER}`, '사유: lost laptop']);
  assert.equal(signDialog('ko', revokeKey).message, '폐기할까요? 되돌릴 수 없어요.');
  assert.equal(signDialog('ko', revokeKey).action, '폐기');
  assert.equal(signDialog('en', revokeKey).action, 'Revoke');
  assert.equal(signDialog('en', revokeKey).message, 'Revoke? This cannot be undone.');
  assert.equal(signDialog('ko', revokeKey).detail.split('\n').at(-1), '폐기는 되돌릴 수 없어요. 이 키가 서명한 모든 인증서가 영구히 검증되지 않아요.');
  assert.equal(signDialog('ko', revokeDigest).detail.split('\n').at(-1), '폐기는 되돌릴 수 없어요. 이 버전의 모든 인증서가 영구히 검증되지 않아요.');
  assert.equal(signDialog('en', revokeKey).detail.split('\n').at(-1), 'Revocation cannot be undone. Every certificate this key signed will permanently fail verification.');
  assert.equal(signDialog('en', revokeDigest).detail.split('\n').at(-1), 'Revocation cannot be undone. Every certificate for this version will permanently fail verification.');
  assert.ok(signDialog('en', revokeDigest).detail.includes(`Version to revoke: docs ${OTHER}`));
  // A key chosen with the picker adds the certificate count after the reason (P8.2); an approver does not.
  const other: AdminSignSummary = { ...revokeKey, label: `${OTHER} · not a current approver`, certificates: 3 };
  assert.deepEqual(signDialog('en', other).detail.split('\n').slice(4, 7), [`Key to revoke: ${OTHER} · not a current approver ${OTHER}`, 'Reason: lost laptop', 'Certificates naming this key: 3']);
  assert.ok(signDialog('ko', other).detail.split('\n').includes('이 키를 쓰는 인증서: 3개'));
  assert.ok(!signDialog('en', revokeKey).detail.includes('Certificates naming'));

  const stamp: AdminSignSummary = {
    ...common, action: 'sign-timestamp', freshnessBlock: true,
    documents: { rootEvents: { sha256: DIGEST, counter: 2, firstSeen: false }, trustRoot: { sha256: OTHER, counter: 4, firstSeen: true }, revocations: { sha256: KEY_ID, counter: 5, firstSeen: false } },
    previousByOtherKey: { keyId: OTHER, version: 8 },
  };
  assert.deepEqual(signDialog('ko', stamp).detail.split('\n').slice(4, 8), [
    `루트 이벤트: 2 ${DIGEST}`, `신뢰 루트: 4 ${OTHER} (이 컴퓨터가 처음 보는 버전)`, `폐기 목록: 5 ${KEY_ID}`, `이전 타임스탬프는 다른 키(${OTHER})가 서명했어요 (버전 8).`,
  ]);
  assert.ok(signDialog('en', stamp).detail.includes(`Trust root: 4 ${OTHER} (first seen by this computer)`));
  assert.ok(!signDialog('en', stamp).detail.includes('This organisation uses timestamps'), 'a timestamp dialog never shows the freshness line');
  assert.equal(signDialog('ko', stamp).message, '타임스탬프를 서명할까요?');
});

test('inserted names, paths and reasons go through dialogSafe', () => {
  const evil: AdminSignSummary = { ...common, action: 'revoke-key', targetKeyId: OTHER, label: 'a‮b', reason: 'x\ny', certificates: null, document: { ...common.document, path: '/p q' } };
  const detail = signDialog('en', evil).detail;
  assert.ok(detail.includes('a⟨U+202E⟩b') && detail.includes('x⟨U+000A⟩y') && detail.includes('/p⟨U+2028⟩q'));
});

test('last approver, offline and public key picker texts', () => {
  assert.deepEqual(lastApproverDialog('ko'), {
    title: '마지막 승인자',
    message: '남는 승인자가 없어요. 지금 승인된 모든 Skill이 검증되지 않게 되고(UNTRUSTED_SIGNER), 새 승인자를 추가할 때까지 어떤 Skill도 승인할 수 없어요. 계속할까요?',
    detail: '', action: '계속',
  });
  assert.deepEqual(lastApproverDialog('en'), {
    title: 'Last approver',
    message: 'No approvers will remain. Every approved Skill will stop verifying (UNTRUSTED_SIGNER), and no Skill can be approved until you add a new approver. Continue?',
    detail: '', action: 'Continue',
  });
  assert.deepEqual(offlineDialog('ko'), { title: '오프라인 확인', message: '루트 키와 복구 키는 오프라인 관리용 컴퓨터에서만 써야 해요. 이 컴퓨터가 그런 컴퓨터인가요?', detail: '', action: '예, 오프라인 관리용이에요' });
  assert.deepEqual(offlineDialog('en'), { title: 'Offline check', message: 'Root and recovery keys must only be used on an offline administration computer. Is this such a computer?', detail: '', action: 'Yes, it is offline' });
  assert.equal(publicKeyPickerTitle('ko'), '승인자 공개 키 선택 (PEM)');
  assert.equal(publicKeyPickerTitle('en'), "Choose the approver's public key (PEM)");
});
