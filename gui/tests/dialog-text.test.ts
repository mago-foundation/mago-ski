// The native dialog texts: Korean is exactly what the dialogs always showed; English has no Hangul and still states every
// value that is inserted (digest, key id, reason, ...). Nothing here needs Electron.
import assert from 'node:assert/strict';
import test from 'node:test';
import {
  cancelLabel, keyPickerAllFiles, keyPickerTitle, notificationGrouped, notificationImmediate, resetDialog, reviewDialog,
  rootPickerTitle, signDialog, startFailure,
} from '../src/main/dialog-text.ts';
import type { AdminReviewSummary, AdminSignSummary } from '../src/service/types.ts';

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
    title: '기록 초기화', message: '이 컴퓨터가 기억하는 조직 문서 버전을 지울까요? 오래된 문서를 다시 받아들일 수 있게 돼요.', detail: '', action: '초기화',
  });
  const en = resetDialog('en');
  for (const text of [en.title, en.message, en.detail, en.action]) assert.doesNotMatch(text, HANGUL);
  assert.equal(en.title, 'Reset memory');
  assert.match(en.message, /older documents/u);

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
