// The message catalog: both languages have the same keys and placeholders, English has no Hangul, and the helpers behave.
import assert from 'node:assert/strict';
import test from 'node:test';
import { LANGS, langFromLocale, MESSAGES, t, type MessageKey } from '../src/i18n/messages.ts';

const HANGUL = /[ᄀ-ᇿ㄰-㆏가-힯]/u;
const placeholders = (text: string): string[] => [...text.matchAll(/\{([A-Za-z][A-Za-z0-9]*)\}/gu)].map((m) => m[1]!).sort();

test('both languages have exactly the same keys', () => {
  assert.deepEqual(LANGS, ['ko', 'en']);
  assert.deepEqual(Object.keys(MESSAGES.en).sort(), Object.keys(MESSAGES.ko).sort());
  assert.ok(Object.keys(MESSAGES.ko).length > 300);
});

test('every text uses the same {placeholders} in both languages', () => {
  for (const key of Object.keys(MESSAGES.ko) as MessageKey[])
    assert.deepEqual(placeholders(MESSAGES.en[key]), placeholders(MESSAGES.ko[key]), key);
});

test('no English text contains Hangul, and no text is empty', () => {
  for (const key of Object.keys(MESSAGES.en) as MessageKey[]) {
    assert.doesNotMatch(MESSAGES.en[key], HANGUL, key);
    assert.notEqual(MESSAGES.en[key].trim(), '', key);
    assert.notEqual(MESSAGES.ko[key].trim(), '', key);
    assert.doesNotMatch(MESSAGES.en[key], /!/u, `${key}: no exclamation marks`);
  }
});

test('t replaces placeholders and leaves unknown ones as they are', () => {
  assert.equal(t('en', 'admin.dialog.review.files', { n: 3 }), 'Files: 3');
  assert.equal(t('ko', 'admin.dialog.review.files', { n: 3 }), '파일: 3개');
  assert.equal(t('en', 'admin.dialog.review.skill', { name: 'a {n} b' }), 'Skill: a {n} b', 'values are not expanded again');
  assert.equal(t('en', 'admin.dialog.sign.lifetime', { lifetime: '30d' }), 'Lifetime: 30d (expires {expiresAt})');
  assert.equal(t('en', 'admin.dialog.review.files'), 'Files: {n}');
  assert.equal(t('en', 'admin.err.scope', { scopes: 'a-*', name: 'x' }), 'The scope (a-*) does not include the Skill name "x"');
});

test('langFromLocale maps ko and ko-… to ko and everything else to en', () => {
  assert.equal(langFromLocale('ko-KR'), 'ko');
  assert.equal(langFromLocale('ko'), 'ko');
  assert.equal(langFromLocale('en-US'), 'en');
  assert.equal(langFromLocale('fr'), 'en');
  assert.equal(langFromLocale(undefined), 'en');
  assert.equal(langFromLocale(''), 'en');
});
