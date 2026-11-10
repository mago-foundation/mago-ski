// Phase 2 texts that are not native dialogs (design R4, S3, T2, U5): the exact values in both languages.
import assert from 'node:assert/strict';
import test from 'node:test';
import { MESSAGES, t, type MessageKey } from '../src/i18n/messages.ts';

const TEXTS: Array<[MessageKey, string, string]> = [
  ['admin.p2.err.previousRoot', '문서가 이전 루트 키로 서명돼 있어요. CLI에서 root adopt로 새 루트 키로 옮기세요. (GUI 지원은 3단계)', 'These documents are signed by a previous root key. Move them to the new root key with root adopt in the CLI. (GUI support comes in phase 3.)'],
  ['admin.p2.err.changed', '문서가 그 사이에 바뀌었어요. 다시 준비하세요.', 'The document changed in the meantime. Prepare it again.'],
  ['admin.p2.err.stale', '이 컴퓨터가 본 것보다 오래된 문서예요. 최신 문서를 되돌려 놓으세요.', 'This document is older than one this computer has already seen. Put the newest document back.'],
  ['admin.p2.err.noFreshness', '이 조직은 타임스탬프를 쓰지 않아요.', 'This organisation does not use timestamps.'],
  ['admin.p2.err.rootRevoked', '루트 키가 폐기됐어요. 루트 사고 대응이 필요해요 (3단계).', 'The root key is revoked. A root incident response is needed (phase 3).'],
  ['admin.p2.err.rolesUnknown', '승인자 역할을 확인할 수 없어요: {reason}', 'The approver roles could not be checked: {reason}'],
  ['admin.p2.err.trustRootUnchanged', '루트 이벤트 기록을 확인할 수 없어서 신뢰 루트를 바꾸지 않았어요: {reason}', 'Cannot check the root event log, so the trust root is not changed: {reason}'],
  ['admin.p2.notice.memoryWarning', '서명은 됐지만 이 컴퓨터의 기록을 갱신하지 못했어요.', "The signature was made, but this computer's memory could not be updated."],
  ['admin.p2.notice.afterReset', '이 컴퓨터의 기록을 초기화한 뒤 첫 서명이에요: 디스크의 문서가 최신인지 확인하세요.', "This is the first signature since this computer's memory was reset: make sure the documents on disk are the newest."],
  ['admin.p2.notice.consequenceHead', '영향받는 Skill: {changed}개 (전체 {skills}개)', 'Skills affected: {changed} (of {skills})'],
  ['admin.p2.notice.consequenceLine', '{name}: {from} → {to}', '{name}: {from} → {to}'],
  ['admin.p2.notice.consequenceLineBlocked', '{name}: {from} → 타임스탬프 전까지 차단 (타임스탬프 뒤 {after})', '{name}: {from} → blocked until a timestamp (after the timestamp: {after})'],
  ['admin.p2.notice.consequenceMore', '외 {n}개', 'and {n} more'],
  ['admin.p2.notice.consequenceTooDeep', '너무 깊어서 확인하지 않은 폴더: {n}개', 'Folders too deep to check: {n}'],
  ['admin.p2.notice.consequenceFromFailed', '현재 문서로는 검증할 수 없어요: {reason}', 'The current documents do not verify: {reason}'],
  ['admin.p2.notice.consequenceToFailed', '서명 후 문서가 검증되지 않아요: {reason}', 'After signing, the documents would not verify: {reason}'],
  ['admin.p2.notice.freshnessCli', '타임스탬프가 새 문서를 가리키지 않아요. CLI에서 mago-ski timestamp sign을 실행하세요.', 'The timestamp does not name the new documents. Run mago-ski timestamp sign in the CLI.'],
  ['admin.p2.notice.freshnessTemplate', '타임스탬프가 새 문서를 가리키지 않아요. 타임스탬프 서명 템플릿을 실행하세요.', 'The timestamp does not name the new documents. Run the Sign timestamp template.'],
  ['admin.p2.forbidden.root', '루트 키', 'the root key'],
  ['admin.p2.forbidden.recovery', '복구 키', 'a recovery key'],
  ['admin.p2.forbidden.timestamp', '타임스탬프 키', 'the timestamp key'],
  ['admin.p2.forbidden.retired', '예전에 루트나 타임스탬프 역할을 했던 키', 'a key that held the root or timestamp role'],
  ['admin.p2.forbidden.formerRecovery', '예전 복구 키', 'a former recovery key'],
  ['admin.p2.forbidden.revoked', '폐기된 키', 'a revoked key'],
  ['admin.p2.forbidden.mustRemove', '{why}: 이 승인자는 빼야 해요', '{why}: this approver must be removed'],
  ['admin.p2.err.removeFirst', '{why}: 이 승인자를 먼저 빼세요', '{why}: remove this approver first'],
  ['admin.p2.notice.timestampOtherKey', '이전 타임스탬프는 다른 키({keyId})가 서명했어요 (버전 {version}).', 'The previous timestamp was signed by another key ({keyId}), version {version}.'],
  ['admin.p2.err.timestampUnreadable', '현재 타임스탬프를 읽을 수 없어요. CLI에서 --version으로 서명하세요.', 'The current timestamp cannot be read. Sign it in the CLI with --version.'],
  ['admin.p2.err.tooManyFolders', '폴더가 너무 많아서 영향을 계산할 수 없어요. 폴더 수를 줄이세요.', 'There are too many folders to work out the effect. Reduce the number of folders.'],
  ['admin.p2.err.cannotRevokeRole', '루트·복구·타임스탬프 키는 여기서 폐기할 수 없어요.', 'Root, recovery and timestamp keys cannot be revoked here.'],
  ['admin.p2.err.notATarget', '현재 승인자나 찾은 인증서의 키만 폐기할 수 있어요', 'Only the keys of current approvers or of certificates found can be revoked'],
  ['admin.p2.err.alreadyRevoked', '이미 폐기됐어요', 'Already revoked'],
  ['admin.p2.err.trustRootExpired', '신뢰 루트가 만료됐어요', 'The trust root has expired'],
  ['admin.p2.err.revocationsExpired', '폐기 목록이 만료됐어요', 'The revocation list has expired'],
  ['admin.p2.err.revocationsExpiredRefresh', '폐기 목록이 만료됐어요. 먼저 폐기 목록 새로 고침을 실행하세요.', 'The revocation list has expired. Run Refresh revocation list first.'],
  ['admin.p2.err.trustRootExpiredRenew', '신뢰 루트가 만료됐어요. 먼저 승인자 관리에서 연장하세요.', 'The trust root has expired. Renew it in Manage approvers first.'],
  ['admin.p2.err.maxLifetimeShort', '조직의 최대 타임스탬프 기간이 6시간보다 짧아요. CLI를 쓰세요.', "The organisation's maximum timestamp lifetime is under 6 hours. Use the CLI."],
  ['admin.p2.err.pickLifetime', '신뢰 루트가 만료됐어요. 신뢰 루트 기간을 고르세요.', 'The trust root has expired. Choose a trust root lifetime.'],
  ['admin.p2.err.publicKeyUnreadable', '공개 키를 읽을 수 없어요', 'The public key cannot be read'],
  ['admin.p2.err.cancelled', '취소했어요', 'Cancelled'],
  ['admin.p2.label.trustRootLifetime', '신뢰 루트 기간', 'Trust root lifetime'],
  ['admin.p2.label.keep', '유지', 'Keep'],
  ['admin.template.approvers', '승인자 관리', 'Manage approvers'],
  ['admin.template.revoke', '폐기', 'Revoke'],
  ['admin.template.refresh', '폐기 목록 새로 고침', 'Refresh revocation list'],
  ['admin.template.timestamp', '타임스탬프 서명', 'Sign timestamp'],
  ['admin.p2.btn.add', '추가', 'Add'], ['admin.p2.btn.remove', '빼기', 'Remove'], ['admin.p2.btn.renew', '연장', 'Renew'],
  ['admin.p2.btn.revoke', '폐기', 'Revoke'], ['admin.p2.btn.resign', '다시 서명', 'Re-sign'], ['admin.p2.btn.sign', '서명', 'Sign'], ['admin.p2.btn.review', '검토', 'Review'],
  ['admin.p2.trustRoot.ready', '승인자 {n}명 · 버전 {v} · 만료 {date}', '{n} approvers · version {v} · expires {date}'],
  ['admin.p2.trustRoot.done', '서명했어요: 버전 {v}', 'Signed: version {v}'],
  ['admin.p2.target.ready', '폐기할 대상을 고르세요', 'Choose what to revoke'],
  ['admin.p2.target.done', '{label} 선택됨', '{label} selected'],
  ['admin.p2.revoke.ready', '사유와 기간을 적고 폐기하세요', 'Enter a reason and lifetime, then revoke'],
  ['admin.p2.revoke.done', '폐기했어요: 버전 {v}', 'Revoked: version {v}'],
  ['admin.p2.refresh.ready', '폐기 목록 버전 {v} · 만료 {date}', 'Revocation list version {v} · expires {date}'],
  ['admin.p2.refresh.done', '다시 서명했어요: 버전 {v}', 'Re-signed: version {v}'],
  ['admin.p2.timestamp.ready', '타임스탬프 버전 {v} · 만료 {date}', 'Timestamp version {v} · expires {date}'],
  ['admin.p2.timestamp.done', '서명했어요: 버전 {v}', 'Signed: version {v}'],
  ['admin.p2.policyCheck.ready', '검사 중…', 'Checking…'],
  ['admin.p2.policyCheck.done', 'VERIFIED {n}개 · 그 외 {m}개', 'VERIFIED {n} · other {m}'],
  ['admin.p2.policyCheck.line', '{verdict} {k}개', '{verdict} {k}'],
  ['admin.p2.notice.permanenceKey', '폐기는 되돌릴 수 없어요. 이 키가 서명한 모든 인증서가 영구히 검증되지 않아요.', 'Revocation cannot be undone. Every certificate this key signed will permanently fail verification.'],
  ['admin.p2.notice.permanenceDigest', '폐기는 되돌릴 수 없어요. 이 버전의 모든 인증서가 영구히 검증되지 않아요.', 'Revocation cannot be undone. Every certificate for this version will permanently fail verification.'],
  ['admin.p2.notice.freshnessBlock', '이 조직은 타임스탬프를 써요: 새 타임스탬프를 서명할 때까지 enforce 모드의 호스트는 모든 Skill을 막아요.', 'This organisation uses timestamps: hosts in enforce mode block every Skill until a new timestamp is signed.'],
  ['admin.dialog.reset.detail', '초기화하면 루트 문서를 쓸 때 지금 디스크에 있는 문서를 기준으로 삼아요.', 'After a reset, root document writes take the documents now on disk as their base.'],
];

test('every phase 2 text has exactly the design values in both languages', () => {
  for (const [key, ko, en] of TEXTS) {
    assert.equal(MESSAGES.ko[key], ko, `ko ${key}`);
    assert.equal(MESSAGES.en[key], en, `en ${key}`);
  }
});

test('the old Publish and approvers/revoke title keys are gone, and t fills the placeholders', () => {
  for (const gone of ['admin.tpl.publish.title', 'admin.tpl.approvers.title', 'admin.tpl.revoke.title']) assert.equal(gone in MESSAGES.ko, false, gone);
  assert.equal(t('en', 'admin.p2.policyCheck.done', { n: 3, m: 1 }), 'VERIFIED 3 · other 1');
  assert.equal(t('ko', 'admin.p2.forbidden.mustRemove', { why: '루트 키' }), '루트 키: 이 승인자는 빼야 해요');
});
