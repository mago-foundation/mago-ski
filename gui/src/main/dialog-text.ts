// The texts of the native dialogs, built as pure functions so they can be tested without Electron. Everything inserted
// from outside goes through dialogSafe, as the dialogs always did. The review and signing texts are security text: both
// languages state the same facts.
import { t, type Lang, type MessageKey } from '../i18n/messages.ts';
import { dialogSafe } from '../service/admin.ts';
import type { AdminConsequence, AdminReviewSummary, AdminSignSummary } from '../service/types.ts';

export interface DialogText {
  title:   string;
  message: string;
  detail:  string;
  /** The label of the confirming button. */
  action:  string;
}

export function cancelLabel(lang: Lang): string {
  return t(lang, 'admin.dialog.cancel');
}

export function reviewDialog(lang: Lang, s: AdminReviewSummary): DialogText {
  return {
    title: t(lang, 'admin.dialog.review.title'), message: t(lang, 'admin.dialog.review.message'), action: t(lang, 'admin.dialog.review.action'),
    detail: [
      t(lang, 'admin.dialog.review.skill', { name: dialogSafe(s.skillName) }),
      t(lang, 'admin.dialog.review.folder', { path: dialogSafe(s.skillPath) }),
      t(lang, 'admin.dialog.review.version', { digest: s.digest }),
      t(lang, 'admin.dialog.review.files', { n: s.files }),
    ].join('\n'),
  };
}

/** The signing dialog for every action. The Korean text of `approve` is what it always was. */
export function signDialog(lang: Lang, s: AdminSignSummary): DialogText {
  if (s.action !== 'approve') return documentDialog(lang, s);
  return {
    title: t(lang, 'admin.dialog.sign.title'), message: t(lang, 'admin.dialog.sign.message'), action: t(lang, 'admin.dialog.sign.action'),
    detail: [
      t(lang, 'admin.dialog.review.skill', { name: dialogSafe(s.skillName) }),
      t(lang, 'admin.dialog.review.folder', { path: dialogSafe(s.skillPath) }),
      t(lang, 'admin.dialog.sign.reviewed', { digest: s.reviewedDigest }),
      t(lang, 'admin.dialog.sign.toSign', { digest: s.digest }),
      t(lang, 'admin.dialog.sign.lifetime', { lifetime: s.lifetime, expiresAt: s.expiresAt }),
      t(lang, 'admin.dialog.sign.reason', { reason: dialogSafe(s.reason) }),
      t(lang, 'admin.dialog.sign.key', { role: s.role, name: dialogSafe(s.keyName ?? '-'), keyId: s.keyId }),
    ].join('\n'),
  };
}

type DocumentSummary = Exclude<AdminSignSummary, { action: 'approve' }>;

const DOC_MESSAGE: Record<DocumentSummary['action'], MessageKey> = {
  'add-approver': 'admin.dialog.addApprover.message', 'remove-approver': 'admin.dialog.removeApprover.message',
  'renew-trust-root': 'admin.dialog.renew.message', 'revoke-key': 'admin.dialog.revoke.message', 'revoke-digest': 'admin.dialog.revoke.message',
  'refresh-revocations': 'admin.dialog.refresh.message', 'sign-timestamp': 'admin.dialog.timestamp.message',
};

const TIMESTAMP_DOC_LABEL: Record<'rootEvents' | 'trustRoot' | 'revocations', MessageKey> = {
  rootEvents: 'admin.p2.notice.timestampDocRootEvents', trustRoot: 'admin.p2.notice.timestampDocTrustRoot', revocations: 'admin.p2.notice.timestampDocRevocations',
};

/** Detail order (design T8): document, action lines, timestamp lines, key, consequence, permanence, freshness, reset. */
function documentDialog(lang: Lang, s: DocumentSummary): DialogText {
  const none = t(lang, 'admin.dialog.doc.none');
  const revoke = s.action === 'revoke-key' || s.action === 'revoke-digest';
  const lines: string[] = [
    t(lang, 'admin.dialog.doc.lineDocument', { path: dialogSafe(s.document.path) }),
    t(lang, 'admin.dialog.doc.lineSha', { sha: s.document.baseSha256 ?? none }),
    t(lang, 'admin.dialog.doc.lineVersion', { from: s.document.versionFrom ?? none, to: s.document.versionTo }),
    t(lang, 'admin.dialog.doc.lineExpires', { date: s.document.expiresAt }),
  ];
  switch (s.action) {
    case 'add-approver':
      lines.push(t(lang, 'admin.dialog.addApprover.lineNew', { name: dialogSafe(s.name), keyId: s.newKeyId }));
      if (s.replaces) lines.push(t(lang, 'admin.p2.notice.replace', {
        oldName: dialogSafe(s.replaces.name), newName: dialogSafe(s.name),
        oldScopes: dialogSafe(s.replaces.scopes.join(', ')), newScopes: dialogSafe(s.scopes.join(', ')),
        oldExpires: s.replaces.expiresAt, newExpires: s.approverExpiresAt,
      }));
      lines.push(t(lang, 'admin.dialog.addApprover.lineScopes', { scopes: dialogSafe(s.scopes.join(', ')) }));
      if (s.scopes.includes('*')) lines.push(t(lang, 'admin.p2.notice.scopeAll'));
      lines.push(t(lang, 'admin.dialog.addApprover.lineKeyExpires', { date: s.approverExpiresAt }));
      break;
    case 'remove-approver':
      lines.push(t(lang, 'admin.dialog.removeApprover.line', { name: dialogSafe(s.name), keyId: s.removedKeyId }));
      break;
    case 'renew-trust-root':
    case 'refresh-revocations':
      lines.push(t(lang, 'admin.dialog.renew.lineFrom', { date: s.expiresFrom }));
      break;
    case 'revoke-key':
      lines.push(t(lang, 'admin.dialog.revoke.lineKey', { label: dialogSafe(s.label), keyId: s.targetKeyId }), t(lang, 'admin.dialog.revoke.lineReason', { reason: dialogSafe(s.reason) }));
      break;
    case 'revoke-digest':
      lines.push(t(lang, 'admin.dialog.revoke.lineDigest', { skill: dialogSafe(s.skillName), digest: s.digest }), t(lang, 'admin.dialog.revoke.lineReason', { reason: dialogSafe(s.reason) }));
      break;
    case 'sign-timestamp':
      for (const name of ['rootEvents', 'trustRoot', 'revocations'] as const) {
        const doc = s.documents[name];
        lines.push(`${t(lang, 'admin.dialog.timestamp.line', { label: t(lang, TIMESTAMP_DOC_LABEL[name]), counter: doc.counter, sha: doc.sha256 })}${doc.firstSeen ? ` ${t(lang, 'admin.p2.notice.timestampFirstSeen')}` : ''}`);
      }
      if (s.previousByOtherKey) lines.push(t(lang, 'admin.p2.notice.timestampOtherKey', { keyId: s.previousByOtherKey.keyId, version: s.previousByOtherKey.version }));
      break;
  }
  lines.push(t(lang, 'admin.dialog.sign.key', { role: s.role, name: dialogSafe(s.keyName ?? '-'), keyId: s.keyId }));
  lines.push(...consequenceLines(lang, s.consequence, s.action === 'sign-timestamp'));
  if (s.action === 'revoke-key') lines.push(t(lang, 'admin.p2.notice.permanenceKey'));
  if (s.action === 'revoke-digest') lines.push(t(lang, 'admin.p2.notice.permanenceDigest'));
  if (s.action !== 'sign-timestamp' && s.freshnessBlock) lines.push(t(lang, 'admin.p2.notice.freshnessBlock'));
  if (s.afterReset) lines.push(t(lang, 'admin.p2.notice.afterReset'));
  return {
    title: t(lang, 'admin.dialog.doc.title'),
    message: t(lang, s.action === 'add-approver' && s.replaces ? 'admin.dialog.replaceApprover.message' : DOC_MESSAGE[s.action]),
    action: t(lang, revoke ? 'admin.dialog.revoke.action' : 'admin.dialog.doc.action'),
    detail: lines.join('\n'),
  };
}

/** The consequence block: head, at most 5 lines, how many more, folders too deep; or why it cannot be shown. */
export function consequenceLines(lang: Lang, c: AdminConsequence, timestamp = false): string[] {
  const out: string[] = [];
  if (c.fromFailed !== null) {
    out.push(t(lang, 'admin.p2.notice.consequenceFromFailed', { reason: dialogSafe(c.fromFailed) }));
    // A timestamp that fixes a stale one: show what signing restores (design U4).
    if (timestamp) {
      const verified = c.afterCounts.VERIFIED ?? 0;
      const others = Object.entries(c.afterCounts).filter(([verdict]) => verdict !== 'VERIFIED') as Array<[string, number]>;
      out.push(t(lang, 'admin.p2.policyCheck.done', { n: verified, m: others.reduce((sum, [, k]) => sum + k, 0) }));
      for (const [verdict, k] of others) out.push(t(lang, 'admin.p2.policyCheck.line', { verdict, k }));
    }
    return out;
  }
  if (c.toFailed !== null) {
    out.push(t(lang, 'admin.p2.notice.consequenceToFailed', { reason: dialogSafe(c.toFailed) }));
    return out;
  }
  out.push(t(lang, 'admin.p2.notice.consequenceHead', { changed: c.changed, skills: c.skills }));
  for (const line of c.lines) {
    out.push(line.to === 'BLOCKED_UNTIL_TIMESTAMP'
      ? t(lang, 'admin.p2.notice.consequenceLineBlocked', { name: dialogSafe(line.name), from: line.from, after: line.after })
      : t(lang, 'admin.p2.notice.consequenceLine', { name: dialogSafe(line.name), from: line.from, to: line.to }));
  }
  if (c.changed > c.lines.length) out.push(t(lang, 'admin.p2.notice.consequenceMore', { n: c.changed - c.lines.length }));
  if (c.tooDeep > 0) out.push(t(lang, 'admin.p2.notice.consequenceTooDeep', { n: c.tooDeep }));
  return out;
}

export function lastApproverDialog(lang: Lang): DialogText {
  return {
    title: t(lang, 'admin.dialog.lastApprover.title'), message: t(lang, 'admin.dialog.lastApprover.message'), detail: '', action: t(lang, 'admin.dialog.lastApprover.action'),
  };
}

export function offlineDialog(lang: Lang): DialogText {
  return {
    title: t(lang, 'admin.dialog.offline.title'), message: t(lang, 'admin.dialog.offline.message'), detail: '', action: t(lang, 'admin.dialog.offline.action'),
  };
}

export function publicKeyPickerTitle(lang: Lang): string {
  return t(lang, 'admin.dialog.publicKey.title');
}

export function resetDialog(lang: Lang): DialogText {
  return {
    title: t(lang, 'admin.dialog.reset.title'), message: t(lang, 'admin.dialog.reset.message'), detail: t(lang, 'admin.dialog.reset.detail'), action: t(lang, 'admin.dialog.reset.action'),
  };
}

export function keyPickerTitle(lang: Lang): string {
  return t(lang, 'admin.dialog.keyPicker.title');
}

export function keyPickerAllFiles(lang: Lang): string {
  return t(lang, 'admin.dialog.keyPicker.allFiles');
}

export function rootPickerTitle(lang: Lang): string {
  return t(lang, 'main.rootPicker');
}

/** Notification text: markup characters are dropped by the caller, as before. */
export function notificationImmediate(lang: Lang, name: string): { title: string; body: string } {
  return { title: t(lang, 'main.notifyImmediateTitle', { name }), body: t(lang, 'main.notifyImmediateBody') };
}

export function notificationGrouped(lang: Lang, names: string[]): { title: string; body: string } {
  return { title: t(lang, 'main.notifyGroupedTitle', { n: names.length }), body: t(lang, 'main.notifyGroupedBody', { names: names.join(', ') }) };
}

export function startFailure(lang: Lang, error: string): string {
  return t(lang, 'main.startFailed', { error });
}
