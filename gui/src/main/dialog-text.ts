// The texts of the native dialogs, built as pure functions so they can be tested without Electron. Everything inserted
// from outside goes through dialogSafe, as the dialogs always did. The review and signing texts are security text: both
// languages state the same facts.
import { t, type Lang } from '../i18n/messages.ts';
import { dialogSafe } from '../service/admin.ts';
import type { AdminReviewSummary, AdminSignSummary } from '../service/types.ts';

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

export function signDialog(lang: Lang, s: AdminSignSummary): DialogText {
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

export function resetDialog(lang: Lang): DialogText {
  return {
    title: t(lang, 'admin.dialog.reset.title'), message: t(lang, 'admin.dialog.reset.message'), detail: '', action: t(lang, 'admin.dialog.reset.action'),
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
