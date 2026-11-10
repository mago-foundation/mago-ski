// The renderer's current language. Every text goes through tr(), so a language change is a re-render.
import { t, type Lang, type MessageKey } from '../i18n/messages.ts';

let current: Lang = 'en';

export function currentLang(): Lang {
  return current;
}

export function setCurrentLang(lang: Lang): void {
  current = lang;
  document.documentElement.lang = lang;
}

export function tr(key: MessageKey, params?: Record<string, string | number>): string {
  return t(current, key, params);
}

/** The locale for dates and times. */
export function locale(): string {
  return current === 'ko' ? 'ko-KR' : 'en-US';
}

/** A message that is built again in the current language each time it is drawn, or fixed text from the main process. */
export type Note = { ok: boolean; text: string | (() => string) };

export function noteText(note: Note): string {
  return typeof note.text === 'function' ? note.text() : note.text;
}
