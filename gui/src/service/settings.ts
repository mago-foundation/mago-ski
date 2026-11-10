// The GUI's own settings file: <userData>/settings.json holds { "lang": "ko" | "en" } and nothing else.
import { mkdir } from 'node:fs/promises';
import path from 'node:path';
import { readRegularFile, writeFileAtomic } from '../../../src/fs-safe.ts';
import { LANGS, type Lang } from '../i18n/messages.ts';

export const SETTINGS_FILE = 'settings.json';
const MAX_SETTINGS_BYTES = 4096;

/** The stored language, or null when the file is missing, unreadable or invalid. */
export async function readLang(dir: string): Promise<Lang | null> {
  try {
    const bytes = await readRegularFile(path.join(dir, SETTINGS_FILE), 'GUI settings', MAX_SETTINGS_BYTES);
    const parsed: unknown = JSON.parse(Buffer.from(bytes).toString('utf8'));
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return null;
    const lang = (parsed as { lang?: unknown }).lang;
    return typeof lang === 'string' && (LANGS as readonly string[]).includes(lang) ? (lang as Lang) : null;
  } catch {
    return null;
  }
}

export async function writeLang(dir: string, lang: Lang): Promise<void> {
  if (!(LANGS as readonly string[]).includes(lang)) throw new Error('invalid language');
  await mkdir(dir, { recursive: true, mode: 0o700 });
  await writeFileAtomic(path.join(dir, SETTINGS_FILE), Buffer.from(`${JSON.stringify({ lang })}\n`, 'utf8'), 0o600);
}
