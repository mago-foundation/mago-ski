// <userData>/settings.json: a missing or invalid file means no setting; a written setting reads back.
import assert from 'node:assert/strict';
import { readFile, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { tempDir } from '../../tests/helpers.ts';
import { readLang, SETTINGS_FILE, writeLang } from '../src/service/settings.ts';

test('settings: a missing file means no setting', async (t) => {
  const dir = await tempDir(t, 'mago-ski-settings-');
  assert.equal(await readLang(dir), null);
  assert.equal(await readLang(path.join(dir, 'nope')), null);
});

test('settings: an invalid file means no setting', async (t) => {
  const dir = await tempDir(t, 'mago-ski-settings-');
  const file = path.join(dir, SETTINGS_FILE);
  for (const body of ['', 'not json', '[]', 'null', '{}', '{"lang":"fr"}', '{"lang":1}', '{"lang":null}', `{"lang":"ko"${' '.repeat(5000)}}`]) {
    await writeFile(file, body);
    assert.equal(await readLang(dir), null, JSON.stringify(body.slice(0, 20)));
  }
});

test('settings: a round trip, with nothing else in the file and mode 0600', async (t) => {
  const dir = await tempDir(t, 'mago-ski-settings-');
  await writeLang(dir, 'en');
  assert.equal(await readLang(dir), 'en');
  await writeLang(dir, 'ko');
  assert.equal(await readLang(dir), 'ko');
  assert.deepEqual(JSON.parse(await readFile(path.join(dir, SETTINGS_FILE), 'utf8')), { lang: 'ko' });
  assert.equal((await stat(path.join(dir, SETTINGS_FILE))).mode & 0o777, 0o600);
  await assert.rejects(writeLang(dir, 'fr' as 'ko'), /invalid language/u);
  assert.equal(await readLang(dir), 'ko');
});
