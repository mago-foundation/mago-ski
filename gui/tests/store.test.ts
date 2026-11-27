// The GUI's own history file and retained copies: read bounded and never through a link; bad saved settings fall back.
import assert from 'node:assert/strict';
import { readdir, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { tempDir } from '../../tests/helpers.ts';
import { DEFAULT_PREFS, emptyState, sanitizePrefs, Store } from '../src/service/store.ts';

test('saved preferences are checked on load: an unknown notify value falls back instead of breaking the window', async (t) => {
  const dir = await tempDir(t, 'mago-ski-store-');
  const store = new Store(dir);
  await store.init();
  await writeFile(path.join(dir, 'state.json'), JSON.stringify({ ...emptyState(), prefs: { notify: 'loud', retainContent: 'yes', retentionDays: 9999 } }));
  const { state, lost } = await store.load();
  assert.equal(lost, null);
  assert.deepEqual(state.prefs, DEFAULT_PREFS);
  assert.deepEqual(sanitizePrefs({ notify: 'off', retainContent: false, retentionDays: 7 }), { notify: 'off', retainContent: false, retentionDays: 7 });
  assert.deepEqual(sanitizePrefs(null), DEFAULT_PREFS);
});

test('a history file that is a link is kept aside as unreadable, not followed', async (t) => {
  const dir = await tempDir(t, 'mago-ski-store-');
  const elsewhere = path.join(await tempDir(t, 'mago-ski-other-'), 'other.json');
  await writeFile(elsewhere, JSON.stringify(emptyState()));
  const store = new Store(dir);
  await store.init();
  await symlink(elsewhere, path.join(dir, 'state.json'));
  const { lost } = await store.load();
  assert.ok(lost?.backup);
  assert.ok((await readdir(dir)).some((f) => f.startsWith('state.json.unreadable-')));
});

test('a retained copy that is a link is not read', async (t) => {
  const dir = await tempDir(t, 'mago-ski-store-');
  const store = new Store(dir);
  await store.init();
  const bytes = Buffer.from('hello\n');
  const { createHash } = await import('node:crypto');
  const sha = createHash('sha256').update(bytes).digest('hex');
  await store.putBlob(sha, bytes);
  assert.deepEqual(await store.getBlob(sha), bytes);
  const target = path.join(dir, 'blobs', sha.slice(0, 2), sha);
  const { rm } = await import('node:fs/promises');
  await rm(target);
  const outside = path.join(await tempDir(t, 'mago-ski-other-'), 'x');
  await writeFile(outside, bytes);
  await symlink(outside, target);
  assert.equal(await store.getBlob(sha), null);
});
