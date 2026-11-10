// loadTrustForPreview is for the GUI's consequence preview only (design phase 2, R1).
import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

const root = path.join(import.meta.dirname, '..');

async function sources(dir: string): Promise<string[]> {
  const found: string[] = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    if (entry.name === 'node_modules' || entry.name === 'dist') continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) found.push(...await sources(full));
    else if (/\.(ts|cts|mts|js|mjs|cjs)$/u.test(entry.name)) found.push(full);
  }
  return found;
}

test('only src/policy.ts defines and only the GUI admin service imports loadTrustForPreview', async () => {
  const allowed = new Set([path.join(root, 'src', 'policy.ts'), path.join(root, 'gui', 'src', 'service', 'admin.ts')]);
  for (const base of ['src', 'hosts', 'scripts', path.join('gui', 'src'), path.join('gui', 'scripts'), path.join('gui', 'tests')]) {
    for (const file of await sources(path.join(root, base))) {
      const text = await readFile(file, 'utf8');
      if (text.includes('loadTrustForPreview'))
        assert.ok(allowed.has(file), `${path.relative(root, file)} must not use loadTrustForPreview`);
    }
  }
});
