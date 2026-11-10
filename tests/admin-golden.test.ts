import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { GOLDEN_DIR, GOLDEN_STEPS, goldenAt, initGolden, writeGoldenKeys } from './admin-golden-world.ts';
import { tempDir } from './helpers.ts';

// The fixtures were produced by the admin functions before they were rebuilt on prepare/commit (design phase 2, W14).
// Set UPDATE_GOLDEN=1 only to regenerate them deliberately.
test('admin functions produce the golden documents byte for byte', async (t) => {
  const dir = await tempDir(t);
  const keys = await writeGoldenKeys(path.join(dir, 'keys'));
  const { trustRoot, revocations } = await initGolden(dir, keys);
  for (const step of GOLDEN_STEPS) {
    await step.run({ keys, trustRoot, revocations, at: goldenAt });
    const produced = await readFile(step.file.startsWith('trust') ? trustRoot : revocations);
    const goldenPath = path.join(GOLDEN_DIR, step.file);
    if (process.env.UPDATE_GOLDEN === '1') await writeFile(goldenPath, produced);
    assert.deepEqual(produced, await readFile(goldenPath), step.file);
  }
});
