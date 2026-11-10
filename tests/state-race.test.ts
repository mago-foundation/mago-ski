// Two processes recording ascending versions in one host state file never leave a lower value on disk (design v11, item 1).
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import path from 'node:path';
import test from 'node:test';
import { readHostState, recordDocumentVersions } from '../src/policy.ts';
import { tempDir } from './helpers.ts';

const CHILD = path.join(import.meta.dirname, 'state-race-child.ts');

const run = (args: string[]) => new Promise<number | null>((resolve) => {
  const child = spawn(process.execPath, [CHILD, ...args], { stdio: ['ignore', 'ignore', 'inherit'] });
  child.on('exit', (code) => resolve(code));
});

test('two processes recording ascending versions never leave a lower value on disk', async (t) => {
  const dir = await tempDir(t, 'mago-ski-race-');
  const file = path.join(dir, 'admin-state.json');
  const rootKeyId = `sha256:${'0'.repeat(64)}`;
  await recordDocumentVersions(file, { rootKeyId, trustRoot: 1 });
  const count = 150;
  // A records 2, 4, 6, ...; B records 1001, 1002, ...; each only raises its own counter, so the final value is 1000 + count.
  const codes = await Promise.all([run([file, rootKeyId, '2', String(count), '2']), run([file, rootKeyId, '1001', String(count), '1'])]);
  assert.deepEqual(codes, [0, 0]);
  assert.equal((await readHostState(file)).roots[rootKeyId]!.trust_root_version, 1000 + count);
});
