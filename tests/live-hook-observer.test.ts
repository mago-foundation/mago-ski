import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, copyFile, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
// @ts-expect-error Test-only JavaScript shared with the live harness.
import { parseObservations, promptDenied } from './live/hook-observation.mjs';

async function observe(event: string, code: number, stderr: string, signal = false) {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'mago-observer-test-'));
  try {
    const observer = path.join(dir, 'observer.mjs');
    const hook = path.join(dir, 'hook.mjs');
    const observations = path.join(dir, 'observations.jsonl');
    await copyFile(fileURLToPath(new URL('./live/hook-observer.mjs', import.meta.url)), observer);
    await writeFile(`${observer}.json`, JSON.stringify({ hook, observations }));
    await writeFile(hook, `let input = ''; for await (const chunk of process.stdin) input += chunk; process.stdout.write(input); process.stderr.write(${JSON.stringify(stderr)}); ${signal ? "process.kill(process.pid, 'SIGTERM');" : `process.exitCode = ${code};`}`);
    const input = JSON.stringify({ hook_event_name: event, prompt: 'PRIVATE-TEST-PROMPT' });
    const child = spawnSync(process.execPath, [observer, 'config', 'enforce'], { input, encoding: 'utf8', timeout: 10000 });
    const record = await readFile(observations, 'utf8');
    return { child, input, record, observations: parseObservations(record) };
  } finally { await rm(dir, { recursive: true, force: true }); }
}

test('observer forwards streams and the real exit status without recording the prompt', async () => {
  const r = await observe('UserPromptSubmit', 2, 'blocked by test hook');
  assert.equal(r.child.status, 2);
  assert.equal(r.child.stdout, r.input);
  assert.equal(r.child.stderr, 'blocked by test hook');
  assert.equal(r.record.includes('PRIVATE-TEST-PROMPT'), false);
  assert.equal(r.record.includes('blocked by test hook'), false);
  assert.equal(promptDenied(r.observations), true);
});

test('a hook killed by a signal is not a denial', { skip: process.platform === 'win32' }, async () => {
  const r = await observe('UserPromptSubmit', 2, 'blocked', true);
  assert.equal(r.child.signal, 'SIGTERM');
  assert.equal(promptDenied(r.observations), false);
});

test('only a prompt hook exit 2 with a reason proves denial', async () => {
  for (const [event, code, reason] of [
    ['UserPromptSubmit', 0, ''], ['UserPromptSubmit', 2, '  '],
    ['UserPromptSubmit', 1, 'error'], ['SessionStart', 2, 'blocked'],
  ] as const) {
    const r = await observe(event, code, reason);
    assert.equal(r.child.status, code);
    assert.equal(promptDenied(r.observations), false);
  }
  assert.equal(promptDenied(parseObservations('{broken')), false);
  assert.equal(promptDenied([{ event: 'UserPromptSubmit', code: 2, reason: true, signal: 'SIGKILL' }]), false);
});
