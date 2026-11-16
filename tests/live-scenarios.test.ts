import assert from 'node:assert/strict';
import { test } from 'node:test';
// The runner is plain JavaScript so users can read the plan without compiling the repository.
// @ts-expect-error The small CLI intentionally does not ship a type declaration.
import { classify, parseArgs, scenarios } from '../scripts/live-scenarios.mjs';

function report(overrides: Record<string, unknown> = {}) {
  return { status: 0, signal: null, stdout: JSON.stringify({ scenarios: [{ scenario: 'mention-project', modelCalls: 0, checks: { 'project body did not reach the model': true, 'the prompt was blocked': true }, ...overrides }] }) };
}

test('the plan accepts only known hosts and explicit options', () => {
  assert.deepEqual(parseArgs(['--host', 'codex', '--run', '--json']), { host: 'codex', run: true, json: true });
  assert.throws(() => parseArgs(['--host', 'other']));
  assert.throws(() => parseArgs(['--host', 'codex', '--run', '--run']));
  assert.equal(scenarios.codex.length, 4);
});

test('a block before model invocation needs explicit hook evidence', () => {
  assert.equal(classify('codex', 'unapproved', 'mention-project', report()).status, 'PASS');
  assert.equal(classify('codex', 'unapproved', 'mention-project', report({ checks: { 'project body did not reach the model': true, 'the prompt was blocked': false } })).status, 'INCONCLUSIVE');
  assert.equal(classify('codex', 'unapproved', 'mention-project', report({ checks: { 'the prompt was blocked': true } })).status, 'INCONCLUSIVE');
  assert.equal(classify('claude-code', 'unapproved', 'mention-project', report({ checks: { 'project body did not reach the model': true, 'the call returned an error': true } })).status, 'INCONCLUSIVE');
});

test('a missing, interrupted or wrong scenario report cannot pass', () => {
  assert.equal(classify('codex', 'unapproved', 'mention-project', { status: 0, stdout: '{}' }).status, 'INCONCLUSIVE');
  assert.equal(classify('codex', 'unapproved', 'mention-project', { status: null, signal: 'SIGKILL', stdout: '' }).status, 'INCONCLUSIVE');
  assert.equal(classify('codex', 'unapproved', 'mention-project', report({ scenario: 'different' })).status, 'INCONCLUSIVE');
  assert.equal(classify('codex', 'unapproved', 'mention-project', { status: 0, stdout: '{"skipped":"missing root"}' }).status, 'SKIP');
});

test('observed mismatches fail and successful observations pass', () => {
  assert.equal(classify('codex', 'unapproved', 'mention-project', report({ modelCalls: 1, checks: { 'project body did not reach the model': false, 'the prompt was blocked': true } })).status, 'FAIL');
  assert.equal(classify('codex', 'unapproved', 'mention-project', report({ modelCalls: 1, checks: { 'project body did not reach the model': true, 'the prompt was blocked': true } })).status, 'PASS');
  assert.equal(classify('codex', 'unapproved', 'mention-project', { ...report(), status: 1 }).status, 'INCONCLUSIVE');
});
