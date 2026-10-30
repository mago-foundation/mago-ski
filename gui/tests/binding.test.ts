import assert from 'node:assert/strict';
import test from 'node:test';
import { actionDigest, detailMatches } from '../src/renderer/binding.ts';
import type { ChangeView, InstanceDetail, InstanceView } from '../src/service/types.ts';

const A = `sha256:${'a'.repeat(64)}`;
const B = `sha256:${'b'.repeat(64)}`;
const C = `sha256:${'c'.repeat(64)}`;

function instance(current: string, baseline: string, state: InstanceView['state'] = 'changed'): InstanceView {
  return {
    id: 'i1', name: 'docs-helper', path: '/s', rootId: 'r', rootLabel: 'r', state, error: null, firstSeen: '', lastChecked: null,
    currentDigest: current, baselineDigest: baseline, baselineAt: null, changedFiles: 1, pki: null, pkiCurrent: true,
  };
}

function detail(current: string, baseline: string, withChange = true): InstanceDetail {
  const change: ChangeView | null = withChange ? {
    baselineDigest: baseline, currentDigest: current, contentRetained: true, contentNote: null, files: [],
    addedOrigins: [], removedOrigins: [], analysisComplete: true, evidenceNote: '', truncated: false,
  } : null;
  return { instance: instance(current, baseline), change, approveCommand: null, history: [], previousVersions: [] };
}

test('the action records the digest of the change on screen', () => {
  assert.equal(actionDigest(instance(B, A), detail(B, A)), B);
});

test('after a further change (B to C) the old diff is not reused and no action is offered', () => {
  const view = instance(C, A);
  assert.equal(detailMatches(view, detail(B, A)), false);
  assert.equal(actionDigest(view, detail(B, A)), null);
});

test('no action before the detail has loaded, or for another Skill', () => {
  assert.equal(actionDigest(instance(B, A), null), null);
  const other = detail(B, A);
  other.instance.id = 'i2';
  assert.equal(actionDigest(instance(B, A), other), null);
});

test('a changed Skill needs the change view itself, not just matching digests', () => {
  assert.equal(actionDigest(instance(B, A), detail(B, A, false)), null);
});

test('a new Skill (no change) can be acknowledged at its current digest', () => {
  assert.equal(actionDigest(instance(A, A, 'new'), detail(A, A, false)), A);
});

test('a re-baselined Skill (same current, new baseline) invalidates the old detail', () => {
  assert.equal(actionDigest(instance(B, B, 'unchanged'), detail(B, A)), null);
});
