// Phase 2 IPC argument checks: exact key sets and types.
import assert from 'node:assert/strict';
import test from 'node:test';
import { parseAddApprover, parseRefresh, parseRemoveApprover, parseRenew, parseRevoke, parseSignTimestamp } from '../src/main/ipc-args.ts';

const KEY = `sha256:${'ab'.repeat(32)}`;

test('add-approver accepts exactly its keys and values', () => {
  assert.deepEqual(parseAddApprover({ name: 'Eve', scopes: ['docs-*', 'pdf'], lifetime: '90d' }), { name: 'Eve', scopes: ['docs-*', 'pdf'], lifetime: '90d' });
  assert.deepEqual(parseAddApprover({ name: 'Eve', scopes: ['*'], lifetime: '365d', trustRootLifetime: '180d' }).trustRootLifetime, '180d');
  for (const bad of [
    null, 'x', [], {}, { name: 'a', scopes: ['*'] }, { name: 'a', scopes: ['*'], lifetime: '90d', extra: 1 },
    { name: 'a'.repeat(129), scopes: ['*'], lifetime: '90d' }, { name: 1, scopes: ['*'], lifetime: '90d' }, { name: 'a', scopes: [], lifetime: '90d' },
    { name: 'a', scopes: Array.from({ length: 65 }, (_, i) => `s${i}`), lifetime: '90d' }, { name: 'a', scopes: ['*'], lifetime: '30d' },
    { name: 'a', scopes: ['*'], lifetime: '90d', trustRootLifetime: '90d' }, { name: 'a', scopes: [1], lifetime: '90d' }, { name: 'a', scopes: ['Bad Scope!'], lifetime: '90d' },
  ]) assert.throws(() => parseAddApprover(bad), Error);
});

test('remove-approver and renew', () => {
  assert.deepEqual(parseRemoveApprover({ keyId: KEY }), { keyId: KEY });
  assert.deepEqual(parseRemoveApprover({ keyId: KEY, trustRootLifetime: '365d' }), { keyId: KEY, trustRootLifetime: '365d' });
  for (const bad of [{}, { keyId: 'sha256:xyz' }, { keyId: KEY, x: 1 }, { keyId: KEY, trustRootLifetime: '1d' }, 5]) assert.throws(() => parseRemoveApprover(bad));
  assert.deepEqual(parseRenew({ lifetime: '180d' }), { lifetime: '180d' });
  for (const bad of [{}, { lifetime: '90d' }, { lifetime: '180d', extra: true }, null]) assert.throws(() => parseRenew(bad));
});

const DIGEST = `sha256:${'cd'.repeat(32)}`;

test('revoke accepts the three target shapes with exact keys', () => {
  assert.deepEqual(parseRevoke({ target: { kind: 'key', keyId: KEY }, reason: 'lost laptop', lifetime: '30d' }), { target: { kind: 'key', keyId: KEY }, reason: 'lost laptop', lifetime: '30d' });
  assert.deepEqual(parseRevoke({ target: { kind: 'digest', digest: DIGEST, instanceId: 'docs-1' }, reason: 'x', lifetime: '7d' }).target, { kind: 'digest', digest: DIGEST, instanceId: 'docs-1' });
  assert.deepEqual(parseRevoke({ target: { kind: 'other' }, reason: 'x', lifetime: '7d' }).target, { kind: 'other' });
  assert.equal(parseRevoke({ target: { kind: 'other' }, reason: 'a'.repeat(4096), lifetime: '7d' }).reason.length, 4096, 'the session applies the 512 limit after trimming');
  for (const bad of [
    null, 'x', [], {}, { target: { kind: 'other' }, reason: 'x' }, { target: { kind: 'other' }, reason: 'x', lifetime: '90d' }, { target: { kind: 'other' }, reason: 'x', lifetime: '7d', extra: 1 },
    { target: { kind: 'other' }, reason: 5, lifetime: '7d' }, { target: { kind: 'other' }, reason: 'a'.repeat(4097), lifetime: '7d' },
    { target: { kind: 'other', keyId: KEY }, reason: 'x', lifetime: '7d' }, { target: { kind: 'key' }, reason: 'x', lifetime: '7d' },
    { target: { kind: 'key', keyId: 'sha256:xyz' }, reason: 'x', lifetime: '7d' }, { target: { kind: 'key', keyId: KEY, extra: 1 }, reason: 'x', lifetime: '7d' },
    { target: { kind: 'digest', digest: 'sha256:xyz', instanceId: 'a' }, reason: 'x', lifetime: '7d' }, { target: { kind: 'digest', digest: DIGEST }, reason: 'x', lifetime: '7d' },
    { target: { kind: 'digest', digest: DIGEST, instanceId: '../etc' }, reason: 'x', lifetime: '7d' }, { target: { kind: 'digest', digest: DIGEST, instanceId: 'a', keyId: KEY }, reason: 'x', lifetime: '7d' },
    { target: { kind: 'path' }, reason: 'x', lifetime: '7d' }, { target: 'key', reason: 'x', lifetime: '7d' }, { target: [], reason: 'x', lifetime: '7d' }, { target: null, reason: 'x', lifetime: '7d' },
  ]) assert.throws(() => parseRevoke(bad), Error, JSON.stringify(bad));
});

test('refresh and sign-timestamp take only their lifetimes', () => {
  assert.deepEqual(parseRefresh({ lifetime: '7d' }), { lifetime: '7d' });
  assert.deepEqual(parseRefresh({ lifetime: '30d' }), { lifetime: '30d' });
  for (const bad of [{}, { lifetime: '90d' }, { lifetime: '6h' }, { lifetime: '7d', extra: 1 }, null, 'x']) assert.throws(() => parseRefresh(bad));
  for (const lifetime of ['6h', '12h', '24h']) assert.deepEqual(parseSignTimestamp({ lifetime }), { lifetime });
  for (const bad of [{}, { lifetime: '7d' }, { lifetime: '48h' }, { lifetime: '6h', extra: 1 }, null, []]) assert.throws(() => parseSignTimestamp(bad));
});
