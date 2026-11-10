// Phase 2 IPC argument checks: exact key sets and types.
import assert from 'node:assert/strict';
import test from 'node:test';
import { parseAddApprover, parseRemoveApprover, parseRenew } from '../src/main/ipc-args.ts';

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
