import assert from 'node:assert/strict';
import { access } from 'node:fs/promises';
import test from 'node:test';
import { loadPolicy, loadPolicyTrust } from '../src/policy.ts';
import { setupOrg, T0 } from './helpers.ts';

test('loadPolicyTrust with recordVersions: false leaves the host state file untouched', async (t) => {
  const org = await setupOrg(t);
  const policy = await loadPolicy(org.policyPath);

  const observed = await loadPolicyTrust(policy, T0, { recordVersions: false });
  assert.equal(observed.ok, true);
  await assert.rejects(access(org.statePath), { code: 'ENOENT' });

  const recorded = await loadPolicyTrust(policy, T0);
  assert.equal(recorded.ok, true);
  await access(org.statePath);
});
