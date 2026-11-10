// Prepare/commit engine for root and timestamp writes (design phase 2: V1-V9 as amended).
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readdir, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import {
  commitRevocations, commitTrustRoot, DocumentChangedError, prepareRevocationsChange, prepareTrustRootChange,
  removeApprover, renewTrustRoot, signPreparedRevocations, signPreparedTrustRoot, StaleDocumentError, updateRevocations,
} from '../src/admin.ts';
import { FileChangedError, writeFileAtomic } from '../src/fs-safe.ts';
import { loadPrivateKey, loadPublicKey } from '../src/keys.ts';
import { commitTimestamp, prepareTimestamp, signPolicyTimestamp, signPreparedTimestamp, TimestampUnreadableError } from '../src/recovery-admin.ts';
import { GOLDEN_DIR, goldenAt, initGolden, writeGoldenKeys } from './admin-golden-world.ts';
import { daysAfter, setupOrg, setupRecoveryOrg, T0, tempDir } from './helpers.ts';

const sha = (bytes: Uint8Array) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const golden = async (name: string) => await readFile(path.join(GOLDEN_DIR, name));

test('prepare then commit writes the bytes the old functions wrote (golden documents)', async (t) => {
  const dir = await tempDir(t);
  const keys = await writeGoldenKeys(path.join(dir, 'keys'));
  const { trustRoot, revocations } = await initGolden(dir, keys);
  const root = await loadPrivateKey(keys.root);
  const a = await loadPublicKey(keys.aPub);
  const b = await loadPublicKey(keys.bPub);
  const trust = async (change: Parameters<typeof prepareTrustRootChange>[0]['change'], days: number) => {
    const p = await prepareTrustRootChange({ rootKeyId: root.keyId, trustRootPath: trustRoot, now: goldenAt(days), change });
    await commitTrustRoot(p, root);
  };
  await trust({ kind: 'add', publicKey: a, name: 'Reviewer A', scopes: ['*'], expires: '90d' }, 1);
  assert.deepEqual(await readFile(trustRoot), await golden('trust-root-2-add.json'));
  await trust({ kind: 'add', publicKey: b, name: 'Reviewer B', scopes: ['pdf-*', 'docs'], expires: '180d', trustRootExpires: '180d' }, 2);
  assert.deepEqual(await readFile(trustRoot), await golden('trust-root-3-add-second.json'));
  const replace = await prepareTrustRootChange({ rootKeyId: root.keyId, trustRootPath: trustRoot, now: goldenAt(3), change: { kind: 'add', publicKey: a, name: 'Reviewer A2', scopes: ['docs'], expires: '365d' } });
  assert.equal(replace.replaces?.name, 'Reviewer A');
  await commitTrustRoot(replace, root);
  assert.deepEqual(await readFile(trustRoot), await golden('trust-root-4-replace.json'));
  await trust({ kind: 'remove', keyId: b.keyId }, 4);
  assert.deepEqual(await readFile(trustRoot), await golden('trust-root-5-remove.json'));

  const list = async (change: Parameters<typeof prepareRevocationsChange>[0]['change'], days: number, expires?: string) => {
    const p = await prepareRevocationsChange({ rootKeyId: root.keyId, rootPublicKey: root.publicKey, revocationsPath: revocations, now: goldenAt(days), expires: expires ?? '30d', change });
    assert.deepEqual(signPreparedRevocations(p, root), signPreparedRevocations(p, root), 'signing is deterministic and pure');
    await commitRevocations(p, root);
  };
  await list({ kind: 'key', keyId: `sha256:${'cd'.repeat(32)}`, reason: 'lost laptop' }, 5, '7d');
  assert.deepEqual(await readFile(revocations), await golden('revocations-2-key.json'));
  await list({ kind: 'digest', digest: `sha256:${'ab'.repeat(32)}`, reason: 'bad version' }, 6);
  assert.deepEqual(await readFile(revocations), await golden('revocations-3-digest.json'));
  await list({ kind: 'both', keyId: `sha256:${'ef'.repeat(32)}`, digest: `sha256:${'12'.repeat(32)}`, reason: 'both at once' }, 7);
  assert.deepEqual(await readFile(revocations), await golden('revocations-4-both.json'));
  await list({ kind: 'refresh' }, 8, '7d');
  assert.deepEqual(await readFile(revocations), await golden('revocations-5-refresh.json'));
});

test('commit refuses a changed source, a wrong key, and writes exactly the prepared payload', async (t) => {
  const org = await setupOrg(t);
  const root = await loadPrivateKey(org.rootKey);
  const prepared = await prepareTrustRootChange({
    rootKeyId: root.keyId, trustRootPath: org.trustRoot, now: T0,
    change: { kind: 'add', publicKey: await loadPublicKey(org.approverPub), name: 'Same key', scopes: ['x'], expires: '30d' },
  });
  assert.equal(prepared.payload.version, prepared.current.version + 1);
  assert.equal(prepared.baseSha256, sha(await readFile(org.trustRoot)));
  const wrong = await loadPrivateKey(org.approverKey);
  await assert.rejects(commitTrustRoot(prepared, wrong), /Key does not match the prepared root key/u);
  // Swap between prepare and commit.
  await removeApprover({ rootKeyPath: org.rootKey, trustRootPath: org.trustRoot, now: daysAfter(T0, 1), keyId: org.approverKeyId });
  await assert.rejects(commitTrustRoot(prepared, root), DocumentChangedError);
});

test('writeFileAtomic expectSha256: a mismatch, a missing file and a surprise file throw FileChangedError and leave nothing behind', async (t) => {
  const dir = await tempDir(t);
  const file = path.join(dir, 'doc.json');
  await writeFile(file, 'one');
  await assert.rejects(writeFileAtomic(file, Buffer.from('two'), 0o644, { expectSha256: sha(Buffer.from('other')) }), FileChangedError);
  assert.equal(await readFile(file, 'utf8'), 'one');
  await writeFileAtomic(file, Buffer.from('two'), 0o644, { expectSha256: sha(Buffer.from('one')) });
  assert.equal(await readFile(file, 'utf8'), 'two');
  await assert.rejects(writeFileAtomic(path.join(dir, 'missing.json'), Buffer.from('x'), 0o644, { expectSha256: sha(Buffer.from('one')) }), FileChangedError);
  await assert.rejects(writeFileAtomic(file, Buffer.from('x'), 0o644, { expectSha256: null }), /File changed before it could be replaced/u);
  await writeFileAtomic(path.join(dir, 'new.json'), Buffer.from('x'), 0o644, { expectSha256: null });
  assert.deepEqual((await readdir(dir)).sort(), ['doc.json', 'new.json']);
});

test('a swap inside writeFileAtomic (after the temporary file is written) is refused', async (t) => {
  const org = await setupOrg(t);
  const root = await loadPrivateKey(org.rootKey);
  const prepared = await prepareTrustRootChange({ rootKeyId: root.keyId, trustRootPath: org.trustRoot, now: T0, change: { kind: 'renew', trustRootExpires: '200d' } });
  const original = await readFile(org.trustRoot);
  let swapped = Buffer.alloc(0);
  await assert.rejects(commitTrustRoot(prepared, root, {
    beforeWrite: async () => { swapped = Buffer.from(`${original.toString()} `); await writeFile(org.trustRoot, swapped); },
  }), FileChangedError);
  assert.deepEqual(await readFile(org.trustRoot), swapped);
});

test('trust root: versions, minimums, forbidden keys, display safety, renew', async (t) => {
  const org = await setupOrg(t);
  const root = await loadPrivateKey(org.rootKey);
  const base = { rootKeyId: root.keyId, trustRootPath: org.trustRoot, now: T0 };
  // v1 init + add = version 2 on disk.
  const equal = await prepareTrustRootChange({ ...base, minimumVersion: 2, change: { kind: 'renew', trustRootExpires: '100d' } });
  assert.equal(equal.payload.version, 3);
  await assert.rejects(prepareTrustRootChange({ ...base, minimumVersion: 3, change: { kind: 'renew', trustRootExpires: '100d' } }), StaleDocumentError);
  await assert.rejects(prepareTrustRootChange({ ...base, minimumVersion: 3, change: { kind: 'renew', trustRootExpires: '100d' } }), /Trust root version 2 is older than version 3 this computer has seen/u);

  const other = await loadPublicKey(org.rootPub);
  const forbidden = [{ keyId: org.approverKeyId, why: 'retired' as const }];
  await assert.rejects(prepareTrustRootChange({ ...base, forbidden, change: { kind: 'renew', trustRootExpires: '100d' } }), new RegExp(`Approver ${org.approverKeyId} cannot stay or be added: it is a key that held the root or timestamp role`, 'u'));
  await assert.rejects(prepareTrustRootChange({ ...base, forbidden: [{ keyId: other.keyId, why: 'root' }, ...forbidden], change: { kind: 'add', publicKey: other, name: 'x', scopes: ['a'], expires: '30d' } }), /root key cannot be an approver|cannot stay or be added/u);
  // Removing the forbidden key itself is allowed.
  const removed = await prepareTrustRootChange({ ...base, forbidden, change: { kind: 'remove', keyId: org.approverKeyId } });
  assert.equal(removed.payload.approvers.length, 0);

  await assert.rejects(prepareTrustRootChange({ ...base, change: { kind: 'add', publicKey: await loadPublicKey(org.approverPub), name: 'evil‮name', scopes: ['a'], expires: '30d' } }), /Approver name contains characters that cannot be shown safely/u);
  await assert.rejects(prepareRevocationsChange({ rootKeyId: root.keyId, rootPublicKey: root.publicKey, revocationsPath: org.revocations, now: T0, expires: '7d', change: { kind: 'key', keyId: `sha256:${'11'.repeat(32)}`, reason: 'bad⁧reason' } }), /Revocation reason contains characters that cannot be shown safely/u);

  const renewed = await renewTrustRoot({ rootKeyPath: org.rootKey, trustRootPath: org.trustRoot, now: daysAfter(T0, 1), expires: '200d' });
  assert.equal(renewed.version, 3);
  assert.equal(renewed.expiresAt.toISOString(), '2027-04-20T00:00:00.000Z');
});

test('revocations: stale, equal, already revoked and a swap', async (t) => {
  const org = await setupOrg(t);
  const root = await loadPrivateKey(org.rootKey);
  const o = { rootKeyId: root.keyId, rootPublicKey: root.publicKey, revocationsPath: org.revocations, now: T0, expires: '7d' };
  const equal = await prepareRevocationsChange({ ...o, minimumVersion: 1, change: { kind: 'refresh' } });
  assert.equal(equal.payload.version, 2);
  await assert.rejects(prepareRevocationsChange({ ...o, minimumVersion: 2, change: { kind: 'refresh' } }), StaleDocumentError);
  const key = `sha256:${'22'.repeat(32)}`;
  await updateRevocations({ rootKeyPath: org.rootKey, revocationsPath: org.revocations, now: T0, revokeKey: key });
  await assert.rejects(prepareRevocationsChange({ ...o, change: { kind: 'key', keyId: key, reason: 'again' } }), /is already revoked/u);
  await assert.rejects(commitRevocations(equal, root), DocumentChangedError);
});

test('timestamp: null base, created-after-prepare, swaps, minimums and versions', async (t) => {
  const org = await setupRecoveryOrg(t, { freshness: true });
  const policy = await org.policy();
  const key = await loadPrivateKey(org.timestamp.priv);
  const first = await prepareTimestamp({ policy, key, now: T0 });
  assert.equal(first.baseSha256, null);
  assert.equal(first.payload.version, 1);
  assert.deepEqual(signPreparedTimestamp(first, key), signPreparedTimestamp(first, key));
  // A file created after prepare is refused.
  await writeFile(org.timestampPath, 'x');
  await assert.rejects(commitTimestamp(first, key), DocumentChangedError);
  await rm(org.timestampPath);
  const written = await commitTimestamp(first, key);
  assert.equal(written.timestamp.version, 1);
  assert.equal(first.documents.trustRoot.sha256, sha(await readFile(org.trustRoot)));

  // A changed document between prepare and commit.
  const second = await prepareTimestamp({ policy, key, now: T0 });
  assert.equal(second.payload.version, 2);
  assert.equal(second.baseSha256, sha(await readFile(org.timestampPath)));
  await updateRevocations({ rootKeyPath: org.root.priv, revocationsPath: org.revocations, now: T0 });
  await assert.rejects(commitTimestamp(second, key), DocumentChangedError);

  // GUI path: minimums.
  const min = (n: Partial<{ trustRoot: number; revocations: number; timestamp: number }>) => ({ trustRoot: 0, revocations: 0, timestamp: 0, ...n });
  await assert.rejects(prepareTimestamp({ policy, key, now: T0, minimumVersions: min({ revocations: 3 }) }), StaleDocumentError);
  await assert.rejects(prepareTimestamp({ policy, key, now: T0, minimumVersions: min({ trustRoot: 9 }) }), StaleDocumentError);
  const gui = await prepareTimestamp({ policy, key, now: T0, minimumVersions: min({ trustRoot: 2, revocations: 2, timestamp: 7 }) });
  assert.equal(gui.payload.version, 8, 'max(own 1, memory 7) + 1');
  const expiredList = await prepareTimestamp({ policy, key, now: daysAfter(T0, 40), minimumVersions: min({}) }).then(() => 'ok', (e: Error) => e.message);
  assert.match(expiredList, /expired|UNVERIFIABLE|trust root/u);
  // An unreadable existing timestamp: GUI refuses with its own class, the CLI path keeps its rule.
  await writeFile(org.timestampPath, 'not a timestamp');
  await assert.rejects(prepareTimestamp({ policy, key, now: T0, minimumVersions: min({}) }), TimestampUnreadableError);
  await assert.rejects(prepareTimestamp({ policy, key, now: T0 }), /pass --version/u);
  await signPolicyTimestamp({ policy, keyPath: org.timestamp.priv, now: T0, version: 5 });
  // Lifetime above max_lifetime is refused, never capped.
  await assert.rejects(prepareTimestamp({ policy, key, now: T0, expires: '48h', version: 9 }), /max_lifetime/u);
});

test('signPolicyTimestamp without freshness keeps its message', async (t) => {
  const org = await setupRecoveryOrg(t);
  await assert.rejects(signPolicyTimestamp({ policy: await org.policy(), keyPath: org.timestamp.priv, now: T0 }), /has no "freshness" block/u);
});
