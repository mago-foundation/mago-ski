import assert from 'node:assert/strict';
import { chmod, cp, mkdir, readdir, readFile, rm, symlink, unlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import test, { type TestContext } from 'node:test';
import { addApprover, updateRevocations } from '../src/admin.ts';
import { generateKeyPair } from '../src/keys.ts';
import { openTrustStore, type TrustStore, type TrustStoreOptions } from '../src/gate/trust-store.ts';
import { CLOCK_SKEW_MS } from '../src/time.ts';
import { daysAfter, setupOrg, T0, tempDir, type Org } from './helpers.ts';

const MIN = 60_000;

async function setup(t: TestContext, opts: { maxListAgeMs?: number } = {}) {
  const org = await setupOrg(t);
  const dir = path.join(await tempDir(t, 'mago-ski-store-'), 'state');
  const docs = async (o: Org = org) => ({ trustRootBytes: await readFile(o.trustRoot), revocationsBytes: await readFile(o.revocations) });
  const open = (now = T0, extra: Partial<TrustStoreOptions> = {}) => openTrustStore(dir, { rootFingerprint: org.rootKeyId, now, ...opts, ...extra });
  return { org, dir, docs, open };
}

async function newList(org: Org, out: string, now: Date, expires = '30d', from = org.revocations) {
  await updateRevocations({ rootKeyPath: org.rootKey, revocationsPath: from, out, now, expires });
  return await readFile(out);
}

async function reason(store: TrustStore, now: Date) {
  const c = await store.current(now);
  return c.ready ? 'ready' : c.reason;
}

test('empty store is not ready; accept then ready; reopen gives same versions', async (t) => {
  const { docs, open, dir } = await setup(t);
  const store = await open();
  assert.equal(await reason(store, T0), 'no-state');
  assert.deepEqual(await store.accept(await docs(), T0), { ok: true, changed: true });
  const cur = await store.current(T0);
  assert.ok(cur.ready);
  const again = await (await open(daysAfter(T0, 1))).current(daysAfter(T0, 1));
  assert.ok(again.ready);
  assert.deepEqual(again.versions, cur.versions);
  const files = (await readdir(dir)).sort();
  assert.equal(files.length, 3);
  assert.ok(files.includes('manifest.json'));
});

test('wrong fingerprint and foreign list signer are rejected', async (t) => {
  const { org, docs, open, dir } = await setup(t);
  const wrong = await openTrustStore(dir, { rootFingerprint: 'sha256:' + '0'.repeat(64), now: T0 });
  assert.equal((await wrong.accept(await docs(), T0)).ok, false);
  const other = await setupOrg(t);
  const store = await open();
  const bad = { trustRootBytes: (await docs()).trustRootBytes, revocationsBytes: await readFile(other.revocations) };
  assert.equal((await store.accept(bad, T0)).ok, false);
  assert.equal(await reason(store, T0), 'no-state');
  void org;
});

test('rollback: lower versions and same-version different bytes rejected; identical is a no-op', async (t) => {
  const { org, docs, open, dir } = await setup(t);
  const store = await open();
  const base = await docs();
  const v2List = await newList(org, path.join(dir + '-v2.json'), T0);
  const v3List = await newList(org, path.join(dir + '-v3.json'), T0);
  assert.ok((await store.accept({ ...base, revocationsBytes: v2List }, T0)).ok);
  assert.deepEqual(await store.accept({ ...base, revocationsBytes: v2List }, T0), { ok: true, changed: false });
  // lower list version
  assert.equal((await store.accept(base, T0)).ok, false);
  // same version, different bytes (re-signed later => different issued_at => different bytes)
  const v2b = await newList(org, dir + '-v2b.json', daysAfter(T0, 1));
  void v3List;
  assert.equal((await store.accept({ ...base, revocationsBytes: v2b }, daysAfter(T0, 1))).ok, false);
  // lower trust-root version
  const oldTrust = base.trustRootBytes;
  await addApprover({ rootKeyPath: org.rootKey, trustRootPath: org.trustRoot, out: dir + '-t2.json', now: T0, publicKeyPath: (await generateKeyPair(dir + '-a.pem', dir + '-a.pub')).publicPath, name: 'Two', scopes: ['*'], expires: '90d' });
  const newTrust = await readFile(dir + '-t2.json');
  assert.ok((await store.accept({ trustRootBytes: newTrust, revocationsBytes: v2List }, T0)).ok);
  assert.equal((await store.accept({ trustRootBytes: oldTrust, revocationsBytes: v2List }, T0)).ok, false);
  // same trust-root version, different bytes
  await addApprover({ rootKeyPath: org.rootKey, trustRootPath: org.trustRoot, out: dir + '-alt.json', now: T0, publicKeyPath: (await generateKeyPair(dir + '-b.pem', dir + '-b.pub')).publicPath, name: 'Three', scopes: ['*'], expires: '90d' });
  const sameVersionAlt = await readFile(dir + '-alt.json');
  assert.equal((await store.accept({ trustRootBytes: sameVersionAlt, revocationsBytes: v2List }, T0)).ok, false);
  // rollback state survives reopen
  const re = await open();
  assert.equal((await re.accept(base, T0)).ok, false);
});

test('expired list: not ready, and a failed accept does not restore readiness', async (t) => {
  const { org, docs, open, dir } = await setup(t);
  const store = await open();
  const short = await newList(org, dir + '-s.json', T0, '1d');
  assert.ok((await store.accept({ ...(await docs()), revocationsBytes: short }, T0)).ok);
  const later = daysAfter(T0, 2);
  assert.equal(await reason(store, later), 'list-expired');
  assert.equal((await store.accept(await docs(), later)).ok, false); // old v1 list: rolled back and expired
  assert.equal(await reason(store, later), 'list-expired');
  const fresh = await newList(org, dir + '-f.json', later, '30d', dir + '-s.json');
  assert.ok((await store.accept({ ...(await docs()), revocationsBytes: fresh }, later)).ok);
  assert.equal(await reason(store, later), 'ready');
});

test('maxListAgeMs counts from issuance, not acceptance', async (t) => {
  const { docs, open } = await setup(t, { maxListAgeMs: 2 * 86_400_000 });
  const store = await open();
  const day3 = daysAfter(T0, 3);
  // list issued at T0 is already too old at day 3, even if it is accepted "now"
  assert.equal((await store.accept(await docs(), day3)).ok, false);
  assert.ok((await store.accept(await docs(), daysAfter(T0, 1))).ok);
  assert.equal(await reason(store, daysAfter(T0, 1)), 'ready');
  assert.equal(await reason(store, day3), 'list-expired');
});

test('clock moved backwards beyond skew: not ready, recovers; high-water never regresses', async (t) => {
  const { docs, open } = await setup(t);
  const store = await open();
  assert.ok((await store.accept(await docs(), T0)).ok);
  const t1 = daysAfter(T0, 2);
  assert.equal(await reason(store, t1), 'ready');
  assert.equal(await reason(store, T0), 'clock-moved-backwards');
  assert.equal(await reason(store, new Date(t1.getTime() - CLOCK_SKEW_MS + MIN)), 'ready');
  assert.equal(await reason(store, T0), 'clock-moved-backwards'); // still measured against t1
  assert.equal(await reason(store, new Date(t1.getTime() + MIN)), 'ready');
  // persisted: a reopened store at an earlier clock is refused
  const re = await open(T0);
  assert.equal(await reason(re, T0), 'clock-moved-backwards');
});

test('crash cases: temp files ignored, orphan docs ignored, tampering and symlinks are state-corrupt', async (t) => {
  const { docs, open, dir } = await setup(t);
  const store = await open();
  assert.ok((await store.accept(await docs(), T0)).ok);
  const files = await readdir(dir);
  const trustFile = files.find((f) => f.startsWith('trust-root.'))!;
  const listFile = files.find((f) => f.startsWith('revocations.'))!;

  // crash before manifest rename: stray temp + orphan new document -> old state still served
  await writeFile(path.join(dir, '.manifest.json.abc.tmp'), 'partial');
  await writeFile(path.join(dir, `revocations.${'a'.repeat(64)}.json`), 'new but uncommitted');
  assert.equal(await reason(await open(), T0), 'ready');

  // manifest pointing at a missing file
  const saved = await readFile(path.join(dir, listFile));
  await unlink(path.join(dir, listFile));
  assert.equal(await reason(await open(), T0), 'state-corrupt');
  // corrupt store refuses accept
  assert.equal((await (await open()).accept(await docs(), T0)).ok, false);

  // tampered committed file
  await writeFile(path.join(dir, listFile), Buffer.concat([saved, Buffer.from(' ')]));
  assert.equal(await reason(await open(), T0), 'state-corrupt');

  // symlinked document with correct bytes
  await unlink(path.join(dir, listFile));
  await writeFile(dir + '-real.json', saved);
  await symlink(dir + '-real.json', path.join(dir, listFile));
  assert.equal(await reason(await open(), T0), 'state-corrupt');
  await unlink(path.join(dir, listFile));
  await writeFile(path.join(dir, listFile), saved);
  assert.equal(await reason(await open(), T0), 'ready');

  // unparseable manifest
  await writeFile(path.join(dir, 'manifest.json'), '{not json');
  assert.equal(await reason(await open(), T0), 'state-corrupt');
  void trustFile;
});

test('store directory: group-writable or symlinked is refused', async (t) => {
  const { dir, open } = await setup(t);
  await mkdir(dir, { mode: 0o700 });
  await chmod(dir, 0o770);
  await assert.rejects(open(), /writable/);
  await chmod(dir, 0o700);
  const link = dir + '-link';
  await symlink(dir, link);
  await assert.rejects(openTrustStore(link, { rootFingerprint: 'x', now: T0 }), /symlink/);
});

async function lists(org: Org, dir: string) {
  const v2 = await newList(org, dir + '-v2.json', T0);
  const v3 = await newList(org, dir + '-v3.json', T0, '30d', dir + '-v2.json');
  return { v2, v3 };
}

for (const v3First of [true, false]) {
  test(`concurrent accept of v3 and v2 (${v3First ? 'v3' : 'v2'} called first): no rollback, reopen reports v3`, async (t) => {
    const { org, docs, open, dir } = await setup(t);
    const store = await open();
    const base = await docs();
    const { v2, v3 } = await lists(org, dir);
    assert.ok((await store.accept(base, T0)).ok);
    const a3 = () => store.accept({ ...base, revocationsBytes: v3 }, T0);
    const a2 = () => store.accept({ ...base, revocationsBytes: v2 }, T0);
    let r3, r2;
    if (v3First) [r3, r2] = await Promise.all([a3(), a2()]);
    else [r2, r3] = await Promise.all([a2(), a3()]);
    assert.ok(r3.ok);
    // v2 can only succeed if it genuinely ran before v3; after v3 it must be rejected
    assert.equal(r2.ok, !v3First);
    for (const s of [store, await open()]) {
      const cur = await s.current(T0);
      assert.ok(cur.ready);
      assert.equal(cur.versions.revocationsVersion, 3);
    }
  });
}

test('time persistence interleaved with accept never rolls the manifest back', async (t) => {
  const { org, docs, open, dir } = await setup(t);
  const store = await open();
  const base = await docs();
  const { v2 } = await lists(org, dir);
  assert.ok((await store.accept(base, T0)).ok);
  const t2 = new Date(T0.getTime() + 2 * MIN);
  const results = await Promise.all([
    store.current(t2),
    store.accept({ ...base, revocationsBytes: v2 }, t2),
    store.current(new Date(T0.getTime() + 4 * MIN)),
    store.current(new Date(T0.getTime() + 6 * MIN)),
  ]);
  assert.ok((results[1] as { ok: boolean }).ok);
  const later = new Date(T0.getTime() + 7 * MIN);
  assert.equal((await store.accept(base, later)).ok, false);
  const re = await open(later);
  const cur = await re.current(later);
  assert.ok(cur.ready);
  assert.equal(cur.versions.revocationsVersion, 2);
});

test('missing manifest with committed documents is state-corrupt, not a fresh store', async (t) => {
  const { org, docs, open, dir } = await setup(t);
  const store = await open();
  const base = await docs();
  const { v3 } = await lists(org, dir);
  assert.ok((await store.accept({ ...base, revocationsBytes: v3 }, T0)).ok);
  await unlink(path.join(dir, 'manifest.json'));
  const re = await open();
  assert.equal(await reason(re, T0), 'state-corrupt');
  const res = await re.accept(base, T0);
  assert.ok(!res.ok && res.reason === 'state-corrupt');
});

test('stale second instance cannot roll back; its current() sees the newer state', async (t) => {
  const { org, docs, open, dir } = await setup(t);
  const base = await docs();
  const { v2, v3 } = await lists(org, dir);
  const a = await open();
  const b = await open();
  assert.ok((await a.accept(base, T0)).ok);
  assert.ok((await b.accept({ ...base, revocationsBytes: v3 }, T0)).ok);
  const cur = await a.current(T0);
  assert.ok(cur.ready);
  assert.equal(cur.versions.revocationsVersion, 3);
  assert.equal((await a.accept({ ...base, revocationsBytes: v2 }, T0)).ok, false);
  const fresh = await (await open()).current(T0);
  assert.ok(fresh.ready);
  assert.equal(fresh.versions.revocationsVersion, 3);
});

test('two instances accepting alternately: highest wins, nothing live is deleted', async (t) => {
  const { org, docs, open, dir } = await setup(t);
  const base = await docs();
  const chain: Buffer[] = [];
  let from = org.revocations;
  for (let v = 2; v <= 6; v++) { chain.push(await newList(org, `${dir}-c${v}.json`, T0, '30d', from)); from = `${dir}-c${v}.json`; }
  const a = await open();
  const b = await open();
  for (const [i, list] of chain.entries()) {
    const res = await (i % 2 === 0 ? a : b).accept({ ...base, revocationsBytes: list }, T0);
    assert.ok(res.ok, JSON.stringify(res));
  }
  for (const s of [a, b, await open()]) {
    const cur = await s.current(T0);
    assert.ok(cur.ready);
    assert.equal(cur.versions.revocationsVersion, 6);
  }
  assert.equal((await readdir(dir)).length, 3);
});

test('time persistence paused mid-write cannot interleave with a queued accept (deterministic)', async (t) => {
  const { org, docs, open, dir } = await setup(t);
  const base = await docs();
  const { v2 } = await lists(org, dir);
  let release!: () => void;
  let reached!: () => void;
  const gate = new Promise<void>((r) => { release = r; });
  const hit = new Promise<void>((r) => { reached = r; });
  let first = true;
  const store = await open(T0, { testHooks: { beforeManifestWrite: async () => {
    if (!first) return;
    first = false;
    reached();
    await gate;
  } } });
  assert.ok((await store.accept(base, T0)).ok);
  const t2 = new Date(T0.getTime() + 2 * MIN);
  const pCur = store.current(t2); // persists time; paused before the manifest write
  await hit;
  const pAcc = store.accept({ ...base, revocationsBytes: v2 }, t2); // queued behind current()
  // Give an unlocked accept ample time to commit while current() is paused; under the lock it stays queued.
  await Promise.race([pAcc, new Promise((r) => setTimeout(r, 300))]);
  release();
  assert.ok((await pCur as { ready: boolean }).ready);
  assert.ok((await pAcc).ok);
  const later = new Date(T0.getTime() + 3 * MIN);
  assert.equal((await store.accept(base, later)).ok, false);
  const cur = await (await open(later)).current(later);
  assert.ok(cur.ready);
  assert.equal(cur.versions.revocationsVersion, 2);
});

test('a trust root past its expiry reports trust-root-expired', async (t) => {
  const { docs, open } = await setup(t);
  const store = await open();
  assert.ok((await store.accept(await docs(), T0)).ok);
  assert.equal(await reason(store, daysAfter(T0, 400)), 'trust-root-expired');
});

test('a running instance refuses a reload that replays an older committed set', async (t) => {
  const { org, docs, open, dir } = await setup(t);
  const base = await docs();
  const { v3 } = await lists(org, dir);
  const a = await open();
  assert.ok((await a.accept(base, T0)).ok);
  const snapshot = `${dir}-snapshot`;
  await cp(dir, snapshot, { recursive: true });
  t.after(() => rm(snapshot, { recursive: true, force: true }));
  assert.ok((await a.accept({ ...base, revocationsBytes: v3 }, T0)).ok);
  // Replay the older complete set (manifest + documents) behind the running instance's back.
  for (const name of await readdir(dir)) await rm(path.join(dir, name));
  for (const name of await readdir(snapshot)) await cp(path.join(snapshot, name), path.join(dir, name));
  const cur = await a.current(T0);
  assert.equal(cur.ready, false);
  assert.equal(cur.ready ? '' : cur.reason, 'state-corrupt');
});
