import assert from 'node:assert/strict';
import { chmod, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import test, { type TestContext } from 'node:test';
import { MAX_LOG, MAX_SESSIONS, MAX_SET, MAX_STARTUP_AGE_MS, MAX_TOMBSTONES, START_MARGIN_MS, openAdmissionStore } from '../src/gate/admission.ts';
import { canonicalBytes } from '../src/canonical-json.ts';
import type { Verdict } from '../src/verify.ts';
import { tempDir } from './helpers.ts';

async function setup(t: TestContext) {
  const dir = path.join(await tempDir(t, 'mago-ski-adm-'), 'state');
  const verdicts = new Map<string, Verdict>();
  const check = async (_n: string, d: string): Promise<Verdict> => verdicts.get(d) ?? 'NO_CERTIFICATE';
  const open = (bootId = 'boot-1') => openAdmissionStore(dir, { bootId });
  return { dir, verdicts, check, open };
}
const ok = (r: { ok: boolean }) => assert.equal(r.ok, true);
const V = 'VERIFIED' as const;
// Step k publishes at at(k); a session "after step k" starts 6 min later, so its skew-adjusted cutoff lies after step k only.
const T0 = 0; // boot ms
const at = (k: number) => k * 600_000;
type Store = Awaited<ReturnType<typeof openAdmissionStore>>;
const adm = (s: Store, ref: string, k: number) => { const d = at(k) + 360_000; return s.admitSession(ref, d, { startedBootMs: d }); };

test('admit then assess with one generation', async (t) => {
  const { open, verdicts, check } = await setup(t);
  const s = await open();
  verdicts.set('d1', V);
  ok(await s.publish('n', 'd1', at(1)));
  ok(await adm(s, 's', 1));
  assert.deepEqual(await s.assess('s', 'n', check), { kind: 'verdict', verdict: V, digests: ['d1'] });
  verdicts.set('d1', 'REVOKED');
  assert.equal((await s.assess('s', 'n', check) as { verdict: string }).verdict, 'REVOKED');
});

test('plain update keeps allowing; three generations with revoked middle is denied', async (t) => {
  const { open, verdicts, check } = await setup(t);
  const s = await open();
  for (const d of ['d1', 'd2', 'd3']) verdicts.set(d, V);
  ok(await s.publish('n', 'd1', at(1)));
  ok(await adm(s, 's', 1));
  ok(await s.publish('n', 'd2', at(2)));
  assert.deepEqual(await s.assess('s', 'n', check), { kind: 'verdict', verdict: V, digests: ['d1', 'd2'] });
  ok(await s.publish('n', 'd3', at(3)));
  verdicts.set('d2', 'REVOKED');
  verdicts.set('d1', 'EXPIRED');
  const r = await s.assess('s', 'n', check);
  assert.deepEqual(r, { kind: 'verdict', verdict: 'REVOKED', digests: ['d1', 'd2', 'd3'] }); // REVOKED outranks EXPIRED; d3 valid
});

test('a session admitted after v2 does not carry v1; a session that never used N still has its history', async (t) => {
  const { open, verdicts, check } = await setup(t);
  const s = await open();
  for (const d of ['d1', 'd2']) verdicts.set(d, V);
  ok(await s.publish('n', 'd1', at(1)));
  ok(await adm(s, 'old', 1));
  ok(await s.publish('n', 'd2', at(2)));
  ok(await adm(s, 'new', 2));
  verdicts.set('d1', 'REVOKED');
  assert.equal((await s.assess('new', 'n', check) as { verdict: string }).verdict, V);
  assert.deepEqual(await s.assess('new', 'n', check), { kind: 'verdict', verdict: V, digests: ['d2'] });
  assert.equal((await s.assess('old', 'n', check) as { verdict: string }).verdict, 'REVOKED');
});

test('uninstall denies; re-publish keeps old sessions carrying the revoked digest, new sessions allowed', async (t) => {
  const { open, verdicts, check } = await setup(t);
  const s = await open();
  for (const d of ['d1', 'd2']) verdicts.set(d, V);
  ok(await s.publish('n', 'd1', at(1)));
  ok(await adm(s, 'old', 1));
  ok(await s.uninstall('n', at(2)));
  assert.deepEqual(await s.assess('old', 'n', check), { kind: 'error', reason: 'not-installed' });
  ok(await adm(s, 'mid', 2)); // admitted while uninstalled
  verdicts.set('d1', 'REVOKED');
  ok(await s.publish('n', 'd2', at(3)));
  ok(await adm(s, 'new', 3));
  assert.equal((await s.assess('old', 'n', check) as { verdict: string }).verdict, 'REVOKED');
  assert.deepEqual(await s.assess('mid', 'n', check), { kind: 'verdict', verdict: V, digests: ['d2'] });
  assert.deepEqual(await s.assess('new', 'n', check), { kind: 'verdict', verdict: V, digests: ['d2'] });
  assert.deepEqual(await s.assess('new', 'other', check), { kind: 'error', reason: 'not-installed' });
});

test('unknown session, replayed admit, end session', async (t) => {
  const { open, verdicts, check } = await setup(t);
  const s = await open();
  verdicts.set('d1', V);
  ok(await s.publish('n', 'd1', T0));
  assert.deepEqual(await s.assess('nope', 'n', check), { kind: 'error', reason: 'no-session-record' });
  ok(await s.admitSession('s', T0, { startedBootMs: T0 }));
  assert.deepEqual(await s.admitSession('s', T0, { startedBootMs: T0 }), { ok: false, reason: 'session-exists' });
  ok(await s.endSession('s'));
  assert.deepEqual(await s.assess('s', 'n', check), { kind: 'error', reason: 'no-session-record' });
});

test('restart preserves sessions and log; a different boot id forgets all sessions but keeps the install', async (t) => {
  const { open, verdicts, check } = await setup(t);
  let s = await open();
  for (const d of ['d1', 'd2']) verdicts.set(d, V);
  ok(await s.publish('n', 'd1', at(1)));
  ok(await adm(s, 's', 1));
  ok(await s.publish('n', 'd2', at(2)));
  s = await open();
  assert.deepEqual(await s.assess('s', 'n', check), { kind: 'verdict', verdict: V, digests: ['d1', 'd2'] });
  s = await open('boot-2');
  assert.deepEqual(await s.assess('s', 'n', check), { kind: 'error', reason: 'no-session-record' });
  ok(await adm(s, 's', 2)); // a new boot may reuse the ref
  assert.deepEqual(await s.assess('s', 'n', check), { kind: 'verdict', verdict: V, digests: ['d2'] });
});

test('corrupt or missing state file is state-corrupt and never reset', async (t) => {
  const { open, dir, check } = await setup(t);
  let s = await open();
  ok(await s.publish('n', 'd1', T0));
  ok(await s.admitSession('s', T0, { startedBootMs: T0 }));
  await writeFile(path.join(dir, 'admission.json'), '{"nope":1}');
  s = await open();
  assert.deepEqual(await s.assess('s', 'n', check), { kind: 'error', reason: 'state-corrupt' });
  assert.deepEqual(await s.publish('n', 'd2', T0), { ok: false, reason: 'state-corrupt' });
  await rm(path.join(dir, 'admission.json'));
  await writeFile(path.join(dir, 'stray.txt'), 'x');
  s = await open();
  assert.deepEqual(await s.admitSession('x', T0, { startedBootMs: T0 }), { ok: false, reason: 'state-corrupt' });
});

test('state changed underneath a running instance: older state is corrupt, newer is adopted', async (t) => {
  const { open, dir, check, verdicts } = await setup(t);
  const a = await open();
  ok(await a.publish('n', 'd1', at(1)));
  const old = await (await import('node:fs/promises')).readFile(path.join(dir, 'admission.json'));
  const b = await open();
  ok(await b.publish('n', 'd2', at(2)));
  verdicts.set('d2', V);
  ok(await adm(b, 's', 2));
  assert.deepEqual(await a.assess('s', 'n', check), { kind: 'verdict', verdict: V, digests: ['d2'] }); // adopted newer state
  await writeFile(path.join(dir, 'admission.json'), old); // rollback
  assert.deepEqual(await a.assess('s', 'n', check), { kind: 'error', reason: 'state-corrupt' });
});

test('check throwing or returning garbage is an error, not VERIFIED', async (t) => {
  const { open } = await setup(t);
  const s = await open();
  ok(await s.publish('n', 'd1', T0));
  ok(await s.admitSession('s', T0, { startedBootMs: T0 }));
  assert.deepEqual(await s.assess('s', 'n', async () => { throw new Error('boom'); }), { kind: 'error', reason: 'internal' });
  assert.deepEqual(await s.assess('s', 'n', async () => 'NOPE' as never), { kind: 'error', reason: 'internal' });
});

test('concurrent operations are serialised without lost updates', async (t) => {
  const { open, verdicts, check, dir } = await setup(t);
  const s = await open();
  const digests = Array.from({ length: 20 }, (_, i) => `d${i}`);
  digests.forEach((d) => verdicts.set(d, V));
  ok(await s.publish('n', 'd0', T0));
  const results = await Promise.all([
    ...digests.slice(1).map((d) => s.publish('n', d, T0)),
    ...Array.from({ length: 20 }, (_, i) => s.admitSession(`s${i}`, T0, { startedBootMs: T0 })),
    s.assess('s0', 'n', check),
  ]);
  results.slice(0, 39).forEach((r) => ok(r as { ok: boolean }));
  const again = await open();
  const r = await again.assess('s0', 'n', check);
  assert.ok(r.kind === 'verdict');
  // s0's set is d(current at its admission) + everything after; together with the final current it has no gaps.
  assert.equal(new Set(r.digests).size, r.digests.length);
  assert.equal(r.digests[r.digests.length - 1], 'd19');
  assert.equal((await readdir(dir)).length, 1);
});

test('bounds fail closed: sessions, log with an old session, set size', async (t) => {
  const { open, verdicts, check } = await setup(t);
  const s = await open();
  for (let i = 0; i < MAX_SESSIONS; i++) ok(await s.admitSession(`s${i}`, T0, { startedBootMs: T0 }));
  assert.deepEqual(await s.admitSession('extra', T0, { startedBootMs: T0 }), { ok: false, reason: 'session-limit' });
  for (let i = 1; i < MAX_SESSIONS; i++) await s.endSession(`s${i}`);
  // s0 stays open, so history cannot be folded: the log fills and publishing is refused (not dropped).
  let last: { ok: boolean; reason?: string } = { ok: true };
  for (let i = 0; i < MAX_LOG + 2 && last.ok; i++) last = await s.publish('m', `x${i}`, T0);
  assert.deepEqual(last, { ok: false, reason: 'log-full' });
  assert.deepEqual(await s.assess('s0', 'm', check), { kind: 'error', reason: 'bound-exceeded' });
  // set larger than MAX_SET denies
  const t2 = await open('boot-10'); // new boot: the old sessions are gone and the old log is folded into base
  const later = 2 * MAX_STARTUP_AGE_MS;
  ok(await t2.admitSession('big', later, { startedBootMs: later }));
  for (let i = 0; i < MAX_SET + 1; i++) { verdicts.set(`g${i}`, V); ok(await t2.publish('z', `g${i}`, later)); }
  assert.deepEqual(await t2.assess('big', 'z', check), { kind: 'error', reason: 'bound-exceeded' });
});

test('without open sessions the log is folded away and later sessions still work', async (t) => {
  const { open, verdicts, check } = await setup(t);
  const s = await open();
  const hour = (i: number) => i * 3_600_000;
  for (let i = 0; i < MAX_LOG + 10; i++) { verdicts.set(`d${i}`, V); ok(await s.publish('n', `d${i}`, hour(i))); }
  ok(await s.admitSession('s', hour(MAX_LOG + 10), { startedBootMs: hour(MAX_LOG + 10) }));
  assert.deepEqual(await s.assess('s', 'n', check), { kind: 'verdict', verdict: V, digests: [`d${MAX_LOG + 9}`] });
});

test('expireSessions drops only old sessions; unsafe directories refused', async (t) => {
  const { open, dir, check } = await setup(t);
  const s = await open();
  ok(await s.publish('n', 'd1', T0));
  ok(await s.admitSession('old', T0, { startedBootMs: T0 }));
  ok(await s.admitSession('young', 3_600_000, { startedBootMs: T0 }));
  const r = await s.expireSessions(1_800_000, 3_600_000);
  assert.deepEqual(r, { ok: true, expired: 1 });
  assert.deepEqual(await s.assess('old', 'n', check), { kind: 'error', reason: 'no-session-record' });
  assert.equal((await s.assess('young', 'n', check)).kind, 'verdict');
  await chmod(dir, 0o777);
  await assert.rejects(open(), /writable/);
});

test('prototype-chain keys from check are errors, never VERIFIED', async (t) => {
  const { open } = await setup(t);
  const s = await open();
  ok(await s.publish('n', 'd1', T0));
  ok(await s.admitSession('s', T0, { startedBootMs: T0 }));
  for (const k of ['toString', 'constructor', '__proto__', 'hasOwnProperty', 'valueOf']) {
    assert.deepEqual(await s.assess('s', 'n', async () => k as never), { kind: 'error', reason: 'internal' }, k);
  }
  ok(await s.publish('n', 'd2', T0));
  assert.deepEqual(await s.assess('s', 'n', async (_n, d) => (d === 'd1' ? 'toString' : 'REVOKED') as never), { kind: 'error', reason: 'internal' });
  assert.deepEqual(await s.assess('s', 'n', async (_n, d) => (d === 'd1' ? 'REVOKED' : 'toString') as never), { kind: 'error', reason: 'internal' });
});

test('ended or expired refs cannot be re-admitted in the same boot; a new boot clears the tombstones', async (t) => {
  const { open, verdicts, check } = await setup(t);
  let s = await open();
  verdicts.set('d3', V);
  ok(await s.publish('n', 'd1', at(1)));
  ok(await adm(s, 'S', 1));
  ok(await s.publish('n', 'd2', at(2)));
  ok(await s.publish('n', 'd3', at(3)));
  verdicts.set('d2', 'REVOKED');
  assert.equal((await s.assess('S', 'n', check) as { verdict: string }).verdict, 'REVOKED');
  ok(await s.endSession('S'));
  assert.deepEqual(await adm(s, 'S', 3), { ok: false, reason: 'session-ended' });
  s = await open(); // same boot, restart: tombstone persisted
  assert.deepEqual(await adm(s, 'S', 3), { ok: false, reason: 'session-ended' });
  ok(await adm(s, 'E', 3));
  assert.deepEqual(await s.expireSessions(0, at(100)), { ok: true, expired: 1 });
  assert.deepEqual(await adm(s, 'E', 101), { ok: false, reason: 'session-ended' });
  s = await open('boot-2');
  ok(await adm(s, 'S', 3));
});

test('tombstone bound fails closed instead of evicting', async (t) => {
  const { open } = await setup(t);
  const s = await open();
  let now = 0;
  for (let round = 0; round < MAX_TOMBSTONES / MAX_SESSIONS; round++) {
    for (let i = 0; i < MAX_SESSIONS; i++) ok(await s.admitSession(`r${round}-${i}`, now, { startedBootMs: now }));
    now += 1000;
    assert.deepEqual(await s.expireSessions(-0, now), { ok: true, expired: MAX_SESSIONS });
  }
  assert.deepEqual(await s.admitSession('fresh', now, { startedBootMs: now }), { ok: false, reason: 'session-limit' });
  assert.deepEqual(await s.admitSession('r0-0', now, { startedBootMs: now }), { ok: false, reason: 'session-ended' });
  assert.deepEqual(await s.endSession('unknown'), { ok: false, reason: 'session-limit' }); // full: fail closed
});

test('the admission race: a Skill snapshot taken before a revoking publish still counts', async (t) => {
  const { open, verdicts, check } = await setup(t);
  const s = await open();
  const min = (m: number) => m * 60_000;
  verdicts.set('v2', V);
  ok(await s.publish('n', 'v1', min(0)));
  ok(await s.publish('n', 'v2', min(20))); // host started at min 10 (snapshot v1); v1 revoked
  verdicts.set('v1', 'REVOKED');
  ok(await s.admitSession('S', min(30), { startedBootMs: min(10) }));
  assert.deepEqual(await s.assess('S', 'n', check), { kind: 'verdict', verdict: 'REVOKED', digests: ['v1', 'v2'] });
  // a start within the margin after v1 is conservatively treated as before it
  ok(await s.admitSession('S2', min(30), { startedBootMs: START_MARGIN_MS / 2 }));
  assert.deepEqual((await s.assess('S2', 'n', check) as { digests: string[] }).digests, ['v1', 'v2']);
});

test('startedBootMs in the future or beyond the startup window is refused; non-integers throw', async (t) => {
  const { open, check } = await setup(t);
  const s = await open();
  ok(await s.publish('n', 'd1', T0));
  assert.deepEqual(await s.admitSession('f', T0, { startedBootMs: T0 + 600_000 }), { ok: false, reason: 'invalid-start' });
  assert.deepEqual(await s.admitSession('o', 2 * MAX_STARTUP_AGE_MS, { startedBootMs: T0 }), { ok: false, reason: 'invalid-start' });
  assert.throws(() => s.admitSession('n', T0, { startedBootMs: NaN }), /boot ms/);
  assert.throws(() => s.admitSession('n', T0, { startedBootMs: 1.5 }), /boot ms/);
  assert.throws(() => s.publish('n', 'd', -1), /boot ms/);
  assert.deepEqual(await s.assess('f', 'n', check), { kind: 'error', reason: 'no-session-record' });
});

test('a non-monotonic clock cannot drop a generation: backwards publish/admit/expire are refused', async (t) => {
  const { open, verdicts, check } = await setup(t);
  const s = await open();
  verdicts.set('v2', V);
  ok(await s.publish('n', 'v1', 100_000));
  assert.deepEqual(await s.publish('n', 'v2', 50_000), { ok: false, reason: 'clock-moved-backwards' });
  assert.deepEqual(await s.admitSession('S', 50_000, { startedBootMs: 40_000 }), { ok: false, reason: 'clock-moved-backwards' });
  assert.deepEqual(await s.expireSessions(0, 50_000), { ok: false, reason: 'clock-moved-backwards' });
  // the correct monotonic sequence: host started before v2, v1 revoked
  ok(await s.admitSession('S', 100_000 + 5000, { startedBootMs: 100_000 + 5000 }));
  ok(await s.publish('n', 'v2', 100_000 + 10_000));
  verdicts.set('v1', 'REVOKED');
  assert.deepEqual(await s.assess('S', 'n', check), { kind: 'verdict', verdict: 'REVOKED', digests: ['v1', 'v2'] });
});

test('uninstall with a lower bootMs still succeeds and is stamped with the high time', async (t) => {
  const { open, dir } = await setup(t);
  const s = await open();
  ok(await s.publish('n', 'd1', 5000));
  ok(await s.uninstall('n', 1000));
  const doc = JSON.parse(await readFile(path.join(dir, 'admission.json'), 'utf8'));
  assert.deepEqual(doc.log.map((e: { at_boot_ms: number }) => e.at_boot_ms), [5000, 5000]);
  assert.equal(doc.high_boot_ms, 5000);
  assert.deepEqual(await s.publish('n', 'd2', 4000), { ok: false, reason: 'clock-moved-backwards' });
});

test('an admission whose start precedes the fold is refused (natural fold and persisted watermark)', async (t) => {
  const { open, dir } = await setup(t);
  const s = await open();
  ok(await s.publish('n', 'v1', 1000));
  ok(await s.publish('n', 'v2', 1000 + MAX_STARTUP_AGE_MS + 10_000)); // folds v1
  const now = 1000 + MAX_STARTUP_AGE_MS + 20_000;
  assert.deepEqual(await s.admitSession('A', now, { startedBootMs: 1500 }), { ok: false, reason: 'invalid-start' });
  // watermark enforced by itself: crafted state with a recent fold
  const file = path.join(dir, 'admission.json');
  await writeFile(file, canonicalBytes({ type: 'mago.gate-admission/v1', boot_id: 'boot-1', seq: 2, high_boot_ms: 10_000, folded_at_boot_ms: 5000,
    log: [], base: [{ name: 'n', digest: 'v1' }], sessions: [], ended: [] }));
  const s2 = await open();
  assert.deepEqual(await s2.admitSession('B', 10_000, { startedBootMs: 5000 + START_MARGIN_MS }), { ok: false, reason: 'invalid-start' });
  ok(await s2.admitSession('C', 10_000, { startedBootMs: 5000 + START_MARGIN_MS + 1 }));
});

test('endSession of an unknown ref tombstones it', async (t) => {
  const { open } = await setup(t);
  const s = await open();
  ok(await s.endSession('ghost'));
  assert.deepEqual(await s.admitSession('ghost', T0, { startedBootMs: T0 }), { ok: false, reason: 'session-ended' });
});

test('a boot id change folds the log into base and resets the boot-relative times', async (t) => {
  const { open, check, verdicts, dir } = await setup(t);
  let s = await open();
  verdicts.set('d2', V);
  ok(await s.publish('n', 'd1', 900_000));
  ok(await s.publish('n', 'd2', 950_000));
  s = await open('boot-2');
  const doc = JSON.parse(await readFile(path.join(dir, 'admission.json'), 'utf8'));
  assert.deepEqual([doc.log, doc.high_boot_ms, doc.folded_at_boot_ms, doc.base], [[], 0, 0, [{ name: 'n', digest: 'd2' }]]);
  ok(await s.admitSession('S', 10, { startedBootMs: 5 })); // small boot ms in the new boot
  assert.deepEqual(await s.assess('S', 'n', check), { kind: 'verdict', verdict: V, digests: ['d2'] });
  ok(await s.publish('n', 'd3', 20));
});

test('compaction keeps entries inside the startup window', async (t) => {
  const { open, check } = await setup(t);
  const s = await open();
  const h = (n: number) => n * 3_600_000;
  ok(await s.publish('n', 'v1', h(0)));
  ok(await s.publish('n', 'v2', h(23)));
  ok(await s.publish('n', 'v3', h(25))); // folds v1 (older than 24 h) into base; v2 stays in the log
  const start = h(1) + 360_000; // cutoff just after h(1): before v2, after folded v1
  ok(await s.admitSession('A', h(25), { startedBootMs: start }));
  assert.deepEqual((await s.assess('A', 'n', check) as { digests: string[] }).digests, ['v1', 'v2', 'v3']);
  ok(await s.admitSession('B', h(25), { startedBootMs: h(24) }));
  assert.deepEqual((await s.assess('B', 'n', check) as { digests: string[] }).digests, ['v2', 'v3']);
});

test('uninstall always succeeds when installed, even with a full log', async (t) => {
  const { open, check } = await setup(t);
  const s = await open();
  ok(await s.admitSession('pin', T0, { startedBootMs: T0 })); // pins the log
  let last: { ok: boolean; reason?: string } = { ok: true };
  for (let i = 0; i < MAX_LOG + 2 && last.ok; i++) last = await s.publish('m', `x${i}`, T0);
  assert.deepEqual(last, { ok: false, reason: 'log-full' });
  ok(await s.uninstall('m', T0));
  assert.deepEqual(await s.assess('pin', 'm', check), { kind: 'error', reason: 'not-installed' });
  ok(await s.uninstall('m', T0)); // already uninstalled: no new entry
});

test('expireSessions rejects a non-finite or negative maxAgeMs', async (t) => {
  const { open } = await setup(t);
  const s = await open();
  for (const bad of [NaN, Infinity, -1]) await assert.rejects(s.expireSessions(bad, T0), /maxAgeMs/);
});

test('duplicate or inconsistent state (duplicates, decreasing times, open and ended ref) is state-corrupt', async (t) => {
  const { open, dir, check } = await setup(t);
  await (await open()).publish('n', 'd1', T0); // creates the state file
  const file = path.join(dir, 'admission.json');
  const doc = (over: Record<string, unknown>) => canonicalBytes({
    type: 'mago.gate-admission/v1', boot_id: 'boot-1', seq: 2, high_boot_ms: 10, folded_at_boot_ms: 0, log: [], base: [], sessions: [], ended: [], ...over,
  });
  const ts = 0;
  const cases: Record<string, unknown>[] = [
    { base: [{ name: 'n', digest: 'a' }, { name: 'n', digest: 'b' }] },
    { sessions: [{ ref: 's', seq: 0, at_boot_ms: ts }, { ref: 's', seq: 0, at_boot_ms: ts }] },
    { log: [{ seq: 1, name: 'n', digest: 'a', at_boot_ms: ts }, { seq: 1, name: 'n', digest: 'b', at_boot_ms: ts }] },
    { ended: ['x', 'x'] },
    { log: [{ seq: 1, name: 'n', digest: 'a', at_boot_ms: 5 }, { seq: 2, name: 'n', digest: 'b', at_boot_ms: 3 }] }, // decreasing time
    { sessions: [{ ref: 's', seq: 0, at_boot_ms: ts }], ended: ['s'] }, // open and ended
  ];
  for (const c of cases) {
    await writeFile(file, doc(c));
    assert.deepEqual(await (await open()).assess('s', 'n', check), { kind: 'error', reason: 'state-corrupt' }, JSON.stringify(c));
  }
});

// Reaping is valid only because the service's kernel-derived refs (pid:starttime) cannot recur within a boot; with
// employee-supplied refs a reaped ref could be re-admitted to shed history, which is why endSession tombstones instead.
const H = 3_600_000;
async function reapSetup(t: TestContext) {
  const { dir, open, verdicts, check } = await setup(t);
  const s = await open();
  for (const d of ['d1', 'd2', 'd3']) verdicts.set(d, V);
  ok(await s.publish('n', 'd1', 1 * H));
  ok(await s.admitSession('a', 1.5 * H, { startedBootMs: 1.5 * H }));
  ok(await s.publish('n', 'd2', 2 * H));
  ok(await s.publish('n', 'd3', 27 * H));
  ok(await s.admitSession('c', 27 * H, { startedBootMs: 27 * H }));
  const logLen = async () => (JSON.parse(await readFile(path.join(dir, 'admission.json'), 'utf8')) as { log: unknown[] }).log.length;
  return { s, check, logLen };
}

test('reapSessions removes dead sessions only, without tombstoning; others keep their history', async (t) => {
  const { s, check } = await reapSetup(t);
  const r = await s.reapSessions((ref) => ref !== 'a');
  assert.equal(r.ok && r.reaped, 1);
  assert.deepEqual(await s.assess('a', 'n', check), { kind: 'error', reason: 'no-session-record' });
  assert.equal((await s.assess('c', 'n', check) as { verdict: string }).verdict, V);
  assert.equal((await s.reapSessions(() => true) as { reaped: number }).reaped, 0);
  assert.equal((await s.reapSessions(() => { throw new Error('x'); }) as { reaped: number }).reaped, 0); // throwing keeps
  // not tombstoned: a fresh admission of the same ref is a new session (only safe for refs that cannot recur)
  ok(await s.admitSession('a', 27 * H, { startedBootMs: 27 * H }));
  assert.deepEqual(await s.assess('a', 'n', check), { kind: 'verdict', verdict: V, digests: ['d2', 'd3'] }); // fresh history: no d1
});

test('an old open session keeps its full history while it is not reaped', async (t) => {
  const { s, check } = await reapSetup(t);
  ok(await s.reapSessions((ref) => ref === 'a'));
  assert.deepEqual(await s.assess('a', 'n', check), { kind: 'verdict', verdict: V, digests: ['d1', 'd2', 'd3'] });
});

test('reaping a session that pinned the log lets compaction advance', async (t) => {
  const { s, logLen } = await reapSetup(t);
  assert.equal(await logLen(), 2); // d1 folded, d2 and d3 kept because 'a' (admitted after d1) pins d2
  ok(await s.reapSessions((ref) => ref !== 'a'));
  assert.equal(await logLen(), 1); // d2 now folded into base
});

// Transient I/O is injected through the store's test-only `fault` hook (no real fd exhaustion needed).
test('transient read/write errors fail one operation as io-busy without latching or mutating; EIO latches corrupt', async (t) => {
  const { dir, check, verdicts } = await setup(t);
  let fault: string | undefined;
  const s = await openAdmissionStore(dir, { bootId: 'boot-1', fault: () => fault });
  verdicts.set('d1', V);
  ok(await s.publish('n', 'd1', at(1)));
  ok(await adm(s, 's', 1));
  for (const code of ['EMFILE', 'ENFILE', 'EAGAIN', 'EINTR', 'ENOMEM']) {
    fault = code; // every read and write fails
    const busy = { ok: false, reason: 'io-busy' };
    assert.deepEqual(await s.publish('n', 'd2', at(2)), busy);
    assert.deepEqual(await s.reapSessions(() => false), busy);
    assert.deepEqual(await s.assess('s', 'n', check), { kind: 'error', reason: 'io-busy' });
    fault = undefined;
    assert.deepEqual(await s.assess('s', 'n', check), { kind: 'verdict', verdict: V, digests: ['d1'] }); // nothing latched or lost
  }
  // a write-only failure leaves memory unchanged: the retry succeeds and is the only d2 entry
  fault = undefined;
  const wf = { v: undefined as string | undefined };
  const s2 = await openAdmissionStore(dir, { bootId: 'boot-1', fault: (op) => (op === 'write' ? wf.v : undefined) });
  wf.v = 'EMFILE';
  assert.deepEqual(await s2.publish('n', 'd2', at(2)), { ok: false, reason: 'io-busy' });
  wf.v = undefined;
  ok(await s2.publish('n', 'd2', at(2)));
  verdicts.set('d2', V);
  assert.deepEqual(await s2.assess('s', 'n', check), { kind: 'verdict', verdict: V, digests: ['d1', 'd2'] });
  fault = undefined;
  wf.v = 'EIO';
  assert.deepEqual(await s2.publish('n', 'd3', at(3)), { ok: false, reason: 'write-failed' });
  wf.v = undefined;
  assert.deepEqual(await s2.assess('s', 'n', check), { kind: 'error', reason: 'state-corrupt' });
});

test('a slow sweep does not block assess; a session admitted after the snapshot is untouched', async (t) => {
  const { s, check } = await reapSetup(t);
  let release!: () => void;
  const gate = new Promise<void>((r) => { release = r; });
  const asked: string[] = [];
  const sweep = s.reapSessions(async (ref) => { asked.push(ref); await gate; return ref === 'c'; }); // 'a' judged dead, 'c' alive
  while (asked.length === 0) await new Promise((r) => setTimeout(r, 5));
  const r = await Promise.race([s.assess('c', 'n', check), new Promise((res) => setTimeout(() => res('blocked'), 1000))]);
  assert.notEqual(r, 'blocked', 'assess waited for the sweep');
  ok(await s.admitSession('z', 27 * H, { startedBootMs: 27 * H })); // admitted while the sweep waits
  release();
  const done = await sweep;
  assert.equal(done.ok && done.reaped, 1);
  assert.equal(asked.includes('z'), false);
  assert.equal((await s.assess('z', 'n', check)).kind, 'verdict');
  assert.deepEqual(await s.assess('a', 'n', check), { kind: 'error', reason: 'no-session-record' });
});

test('a transient error at open leaves the store unloaded (not corrupt); the next operation loads it', async (t) => {
  const { dir } = await setup(t);
  let fault: string | undefined = 'EMFILE';
  const s = await openAdmissionStore(dir, { bootId: 'boot-1', fault: (op) => (op === 'read' ? fault : undefined) });
  assert.equal(await s.health(), 'unloaded');
  assert.deepEqual(await s.publish('n', 'd1', at(1)), { ok: false, reason: 'io-busy' });
  fault = undefined;
  ok(await s.publish('n', 'd1', at(1)));
  assert.equal(await s.health(), 'ready');
  let eio: string | undefined = 'EIO';
  const bad = await openAdmissionStore(dir, { bootId: 'boot-1', fault: (op) => (op === 'read' ? eio : undefined) });
  assert.equal(await bad.health(), 'corrupt'); // a non-transient error still latches
  eio = undefined;
  assert.equal(await bad.health(), 'corrupt');
});
