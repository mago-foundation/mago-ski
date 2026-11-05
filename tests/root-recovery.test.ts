// Root recovery v1 (docs/spec/root-recovery-v1.md): policy v2, the root event log, host state v2, freshness and
// the once-per-host reporting of trust failures on every host.
import assert from 'node:assert/strict';
import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import test, { type TestContext } from 'node:test';
import { createMagoSkiExtension } from '../hosts/pi/index.ts';
import { runGitHubCheck } from '../hosts/github/run.ts';
import { canonicalBytes, parseCanonicalJsonBytes } from '../src/canonical-json.ts';
import { generateKeyPair, loadPrivateKey } from '../src/keys.ts';
import { loadPolicy, loadPolicyTrust, verifyWithPolicy, type Policy } from '../src/policy.ts';
import {
  adoptTrustDocuments, appendRootEvent, buildRecoverySet, currentRootState, initRootEventLog, prepareRootEvent, signPolicyTimestamp, signRootEvent,
} from '../src/recovery-admin.ts';
import {
  addEnvelopeSignature, clearRootWalkCache, parseRootEventLog, rootEventLogBytes, unsignedEventEnvelope, walkRootEvents, walkRootEventsCached,
} from '../src/root-events.ts';
import { addApprover } from '../src/admin.ts';
import { approve, daysAfter, T0, tempDir, writeSkill } from './helpers.ts';
import { initRoot } from '../src/admin.ts';

const NOW = new Date(T0.getTime() + 60_000);
const later = (minutes: number) => new Date(NOW.getTime() + minutes * 60_000);

interface Key { priv: string; pub: string; keyId: string }

interface RecoveryOrg {
  dir: string;
  policyDir: string;
  policyPath: string;
  statePath: string;
  logPath: string;
  eventsPath: string;
  timestampPath: string;
  trustRoot: string;
  revocations: string;
  root: Key;
  approver: Key;
  recovery: Key[];
  timestamp: Key;
  key: (name: string) => Promise<Key>;
  policy: () => Promise<Policy>;
  writePolicy: (changes: Record<string, unknown>) => Promise<void>;
}

async function setupRecoveryOrg(t: TestContext, options: { mode?: 'shadow' | 'enforce'; freshness?: boolean; rotate?: number; revoke?: number } = {}): Promise<RecoveryOrg> {
  const dir = await tempDir(t, 'mago-ski-recovery-');
  const keys = path.join(dir, 'keys');
  await mkdir(keys);
  const key = async (name: string): Promise<Key> => {
    const pair = await generateKeyPair(path.join(keys, `${name}.pem`), path.join(keys, `${name}.pub`));
    return { priv: pair.privatePath, pub: pair.publicPath, keyId: pair.keyId };
  };
  const root = await key('root');
  const approver = await key('approver');
  const recovery = [await key('a'), await key('b'), await key('c')];
  const timestamp = await key('timestamp');
  const policyDir = path.join(dir, 'policy');
  await mkdir(policyDir);
  const trustRoot = path.join(policyDir, 'trust-root.json');
  const revocations = path.join(policyDir, 'revocations.json');
  const eventsPath = path.join(policyDir, 'root-events.json');
  const timestampPath = path.join(policyDir, 'timestamp.json');
  await initRoot({ rootKeyPath: root.priv, trustRootOut: trustRoot, revocationsOut: revocations, now: T0 });
  await addApprover({ rootKeyPath: root.priv, trustRootPath: trustRoot, now: T0, publicKeyPath: approver.pub, name: 'Reviewer', scopes: ['*'], expires: '180d' });
  await initRootEventLog(eventsPath);
  const set = await buildRecoverySet({ publicKeyPaths: recovery.map((item) => item.pub), rotateThreshold: options.rotate ?? 2, revokeThreshold: options.revoke ?? 1 });
  const policyPath = path.join(policyDir, 'policy.json');
  let document: Record<string, unknown> = {
    policy_version: 'mago.policy/v2',
    mode: options.mode ?? 'shadow',
    root_fingerprint: root.keyId,
    recovery: { key_ids: set.keyIds, rotate_threshold: set.rotateThreshold, revoke_threshold: set.revokeThreshold },
    root_events: 'root-events.json',
    trust_root: 'trust-root.json',
    revocations: 'revocations.json',
    state_file: 'state.json',
    decision_log: 'decisions.jsonl',
    ...(options.freshness ? { freshness: { timestamp: 'timestamp.json', key_id: timestamp.keyId, max_lifetime: '24h' } } : {}),
  };
  const writePolicy = async (changes: Record<string, unknown>) => {
    document = { ...document, ...changes };
    for (const [name, value] of Object.entries(changes)) if (value === undefined) delete document[name];
    await writeFile(policyPath, JSON.stringify(document, null, 2));
  };
  await writePolicy({});
  return {
    dir, policyDir, policyPath, statePath: path.join(policyDir, 'state.json'), logPath: path.join(policyDir, 'decisions.jsonl'),
    eventsPath, timestampPath, trustRoot, revocations, root, approver, recovery, timestamp, key,
    policy: async () => await loadPolicy(policyPath), writePolicy,
  };
}

let proposals = 0;
/** prepare + sign by each key + append, as the CLI does. */
async function event(org: RecoveryOrg, options: {
  action: 'revoke' | 'rotate'; signers: Key[]; signWith?: Key[]; now?: Date; newRoot?: Key; newRecovery?: Key[];
  rotateThreshold?: number; revokeThreshold?: number; newTimestamp?: Key; reason?: string;
}) {
  const out = path.join(org.dir, `proposal-${++proposals}.json`);
  const now = options.now ?? NOW;
  await prepareRootEvent({
    policy: await org.policy(), action: options.action, reason: options.reason ?? `${options.action} for test`, out, now,
    signerPublicPaths: options.signers.map((item) => item.pub),
    newRootPublicPath: options.newRoot?.pub, newRecoveryPublicPaths: options.newRecovery?.map((item) => item.pub),
    rotateThreshold: options.rotateThreshold, revokeThreshold: options.revokeThreshold, newTimestampPublicPath: options.newTimestamp?.pub,
  });
  const signWith = options.signWith ?? [...options.signers, ...(options.newRoot ? [options.newRoot] : []), ...(options.newTimestamp ? [options.newTimestamp] : [])];
  for (const signer of signWith) await signRootEvent({ proposalPath: out, keyPath: signer.priv });
  return { out, append: async () => await appendRootEvent({ policy: await org.policy(), proposalPath: out, now }) };
}

async function readJsonLines(file: string): Promise<Array<Record<string, unknown>>> {
  return (await readFile(file, 'utf8')).trim().split('\n').filter(Boolean).map((line) => JSON.parse(line));
}

test.beforeEach(() => clearRootWalkCache());

test('a v2 policy with an empty log behaves like v1 and keeps a v1 state file', async (t) => {
  const org = await setupRecoveryOrg(t);
  const trust = await loadPolicyTrust(await org.policy(), NOW);
  assert.equal(trust.ok, true);
  assert.equal(trust.ok && trust.context.root?.activeRootKeyId, org.root.keyId);
  assert.equal(trust.ok && trust.context.root?.sequence, 0);
  const state = JSON.parse(await readFile(org.statePath, 'utf8'));
  assert.equal(state.type, 'mago.host-state/v1');
});

test('policy v2 fields are validated', async (t) => {
  const org = await setupRecoveryOrg(t);
  const policy = JSON.parse(await readFile(org.policyPath, 'utf8'));
  const attempt = async (changes: Record<string, unknown>, pattern: RegExp) => {
    const next = { ...policy, ...changes };
    for (const [name, value] of Object.entries(changes)) if (value === undefined) delete next[name];
    await writeFile(org.policyPath, JSON.stringify(next));
    await assert.rejects(loadPolicy(org.policyPath), pattern);
  };
  await attempt({ policy_version: 'mago.policy/v1' }, /needs policy_version "mago.policy\/v2"/u);
  await attempt({ root_events: undefined }, /requires "root_events"/u);
  await attempt({ recovery: undefined }, /"root_events" requires "recovery"/u);
  await attempt({ recovery: { ...policy.recovery, key_ids: [...policy.recovery.key_ids].reverse() } }, /unique and sorted/u);
  await attempt({ recovery: { ...policy.recovery, rotate_threshold: 4 } }, /rotate_threshold <= number of key_ids/u);
  await attempt({ recovery: { ...policy.recovery, revoke_threshold: 3 } }, /revoke_threshold <= rotate_threshold/u);
  await attempt({ recovery: { ...policy.recovery, key_ids: [org.root.keyId, ...policy.recovery.key_ids].sort() } }, /must not include root_fingerprint/u);
  await attempt({ root_events_after: -1 }, /non-negative integer/u);
  await attempt({ freshness: { timestamp: 'timestamp.json', key_id: org.recovery[0]!.keyId } }, /must not be root_fingerprint or a recovery key/u);
  await attempt({ freshness: { timestamp: 'timestamp.json', key_id: org.timestamp.keyId, max_lifetime: '8d' } }, /at most 7d/u);
  await attempt({ freshness: { timestamp: 'timestamp.json', key_id: org.timestamp.keyId, extra: 1 } }, /unsupported field "extra"/u);
  await attempt({ state_file: 'root-events.json' }, /state_file must not be root_events/u);
});

test('a missing root event log is UNVERIFIABLE, so deleting it cannot hide a revocation', async (t) => {
  const org = await setupRecoveryOrg(t);
  await rm(org.eventsPath);
  const trust = await loadPolicyTrust(await org.policy(), NOW);
  assert.equal(trust.ok, false);
  assert.match(!trust.ok ? trust.reason : '', /root event log/u);
  assert.notEqual(!trust.ok && trust.rootRevoked, true);
});

test('revoke, then rotate: one trustee stops trust in every mode, two trustees and the new root restore it', async (t) => {
  const org = await setupRecoveryOrg(t, { mode: 'shadow' });
  const skills = await tempDir(t, 'mago-ski-skills-');
  const skill = await writeSkill(skills, 'docs-helper');
  await approve({ approverKey: org.approver.priv } as never, skill);
  assert.equal((await verifyWithPolicy(await org.policy(), skill, { now: NOW })).verdict, 'VERIFIED');

  // Revoke: revoke_threshold is 1, so trustee A alone is enough.
  await (await event(org, { action: 'revoke', signers: [org.recovery[0]!], reason: 'root.pem appeared in a public CI log' })).append();
  const revoked = await loadPolicyTrust(await org.policy(), later(1));
  assert.equal(revoked.ok, false);
  assert.equal(!revoked.ok && revoked.rootRevoked, true);
  assert.match(!revoked.ok ? revoked.reason : '', /revoked by root event 1 \(root\.pem appeared in a public CI log\); waiting for a rotation/u);
  const state = JSON.parse(await readFile(org.statePath, 'utf8'));
  assert.equal(state.type, 'mago.host-state/v2');
  assert.equal(state.root_events[org.root.keyId].sequence, 1);

  // A second revoke of the same key is refused; the next event must be a rotate.
  await assert.rejects(event(org, { action: 'revoke', signers: [org.recovery[1]!] }), /already revoked/u);

  // Rotate: rotate_threshold 2 of the current set (and of the new, identical set), plus the new root.
  const r1 = await org.key('r1');
  await (await event(org, { action: 'rotate', signers: [org.recovery[0]!, org.recovery[1]!], newRoot: r1, now: later(2) })).append();
  // Until the trust documents are signed by the new root, nothing verifies.
  const stale = await loadPolicyTrust(await org.policy(), later(3));
  assert.equal(stale.ok, false);
  assert.notEqual(!stale.ok && stale.rootRevoked, true);
  await adoptTrustDocuments({ rootKeyPath: r1.priv, fromRootKeyId: org.root.keyId, trustRootPath: org.trustRoot, revocationsPath: org.revocations, now: later(3) });
  const back = await loadPolicyTrust(await org.policy(), later(4));
  assert.equal(back.ok, true);
  assert.equal(back.ok && back.context.root?.activeRootKeyId, r1.keyId);
  // Existing certificates keep verifying: they are signed by approver keys and do not name the root.
  assert.equal((await verifyWithPolicy(await org.policy(), skill, { now: later(4) })).verdict, 'VERIFIED');
  const after = JSON.parse(await readFile(org.statePath, 'utf8'));
  assert.equal(after.root_events[org.root.keyId].sequence, 2);
  assert.ok(after.roots[r1.keyId], 'versions are recorded per root key');
});

test('a thief holding only the root key cannot write root events', async (t) => {
  const org = await setupRecoveryOrg(t);
  const thief = await org.key('thief');
  // The thief cannot sign a proposal as a trustee.
  const { out } = await event(org, { action: 'rotate', signers: [org.recovery[0]!, org.recovery[1]!], newRoot: thief, signWith: [] });
  await assert.rejects(signRootEvent({ proposalPath: out, keyPath: org.root.priv }), /not one of the keys this event must be signed by/u);
  // A hand-made event signed by the root key is rejected by every host.
  const root = await loadPrivateKey(org.root.priv);
  const envelope = addEnvelopeSignature(JSON.parse(await readFile(out, 'utf8')), org.root.keyId, root.privateKey);
  await writeFile(org.eventsPath, rootEventLogBytes([envelope]));
  const trust = await loadPolicyTrust(await org.policy(), NOW);
  assert.equal(trust.ok, false);
  assert.match(!trust.ok ? trust.reason : '', /root event 1 must be signed by exactly/u);
});

test('a rotate needs rotate_threshold signatures and the new root', async (t) => {
  const org = await setupRecoveryOrg(t);
  const r1 = await org.key('r1');
  const one = await event(org, { action: 'rotate', signers: [org.recovery[0]!], newRoot: r1 });
  await assert.rejects(one.append(), /has 1 signature\(s\) from the current recovery set; a rotate needs 2/u);
  const noRoot = await event(org, { action: 'rotate', signers: [org.recovery[0]!, org.recovery[1]!], newRoot: r1, signWith: [org.recovery[0]!, org.recovery[1]!] });
  await assert.rejects(noRoot.append(), /missing signatures from/u);
});

test('an invalid or extra signature rejects the event even if enough valid ones remain', async (t) => {
  const org = await setupRecoveryOrg(t);
  const { out } = await event(org, { action: 'revoke', signers: [org.recovery[0]!] });
  const envelope = JSON.parse(await readFile(out, 'utf8'));
  const extra = await loadPrivateKey(org.recovery[1]!.priv);
  await writeFile(org.eventsPath, rootEventLogBytes([addEnvelopeSignature(envelope, extra.keyId, extra.privateKey)]));
  const policy = await org.policy();
  assert.match((await loadPolicyTrust(policy, NOW) as { reason: string }).reason, /must be signed by exactly/u);

  const forged = { ...envelope, signatures: [{ keyid: envelope.signatures[0].keyid, sig: Buffer.alloc(64, 7).toString('base64') }] };
  await writeFile(org.eventsPath, rootEventLogBytes([forged]));
  assert.match((await loadPolicyTrust(policy, NOW) as { reason: string }).reason, /invalid signature/u);
});

test('rollback to a shorter log and a fork at the same number are both UNVERIFIABLE', async (t) => {
  const org = await setupRecoveryOrg(t);
  const empty = await readFile(org.eventsPath);
  const first = await event(org, { action: 'revoke', signers: [org.recovery[0]!], reason: 'first' });
  const second = await event(org, { action: 'revoke', signers: [org.recovery[1]!], reason: 'second' });
  await first.append();
  assert.equal((await loadPolicyTrust(await org.policy(), NOW) as { rootRevoked?: boolean }).rootRevoked, true);

  await writeFile(org.eventsPath, empty);
  const rolledBack = await loadPolicyTrust(await org.policy(), NOW);
  assert.match(!rolledBack.ok ? rolledBack.reason : '', /has already applied 1 \(rollback\)/u);

  // A different, equally valid event 1: a fork.
  await second.append();
  const forked = await loadPolicyTrust(await org.policy(), NOW);
  assert.match(!forked.ok ? forked.reason : '', /differs from the one this host already applied \(fork\)/u);
  assert.notEqual(!forked.ok && forked.rootRevoked, true);
});

test('a key that left the root role never returns, in any role', async (t) => {
  const org = await setupRecoveryOrg(t);
  await (await event(org, { action: 'revoke', signers: [org.recovery[0]!] })).append();
  // The revoked root cannot be "rotated" back in.
  const back = await event(org, { action: 'rotate', signers: [org.recovery[0]!, org.recovery[1]!], newRoot: org.root, now: later(1) });
  await assert.rejects(back.append(), /has left the root role and cannot return/u);
  const r1 = await org.key('r1');
  await (await event(org, { action: 'rotate', signers: [org.recovery[0]!, org.recovery[1]!], newRoot: r1, now: later(2) })).append();
  // Nor can it become a recovery key.
  const sneaky = await event(org, {
    action: 'rotate', signers: [org.recovery[0]!, org.recovery[1]!], newRoot: r1, now: later(3),
    newRecovery: [org.recovery[0]!, org.recovery[1]!, org.root], rotateThreshold: 2, revokeThreshold: 1,
    signWith: [org.recovery[0]!, org.recovery[1]!, r1],
  });
  await assert.rejects(sneaky.append(), /has held the root or timestamp role/u);
});

test('a rotate can replace the recovery set; the new set must sign too', async (t) => {
  const org = await setupRecoveryOrg(t);
  const [a, b] = org.recovery as [Key, Key, Key];
  const d = await org.key('d');
  const e = await org.key('e');
  const r1 = await org.key('r1');
  // New set {d, e} with rotate_threshold 2: two current signatures and both new ones.
  const missingNew = await event(org, {
    action: 'rotate', signers: [a, b, d], newRoot: r1, newRecovery: [d, e], rotateThreshold: 2, revokeThreshold: 1,
  });
  await assert.rejects(missingNew.append(), /has 1 signature\(s\) from the new recovery set; it needs 2/u);
  await (await event(org, {
    action: 'rotate', signers: [a, b, d, e], newRoot: r1, newRecovery: [d, e], rotateThreshold: 2, revokeThreshold: 1, now: later(1),
  })).append();
  const state = await currentRootState(await org.policy(), later(2));
  assert.deepEqual(state.recovery.keyIds, [d.keyId, e.keyId].sort());
  // The old trustees can no longer revoke.
  await assert.rejects(event(org, { action: 'revoke', signers: [a], now: later(2) }), /not in the current recovery set/u);
});

test('reasons with bidirectional or invisible characters are refused', async (t) => {
  const org = await setupRecoveryOrg(t);
  await assert.rejects(event(org, { action: 'revoke', signers: [org.recovery[0]!], reason: 'ok ‮ txt.exe' }), /bidirectional/u);
  await assert.rejects(event(org, { action: 'revoke', signers: [org.recovery[0]!], reason: 'line\nbreak' }), /control characters/u);
});

test('an event issued in the future is refused, and a failed walk is not cached', async (t) => {
  const org = await setupRecoveryOrg(t);
  const future = await event(org, { action: 'revoke', signers: [org.recovery[0]!], now: later(60) });
  await assert.rejects(appendRootEvent({ policy: await org.policy(), proposalPath: future.out, now: NOW }), /issued in the future/u);
  // Write it by hand: it is valid in an hour, not now.
  const envelope = JSON.parse(await readFile(future.out, 'utf8'));
  await writeFile(org.eventsPath, rootEventLogBytes([envelope]));
  const policy = await org.policy();
  const start = { rootKeyId: org.root.keyId, recovery: policy.recovery!.set, timestampKeyId: null, eventsAfter: 0 };
  const bytes = await readFile(org.eventsPath);
  assert.throws(() => walkRootEventsCached(bytes, start, NOW), /issued in the future/u);
  assert.equal(walkRootEventsCached(bytes, start, later(61)).revoked?.sequence, 1);
});

test('root_events_after lets a host set up after a rotation start at the next event', async (t) => {
  const org = await setupRecoveryOrg(t);
  const r1 = await org.key('r1');
  await (await event(org, { action: 'rotate', signers: [org.recovery[0]!, org.recovery[1]!], newRoot: r1 })).append();
  await adoptTrustDocuments({ rootKeyPath: r1.priv, fromRootKeyId: org.root.keyId, trustRootPath: org.trustRoot, revocationsPath: org.revocations, now: later(1) });
  await org.writePolicy({ root_fingerprint: r1.keyId, root_events_after: 1, state_file: 'state-new.json' });
  assert.equal((await loadPolicyTrust(await org.policy(), later(2))).ok, true);
  await org.writePolicy({ root_events_after: 2 });
  const short = await loadPolicyTrust(await org.policy(), later(2));
  assert.match(!short.ok ? short.reason : '', /fewer than root_events_after/u);
});

test('an approver that is also a recovery key makes the trust root UNVERIFIABLE', async (t) => {
  const org = await setupRecoveryOrg(t);
  await addApprover({ rootKeyPath: org.root.priv, trustRootPath: org.trustRoot, now: T0, publicKeyPath: org.recovery[2]!.pub, name: 'Trustee C', scopes: ['*'], expires: '30d' });
  const trust = await loadPolicyTrust(await org.policy(), NOW);
  assert.match(!trust.ok ? trust.reason : '', /recovery or timestamp key; no key may hold two roles/u);
});

test('freshness: a current timestamp passes; an expired, mismatched or rolled-back one does not', async (t) => {
  const org = await setupRecoveryOrg(t, { freshness: true });
  const policy = await org.policy();
  const missing = await loadPolicyTrust(policy, NOW);
  assert.match(!missing.ok ? missing.reason : '', /Timestamp/u);

  await signPolicyTimestamp({ policy, keyPath: org.timestamp.priv, now: NOW, expires: '24h' });
  const fresh = await loadPolicyTrust(policy, later(1));
  assert.equal(fresh.ok, true);
  assert.equal(fresh.ok && fresh.context.root?.timestamp?.version, 1);

  // Expired: a frozen host stops trusting.
  const expired = await loadPolicyTrust(policy, daysAfter(NOW, 2));
  assert.match(!expired.ok ? expired.reason : '', /timestamp expired at/u);

  // A new trust root that the timestamp does not name is refused.
  const previousTrustRoot = await readFile(org.trustRoot);
  const previousTimestamp = await readFile(org.timestampPath);
  await addApprover({ rootKeyPath: org.root.priv, trustRootPath: org.trustRoot, now: later(2), publicKeyPath: (await org.key('second')).pub, name: 'Second', scopes: ['*'], expires: '30d' });
  const mismatch = await loadPolicyTrust(policy, later(3));
  assert.match(!mismatch.ok ? mismatch.reason : '', /the trust root does not match the timestamp/u);
  await signPolicyTimestamp({ policy, keyPath: org.timestamp.priv, now: later(3) });
  const v2 = await loadPolicyTrust(policy, later(4));
  assert.equal(v2.ok && v2.context.root?.timestamp?.version, 2);
  assert.equal(JSON.parse(await readFile(org.statePath, 'utf8')).timestamps[org.timestamp.keyId].version, 2);

  // Rollback: the version-1 timestamp and the trust root it names are still validly signed and unexpired.
  await writeFile(org.trustRoot, previousTrustRoot);
  await writeFile(org.timestampPath, previousTimestamp);
  const rolledBack = await loadPolicyTrust(policy, later(5));
  assert.match(!rolledBack.ok ? rolledBack.reason : '', /timestamp version 1 is older than version 2 already seen \(rollback\)/u);
});

test('freshness: the lifetime is capped by max_lifetime, and only the active timestamp key signs', async (t) => {
  const org = await setupRecoveryOrg(t, { freshness: true });
  const policy = await org.policy();
  await assert.rejects(signPolicyTimestamp({ policy, keyPath: org.timestamp.priv, now: NOW, expires: '2d' }), /longer than the policy's freshness max_lifetime/u);
  await assert.rejects(signPolicyTimestamp({ policy, keyPath: org.recovery[0]!.priv, now: NOW }), /not the active timestamp key/u);
});

test('freshness: a rotate with new_timestamp moves trust to the new timestamp key', async (t) => {
  const org = await setupRecoveryOrg(t, { freshness: true });
  const t2 = await org.key('timestamp2');
  await (await event(org, { action: 'rotate', signers: [org.recovery[0]!, org.recovery[1]!], newRoot: org.root, newTimestamp: t2 })).append();
  const policy = await org.policy();
  await assert.rejects(signPolicyTimestamp({ policy, keyPath: org.timestamp.priv, now: later(1) }), /not the active timestamp key/u);
  await signPolicyTimestamp({ policy, keyPath: t2.priv, now: later(1) });
  const trust = await loadPolicyTrust(policy, later(2));
  assert.equal(trust.ok, true);
  assert.equal(trust.ok && trust.context.root?.timestampKeyId, t2.keyId);
  // The old timestamp key can never come back.
  const back = await event(org, { action: 'rotate', signers: [org.recovery[0]!, org.recovery[1]!], newRoot: org.root, newTimestamp: org.timestamp, now: later(3) });
  await assert.rejects(back.append(), /has left a role and cannot return/u);
});

test('a revoked root blocks without reading the timestamp or the trust documents', async (t) => {
  const org = await setupRecoveryOrg(t, { freshness: true });
  await (await event(org, { action: 'revoke', signers: [org.recovery[0]!] })).append();
  await rm(org.trustRoot);
  const trust = await loadPolicyTrust(await org.policy(), later(1));
  assert.equal(!trust.ok && trust.rootRevoked, true);
});

test('CLI: verify-all reports a revoked root once and logs one block record, in shadow mode', async (t) => {
  const org = await setupRecoveryOrg(t, { mode: 'shadow' });
  const skills = path.join(org.dir, 'skills');
  await writeSkill(skills, 'one');
  await writeSkill(skills, 'two');
  await org.writePolicy({ skill_dirs: ['../skills'] });
  await (await event(org, { action: 'revoke', signers: [org.recovery[0]!], reason: 'leak' })).append();
  const { runCli } = await import('../src/cli.ts');
  const chunks: string[] = [];
  const original = process.stdout.write.bind(process.stdout);
  process.stdout.write = ((chunk: string) => { chunks.push(String(chunk)); return true; }) as typeof process.stdout.write;
  let code: number;
  try {
    code = await runCli(['verify-all', '--policy', org.policyPath], later(1));
  } finally {
    process.stdout.write = original;
  }
  assert.equal(code, 1);
  const output = chunks.join('');
  assert.equal(output.match(/FAIL/gu)?.length, 1);
  assert.match(output, /ROOT-REVOKED/u);
  assert.match(output, /0\/2 Skills verified \(mode: enforce\)/u);
  const records = await readJsonLines(org.logPath);
  assert.equal(records.length, 1);
  assert.deepEqual([records[0]!.event, records[0]!.action, records[0]!.mode, records[0]!.skill, records[0]!.digest], ['root-revoked', 'block', 'shadow', '', null]);
});

test('CLI: the recovery commands drive a whole revoke and rotate', async (t) => {
  const org = await setupRecoveryOrg(t);
  const { runCli } = await import('../src/cli.ts');
  const quiet = async (args: string[], now = NOW) => {
    const original = process.stdout.write.bind(process.stdout);
    const chunks: string[] = [];
    process.stdout.write = ((chunk: string) => { chunks.push(String(chunk)); return true; }) as typeof process.stdout.write;
    try {
      return { code: await runCli(args, now), out: chunks.join('') };
    } finally {
      process.stdout.write = original;
    }
  };
  const init = await quiet(['recovery', 'init', ...org.recovery.flatMap((k) => ['--public-key', k.pub]), '--rotate-threshold', '2', '--revoke-threshold', '1']);
  assert.equal(JSON.parse(init.out).recovery.key_ids.length, 3);
  const proposal = path.join(org.dir, 'cli-revoke.json');
  assert.equal((await quiet(['root-events', 'prepare-revoke', '--policy', org.policyPath, '--signer-public', org.recovery[0]!.pub, '--reason', 'leak', '--out', proposal])).code, 0);
  assert.deepEqual(JSON.parse((await quiet(['root-events', 'sign', proposal, '--key', org.recovery[0]!.priv])).out).still_missing, []);
  assert.equal((await quiet(['root-events', 'append', proposal, '--policy', org.policyPath])).code, 0);
  const check = await quiet(['policy', 'check', '--policy', org.policyPath], later(1));
  assert.equal(check.code, 1);
  assert.equal(JSON.parse(check.out).status, 'ROOT_REVOKED');
  assert.equal(JSON.parse(check.out).effective_mode, 'enforce');
  // policy check never writes the host state.
  await assert.rejects(readFile(org.statePath), /ENOENT/u);

  const r1 = await org.key('r1');
  const rotate = path.join(org.dir, 'cli-rotate.json');
  await quiet(['root-events', 'prepare-rotate', '--policy', org.policyPath, '--new-root-public', r1.pub, '--signer-public', org.recovery[0]!.pub, '--signer-public', org.recovery[2]!.pub, '--reason', 'replace leaked root', '--out', rotate], later(2));
  for (const key of [r1, org.recovery[0]!, org.recovery[2]!]) await quiet(['root-events', 'sign', rotate, '--key', key.priv]);
  assert.equal((await quiet(['root-events', 'append', rotate, '--policy', org.policyPath], later(2))).code, 0);
  assert.equal((await quiet(['root', 'adopt', '--root-key', r1.priv, '--from-root-fingerprint', org.root.keyId, '--trust-root', org.trustRoot, '--revocations', org.revocations], later(3))).code, 0);
  const ok = await quiet(['policy', 'check', '--policy', org.policyPath], later(4));
  assert.equal(ok.code, 0, ok.out);
  assert.equal(JSON.parse(ok.out).active_root_key_id, r1.keyId);
  assert.equal(JSON.parse(ok.out).root_events, 2);
});

test('GitHub Action: a revoked root fails the check in shadow mode with one summary line', async (t) => {
  const org = await setupRecoveryOrg(t, { mode: 'shadow' });
  await writeSkill(path.join(org.dir, 'skills'), 'repo-skill');
  await org.writePolicy({ skill_dirs: ['../skills'], state_file: undefined, decision_log: undefined });
  await (await event(org, { action: 'revoke', signers: [org.recovery[0]!] })).append();
  const result = await runGitHubCheck({ policyRoot: org.dir, workspace: org.dir, policy: 'policy/policy.json', now: later(1) });
  assert.equal(result.exitCode, 1);
  assert.equal(result.trustFailure, 'root-revoked');
  assert.equal(result.results.length, 1);
  assert.match(result.summary, /root key revoked, every Skill blocked \(shadow mode\)/u);

  // An ordinary trust failure in shadow mode is reported but does not fail.
  await rm(org.eventsPath);
  const unavailable = await runGitHubCheck({ policyRoot: org.dir, workspace: org.dir, policy: 'policy/policy.json', now: later(1) });
  assert.equal(unavailable.exitCode, 0);
  assert.equal(unavailable.trustFailure, 'trust-unavailable');
});

test('Pi: a revoked root hides every Skill in shadow mode and is logged once', async (t) => {
  const org = await setupRecoveryOrg(t, { mode: 'shadow' });
  const skills = await tempDir(t, 'mago-ski-skills-');
  const one = await writeSkill(skills, 'one');
  const two = await writeSkill(skills, 'two');
  await approve({ approverKey: org.approver.priv } as never, one);
  await (await event(org, { action: 'revoke', signers: [org.recovery[0]!], reason: 'leak' })).append();

  const handlers = new Map<string, Array<(event: any, ctx: any) => any>>();
  const api = { on: (name: string, fn: (event: any, ctx: any) => any) => { handlers.set(name, [...(handlers.get(name) ?? []), fn]); } };
  createMagoSkiExtension({ policyPath: org.policyPath, now: () => later(1) })(api as never);
  const notices: string[] = [];
  const statuses: string[] = [];
  const ctx = { cwd: skills, hasUI: true, ui: { notify: (text: string) => notices.push(text), setStatus: (_key: string, text: string) => statuses.push(text) } };
  const emit = async (name: string, payload: any) => { let result; for (const fn of handlers.get(name) ?? []) result = await fn(payload, ctx); return result; };
  const run = async () => {
    const payload = { systemPromptOptions: { skills: [one, two].map((dir) => ({ name: path.basename(dir), filePath: path.join(dir, 'SKILL.md'), baseDir: dir })) } };
    await emit('before_agent_start', payload);
    return payload.systemPromptOptions.skills.length;
  };
  assert.equal(await run(), 0);
  assert.equal(await run(), 0);
  const blocked = await emit('tool_call', { type: 'tool_call', toolCallId: 't', toolName: 'read', input: { path: path.join(one, 'SKILL.md') } });
  assert.equal(blocked?.block, true);
  assert.equal(notices.length, 1);
  assert.match(notices[0]!, /ROOT KEY REVOKED/u);
  assert.match(statuses.at(-1)!, /ROOT KEY REVOKED - all Skills blocked/u);
  const records = await readJsonLines(org.logPath);
  assert.equal(records.length, 1);
  assert.equal(records[0]!.event, 'root-revoked');
  assert.equal(records[0]!.action, 'block');
});

test('the walk cache returns copies, so callers cannot change a cached walk', async (t) => {
  const org = await setupRecoveryOrg(t);
  const policy = await org.policy();
  const bytes = await readFile(org.eventsPath);
  const start = { rootKeyId: org.root.keyId, recovery: policy.recovery!.set, timestampKeyId: null, eventsAfter: 0 };
  const first = walkRootEventsCached(bytes, start, NOW);
  first.recovery.keyIds.push('x');
  assert.equal(walkRootEventsCached(bytes, start, NOW).recovery.keyIds.length, 3);
  assert.equal(walkRootEvents(bytes, start, NOW).count, 0);
  assert.equal(parseRootEventLog(bytes).length, 0);
  assert.ok(parseCanonicalJsonBytes(canonicalBytes(unsignedEventEnvelope({
    sequence: 1, action: 'revoke', rootKeyId: org.root.keyId, issuedAt: NOW, reason: 'r', signers: [],
  }))));
});
