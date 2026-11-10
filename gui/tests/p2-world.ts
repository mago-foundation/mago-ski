// Shared fixture for the phase 2 GUI tests (admin-p2.test.ts and admin-p2b.test.ts): a v1 or v2 organisation behind a pin in a temp /etc.
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import assert from 'node:assert/strict';
import path from 'node:path';
import type { TestContext } from 'node:test';
import { loadPublicKey, type PublicKeyInfo, generateKeyPair } from '../../src/keys.ts';
import { signPolicyTimestamp } from '../../src/recovery-admin.ts';
import { approve, daysAfter, setupOrg, setupRecoveryOrg, T0, tempDir, writeSkill, type Key } from '../../tests/helpers.ts';
import { AdminSession, type AdminSessionOptions } from '../src/service/admin.ts';
import type { AdminReviewSummary, AdminSignSummary } from '../src/service/types.ts';

export const UID = process.getuid!();
export const NOW = daysAfter(T0, 1);

export type DocSummary = Exclude<AdminSignSummary, { action: 'approve' }>;

export async function procFixture(base: string): Promise<string> {
  const procDir = path.join(base, 'proc');
  await mkdir(path.join(procDir, 'self'), { recursive: true });
  await writeFile(path.join(procDir, 'self', 'uid_map'), '0 0 4294967295\n');
  await writeFile(path.join(procDir, 'self', 'gid_map'), '0 0 4294967295\n');
  return procDir;
}

interface Options { recovery?: boolean; freshness?: boolean; maxLifetime?: string; now?: Date; dialogTimeoutMs?: number; lang?: 'ko' | 'en' }

/** A v1 organisation, or (recovery) a v2 one with a recovery set and optionally freshness, behind a pin in a temp /etc. */
export async function world(t: TestContext, options: Options = {}) {
  const base = await tempDir(t, 'mago-ski-p2-');
  const pinDir = path.join(base, 'etc', 'mago-ski');
  await mkdir(pinDir, { recursive: true, mode: 0o755 });
  const pinPath = path.join(pinDir, 'policy.json');
  const skills = path.join(base, 'skills');
  const pinSkills = path.join(base, 'pin-skills');
  const hostSkills = path.join(base, 'host-skills');
  const certDir = path.join(base, 'certs');
  await mkdir(certDir);
  const hostSkillDirs: string[] = [hostSkills];
  let rootPriv: string; let rootPub: string; let rootKeyId: string; let trustRoot: string; let revocations: string; let approverKey: string; let approverPub: string; let approverKeyId: string;
  let recovery: Key[] = []; let timestamp: Key | null = null; let eventsPath = ''; let timestampPath = ''; let policyOf: () => Promise<import('../../src/policy.ts').Policy>; let keyFn: ((name: string) => Promise<Key>) | null = null;
  const common = { state_file: 'state.json', certificate_dirs: [certDir], skill_dirs: [pinSkills] };
  if (options.recovery) {
    const org = await setupRecoveryOrg(t, { freshness: options.freshness ?? false });
    ({ priv: rootPriv, pub: rootPub, keyId: rootKeyId } = org.root);
    trustRoot = org.trustRoot; revocations = org.revocations; approverKey = org.approver.priv; approverPub = org.approver.pub; approverKeyId = org.approver.keyId;
    recovery = org.recovery; timestamp = org.timestamp; eventsPath = org.eventsPath; timestampPath = org.timestampPath; policyOf = org.policy; keyFn = org.key;
    await writeFile(pinPath, JSON.stringify({
      policy_version: 'mago.policy/v2', mode: 'enforce', root_fingerprint: rootKeyId,
      recovery: { key_ids: (await org.policy()).recovery!.set.keyIds, rotate_threshold: 2, revoke_threshold: 1 }, root_events: eventsPath,
      trust_root: trustRoot, revocations, ...common,
      ...(options.freshness ? { freshness: { timestamp: timestampPath, key_id: timestamp.keyId, max_lifetime: options.maxLifetime ?? '24h' } } : {}),
    }), { mode: 0o644 });
    if (options.freshness) await signPolicyTimestamp({ policy: await org.policy(), keyPath: timestamp.priv, now: NOW, ...(options.maxLifetime ? { expires: options.maxLifetime } : {}) });
  } else {
    const org = await setupOrg(t, { scopes: ['*'] });
    rootPriv = org.rootKey; rootPub = org.rootPub; rootKeyId = org.rootKeyId; trustRoot = org.trustRoot; revocations = org.revocations;
    approverKey = org.approverKey; approverPub = org.approverPub; approverKeyId = org.approverKeyId;
    policyOf = async () => { throw new Error('no v1 policy object'); };
    await writeFile(pinPath, JSON.stringify({ policy_version: 'mago.policy/v1', mode: 'enforce', root_fingerprint: rootKeyId, trust_root: trustRoot, revocations, ...common }), { mode: 0o644 });
  }
  const orgLike = { rootKey: rootPriv, approverKey, certDir };
  const names = [['docs-helper', skills], ['pdf-tools', skills], ['docs-pin', pinSkills], ['docs-host', hostSkills]] as const;
  /** The discovered instances of the observation service: the two Skills under `skills`. */
  const instanceList: Array<{ id: string; path: string; name: string }> = [];
  for (const [name, dir] of names) {
    const skill = await writeSkill(dir, name);
    if (dir === skills) instanceList.push({ id: name === 'docs-helper' ? 'docs' : 'pdf', path: skill, name });
    await approve(orgLike as never, skill, { out: path.join(certDir, `${name}.cert.json`), now: T0 });
  }
  const calls = { sign: [] as AdminSignSummary[], offline: 0, lastApprover: 0, pick: 0 };
  const handlers = {
    sign: async (_s: AdminSignSummary): Promise<boolean> => true,
    offline: async (): Promise<boolean> => true,
    lastApprover: async (): Promise<boolean> => true,
    pick: async (): Promise<{ ok: true; key: PublicKeyInfo } | { ok: false; reason: string }> => ({ ok: false, reason: 'cancelled' }),
  };
  const hooks: NonNullable<AdminSessionOptions['hooks']> = {};
  const session = new AdminSession({
    pinPath, rootUid: UID, trustedBase: base, platform: 'linux', procDir: await procFixture(base), stateDir: path.join(base, 'state'), cooldownMs: 0,
    idleMs: 600_000, now: () => options.now ?? NOW, ...(options.dialogTimeoutMs ? { dialogTimeoutMs: options.dialogTimeoutMs } : {}), ...(options.lang ? { lang: () => options.lang! } : {}),
    confirmReview: async (_s: AdminReviewSummary) => true,
    confirmSign: async (s) => { calls.sign.push(s); return await handlers.sign(s); },
    confirmReset: async () => true,
    confirmOffline: async () => { calls.offline += 1; return await handlers.offline(); },
    confirmLastApprover: async () => { calls.lastApprover += 1; return await handlers.lastApprover(); },
    pickPublicKey: async () => { calls.pick += 1; return await handlers.pick(); },
    instance: (id) => instanceList.find((i) => i.id === id) ?? null, instances: () => instanceList, discoveryRoots: () => [skills], skillFolders: () => [], hostSkillDirs: () => hostSkillDirs, hooks,
  });
  t.after(() => session.disarm());
  const newKey = async (name: string): Promise<{ priv: string; pub: string; keyId: string }> => {
    const dir = path.join(base, 'newkeys');
    await mkdir(dir, { recursive: true });
    const pair = await generateKeyPair(path.join(dir, `${name}.pem`), path.join(dir, `${name}.pub`));
    return { priv: pair.privatePath, pub: pair.publicPath, keyId: pair.keyId };
  };
  const stateFile = path.join(base, 'state', 'admin-state.json');
  const pick = (key: { pub: string }) => { handlers.pick = async () => ({ ok: true, key: await loadPublicKey(key.pub) }); };
  return {
    base, instanceList, session, calls, handlers, hooks, skills, pinSkills, hostSkills, certDir, hostSkillDirs, rootPriv, rootPub, rootKeyId, trustRoot, revocations, approverKey, approverPub, approverKeyId,
    recovery, timestamp, eventsPath, timestampPath, policyOf, keyFn, newKey, stateFile, pick, pinPath,
  };
}
export type World = Awaited<ReturnType<typeof world>>;

export const doc = (s: AdminSignSummary | undefined): DocSummary => { assert.ok(s && s.action !== 'approve'); return s as DocSummary; };
export const failure = (result: { ok: boolean; message?: string }): string => (result.ok ? '' : result.message ?? '');
export const fileBytes = async (file: string) => await readFile(file);

export async function armRoot(w: World): Promise<void> {
  const armed = await w.session.arm(w.rootPriv);
  assert.equal(armed.ok, true, JSON.stringify(armed));
}

export const trust = async (w: World) => {
  const view = await w.session.trustRoot();
  assert.equal(view.ok, true, JSON.stringify(view));
  return view as Extract<typeof view, { ok: true }>;
};


export async function armTimestamp(w: World): Promise<void> {
  assert.ok(w.timestamp, 'a freshness world');
  const armed = await w.session.arm(w.timestamp.priv);
  assert.equal(armed.ok, true, JSON.stringify(armed));
}
