// Administration rack, phase 1 (docs/spec/gui-admin-rack-v1.md): the organisation pin, roles recognised by proof of
// possession, the armed key and the devices of the "Approve a Skill version" template. Plain Node, used only by the
// Electron main process: key material never leaves this module and never reaches the renderer.
import { randomBytes, sign, verify, type KeyObject } from 'node:crypto';
import { lstat } from 'node:fs/promises';
import path from 'node:path';
import { approveSkill } from '../../../src/admin.ts';
import { parseCertificate } from '../../../src/certificate.ts';
import { readRegularFile } from '../../../src/fs-safe.ts';
import { loadPrivateKey, type PrivateKeyInfo } from '../../../src/keys.ts';
import { scopeMatches } from '../../../src/names.ts';
import { loadPolicy, loadPolicyTrust, verifyWithPolicy, type Policy } from '../../../src/policy.ts';
import { MAX_ROOT_EVENTS_BYTES, requireDisplaySafeText, walkRootEvents, type RootWalk } from '../../../src/root-events.ts';
import { addDuration, formatTimestamp } from '../../../src/time.ts';
import { collectSkillTree, sha256Hex } from '../../../src/tree-digest.ts';
import type { TrustContextResult } from '../../../src/verify.ts';
import { resolveSkillName } from '../../../src/verify.ts';
import type {
  AdminActionResult, AdminArmResult, AdminCheckView, AdminInspectView, AdminLifetime, AdminPinView, AdminRoleView, AdminStatusView,
} from './types.ts';

/** The only place the organisation pin is read from. No environment variable or setting redirects it. */
export const ORG_PIN_PATH = '/etc/mago-ski/policy.json';
export const ARM_IDLE_MS = 15 * 60 * 1000;
export const LIFETIMES: readonly AdminLifetime[] = ['30d', '90d', '180d'];
export const MAX_REASON = 1024;
const IDENTITY_CONTEXT = 'mago-ski gui identity v1';

export type PinState =
  | { kind: 'missing'; path: string }
  | { kind: 'unprotected'; path: string; reason: string }
  | { kind: 'invalid'; path: string; reason: string }
  | {
      kind:     'loaded';
      path:     string;
      policy:   Policy;
      /** SHA-256 of the pin's bytes: a change disarms the key. */
      sha256:   string;
      /** The active root after the root event log; null when the log cannot be walked. */
      walk:     RootWalk | null;
      walkError: string | null;
      trust:    TrustContextResult;
    };

/**
 * The pin is trusted only if it is a regular file and it and every directory from `trustedBase` down to it are
 * owned by `rootUid`, not group- or other-writable, and not symbolic links. Production: base "/", uid 0.
 * Returns why it is not trusted, or null.
 */
export async function pinOwnershipProblem(file: string, rootUid: number, trustedBase = '/'): Promise<string | null> {
  if (!path.isAbsolute(file)) return 'the pin path is not absolute';
  const base = path.resolve(trustedBase);
  const relative = path.relative(base, file);
  if (relative.startsWith('..') || path.isAbsolute(relative)) return 'the pin is outside the trusted base';
  const parts = relative.split(path.sep).filter(Boolean);
  let current = base;
  for (let index = -1; index < parts.length; index += 1) {
    if (index >= 0) current = path.join(current, parts[index]!);
    const last = index === parts.length - 1;
    let info;
    try {
      info = await lstat(current);
    } catch (error) {
      return (error as NodeJS.ErrnoException).code === 'ENOENT' ? `${current} does not exist` : `${current} cannot be read`;
    }
    if (info.isSymbolicLink()) return `${current} is a symbolic link`;
    if (last ? !info.isFile() : !info.isDirectory()) return `${current} is not a ${last ? 'regular file' : 'directory'}`;
    if (info.uid !== rootUid) return `${current} is not owned by ${rootUid === 0 ? 'root' : `uid ${rootUid}`}`;
    if ((info.mode & 0o022) !== 0) return `${current} is writable by group or others`;
  }
  return null;
}

export async function readPin(options: { path: string; rootUid: number; trustedBase?: string; now: Date }): Promise<PinState> {
  const file = options.path;
  try {
    await lstat(file);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return { kind: 'missing', path: file };
  }
  const problem = await pinOwnershipProblem(file, options.rootUid, options.trustedBase);
  if (problem) return { kind: 'unprotected', path: file, reason: problem };
  let policy: Policy;
  let bytes: Buffer;
  try {
    bytes = await readRegularFile(file, 'Organisation pin', 256 * 1024);
    policy = await loadPolicy(file);
  } catch (error) {
    return { kind: 'invalid', path: file, reason: (error as Error).message };
  }
  let walk: RootWalk | null = null;
  let walkError: string | null = null;
  if (policy.recovery) {
    try {
      const log = await readRegularFile(policy.recovery.rootEventsPath, 'Root event log', MAX_ROOT_EVENTS_BYTES);
      walk = walkRootEvents(log, {
        rootKeyId: policy.rootKeyId, recovery: policy.recovery.set, timestampKeyId: policy.recovery.freshness?.keyId ?? null,
        eventsAfter: policy.recovery.eventsAfter,
      }, options.now);
    } catch (error) {
      walkError = (error as Error).message;
    }
  }
  const trust = await loadPolicyTrust(policy, options.now, { recordVersions: false });
  return { kind: 'loaded', path: file, policy, sha256: sha256Hex(bytes), walk, walkError, trust };
}

type LoadedPin = Extract<PinState, { kind: 'loaded' }>;

/** The active root key id under the pin, or null when it cannot be known (a broken log) or is revoked. */
function activeRoot(pin: LoadedPin): string | null {
  if (!pin.policy.recovery) return pin.policy.rootKeyId;
  if (!pin.walk || pin.walk.revoked) return null;
  return pin.walk.activeRootKeyId;
}

/**
 * What a key is under the pin and its signed documents, with the public key the documents name for that role
 * (used to verify the proof of possession). A key holds at most one role.
 */
export function roleOf(pin: LoadedPin, key: PrivateKeyInfo, now: Date): { view: AdminRoleView; publicKey: KeyObject | null } {
  const base = { keyId: key.keyId, name: null, scopes: null, expiresAt: null, note: null };
  const root = activeRoot(pin);
  if (root === key.keyId) {
    const documentKey = pin.trust.ok && pin.trust.context.trustRoot.root.keyId === key.keyId ? pin.trust.context.trustRoot.root.publicKey : key.publicKey;
    return { view: { ...base, role: 'root', note: pin.trust.ok ? null : `the trust documents do not verify: ${pin.trust.reason}` }, publicKey: documentKey };
  }
  if (pin.trust.ok) {
    const approver = pin.trust.context.trustRoot.approvers.find((entry) => entry.keyId === key.keyId);
    if (approver) {
      if (approver.expiresAt <= now) return { view: { ...base, role: 'none', note: `this approver key expired at ${formatTimestamp(approver.expiresAt)}` }, publicKey: null };
      if (pin.trust.context.revocations.keys.some((entry) => entry.keyId === key.keyId))
        return { view: { ...base, role: 'none', note: 'this approver key is revoked' }, publicKey: null };
      return {
        view: { ...base, role: 'approver', name: approver.name, scopes: [...approver.scopes], expiresAt: formatTimestamp(approver.expiresAt) },
        publicKey: approver.publicKey,
      };
    }
  }
  if (pin.walk && !pin.walkError) {
    if (pin.walk.recovery.keyIds.includes(key.keyId)) return { view: { ...base, role: 'recovery' }, publicKey: key.publicKey };
    if (pin.walk.timestampKeyId === key.keyId) return { view: { ...base, role: 'timestamp' }, publicKey: key.publicKey };
  }
  let note = 'this key holds no role in the organisation';
  if (pin.walkError) note = `the root event log cannot be checked (${pin.walkError}), so root and recovery roles are not recognised`;
  else if (pin.walk?.revoked && pin.walk.activeRootKeyId === key.keyId) note = `this root key was revoked by root event ${pin.walk.revoked.sequence}`;
  else if (!pin.trust.ok) note = `the trust documents do not verify (${pin.trust.reason}), so approvers are not recognised`;
  return { view: { ...base, role: 'none', note }, publicKey: null };
}

/** Signs a fresh challenge bound to the pinned root with the loaded key and verifies it with the documents' key. */
export function proveIdentity(pin: LoadedPin, key: PrivateKeyInfo, publicKey: KeyObject): boolean {
  const challenge = randomBytes(32).toString('hex');
  const message = Buffer.from(`${IDENTITY_CONTEXT}\n${pin.policy.rootKeyId}\n${challenge}\n`, 'utf8');
  try {
    return verify(null, message, publicKey, sign(null, message, key.privateKey));
  } catch {
    return false;
  }
}

function pinView(pin: PinState): AdminPinView {
  if (pin.kind !== 'loaded') return { kind: pin.kind, path: pin.path, reason: 'reason' in pin ? pin.reason : null, rootKeyId: null, activeRootKeyId: null, mode: null, trustOk: false, trustNote: null };
  return {
    kind: 'loaded', path: pin.path, reason: pin.walkError ? `root event log: ${pin.walkError}` : null,
    rootKeyId: pin.policy.rootKeyId, activeRootKeyId: activeRoot(pin), mode: pin.policy.mode,
    trustOk: pin.trust.ok, trustNote: pin.trust.ok ? null : `${pin.trust.verdict}: ${pin.trust.reason}`,
  };
}

export interface AdminSessionOptions {
  /** Tests only: production always reads ORG_PIN_PATH, owned by uid 0, checked from "/". */
  pinPath?: string;
  rootUid?: number;
  trustedBase?: string;
  idleMs?: number;
  now?: () => Date;
  /** The Skill a discovered instance id names, from the observation service. */
  instance: (id: string) => { path: string; name: string } | null;
  /** The observation service's policy path, to say when it differs from the pin. */
  hostPolicyPath?: () => string | null;
}

interface Armed {
  key:      PrivateKeyInfo;
  role:     AdminRoleView;
  pinSha:   string;
  lastUsed: number;
}

class AdminError extends Error {}

export class AdminSession {
  private readonly pinPath: string;
  private readonly rootUid: number;
  private readonly trustedBase: string;
  private readonly idleMs: number;
  private readonly now: () => Date;
  private armed: Armed | null = null;
  private idleTimer: NodeJS.Timeout | null = null;
  /** Digests the armed approver confirmed as inspected, per instance; cleared with the key. */
  private readonly inspected = new Map<string, string>();

  private readonly options: AdminSessionOptions;

  constructor(options: AdminSessionOptions) {
    this.options = options;
    this.pinPath = options.pinPath ?? ORG_PIN_PATH;
    this.rootUid = options.rootUid ?? 0;
    this.trustedBase = options.trustedBase ?? '/';
    this.idleMs = options.idleMs ?? ARM_IDLE_MS;
    this.now = options.now ?? (() => new Date());
  }

  private async pin(): Promise<PinState> {
    return await readPin({ path: this.pinPath, rootUid: this.rootUid, trustedBase: this.trustedBase, now: this.now() });
  }

  async status(): Promise<AdminStatusView> {
    this.expireIfIdle();
    const pin = await this.pin();
    const hostPolicy = this.options.hostPolicyPath?.() ?? null;
    return {
      pin: pinView(pin),
      hostPolicyDiffers: pin.kind === 'loaded' && hostPolicy !== null && path.resolve(hostPolicy) !== pin.path,
      armed: this.armed ? { ...this.armed.role } : null,
      idleMinutes: Math.round(this.idleMs / 60000),
    };
  }

  /** Loads a private key file chosen by the user, proves possession and arms it if it holds a role. */
  async arm(keyPath: string): Promise<AdminArmResult> {
    this.disarm();
    const pin = await this.pin();
    if (pin.kind !== 'loaded') return { ok: false, reason: pinView(pin).reason ?? `organisation pin: ${pin.kind}` };
    let key: PrivateKeyInfo;
    try {
      key = await loadPrivateKey(keyPath);
    } catch (error) {
      return { ok: false, reason: `cannot load the key: ${(error as Error).message}` };
    }
    const { view, publicKey } = roleOf(pin, key, this.now());
    if (view.role === 'none' || !publicKey) return { ok: false, reason: view.note ?? 'this key holds no role in the organisation', keyId: key.keyId };
    if (!proveIdentity(pin, key, publicKey)) return { ok: false, reason: 'the key could not prove possession: it is not the private half of the key the documents name', keyId: key.keyId };
    this.armed = { key, role: view, pinSha: pin.sha256, lastUsed: Date.now() };
    this.scheduleIdle();
    return { ok: true, role: { ...view } };
  }

  disarm(): void {
    this.armed = null;
    this.inspected.clear();
    if (this.idleTimer) clearTimeout(this.idleTimer);
    this.idleTimer = null;
  }

  private scheduleIdle(): void {
    if (this.idleTimer) clearTimeout(this.idleTimer);
    this.idleTimer = setTimeout(() => this.disarm(), this.idleMs);
    this.idleTimer.unref?.();
  }

  private expireIfIdle(): void {
    if (this.armed && Date.now() - this.armed.lastUsed > this.idleMs) this.disarm();
  }

  /** The armed key, re-checked against the current pin and documents. Any change disarms it. */
  private async current(role: AdminRoleView['role']): Promise<{ pin: LoadedPin; armed: Armed }> {
    this.expireIfIdle();
    const armed = this.armed;
    if (!armed) throw new AdminError('no key is armed; load your key in the IDENTITY device');
    const pin = await this.pin();
    if (pin.kind !== 'loaded' || pin.sha256 !== armed.pinSha) {
      this.disarm();
      throw new AdminError('the organisation pin changed; load your key again');
    }
    const { view, publicKey } = roleOf(pin, armed.key, this.now());
    if (view.role !== armed.role.role || !publicKey || !proveIdentity(pin, armed.key, publicKey)) {
      this.disarm();
      throw new AdminError(`this key no longer holds its role${view.note ? `: ${view.note}` : ''}; load your key again`);
    }
    if (view.role !== role) throw new AdminError(`this needs the ${role} role; the armed key is ${view.role}`);
    armed.role = view;
    armed.lastUsed = Date.now();
    this.scheduleIdle();
    return { pin, armed };
  }

  private skill(id: string): { path: string; name: string } {
    const found = this.options.instance(id);
    if (!found) throw new AdminError('this Skill is no longer discovered');
    return found;
  }

  /** INSPECT: the exact current version, its files and the certificate it carries. Read-only; no key needed. */
  async inspect(instanceId: string): Promise<AdminInspectView> {
    const skill = this.skill(instanceId);
    const tree = await collectSkillTree(skill.path);
    const name = await resolveSkillName(skill.path).catch(() => skill.name);
    const pin = await this.pin();
    let certificate: AdminInspectView['certificate'] = null;
    let verdict: AdminInspectView['verdict'] = null;
    if (pin.kind === 'loaded' && !pin.trust.ok) {
      verdict = { verdict: pin.trust.verdict, reason: pin.trust.reason };
    } else if (pin.kind === 'loaded' && pin.trust.ok) {
      // Always with the context already loaded: verifyWithPolicy without one would record versions in the host state.
      const result = await verifyWithPolicy(pin.policy, skill.path, { now: this.now(), context: pin.trust.context });
      verdict = { verdict: result.verdict, reason: result.reason };
      if (result.certificateSource) {
        try {
          const parsed = parseCertificate(await readRegularFile(result.certificateSource, 'Certificate', 8 * 1024 * 1024));
          certificate = {
            source: result.certificateSource, id: parsed.id, digest: parsed.digest, approverKeyId: parsed.approverKeyId,
            issuedAt: formatTimestamp(parsed.issuedAt), expiresAt: formatTimestamp(parsed.expiresAt), reason: parsed.reason,
          };
        } catch {
          certificate = null;
        }
      }
    }
    return {
      instanceId, name, path: skill.path, digest: tree.digest, totalBytes: tree.totalBytes,
      files: tree.files.map((f) => ({ path: f.path, size: f.size, sha256: f.sha256, exec: f.exec })),
      excluded: [...tree.excluded], certificate, verdict,
      inspected: this.inspected.get(instanceId) === tree.digest,
    };
  }

  /** Records that the armed approver reviewed exactly `digest`, if it is still the Skill's current version. */
  async confirmInspected(instanceId: string, digest: string): Promise<AdminActionResult> {
    try {
      await this.current('approver');
      const skill = this.skill(instanceId);
      const now = (await collectSkillTree(skill.path)).digest;
      if (now !== digest) return { ok: false, message: 'the Skill changed since it was shown; inspect it again' };
      this.inspected.set(instanceId, digest);
      return { ok: true };
    } catch (error) {
      return { ok: false, message: (error as Error).message };
    }
  }

  /** APPROVE: signs a certificate for the inspected digest, after re-checking the role, the scope and the bytes. */
  async approve(instanceId: string, digest: string, lifetime: AdminLifetime, reason: string): Promise<AdminActionResult> {
    try {
      const { pin, armed } = await this.current('approver');
      if (this.inspected.get(instanceId) !== digest) throw new AdminError('inspect this exact version first, and confirm that you reviewed it');
      if (!LIFETIMES.includes(lifetime)) throw new AdminError('choose a lifetime of 30, 90 or 180 days');
      const text = requireDisplaySafeText(reason, 'Reason', MAX_REASON);
      const skill = this.skill(instanceId);
      const name = await resolveSkillName(skill.path);
      const scopes = armed.role.scopes ?? [];
      if (!scopes.some((scope) => scopeMatches(scope, name))) throw new AdminError(`your scopes (${scopes.join(', ')}) do not cover the Skill name "${name}"`);
      const now = this.now();
      if (armed.role.expiresAt && addDuration(now, lifetime, 'certificate lifetime') > new Date(armed.role.expiresAt))
        throw new AdminError(`this lifetime would outlast your approver key, which expires at ${armed.role.expiresAt}; choose a shorter one`);
      const dir = pin.policy.certificateDirs[0];
      const issued = await approveSkill({
        skillDir: skill.path, approverKey: armed.key, now, expires: lifetime, reason: text, expectDigest: digest,
        ...(dir ? { out: path.join(dir, `${name}.cert.json`) } : {}),
      });
      this.inspected.delete(instanceId);
      return { ok: true, certificateId: issued.certificateId, certificatePath: issued.path, digest: issued.digest, expiresAt: formatTimestamp(issued.expiresAt) };
    } catch (error) {
      return { ok: false, message: (error as Error).message };
    }
  }

  /** POLICY CHECK: the Skill's verdict under the pin's policy, without recording versions. */
  async check(instanceId: string): Promise<AdminCheckView> {
    const skill = this.skill(instanceId);
    const pin = await this.pin();
    if (pin.kind !== 'loaded') return { verdict: null, reason: pinView(pin).reason ?? `organisation pin: ${pin.kind}`, trustOk: false, trustNote: null };
    if (!pin.trust.ok) return { verdict: pin.trust.verdict, reason: pin.trust.reason, trustOk: false, trustNote: `${pin.trust.verdict}: ${pin.trust.reason}` };
    const result = await verifyWithPolicy(pin.policy, skill.path, { now: this.now(), context: pin.trust.context });
    return { verdict: result.verdict, reason: result.reason, trustOk: true, trustNote: null };
  }
}
