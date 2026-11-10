// Administration rack (docs/spec/gui-admin-rack-v1.md): the organisation pin, roles recognised by proof of
// possession, the armed key and the devices of the "Approve a Skill version" template. Plain Node, used only by the
// Electron main process: key material never leaves this module and never reaches the renderer.
import { randomBytes, sign, verify, type KeyObject } from 'node:crypto';
import { readlinkSync } from 'node:fs';
import { constants as fsConstants } from 'node:fs';
import { lstat, mkdir, open, readFile, realpath, rename } from 'node:fs/promises';
import path from 'node:path';
import {
  approveSkill, commitTrustRoot, DocumentChangedError, prepareTrustRootChange, signPreparedTrustRoot, StaleDocumentError,
  type PreparedTrustRoot, type TrustRootChange,
} from '../../../src/admin.ts';
import { parseCertificate } from '../../../src/certificate.ts';
import { FileChangedError, isInside, readRegularFile, realpathAllowingMissing, resolveOutside } from '../../../src/fs-safe.ts';
import { loadPrivateKeyBytes, type PrivateKeyInfo } from '../../../src/keys.ts';
import { scopeMatches, validateScope } from '../../../src/names.ts';
import {
  DiscoveryBudgetError, findSkillDirs, forbiddenApproverKeys, loadPolicy, loadPolicyRoot, loadPolicyTrust, loadTrustForPreview, memoryMinimums,
  readHostState, recordDocumentVersions, tooDeepResult, verifyWithPolicy, type ForbiddenKey, type Policy, type PolicyRootResult, type PreviewOverride,
} from '../../../src/policy.ts';
import { readTrustRootForUpdate, type TrustRoot } from '../../../src/trust-root.ts';
import { requireDisplaySafeText } from '../../../src/root-events.ts';
import { t, type Lang, type MessageKey } from '../i18n/messages.ts';
import { addDuration, formatTimestamp } from '../../../src/time.ts';
import { collectSkillTree, SKILL_FILENAME, sha256Hex } from '../../../src/tree-digest.ts';
import type { TrustContextResult, Verdict } from '../../../src/verify.ts';
import { skillNameFromSkillFile } from '../../../src/verify.ts';
import type {
  AdminActionResult, AdminApproverLifetime, AdminArmResult, AdminCheckView, AdminConsequence, AdminInspectView, AdminLifetime, AdminPinView,
  AdminReviewSummary, AdminRoleView, AdminResetResult, AdminSignSummary, AdminStatusView, AdminTrustRootLifetime, AdminTrustRootView,
  AdminVerifyAllView, AdminWriteResult,
} from './types.ts';
import type { PublicKeyInfo } from '../../../src/keys.ts';

/** The only place the organisation pin is read from. No environment variable or setting redirects it. */
export const ORG_PIN_PATH = '/etc/mago-ski/policy.json';
export const ARM_IDLE_MS = 15 * 60 * 1000;
export const LIFETIMES: readonly AdminLifetime[] = ['30d', '90d', '180d'];
export const MAX_REASON = 1024;
export const DIALOG_TIMEOUT_MS = 120_000;
export const COOLDOWN_MS = 10_000;
export const DIALOG_SLOT_GRACE_MS = 5000;
export const MEMORY_FILE = 'admin-state.json';
export const APPROVER_LIFETIMES: readonly AdminApproverLifetime[] = ['90d', '180d', '365d'];
export const TRUST_ROOT_LIFETIMES: readonly AdminTrustRootLifetime[] = ['180d', '365d'];
export const MAX_APPROVER_NAME = 128;
const IDENTITY_CONTEXT = 'mago-ski gui identity v1';

// Refusal texts are in the message catalog (admin.err.*); a session reads its language when it builds each one.
const MAX_KEY_FILE_BYTES = 64 * 1024;
const READ_RETRY_MS = [50, 100, 200] as const;

export type PinState =
  | { kind: 'missing'; path: string }
  | { kind: 'unprotected'; path: string; reason: string }
  | { kind: 'invalid'; path: string; reason: string }
  | {
      kind:       'loaded';
      path:       string;
      policy:     Policy;
      /** SHA-256 of the pin's bytes: a change disarms the key. */
      sha256:     string;
      /** The root event log checked against this computer's memory: active root, walk, revoke, rollback. */
      root:       PolicyRootResult;
      trust:      TrustContextResult;
      memoryFile: string;
    };

type LoadedPin = Extract<PinState, { kind: 'loaded' }>;

export interface PinEnv {
  platform: NodeJS.Platform;
  procDir:  string;
  /** The language of the refusal text; Korean when absent. */
  lang?:    Lang;
}

/**
 * On macOS `/etc` is a symbolic link to `private/etc`, which the ownership walk would refuse. When it is exactly that
 * link, the walk runs on the real path under `/private`; anything else is returned unchanged (and then refused as a link).
 */
export function mapPinPath(file: string, platform: NodeJS.Platform, readlink: (p: string) => string): string {
  if (platform !== 'darwin' || !file.startsWith('/etc/')) return file;
  try {
    return readlink('/etc') === 'private/etc' ? `/private${file}` : file;
  } catch {
    return file;
  }
}

/**
 * A user can map themself to uid 0 in a user namespace and bind-mount a file they own over the pin. A namespace shows
 * itself in the identity maps, so anything but the full identity map is refused. This is a hurdle, not a boundary:
 * the user can also mount over these files inside their namespace.
 */
async function namespaceProblem(env: PinEnv): Promise<string | null> {
  if (env.platform !== 'linux') return null;
  for (const name of ['uid_map', 'gid_map']) {
    let text: string;
    try {
      text = await readFile(path.join(env.procDir, 'self', name), 'utf8');
    } catch {
      return t(env.lang ?? 'ko', 'admin.err.nsUnknown');
    }
    const lines = text.trim().split(/\r?\n/u);
    if (lines.length !== 1 || lines[0]!.trim().split(/\s+/u).join(' ') !== '0 0 4294967295')
      return t(env.lang ?? 'ko', 'admin.err.nsUntrusted');
  }
  return null;
}

/**
 * The pin is trusted only if it is a regular file and it and every directory from `trustedBase` down to it are
 * owned by `rootUid`, not group- or other-writable, and not symbolic links; and on Linux the process is not in a
 * user namespace. Production: base "/", uid 0. Returns why it is not trusted, or null.
 */
export async function pinOwnershipProblem(
  file: string,
  rootUid: number,
  trustedBase = '/',
  env: PinEnv = { platform: process.platform, procDir: '/proc' },
): Promise<string | null> {
  if (!path.isAbsolute(file)) return 'the pin path is not absolute';
  const base = path.resolve(trustedBase);
  const relative = path.relative(base, file);
  if (relative.startsWith('..') || path.isAbsolute(relative)) return 'the pin is outside the trusted base';
  const namespace = await namespaceProblem(env);
  if (namespace) return namespace;
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

export interface ReadPinOptions {
  path:         string;
  rootUid:      number;
  trustedBase?: string;
  now:          Date;
  /** This computer's rollback memory for the pin's documents (the engine's host state format). */
  memoryFile:   string;
  platform:     NodeJS.Platform;
  procDir:      string;
  readlink:     (p: string) => string;
  /** The language of the reasons in the result; Korean when absent. */
  lang?:        Lang;
  /** Called when an unreadable memory file was moved aside. */
  onMemoryReset?: (reset: { at: string; backup: string }) => void;
}

/** Moves the memory file aside under a name that says when; returns the new absolute path. Throws if it is not there. */
export async function moveMemoryAside(memoryFile: string, now: Date): Promise<string> {
  const backup = `${memoryFile}.unreadable-${now.toISOString().replace(/:/gu, '-')}`;
  await rename(memoryFile, backup);
  return path.resolve(backup);
}

/** The pin's policy with this computer's memory as its state file and no decision log: what admin reads never write elsewhere. */
export function memoryPolicy(pin: { policy: Policy; memoryFile: string }): Policy {
  return { ...pin.policy, statePath: pin.memoryFile, decisionLogPath: null };
}

export async function readPin(options: ReadPinOptions): Promise<PinState> {
  const lang = options.lang ?? 'ko';
  const file = mapPinPath(options.path, options.platform, options.readlink);
  try {
    await lstat(file);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return { kind: 'missing', path: file };
  }
  const problem = await pinOwnershipProblem(file, options.rootUid, options.trustedBase, { platform: options.platform, procDir: options.procDir, lang: options.lang ?? 'ko' });
  if (problem) return { kind: 'unprotected', path: file, reason: problem };
  let policy: Policy;
  let bytes: Buffer;
  try {
    bytes = await readRegularFile(file, 'Organisation pin', 256 * 1024);
    policy = await loadPolicy(file);
  } catch (error) {
    return { kind: 'invalid', path: file, reason: (error as Error).message };
  }
  const sha256 = sha256Hex(bytes);
  // The organisation's own state file is never touched: the GUI keeps its own memory, and the engine alone writes it.
  const memory = memoryPolicy({ policy, memoryFile: options.memoryFile });
  try {
    await mkdir(path.dirname(options.memoryFile), { recursive: true, mode: 0o700 });
  } catch (error) {
    return { kind: 'invalid', path: file, reason: t(lang, 'admin.err.saveFailed', { error: (error as Error).message }) };
  }
  let moved = false;
  let retries = 0;
  for (;;) {
    // Root first, so the root events are recorded before the trust documents are judged against them.
    const root = await loadPolicyRoot(memory, options.now, { recordVersions: true });
    const trust = await loadPolicyTrust(memory, options.now, { recordVersions: true });
    const writeFailed = (!root.ok && root.stateError === 'write') ? root.reason : (!trust.ok && trust.stateError === 'write') ? trust.reason : null;
    if (writeFailed !== null) return { kind: 'invalid', path: file, reason: t(lang, 'admin.err.saveFailed', { error: writeFailed }) };
    const corrupt = (!root.ok && root.stateError === 'corrupt') || (!trust.ok && trust.stateError === 'corrupt');
    const unreadable = (!root.ok && root.stateError === 'unreadable') || (!trust.ok && trust.stateError === 'unreadable');
    // A memory that was read and is wrong is moved aside once. A memory that could not be read is never moved.
    if (corrupt && !moved) {
      moved = true;
      try {
        const backup = await moveMemoryAside(options.memoryFile, options.now);
        options.onMemoryReset?.({ at: formatTimestamp(options.now), backup });
      } catch (error) {
        // Another reader may have moved it already; anything else cannot be repaired here.
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT')
          return { kind: 'invalid', path: file, reason: t(lang, 'admin.err.saveFailed', { error: (error as Error).message }) };
      }
      continue;
    }
    if (unreadable && retries < READ_RETRY_MS.length) {
      await new Promise((resolve) => setTimeout(resolve, READ_RETRY_MS[retries]));
      retries += 1;
      continue;
    }
    if (corrupt || unreadable) return { kind: 'invalid', path: file, reason: t(lang, 'admin.err.memoryBusy') };
    return { kind: 'loaded', path: file, policy, sha256, root, trust, memoryFile: options.memoryFile };
  }
}

/** True when the pin's documents are older than this computer's memory of them. */
export function pinRollback(pin: PinState): boolean {
  return pin.kind === 'loaded' && ((!pin.root.ok && pin.root.rollback === true) || (!pin.trust.ok && pin.trust.rollback === true));
}

/** The active root key id under the pin, or null when it cannot be known (a broken log) or is revoked. */
function activeRoot(pin: LoadedPin): string | null {
  return pin.root.ok ? pin.root.activeRootKeyId : null;
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
  // After a revoke the trustees can still sign the rotation, so the walk up to the revoke is enough for their roles.
  const walk = pin.root.walk;
  if (walk) {
    if (walk.recovery.keyIds.includes(key.keyId)) return { view: { ...base, role: 'recovery' }, publicKey: key.publicKey };
    if (walk.timestampKeyId === key.keyId) return { view: { ...base, role: 'timestamp' }, publicKey: key.publicKey };
  }
  let note = 'this key holds no role in the organisation';
  if (!pin.root.ok && pin.root.walk === null) note = `the root event log cannot be checked (${pin.root.reason}), so root and recovery roles are not recognised`;
  else if (pin.root.walk?.revoked && pin.root.walk.activeRootKeyId === key.keyId) note = `this root key was revoked by root event ${pin.root.walk.revoked.sequence}`;
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
    kind: 'loaded', path: pin.path, reason: pin.root.ok ? null : `root event log: ${pin.root.reason}`,
    rootKeyId: pin.policy.rootKeyId, activeRootKeyId: activeRoot(pin), mode: pin.policy.mode,
    trustOk: pin.trust.ok, trustNote: pin.trust.ok ? null : `${pin.trust.verdict}: ${pin.trust.reason}`,
  };
}

/**
 * Text shown in a native dialog: controls, line and bidirectional marks and zero-width characters are replaced by
 * their code point (format characters, surrogates, private-use and unassigned code points included), so a path, name or reason cannot rewrite or hide the lines around it.
 */
export function dialogSafe(text: string): string {
  return text.replace(/[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Cn}\p{Zl}\p{Zp}\uFE00-\uFE0F\u{E0100}-\u{E01EF}\u034F\u3164\u2800]/gu,
    (c) => `⟨U+${c.codePointAt(0)!.toString(16).toUpperCase().padStart(4, '0')}⟩`);
}

/** The root key id a trust root file claims, read without verifying it (to tell a previous root's documents apart). */
function unverifiedRootKeyId(bytes: Buffer): string | null {
  try {
    const envelope = JSON.parse(bytes.toString('utf8')) as { payload?: unknown };
    if (typeof envelope.payload !== 'string') return null;
    const payload = JSON.parse(Buffer.from(envelope.payload, 'base64').toString('utf8')) as { root?: { key_id?: unknown } };
    return typeof payload.root?.key_id === 'string' ? payload.root.key_id : null;
  } catch {
    return null;
  }
}

/** A key load error as fixed text; the raw message may carry the key file's path. */
function keyLoadMessage(error: unknown, lang: Lang): string {
  const message = error instanceof Error ? error.message : '';
  if (message.includes('Private key permissions')) return t(lang, 'admin.err.keyPerm');
  if (message.includes('not a valid PKCS#8 key') || message.includes('not Ed25519')) return t(lang, 'admin.err.keyNotEd');
  return t(lang, 'admin.err.keyUnreadable');
}

/** An engine message, unless it could carry a path. */
function safeMessage(error: unknown, fallback: string): string {
  const message = error instanceof Error ? error.message : String(error);
  return message.includes('/') ? fallback : message;
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
  /** Native dialogs, answered by a human in the main process. Each resolves true only for the confirming button. */
  confirmReview: (summary: AdminReviewSummary) => Promise<boolean>;
  confirmSign:   (summary: AdminSignSummary) => Promise<boolean>;
  confirmReset:  () => Promise<boolean>;
  /** Asked when a root or recovery key is armed: is this the offline administration computer? */
  confirmOffline: () => Promise<boolean>;
  /** The second confirmation when the last approver would be removed. */
  confirmLastApprover: () => Promise<boolean>;
  /** The approver's public key, chosen by the person in a native dialog; a failure never carries a path. */
  pickPublicKey: () => Promise<{ ok: true; key: PublicKeyInfo } | { ok: false; reason: string }>;
  /** The GUI's user data folder; the rollback memory lives here. */
  stateDir: string;
  /** Folders a key must not live in: discovery roots, discovered Skill folders and the host policy's skill_dirs. */
  discoveryRoots: () => string[];
  skillFolders:   () => string[];
  hostSkillDirs:  () => string[];
  /** The language of the refusal texts, read each time one is built. Korean when absent. */
  lang?: () => Lang;
  /** Tests only. */
  platform?: NodeJS.Platform;
  procDir?: string;
  dialogTimeoutMs?: number;
  cooldownMs?: number;
  hooks?: { afterInspectTree?: () => Promise<void>; beforeSign?: () => Promise<void> };
}

interface Armed {
  key:      PrivateKeyInfo;
  /** Canonical path of the key file; never sent anywhere. */
  keyPath:  string;
  /** Device and inode of the key file as opened at arm; checked again before signing. */
  keyDev:   bigint;
  keyIno:   bigint;
  role:     AdminRoleView;
  pinSha:   string;
  lastUsed: number;
}

interface Review {
  digest:     string;
  name:       string;
  keyId:      string;
  generation: number;
}

class AdminError extends Error {}

const sameRole = (a: AdminRoleView, b: AdminRoleView): boolean =>
  a.role === b.role && a.keyId === b.keyId && a.expiresAt === b.expiresAt && JSON.stringify(a.scopes) === JSON.stringify(b.scopes);

export class AdminSession {
  private readonly pinPath: string;
  private readonly rootUid: number;
  private readonly trustedBase: string;
  private readonly idleMs: number;
  private readonly now: () => Date;
  private readonly platform: NodeJS.Platform;
  private readonly procDir: string;
  private readonly memoryFile: string;
  private readonly dialogTimeoutMs: number;
  private readonly cooldownMs: number;
  private armed: Armed | null = null;
  /** Bumped by every disarm; an operation that captured an older value ends without writing anything. */
  private generation = 0;
  private idleTimer: NodeJS.Timeout | null = null;
  /** Reviews the armed approver recorded through the native dialog, keyed by `${keyId}|${generation}|${instanceId}`. */
  private readonly reviews = new Map<string, Review>();
  /** arm, review, approve and resetMemory run one at a time. */
  private queue: Promise<unknown> = Promise.resolve();
  private memoryReset: { at: string; backup: string } | null = null;
  /** Dialogs whose promise has not settled (a timed-out dialog may still be on screen). */
  private dialogsOpen = 0;
  private cooldownUntil = 0;
  /** This computer's memory was reset: the next root or timestamp signature says so in its dialog. */
  private resetPending = false;

  private readonly options: AdminSessionOptions;

  constructor(options: AdminSessionOptions) {
    this.options = options;
    this.pinPath = options.pinPath ?? ORG_PIN_PATH;
    this.rootUid = options.rootUid ?? 0;
    this.trustedBase = options.trustedBase ?? '/';
    this.idleMs = options.idleMs ?? ARM_IDLE_MS;
    this.now = options.now ?? (() => new Date());
    this.platform = options.platform ?? process.platform;
    this.procDir = options.procDir ?? '/proc';
    this.memoryFile = path.join(options.stateDir, MEMORY_FILE);
    this.dialogTimeoutMs = options.dialogTimeoutMs ?? DIALOG_TIMEOUT_MS;
    this.cooldownMs = options.cooldownMs ?? COOLDOWN_MS;
  }

  /** Every call records the pin's document versions in this computer's memory; the engine merges concurrent writers. */
  private async pin(): Promise<PinState> {
    return await readPin({
      path: this.pinPath, rootUid: this.rootUid, trustedBase: this.trustedBase, now: this.now(),
      memoryFile: this.memoryFile, platform: this.platform, procDir: this.procDir, readlink: (p) => readlinkSync(p),
      onMemoryReset: (reset) => { this.memoryReset = reset; this.resetPending = true; }, lang: this.lang(),
    });
  }

  private lang(): Lang {
    return this.options.lang?.() ?? 'ko';
  }

  private msg(key: MessageKey, params?: Record<string, string | number>): string {
    return t(this.lang(), key, params);
  }

  /** Synchronous and never queued: nothing awaits between the decision to disarm and the disarm. */
  private dropKey(_reason: string): void {
    this.armed = null;
    this.generation += 1;
    this.reviews.clear();
    if (this.idleTimer) clearTimeout(this.idleTimer);
    this.idleTimer = null;
  }

  disarm(): void {
    this.dropKey('disarm');
  }

  private serial<T>(work: () => Promise<T>): Promise<T> {
    const result = this.queue.then(work);
    this.queue = result.then(() => undefined, () => undefined);
    return result;
  }

  /** Resolves `fallback` after `ms`; the dialog may stay on screen and a late answer is ignored. */
  private withTimeout<T>(answer: Promise<T>, ms: number, fallback: T): Promise<T> {
    return new Promise((resolve) => {
      const timer = setTimeout(() => resolve(fallback), ms);
      timer.unref?.();
      answer.then((value) => { clearTimeout(timer); resolve(value); }, () => { clearTimeout(timer); resolve(fallback); });
    });
  }

  /**
   * Shows a dialog and counts it as open until it settles or `dialogTimeoutMs + 5000` ms after it opened, whichever
   * comes first, so one stuck dialog cannot block every other for ever.
   */
  private async ask<T>(show: () => Promise<T>, fallback: T): Promise<T> {
    this.dialogsOpen += 1;
    let released = false;
    const release = (): void => {
      if (released) return;
      released = true;
      this.dialogsOpen -= 1;
    };
    const slot = setTimeout(release, this.dialogTimeoutMs + DIALOG_SLOT_GRACE_MS);
    slot.unref?.();
    const shown = Promise.resolve().then(show).finally(() => { clearTimeout(slot); release(); });
    return await this.withTimeout(shown, this.dialogTimeoutMs, fallback);
  }

  /**
   * The key file picker: one dialog at a time like every other, counted while open, a cancel starts the cooldown.
   * Throws the refusal text; resolves null when the person cancelled.
   */
  async pickFile(open: () => Promise<string | null>): Promise<string | null> {
    this.requireNoDialog();
    const chosen = await this.ask(open, null);
    if (chosen === null) this.startCooldown();
    return chosen;
  }

  private startCooldown(): void {
    this.cooldownUntil = Date.now() + this.cooldownMs;
  }

  /** One dialog at a time, and a pause after any cancel or timeout, so a page cannot spam dialogs until one is clicked. */
  private requireNoDialog(): void {
    if (Date.now() < this.cooldownUntil) throw new AdminError(this.msg('admin.err.cooldown'));
    if (this.dialogsOpen > 0) throw new AdminError(this.msg('admin.err.dialogOpen'));
  }

  private async hostDiffers(pin: PinState): Promise<boolean> {
    const hostPolicy = this.options.hostPolicyPath?.() ?? null;
    if (pin.kind !== 'loaded' || hostPolicy === null) return false;
    const resolved = await realpath(hostPolicy).catch(() => path.resolve(hostPolicy));
    return resolved !== pin.path;
  }

  /** Reads the pin, drops the key if the pin or its role changed, and reports. Never throws; never counts as use. */
  async status(): Promise<AdminStatusView> {
    this.expireIfIdle();
    const pin = await this.pin();
    this.recheck(pin);
    return {
      pin: pinView(pin),
      hostPolicyDiffers: await this.hostDiffers(pin),
      armed: this.armed ? { ...this.armed.role } : null,
      idleMinutes: Math.round(this.idleMs / 60000),
      memoryReset: this.memoryReset ? { ...this.memoryReset } : null,
      rollback: pinRollback(pin),
    };
  }

  /** The armed key against a pin that was read a moment ago. A pin change or any role change disarms at once. */
  private recheck(pin: PinState): void {
    const armed = this.armed;
    if (!armed) return;
    if (pin.kind !== 'loaded' || pin.sha256 !== armed.pinSha) {
      this.dropKey('pin');
      return;
    }
    const { view, publicKey } = roleOf(pin, armed.key, this.now());
    // The read took time: only drop the key that was checked, never one armed since.
    if (this.armed === armed && (!publicKey || !sameRole(view, armed.role))) this.dropKey('role');
  }

  /** Loads a private key file chosen by the user, proves possession and arms it if it holds a role. */
  arm(keyPath: string): Promise<AdminArmResult> {
    return this.serial(async () => {
      this.dropKey('arm');
      const generation = this.generation;
      const pin = await this.pin();
      if (pin.kind !== 'loaded') return { ok: false, reason: pinView(pin).reason ?? `organisation pin: ${pin.kind}` } as AdminArmResult;
      let key: PrivateKeyInfo;
      let canonical: string;
      let identity: { dev: bigint; ino: bigint };
      try {
        ({ key, canonical, identity } = await this.openKeyFile(keyPath));
      } catch (error) {
        return { ok: false, reason: keyLoadMessage(error, this.lang()) };
      }
      if (await this.keyInsideSkills(canonical, pin)) return { ok: false, reason: this.msg('admin.err.keyInSkill'), keyId: key.keyId };
      const { view, publicKey } = roleOf(pin, key, this.now());
      if (view.role === 'none' || !publicKey) return { ok: false, reason: view.note ?? 'this key holds no role in the organisation', keyId: key.keyId };
      if (!proveIdentity(pin, key, publicKey)) return { ok: false, reason: 'the key could not prove possession: it is not the private half of the key the documents name', keyId: key.keyId };
      if (view.role === 'root' || view.role === 'recovery') {
        // A computer cannot prove it is offline; the person is asked, after the key is proven and before it is armed.
        try {
          this.requireNoDialog();
        } catch (error) {
          return { ok: false, reason: (error as Error).message };
        }
        const offline = await this.ask(() => this.options.confirmOffline(), false);
        if (!offline) {
          this.startCooldown();
          return { ok: false, reason: 'cancelled' };
        }
      }
      if (generation !== this.generation) return { ok: false, reason: this.msg('admin.err.keyGone') };
      this.armed = { key, keyPath: canonical, keyDev: identity.dev, keyIno: identity.ino, role: view, pinSha: pin.sha256, lastUsed: Date.now() };
      this.scheduleIdle();
      return { ok: true, role: { ...view } };
    });
  }

  /** One file, one open: the real path, a no-follow handle, the checks on that handle and the bytes read from it. */
  private async openKeyFile(keyPath: string): Promise<{ key: PrivateKeyInfo; canonical: string; identity: { dev: bigint; ino: bigint } }> {
    const canonical = await realpath(keyPath);
    const handle = await open(canonical, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | (fsConstants.O_NONBLOCK ?? 0));
    let pem: Buffer | null = null;
    try {
      const info = await handle.stat({ bigint: true });
      if (!info.isFile()) throw new Error('Private key must be a regular, non-symlink file');
      if (this.platform !== 'win32' && (info.mode & 0o077n) !== 0n)
        throw new Error('Private key permissions must deny group and other access (chmod 600)');
      const buffer = Buffer.alloc(MAX_KEY_FILE_BYTES + 1);
      let total = 0;
      while (total <= MAX_KEY_FILE_BYTES) {
        const { bytesRead } = await handle.read(buffer, total, buffer.length - total, null);
        if (bytesRead === 0) break;
        total += bytesRead;
      }
      pem = buffer;
      if (total > MAX_KEY_FILE_BYTES) throw new Error('Private key is too large');
      const key = loadPrivateKeyBytes(buffer.subarray(0, total));
      return { key, canonical, identity: { dev: info.dev, ino: info.ino } };
    } finally {
      pem?.fill(0);
      await handle.close();
    }
  }

  /** The stored key path must still be the regular file that was opened at arm. Otherwise the key is dropped. */
  private async requireSameKeyFile(armed: Armed): Promise<void> {
    let same = false;
    try {
      const info = await lstat(armed.keyPath, { bigint: true });
      same = info.isFile() && info.dev === armed.keyDev && info.ino === armed.keyIno;
    } catch {
      same = false;
    }
    if (!same) {
      if (this.armed === armed) this.dropKey('key file');
      throw new AdminError(this.msg('admin.err.keySwapped'));
    }
  }

  /** The key must not live where Skills do: a Skill folder is shared, copied and scanned by tools. */
  private async keyInsideSkills(keyCanonical: string, pin: LoadedPin): Promise<boolean> {
    const roots = [...this.options.discoveryRoots(), ...this.options.skillFolders(), ...pin.policy.skillDirs, ...this.options.hostSkillDirs()];
    for (const root of roots) {
      try {
        if (isInside(await realpathAllowingMissing(root), keyCanonical)) return true;
      } catch {
        // A root that cannot be resolved cannot hold the key.
      }
    }
    return false;
  }

  private scheduleIdle(): void {
    if (this.idleTimer) clearTimeout(this.idleTimer);
    this.idleTimer = setTimeout(() => this.dropKey('idle'), this.idleMs);
    this.idleTimer.unref?.();
  }

  private expireIfIdle(): void {
    if (this.armed && Date.now() - this.armed.lastUsed > this.idleMs) this.dropKey('idle');
  }

  /**
   * The armed key, re-checked against the current pin and documents. Any change disarms it. Only arm, review and
   * approve come through here, so only they count as use for the idle timer.
   */
  private async current(role: AdminRoleView['role'], op: { generation: number }): Promise<{ pin: LoadedPin; armed: Armed }> {
    this.expireIfIdle();
    const armed = this.armed;
    if (!armed || op.generation !== this.generation) throw new AdminError(this.msg('admin.err.keyGone'));
    const pin = await this.pin();
    if (op.generation !== this.generation) throw new AdminError(this.msg('admin.err.keyGone'));
    if (pin.kind !== 'loaded' || pin.sha256 !== armed.pinSha) {
      this.dropKey('pin');
      throw new AdminError('the organisation pin changed; load your key again');
    }
    const { view, publicKey } = roleOf(pin, armed.key, this.now());
    if (view.role !== armed.role.role || !publicKey || !proveIdentity(pin, armed.key, publicKey)) {
      this.dropKey('role');
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

  /** One read of the Skill: the digest and the name come from the same bytes. */
  private async readSkill(dir: string) {
    const tree = await collectSkillTree(dir, { includeContents: true });
    const name = skillNameFromSkillFile(dir, tree.contents!.get(SKILL_FILENAME));
    return { tree, name };
  }

  /** INSPECT: the exact current version, its files and the certificate it carries. Read-only; no key needed. */
  async inspect(instanceId: string): Promise<AdminInspectView> {
    const skill = this.skill(instanceId);
    const tree = await collectSkillTree(skill.path, { includeContents: true });
    let name = skill.name;
    try {
      name = skillNameFromSkillFile(skill.path, tree.contents!.get(SKILL_FILENAME));
    } catch {
      // An unreadable name does not stop the inspection; the discovered name stays.
    }
    await this.options.hooks?.afterInspectTree?.();
    const pin = await this.pin();
    let certificate: AdminInspectView['certificate'] = null;
    let verdict: AdminInspectView['verdict'] = null;
    let verdictDigest: string | null = null;
    if (pin.kind === 'loaded' && !pin.trust.ok) {
      verdict = { verdict: pin.trust.verdict, reason: pin.trust.reason };
    } else if (pin.kind === 'loaded' && pin.trust.ok) {
      // Always with the context already loaded: verifyWithPolicy without one would record versions in the host state.
      const result = await verifyWithPolicy(pin.policy, skill.path, { now: this.now(), context: pin.trust.context });
      verdict = { verdict: result.verdict, reason: result.reason };
      verdictDigest = result.digest;
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
    const armed = this.armed;
    return {
      instanceId, name, path: skill.path, digest: tree.digest, totalBytes: tree.totalBytes,
      files: tree.files.map((f) => ({ path: f.path, size: f.size, sha256: f.sha256, exec: f.exec })),
      excluded: [...tree.excluded], certificate, verdict,
      // The verdict was computed from a second read; if it saw other bytes it describes a different version.
      verdictStale: verdictDigest !== null && verdictDigest !== tree.digest,
      inspected: armed !== null && this.reviews.get(`${armed.key.keyId}|${this.generation}|${instanceId}`)?.digest === tree.digest,
    };
  }

  /**
   * REVIEW: shows a native dialog with the exact version; only its confirming button records the review. The renderer
   * only asks; it cannot answer.
   */
  review(instanceId: string): Promise<AdminActionResult> {
    return this.serial(async () => {
      try {
        this.requireNoDialog();
        const first = this.armed;
        if (!first) throw new AdminError(this.msg('admin.err.needKey'));
        const op = { keyId: first.key.keyId, generation: this.generation };
        await this.current(first.role.role === 'root' ? 'root' : 'approver', op);
        const skill = this.skill(instanceId);
        let read;
        try {
          read = await this.readSkill(skill.path);
        } catch (error) {
          throw new AdminError(safeMessage(error, this.msg('admin.err.skillUnreadable')));
        }
        const summary: AdminReviewSummary = { skillName: read.name, skillPath: skill.path, digest: read.tree.digest, files: read.tree.files.length };
        this.requireNoDialog();
        const confirmed = await this.ask(() => this.options.confirmReview(summary), false);
        if (!confirmed || op.generation !== this.generation) {
          this.startCooldown();
          return { ok: false, message: this.msg('admin.err.reviewNotRecorded') };
        }
        this.reviews.set(`${op.keyId}|${op.generation}|${instanceId}`, { digest: read.tree.digest, name: read.name, keyId: op.keyId, generation: op.generation });
        return { ok: true };
      } catch (error) {
        return { ok: false, message: (error as Error).message };
      }
    });
  }

  /**
   * APPROVE: signs a certificate for the reviewed digest. Order: key and refusals, review record, reason and lifetime,
   * role and scope, key location, one fresh read, claim the record, signing dialog, sign, and a last check inside
   * the engine just before the file is written.
   */
  approve(instanceId: string, digest: string, lifetime: AdminLifetime, reason: string): Promise<AdminActionResult> {
    return this.serial(async () => {
      try {
        const first = this.armed;
        if (!first) throw new AdminError(this.msg('admin.err.needKey'));
        const op = { keyId: first.key.keyId, generation: this.generation };
        if (first.role.role !== 'approver') throw new AdminError(`this needs the approver role; the armed key is ${first.role.role}`);
        this.requireNoDialog();

        const recordKey = `${op.keyId}|${op.generation}|${instanceId}`;
        const record = this.reviews.get(recordKey);
        if (!record || record.digest !== digest) throw new AdminError(this.msg('admin.err.needReview'));

        const text = this.checkReason(reason);
        if (!LIFETIMES.includes(lifetime)) throw new AdminError('choose a lifetime of 30, 90 or 180 days');
        const now = this.now();
        const expires = addDuration(now, lifetime, 'certificate lifetime');

        const { pin, armed } = await this.current('approver', op);
        // The expiry as the re-check has just refreshed it, not the one seen when the key was armed.
        const keyExpiry = armed.role.expiresAt;
        if (keyExpiry && expires > new Date(keyExpiry))
          throw new AdminError(this.msg('admin.err.keyExpiry', { expiry: keyExpiry }));
        const scopes = armed.role.scopes ?? [];
        if (!scopes.some((scope) => scopeMatches(scope, record.name)))
          throw new AdminError(this.msg('admin.err.scope', { scopes: scopes.join(', '), name: record.name }));
        await this.requireSameKeyFile(armed);
        const skill = this.skill(instanceId);
        try {
          await resolveOutside(armed.keyPath, skill.path, 'Approver private key');
        } catch {
          throw new AdminError(this.msg('admin.err.keyInSkill'));
        }
        if (await this.keyInsideSkills(armed.keyPath, pin)) throw new AdminError(this.msg('admin.err.keyInSkill'));
        await this.requireSameKeyFile(armed);

        let read;
        try {
          read = await this.readSkill(skill.path);
        } catch {
          throw new AdminError(this.msg('admin.err.changed'));
        }
        if (read.tree.digest !== record.digest || read.name !== record.name) throw new AdminError(this.msg('admin.err.changed'));

        // Claim the record before the dialog, so a second approve cannot use it while this one waits for the human.
        this.requireNoDialog();
        this.reviews.delete(recordKey);
        const summary: AdminSignSummary = {
          action: 'approve', skillName: read.name, skillPath: skill.path, reviewedDigest: record.digest, digest: read.tree.digest,
          lifetime, expiresAt: formatTimestamp(expires), reason: text, role: armed.role.role, keyName: armed.role.name, keyId: op.keyId,
        };
        const confirmed = await this.ask(() => this.options.confirmSign(summary), false);
        if (!confirmed) {
          if (op.generation === this.generation) this.reviews.set(recordKey, record);
          this.startCooldown();
          return { ok: false, message: this.msg('admin.err.signCancelled') };
        }
        if (op.generation !== this.generation) throw new AdminError(this.msg('admin.err.keyGone'));

        const dir = pin.policy.certificateDirs[0];
        try {
          const issued = await approveSkill({
            skillDir: skill.path, approverKey: armed.key, now, expires: lifetime, reason: text,
            expectDigest: record.digest, expectName: record.name, ...(dir ? { outDir: dir } : {}),
            beforeSign: async (info) => {
              await this.options.hooks?.beforeSign?.();
              // Last look before the file is written: the key must still be this generation's and still hold its role.
              const latest = await this.current('approver', op);
              await this.requireSameKeyFile(latest.armed);
              const latestScopes = latest.armed.role.scopes ?? [];
              if (!latestScopes.some((scope) => scopeMatches(scope, info.skillName)))
                throw new AdminError(this.msg('admin.err.scope', { scopes: latestScopes.join(', '), name: info.skillName }));
              if (op.generation !== this.generation) throw new AdminError(this.msg('admin.err.keyGone'));
              if (await this.keyInsideSkills(latest.armed.keyPath, latest.pin)) throw new AdminError(this.msg('admin.err.keyInSkill'));
            },
          });
          return { ok: true, certificateId: issued.certificateId, certificatePath: issued.path, digest: issued.digest, expiresAt: formatTimestamp(issued.expiresAt) };
        } catch (error) {
          if (error instanceof AdminError) throw error;
          throw new AdminError(safeMessage(error, this.msg('admin.err.signFailed')));
        }
      } catch (error) {
        return { ok: false, message: (error as Error).message };
      }
    });
  }

  /** Trim; at most 1024 units; display-safe; and real letters or digits, not fillers. */
  private checkReason(reason: string): string {
    const text = reason.trim();
    if (text === '') throw new AdminError(this.msg('admin.err.needReason'));
    if (text.length > MAX_REASON) throw new AdminError(this.msg('admin.err.reasonTooLong'));
    requireDisplaySafeText(text, 'Reason', MAX_REASON);
    const real = [...text].filter((c) => /[\p{L}\p{N}]/u.test(c) && !'ᅟᅠㅤﾠ⠀'.includes(c));
    if (real.length < 3) throw new AdminError(this.msg('admin.err.needReason'));
    return text;
  }

  /** POLICY CHECK: the Skill's verdict under the pin's policy, without recording versions in the organisation's state. */
  async check(instanceId: string): Promise<AdminCheckView> {
    const skill = this.skill(instanceId);
    const pin = await this.pin();
    if (pin.kind !== 'loaded') return { verdict: null, reason: pinView(pin).reason ?? `organisation pin: ${pin.kind}`, trustOk: false, trustNote: null };
    if (!pin.trust.ok) return { verdict: pin.trust.verdict, reason: pin.trust.reason, trustOk: false, trustNote: `${pin.trust.verdict}: ${pin.trust.reason}` };
    const result = await verifyWithPolicy(pin.policy, skill.path, { now: this.now(), context: pin.trust.context });
    return { verdict: result.verdict, reason: result.reason, trustOk: true, trustNote: null };
  }

  // ------------------------------------------------------------------ phase 2a: the trust root

  private forbiddenText(why: ForbiddenKey['why']): string {
    const keys: Record<ForbiddenKey['why'], MessageKey> = {
      root: 'admin.p2.forbidden.root', recovery: 'admin.p2.forbidden.recovery', timestamp: 'admin.p2.forbidden.timestamp',
      retired: 'admin.p2.forbidden.retired', formerRecovery: 'admin.p2.forbidden.formerRecovery', revoked: 'admin.p2.forbidden.revoked',
    };
    return this.msg(keys[why]);
  }

  /** Engine failures as the person sees them: typed errors by class, everything else in English, never with a path. */
  private writeMessage(error: unknown): string {
    if (error instanceof AdminError) return error.message;
    if (error instanceof StaleDocumentError) return this.msg('admin.p2.err.stale');
    if (error instanceof DocumentChangedError || error instanceof FileChangedError) return this.msg('admin.p2.err.changed');
    return dialogSafe(safeMessage(error, this.msg('admin.err.signFailed')));
  }

  /**
   * The trust root read under the active root, with no expiry check (an expired one can be renewed). Documents signed by
   * a previous root are recognised before the verified read: the file's own root key id is in the walk's retired keys.
   */
  private async trustRootDocument(pin: PinState): Promise<
    { ok: true; document: TrustRoot; bytes: Buffer; activeRootKeyId: string; pin: LoadedPin } | { ok: false; message: string; signedByPreviousRoot: boolean }> {
    const fail = (message: string, signedByPreviousRoot = false) => ({ ok: false as const, message, signedByPreviousRoot });
    if (pin.kind !== 'loaded') return fail(pinView(pin).reason ?? `organisation pin: ${pin.kind}`);
    if (!pin.root.ok) return fail(pin.root.rootRevoked ? this.msg('admin.p2.err.rootRevoked') : this.msg('admin.p2.err.trustRootUnchanged', { reason: dialogSafe(pin.root.reason) }));
    let bytes: Buffer;
    try {
      bytes = await readRegularFile(pin.policy.trustRootPath, 'Trust root', 4 * 1024 * 1024);
    } catch (error) {
      return fail(dialogSafe(safeMessage(error, this.msg('admin.p2.why.documents'))));
    }
    const activeRootKeyId = pin.root.activeRootKeyId;
    try {
      return { ok: true, document: readTrustRootForUpdate(bytes, activeRootKeyId), bytes, activeRootKeyId, pin };
    } catch (error) {
      const claimed = unverifiedRootKeyId(bytes);
      if (claimed !== null && pin.root.walk?.retired.includes(claimed)) return fail(this.msg('admin.p2.err.previousRoot'), true);
      return fail(dialogSafe((error as Error).message));
    }
  }

  /** TRUST ROOT: the document as it is, whether or not the organisation's trust fully loads. Unqueued; not use. */
  async trustRoot(): Promise<AdminTrustRootView> {
    const pin = await this.pin();
    const found = await this.trustRootDocument(pin);
    if (!found.ok) return found;
    const now = this.now();
    const { document } = found;
    let forbidden = new Map<string, ForbiddenKey['why']>();
    let note: string | null = null;
    try {
      forbidden = new Map((await forbiddenApproverKeys(memoryPolicy(found.pin), now)).map((item) => [item.keyId, item.why]));
    } catch (error) {
      note = this.msg('admin.p2.err.rolesUnknown', { reason: dialogSafe((error as Error).message) });
    }
    const state = await readHostState(found.pin.memoryFile).catch(() => null);
    const minimum = state ? memoryMinimums(state, found.activeRootKeyId, null).trustRoot : 0;
    return {
      ok: true, path: found.pin.policy.trustRootPath, sha256: `sha256:${sha256Hex(found.bytes)}`, version: document.version,
      expiresAt: formatTimestamp(document.expiresAt), expired: document.expiresAt <= now,
      approvers: document.approvers.map((entry) => ({
        keyId: entry.keyId, name: entry.name, scopes: [...entry.scopes], expiresAt: formatTimestamp(entry.expiresAt), expired: entry.expiresAt <= now,
        forbidden: forbidden.has(entry.keyId) ? this.forbiddenText(forbidden.get(entry.keyId)!) : null,
      })),
      stale: document.version < minimum, signedByPreviousRoot: false, note,
    };
  }

  /** Every Skill folder the organisation or the host names, once each, plus folders too deep to search. */
  private async skillSet(pin: LoadedPin): Promise<{ dirs: string[]; tooDeep: string[] }> {
    const roots: string[] = [];
    for (const root of [...this.options.discoveryRoots(), ...pin.policy.skillDirs, ...this.options.hostSkillDirs()]) {
      if (await lstat(root).then(() => true, () => false)) roots.push(root);
    }
    let found;
    try {
      found = await findSkillDirs(roots);
    } catch (error) {
      if (error instanceof DiscoveryBudgetError) throw new AdminError(this.msg('admin.p2.err.tooManyFolders'));
      throw error;
    }
    const unique = async (list: string[]): Promise<string[]> => {
      const seen = new Map<string, string>();
      for (const dir of list) seen.set(await realpath(dir).catch(() => path.resolve(dir)), dir);
      return [...seen.values()];
    };
    return { dirs: await unique(found.skillDirs), tooDeep: await unique(found.tooDeep) };
  }

  /**
   * What a write does to the Skills, computed with the hosts' own loader (design A1, S2, T5, T6). `from` is the current
   * documents, `to` the documents with `override` in place; in a freshness organisation a root document write blocks every
   * Skill until a timestamp, so `after` (the timestamp check skipped) shows the result that matters.
   */
  private async consequence(pin: LoadedPin, now: Date, override: PreviewOverride, kind: 'document' | 'timestamp'): Promise<AdminConsequence> {
    const policy = memoryPolicy(pin);
    const freshness = pin.policy.recovery?.freshness !== undefined;
    const blocks = freshness && kind === 'document';
    const set = await this.skillSet(pin);
    const from = await loadTrustForPreview(policy, now);
    const to = await loadTrustForPreview(policy, now, { override });
    const after = blocks ? await loadTrustForPreview(policy, now, { override, skipFreshness: true }) : to;
    const verdict = async (dir: string, load: TrustContextResult): Promise<{ name: string; verdict: Verdict }> => {
      if (!load.ok) return { name: path.basename(dir), verdict: 'UNVERIFIABLE' };
      const result = await verifyWithPolicy(policy, dir, { now, context: load.context });
      return { name: result.skillName, verdict: result.verdict };
    };
    const rows: Array<{ name: string; from: Verdict; after: Verdict }> = [];
    for (const dir of set.dirs) {
      const f = await verdict(dir, from);
      const a = await verdict(dir, after);
      rows.push({ name: f.name === path.basename(dir) && a.name !== f.name ? a.name : f.name, from: f.verdict, after: a.verdict });
    }
    const afterCounts: Partial<Record<Verdict, number>> = {};
    for (const row of rows) afterCounts[row.after] = (afterCounts[row.after] ?? 0) + 1;
    if (set.tooDeep.length > 0) afterCounts.UNVERIFIABLE = (afterCounts.UNVERIFIABLE ?? 0) + set.tooDeep.length;
    const changed = rows.filter((row) => row.from !== row.after).sort((a, b) => a.name.localeCompare(b.name));
    // A write the documents could not survive is refused before the dialog; a timestamp that is still missing is not that.
    const toFailed = after.ok ? null : after.reason;
    return {
      skills: rows.length + set.tooDeep.length,
      changed: changed.length,
      lines: changed.slice(0, 5).map((row) => ({ name: row.name, from: row.from, to: blocks ? 'BLOCKED_UNTIL_TIMESTAMP' as const : row.after, after: row.after })),
      tooDeep: set.tooDeep.length,
      freshnessBlock: blocks,
      fromFailed: from.ok ? null : from.reason,
      toFailed,
      afterCounts,
    };
  }

  /** POLICY CHECK for the organisation: the verdict of every Skill under the host's own view. Unqueued; not use. */
  async verifyAll(): Promise<AdminVerifyAllView> {
    const pin = await this.pin();
    if (pin.kind !== 'loaded') return { skills: 0, counts: {}, trustOk: false, trustNote: pinView(pin).reason ?? `organisation pin: ${pin.kind}`, timestampMismatch: false };
    const now = this.now();
    const policy = memoryPolicy(pin);
    const set = await this.skillSet(pin);
    const trust = await loadPolicyTrust(policy, now, { recordVersions: false });
    const counts: Partial<Record<Verdict, number>> = {};
    const add = (verdict: Verdict) => { counts[verdict] = (counts[verdict] ?? 0) + 1; };
    for (const dir of set.dirs) add(trust.ok ? (await verifyWithPolicy(policy, dir, { now, context: trust.context })).verdict : 'UNVERIFIABLE');
    for (const dir of set.tooDeep) add(tooDeepResult(dir, now).verdict);
    let timestampMismatch = false;
    if (!trust.ok && pin.policy.recovery?.freshness)
      timestampMismatch = (await loadTrustForPreview(policy, now, { skipFreshness: true })).ok;
    return {
      skills: set.dirs.length + set.tooDeep.length, counts, trustOk: trust.ok,
      trustNote: trust.ok ? null : `${trust.verdict}: ${dialogSafe(trust.reason)}`, timestampMismatch,
    };
  }

  /** The files a signing was prepared from; any change before the write is a changed document. */
  private async inputsOf(pin: LoadedPin): Promise<Array<{ path: string; sha256: string | null }>> {
    const files = [pin.path, pin.policy.trustRootPath, pin.policy.revocationsPath];
    if (pin.policy.recovery) files.push(pin.policy.recovery.rootEventsPath);
    if (pin.policy.recovery?.freshness) files.push(pin.policy.recovery.freshness.timestampPath);
    const out: Array<{ path: string; sha256: string | null }> = [];
    for (const file of files) {
      try {
        out.push({ path: file, sha256: sha256Hex(await readRegularFile(file, 'Document', 16 * 1024 * 1024)) });
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
        out.push({ path: file, sha256: null });
      }
    }
    return out;
  }

  private async requireInputs(inputs: Array<{ path: string; sha256: string | null }>): Promise<void> {
    for (const input of inputs) {
      let now: string | null = null;
      try {
        now = sha256Hex(await readRegularFile(input.path, 'Document', 16 * 1024 * 1024));
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw new DocumentChangedError('Document');
      }
      if (now !== input.sha256) throw new DocumentChangedError('Document');
    }
  }

  /** The checks every root or timestamp commit repeats just before the file is written. */
  private async guardBeforeWrite(role: 'root' | 'timestamp', op: { keyId: string; generation: number }, inputs: Array<{ path: string; sha256: string | null }>): Promise<void> {
    if (op.generation !== this.generation) throw new AdminError(this.msg('admin.err.keyGone'));
    const latest = await this.current(role, op);
    await this.requireSameKeyFile(latest.armed);
    if (await this.keyInsideSkills(latest.armed.keyPath, latest.pin)) throw new AdminError(this.msg('admin.err.keyInSkill'));
    await this.requireInputs(inputs);
    if (op.generation !== this.generation) throw new AdminError(this.msg('admin.err.keyGone'));
  }

  addApprover(o: { name: string; scopes: string[]; lifetime: AdminApproverLifetime; trustRootLifetime?: AdminTrustRootLifetime }): Promise<AdminWriteResult> {
    return this.writeTrustRoot({ kind: 'add', ...o });
  }

  removeApprover(keyId: string, trustRootLifetime?: AdminTrustRootLifetime): Promise<AdminWriteResult> {
    return this.writeTrustRoot({ kind: 'remove', keyId, ...(trustRootLifetime ? { trustRootLifetime } : {}) });
  }

  renewTrustRoot(lifetime: AdminTrustRootLifetime): Promise<AdminWriteResult> {
    return this.writeTrustRoot({ kind: 'renew', lifetime });
  }

  /**
   * Add, remove and renew: prepare, consequence, native dialog(s), commit, record. Order (design V12 as amended): D9
   * refusals and capture, role, key location, the public-key picker (add), previous-root and root-walk checks, forbidden
   * keys and minimums, prepare, consequence, dialog, last-approver confirm, commit with the checks repeated in beforeWrite.
   */
  private writeTrustRoot(request:
    | { kind: 'add'; name: string; scopes: string[]; lifetime: AdminApproverLifetime; trustRootLifetime?: AdminTrustRootLifetime }
    | { kind: 'remove'; keyId: string; trustRootLifetime?: AdminTrustRootLifetime }
    | { kind: 'renew'; lifetime: AdminTrustRootLifetime }): Promise<AdminWriteResult> {
    return this.serial(async () => {
      try {
        const first = this.armed;
        if (!first) throw new AdminError(this.msg('admin.err.needKey'));
        const op = { keyId: first.key.keyId, generation: this.generation };
        this.requireNoDialog();
        if (first.role.role !== 'root') throw new AdminError(this.msg('admin.p2.err.notRoot', { role: first.role.role }));
        const name = request.kind === 'add' ? request.name.trim() : '';
        if (request.kind === 'add') {
          if (name === '' || name.length > MAX_APPROVER_NAME || request.scopes.length === 0 || request.scopes.length > 64) throw new AdminError(this.msg('admin.p2.err.badInput'));
          for (const scope of request.scopes) validateScope(scope);
        }

        const { pin, armed } = await this.current('root', op);
        await this.requireSameKeyFile(armed);
        if (await this.keyInsideSkills(armed.keyPath, pin)) throw new AdminError(this.msg('admin.err.keyInSkill'));

        let publicKey: PublicKeyInfo | null = null;
        if (request.kind === 'add') {
          this.requireNoDialog();
          const picked = await this.ask(() => this.options.pickPublicKey(), { ok: false as const, reason: 'cancelled' });
          if (!picked.ok) {
            this.startCooldown();
            throw new AdminError(picked.reason === 'cancelled' ? this.msg('admin.p2.err.cancelled') : this.msg('admin.p2.err.publicKeyUnreadable'));
          }
          if (op.generation !== this.generation) throw new AdminError(this.msg('admin.err.keyGone'));
          publicKey = picked.key;
        }

        const now = this.now();
        const found = await this.trustRootDocument(pin);
        if (!found.ok) throw new AdminError(found.message);
        // The root walk must load (design U1); add keeps the engine's own text.
        const rootCheck = await loadPolicyRoot(memoryPolicy(pin), now, { recordVersions: false });
        if (!rootCheck.ok) {
          throw new AdminError(rootCheck.rootRevoked ? this.msg('admin.p2.err.rootRevoked')
            : request.kind === 'add' ? dialogSafe(`Cannot check the root event log, so no approver is added: ${rootCheck.reason}`)
            : this.msg('admin.p2.err.trustRootUnchanged', { reason: dialogSafe(rootCheck.reason) }));
        }
        let forbidden: ForbiddenKey[];
        try {
          forbidden = await forbiddenApproverKeys(memoryPolicy(pin), now);
        } catch (error) {
          throw new AdminError(this.msg('admin.p2.err.rolesUnknown', { reason: dialogSafe((error as Error).message) }));
        }
        const listed = found.document.approvers.filter((entry) => forbidden.some((item) => item.keyId === entry.keyId));
        const leftOver = listed.filter((entry) => request.kind !== 'remove' || entry.keyId !== request.keyId);
        if (leftOver.length > 0) {
          const why = forbidden.find((item) => item.keyId === leftOver[0]!.keyId)!.why;
          throw new AdminError(this.msg('admin.p2.err.removeFirst', { why: this.forbiddenText(why) }));
        }

        const expired = found.document.expiresAt <= now;
        const trustRootLifetime = request.kind === 'renew' ? request.lifetime : request.trustRootLifetime;
        if (request.kind !== 'renew') {
          if (trustRootLifetime !== undefined && !TRUST_ROOT_LIFETIMES.includes(trustRootLifetime)) throw new AdminError(this.msg('admin.p2.err.badInput'));
          if (expired && trustRootLifetime === undefined) throw new AdminError(this.msg('admin.p2.err.pickLifetime'));
        } else if (!TRUST_ROOT_LIFETIMES.includes(request.lifetime)) {
          throw new AdminError(this.msg('admin.p2.err.badInput'));
        }
        if (request.kind === 'add' && !APPROVER_LIFETIMES.includes(request.lifetime)) throw new AdminError(this.msg('admin.p2.err.badInput'));

        const state = await readHostState(pin.memoryFile);
        const minimum = memoryMinimums(state, found.activeRootKeyId, null).trustRoot;
        const inputs = await this.inputsOf(pin);
        const change: TrustRootChange = request.kind === 'add'
          ? { kind: 'add', publicKey: publicKey!, name, scopes: request.scopes, expires: request.lifetime, ...(trustRootLifetime ? { trustRootExpires: trustRootLifetime } : {}) }
          : request.kind === 'remove'
            ? { kind: 'remove', keyId: request.keyId, ...(trustRootLifetime ? { trustRootExpires: trustRootLifetime } : {}) }
            : { kind: 'renew', trustRootExpires: request.lifetime };
        const prepared = await prepareTrustRootChange({
          rootKeyId: found.activeRootKeyId, trustRootPath: pin.policy.trustRootPath, now, change, forbidden, minimumVersion: minimum,
        });
        const consequence = await this.consequence(pin, now, { trustRoot: signPreparedTrustRoot(prepared, armed.key) }, 'document');
        if (consequence.toFailed !== null) throw new AdminError(this.msg('admin.p2.notice.consequenceToFailed', { reason: dialogSafe(consequence.toFailed) }));

        const document = {
          path: pin.policy.trustRootPath, baseSha256: prepared.baseSha256, versionFrom: prepared.current.version,
          versionTo: prepared.payload.version, expiresAt: formatTimestamp(prepared.payload.expiresAt),
        };
        const common = { role: armed.role.role, keyName: armed.role.name, keyId: op.keyId, document, consequence, freshnessBlock: consequence.freshnessBlock, afterReset: this.resetPending };
        const lastApprover = request.kind === 'remove' && prepared.payload.approvers.length === 0;
        const summary: AdminSignSummary = request.kind === 'add'
          ? {
              ...common, action: 'add-approver', newKeyId: publicKey!.keyId, name, scopes: [...prepared.payload.approvers.find((entry) => entry.keyId === publicKey!.keyId)!.scopes],
              approverExpiresAt: formatTimestamp(prepared.payload.approvers.find((entry) => entry.keyId === publicKey!.keyId)!.expiresAt),
              replaces: prepared.replaces ? { name: prepared.replaces.name, scopes: [...prepared.replaces.scopes], expiresAt: formatTimestamp(prepared.replaces.expiresAt) } : null,
            }
          : request.kind === 'remove'
            ? { ...common, action: 'remove-approver', removedKeyId: request.keyId, name: prepared.current.approvers.find((entry) => entry.keyId === request.keyId)!.name, lastApprover }
            : { ...common, action: 'renew-trust-root', expiresFrom: formatTimestamp(prepared.current.expiresAt) };

        // The key may have moved or the pin changed while the work above ran.
        await this.requireSameKeyFile(armed);
        this.requireNoDialog();
        const confirmed = await this.ask(() => this.options.confirmSign(summary), false);
        if (!confirmed) {
          this.startCooldown();
          return { ok: false, message: this.msg('admin.err.signCancelled') };
        }
        if (op.generation !== this.generation) throw new AdminError(this.msg('admin.err.keyGone'));
        if (lastApprover) {
          this.requireNoDialog();
          const again = await this.ask(() => this.options.confirmLastApprover(), false);
          if (!again) {
            this.startCooldown();
            return { ok: false, message: this.msg('admin.err.signCancelled') };
          }
          if (op.generation !== this.generation) throw new AdminError(this.msg('admin.err.keyGone'));
        }

        const written = await commitTrustRoot(prepared, armed.key, { beforeWrite: async () => { await this.guardBeforeWrite('root', op, inputs); } });
        this.resetPending = false;
        let memoryWarning = false;
        try {
          await recordDocumentVersions(pin.memoryFile, { rootKeyId: found.activeRootKeyId, trustRoot: written.version });
        } catch {
          memoryWarning = true;
        }
        return { ok: true, version: written.version, path: written.path, needsTimestamp: pin.policy.recovery?.freshness !== undefined, memoryWarning };
      } catch (error) {
        return { ok: false, message: this.writeMessage(error) };
      }
    });
  }

  /** Discards this computer's memory of the organisation's document versions, after a native confirmation. */
  resetMemory(): Promise<AdminResetResult> {
    return this.serial(async () => {
      let refusal: string | null = null;
      try {
        this.requireNoDialog();
        const confirmed = await this.ask(() => this.options.confirmReset(), false);
        if (!confirmed) {
          this.startCooldown();
        } else {
          this.dropKey('reset');
          this.resetPending = true;
          await moveMemoryAside(this.memoryFile, this.now()).catch((error) => {
            if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
          });
        }
      } catch (error) {
        refusal = error instanceof AdminError ? error.message : this.msg('admin.err.moveFailed');
      }
      const status = await this.status();
      return refusal === null ? { ok: true, status } : { ok: false, message: refusal, status };
    });
  }

  dismissMemoryReset(): void {
    this.memoryReset = null;
  }
}
