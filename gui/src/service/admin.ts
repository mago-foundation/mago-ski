// Administration rack (docs/spec/gui-admin-rack-v1.md): the organisation pin, roles recognised by proof of
// possession, the armed key and the devices of the "Approve a Skill version" template. Plain Node, used only by the
// Electron main process: key material never leaves this module and never reaches the renderer.
import { randomBytes, sign, verify, type KeyObject } from 'node:crypto';
import { readlinkSync } from 'node:fs';
import { constants as fsConstants } from 'node:fs';
import { lstat, mkdir, open, readFile, realpath, rename } from 'node:fs/promises';
import path from 'node:path';
import { approveSkill } from '../../../src/admin.ts';
import { parseCertificate } from '../../../src/certificate.ts';
import { isInside, readRegularFile, realpathAllowingMissing, resolveOutside } from '../../../src/fs-safe.ts';
import { loadPrivateKeyBytes, type PrivateKeyInfo } from '../../../src/keys.ts';
import { scopeMatches } from '../../../src/names.ts';
import { loadPolicy, loadPolicyRoot, loadPolicyTrust, verifyWithPolicy, type Policy, type PolicyRootResult } from '../../../src/policy.ts';
import { requireDisplaySafeText } from '../../../src/root-events.ts';
import { addDuration, formatTimestamp } from '../../../src/time.ts';
import { collectSkillTree, SKILL_FILENAME, sha256Hex } from '../../../src/tree-digest.ts';
import type { TrustContextResult } from '../../../src/verify.ts';
import { skillNameFromSkillFile } from '../../../src/verify.ts';
import type {
  AdminActionResult, AdminArmResult, AdminCheckView, AdminInspectView, AdminLifetime, AdminPinView, AdminReviewSummary, AdminRoleView,
  AdminResetResult, AdminSignSummary, AdminStatusView,
} from './types.ts';

/** The only place the organisation pin is read from. No environment variable or setting redirects it. */
export const ORG_PIN_PATH = '/etc/mago-ski/policy.json';
export const ARM_IDLE_MS = 15 * 60 * 1000;
export const LIFETIMES: readonly AdminLifetime[] = ['30d', '90d', '180d'];
export const MAX_REASON = 1024;
export const DIALOG_TIMEOUT_MS = 120_000;
export const COOLDOWN_MS = 10_000;
export const DIALOG_SLOT_GRACE_MS = 5000;
export const MEMORY_FILE = 'admin-state.json';
const IDENTITY_CONTEXT = 'mago-ski gui identity v1';

const KEY_IN_SKILL = 'Skill 폴더 안에 있는 키는 쓸 수 없어요. 키를 Skill 밖으로 옮기세요.';
const KEY_GONE     = '키가 빠졌어요';
const NEED_REASON  = '이유에 글자나 숫자를 3개 이상 적으세요';
const KEY_SWAPPED = '키 파일이 바뀌었어요. 다시 불러오세요.';
const MEMORY_BUSY  = '이 컴퓨터의 관리 기록을 지금 읽을 수 없어요. 잠시 후 다시 시도하세요.';
const MAX_KEY_FILE_BYTES = 64 * 1024;
const READ_RETRY_MS = [50, 100, 200] as const;
const CHANGED      = '검토한 뒤 Skill이 바뀌었어요. 다시 검토하세요';

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
      return '실행 환경을 확인할 수 없어 조직 고정 정책을 쓰지 않아요';
    }
    const lines = text.trim().split(/\r?\n/u);
    if (lines.length !== 1 || lines[0]!.trim().split(/\s+/u).join(' ') !== '0 0 4294967295')
      return '이 실행 환경(사용자 네임스페이스)에서는 조직 고정 정책을 믿을 수 없어요';
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
  /** Called when an unreadable memory file was moved aside. */
  onMemoryReset?: (reset: { at: string; backup: string }) => void;
}

/** Moves the memory file aside under a name that says when; returns the new absolute path. Throws if it is not there. */
export async function moveMemoryAside(memoryFile: string, now: Date): Promise<string> {
  const backup = `${memoryFile}.unreadable-${now.toISOString().replace(/:/gu, '-')}`;
  await rename(memoryFile, backup);
  return path.resolve(backup);
}

export async function readPin(options: ReadPinOptions): Promise<PinState> {
  const file = mapPinPath(options.path, options.platform, options.readlink);
  try {
    await lstat(file);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return { kind: 'missing', path: file };
  }
  const problem = await pinOwnershipProblem(file, options.rootUid, options.trustedBase, { platform: options.platform, procDir: options.procDir });
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
  const memoryPolicy: Policy = { ...policy, statePath: options.memoryFile, decisionLogPath: null };
  try {
    await mkdir(path.dirname(options.memoryFile), { recursive: true, mode: 0o700 });
  } catch (error) {
    return { kind: 'invalid', path: file, reason: `이 컴퓨터의 기록을 저장하지 못했어요: ${(error as Error).message}` };
  }
  let moved = false;
  let retries = 0;
  for (;;) {
    // Root first, so the root events are recorded before the trust documents are judged against them.
    const root = await loadPolicyRoot(memoryPolicy, options.now, { recordVersions: true });
    const trust = await loadPolicyTrust(memoryPolicy, options.now, { recordVersions: true });
    const writeFailed = (!root.ok && root.stateError === 'write') ? root.reason : (!trust.ok && trust.stateError === 'write') ? trust.reason : null;
    if (writeFailed !== null) return { kind: 'invalid', path: file, reason: `이 컴퓨터의 기록을 저장하지 못했어요: ${writeFailed}` };
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
          return { kind: 'invalid', path: file, reason: `이 컴퓨터의 기록을 저장하지 못했어요: ${(error as Error).message}` };
      }
      continue;
    }
    if (unreadable && retries < READ_RETRY_MS.length) {
      await new Promise((resolve) => setTimeout(resolve, READ_RETRY_MS[retries]));
      retries += 1;
      continue;
    }
    if (corrupt || unreadable) return { kind: 'invalid', path: file, reason: MEMORY_BUSY };
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
  return text.replace(/[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Cn}\p{Zl}\p{Zp}]/gu,
    (c) => `⟨U+${c.codePointAt(0)!.toString(16).toUpperCase().padStart(4, '0')}⟩`);
}

/** A key load error as fixed text; the raw message may carry the key file's path. */
function keyLoadMessage(error: unknown): string {
  const message = error instanceof Error ? error.message : '';
  if (message.includes('Private key permissions')) return '키 파일 권한이 너무 넓어요 (chmod 600)';
  if (message.includes('not a valid PKCS#8 key') || message.includes('not Ed25519')) return 'Ed25519 개인 키가 아니에요';
  return '키 파일을 읽을 수 없어요';
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
  /** The GUI's user data folder; the rollback memory lives here. */
  stateDir: string;
  /** Folders a key must not live in: discovery roots, discovered Skill folders and the host policy's skill_dirs. */
  discoveryRoots: () => string[];
  skillFolders:   () => string[];
  hostSkillDirs:  () => string[];
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
      onMemoryReset: (reset) => { this.memoryReset = reset; },
    });
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
    if (Date.now() < this.cooldownUntil) throw new AdminError('잠시 후 다시 시도하세요');
    if (this.dialogsOpen > 0) throw new AdminError('다른 확인 창이 열려 있어요');
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
        return { ok: false, reason: keyLoadMessage(error) };
      }
      if (await this.keyInsideSkills(canonical, pin)) return { ok: false, reason: KEY_IN_SKILL, keyId: key.keyId };
      const { view, publicKey } = roleOf(pin, key, this.now());
      if (view.role === 'none' || !publicKey) return { ok: false, reason: view.note ?? 'this key holds no role in the organisation', keyId: key.keyId };
      if (!proveIdentity(pin, key, publicKey)) return { ok: false, reason: 'the key could not prove possession: it is not the private half of the key the documents name', keyId: key.keyId };
      if (generation !== this.generation) return { ok: false, reason: KEY_GONE };
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
      throw new AdminError(KEY_SWAPPED);
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
    if (!armed || op.generation !== this.generation) throw new AdminError(KEY_GONE);
    const pin = await this.pin();
    if (op.generation !== this.generation) throw new AdminError(KEY_GONE);
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
        if (!first) throw new AdminError('승인자 키를 먼저 불러오세요');
        const op = { keyId: first.key.keyId, generation: this.generation };
        await this.current('approver', op);
        const skill = this.skill(instanceId);
        let read;
        try {
          read = await this.readSkill(skill.path);
        } catch (error) {
          throw new AdminError(safeMessage(error, 'Skill을 읽을 수 없어요. 다시 시도하세요.'));
        }
        const summary: AdminReviewSummary = { skillName: read.name, skillPath: skill.path, digest: read.tree.digest, files: read.tree.files.length };
        const confirmed = await this.ask(() => this.options.confirmReview(summary), false);
        if (!confirmed || op.generation !== this.generation) {
          this.startCooldown();
          return { ok: false, message: '검토를 기록하지 않았어요' };
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
        if (!first) throw new AdminError('승인자 키를 먼저 불러오세요');
        const op = { keyId: first.key.keyId, generation: this.generation };
        if (first.role.role !== 'approver') throw new AdminError(`this needs the approver role; the armed key is ${first.role.role}`);
        this.requireNoDialog();

        const recordKey = `${op.keyId}|${op.generation}|${instanceId}`;
        const record = this.reviews.get(recordKey);
        if (!record || record.digest !== digest) throw new AdminError('먼저 이 정확한 버전을 검토하세요');

        const text = this.checkReason(reason);
        if (!LIFETIMES.includes(lifetime)) throw new AdminError('choose a lifetime of 30, 90 or 180 days');
        const now = this.now();
        const expires = addDuration(now, lifetime, 'certificate lifetime');

        const { pin, armed } = await this.current('approver', op);
        // The expiry as the re-check has just refreshed it, not the one seen when the key was armed.
        const keyExpiry = armed.role.expiresAt;
        if (keyExpiry && expires > new Date(keyExpiry))
          throw new AdminError(`이 기간은 승인자 키의 만료(${keyExpiry})를 넘어요. 더 짧게 고르세요.`);
        const scopes = armed.role.scopes ?? [];
        if (!scopes.some((scope) => scopeMatches(scope, record.name)))
          throw new AdminError(`범위(${scopes.join(', ')})가 Skill 이름 "${record.name}"을 포함하지 않아요`);
        const skill = this.skill(instanceId);
        try {
          await resolveOutside(armed.keyPath, skill.path, 'Approver private key');
        } catch {
          throw new AdminError(KEY_IN_SKILL);
        }
        if (await this.keyInsideSkills(armed.keyPath, pin)) throw new AdminError(KEY_IN_SKILL);
        await this.requireSameKeyFile(armed);

        let read;
        try {
          read = await this.readSkill(skill.path);
        } catch {
          throw new AdminError(CHANGED);
        }
        if (read.tree.digest !== record.digest || read.name !== record.name) throw new AdminError(CHANGED);

        // Claim the record before the dialog, so a second approve cannot use it while this one waits for the human.
        this.reviews.delete(recordKey);
        const summary: AdminSignSummary = {
          action: 'approve', skillName: read.name, skillPath: skill.path, reviewedDigest: record.digest, digest: read.tree.digest,
          lifetime, expiresAt: formatTimestamp(expires), reason: text, role: armed.role.role, keyName: armed.role.name, keyId: op.keyId,
        };
        const confirmed = await this.ask(() => this.options.confirmSign(summary), false);
        if (!confirmed) {
          if (op.generation === this.generation) this.reviews.set(recordKey, record);
          this.startCooldown();
          return { ok: false, message: '서명을 취소했어요' };
        }
        if (op.generation !== this.generation) throw new AdminError(KEY_GONE);

        const dir = pin.policy.certificateDirs[0];
        try {
          const issued = await approveSkill({
            skillDir: skill.path, approverKey: armed.key, now, expires: lifetime, reason: text,
            expectDigest: record.digest, expectName: record.name, ...(dir ? { outDir: dir } : {}),
            beforeSign: async (info) => {
              await this.options.hooks?.beforeSign?.();
              // Last look before the file is written: the key must still be this generation's and still hold its role.
              const latest = await this.current('approver', op);
              const latestScopes = latest.armed.role.scopes ?? [];
              if (!latestScopes.some((scope) => scopeMatches(scope, info.skillName)))
                throw new AdminError(`범위(${latestScopes.join(', ')})가 Skill 이름 "${info.skillName}"을 포함하지 않아요`);
              if (op.generation !== this.generation) throw new AdminError(KEY_GONE);
              if (await this.keyInsideSkills(latest.armed.keyPath, latest.pin)) throw new AdminError(KEY_IN_SKILL);
            },
          });
          return { ok: true, certificateId: issued.certificateId, certificatePath: issued.path, digest: issued.digest, expiresAt: formatTimestamp(issued.expiresAt) };
        } catch (error) {
          if (error instanceof AdminError) throw error;
          throw new AdminError(safeMessage(error, '서명하지 못했어요. Skill을 다시 검토하세요.'));
        }
      } catch (error) {
        return { ok: false, message: (error as Error).message };
      }
    });
  }

  /** Trim; at most 1024 units; display-safe; and real letters or digits, not fillers. */
  private checkReason(reason: string): string {
    const text = reason.trim();
    if (text === '') throw new AdminError(NEED_REASON);
    if (text.length > MAX_REASON) throw new AdminError('이유는 1024자 이하여야 해요');
    requireDisplaySafeText(text, 'Reason', MAX_REASON);
    const real = [...text].filter((c) => /[\p{L}\p{N}]/u.test(c) && !'ᅟᅠㅤﾠ⠀'.includes(c));
    if (real.length < 3) throw new AdminError(NEED_REASON);
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
          await moveMemoryAside(this.memoryFile, this.now()).catch((error) => {
            if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
          });
        }
      } catch (error) {
        refusal = error instanceof AdminError ? error.message : '기록을 옮기지 못했어요';
      }
      const status = await this.status();
      return refusal === null ? { ok: true, status } : { ok: false, message: refusal, status };
    });
  }

  dismissMemoryReset(): void {
    this.memoryReset = null;
  }
}
