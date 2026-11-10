// View model shared by the observation service, the Electron main process and the renderer.
// Self-contained on purpose: the renderer type-checks against this file without the engine or Node types.

import type { Lang } from '../i18n/messages.ts';
/** Mirrors the engine's VERDICTS (src/verify.ts); service.ts checks the two stay equal. */
export type Verdict =
  | 'VERIFIED' | 'REVOKED' | 'UNAPPROVED_CHANGE' | 'EXPIRED' | 'UNTRUSTED_SIGNER' | 'UNVERIFIABLE' | 'NO_CERTIFICATE';

/** One covered file as the engine hashed it. */
export interface FileRecord {
  path:   string;
  size:   number;
  sha256: string;
  exec:   boolean;
}

/** How much of a version's file content the GUI kept, outside the Skill directory. */
export interface SnapshotCoverage {
  stored:   number;
  total:    number;
  complete: boolean;
}

/** A remembered version: the comparison start point. Not an approval. */
export interface Baseline {
  digest:     string;
  recordedAt: string;
  reason:     'first-seen' | 'remembered';
  files:      FileRecord[];
  coverage:   SnapshotCoverage;
  /** When another version replaced it as the baseline; retention counts from here. */
  supersededAt?: string;
}

/** What the last complete check saw on disk. */
export interface Observation {
  digest:     string;
  observedAt: string;
  files:      FileRecord[];
  excluded:   string[];
  totalBytes: number;
  coverage:   SnapshotCoverage;
}

/** Relation of the current bytes to the remembered version. Independent of the PKI verdict. */
export type ObservationState = 'new' | 'unchanged' | 'changed' | 'reviewed' | 'unreadable' | 'missing';

export interface DiscoveryRootView {
  id:      string;
  path:    string;
  label:   string;
  origin:  'default' | 'user';
  exists:  boolean;
  error:   string | null;
  /** Directories at the discovery depth limit; Skills below them were not checked. */
  tooDeep: string[];
}

export interface PkiResultView {
  verdict:       Verdict;
  reason:        string;
  digest:        string | null;
  certificateId: string | null;
  approverKeyId: string | null;
  checkedAt:     string;
}

export interface InstanceView {
  id:              string;
  name:            string;
  path:            string;
  rootId:          string;
  rootLabel:       string;
  state:           ObservationState;
  error:           string | null;
  firstSeen:       string;
  lastChecked:     string | null;
  currentDigest:   string | null;
  baselineDigest:  string | null;
  baselineAt:      string | null;
  changedFiles:    number;
  pki:             PkiResultView | null;
  /** False when the PKI result is about other bytes than `currentDigest` (the Skill changed between the two reads). */
  pkiCurrent:      boolean;
}

/** One LED on the inspection meter: one completed check of every Skill. */
export interface CheckEvent {
  at:      string;
  outcome: 'same' | 'new' | 'changed' | 'error';
  skills:  number;
}

export interface HistoryEvent {
  at:         string;
  kind:       'first-seen' | 'new-skill' | 'changed' | 'reviewed' | 'remembered' | 'missing' | 'returned' | 'unreadable' | 'history-reset';
  instanceId: string;
  name:       string;
  digest:     string | null;
  detail:     string | null;
}

export type PolicyView =
  | { kind: 'none'; path: string | null; reason: string | null }
  | { kind: 'error'; path: string; reason: string }
  | {
      kind:      'loaded';
      path:      string;
      mode:      'shadow' | 'enforce';
      trustOk:   boolean;
      trustNote: string | null;
    };

export interface HostDecisionView {
  timestamp: string;
  action:    string;
  skill:     string;
  verdict:   string;
  event:     string;
}

export interface HostView {
  name:             'Pi';
  agentDir:         string;
  present:          boolean;
  /** Whether Pi's settings list the mago-ski package; null when the settings could not be read. */
  extensionListed:  boolean | null;
  policy:           PolicyView;
  /** Pi reads the policy once per session. */
  appliesAt:        'next-session';
  recentDecisions:  HostDecisionView[];
}

export interface Prefs {
  notify:        'off' | 'grouped' | 'immediate';
  retainContent: boolean;
  retentionDays: number;
}

export interface ServiceView {
  service: {
    status:            'starting' | 'watching' | 'checking' | 'error';
    lastCheckAt:       string | null;
    lastError:         string | null;
    platformSupported: boolean;
    platform:          string;
    dataDir:           string;
    /** Set when earlier history was lost; baselines recorded since are not continuous with it. */
    historyReset:      HistoryReset | null;
  };
  roots:     DiscoveryRootView[];
  instances: InstanceView[];
  checks:    CheckEvent[];
  history:   HistoryEvent[];
  host:      HostView;
  prefs:     Prefs;
}

export interface HistoryReset {
  at:     string;
  reason: string;
  /** Where the unreadable history file was moved, if there was one. */
  backup: string | null;
}

export interface DiffLine {
  kind:  'same' | 'add' | 'del' | 'gap';
  old:   number | null;
  new:   number | null;
  text:  string;
}

export interface FileChangeView {
  path:      string;
  change:    'added' | 'deleted' | 'modified' | 'mode-changed';
  execBefore: boolean | null;
  execAfter:  boolean | null;
  sections:   string[];
  /** Line diff of retained text, or null with a note saying why not. */
  lines:      DiffLine[] | null;
  note:       string | null;
}

export interface ChangeView {
  baselineDigest:  string;
  currentDigest:   string;
  /** False when the remembered or current content was not retained: only file metadata can be compared. */
  contentRetained: boolean;
  /** Why content could not be compared, when `contentRetained` is false. */
  contentNote:     string | null;
  files:           FileChangeView[];
  addedOrigins:    string[];
  removedOrigins:  string[];
  analysisComplete: boolean;
  evidenceNote:    string;
  truncated:       boolean;
}

export interface InstanceDetail {
  instance:        InstanceView;
  change:          ChangeView | null;
  /** Copyable `mago-ski approve` command pinned to the current digest; only when an org policy is loaded. */
  approveCommand:  string | null;
  /**
   * How much of this version the screen showed: every changed file as text, only part of it, or no diff at all
   * (a new or unchanged Skill). The approve command never claims a review the screen could not have shown.
   */
  approveScope:    'full-diff' | 'partial-diff' | 'no-diff' | null;
  history:         HistoryEvent[];
  /** Earlier baselines kept for the retention period, newest first. */
  previousVersions: Array<{ digest: string; recordedAt: string; supersededAt: string | null; retained: boolean }>;
}

export type ActionResult =
  | { ok: true }
  | { ok: false; code: 'stale' | 'not-found' | 'unreadable'; message: string };

// ------------------------------------------------------------------ administration rack (docs/spec/gui-admin-rack-v1.md)

export type AdminRole = 'root' | 'approver' | 'recovery' | 'timestamp' | 'none';
export type AdminLifetime = '30d' | '90d' | '180d';

/** The organisation pin (/etc/mago-ski/policy.json) as the administration rack sees it. */
export interface AdminPinView {
  kind:            'missing' | 'unprotected' | 'invalid' | 'loaded';
  path:            string;
  /** Why the pin is not usable, or a problem with its root event log. */
  reason:          string | null;
  rootKeyId:       string | null;
  /** The root key now in force after root events; null when unknown or revoked. */
  activeRootKeyId: string | null;
  mode:            'shadow' | 'enforce' | null;
  trustOk:         boolean;
  trustNote:       string | null;
}

/** What the armed key is. Never carries key material. */
export interface AdminRoleView {
  role:      AdminRole;
  keyId:     string;
  name:      string | null;
  scopes:    string[] | null;
  expiresAt: string | null;
  note:      string | null;
}

export interface AdminStatusView {
  pin:               AdminPinView;
  /** True when the observation rack reads another policy than the pin (Pi's own). */
  hostPolicyDiffers: boolean;
  armed:             AdminRoleView | null;
  idleMinutes:       number;
  /** Set when this computer's admin memory was unreadable and was moved aside; shown until dismissed. */
  memoryReset:       { at: string; backup: string } | null;
  /** The organisation's documents are older than this computer's memory of them. */
  rollback:          boolean;
}

/** What the review dialog (native, main process) shows. */
export interface AdminReviewSummary {
  skillName: string;
  skillPath: string;
  digest:    string;
  files:     number;
}

export type AdminApproverLifetime  = '90d' | '180d' | '365d';
export type AdminTrustRootLifetime = '180d' | '365d';
export type AdminListLifetime      = '7d' | '30d';
export type AdminTimestampLifetime = '6h' | '12h' | '24h';

/** A verdict as a consequence line shows it: `BLOCKED_UNTIL_TIMESTAMP` only on the `to` side of a freshness organisation. */
export type AdminVerdictTo = Verdict | 'BLOCKED_UNTIL_TIMESTAMP';

/** What a root or timestamp write does to the Skills this computer can see, computed with the hosts' own loader. */
export interface AdminConsequence {
  /** Skills in every configured folder (a folder too deep to search counts as one). */
  skills:         number;
  /** Skills whose verdict changes: `from !== after`. */
  changed:        number;
  /** At most 5 changed Skills, sorted by name. `to` is the verdict hosts would give right after signing. */
  lines:          Array<{ name: string; from: Verdict; to: AdminVerdictTo; after: Verdict }>;
  /** Folders too deep to check. */
  tooDeep:        number;
  freshnessBlock: boolean;
  /** Why the current documents do not verify (then there are no lines), or null. */
  fromFailed:     string | null;
  /** Why the documents after signing would not verify for a reason a timestamp does not fix, or null. */
  toFailed:       string | null;
  /** Verdict counts of the Skills after signing (used by the timestamp dialog). */
  afterCounts:    Partial<Record<Verdict, number>>;
}

interface AdminSignCommon {
  role:     AdminRole;
  keyName:  string | null;
  keyId:    string;
  document: { path: string; baseSha256: string | null; versionFrom: number | null; versionTo: number; expiresAt: string };
  consequence:    AdminConsequence;
  freshnessBlock: boolean;
  /** The first root or timestamp signature since this computer's memory was reset. */
  afterReset:     boolean;
}

/** What the signing dialog (native, main process) shows. */
export type AdminSignSummary =
  | {
      action:         'approve';
      skillName:      string;
      skillPath:      string;
      reviewedDigest: string;
      digest:         string;
      lifetime:       AdminLifetime;
      expiresAt:      string;
      reason:         string;
      role:           AdminRole;
      keyName:        string | null;
      keyId:          string;
    }
  | (AdminSignCommon & { action: 'add-approver'; newKeyId: string; name: string; scopes: string[]; approverExpiresAt: string;
      replaces: { name: string; scopes: string[]; expiresAt: string } | null })
  | (AdminSignCommon & { action: 'remove-approver'; removedKeyId: string; name: string; lastApprover: boolean })
  | (AdminSignCommon & { action: 'renew-trust-root'; expiresFrom: string })
  | (AdminSignCommon & { action: 'revoke-key'; targetKeyId: string; label: string; reason: string;
      /** Certificates naming the key (found in the configured folders), only for a key chosen with the picker; null for an approver. */
      certificates: number | null })
  | (AdminSignCommon & { action: 'revoke-digest'; digest: string; skillName: string; reason: string })
  | (AdminSignCommon & { action: 'refresh-revocations'; expiresFrom: string })
  | (AdminSignCommon & { action: 'sign-timestamp';
      documents: Record<'rootEvents' | 'trustRoot' | 'revocations', { sha256: string; counter: number; firstSeen: boolean }>;
      previousByOtherKey: { keyId: string; version: number } | null });

export interface AdminApproverView { keyId: string; name: string; scopes: string[]; expiresAt: string; expired: boolean; forbidden: string | null }

export type AdminTrustRootView =
  | { ok: true; path: string; sha256: string; version: number; expiresAt: string; expired: boolean; approvers: AdminApproverView[];
      stale: boolean; signedByPreviousRoot: boolean; note: string | null }
  | { ok: false; message: string; signedByPreviousRoot: boolean };

export interface AdminRevocationEntry { reason: string; revokedAt: string }

export type AdminRevocationsView =
  | { ok: true; path: string; sha256: string; version: number; expiresAt: string; expired: boolean;
      keys: Array<AdminRevocationEntry & { keyId: string }>; digests: Array<AdminRevocationEntry & { digest: string }>;
      stale: boolean; signedByPreviousRoot: boolean }
  | { ok: false; message: string; signedByPreviousRoot: boolean };

export type AdminTimestampView =
  | { ok: true; configured: false }
  | { ok: true; configured: true; path: string; keyId: string | null; version: number | null; expiresAt: string | null; readable: boolean;
      /** The timestamp names the documents now on disk (the host's own check, memory included). */
      matches: boolean; maxLifetime: string;
      /** The lifetimes (6h, 12h, 24h) within `max_lifetime`; empty means the template is disabled. */
      lifetimes: AdminTimestampLifetime[];
      /** Why signing is disabled before any dialog (revoked root, no allowed lifetime), or null. */
      disabled: string | null }
  | { ok: false; message: string };

/** One discovered Skill in TARGET: its tree digest (or why it could not be read) and whether the armed key reviewed that digest. */
export interface AdminRevocationSkill { instanceId: string; name: string; digest: string | null; reviewed: boolean; error: string | null }

/** What REVOKE offers from the documents and the review records. `other` (a key chosen with the picker) is a request, not a listed target. */
export type AdminRevocationTarget =
  | { kind: 'key'; keyId: string; label: string }
  | { kind: 'digest'; digest: string; skillName: string; instanceId: string };

export type AdminRevokeRequest =
  | { kind: 'key'; keyId: string }
  | { kind: 'digest'; digest: string; instanceId: string }
  | { kind: 'other' };

export interface AdminVerifyAllView {
  skills:            number;
  counts:            Partial<Record<Verdict, number>>;
  trustOk:           boolean;
  trustNote:         string | null;
  /** The pin has `freshness` and the timestamp on disk does not name the documents now on disk. */
  timestampMismatch: boolean;
}

export type AdminWriteResult =
  | { ok: true; version: number; path: string; needsTimestamp: boolean; memoryWarning: boolean }
  | { ok: false; message: string };

export type AdminArmResult =
  | { ok: true; role: AdminRoleView }
  | { ok: false; reason: string; keyId?: string }
  | { ok: false; reason: 'cancelled' };

export type AdminResetResult =
  | { ok: true; status: AdminStatusView }
  | { ok: false; message: string; status: AdminStatusView };

export interface AdminInspectView {
  instanceId:  string;
  name:        string;
  path:        string;
  digest:      string;
  totalBytes:  number;
  files:       FileRecord[];
  excluded:    string[];
  certificate: { source: string; id: string; digest: string; approverKeyId: string; issuedAt: string; expiresAt: string; reason: string } | null;
  verdict:     { verdict: Verdict; reason: string } | null;
  /** True when the armed approver already reviewed this exact digest (a native dialog recorded it). */
  inspected:   boolean;
  /** The verdict was computed for different bytes than the digest shown; the verdict must not be shown. */
  verdictStale: boolean;
}

export type AdminActionResult =
  | { ok: true; certificateId?: string; certificatePath?: string; digest?: string; expiresAt?: string }
  | { ok: false; message: string };

export interface AdminCheckView {
  verdict:   Verdict | null;
  reason:    string;
  trustOk:   boolean;
  trustNote: string | null;
}

/** The narrow API the preload script exposes to the renderer as `window.magoSki`. */
export interface RendererApi {
  getView():                                          Promise<ServiceView>;
  checkNow():                                         Promise<ServiceView>;
  getDetail(instanceId: string):                      Promise<InstanceDetail | null>;
  markReviewed(instanceId: string, digest: string):   Promise<ActionResult>;
  rememberVersion(instanceId: string, digest: string): Promise<ActionResult>;
  addRoot():                                          Promise<ServiceView>;
  removeRoot(rootId: string):                         Promise<ServiceView>;
  setPrefs(prefs: Partial<Prefs>):                    Promise<ServiceView>;
  copyText(text: string):                             Promise<void>;
  dismissHistoryReset():                              Promise<ServiceView>;
  /** The language in effect: the stored setting, or the system locale. */
  getLang():                                          Promise<Lang>;
  /** Stores the language and returns it. Only 'ko' and 'en' are accepted. */
  setLang(lang: Lang):                                Promise<Lang>;
  onUpdate(listener: (view: ServiceView) => void):    () => void;
  admin: {
    status():                                                          Promise<AdminStatusView>;
    /** Opens the key dialog in the main process; the renderer never names a file. */
    arm():                                                             Promise<AdminArmResult>;
    disarm():                                                          Promise<AdminStatusView>;
    inspect(instanceId: string):                                       Promise<AdminInspectView>;
    /** Opens a native confirmation in the main process; only its Reviewed (검토함) answer records the review. */
    review(instanceId: string):                                        Promise<AdminActionResult>;
    approve(instanceId: string, digest: string, lifetime: AdminLifetime, reason: string): Promise<AdminActionResult>;
    check(instanceId: string):                                         Promise<AdminCheckView>;
    /** Opens a native confirmation, then moves this computer's admin memory aside. */
    resetMemory():                                                     Promise<AdminResetResult>;
    dismissMemoryReset():                                              Promise<AdminStatusView>;
    trustRoot():                                                       Promise<AdminTrustRootView>;
    /** Opens the public-key picker and the native signing dialog in the main process. */
    addApprover(o: { name: string; scopes: string[]; lifetime: AdminApproverLifetime; trustRootLifetime?: AdminTrustRootLifetime }): Promise<AdminWriteResult>;
    removeApprover(o: { keyId: string; trustRootLifetime?: AdminTrustRootLifetime }): Promise<AdminWriteResult>;
    renewTrustRoot(o: { lifetime: AdminTrustRootLifetime }):           Promise<AdminWriteResult>;
    verifyAll():                                                       Promise<AdminVerifyAllView>;
    revocations():                                                     Promise<AdminRevocationsView>;
    /** The discovered Skills for TARGET; the digest is offered for revocation only once reviewed. */
    revocationSkills():                                                Promise<AdminRevocationSkill[]>;
    revocationTargets():                                               Promise<AdminRevocationTarget[]>;
    /** Opens the native signing dialog (for `other`, the public-key picker first); writes only after it is confirmed. */
    revoke(o: { target: AdminRevokeRequest; reason: string; lifetime: AdminListLifetime }): Promise<AdminWriteResult>;
    refreshRevocations(o: { lifetime: AdminListLifetime }):            Promise<AdminWriteResult>;
    timestamp():                                                       Promise<AdminTimestampView>;
    signTimestamp(o: { lifetime: AdminTimestampLifetime }):            Promise<AdminWriteResult>;
  };
}
