// View model shared by the observation service, the Electron main process and the renderer.
// Self-contained on purpose: the renderer type-checks against this file without the engine or Node types.

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
  history:         HistoryEvent[];
  /** Earlier baselines kept for the retention period, newest first. */
  previousVersions: Array<{ digest: string; recordedAt: string; supersededAt: string | null; retained: boolean }>;
}

export type ActionResult =
  | { ok: true }
  | { ok: false; code: 'stale' | 'not-found' | 'unreadable'; message: string };

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
  onUpdate(listener: (view: ServiceView) => void):    () => void;
}
