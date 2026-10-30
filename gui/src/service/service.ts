// The local observation service: discovers installed Skills, remembers versions, records changes and
// projects the engine's PKI verdicts. It reuses the engine for every digest, diff and verification.
import { randomUUID } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { watch, type FSWatcher } from 'node:fs';
import { chmod, mkdir, mkdtemp, realpath, rm, stat, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { diffSkillTrees } from '../../../src/diff.ts';
import { DiscoveryBudgetError, findSkillDirs, verifyWithPolicy } from '../../../src/policy.ts';
import { collectSkillTree, type SkillTree } from '../../../src/tree-digest.ts';
import { resolveSkillName, unverifiable, VERDICTS, type VerificationResult } from '../../../src/verify.ts';
import { defaultRoots, readHost, type HostSnapshot } from './host.ts';
import { Store, type DiscoveryRoot, type PersistedState, type SkillInstance } from './store.ts';
import { diffLines } from './textdiff.ts';
import type {
  ActionResult, Baseline, ChangeView, CheckEvent, DiscoveryRootView, FileChangeView, FileRecord, HistoryEvent,
  InstanceDetail, InstanceView, Observation, ObservationState, PkiResultView, Prefs, ServiceView, SnapshotCoverage, Verdict,
} from './types.ts';

// Compile-time check: the GUI's Verdict type lists exactly the engine's verdicts.
type Same<A, B> = [A] extends [B] ? ([B] extends [A] ? true : false) : false;
const verdictsMatch: Same<Verdict, (typeof VERDICTS)[number]> = true;
void verdictsMatch;

/** Files larger than this are not retained; the version is then marked as not fully retained. */
export const MAX_RETAINED_FILE_BYTES = 4 * 1024 * 1024;
const MAX_TEXT_DIFF_BYTES = 512 * 1024;
const MAX_HISTORY = 500;
const MAX_CHECKS = 48;
const DAY_MS = 86_400_000;

export interface ServiceOptions {
  dataDir:      string;
  env?:         NodeJS.ProcessEnv;
  home?:        string;
  now?:         () => Date;
  /** Quiet period after a file-system event before checking; installers write files in bursts. */
  debounceMs?:  number;
  /** Full re-check interval, to cover missed watch events. 0 disables it. */
  intervalMs?:  number;
  watch?:       boolean;
}

interface RootScan {
  view:    DiscoveryRootView;
  dirs:    string[];
  ok:      boolean;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function toFileRecords(tree: SkillTree): FileRecord[] {
  return tree.files.map(({ path: p, size, sha256, exec }) => ({ path: p, size, sha256, exec }));
}

function shellQuote(value: string): string {
  return /^[A-Za-z0-9_./~:@%+=-]+$/u.test(value) ? value : `'${value.replaceAll("'", `'\\''`)}'`;
}

function decodeText(bytes: Buffer): string | null {
  if (bytes.length > MAX_TEXT_DIFF_BYTES || bytes.includes(0)) return null;
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
}

/** A directory name shown when SKILL.md gives no valid name: control and markup characters removed, length capped. */
export function displayName(name: string): string {
  const clean = name.replace(/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2066-\u2069<>&]/gu, '').slice(0, 100);
  return clean || '(unnamed)';
}

const INVISIBLE = /[\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/u;

export function observationState(instance: SkillInstance): ObservationState {
  if (instance.presence === 'missing') return 'missing';
  if (instance.presence === 'unreadable' || !instance.current || !instance.baseline) return 'unreadable';
  if (instance.current.digest === instance.baseline.digest) return instance.isNew ? 'new' : 'unchanged';
  if (instance.reviewedDigest === instance.current.digest) return 'reviewed';
  return 'changed';
}

function countChangedFiles(before: FileRecord[], after: FileRecord[]): number {
  const map = new Map(before.map((f) => [f.path, f]));
  let changed = 0;
  for (const file of after) {
    const old = map.get(file.path);
    if (!old || old.sha256 !== file.sha256 || old.exec !== file.exec) changed += 1;
    map.delete(file.path);
  }
  return changed + map.size;
}

export class ObservationService extends EventEmitter {
  readonly store: Store;
  private readonly env:        NodeJS.ProcessEnv;
  private readonly home:       string;
  private readonly now:        () => Date;
  private readonly debounceMs: number;
  private readonly intervalMs: number;
  private readonly watchFiles: boolean;

  private state:     PersistedState | null = null;
  private host:      HostSnapshot | null = null;
  private roots:     DiscoveryRootView[] = [];
  private pki        = new Map<string, PkiResultView>();
  private status:    ServiceView['service']['status'] = 'starting';
  private lastError: string | null = null;
  private lastCheckAt: string | null = null;

  /** Every check, user action, detail read and cleanup runs here one at a time, so none sees another half-done. */
  private queue:     Promise<unknown> = Promise.resolve();
  private pendingCheck: Promise<void> | null = null;
  private timer:     NodeJS.Timeout | null = null;
  private interval:  NodeJS.Timeout | null = null;
  private watchers   = new Map<string, FSWatcher>();
  private stopped    = false;

  constructor(options: ServiceOptions) {
    super();
    this.store      = new Store(options.dataDir);
    this.env        = options.env ?? process.env;
    this.home       = options.home ?? os.homedir();
    this.now        = options.now ?? (() => new Date());
    this.debounceMs = options.debounceMs ?? 1_200;
    this.intervalMs = options.intervalMs ?? 60_000;
    this.watchFiles = options.watch ?? true;
  }

  private get s(): PersistedState {
    if (!this.state) throw new Error('service not started');
    return this.state;
  }

  private serial<T>(task: () => Promise<T>): Promise<T> {
    const run = this.queue.then(task, task);
    this.queue = run.catch(() => {});
    return run;
  }

  async start(): Promise<void> {
    await this.store.init();
    const { state, lost } = await this.store.load();
    this.state = state;
    if (lost) {
      // Baselines recorded from here on are new first sightings, not continuity with the lost history.
      const at = this.now().toISOString();
      state.historyReset = { at, reason: lost.reason, backup: lost.backup };
      this.record({ at, kind: 'history-reset', instanceId: '', name: '', digest: null, detail: lost.reason });
    }
    // Default roots are re-derived each start, so a changed PI_CODING_AGENT_DIR is picked up.
    const userRoots = this.s.roots.filter((r) => r.origin === 'user');
    this.s.roots = [...defaultRoots(this.env, this.home), ...userRoots];
    await this.check();
    if (this.intervalMs > 0) this.interval = setInterval(() => void this.check().catch(() => {}), this.intervalMs);
  }

  async stop(): Promise<void> {
    this.stopped = true;
    if (this.timer) clearTimeout(this.timer);
    if (this.interval) clearInterval(this.interval);
    for (const watcher of this.watchers.values()) watcher.close();
    this.watchers.clear();
    await this.queue;
  }

  // ---------------------------------------------------------------- checking

  /** Queues one full check; requests made before it starts share it, so a burst of events runs at most one more. */
  check(): Promise<void> {
    if (this.pendingCheck) return this.pendingCheck;
    const run = this.serial(async () => {
      this.pendingCheck = null;
      if (!this.stopped) await this.runCheck();
    });
    this.pendingCheck = run;
    return run;
  }

  private schedule(): void {
    if (this.stopped) return;
    if (this.timer) clearTimeout(this.timer);
    this.timer = setTimeout(() => { this.timer = null; void this.check().catch(() => {}); }, this.debounceMs);
  }

  private async scanRoot(root: DiscoveryRoot): Promise<RootScan> {
    const view: DiscoveryRootView = { id: root.id, path: root.path, label: root.label, origin: root.origin, exists: false, error: null, tooDeep: [] };
    try {
      if (!(await stat(root.path)).isDirectory()) {
        view.error = 'not a directory';
        return { view, dirs: [], ok: false };
      }
      view.exists = true;
    } catch (error) {
      // A missing default root is normal: nothing is installed there yet.
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return { view, dirs: [], ok: true };
      view.error = errorMessage(error);
      return { view, dirs: [], ok: false };
    }
    try {
      const found = await findSkillDirs([root.path]);
      view.tooDeep = found.tooDeep;
      return { view, dirs: found.skillDirs, ok: true };
    } catch (error) {
      view.error = error instanceof DiscoveryBudgetError ? `${error.message}` : errorMessage(error);
      return { view, dirs: [], ok: false };
    }
  }

  private async runCheck(): Promise<void> {
    const state = this.s;
    const now = this.now();
    const at = now.toISOString();
    // After lost history, Skills are shown as new (to be looked at again), never as quietly unchanged.
    const onboarding = state.onboardedAt === null && state.historyReset === null;
    // A fixed list for this run: indices below must keep pointing at the roots that were scanned.
    const roots = [...state.roots];
    this.status = 'checking';
    this.emitUpdate();

    try {
      this.host = await readHost(this.env, this.home, now);
      const scans = await Promise.all(roots.map((root) => this.scanRoot(root)));
      this.roots = scans.map((scan) => scan.view);
      this.syncWatchers();

      const seen = new Set<string>();
      let outcome: CheckEvent['outcome'] = 'same';
      const raise = (next: CheckEvent['outcome']) => {
        const rank = { same: 0, new: 1, changed: 2, error: 3 } as const;
        if (rank[next] > rank[outcome]) outcome = next;
      };
      const changedNow: SkillInstance[] = [];

      for (const [index, scan] of scans.entries()) {
        const root = roots[index]!;
        for (const dir of scan.dirs) {
          let realPath: string;
          try {
            realPath = await realpath(dir);
          } catch {
            realPath = path.resolve(dir);
          }
          if (seen.has(realPath)) continue;
          seen.add(realPath);
          const result = await this.observe(root, dir, realPath, at, onboarding);
          if (result === 'changed') changedNow.push(this.byRealPath(realPath)!);
          raise(result);
        }
      }

      // Installations under roots that were fully scanned but not found again are missing.
      const scannedRoots = new Set(scans.filter((scan) => scan.ok).map((scan) => scan.view.id));
      for (const instance of state.instances) {
        if (seen.has(instance.realPath) || !scannedRoots.has(instance.rootId) || instance.presence === 'missing') continue;
        instance.presence = 'missing';
        this.record({ at, kind: 'missing', instanceId: instance.id, name: instance.name, digest: instance.current?.digest ?? null, detail: null });
      }
      if (scans.some((scan) => !scan.ok)) raise('error');

      await this.verifyAll(now);
      state.checks = [...state.checks, { at, outcome, skills: seen.size }].slice(-MAX_CHECKS);
      state.onboardedAt ??= at;
      this.prune(now);
      await this.store.save(state);
      await this.collectGarbage();
      this.lastCheckAt = at;
      this.lastError = null;
      this.status = 'watching';
      if (changedNow.length > 0) this.emit('changes', changedNow.map((instance) => this.instanceView(instance)));
    } catch (error) {
      this.status = 'error';
      this.lastError = errorMessage(error);
    }
    this.emitUpdate();
  }

  private byRealPath(realPath: string): SkillInstance | undefined {
    return this.s.instances.find((instance) => instance.realPath === realPath);
  }

  /** True when nothing more can be retained: copying is off, or every copy recorded as kept is present. */
  private async coverageIntact(version: Observation): Promise<boolean> {
    if (!this.s.prefs.retainContent) return true;
    if (!version.coverage.complete) return false;
    // Hash-checked, so a damaged copy is noticed here and rewritten from the bytes just read.
    for (const file of version.files) if (!(await this.store.getBlob(file.sha256))) return false;
    return true;
  }

  private async retain(tree: SkillTree & { contents?: Map<string, Buffer> }): Promise<SnapshotCoverage> {
    const total = tree.files.length;
    if (!this.s.prefs.retainContent || !tree.contents) return { stored: 0, total, complete: total === 0 };
    let stored = 0;
    for (const file of tree.files) {
      const bytes = tree.contents.get(file.path);
      if (!bytes || bytes.length > MAX_RETAINED_FILE_BYTES) continue;
      await this.store.putBlob(file.sha256, bytes);
      stored += 1;
    }
    return { stored, total, complete: stored === total };
  }

  /** Observes one Skill directory and updates its instance. Returns the check outcome for the meter. */
  private async observe(root: DiscoveryRoot, dir: string, realPath: string, at: string, onboarding: boolean): Promise<CheckEvent['outcome']> {
    const state = this.s;
    let instance = this.byRealPath(realPath);
    const created = !instance;
    if (!instance) {
      instance = {
        id: randomUUID(), rootId: root.id, path: dir, realPath, name: path.basename(dir),
        firstSeen: at, lastSeen: at, presence: 'present', error: null, current: null, baseline: null,
        previousBaselines: [], reviewedDigest: null, isNew: !onboarding,
      };
      state.instances.push(instance);
    }

    let tree: SkillTree & { contents?: Map<string, Buffer> };
    try {
      tree = await collectSkillTree(dir, { includeContents: state.prefs.retainContent });
      instance.name = await resolveSkillName(dir).catch(() => displayName(path.basename(dir)));
    } catch (error) {
      const wasReadable = instance.presence !== 'unreadable';
      instance.presence = 'unreadable';
      instance.error = errorMessage(error);
      instance.lastSeen = at;
      if (wasReadable) this.record({ at, kind: 'unreadable', instanceId: instance.id, name: instance.name, digest: null, detail: instance.error });
      return 'error';
    }

    const returning = instance.presence === 'missing';
    const previousDigest = instance.current?.digest ?? null;
    const changed = previousDigest !== null && previousDigest !== tree.digest;
    // Content is retained once per version; an unchanged tree keeps its coverage while its copies are intact.
    const coverage = !changed && instance.current && await this.coverageIntact(instance.current)
      ? instance.current.coverage
      : await this.retain(tree);
    if (instance.baseline?.digest === tree.digest) instance.baseline.coverage = coverage;

    instance.path = dir;
    instance.rootId = root.id;
    instance.presence = 'present';
    instance.error = null;
    instance.lastSeen = at;
    instance.current = {
      digest: tree.digest, observedAt: changed || !instance.current ? at : instance.current.observedAt,
      files: toFileRecords(tree), excluded: tree.excluded, totalBytes: tree.totalBytes, coverage,
    };

    if (!instance.baseline) {
      instance.baseline = { digest: tree.digest, recordedAt: at, reason: 'first-seen', files: toFileRecords(tree), coverage };
      this.record({ at, kind: created && !onboarding ? 'new-skill' : 'first-seen', instanceId: instance.id, name: instance.name, digest: tree.digest, detail: null });
      return created && !onboarding ? 'new' : 'same';
    }
    if (returning) this.record({ at, kind: 'returned', instanceId: instance.id, name: instance.name, digest: tree.digest, detail: null });
    if (changed) {
      this.record({ at, kind: 'changed', instanceId: instance.id, name: instance.name, digest: tree.digest,
        detail: `${countChangedFiles(instance.baseline.files, instance.current.files)} file(s) differ from the remembered version` });
      return 'changed';
    }
    return 'same';
  }

  private async verifyAll(now: Date): Promise<void> {
    this.pki.clear();
    const host = this.host;
    if (!host?.policy) return;
    for (const instance of this.s.instances) {
      if (instance.presence === 'missing') continue;
      let result: VerificationResult;
      if (!host.context) {
        const policyView = host.view.policy;
        const reason = policyView.kind === 'loaded' && policyView.trustNote ? policyView.trustNote : 'trust documents could not be loaded';
        const verdict = reason.startsWith('EXPIRED') ? 'EXPIRED' : 'UNVERIFIABLE';
        result = unverifiable(instance.path, instance.name, reason, now, verdict);
      } else {
        result = await verifyWithPolicy(host.policy, instance.path, { now, context: host.context });
      }
      this.pki.set(instance.id, {
        verdict: result.verdict, reason: result.reason, digest: result.digest,
        certificateId: result.certificateId, approverKeyId: result.approverKeyId, checkedAt: result.checkedAt,
      });
    }
  }

  private record(event: HistoryEvent): void {
    this.s.history = [...this.s.history, event].slice(-MAX_HISTORY);
  }

  /** Drops remembered versions older than the retention period. The active baseline is always kept. */
  private prune(now: Date): void {
    const cutoff = now.getTime() - this.s.prefs.retentionDays * DAY_MS;
    for (const instance of this.s.instances) {
      instance.previousBaselines = instance.previousBaselines.filter((b) => Date.parse(b.supersededAt ?? b.recordedAt) >= cutoff);
    }
  }

  private async collectGarbage(): Promise<void> {
    const referenced = new Set<string>();
    // With copying off, every retained copy is deleted.
    if (this.s.prefs.retainContent) for (const instance of this.s.instances) {
      for (const version of [instance.baseline, instance.current, ...instance.previousBaselines]) {
        for (const file of version?.files ?? []) referenced.add(file.sha256);
      }
    }
    await this.store.collectGarbage(referenced);
  }

  // ---------------------------------------------------------------- watching

  private syncWatchers(): void {
    if (!this.watchFiles || this.stopped) return;
    const wanted = new Set(this.roots.filter((root) => root.exists).map((root) => root.path));
    for (const [rootPath, watcher] of this.watchers) {
      if (!wanted.has(rootPath)) { watcher.close(); this.watchers.delete(rootPath); }
    }
    for (const rootPath of wanted) {
      if (this.watchers.has(rootPath)) continue;
      try {
        const watcher = watch(rootPath, { recursive: true, persistent: false }, () => this.schedule());
        watcher.on('error', () => { watcher.close(); this.watchers.delete(rootPath); this.schedule(); });
        this.watchers.set(rootPath, watcher);
      } catch {
        // Without a watcher the periodic check still covers this root.
      }
    }
  }

  // ---------------------------------------------------------------- views

  private instanceView(instance: SkillInstance): InstanceView {
    const root = this.s.roots.find((r) => r.id === instance.rootId);
    return {
      id: instance.id, name: instance.name, path: instance.path, rootId: instance.rootId, rootLabel: root?.label ?? 'removed location',
      state: observationState(instance), error: instance.error, firstSeen: instance.firstSeen, lastChecked: instance.lastSeen,
      currentDigest: instance.current?.digest ?? null, baselineDigest: instance.baseline?.digest ?? null,
      baselineAt: instance.baseline?.recordedAt ?? null,
      changedFiles: instance.current && instance.baseline ? countChangedFiles(instance.baseline.files, instance.current.files) : 0,
      pki: this.pki.get(instance.id) ?? null,
      pkiCurrent: (() => {
        const pki = this.pki.get(instance.id);
        return !pki || pki.digest === null || pki.digest === (instance.current?.digest ?? null);
      })(),
    };
  }

  view(): ServiceView {
    const state = this.s;
    const order: Record<ObservationState, number> = { changed: 0, unreadable: 1, new: 2, missing: 3, reviewed: 4, unchanged: 5 };
    const instances = state.instances.map((instance) => this.instanceView(instance))
      .sort((a, b) => order[a.state] - order[b.state] || a.name.localeCompare(b.name));
    return {
      service: {
        status: this.status, lastCheckAt: this.lastCheckAt, lastError: this.lastError,
        platformSupported: process.platform === 'linux' || process.platform === 'darwin',
        platform: process.platform, dataDir: this.store.dataDir, historyReset: state.historyReset,
      },
      roots: this.roots,
      instances,
      checks: state.checks.slice(-12),
      history: state.history.slice(-100).reverse(),
      host: this.host?.view ?? {
        name: 'Pi', agentDir: '', present: false, extensionListed: null, appliesAt: 'next-session',
        policy: { kind: 'none', path: null, reason: null }, recentDecisions: [],
      },
      prefs: { ...state.prefs },
    };
  }

  private emitUpdate(): void {
    if (this.state) this.emit('update', this.view());
  }

  // ---------------------------------------------------------------- detail and diff

  /** Writes retained copies into a private temp directory; returns it with the (hash-checked) bytes it wrote. */
  private async materialize(files: FileRecord[]): Promise<{ dir: string; bytes: Map<string, Buffer> } | null> {
    const dir = await mkdtemp(path.join(os.tmpdir(), 'mago-ski-gui-'));
    const written = new Map<string, Buffer>();
    try {
      for (const file of files) {
        const bytes = await this.store.getBlob(file.sha256);
        if (!bytes) { await rm(dir, { recursive: true, force: true }); return null; }
        written.set(file.path, bytes);
        const target = path.join(dir, file.path);
        await mkdir(path.dirname(target), { recursive: true });
        await writeFile(target, bytes, { mode: 0o600 });
        await chmod(target, file.exec ? 0o700 : 0o600);
      }
      return { dir, bytes: written };
    } catch (error) {
      await rm(dir, { recursive: true, force: true });
      throw error;
    }
  }

  private metadataChanges(before: FileRecord[], after: FileRecord[], note: string): FileChangeView[] {
    const old = new Map(before.map((f) => [f.path, f]));
    const out: FileChangeView[] = [];
    for (const file of after) {
      const prev = old.get(file.path);
      old.delete(file.path);
      if (prev && prev.sha256 === file.sha256 && prev.exec === file.exec) continue;
      const change = !prev ? 'added' : prev.sha256 === file.sha256 ? 'mode-changed' : 'modified';
      out.push({ path: file.path, change, execBefore: prev?.exec ?? null, execAfter: file.exec, sections: [], lines: null, note });
    }
    for (const prev of old.values()) {
      out.push({ path: prev.path, change: 'deleted', execBefore: prev.exec, execAfter: null, sections: [], lines: null, note });
    }
    return out.sort((a, b) => a.path.localeCompare(b.path));
  }

  /** Compares the remembered version with the last observed one, from retained copies only. */
  private async changeView(base: Baseline, current: Observation): Promise<ChangeView> {
    const evidenceNote = 'Partial evidence: only HTTP(S) origins in text files are detected. No detected change does not make changed content safe or approved.';
    const metadataOnly = (note: string): ChangeView => ({
      baselineDigest: base.digest, currentDigest: current.digest, contentRetained: false, contentNote: note,
      files: this.metadataChanges(base.files, current.files, note),
      addedOrigins: [], removedOrigins: [], analysisComplete: false, evidenceNote, truncated: false,
    });
    if (!base.coverage.complete || !current.coverage.complete) {
      return metadataOnly('Content of this version was not retained, so only file names, sizes and executable bits are compared.');
    }

    const baseCopy = await this.materialize(base.files);
    const currentCopy = baseCopy ? await this.materialize(current.files) : null;
    try {
      if (!baseCopy || !currentCopy) return metadataOnly('A retained copy is missing or damaged, so only file metadata is compared.');
      const diff = await diffSkillTrees(baseCopy.dir, currentCopy.dir);
      // The engine re-hashes both copies: they must be exactly the versions on record.
      if (diff.base_digest !== base.digest || diff.candidate_digest !== current.digest) {
        return metadataOnly('A retained copy does not match its recorded digest, so only file metadata is compared.');
      }
      const before = new Map(base.files.map((f) => [f.path, f]));
      const after = new Map(current.files.map((f) => [f.path, f]));
      const files: FileChangeView[] = [];
      for (const change of diff.files) {
        const oldFile = before.get(change.path);
        const newFile = after.get(change.path);
        const oldText = oldFile ? decodeText(baseCopy.bytes.get(change.path)!) : '';
        const newText = newFile ? decodeText(currentCopy.bytes.get(change.path)!) : '';
        let lines = null;
        let note: string | null = null;
        if (change.change === 'mode-changed') note = `Executable bit ${change.exec_after ? 'added' : 'removed'}; content unchanged.`;
        else if (oldText === null || newText === null) note = 'Not shown as text (binary, not UTF-8, or larger than 512 KiB).';
        else {
          lines = diffLines(oldText, newText);
          if (!lines) note = 'Too large or too different to show line by line.';
          else if (!lines.some((l) => l.kind === 'add' || l.kind === 'del')) note = 'Only line endings or the final newline changed; the bytes differ.';
          else if (lines.some((l) => l.kind === 'add' && INVISIBLE.test(l.text))) note = 'Added lines contain invisible or bidirectional control characters, shown as ⟨U+…⟩.';
        }
        files.push({
          path: change.path, change: change.change, execBefore: change.exec_before, execAfter: change.exec_after,
          sections: change.changed_sections, lines, note,
        });
      }
      return {
        baselineDigest: base.digest, currentDigest: current.digest, contentRetained: true, contentNote: null, files,
        addedOrigins: diff.capability_evidence.added_network_origins, removedOrigins: diff.capability_evidence.removed_network_origins,
        analysisComplete: diff.capability_evidence.analysis_complete, evidenceNote: diff.capability_evidence.note, truncated: diff.diff_truncated,
      };
    } finally {
      if (baseCopy) await rm(baseCopy.dir, { recursive: true, force: true });
      if (currentCopy) await rm(currentCopy.dir, { recursive: true, force: true });
    }
  }

  detail(instanceId: string): Promise<InstanceDetail | null> {
    return this.serial(() => this.buildDetail(instanceId));
  }

  private async buildDetail(instanceId: string): Promise<InstanceDetail | null> {
    const instance = this.s.instances.find((i) => i.id === instanceId);
    if (!instance) return null;
    const view = this.instanceView(instance);
    const change = instance.baseline && instance.current && instance.baseline.digest !== instance.current.digest
      ? await this.changeView(instance.baseline, instance.current)
      : null;
    const policy = this.host?.view.policy;
    const approveCommand = policy?.kind === 'loaded' && instance.current
      ? [
          'mago-ski approve', shellQuote(instance.path), '--key', 'YOUR-APPROVER-KEY.pem', '--expires', '90d',
          '--reason', shellQuote('Reviewed in mago-ski GUI'), '--expect-digest', instance.current.digest,
        ].join(' ')
      : null;
    const previousVersions = [];
    for (const b of [...instance.previousBaselines].reverse()) {
      let retained = b.coverage.complete;
      for (const file of b.files) if (retained && !(await this.store.hasBlob(file.sha256))) retained = false;
      previousVersions.push({ digest: b.digest, recordedAt: b.recordedAt, supersededAt: b.supersededAt ?? null, retained });
    }
    return {
      instance: view, change, approveCommand, previousVersions,
      history: this.s.history.filter((e) => e.instanceId === instanceId).slice(-50).reverse(),
    };
  }

  // ---------------------------------------------------------------- user actions

  /**
   * Re-reads the Skill and checks it is still exactly the version the user looked at.
   * Every action is bound to that digest; a Skill that changed in between is never recorded.
   */
  private async confirmTarget(instanceId: string, digest: string, includeContents: boolean):
    Promise<{ instance: SkillInstance; tree: SkillTree & { contents?: Map<string, Buffer> } } | ActionResult> {
    const instance = this.s.instances.find((i) => i.id === instanceId);
    if (!instance) return { ok: false, code: 'not-found', message: 'This Skill is no longer tracked.' };
    if (instance.current?.digest !== digest) {
      return { ok: false, code: 'stale', message: 'The Skill changed after this view was shown. Review the latest change.' };
    }
    let tree;
    try {
      tree = await collectSkillTree(instance.path, { includeContents });
    } catch (error) {
      return { ok: false, code: 'unreadable', message: errorMessage(error) };
    }
    if (tree.digest !== digest) {
      void this.check();
      return { ok: false, code: 'stale', message: 'The Skill changed while you were reviewing it. Review the latest change.' };
    }
    return { instance, tree };
  }

  /** Records that the user looked at this exact version. It is not an approval. */
  markReviewed(instanceId: string, digest: string): Promise<ActionResult> {
    return this.serial(() => this.doMarkReviewed(instanceId, digest));
  }

  private async doMarkReviewed(instanceId: string, digest: string): Promise<ActionResult> {
    const target = await this.confirmTarget(instanceId, digest, false);
    if ('ok' in target) return target;
    const { instance } = target;
    instance.isNew = false;
    if (instance.baseline?.digest !== digest) instance.reviewedDigest = digest;
    this.record({ at: this.now().toISOString(), kind: 'reviewed', instanceId, name: instance.name, digest, detail: null });
    await this.store.save(this.s);
    this.emitUpdate();
    return { ok: true };
  }

  /** Makes this exact version the comparison baseline. The previous baseline stays in history. */
  rememberVersion(instanceId: string, digest: string): Promise<ActionResult> {
    return this.serial(() => this.doRememberVersion(instanceId, digest));
  }

  private async doRememberVersion(instanceId: string, digest: string): Promise<ActionResult> {
    const target = await this.confirmTarget(instanceId, digest, this.s.prefs.retainContent);
    if ('ok' in target) return target;
    const { instance, tree } = target;
    const at = this.now().toISOString();
    const coverage = await this.retain(tree);
    if (instance.baseline && instance.baseline.digest !== digest) instance.previousBaselines.push({ ...instance.baseline, supersededAt: at });
    instance.baseline = { digest, recordedAt: at, reason: 'remembered', files: toFileRecords(tree), coverage };
    if (instance.current?.digest === digest) instance.current.coverage = coverage;
    instance.reviewedDigest = null;
    instance.isNew = false;
    this.record({ at, kind: 'remembered', instanceId, name: instance.name, digest, detail: null });
    await this.store.save(this.s);
    await this.collectGarbage();
    this.emitUpdate();
    return { ok: true };
  }

  // ---------------------------------------------------------------- settings

  async addRoot(rootPath: string): Promise<void> {
    await this.serial(async () => {
      const resolved = path.resolve(rootPath);
      if (this.s.roots.some((root) => path.resolve(root.path) === resolved)) return;
      this.s.roots.push({ id: `user-${randomUUID()}`, path: resolved, label: displayName(path.basename(resolved)) || resolved, origin: 'user' });
      await this.store.save(this.s);
    });
    await this.check();
  }

  /** Stops observing a location the user added. Default locations stay; their history is kept. */
  async removeRoot(rootId: string): Promise<void> {
    await this.serial(async () => {
      const root = this.s.roots.find((r) => r.id === rootId);
      if (!root || root.origin !== 'user') return;
      this.s.roots = this.s.roots.filter((r) => r.id !== rootId);
      this.s.instances = this.s.instances.filter((instance) => instance.rootId !== rootId);
      await this.store.save(this.s);
    });
    await this.check();
  }

  setPrefs(prefs: Partial<Prefs>): Promise<void> {
    return this.serial(async () => {
      const next = { ...this.s.prefs };
      if (prefs.notify === 'off' || prefs.notify === 'grouped' || prefs.notify === 'immediate') next.notify = prefs.notify;
      if (typeof prefs.retainContent === 'boolean') next.retainContent = prefs.retainContent;
      if (typeof prefs.retentionDays === 'number' && Number.isInteger(prefs.retentionDays) && prefs.retentionDays >= 1 && prefs.retentionDays <= 365) {
        next.retentionDays = prefs.retentionDays;
      }
      const stopRetaining = this.s.prefs.retainContent && !next.retainContent;
      this.s.prefs = next;
      if (stopRetaining) {
        // Turning copies off deletes the ones already kept; versions then compare by file metadata only.
        for (const instance of this.s.instances) {
          for (const version of [instance.baseline, instance.current, ...instance.previousBaselines]) {
            if (version) version.coverage = { stored: 0, total: version.files.length, complete: version.files.length === 0 };
          }
        }
      }
      this.prune(this.now());
      await this.store.save(this.s);
      await this.collectGarbage();
      this.emitUpdate();
    });
  }

  /** The user has seen that earlier history was lost. The history event stays. */
  dismissHistoryReset(): Promise<void> {
    return this.serial(async () => {
      this.s.historyReset = null;
      await this.store.save(this.s);
      this.emitUpdate();
    });
  }
}
