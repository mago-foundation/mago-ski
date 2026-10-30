// Local history store: state.json plus content-addressed file copies, all in the GUI's own data directory.
// Nothing here is written into a Skill directory, so retained copies never change a digest.
import { createHash } from 'node:crypto';
import { mkdir, opendir, readFile, rename, rm, unlink } from 'node:fs/promises';
import path from 'node:path';
import { writeFileAtomic, writeNewFile } from '../../../src/fs-safe.ts';
import type { Baseline, CheckEvent, HistoryEvent, Observation, Prefs } from './types.ts';

export const STATE_SCHEMA = 'mago.gui-state/poc-1';
const MAX_STATE_BYTES = 64 * 1024 * 1024;

export interface DiscoveryRoot {
  id:     string;
  path:   string;
  label:  string;
  origin: 'default' | 'user';
}

export interface SkillInstance {
  id:                string;
  rootId:            string;
  /** Path as discovered; `realPath` (symlinks resolved) is the installation identity. */
  path:              string;
  realPath:          string;
  name:              string;
  firstSeen:         string;
  lastSeen:          string;
  presence:          'present' | 'missing' | 'unreadable';
  error:             string | null;
  current:           Observation | null;
  baseline:          Baseline | null;
  previousBaselines: Baseline[];
  /** Digest the user marked as reviewed against the active baseline. */
  reviewedDigest:    string | null;
  /** Discovered after onboarding and not looked at yet. */
  isNew:             boolean;
}

export interface PersistedState {
  schema:      typeof STATE_SCHEMA;
  onboardedAt: string | null;
  roots:       DiscoveryRoot[];
  instances:   SkillInstance[];
  history:     HistoryEvent[];
  checks:      CheckEvent[];
  prefs:       Prefs;
}

export const DEFAULT_PREFS: Prefs = { notify: 'grouped', retainContent: true, retentionDays: 30 };

export function emptyState(): PersistedState {
  return { schema: STATE_SCHEMA, onboardedAt: null, roots: [], instances: [], history: [], checks: [], prefs: { ...DEFAULT_PREFS } };
}

function sha256Hex(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

export class Store {
  readonly dataDir:  string;
  readonly statePath: string;
  readonly blobDir:  string;

  constructor(dataDir: string) {
    this.dataDir   = path.resolve(dataDir);
    this.statePath = path.join(this.dataDir, 'state.json');
    this.blobDir   = path.join(this.dataDir, 'blobs');
  }

  async init(): Promise<void> {
    await mkdir(this.blobDir, { recursive: true, mode: 0o700 });
  }

  /** Loads saved state. An unreadable or foreign file is kept aside, never silently overwritten. */
  async load(): Promise<PersistedState> {
    let text: string;
    try {
      text = await readFile(this.statePath, 'utf8');
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return emptyState();
      throw error;
    }
    try {
      if (text.length > MAX_STATE_BYTES) throw new Error('state file too large');
      const value = JSON.parse(text) as PersistedState;
      if (value?.schema !== STATE_SCHEMA || !Array.isArray(value.instances) || !Array.isArray(value.roots)) throw new Error('unsupported state format');
      value.prefs = { ...DEFAULT_PREFS, ...value.prefs };
      value.history ??= [];
      value.checks ??= [];
      return value;
    } catch {
      await rename(this.statePath, `${this.statePath}.unreadable-${Date.now()}`);
      return emptyState();
    }
  }

  async save(state: PersistedState): Promise<void> {
    await writeFileAtomic(this.statePath, Buffer.from(JSON.stringify(state)), 0o600);
  }

  private blobPath(sha256: string): string {
    if (!/^[0-9a-f]{64}$/u.test(sha256)) throw new Error('invalid content hash');
    return path.join(this.blobDir, sha256.slice(0, 2), sha256);
  }

  /** Stores bytes under their SHA-256; the caller's hash is checked, not trusted. */
  async putBlob(sha256: string, bytes: Uint8Array): Promise<void> {
    if (sha256Hex(bytes) !== sha256) throw new Error('content does not match its hash');
    const target = this.blobPath(sha256);
    await mkdir(path.dirname(target), { recursive: true, mode: 0o700 });
    try {
      await writeNewFile(target, bytes, 0o600);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
    }
  }

  /** Returns retained bytes, or null when missing or corrupted. */
  async getBlob(sha256: string): Promise<Buffer | null> {
    try {
      const bytes = await readFile(this.blobPath(sha256));
      return sha256Hex(bytes) === sha256 ? bytes : null;
    } catch {
      return null;
    }
  }

  /** Deletes retained copies no remembered or observed version refers to. */
  async collectGarbage(referenced: Set<string>): Promise<number> {
    let removed = 0;
    let shards;
    try {
      shards = await opendir(this.blobDir);
    } catch {
      return 0;
    }
    for await (const shard of shards) {
      if (!shard.isDirectory()) continue;
      const shardPath = path.join(this.blobDir, shard.name);
      for await (const entry of await opendir(shardPath)) {
        if (!referenced.has(entry.name)) {
          await unlink(path.join(shardPath, entry.name)).catch(() => {});
          removed += 1;
        }
      }
    }
    return removed;
  }

  async destroy(): Promise<void> {
    await rm(this.dataDir, { recursive: true, force: true });
  }
}
