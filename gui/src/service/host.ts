// Read-only view of the Pi host: where it keeps Skills, whether the mago-ski extension is listed,
// which policy it reads and what it decided. Nothing here writes host files.
import { constants as fsConstants } from 'node:fs';
import { open, stat } from 'node:fs/promises';
import path from 'node:path';
import { readRegularFile } from '../../../src/fs-safe.ts';
import { defaultPolicyPath, loadPolicy, loadPolicyTrust, type Policy } from '../../../src/policy.ts';
import type { TrustContext } from '../../../src/verify.ts';
import type { DiscoveryRoot } from './store.ts';
import type { HostDecisionView, HostView, PolicyView } from './types.ts';

const MAX_SETTINGS_BYTES = 1024 * 1024;
const DECISION_TAIL_BYTES = 64 * 1024;
const MAX_DECISIONS = 20;

export function piAgentDir(env: NodeJS.ProcessEnv, home: string): string {
  const configured = env.PI_CODING_AGENT_DIR;
  if (!configured) return path.join(home, '.pi', 'agent');
  if (configured === '~' || configured.startsWith('~/')) return path.join(home, configured.slice(2));
  return path.resolve(configured);
}

/** Pi's user-level Skill locations: <agent-dir>/skills and the Agent Skills ~/.agents/skills. */
export function defaultRoots(env: NodeJS.ProcessEnv, home: string): DiscoveryRoot[] {
  return [
    { id: 'pi-user',     path: path.join(piAgentDir(env, home), 'skills'), label: 'Pi · user',           origin: 'default' },
    { id: 'agents-user', path: path.join(home, '.agents', 'skills'),       label: 'Agent Skills · user', origin: 'default' },
  ];
}

async function exists(target: string): Promise<boolean> {
  try {
    await stat(target);
    return true;
  } catch {
    return false;
  }
}

/** Best effort: true or false when Pi's settings could be read, null otherwise. */
async function extensionListed(agentDir: string): Promise<boolean | null> {
  try {
    // A regular file only: a FIFO or device here would block the read forever.
    const bytes = await readRegularFile(path.join(agentDir, 'settings.json'), 'Pi settings', MAX_SETTINGS_BYTES);
    const settings = JSON.parse(bytes.toString('utf8')) as { packages?: unknown };
    if (!Array.isArray(settings.packages)) return false;
    return settings.packages.some((entry) => {
      const source = typeof entry === 'string' ? entry : (entry as { source?: unknown })?.source;
      return typeof source === 'string' && source.includes('mago-ski');
    });
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === 'ENOENT' ? false : null;
  }
}

/** The last decisions the host logged, newest last. Only well-formed string fields are kept. */
async function recentDecisions(logPath: string | null): Promise<HostDecisionView[]> {
  if (!logPath) return [];
  let handle;
  try {
    // Non-blocking and without following links, then checked: a FIFO would otherwise block the read forever.
    handle = await open(logPath, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0) | (fsConstants.O_NONBLOCK ?? 0));
    const info = await handle.stat();
    if (!info.isFile()) return [];
    const { size } = info;
    const length = Math.min(size, DECISION_TAIL_BYTES);
    const buffer = Buffer.alloc(length);
    await handle.read(buffer, 0, length, size - length);
    const lines = buffer.toString('utf8').split('\n');
    if (size > length) lines.shift();
    const decisions: HostDecisionView[] = [];
    for (const line of lines) {
      if (!line.trim()) continue;
      try {
        const r = JSON.parse(line) as Record<string, unknown>;
        if ([r.timestamp, r.action, r.skill, r.verdict, r.event].every((v) => typeof v === 'string')) {
          decisions.push({ timestamp: r.timestamp as string, action: r.action as string, skill: r.skill as string, verdict: r.verdict as string, event: r.event as string });
        }
      } catch {
        // A partial or foreign line is skipped, not shown.
      }
    }
    return decisions.slice(-MAX_DECISIONS);
  } catch {
    return [];
  } finally {
    await handle?.close();
  }
}

export interface HostSnapshot {
  view:    HostView;
  policy:  Policy | null;
  context: TrustContext | null;
}

/** Reads the policy the way Pi does ($MAGO_SKI_POLICY, else ~/.mago-ski/policy.json), without recording trust versions. */
export async function readHost(env: NodeJS.ProcessEnv, home: string, now: Date): Promise<HostSnapshot> {
  const agentDir = piAgentDir(env, home);
  const [present, listed] = await Promise.all([exists(agentDir), extensionListed(agentDir)]);
  const base = { name: 'Pi' as const, agentDir, present, extensionListed: listed, appliesAt: 'next-session' as const };

  let policyPath: string;
  try {
    policyPath = defaultPolicyPath(env, home);
  } catch (error) {
    return { view: { ...base, policy: { kind: 'error', path: env.MAGO_SKI_POLICY ?? '', reason: (error as Error).message }, recentDecisions: [] }, policy: null, context: null };
  }
  if (!(await exists(policyPath))) {
    return { view: { ...base, policy: { kind: 'none', path: policyPath, reason: null }, recentDecisions: [] }, policy: null, context: null };
  }

  let policy: Policy;
  try {
    policy = await loadPolicy(policyPath);
  } catch (error) {
    return { view: { ...base, policy: { kind: 'error', path: policyPath, reason: (error as Error).message }, recentDecisions: [] }, policy: null, context: null };
  }

  const trust = await loadPolicyTrust(policy, now, { recordVersions: false });
  const policyView: PolicyView = {
    kind: 'loaded', path: policy.path, mode: policy.mode,
    trustOk: trust.ok, trustNote: trust.ok ? null : `${trust.verdict}: ${trust.reason}`,
  };
  return {
    view: { ...base, policy: policyView, recentDecisions: await recentDecisions(policy.decisionLogPath) },
    policy,
    context: trust.ok ? trust.context : null,
  };
}
