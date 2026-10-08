// mago-ski host verifier for Pi (https://github.com/earendil-works/pi).
//
// Load it as a Pi extension. Policy comes from MAGO_SKI_POLICY or ~/.mago-ski/policy.json,
// never from the project directory, because project files may be controlled by the code under review.
//
// Enforce mode: unverified Skills are not advertised to the model, `/skill:name` cannot load them,
// and the structured file tools refuse their files. Shadow mode allows everything and logs
// what enforce mode would have blocked.
import type { ExtensionAPI, ExtensionContext } from '@earendil-works/pi-coding-agent';
import { realpath } from 'node:fs/promises';
import { homedir, hostname } from 'node:os';
import path from 'node:path';
import { isInside, readRegularFile } from '../../src/fs-safe.ts';
import { appendDecision, loadPolicy, loadPolicyTrust, verifyWithPolicy, type DecisionRecord, type Mode, type Policy } from '../../src/policy.ts';
import { formatTimestamp } from '../../src/time.ts';
import { hashFile, sha256Hex } from '../../src/tree-digest.ts';
import { unverifiable, type VerificationResult } from '../../src/verify.ts';

export interface MagoSkiPiOptions {
  /** Policy file; defaults to $MAGO_SKI_POLICY, then ~/.mago-ski/policy.json. */
  policyPath?: string;
  now?: () => Date;
}

interface PiSkill {
  name: string;
  filePath: string;
  baseDir: string;
}

interface Entry {
  name: string;
  /** Directory as Pi reports it and its canonical form. */
  baseDir: string;
  realDir: string;
  filePath: string;
  result: VerificationResult;
}

type Verdictish = VerificationResult['verdict'];

function defaultPolicyPath(): string {
  return process.env.MAGO_SKI_POLICY || path.join(homedir(), '.mago-ski', 'policy.json');
}

async function canonical(target: string): Promise<string> {
  // Resolve symlinks on the longest existing prefix so a link cannot hide a Skill path.
  let current = path.resolve(target);
  const rest: string[] = [];
  while (true) {
    try {
      return path.join(await realpath(current), ...rest.reverse());
    } catch (error) {
      if ((error as NodeJS.ErrnoException)?.code !== 'ENOENT') throw error;
      const parent = path.dirname(current);
      if (parent === current) return path.resolve(target);
      rest.push(path.basename(current));
      current = parent;
    }
  }
}

function expandHome(value: string): string {
  return value === '~' ? homedir() : value.startsWith('~/') ? path.join(homedir(), value.slice(2)) : value;
}

/** Same frontmatter handling and block format as Pi's own /skill: expansion. */
export function skillBlock(name: string, filePath: string, baseDir: string, content: string, args: string): string {
  const body = content.replace(/^---\r?\n[\s\S]*?\r?\n---(?:\r?\n|$)/u, '').trim();
  const block = `<skill name="${name}" location="${filePath}">\nReferences are relative to ${baseDir}.\n\n${body}\n</skill>`;
  return args ? `${block}\n\n${args}` : block;
}

export function createMagoSkiExtension(options: MagoSkiPiOptions = {}) {
  return function magoSki(pi: ExtensionAPI): void {
    const now = options.now ?? (() => new Date());
    let policy: Policy | null = null;
    /** Set when a policy file exists but cannot be loaded; the extension then fails closed. */
    let policyError: string | null = null;
    let loaded = false;
    const entries = new Map<string, Entry>();
    const lastLogged = new Map<string, Verdictish>();

    const mode = (): Mode => (policy ? policy.mode : 'enforce');
    const active = () => policy !== null || policyError !== null;

    async function ensurePolicy(ctx: ExtensionContext): Promise<void> {
      if (loaded) return;
      loaded = true;
      const policyPath = options.policyPath ?? defaultPolicyPath();
      try {
        policy = await loadPolicy(policyPath);
      } catch (error) {
        if ((error as NodeJS.ErrnoException)?.code === 'ENOENT') {
          if (ctx.hasUI) ctx.ui.notify(`mago-ski: no policy at ${policyPath}; Skills are not being checked`, 'warning');
          return;
        }
        policyError = `cannot load policy ${policyPath}: ${(error as Error).message}`;
        if (ctx.hasUI) ctx.ui.notify(`mago-ski: ${policyError}. Blocking all Skills until fixed.`, 'error');
      }
    }

    async function log(record: Omit<DecisionRecord, 'timestamp' | 'host' | 'mode' | 'action'>, verified: boolean): Promise<void> {
      if (!policy?.decisionLogPath) return;
      const action = verified ? 'allow' : mode() === 'enforce' ? 'block' : 'would-block';
      await appendDecision(policy.decisionLogPath, { timestamp: formatTimestamp(now()), host: hostname(), mode: mode(), action, ...record })
        .catch(() => {});
    }

    function recordFor(entry: Entry, event: string, verdict: Verdictish = entry.result.verdict, reason = entry.result.reason) {
      return {
        event, skill: entry.name, skill_dir: entry.realDir, digest: entry.result.digest,
        certificate_id: entry.result.certificateId, verdict, reason,
      };
    }

    async function verifyEntry(skill: PiSkill, context: Awaited<ReturnType<typeof loadPolicyTrust>>): Promise<Entry> {
      const realDir = await canonical(skill.baseDir);
      let result: VerificationResult;
      if (policyError || !policy) {
        result = unverifiable(realDir, skill.name, policyError ?? 'no policy', now());
      } else if (path.basename(skill.filePath) !== 'SKILL.md') {
        result = unverifiable(realDir, skill.name, 'standalone Markdown Skills cannot be certified; use a directory with SKILL.md', now());
      } else if (!context.ok) {
        result = unverifiable(realDir, skill.name, context.reason, now(), context.verdict);
      } else {
        result = await verifyWithPolicy(policy, realDir, { now: now(), skillName: skill.name, context: context.context });
      }
      return { name: skill.name, baseDir: skill.baseDir, realDir, filePath: skill.filePath, result };
    }

    async function refresh(skills: PiSkill[], ctx: ExtensionContext): Promise<Entry[]> {
      const context = policy ? await loadPolicyTrust(policy, now()) : { ok: false as const, verdict: 'UNVERIFIABLE' as const, reason: policyError ?? 'no policy' };
      const fresh: Entry[] = [];
      for (const skill of skills) fresh.push(await verifyEntry(skill, context));
      entries.clear();
      for (const entry of fresh) {
        entries.set(entry.realDir, entry);
        if (lastLogged.get(entry.realDir) !== entry.result.verdict) {
          lastLogged.set(entry.realDir, entry.result.verdict);
          await log(recordFor(entry, 'advertise'), entry.result.verdict === 'VERIFIED');
          if (entry.result.verdict !== 'VERIFIED' && ctx.hasUI) {
            const verb = mode() === 'enforce' ? 'blocked' : 'would block (shadow)';
            ctx.ui.notify(`mago-ski ${verb} Skill "${entry.name}": ${entry.result.verdict} - ${entry.result.reason}`, mode() === 'enforce' ? 'error' : 'warning');
          }
        }
      }
      if (ctx.hasUI) {
        const ok = fresh.filter((entry) => entry.result.verdict === 'VERIFIED').length;
        ctx.ui.setStatus('mago-ski', `mago-ski ${mode()}: ${ok}/${fresh.length} Skills verified`);
      }
      return fresh;
    }

    function entryFor(target: string): Entry | undefined {
      for (const entry of entries.values()) if (isInside(entry.realDir, target)) return entry;
      return undefined;
    }

    function byName(name: string): Entry | undefined {
      for (const entry of entries.values()) if (entry.name === name) return entry;
      return undefined;
    }

    /** Returns a block reason, or undefined to allow. Shadow mode logs the reason and allows. */
    async function judge(entry: Entry, event: string, verdict: Verdictish, reason: string): Promise<string | undefined> {
      await log(recordFor(entry, event, verdict, reason), false);
      return mode() === 'enforce' ? `mago-ski: Skill "${entry.name}" ${verdict}: ${reason}` : undefined;
    }

    async function reverify(entry: Entry): Promise<Entry> {
      const context = policy ? await loadPolicyTrust(policy, now()) : { ok: false as const, verdict: 'UNVERIFIABLE' as const, reason: policyError ?? 'no policy' };
      const updated = await verifyEntry({ name: entry.name, baseDir: entry.baseDir, filePath: entry.filePath }, context);
      entries.set(updated.realDir, updated);
      return updated;
    }

    pi.on('session_start', async (_event, ctx) => {
      await ensurePolicy(ctx);
    });

    pi.on('before_agent_start', async (event, ctx) => {
      await ensurePolicy(ctx);
      if (!active()) return;
      try {
        const checked = await refresh(event.systemPromptOptions.skills, ctx);
        if (mode() === 'enforce') {
          const allowed = new Set(checked.filter((entry) => entry.result.verdict === 'VERIFIED').map((entry) => entry.realDir));
          const keep = [];
          for (const skill of event.systemPromptOptions.skills) if (allowed.has(await canonical(skill.baseDir))) keep.push(skill);
          event.systemPromptOptions.skills = keep;
        }
      } catch (error) {
        // Fail closed: an unexpected error must not leave unchecked Skills advertised.
        if (mode() === 'enforce') event.systemPromptOptions.skills = [];
        if (ctx.hasUI) ctx.ui.notify(`mago-ski: verification failed (${(error as Error).message}); no Skills advertised`, 'error');
      }
    });

    pi.on('input', async (event, ctx) => {
      await ensurePolicy(ctx);
      if (!active() || !event.text.startsWith('/skill:')) return { action: 'continue' };
      const space = event.text.indexOf(' ');
      const name = space === -1 ? event.text.slice(7) : event.text.slice(7, space);
      const args = space === -1 ? '' : event.text.slice(space + 1).trim();
      const known = byName(name);
      if (!known) {
        // Not seen yet (first prompt of a session). Never let Pi expand it unchecked: turn it into a
        // plain request; the model can only use the Skill if it is advertised, and reads are checked.
        if (mode() !== 'enforce') return { action: 'continue' };
        return { action: 'transform', text: `Use the "${name}" skill.${args ? ` ${args}` : ''}` };
      }
      const entry = await reverify(known);
      if (entry.result.verdict === 'VERIFIED') {
        try {
          const bytes = await readRegularFile(entry.filePath, 'SKILL.md', 8 * 1024 * 1024);
          const approved = entry.result.files?.find((file) => file.path === 'SKILL.md');
          if (!approved || approved.sha256 !== sha256Hex(bytes)) throw new Error('SKILL.md changed after verification');
          return { action: 'transform', text: skillBlock(entry.name, entry.filePath, entry.baseDir, bytes.toString('utf8'), args) };
        } catch (error) {
          const reason = await judge(entry, 'skill-command', 'UNAPPROVED_CHANGE', (error as Error).message);
          if (reason) {
            if (ctx.hasUI) ctx.ui.notify(reason, 'error');
            return { action: 'handled' };
          }
          return { action: 'continue' };
        }
      }
      const reason = await judge(entry, 'skill-command', entry.result.verdict, entry.result.reason);
      if (!reason) return { action: 'continue' };
      if (ctx.hasUI) ctx.ui.notify(reason, 'error');
      return { action: 'handled' };
    });

    pi.on('tool_call', async (event, ctx) => {
      if (!active() || entries.size === 0) return undefined;
      const input = event.input as Record<string, unknown>;
      const toolName = event.toolName;

      if (toolName === 'bash') {
        const command = typeof input.command === 'string' ? input.command : '';
        for (const entry of [...entries.values()]) {
          const forms = new Set([entry.realDir, entry.baseDir]);
          if (entry.baseDir.startsWith(homedir())) forms.add(`~${entry.baseDir.slice(homedir().length)}`);
          if (![...forms].some((form) => command.includes(form))) continue;
          // Best-effort: shell commands can reach files in ways a string match cannot see.
          const current = entry.result.verdict === 'VERIFIED' ? await reverify(entry) : entry;
          if (current.result.verdict !== 'VERIFIED') {
            const reason = await judge(current, 'tool:bash', current.result.verdict, current.result.reason);
            if (reason) return { block: true, reason };
          }
        }
        return undefined;
      }

      if (!['read', 'edit', 'write', 'grep', 'find', 'ls'].includes(toolName)) return undefined;
      const rawPath = typeof input.path === 'string' && input.path !== '' ? input.path : '.';
      const target = await canonical(path.resolve(ctx.cwd, expandHome(rawPath)));
      const entry = entryFor(target);

      if (!entry) {
        // Searching a parent directory with grep would return lines from unverified Skills inside it.
        if (toolName === 'grep') {
          for (const inner of entries.values()) {
            if (inner.result.verdict !== 'VERIFIED' && isInside(target, inner.realDir)) {
              const reason = await judge(inner, 'tool:grep', inner.result.verdict, `search covers an unverified Skill directory (${inner.result.reason})`);
              if (reason) return { block: true, reason };
            }
          }
        }
        return undefined;
      }

      if (entry.result.verdict !== 'VERIFIED') {
        const reason = await judge(entry, `tool:${toolName}`, entry.result.verdict, entry.result.reason);
        return reason ? { block: true, reason } : undefined;
      }
      if (toolName === 'edit' || toolName === 'write') {
        const reason = await judge(entry, `tool:${toolName}`, 'UNAPPROVED_CHANGE', 'changing an approved Skill would invalidate its certificate');
        return reason ? { block: true, reason } : undefined;
      }
      if (toolName === 'read') {
        const relative = path.relative(entry.realDir, target).split(path.sep).join('/');
        const approved = entry.result.files?.find((file) => file.path === relative);
        if (!approved) {
          const reason = await judge(entry, 'tool:read', 'UNAPPROVED_CHANGE', `${relative} is not covered by the Skill's certificate`);
          return reason ? { block: true, reason } : undefined;
        }
        try {
          const actual = await hashFile(target, relative);
          if (actual.sha256 !== approved.sha256 || actual.exec !== approved.exec) throw new Error(`${relative} changed after verification`);
        } catch (error) {
          entry.result = { ...entry.result, verdict: 'UNAPPROVED_CHANGE', reason: (error as Error).message, files: null };
          const reason = await judge(entry, 'tool:read', 'UNAPPROVED_CHANGE', (error as Error).message);
          return reason ? { block: true, reason } : undefined;
        }
      }
      return undefined;
    });
  };
}

export default createMagoSkiExtension();
