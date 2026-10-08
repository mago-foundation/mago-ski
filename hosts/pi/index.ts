// mago-ski host verifier for Pi (https://github.com/earendil-works/pi).
//
// Load it as a Pi extension. Policy comes from MAGO_SKI_POLICY or ~/.mago-ski/policy.json,
// never from the project directory, because project files may be controlled by the code under review.
//
// Enforce mode: unverified Skills are not advertised to the model, `/skill:name` cannot load them,
// and the structured file tools refuse their files. Shell tools (bash, powershell) are checked
// best-effort by matching Skill paths in the command text. Shadow mode allows everything and logs
// what enforce mode would have blocked.
import type { ExtensionAPI, ExtensionContext } from '@earendil-works/pi-coding-agent';
import { realpath } from 'node:fs/promises';
import { homedir, hostname } from 'node:os';
import path from 'node:path';
import { isInside, readRegularFile } from '../../src/fs-safe.ts';
import { appendDecision, loadPolicy, loadPolicyTrust, verifyWithPolicy, type DecisionRecord, type Mode, type Policy } from '../../src/policy.ts';
import { formatTimestamp } from '../../src/time.ts';
import { CERTIFICATE_FILENAME, hashFile, sha256Hex } from '../../src/tree-digest.ts';
import { unverifiable, type TrustContextResult, type VerificationResult } from '../../src/verify.ts';
import { piReadTarget, piReadVariants, piResolveToCwd } from './paths.ts';

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
  /** Directory as Pi reports it, its absolute lexical form, and its canonical (symlink-free) form. */
  baseDir: string;
  lexDir: string;
  realDir: string;
  filePath: string;
  result: VerificationResult;
}

type Verdictish = VerificationResult['verdict'];
type Block = { block: true; reason: string } | undefined;

const SHELL_TOOLS = new Set(['bash', 'powershell']);
const FILE_TOOLS = new Set(['read', 'edit', 'write', 'grep', 'find', 'ls']);

function defaultPolicyPath(): string {
  return process.env.MAGO_SKI_POLICY || path.join(homedir(), '.mago-ski', 'policy.json');
}

/** Resolves symlinks on the longest existing prefix. Throws on errors other than ENOENT. */
async function canonical(target: string): Promise<string> {
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

function dirsOf(entry: Entry): string[] {
  return entry.lexDir === entry.realDir ? [entry.lexDir] : [entry.lexDir, entry.realDir];
}

/** Excluded paths that a tool could expose; the in-tree certificate is signed public data. */
function riskyExclusions(entry: Entry): string[] {
  return entry.result.excluded.filter((item) => item !== CERTIFICATE_FILENAME);
}

export function createMagoSkiExtension(options: MagoSkiPiOptions = {}) {
  return function magoSki(pi: ExtensionAPI): void {
    const now = options.now ?? (() => new Date());
    let policy: Policy | null = null;
    /** Set when a policy file exists but cannot be loaded; the extension then fails closed. */
    let policyError: string | null = null;
    let loaded = false;
    let entries: Entry[] = [];
    /** Lexical Skill directories from the last run, recorded before any verification can fail. */
    let knownDirs: string[] = [];
    /** Enforce-mode latch: verification itself crashed, so every Skill path is treated as unverified. */
    let failedClosed = false;
    const lastLogged = new Map<string, Verdictish>();

    const mode = (): Mode => (policy ? policy.mode : 'enforce');
    const active = () => policy !== null || policyError !== null;
    const enforcing = () => mode() === 'enforce';

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
      const action = verified ? 'allow' : enforcing() ? 'block' : 'would-block';
      await appendDecision(policy.decisionLogPath, { timestamp: formatTimestamp(now()), host: hostname(), mode: mode(), action, ...record })
        .catch(() => {});
    }

    async function trustContext(): Promise<TrustContextResult> {
      if (!policy) return { ok: false, verdict: 'UNVERIFIABLE', reason: policyError ?? 'no policy' };
      try {
        return await loadPolicyTrust(policy, now());
      } catch (error) {
        return { ok: false, verdict: 'UNVERIFIABLE', reason: (error as Error).message };
      }
    }

    /** Never throws: any failure becomes an UNVERIFIABLE entry for that Skill. */
    async function verifyEntry(skill: PiSkill, context: TrustContextResult): Promise<Entry> {
      const lexDir = path.resolve(skill.baseDir);
      const entry: Entry = {
        name: skill.name, baseDir: skill.baseDir, lexDir, realDir: lexDir, filePath: skill.filePath,
        result: unverifiable(lexDir, skill.name, 'verification did not complete', now()),
      };
      try {
        entry.realDir = await canonical(lexDir);
        if (path.basename(skill.filePath) !== 'SKILL.md') {
          entry.result = unverifiable(entry.realDir, skill.name, 'standalone Markdown Skills cannot be certified; use a directory with SKILL.md', now());
        } else if (!context.ok) {
          entry.result = unverifiable(entry.realDir, skill.name, context.reason, now(), context.verdict);
        } else {
          entry.result = await verifyWithPolicy(policy!, entry.realDir, { now: now(), skillName: skill.name, context: context.context });
        }
      } catch (error) {
        entry.result = unverifiable(entry.realDir, skill.name, `verification failed: ${(error as Error).message}`, now());
      }
      return entry;
    }

    function recordFor(entry: Entry, event: string, verdict: Verdictish = entry.result.verdict, reason = entry.result.reason) {
      return {
        event, skill: entry.name, skill_dir: entry.realDir, digest: entry.result.digest,
        certificate_id: entry.result.certificateId, verdict, reason,
      };
    }

    async function refresh(skills: PiSkill[], ctx: ExtensionContext): Promise<Entry[]> {
      const context = await trustContext();
      const fresh: Entry[] = [];
      for (const skill of skills) fresh.push(await verifyEntry(skill, context));
      entries = fresh;
      for (const entry of fresh) {
        if (lastLogged.get(entry.lexDir) === entry.result.verdict) continue;
        lastLogged.set(entry.lexDir, entry.result.verdict);
        await log(recordFor(entry, 'advertise'), entry.result.verdict === 'VERIFIED');
        if (entry.result.verdict !== 'VERIFIED' && ctx.hasUI) {
          const verb = enforcing() ? 'blocked' : 'would block (shadow)';
          ctx.ui.notify(`mago-ski ${verb} Skill "${entry.name}": ${entry.result.verdict} - ${entry.result.reason}`, enforcing() ? 'error' : 'warning');
        }
      }
      if (ctx.hasUI) {
        const ok = fresh.filter((entry) => entry.result.verdict === 'VERIFIED').length;
        ctx.ui.setStatus('mago-ski', `mago-ski ${mode()}: ${ok}/${fresh.length} Skills verified`);
      }
      return fresh;
    }

    async function reverify(entry: Entry): Promise<Entry> {
      const updated = await verifyEntry({ name: entry.name, baseDir: entry.baseDir, filePath: entry.filePath }, await trustContext());
      entries = entries.map((item) => (item === entry ? updated : item));
      return updated;
    }

    function byName(name: string): Entry | undefined {
      return entries.find((entry) => entry.name === name);
    }

    /** Skills a path is inside, matching the lexical and the canonical path against both Skill forms. */
    function containing(paths: string[]): Entry[] {
      return entries.filter((entry) => dirsOf(entry).some((dir) => paths.some((target) => isInside(dir, target))));
    }

    /** Skills inside a directory a tool would search. */
    function contained(paths: string[]): Entry[] {
      return entries.filter((entry) => dirsOf(entry).some((dir) => paths.some((target) => target !== dir && isInside(target, dir))));
    }

    /** Logs the decision; returns a block in enforce mode, undefined in shadow mode. */
    async function judge(entry: Entry, event: string, verdict: Verdictish, reason: string): Promise<Block> {
      await log(recordFor(entry, event, verdict, reason), false);
      return enforcing() ? { block: true, reason: `mago-ski: Skill "${entry.name}" ${verdict}: ${reason}` } : undefined;
    }

    async function checkShell(toolName: string, command: string): Promise<Block> {
      // Best-effort: shell commands can reach files in ways a string match cannot see.
      for (const entry of [...entries]) {
        const forms = new Set([...dirsOf(entry), entry.baseDir]);
        for (const dir of [...forms]) if (dir.startsWith(homedir())) forms.add(`~${dir.slice(homedir().length)}`);
        if (![...forms].some((form) => command.includes(form))) continue;
        const current = entry.result.verdict === 'VERIFIED' ? await reverify(entry) : entry;
        if (current.result.verdict !== 'VERIFIED') {
          const blocked = await judge(current, `tool:${toolName}`, current.result.verdict, current.result.reason);
          if (blocked) return blocked;
        }
      }
      return undefined;
    }

    async function checkGrep(affected: Entry[]): Promise<Block> {
      for (const entry of affected) {
        if (entry.result.verdict !== 'VERIFIED') {
          const blocked = await judge(entry, 'tool:grep', entry.result.verdict, entry.result.reason);
          if (blocked) return blocked;
          continue;
        }
        const risky = riskyExclusions(entry);
        if (risky.length > 0) {
          const blocked = await judge(entry, 'tool:grep', 'UNAPPROVED_CHANGE',
            `the Skill has files excluded from its certificate (${risky.slice(0, 3).join(', ')}); grep could return them. Use read on specific files`);
          if (blocked) return blocked;
          continue;
        }
        const current = await reverify(entry);
        if (current.result.verdict !== 'VERIFIED') {
          const blocked = await judge(current, 'tool:grep', current.result.verdict, current.result.reason);
          if (blocked) return blocked;
          continue;
        }
        // Files can appear in excluded locations after the run started; check the fresh result too.
        const late = riskyExclusions(current);
        if (late.length > 0) {
          const blocked = await judge(current, 'tool:grep', 'UNAPPROVED_CHANGE',
            `the Skill has files excluded from its certificate (${late.slice(0, 3).join(', ')}); grep could return them. Use read on specific files`);
          if (blocked) return blocked;
        }
      }
      return undefined;
    }

    /**
     * Every path a file tool call could touch: Pi's own resolution of the argument (and, for read,
     * the filename variants Pi tries), a plain resolution as a fallback, and each one's canonical form.
     */
    async function toolTargets(toolName: string, rawPath: string, cwd: string): Promise<{ targets: string[]; piPath: string }> {
      const piPath = piResolveToCwd(rawPath, cwd);
      const lexicals = new Set([...(toolName === 'read' ? piReadVariants(piPath) : [piPath]), path.resolve(cwd, expandHome(rawPath))]);
      const targets = new Set<string>();
      for (const lexical of lexicals) {
        targets.add(lexical);
        // An unresolvable path (for example, permission denied) is still matched lexically.
        targets.add(await canonical(lexical).catch(() => lexical));
      }
      return { targets: [...targets], piPath };
    }

    async function checkFileTool(toolName: string, rawPath: string, cwd: string): Promise<Block> {
      const { targets, piPath } = await toolTargets(toolName, rawPath, cwd);
      const inside = containing(targets);

      if (toolName === 'grep') return await checkGrep([...inside, ...contained(targets).filter((entry) => !inside.includes(entry))]);

      const unverified = inside.find((entry) => entry.result.verdict !== 'VERIFIED');
      if (unverified) return await judge(unverified, `tool:${toolName}`, unverified.result.verdict, unverified.result.reason);
      const entry = inside[0];
      if (!entry) return undefined;
      if (toolName === 'edit' || toolName === 'write') {
        return await judge(entry, `tool:${toolName}`, 'UNAPPROVED_CHANGE', 'changing an approved Skill would invalidate its certificate');
      }
      if (toolName !== 'read') return undefined; // find and ls show names, not contents
      const opened = piReadTarget(piPath);
      const resolved = await canonical(opened).catch(() => opened);
      if (!isInside(entry.realDir, resolved)) {
        return await judge(entry, 'tool:read', 'UNAPPROVED_CHANGE', `${rawPath} leaves the Skill directory through a link`);
      }
      const relative = path.relative(entry.realDir, resolved).split(path.sep).join('/');
      const approved = entry.result.files?.find((file) => file.path === relative);
      if (!approved) return await judge(entry, 'tool:read', 'UNAPPROVED_CHANGE', `${relative} is not covered by the Skill's certificate`);
      try {
        const actual = await hashFile(resolved, relative);
        if (actual.sha256 !== approved.sha256 || actual.exec !== approved.exec) throw new Error(`${relative} changed after verification`);
      } catch (error) {
        entry.result = { ...entry.result, verdict: 'UNAPPROVED_CHANGE', reason: (error as Error).message, files: null };
        return await judge(entry, 'tool:read', 'UNAPPROVED_CHANGE', (error as Error).message);
      }
      return undefined;
    }

    /** Used only after verification itself crashed in enforce mode. Matches Skill dirs in every known form. */
    async function latchBlock(toolName: string, input: Record<string, unknown>, cwd: string): Promise<Block> {
      const reason = 'mago-ski: Skill verification failed earlier in this run; Skill files are blocked until it succeeds';
      if (SHELL_TOOLS.has(toolName)) {
        const command = String(input.command ?? '');
        const forms = new Set(knownDirs);
        for (const dir of knownDirs) if (dir.startsWith(homedir())) forms.add(`~${dir.slice(homedir().length)}`);
        return [...forms].some((form) => command.includes(form)) ? { block: true, reason } : undefined;
      }
      const rawPath = typeof input.path === 'string' && input.path !== '' ? input.path : '.';
      const { targets } = await toolTargets(toolName, rawPath, cwd);
      const touches = knownDirs.some((dir) => targets.some((target) => isInside(dir, target) || isInside(target, dir)));
      return touches ? { block: true, reason } : undefined;
    }

    pi.on('session_start', async (_event, ctx) => {
      await ensurePolicy(ctx);
    });

    pi.on('before_agent_start', async (event, ctx) => {
      await ensurePolicy(ctx);
      if (!active()) return;
      knownDirs = event.systemPromptOptions.skills.map((skill) => path.resolve(skill.baseDir));
      try {
        for (const dir of [...knownDirs]) {
          const real = await canonical(dir).catch(() => dir);
          if (!knownDirs.includes(real)) knownDirs.push(real);
        }
        const checked = await refresh(event.systemPromptOptions.skills, ctx);
        failedClosed = false;
        if (enforcing()) {
          const allowed = new Set(checked.filter((entry) => entry.result.verdict === 'VERIFIED').map((entry) => entry.lexDir));
          event.systemPromptOptions.skills = event.systemPromptOptions.skills.filter((skill) => allowed.has(path.resolve(skill.baseDir)));
        }
      } catch (error) {
        // Fail closed: an unexpected error must not leave unchecked Skills advertised or readable.
        if (enforcing()) {
          failedClosed = true;
          event.systemPromptOptions.skills = [];
        }
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
        if (!enforcing()) return { action: 'continue' };
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
          const blocked = await judge(entry, 'skill-command', 'UNAPPROVED_CHANGE', (error as Error).message);
          if (!blocked) return { action: 'continue' };
          if (ctx.hasUI) ctx.ui.notify(blocked.reason, 'error');
          return { action: 'handled' };
        }
      }
      const blocked = await judge(entry, 'skill-command', entry.result.verdict, entry.result.reason);
      if (!blocked) return { action: 'continue' };
      if (ctx.hasUI) ctx.ui.notify(blocked.reason, 'error');
      return { action: 'handled' };
    });

    pi.on('tool_call', async (event, ctx) => {
      if (!active()) return undefined;
      const input = event.input as Record<string, unknown>;
      const toolName = event.toolName;
      if (!SHELL_TOOLS.has(toolName) && !FILE_TOOLS.has(toolName)) return undefined;
      if (failedClosed && enforcing()) return await latchBlock(toolName, input, ctx.cwd);
      if (entries.length === 0) return undefined;
      if (SHELL_TOOLS.has(toolName)) return await checkShell(toolName, typeof input.command === 'string' ? input.command : '');
      const rawPath = typeof input.path === 'string' && input.path !== '' ? input.path : '.';
      return await checkFileTool(toolName, rawPath, ctx.cwd);
    });
  };
}

export default createMagoSkiExtension();
