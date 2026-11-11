// Generator of /etc/codex/requirements.toml for the Codex hook adapter. Pure: no file access.
// EVIDENCE: every setting marked [cx0.1]/[cx0.2] was exercised on codex-cli 0.163.0 / Linux (.agent/reviews/
// cx0.1-codex-surface-spike.md and its cx0.2 addendum, cx0.1-fixtures/evidence.txt, cx0.2-evidence.txt). Unverified for
// other Codex versions; not a broad host-level guarantee.
//
// KNOWN GAPS (also written into the generated header):
//  * Repo-scope Skills (<repo>/.codex/skills, .agents/skills) cannot be hidden natively: hook-only, best-effort,
//    audit-level. Codex hooks also fail OPEN on crash/timeout, so the hook is not a lock; the lock is deny_read plus
//    uninstall-on-revoke.
//  * deny_read does NOT hide the user roots from Codex's Skill catalog: in the live test (codex-cli 0.163.0 and 0.166.0,
//    as root and as an unprivileged user with bwrap; docs/spikes/codex-gate-live.md) a Skill under a denied root was
//    still listed with its path. Using it is blocked by the hook only, so the user route is hook-only like the repo route.
//  * deny_read works only for the fixed absolute roots listed in `userSkillRoots` (not for ** or /home/* globs, cx0.2).
//  * Codex's sandbox needs unprivileged user namespaces, so the max_user_namespaces=0 hardening used for Claude Code
//    breaks Codex (cx0.2: bwrap ENOSPC). Packet 10 resolves this.
//  * The hook adapter finds the employee's user roots itself from the host's CODEX_HOME/HOME (read from /proc/<host pid>/
//    environ); the roots below only feed the native deny_read. The adapter scans every cwd ancestor for repo roots.
//  * Not gateable by the UserPromptSubmit hook: structured Skill selection (UserInput::Skill, skill:// mentions from
//    non-TUI clients or the app-server API) and app-server `skills/extraRoots/set`. Endpoint requirement: restrict
//    app-server and non-TUI Codex clients. A token split across text items can differ from what the hook sees; the
//    PreToolUse shell check is best-effort. In enforce, Codex coverage is weaker than Claude Code; the live test confirmed
//    that the repo and user routes are audit-level.
//  * Startup state: Codex fixes HOME, CODEX_HOME and ~/.codex/.env at startup; the hook sees only the current state, so
//    an employee can start Codex pointed at other Skills and undo it (accepted limit; needs an admin-owned CODEX_HOME).
import path from 'node:path';
import type { Mode } from '../../policy.ts';

export interface CodexRequirementsInput {
  mode: Mode;
  nodePath: string;
  hookEntry: string;
  configPath: string;
  hookTimeoutSec: number;
  /** Must match the hook config's self_deadline_ms; the host timeout has to outlast it by at least 1 s. */
  selfDeadlineMs: number;
  envPath?: string;
  /**
   * Absolute fixed user Skill roots, supplied by the installer, per user: <home>/.codex/skills, <home>/.codex/skills/.system
   * (bundled system Skills) and <home>/.agents/skills (the generator reads no env, so it cannot find $CODEX_HOME). These feed
   * only deny_read; the adapter derives its own scan roots from the host's environment, so listing them in the adapter
   * config's `skill_roots` is optional.
   */
  userSkillRoots: string[];
}

const SAFE_PATH = /^\/[A-Za-z0-9._/@-]+$/u; // also valid inside a TOML basic string and a shell command: nothing to escape
const q = (s: string): string => `"${s}"`;

export function codexRequirementsToml(input: CodexRequirementsInput): string {
  const { mode, nodePath, hookEntry, configPath, hookTimeoutSec, selfDeadlineMs, userSkillRoots } = input;
  const envPath = input.envPath ?? '/usr/bin/env';
  for (const p of [envPath, nodePath, hookEntry, configPath, ...userSkillRoots])
    if (!path.isAbsolute(p) || !SAFE_PATH.test(p) || p.endsWith('/')) throw new Error('paths must be absolute, shell-safe and without a trailing slash');
  if (mode !== 'enforce' && mode !== 'shadow') throw new Error('mode must be enforce or shadow');
  if (!Number.isInteger(hookTimeoutSec) || hookTimeoutSec < 1 || hookTimeoutSec > 600) throw new Error('hookTimeoutSec must be an integer in 1..600');
  if (!Number.isInteger(selfDeadlineMs) || selfDeadlineMs < 1 || hookTimeoutSec * 1000 < selfDeadlineMs + 1000)
    throw new Error('hookTimeoutSec * 1000 must be at least selfDeadlineMs + 1000');
  const command = q(`${envPath} -i ${nodePath} --no-addons ${hookEntry} ${configPath} ${mode}`); // env -i: no NODE_OPTIONS etc.
  const lines: string[] = [
    '# mago-ski Codex requirements (generated). Evidence: codex-cli 0.163.0 / Linux only; unverified for other versions.',
    '# Known gaps: repo-scope Skills cannot be hidden in Codex (hook-only, best-effort, audit-level); deny_read covers only',
    '# the fixed roots listed below; hooks fail OPEN on crash/timeout; Codex sandboxing needs unprivileged user namespaces,',
    '# so max_user_namespaces=0 (used for Claude Code) breaks it.',
  ];
  if (mode === 'enforce') {
    lines.push(
      '# [cx0.1] managed hooks only: user/repo/project hooks are ignored.',
      'allow_managed_hooks_only = true',
      '# [cx0.2] keeps the sandbox on; no danger-full-access.',
      'allowed_sandbox_modes = ["read-only", "workspace-write"]',
      '',
      '# [cx0.2] feature pins: hooks on; plugins, remote plugins and apps off.',
      '[features]', 'hooks = true', 'plugins = false', 'remote_plugin = false', 'apps = false',
    );
    if (userSkillRoots.length > 0)
      lines.push('', '# [cx0.2] meant to block sandboxed reads of these fixed user roots. It does NOT hide them from the Skill catalog', '# (live test, codex-cli 0.163.0 and 0.166.0); their use is blocked by the hooks only.', '[permissions.filesystem]',
        `deny_read = [${userSkillRoots.map((r) => q(`${r}/**`)).join(', ')}]`);
  }
  lines.push('', '# [cx0.1] managed hooks; Codex needs managed_dir (without it the hooks are ignored).', '[hooks]', `managed_dir = ${q(path.dirname(hookEntry))}`);
  for (const [event, matcher] of [['SessionStart', false], ['UserPromptSubmit', false], ['PreToolUse', true]] as const)
    lines.push('', `[[hooks.${event}]]`, ...(matcher ? ['matcher = "*"'] : []), `[[hooks.${event}.hooks]]`,
      'type = "command"', `command = ${command}`, `timeout = ${hookTimeoutSec}`);
  return `${lines.join('\n')}\n`;
}
