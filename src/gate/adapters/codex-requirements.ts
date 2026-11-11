// Generators of the two Codex managed files: /etc/codex/requirements.toml (codexRequirementsToml) and
// /etc/codex/managed_config.toml (codexManagedConfigToml). Pure: no file access. Design: docs/design/codex-profile.md (C1, C6).
// EVIDENCE: the keys marked [cx0.1]/[cx0.2] were exercised on codex-cli 0.163.0 / Linux (.agent/reviews/cx0.1-codex-surface-spike.md and
// its cx0.2 addendum); the managed_config.toml keys and the two executor feature pins come from the research spike against Codex
// rust-v0.166.0 (docs/spikes/codex-full-research.md). Unverified for other Codex versions; not a broad host-level guarantee.
//
// WHAT THE PROFILE LEAVES TO THE ORGANISATION (also written into the generated header):
//  * A Skill picked from Codex's menu, or sent as structured input (UserInput::Skill) by an IDE or app-server client, reaches the
//    model with no hook involved. The control is that no non-admin Skill is LISTED (`gate doctor` FAILs when a listed home has
//    one; the GitHub Action checks repositories; optional `--lock-user-skill-folders`). Detected, not prevented.
//  * Hooks fail OPEN when the hook process crashes, times out or is killed (a hook that runs but cannot reach the service blocks).
//  * Repo-scope Skills (<repo>/.codex/skills, .agents/skills) cannot be hidden natively.
//  * deny_read blocks sandboxed shell reads of the listed user roots; it does NOT hide them from the Skill catalog and does not
//    stop mention injection (live test, codex-cli 0.163.0 and 0.166.0).
//  * deny_read works only for the fixed absolute roots listed in `userSkillRoots` (not for ** or /home/* globs, cx0.2).
//  * Codex's sandbox needs unprivileged user namespaces, so the max_user_namespaces=0 hardening used for Claude Code breaks it.
//  * The hook adapter finds the employee's user roots itself from the host's CODEX_HOME/HOME; a HOME or CODEX_HOME that the
//    instance does not list makes bare mentions blocked.
//  * Startup state: Codex fixes HOME, CODEX_HOME and <codex_home>/.env at startup (needs an admin-owned CODEX_HOME).
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
    '# mago-ski Codex requirements (generated). Evidence: codex-cli 0.163.0 and 0.166.0 / Linux; unverified for other versions.',
    '# Limits: a Skill picked from the menu or sent by an IDE/app-server client reaches the model with no hook (detected by',
    '# gate doctor, not prevented); hooks fail OPEN when the hook process crashes, times out or is killed; repo Skills cannot be',
    '# hidden; deny_read covers only the fixed roots listed below; Codex sandboxing needs unprivileged user namespaces, so',
    '# max_user_namespaces=0 (used for Claude Code) breaks it.',
  ];
  if (mode === 'enforce') {
    lines.push(
      '# [cx0.1] managed hooks only: user/repo/project hooks are ignored.',
      'allow_managed_hooks_only = true',
      '# [cx0.2] keeps the sandbox on; no danger-full-access.',
      'allowed_sandbox_modes = ["read-only", "workspace-write"]',
      '',
      '# [cx0.2] feature pins: hooks on; plugins, remote plugins, apps and executor capability discovery off.',
      '[features]', 'hooks = true', 'plugins = false', 'remote_plugin = false', 'apps = false',
      'executor_capability_discovery = false', 'executor_capability_discovery_v2 = false',
    );
    if (userSkillRoots.length > 0)
      lines.push('', '# [cx0.2] blocks sandboxed shell reads of these fixed user roots. It does NOT hide them from the Skill catalog and does not', '# stop mention injection (live test, codex-cli 0.163.0 and 0.166.0); typed use is blocked by the hooks.', '[permissions.filesystem]',
        `deny_read = [${userSkillRoots.map((r) => q(`${r}/**`)).join(', ')}]`);
  }
  lines.push('', '# [cx0.1] managed hooks; Codex needs managed_dir (without it the hooks are ignored).', '[hooks]', `managed_dir = ${q(path.dirname(hookEntry))}`);
  for (const [event, matcher] of [['SessionStart', false], ['UserPromptSubmit', false], ['PreToolUse', true]] as const)
    lines.push('', `[[hooks.${event}]]`, ...(matcher ? ['matcher = "*"'] : []), `[[hooks.${event}.hooks]]`,
      'type = "command"', `command = ${command}`, `timeout = ${hookTimeoutSec}`);
  return `${lines.join('\n')}\n`;
}

/**
 * /etc/codex/managed_config.toml (codex-profile.md C1): the managed config outranks user config, project config, profiles and
 * `-c`. It removes Skill sources and keeps Skill descriptions out of the prompt; nothing here blocks by itself, so shadow mode
 * gets the same file. Takes no input. Keys (research spike, codex-cli rust-v0.166.0 / Linux):
 *   project_root_markers = []   the repo Skill scan covers the working directory only (a repo .codex/config.toml is not loaded
 *                               when Codex starts in a subdirectory);
 *   [skills] include_instructions = false   Skill descriptions are not injected;
 *   [skills.bundled] enabled = false        no bundled .system Skills;
 *   [cloud.skills] enabled = false          no cloud Skills.
 */
export function codexManagedConfigToml(): string {
  return [
    '# mago-ski Codex profile (generated). Evidence: codex-cli 0.166.0 / Linux.',
    '# Outranks user config, project config, profiles and -c. It removes Skill sources; it does not block by itself.',
    '# project_root_markers = []: the repo Skill scan covers the working directory only.',
    'project_root_markers = []',
    '',
    '# Skill descriptions are not injected into the prompt.',
    '[skills]',
    'include_instructions = false',
    '',
    '# No bundled (.system) Skills.',
    '[skills.bundled]',
    'enabled = false',
    '',
    '# No cloud Skills.',
    '[cloud.skills]',
    'enabled = false',
    '',
  ].join('\n');
}
