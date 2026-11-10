// Managed-settings generator for the Claude Code hook adapter. Pure: no file access.
// EVIDENCE: every field marked [cc0.4] is copied from .agent/reviews/cc0.4-fixtures/setup.sh as tested on Claude Code CLI
// 2.1.296 / Linux (cc0.3-b2b-enforcement-check.md, cc0.4-enforcement-verification.md). The generated settings were also
// run live on 2.1.318 (-p mode) with the real service and hook: the locks hid every project, user and bundled Skill
// (tests/live/claude-code-gate.live.ts, docs/spikes/claude-code-gate-live.md). Unverified for any other version;
// the native locks are bounded spike observations, not a broad host-level guarantee.
// ENDPOINT REQUIREMENTS (founder-accepted deployment requirements, NOT enforced by this file): the hook command is
// started with `env -i`, which scrubs NODE_OPTIONS/NODE_PATH/PYTHONPATH etc. for the interpreter, but loader-time
// variables act BEFORE `env` runs: LD_PRELOAD on the shell Claude Code uses to run the hook, and BASH_ENV if that shell
// is bash. Same-UID ptrace of the hook or host also stays an endpoint requirement.
import path from 'node:path';
import type { Mode } from '../../policy.ts';

export interface ClaudeCodeSettingsInput {
  mode: Mode;
  nodePath: string;
  hookEntry: string;
  configPath: string;
  hookTimeoutSec: number;
  /** Must match the hook config's self_deadline_ms; the host timeout has to outlast it by at least 1 s. */
  selfDeadlineMs: number;
  /** Absolute path of env(1); default /usr/bin/env. */
  envPath?: string;
}

const SAFE_PATH = /^\/[A-Za-z0-9._/-]+$/u; // the command is parsed by a shell: no spaces, quotes or metacharacters

export function claudeCodeManagedSettings(input: ClaudeCodeSettingsInput): Record<string, unknown> {
  const { mode, nodePath, hookEntry, configPath, hookTimeoutSec, selfDeadlineMs } = input;
  const envPath = input.envPath ?? '/usr/bin/env';
  for (const p of [envPath, nodePath, hookEntry, configPath])
    if (!path.isAbsolute(p) || !SAFE_PATH.test(p)) throw new Error('paths must be absolute and shell-safe');
  if (mode !== 'enforce' && mode !== 'shadow') throw new Error('mode must be enforce or shadow');
  if (!Number.isInteger(hookTimeoutSec) || hookTimeoutSec < 1) throw new Error('hookTimeoutSec must be a positive integer');
  if (!Number.isInteger(selfDeadlineMs) || selfDeadlineMs < 1 || hookTimeoutSec * 1000 < selfDeadlineMs + 1000)
    throw new Error('hookTimeoutSec * 1000 must be at least selfDeadlineMs + 1000');
  // env -i: the interpreter starts with an empty environment (the adapter needs none), so NODE_OPTIONS etc. cannot hijack it.
  const command = `${envPath} -i ${nodePath} --no-addons ${hookEntry} ${configPath} ${mode}`;
  const gate = { type: 'command', command, timeout: hookTimeoutSec, ...(mode === 'enforce' ? { onFailure: 'block' } : {}) }; // [cc0.4] onFailure
  const hooks = {
    PreToolUse: [{ matcher: 'Skill', hooks: [gate] }],              // [cc0.4]
    UserPromptExpansion: [{ hooks: [gate] }],                        // [cc0.4]
    SessionStart: [{ hooks: [{ type: 'command', command, timeout: hookTimeoutSec }] }], // never blocks
  };
  if (mode === 'shadow') return { hooks }; // shadow must not change behaviour: no native locks
  return {
    strictPluginOnlyCustomization: ['skills', 'hooks', 'agents', 'mcp'], // [cc0.4]
    strictKnownMarketplaces: [],                                        // [cc0.4]
    disableSideloadFlags: true,                                         // [cc0.4]
    allowManagedHooksOnly: true,                                        // [cc0.4]
    requiredMinimumVersion: '2.1.296',                                  // [cc0.4] the tested version
    // Built-in / bundled Skills: [cc0.4] setup.sh removes them so only managed-directory Skills exist. Keys and names are
    // copied from that fixture; unverified for other CLI versions (the built-in plugin ids may differ).
    disableBundledSkills: true,                                         // [cc0.4]
    skillOverrides: { design: 'off', doctor: 'off', 'plugin-authoring': 'off' }, // [cc0.4]
    enabledPlugins: Object.fromEntries(                                 // [cc0.4]
      ['cc-plugin-sec-default', 'cc-plugin-agents-md', 'cc-plugin-telemetry', 'cc-plugin-plugin-authoring'].map((x) => [`${x}@builtin`, false])),
    hooks,
  };
}
