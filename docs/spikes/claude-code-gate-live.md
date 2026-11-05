# Claude Code gate: live test

Date: 2026-11-05. Claude Code 2.1.318 (Linux, root), Node 22.23.4.

**Question:** does the E3 gate (`src/gate/`) enforce Skill approval on the real Claude Code CLI, using exactly the managed settings, hook entry and service it ships? Until now the gate was tested only against fake hosts, and [the adapter interface](../hosts/adapter-interface.md) made no "works with Claude Code" claim.

**Method:** [`tests/live/claude-code-gate.live.ts`](../../tests/live/claude-code-gate.live.ts) runs the real `claude -p` against the real gate service (`createGateService`, with its trust, admission, generation and decision-log stores and its sockets), the managed settings from `claudeCodeManagedSettings`, and the production hook entry `src/gate/adapters/claude-code-hook.ts`, which Claude Code starts through `env -i`. Only the model is faked: a local Messages API plays a script and records every request, so whether a Skill's body reached the model is observed directly. Skills are installed with the service's admin `install` command and revoked with `accept-trust`, as an administrator would. The script runs in a private mount namespace with a temporary folder bind-mounted over `/etc/claude-code`, so the machine's own managed settings are never touched.

```bash
sudo node tests/live/claude-code-gate.live.ts                    # all scenarios, JSON report on stdout
sudo node tests/live/claude-code-gate.live.ts listing service-down
```

It needs root and util-linux `unshare`, is not part of `npm test`, and exits 1 if any expectation fails.

**Where Claude Code looks.** This version reads managed settings from `/etc/claude-code/managed-settings.json` and managed Skills from `/etc/claude-code/.claude/skills` (from the binary: the `policySettings` Skill source is `<managed dir>/.claude/skills`). That folder is the gate's `managedDir`.

## Results

Every scenario starts a fresh `claude -p` with a fresh `HOME`, `CLAUDE_CONFIG_DIR` and project. Each project holds an unapproved Skill in `.claude/skills/project-skill`, and each user folder holds one in `skills/user-skill`.

| Scenario | Mode | Observed | Blocked by |
|---|---|---|---|
| Listing | enforce | Only `approved-skill`, installed by the gate as a **symlink** to its generation, is listed. Project, user and all 13 bundled Skills are not | Native lock |
| Skill tool, installed Skill | enforce | Allowed; the body reached the model | — |
| Skill tool, project Skill | enforce | `Unknown skill: project-skill`; body never reached the model; the hook was not asked | Native lock |
| `/approved-skill go` | enforce | `UserPromptExpansion` hook allowed it; body reached the model | — |
| `/project-skill go` | enforce | Not expanded (Claude Code does not know the command); body never reached the model | Native lock |
| Revoked after the session started, then the model calls it | enforce | Denied by the hook: `This Skill is not approved by your organisation (mago-ski: NO_CERTIFICATE)`. Body never reached the model | Hook |
| New session after the revoke | enforce | The auto-uninstalled Skill is no longer listed; `Unknown skill` | Gate removed the link |
| A Skill copied straight into the managed folder (not installed by the gate), Skill tool | enforce | Claude Code lists and loads it; the hook denies it (`NO_CERTIFICATE`); body never reached the model | Hook |
| The same planted Skill as `/planted-skill go` | enforce | `UserPromptExpansion operation blocked by hook`; the model was never called | Hook |
| Gate service stopped, Skill tool | enforce | Still listed, but denied: `mago-ski could not verify this Skill; it is blocked until verification works.` | Hook (fail closed) |
| Gate service stopped, `/approved-skill go` | enforce | Blocked by the hook; the model was never called | Hook (fail closed) |
| Project Skill | shadow | Listed (with the user and bundled Skills) and runs; nothing blocked | — |

All 12 scenarios passed.

## Findings

1. **Symlinked managed Skills work.** Since [mago-foundation/mago-ski#13](https://github.com/mago-foundation/mago-ski/pull/13) the gate publishes each Skill as `<managedDir>/<name>`, a symlink to its immutable generation. That this works was marked UNVERIFIED in `src/gate/service.ts`. Claude Code 2.1.318 follows it: the Skill is listed, and the Skill tool and `/name` serve its body.
2. **The native locks hold on 2.1.318.** The settings generator's lock fields were copied from tests on 2.1.296: `strictPluginOnlyCustomization`, `disableBundledSkills`, `skillOverrides` and the built-in `enabledPlugins` ids. On 2.1.318 they still hide every project, user and bundled Skill.
3. **Two independent layers.** For Skills outside the managed folder, Claude Code's lock already stops them; the gate's hooks never see them. For anything Claude Code does load from the managed folder, the hooks decide, on both paths (Skill tool and `/name`). The planted-Skill scenarios show the hooks blocking on their own.
4. **Fail closed works end to end.** With the service gone, both hooks answer with an explicit deny within their deadline. Claude Code honours it (`PreToolUse` deny JSON, `UserPromptExpansion` `decision: block`, both with exit 0).
5. **Misleading verdict after a revoke (minor).** Revoking a digest makes the service auto-uninstall the Skill. A session that started before the revoke still lists it, and its next use is denied, but the reason says `NO_CERTIFICATE`, because an uninstalled Skill answers `NO_CERTIFICATE`. `REVOKED` would tell the user what happened. The block itself is correct.

## Not covered

- **Interactive sessions.** Only `-p` was run. Whether an interactive session reloads Skills when the managed folder changes is still open.
- **Subagents.** Whether their Skill calls reach the managed `PreToolUse` hook.
- **The exit-2 block.** The hook exits 2 only when it cannot tell the event (unparseable input), which Claude Code does not produce in normal use. That Claude Code treats exit 2 as a block is still unverified.
- **Other platforms and versions.** macOS, and Claude Code versions other than 2.1.318 (the settings still require at least 2.1.296).
- **Codex.** It needs its own live run.
