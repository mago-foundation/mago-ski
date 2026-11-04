# Claude Code interception spike

Date: 2026-10-31. Claude Code 2.1.314 (Linux, root), Node 22.23.4.

**Question:** can Claude Code's hooks and settings provide the [host hook points](../hosts/adapter-interface.md) H1–H6, or does mago-ski need a verified-install store, as Pi did not?

**Method:** [`claude-code-spike.mjs`](claude-code-spike.mjs) runs the real `claude -p` against a local faux Messages API (`ANTHROPIC_BASE_URL`, dummy key, no network), with a scripted model, two project Skills (`approved-skill`, `unapproved-skill`, each carrying a marker string) and a hook script that denies anything touching `unapproved-skill`. Each scenario gets a fresh `HOME`, `CLAUDE_CONFIG_DIR` and project, and a clean environment. Observations come from the requests Claude Code sends to the model: which Skills are listed, and whether a Skill's marker ever reached the model. Managed settings are bind-mounted over `/etc/claude-code` in a private mount namespace (needs root and `unshare`); `CLAUDE_CODE_MANAGED_SETTINGS_PATH` was not honoured. `--permission-mode bypassPermissions` is refused as root, so tools are pre-allowed with `--allowedTools` instead and only the hook decides.

```bash
node docs/spikes/claude-code-spike.mjs                 # all scenarios, JSON on stdout
node docs/spikes/claude-code-spike.mjs h2-model-Skill-tool h6-bare-vs-managed-hooks
```

## Results

| Hook point | Mechanism tried | Observed |
|---|---|---|
| H1 Skill list | Any hook | No hook can edit the listing. The model is told "The following skills are available…" in a message, built at startup. A `SessionStart` hook that wrote `skillOverrides` into user settings had no effect for the rest of that session |
| | `skillOverrides: {"name": "off"}` | Hidden from the listing; the `Skill` tool refuses it; `/name` refuses it. Keyed by **name**, and absent means on, so it is a denylist: a newly installed Skill is listed until the next sync |
| | … in user settings, project sets `"on"` | **The project wins**: the Skill is listed again |
| | … in managed settings, project sets `"on"` | Managed wins: still hidden |
| | Managed `strictPluginOnlyCustomization: ["skills"]` plus a plugin whose `skills/` holds verified copies | Only `mago-verified:store-skill` is listed; project Skills are not; `/unapproved-skill` loads nothing. An allowlist that fails closed |
| H2 Skill invocation | `PreToolUse`, matcher `Skill` (model calls the tool) | `tool_input.skill` is the name; `deny` returns the reason to the model as a tool error and the body is not delivered |
| | `PreToolUse` only, user types `/unapproved-skill go` | **Bypassed**: no hook fired and the body reached the model |
| | `UserPromptExpansion` | Fires before expansion with `expansion_type: "slash_command"`, `command_name`, `command_args`, `command_source` (`"projectSettings"`); `decision: "block"` stops it and the model is never called |
| | `UserPromptSubmit` | Sees the raw `/unapproved-skill go` and can block it the same way |
| | Change `SKILL.md` inside the allowing hook, or between turns | **The change never reached the model**; the bytes from startup did. Claude Code serves Skill bodies from what it loaded at startup, not from the file at invocation |
| H3 File tools | `PreToolUse`, matcher `*` | `Read`/`Edit` give `file_path`, `Grep`/`Glob` give `path`; `deny` blocked all of them, each call in a parallel batch separately, even though the tools were pre-allowed. The approved file read normally |
| H4 Shell | `PreToolUse` on `Bash` | `command` is the text; a direct path is blocked; `cd .claude/skills && cat unapp*/SKILL.md` gets through (as on Pi) |
| H5 Report | Hook output | The deny reason reaches the model (`PreToolUse:Read hook error: <reason>`); a blocked prompt ends the turn with `UserPromptExpansion operation blocked by hook: <reason>`; `systemMessage` shows up in `stream-json` hook events. Interactive display not checked |
| H6 Configuration | Project `.claude/settings.json` `disableAllHooks: true` | **User hooks are switched off**: the unapproved body reached the model. Managed hooks kept running |
| | Project hook returning `allow` vs a user `deny` | Deny wins |
| | `--bare` | User hooks skipped (and no Skill listing); managed hooks still ran |
| | Managed `allowManagedHooksOnly: true` | The project's hook did not run; managed ones did |

**Decision:** user-level hooks cannot enforce anything on Claude Code: the project being worked on can turn them off, and no hook controls the listing. Enforcement needs **managed settings**, and with them a verified-install store is required, not optional:

1. Managed `strictPluginOnlyCustomization: ["skills"]`, so only plugin Skills load, and a mago-ski plugin whose `skills/` is the store: copies written by mago-ski from verified bytes, outside the session. This gives H1 as an allowlist, and since Claude Code serves the bytes it loaded at startup, those are the bytes that were verified.
2. Managed hooks: `UserPromptExpansion` and `PreToolUse` (`Skill`, file tools, `Bash`) for H2–H5, re-verifying store entries and refusing writes into the store. `allowManagedHooksOnly` keeps project hooks out entirely.
3. Without managed settings (no admin rights), Claude Code support can only be shadow mode: report, not block.

## Constraints the adapter design must handle

1. **Startup snapshot.** A call-time hook hashes the file on disk, but the model gets the bytes Claude Code read at startup. If the file changes in between, the hook checks bytes the model never sees. The store avoids this. Without one, verify before launch and treat any change during the session as a failure.
2. **Two invocation paths.** The model's `Skill` call goes through `PreToolUse`; a typed `/name` goes only through `UserPromptExpansion`/`UserPromptSubmit`. Both need covering.
3. **Name-keyed settings.** `skillOverrides` and `Skill` tool input use names; plugin Skills are `plugin:name`. With the store plugin, the hooks should accept only `mago-verified:*` names and refuse everything else.
4. **Project settings are hostile input.** They can disable hooks, re-enable overridden Skills and add their own hooks; in `-p` mode the workspace trust dialog is skipped. Only managed settings hold.
5. **Bash blocking is best-effort**, as on Pi. The strong guarantees are the listing and the structured tools.
6. **Managed settings location.** Linux reads `/etc/claude-code/managed-settings.json`; `CLAUDE_CODE_MANAGED_SETTINGS_PATH` was not honoured. Installing means admin rights or MDM.

## Open questions

- How a managed setup installs and enables the store plugin (`enabledPlugins`, a local marketplace), and whether `disableSideloadFlags` is needed to stop `--plugin-dir` adding other plugin Skills.
- Whether interactive sessions reload Skills when files change (a file watcher would change the snapshot finding). This spike used `-p` only.
- Subagents: whether they see the same listing and whether `PreToolUse` fires for their tool calls.
- Directory-scoped Skills (nested `.claude/skills`), `--add-dir` Skills and Skills in plugins installed by the user, under `strictPluginOnlyCustomization`.
- macOS managed settings path, and whether `--safe-mode` keeps managed hooks as it keeps managed settings.
