# Codex gate: live test

Date: 2026-11-05. codex-cli 0.166.0 and 0.163.0 (Linux), Node 22.23.4.

**Question:** what does the E3 gate (`src/gate/`) enforce on the real Codex CLI, using exactly the requirements file, hook entry and service it ships? The Codex adapter (`src/gate/adapters/codex.ts`) and the requirements generator (`codex-requirements.ts`) marked several behaviours "unverified until the live test".

**Method:** [`tests/live/codex-gate.live.ts`](../../tests/live/codex-gate.live.ts) runs the real `codex exec` against the real gate service, the requirements file from `codexRequirementsToml`, and the production hook entry `src/gate/adapters/codex-hook.ts`, which Codex starts through `env -i`. Only the model is faked: a local Responses API (a custom `model_provider`) plays a script and records every request. That shows directly what Codex lists, which Skill bodies it injects (`<skill>` blocks), and what the model's shell calls return. Admin Skills are installed with the service's admin `install` command and revoked with `accept-trust`. The script runs in a private mount namespace with a temporary folder bind-mounted over `/etc/codex`. Codex reads `/etc/codex/requirements.toml` and admin Skills from `/etc/codex/skills`, which is the gate's `managedDir`.

```bash
sudo useradd --system --no-create-home mago-live                                  # once; optional
sudo MAGO_LIVE_USER=mago-live CODEX_BIN=/path/to/native/codex node tests/live/codex-gate.live.ts
```

`CODEX_BIN` must be the native binary (`node_modules/@openai/codex-linux-x64/vendor/<triple>/bin/codex`), because the gate allowlists the host by `/proc/<pid>/exe`. With `MAGO_LIVE_USER`, Codex and its hooks run as that unprivileged user, as in a real deployment; the gate service stays root. Codex then needs `bwrap` (bubblewrap) for its sandbox. The script needs root, is not part of `npm test`, and exits 1 if any expectation fails.

## Results

Each run has a fresh `HOME`, `CODEX_HOME` and project. Codex itself writes its bundled Skills (`imagegen`, `openai-docs`, `skill-creator`, `skill-installer`) into `~/.codex/skills/.system` at startup. Both versions gave the same results, as root and as `mago-live`.

| Scenario | Mode | Observed | Blocked by |
|---|---|---|---|
| Listing | enforce | The gate-installed Skill (a **symlink** in `/etc/codex/skills`) is listed, but so are the repo Skill, the user's own Skill and Codex's 4 bundled Skills | — |
| Linked mention `[$approved-skill](/etc/codex/skills/approved-skill/SKILL.md)` | enforce | Checked with the service, allowed; the body was injected | — |
| Bare mention `$approved-skill` | enforce | Blocked; the model was never called | Hook (by design, see finding 2) |
| `$project-skill` (repo Skill) | enforce | Blocked; the model was never called | Hook |
| `$user-skill` (`~/.codex/skills`) | enforce | Blocked; the model was never called | Hook |
| The model runs `cat .agents/skills/project-skill/SKILL.md` | enforce | `Command blocked by PreToolUse hook: … (mago-ski: NOT_ADMIN_ROOT)`; the body never reached the model | Hook (best-effort by design) |
| New session after a revoke | enforce | The auto-uninstalled Skill is not listed; its linked mention is blocked | Gate removed the link; hook |
| Gate service stopped, linked mention | enforce | Blocked; the model was never called | Hook (fail closed) |
| `$project-skill` | shadow | Allowed; the body was injected | — |

All 9 scenarios passed on both versions. Two properties the design documents claimed were reported as known gaps (findings 2 and 3).

## Findings

1. **Symlinked admin Skills work.** Codex follows the gate's `<managedDir>/<name>` links, and a linked mention whose path resolves to the admin `SKILL.md` is checked with the service and served.
2. **A bare `$name` for an admin Skill never works.** The adapter blocks a bare mention of an admin Skill whenever any non-admin Skill exists (MASKING in `codex.ts`), because Codex may resolve a same-name repo Skill instead. Codex creates its bundled Skills in `~/.codex/skills/.system` at every startup, so that condition is always true. In practice users must type the linked form `[$name](/etc/codex/skills/name/SKILL.md)`. The adapter's "on a clean machine" case does not occur. Possible fixes: exempt the bundled `.system` Skills, which Codex rewrites itself (risky, because the folder is user-writable), or have the gate rename admin Skills so they cannot collide.
3. **`deny_read` does not hide user Skills.** The requirements file's `[permissions.filesystem] deny_read` on the user's fixed Skill roots was meant to hide them from the catalog (cx0.2 on 0.163.0). Neither 0.163.0 nor 0.166.0 hid them: we tried four path forms (`root/**`, `root`, `root/*`, `root/<skill>/**`), as root and as an unprivileged user with bubblewrap. The Skill stays listed with its path, and using it is stopped only by the hooks. The user route is therefore hook-only and audit-level, like the repo route. Whether `deny_read` still blocks sandboxed reads was not isolated here, because the shell hook blocks those reads first. The comments in `codex-requirements.ts` and `codex.ts`, and the generated file's comment, are corrected.
4. **The hooks block on every route tested, and fail closed.** Repo, user and revoked Skills, a shell read of a repo `SKILL.md`, and every mention while the service is down were all refused. When the service is down, the adapter answers exit 2 with a reason within its own deadline, so Codex's fail-open on hook crashes or timeouts was not triggered.
5. **A blocked prompt is silent in `codex exec`.** It prints only `hook: UserPromptSubmit Blocked`, with no reason, and exits 0, so neither a user nor a script can tell what happened. The interactive TUI was not checked. A blocked shell call is different: its reason reaches the model as the tool output.
6. **`NOT_ADMIN_ROOT` reads like a verdict.** The block message says `This Skill is not approved by your organisation (mago-ski: NOT_ADMIN_ROOT)`, but `NOT_ADMIN_ROOT` is an adapter label, not one of the seven verdicts.

## Not covered

- **The interactive TUI.** Whether it shows the block reason is unknown.
- **Structured Skill selection** (`UserInput::Skill`, `skill://` mentions, app-server `skills/extraRoots/set`). The adapter already lists these as residuals no hook can see.
- **Startup-state tricks** (`.env` `HOME`, a symlinked `CODEX_HOME`). These are an accepted limit in `codex.ts`.
- **The sandbox's own enforcement of `deny_read`.**
- **macOS**, and Codex versions other than 0.163.0 and 0.166.0.
