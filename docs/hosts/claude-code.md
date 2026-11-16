# Claude Code host (the company gate)

The company gate is a root service that installs approved Skills into an admin-owned folder and answers Claude Code's hooks each time a Skill is used. It is set up with the `mago-ski gate` commands. Linux only. Tested with Claude Code 2.1.318 in non-interactive (`claude -p`) sessions ([live test](../spikes/claude-code-gate-live.md)); the managed settings need Claude Code 2.1.296 or newer.

Codex has its own guide: [codex.md](codex.md).

## What you need

- Linux with systemd, and root.
- Node.js and the `mago-ski` package installed system-wide, in root-owned folders. `gate init` refuses a per-user install (nvm, volta) and any package, node or host binary a user could edit, because an editable hook would let a user bypass the gate.
- The real `claude` binary, root-owned.
- Your organisation's root fingerprint (printed by `mago-ski root init`), its `trust-root.json` and `revocations.json`, and a certificate for each Skill you want to install.

## Set up

```bash
# 1. See what would be written. Writes nothing, needs no root.
mago-ski gate init --host claude-code --root-fingerprint sha256:… --print

# 2. Write it. The default mode is shadow: decisions are logged, nothing is blocked.
sudo mago-ski gate init --host claude-code --root-fingerprint sha256:…

# 3. Start the service (gate init prints these commands; it never runs systemctl itself).
sudo systemctl daemon-reload && sudo systemctl enable --now mago-ski-gate@claude-code

# 4. Give the gate the organisation's trust documents.
sudo mago-ski gate trust --host claude-code --trust-root trust-root.json --revocations revocations.json

# 5. Install an approved Skill version.
sudo mago-ski gate install --host claude-code skills/docs-helper --certificate docs-helper.cert.json

# 6. Check the whole installation.
sudo mago-ski gate doctor --host claude-code
```

`gate init` writes, all root-owned:

| File or folder | Purpose |
|---|---|
| `/etc/mago-ski/gate/claude-code.json` | The instance config: mode, root fingerprint, host binaries, folders |
| `/etc/mago-ski/gate/claude-code-hook.json` | What the hook reads to find the gate |
| `/etc/mago-ski/gate/claude-code.manifest.json`, `shared.manifest.json` | Which files mago-ski wrote, so a later `gate init` can tell its own files from yours |
| `/etc/systemd/system/mago-ski-gate@.service` and `mago-ski-gate@claude-code.service.d/paths.conf` | The service unit |
| `/etc/claude-code/managed-settings.json` | Claude Code's managed settings: the hooks, and in enforce mode the locks |
| `/etc/claude-code/.claude/skills/` | The managed Skill folder. Each installed Skill is a link to an immutable copy |
| `/var/lib/mago-ski/gate/claude-code/` | The gate's state, the published Skill versions and the decision log |

If one of the host files already exists and mago-ski did not write it, `gate init` stops. `--force` moves the existing file aside to `<file>.mago-ski-bak-<time>` and replaces it.

## Shadow first, then enforce

Run in shadow mode until the decision log shows only what you expect to be blocked. Then:

```bash
sudo mago-ski gate init --host claude-code --root-fingerprint sha256:… --mode enforce
sudo systemctl daemon-reload && sudo systemctl restart mago-ski-gate@claude-code
```

Enforce mode applies Claude Code's managed locks to **every user of this machine**: project Skills, user Skills and Claude Code's bundled Skills are no longer listed.

## What it does

| Situation | Enforce mode | Shadow mode |
|---|---|---|
| A Skill installed by the gate, through the Skill tool or `/name` | Allowed; the hook asks the gate each time | Allowed |
| A project, user or bundled Skill | Not listed by Claude Code and cannot be loaded (managed lock) | Listed and runs; nothing is blocked |
| A Skill copied into the managed folder without `gate install` | Claude Code lists it; the hook denies it (`NO_CERTIFICATE`) | Logged |
| An installed Skill whose approval is revoked | Removed from the managed folder by the gate. A session that was already open is denied at the next use; the session itself keeps running | Removed (a revocation uninstalls in every mode) |
| An installed Skill whose approval expired, or whose files no longer match | Blocked, and hidden at the next check (at most about 60 seconds later) | Logged |
| The gate service is down or cannot verify | Blocked: `mago-ski could not verify this Skill; it is blocked until verification works.` | Allowed |
| A Skill folder that contains a second `SKILL.md` below the top level | `gate install` refuses it, because the nested Skill would be loaded without being approved | Refused at install too |

A blocked user sees `This Skill is not approved by your organisation (mago-ski: <verdict>). If it was updated, restart the session to use the new version.`

Every decision is written to the gate's decision log, which only root can read.

## Keeping it current

- **New trust root or revocation list:** `sudo mago-ski gate trust --host claude-code --trust-root FILE --revocations FILE`. A revocation takes effect when the gate receives it.
- **An inbox instead:** create the instance with `gate init --inbox DIR` and let your distribution drop `trust-root.json` and `revocations.json` there (root-owned, not group- or world-writable). The gate reads the folder about once a minute, or at once with `sudo mago-ski gate refresh --host claude-code`.
- **Remove a Skill:** `sudo mago-ski gate uninstall --host claude-code NAME`.
- **State:** `sudo mago-ski gate status --host claude-code` shows the mode, readiness, trust and when the revocation list expires. `gate doctor` prints PASS, FAIL, SKIP or WARN for each check and exits 1 on a FAIL.

## Limits

- **Linux only.** macOS and Windows are not supported by the gate.
- **Tested on Claude Code 2.1.318, non-interactive sessions only.** Whether an interactive session reloads its Skill list when the managed folder changes, and whether a subagent's Skill calls reach the managed hook, are not tested yet.
- **Instructions already read stay.** The gate cannot remove a Skill's text from a session that has already loaded it. A revoked Skill is blocked at its next use, not unread.
- **After a revoke, the reason shown is `NO_CERTIFICATE`,** not `REVOKED`, because the gate has already removed the Skill. The block is correct; the wording is not.
- **A user who can run a different Claude Code binary,** or change the machine's managed settings, is outside what the gate controls. Use your organisation's execution control for that.
- **Root recovery and freshness are not applied by the gate yet.** The gate keeps the root fingerprint it was given at `gate init`, and does not read root events or timestamps. A revoked root key is therefore not noticed by the gate. After a root rotation there is no supported command to move a gate to the new root: `gate init` with the new fingerprint is accepted, but the gate then reports its stored trust state as corrupt (`state-corrupt`) and refuses the new documents, and in enforce mode every Skill is blocked. Plan a root rotation with this in mind until the gate supports root events.
- An approval records who approved which exact version. It does not say that a Skill is safe.
