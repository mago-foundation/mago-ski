# Codex host (the company gate and the mago-ski Codex profile)

The company gate is a root service that installs approved Skills into an admin-owned folder and answers Codex's hooks when a Skill is mentioned. For Codex it also writes two managed files, together called the **mago-ski Codex profile**, that switch off every Skill source an administrator can switch off.

Read this page before you enable enforce mode. Codex has routes that no hook sees, so **part of the enforcement is your organisation's job, not mago-ski's**. The section [What Codex leaves to your organisation](#what-codex-leaves-to-your-organisation) lists them.

Linux only. The profile was verified against Codex 0.166.x; `gate doctor` warns on any other version. Claude Code has its own guide: [claude-code.md](claude-code.md).

## The main limit, first

Codex lists every Skill folder it finds in a user's home and in the working folder. A Skill picked from Codex's menu, or sent as structured input by an IDE or app-server client, reaches the model **with no hook involved**. mago-ski can detect such a Skill folder. It cannot prevent the pick inside Codex.

So the control is that no Skill other than the administrator's is there to be listed:

- `gate doctor` FAILs when a listed home has a Skill folder. Run it on a timer.
- Repositories should require the [mago-ski GitHub Action](github-action.md) check.
- `gate init --lock-user-skill-folders` can make the user Skill folders empty and immutable (see below).
- The decision log has no record for a menu-picked Skill, which an audit can notice.

This route has not been tested by driving Codex's menu. The claims on this page about blocking are made for typed and linked mentions.

## What you need

- Linux with systemd, and root.
- Node.js and the `mago-ski` package installed system-wide, in root-owned folders. `gate init` refuses a per-user install and any package, node or host binary a user could edit.
- The real `codex` binary, root-owned.
- Your organisation's root fingerprint, its `trust-root.json` and `revocations.json`, and a certificate for each Skill you install.

## Set up

```bash
# 1. See what would be written and which homes are covered. Writes nothing, needs no root.
mago-ski gate init --host codex --root-fingerprint sha256:… --print

# 2. Write it (shadow mode by default).
sudo mago-ski gate init --host codex --root-fingerprint sha256:…

# 3. Start the service.
sudo systemctl daemon-reload && sudo systemctl enable --now mago-ski-gate@codex

# 4. Give the gate the organisation's trust documents.
sudo mago-ski gate trust --host codex --trust-root trust-root.json --revocations revocations.json

# 5. Install an approved Skill version.
sudo mago-ski gate install --host codex skills/docs-helper --certificate docs-helper.cert.json

# 6. Check the whole installation.
sudo mago-ski gate doctor --host codex
```

### Which homes the profile covers

The profile covers only the homes it is told about:

- `--user-home DIR` (repeatable) names a user's home. With none, `gate init` takes every home in `/etc/passwd` with uid 1000 or above and a login shell, and prints the list in its plan.
- `--codex-home DIR` (repeatable) names a non-default `CODEX_HOME`.

For each listed home, `gate init`:

- adds `<home>/.codex/skills`, `<home>/.codex/skills/.system` and `<home>/.agents/skills` to `deny_read`, so sandboxed shell commands cannot read them (`--no-deny-read` leaves this out);
- moves an existing `.codex/skills/.system` folder (Codex's bundled Skills) to `<home>/.codex/mago-ski-backup/system-<UTC>`, because the profile turns bundled Skills off.

When Codex runs with a `HOME` or `CODEX_HOME` that is not listed, the hook cannot tell where that user's Skills are, so it blocks every plain `$name` mention.

### Optional: lock the user Skill folders

```bash
sudo mago-ski gate init --host codex --root-fingerprint sha256:… --lock-user-skill-folders
```

In every listed home this makes `~/.agents`, `~/.agents/skills` and `~/.codex/skills` empty, root-owned and immutable (`chattr +i`), so a user cannot add a Skill there. The command stops if the filesystem cannot set the attribute. The lock does **not** cover:

- a `CODEX_HOME` the user points somewhere else;
- repository folders;
- a user renaming `~/.codex` and creating a new one. `~/.codex` itself cannot be locked because Codex writes there. `gate doctor` detects the new folder.

### What gate init writes

Besides the files every gate instance gets (see the [Claude Code guide](claude-code.md#set-up), with `codex` in place of `claude-code`):

| File | What it does |
|---|---|
| `/etc/codex/requirements.toml` | Turns hooks on and pins plugins, remote plugins, apps and executor capability discovery off; registers the gate's hooks; carries `deny_read` for the listed Skill roots |
| `/etc/codex/managed_config.toml` | Turns off bundled Skills and cloud Skills, keeps Skill descriptions out of the prompt, and sets `project_root_markers = []` |
| `/etc/codex/skills/` | The managed Skill folder. Each installed Skill is a link to an immutable copy |

`/etc/codex/managed_config.toml` outranks user config, project config, profiles and `-c`. Both files are written in shadow mode too: they remove Skill sources, they do not block anything.

`project_root_markers = []` has a side effect: Codex scans only the working folder for repository Skills, and does not load a repository's `.codex/config.toml` when started in a subfolder.

## Skills must be named plainly

Codex names a Skill from its `SKILL.md` frontmatter. `gate install` therefore refuses a Skill unless its frontmatter:

- has exactly one top-level line `name: <name>`, unquoted, in plain ASCII, equal to the install name;
- has exactly one non-empty `description:` line;
- uses only plain `key: value` lines (no quotes, indentation, anchors or other YAML forms).

The refusal reads `SKILL.md must start its frontmatter with one plain line "name: <name>" so every host names it the same`. `gate install` also refuses a folder that contains a second `SKILL.md` below the top level.

## What it does

With the profile in enforce mode, for listed homes and listed `CODEX_HOME`s:

| Situation | Result |
|---|---|
| Skills from plugins, the cloud, executor discovery and Codex's bundled `.system` folder | Not loaded |
| Skill descriptions | Not put into the prompt |
| A typed `$name` for an installed, approved Skill, when no other Skill folder is present | Checked by the gate and allowed |
| A typed `$name` or a linked mention of anything that is not an installed, approved Skill | Blocked by the hook |
| A typed `$name` while a user or repository Skill folder exists, or the hook could not finish looking | Blocked: `A Skill with this name also exists outside your organisation's approved Skills, so a plain mention is blocked. Mention the approved Skill by its link, or remove the other Skill.` |
| A linked mention, `[$name](/etc/codex/skills/name/SKILL.md)` | Allowed only when the link resolves to the current installed copy. The text of the mention never selects the Skill |
| A plugin-namespaced mention, `$ns:name` | Blocked |
| An installed Skill that is revoked | Uninstalled when the gate receives the revocation, in every mode. Its name stays blocked |
| An installed Skill that expired, no longer matches, has a nested `SKILL.md` or a name that no longer matches | Hidden at the next check |
| Sandboxed shell reads of the listed user Skill roots | Refused by Codex's sandbox (`deny_read`) |
| The gate cannot be reached, or cannot verify | Blocked: the hook fails closed |
| The trust documents are expired, missing or rolled back | Every installed Skill is hidden until trust is valid again, and the decision log records it |

The hook looks for repository Skill folders in the working folder and every parent folder, while Codex (with the profile) scans only the working folder. A Skill folder in a parent folder therefore blocks plain mentions without Codex loading it.

In shadow mode nothing is blocked or hidden, except that a revocation still uninstalls. The decision log records what would have been blocked, hidden (`would-hide`) or uninstalled (`would-uninstall`).

### How quickly a change takes effect

- **A revocation** takes effect when the gate receives it: `gate trust` and `gate refresh` re-check every installed Skill at once.
- **An expiry** takes effect at the next periodic check, at most about 60 seconds later (longer while an admin command is running).
- **While the service is down** nothing is re-checked. Typed uses are blocked, because the hook cannot reach the gate. A menu pick of an already installed Skill during the outage is not checked. The unit restarts the service automatically, and `gate doctor` FAILs while it is down.

## What Codex leaves to your organisation

| What can still happen | Your organisation's control |
|---|---|
| A Skill folder created after a check is listed, and a menu pick of it reaches the model with no hook | Not prevented. Detected by `gate doctor` on a timer, by the GitHub Action on repositories, and by missing records in the decision log. Narrowed by `--lock-user-skill-folders` |
| A hook process crashes, times out or is killed, and Codex continues without it | Execution control (MDM or EDR). The decision log shows the missing decisions |
| A user runs their own Codex binary, or `codex app-server`, which ignores the managed files | Allow only the managed Codex binary and approved clients, and block `codex app-server` |
| A repository's `.agents/skills` or `.codex/skills` folder is listed and can be picked from the menu | Require the mago-ski GitHub Action check, and start the agent only in checked working copies |
| An untracked Skill folder in a working copy. The GitHub Action sees only committed files | The hook still blocks typed plain mentions there. The menu pick is the first row |
| Start-up tricks, such as a `.env` file that changes `HOME`, or a symlinked `CODEX_HOME` | An admin-owned `CODEX_HOME`, or execution control |

## Keeping it current

- **New trust root or revocation list:** `sudo mago-ski gate trust --host codex --trust-root FILE --revocations FILE`, or an inbox (`gate init --inbox DIR`, then `gate refresh`).
- **Remove a Skill:** `sudo mago-ski gate uninstall --host codex NAME`.
- **Removed names.** The gate records the Skills it removed in `/etc/codex/skills/.mago-ski-removed-names.json` (at most 4096 entries, oldest dropped first), so a removed name gets a clear block message. `sudo mago-ski gate prune-removed --host codex --older-than-days N` (default 90, at least 7) drops old entries. Blocking rests on the removed link, so pruning only loses the message. A removed name is blocked by the hook without asking the gate, so that block is not in the decision log.
- **Checks.** `sudo mago-ski gate doctor --host codex` FAILs on, among other things: a managed file that differs from what `gate init` writes, a Skill folder or a `.system` folder in a listed home, an installed Skill with a name mismatch, and a service that is down. It WARNs on an untested Codex version, on unlocked user Skill folders and on shadow mode.

## After a root rotation

The gate does not follow root events by itself. When your organisation has replaced its root key and re-signed its documents (`mago-ski root adopt`), move each gate to the new root:

```bash
sudo mago-ski gate init --host codex --root-fingerprint sha256:<new> --new-root    # with the same options as your original init
sudo systemctl daemon-reload && sudo systemctl restart mago-ski-gate@codex
sudo mago-ski gate trust --host codex --trust-root trust-root.json --revocations revocations.json
sudo mago-ski gate doctor --host codex
```

- `gate init` refuses a root fingerprint that differs from the installed one unless `--new-root` is given, so a mistyped fingerprint cannot switch roots by accident. `--print` shows the move without writing anything.
- Between the restart and `gate trust`, the gate has no documents for the new root. In enforce mode every Skill is blocked during that time, so run the commands together.
- Installed Skills do not need to be installed again. Their certificates were signed by approvers, and the approvers are kept.
- The old root's stored documents are kept and no longer used.

## Limits

- **Linux only.**
- **Verified on Codex 0.166.x.** The earlier live test ([results](../spikes/codex-gate-live.md)) ran 0.163.0 and 0.166.0 in non-interactive sessions, before the profile existed. Results for the profile's own live scenarios are not published yet, and the menu route has not been tested.
- **Instructions already read stay.** The gate cannot remove a Skill's text from a session that has already loaded it.
- **The gate does not follow root events or timestamps by itself.** It keeps the root fingerprint it was given, so a rotated or revoked root key is not noticed until an administrator moves the gate (see [After a root rotation](#after-a-root-rotation)). On a fleet, that means running the four commands on every machine.
- An approval records who approved which exact version. It does not say that a Skill is safe.
