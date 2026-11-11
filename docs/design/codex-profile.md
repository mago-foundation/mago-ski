# Design: the mago-ski Codex profile (0.4.0, streams 2 and 3)

Status: v1, for Goldfish review. This design replaces commits 2–4 of `codex-gate-findings.md`. Commit 1, the security commit, is already merged and stays.

## Problem

The 0.4.0 goal was "Codex, full". A research spike against Codex `rust-v0.166.0`, its source and the real binary, found that this is not achievable inside Codex. The spike's report is in `docs/spikes/codex-full-research.md`, which this work adds from `/var/tmp/spike-codex-full/REPORT.md`.

Two routes are invisible to every hook:
- a Skill picked from Codex's menu, or sent as structured input by an IDE or app-server client;
- hooks that fail open on a crash, a timeout or a kill.

Codex also has no admin allowlist of Skill folders. A Codex change upstream would close these gaps, and the product owner judged that unrealistic.

The product decision is to enforce everything Codex lets an administrator control, and to document plainly, as a deployment guide, what Codex's design leaves to the organisation. This is the **mago-ski Codex profile**.

The spike also found controls the gate does not use yet. `/etc/codex/managed_config.toml` outranks user config, project config, profiles and `-c`. With it the gate can:
- switch off bundled, cloud and plugin Skills;
- keep Skill descriptions out of the prompt.

`deny_read` does block sandboxed shell reads, which earlier text doubted.

A Goldfish review of the remaining adapter design found one HIGH issue in the merged adapter: an admin Skill named by its digest folder. It recommends dropping the precise name reader.

## Decisions

### C1. Two managed files

`codexManagedConfigToml(input)` is new, in `src/gate/adapters/codex-requirements.ts`, beside `codexRequirementsToml`. It generates `/etc/codex/managed_config.toml`:

```toml
# mago-ski Codex profile (generated). Evidence: codex-cli 0.166.0 / Linux.
project_root_markers = []

[skills]
include_instructions = false

[skills.bundled]
enabled = false

[cloud.skills]
enabled = false
```

- **`project_root_markers = []`** limits the repo scan to the working directory. Its effect is stated in the guide.
- **Shadow mode** gets the same file. These settings do not block anything; they remove sources.
- **Verification.** Every key is verified against `rust-v0.166.0`, with the source lines cited in the generator's comment, as the existing file does.

`codexRequirementsToml` changes as follows:
- **The pinned features** are `hooks = true`, `plugins = false`, `remote_plugin = false`, `apps = false`, `executor_capability_discovery = false` and `executor_capability_discovery_v2 = false`. Before, the last two were not pinned.
- **The header comment** states the C6 limits and nothing outdated. The stale `deny_read` text goes.
- **`deny_read`** stays for the roots listed in `userSkillRoots`. Its comment now says it blocks sandboxed shell reads, but does not hide the catalog or stop mention injection.

### C2. Adapter fixes in the merged Codex adapter

These go in `src/gate/adapters/codex.ts`.

1. **Digest-named admin Skills (review H1).** `findSkills` maps every admin entry under two keys:
   - its directory name, lower-cased;
   - `basename(realpath(<admin>/<n>)).toLowerCase()`, the digest folder name Codex uses for a Skill without a `name:` line.

   Both keys map to `n`, so `$<digest>` is asked as `n`, and is blocked once `n` is no longer installed. The existing tests gain a digest-mention row.
2. **Removed names never ask (review M1).** A token in `removed` that is not a current admin key gets NOT_ADMIN. It is never sent to the service. This replaces X1's T3. A name in `removed` that is linked again is handled by T2.
3. **No precise reader (review recommendation 3).** Commit 3 of `codex-gate-findings.md` (X2, Y3) is dropped. There is no `known` / `unknown` split. The wide rule stays, using `found || incomplete`. On a machine with the profile, bundled Skills are off, so `found` is false unless a user or repo Skill exists. Bare `$name` mentions of admin Skills are then asked and work.

   Where `found` is true, the existing MASKED block applies, and the guide tells organisations to keep repos free of `.agents/skills`.

### C3. Removed names (commit 2 of the earlier design, simplified)

This is X4/Y4 with two changes:
- **What is recorded.** The service records the Skill name **and** its current digest folder name in `<managedDir>/.mago-ski-removed-names.json`, written before the link is removed. The adapter treats both as removed.
- **No eviction (review L1).**
  - The file holds at most 8192 entries, and the adapter reads at most 1 MiB.
  - When the cap is reached, the service still removes the link and logs a `removed-names-full` warning in `status`.
  - The admin prunes the file with a new admin command, `prune-removed`, which drops names no longer present in the trust store's revocation list. The CLI exposes it as `mago-ski gate prune-removed --host codex`.

  Revocation never fails because of this file.

Everything else in Y4 stands: write order, install edits, the dot-entry filter, and the test changes.

### C4. Install-time name check, narrow (replaces X5)

**At install.** The service refuses a Codex install unless the published `SKILL.md`'s frontmatter has:
- exactly one top-level line `name: <skill_name>`, plain ASCII and unquoted, equal to the install name;
- no other line with a top-level `name` key.

The refusal is `SKILL.md must start its frontmatter with one plain line "name: <name>" so every host names it the same`.

**Testing the check.** The check is a small pure function, `plainNameLine(bytes): string | null`. It is tested against the existing `serde_yaml` oracle corpus. For every file it accepts, Codex's name must equal the name the check found.

**Existing installs.** Reconcile checks existing Codex installs with the same function. A mismatch is reported in `status` as `name-mismatch: <names>`, and `gate doctor` fails on it. Existing installs are not removed automatically, because uninstalling approved Skills on upgrade would be destructive. The digest key from C2.1 already closes the bypass for them.

The check applies only to instances whose host is `codex`. The service learns the host from a new optional `host` field in its config, which `gate init` sets.

### C5. `gate init --host codex`

This depends on stream 1, `gate-cli.md`:
- It writes both managed files (C1). The ownership manifest (G5) covers both.
- **`userSkillRoots`** come from `--user-home DIR`, which can be repeated. For each home, the roots are `<home>/.codex/skills`, `<home>/.codex/skills/.system` and `<home>/.agents/skills`.
  - With no `--user-home`, the roots are every home in `/etc/passwd` with uid 1000 or above and a login shell, listed in the plan for the admin to see.
  - `--no-deny-read` skips them.
- **Enforce mode** is allowed for Codex. G9's refusal is removed. The CLI prints one line: `Codex enforcement depends on organisation controls; read docs/hosts/codex.md before enabling enforce`.
- **`gate doctor`** for Codex also checks:
  - `managed_config.toml` matches the generator output;
  - no `.agents/skills` or `.codex/skills` exists in any listed home's root (WARN);
  - `codex --version` is 0.166.x, or WARN `untested Codex version`.

### C6. What is enforced, and the residuals

**With the profile in enforce mode,** the following are blocked or closed:
- non-admin Skills from plugins, cloud, executor discovery and bundled `.system` (not loaded);
- Skill descriptions (not injected);
- typed `$name` and linked mentions of anything that is not an approved admin Skill (blocked by the hook, from the merged commit 1, plus C2);
- shell reads of the listed user Skill roots (refused by the sandbox);
- approved Skills that changed, expired or were revoked (blocked, and uninstalled on revoke);
- digest mentions and removed names (blocked, C2 and C3).

**Codex's design leaves these to the organisation.** The guide lists them with the organisation-side control:

| Residual | Organisation control |
|---|---|
| A Skill picked from Codex's menu, or sent as structured input by an IDE or app-server client, bypasses hooks | Allow only the managed Codex binary and approved clients, through MDM or EDR execution control, and block `codex app-server` |
| Hooks fail open on a crash, timeout or kill | The same execution control. The decision log shows the missing decisions |
| A user can run their own Codex binary or `codex app-server`, which ignores managed files | Execution control |
| A repo `.agents/skills` or `.codex/skills` folder is listed, and can be picked from the menu | Require the mago-ski GitHub Action check on repositories, and keep agent working folders free of unapproved Skills |
| Start-up environment tricks (`.env` HOME, a symlinked `CODEX_HOME`) | An admin-owned `CODEX_HOME`, or execution control |

### C7. Tests

- **Generators.** Golden tests for both generators, including a scoped `@` path (stream 1 G3).
- **Adapter.**
  - A digest mention is asked as the name.
  - A digest mention after uninstall is blocked.
  - A removed name is blocked without asking.
  - A bare `$name` is asked when no non-admin Skill exists.
- **Service.**
  - Removed names hold both name and digest, are written before the unlink, and are not evicted.
  - `prune-removed`.
  - The install name check, with refusals.
  - Reconcile reporting `name-mismatch`.
- **Name check.** `plainNameLine` is run against the oracle corpus, with a committed fixture generated from `/var/tmp/review-codex-scratch/yamlprobe`. The generator is committed under `tests/fixtures/codex-names/generator/`.
- **Live tests** (`tests/live/codex-gate.live.ts`):
  - with both managed files, bare `$approved-skill` is served;
  - a planted `.system` Skill is not loaded;
  - `$<digest>` after revoke is blocked.

### C8. Documentation

The documentation subagent writes these from the planner's notes:
- the enforcement guide `docs/hosts/codex.md`;
- the README row;
- `docs/capabilities.md`;
- corrections to `docs/spikes/codex-gate-live.md`;
- `docs/spikes/codex-full-research.md`, from the spike report;
- the CHANGELOG.

## Alternatives considered

- **Upstream Codex change** (`[skills] allowed_roots`, `hooks.fail_closed`). Rejected by the product owner as unrealistic.
- **A patched Codex build.** Rejected: it means maintaining a fork.
- **The precise name reader** (`codex-gate-findings.md` commit 3). Dropped, per the review. It is the only piece that could let a non-admin Skill through by misnaming it, and the profile makes it unnecessary on a clean machine.

## Implementation plan

1. **Branch.** `feat/0.4.0-codex-profile`. C2, C3 and C4's service part do not depend on stream 1, and can be built now. C5 lands after stream 1 merges.
2. **Order:** C2 (adapter fixes, with tests), then C1 (generators), C3, C4, and C5 (after stream 1). Live tests last.

## Decisions (v2)

These decisions resolve the v1 Goldfish review. Where they differ from v1, v2 wins.

### D1. The menu route, and the true control (HIGH-1)

- **The route.** Codex's Skill picker runs inside the managed binary and builds structured input that hooks never see. It offers the **listed** Skills. Execution control does not close this.
- **The control** is that no non-admin Skill is listed:
  - **Homes.** `gate doctor` **FAILs**, not WARNs, when any listed home has a `SKILL.md` under `.agents/skills`, `.codex/skills` or `$CODEX_HOME/skills`, or has a `.codex/skills/.system` folder (D3).
  - **Repositories.** They must pass the mago-ski GitHub Action as a required check, and the agent should be started only in checked-out working copies.
- **Admin Skills picked from the menu** skip the per-use check. The service therefore keeps every installed Skill current, by a periodic reconcile (D6), so a listed admin Skill is always VERIFIED.
- **The C6 table**, row 1 changes. A menu pick of a non-admin Skill is a residual. It is closed by keeping homes and repos free of non-admin Skills (`doctor` and the GitHub Action), not by execution control.
- **Live test.** The TUI is driven through a pseudo-terminal: pick from the menu, and check that only admin Skills are offered under the profile. If the harness cannot drive the TUI, the live test records the route as untested, and the guide says so.

### D2. Keying admin Skills by the name Codex gives them (HIGH-2)

In `findSkills`, for each admin entry `e` (dot-entries skipped, which adds the Y4 dot filter to `listRoot`):
1. `real = realpath(join(adminRoot, e))`. A failure sets `incomplete`.
2. `digestKey = basename(real).toLowerCase()`.
3. `nameKey = plainNameLine(<real>/SKILL.md bytes)`. The bytes are read with `readRegularFile`, at most 64 KiB. A result of `null`, meaning not plain, sets `incomplete`.
4. The keys `e.toLowerCase()`, `digestKey` and `nameKey.toLowerCase()` all map to `e`. On a collision, the directory-name key wins, and a different admin entry claiming the same key sets `incomplete`.

C4's sentence "the digest key already closes the bypass" is replaced by: "Existing installs are covered by D2, which keys each admin Skill by its directory, its digest folder and its plain `name:`. A Skill without a plain name line sets the walk incomplete, which blocks bare mentions."

### D3. Stale `.system` folders (MEDIUM-3)

- `gate init --host codex` moves each listed home's `.codex/skills/.system` to `.system.mago-ski-bak-<UTC>`. It is printed in the plan, and `--keep-system` skips the move.
- Codex recreates the folder only when bundled Skills are on.
- `gate doctor` FAILs when a listed home has `.system`, because the profile turns bundled Skills off.

### D4. `plainNameLine`, a whitelist (MEDIUM-4)

`plainNameLine(bytes: Buffer): string | null` returns the name only when all of the following hold, and `null` otherwise:
- **The bytes.** They are valid UTF-8 with no BOM. Every byte inside the frontmatter is ASCII, and contains no tab and no `\r` other than one at a line end.
- **The lines.** They come from splitting on `\n`, then removing one trailing `\r`.
- **The frontmatter.** It is the lines strictly between a first line exactly `---` and the next line exactly `---`.
- **Each frontmatter line** is either empty, or `key: value`:
  - `key` matches `^[a-z][a-z0-9_-]*$` and sits at column 0;
  - one space follows the colon;
  - `value` matches `^[A-Za-z0-9 ._/,()-]*$`.

  No other line forms are allowed: no indentation, quotes, flow, anchors, tags, `<<`, `...` or `%`.
- **The `name` key.** Exactly one line has it. Its value passes `validateSkillName`, and is not one of `null`, `Null`, `NULL`, `~`, `true`, `false`, `yes`, `no`, `on`, `off`, or a number.
- **The `description` key.** Exactly one line has it, and its value is not empty, because Codex rejects Skills without a description.

**Oracle.** The test oracle is Codex's own parser: a small Rust harness against the `codex-skills` crate at the `rust-v0.166.0` `Cargo.lock`, which calls `parse_skill_frontmatter_metadata`. The harness is committed under `tests/fixtures/codex-names/oracle/`. A committed corpus records each document with the harness's output.

The test asserts that every document `plainNameLine` accepts has Codex name equal to the returned name. Refusing is always allowed.

The corpus includes:
- the cases the reviewer listed (null spellings, BOM, a bare `\r`, CRLF, a `name:` line inside a block scalar, duplicate keys, quoted names);
- the H3–H6 shapes from the earlier reviews.

### D5. `project_root_markers = []` (MEDIUM-5)

The effect is confirmed. The repo Skill scan covers the working directory only, and a repository's `.codex/config.toml` is not loaded when Codex starts in a subdirectory.

The guide states this as a side effect of the profile, and a live test covers it.

### D6. Removed names, and keeping installs current (MEDIUM-6, LOW-7)

- **Where the block happens.** Codex reads a Skill's body when it injects the Skill (`ext/skills` host outcome). Removing the managed link is therefore the actual block. The removed-names file only gives a clear message and keeps the name blocked if a link reappears. A live test confirms it: revoke during an open session, then mention the Skill. Nothing is injected. If the test shows a body served from a cache, this becomes a HIGH finding and the design is revisited.
- **File schema.** Canonical JSON `{ "type": "mago-ski.gate.removed-names.v1", "entries": [{ "name", "digest", "kind": "revoked" | "uninstalled", "at": "<ISO>" }] }`, at most 8192 entries, read limit 1 MiB.
- **Pruning.** `prune-removed` (admin command `{ v: 1, cmd: 'prune-removed', older_than_days: number }`, default 90, minimum 7) drops entries older than that age. Because blocking rests on the link, pruning only loses the message.
- **When the file is full,** the service evicts the oldest entry and reports `removedNames: { full: true, evicted: <n> }` in `status`. `gate doctor` WARNs on it.
- **Periodic reconcile.** The service runs `reconcileOnce` every 60 s, whether or not an inbox is configured. Installed Skills whose verdict is no longer VERIFIED are uninstalled, including expired ones. The menu route therefore never offers a stale admin Skill.
- **Writes.** Uninstall and reconcile write the entry before `hostLink(name, null)` (`service.ts:602` and `:527`). Install removes the name's entries after publish.
- **No service ask.** A removed name that is not a current admin key is blocked by the adapter without asking the service. The decision log therefore has no record of that block, and the guide says so (LOW-7 accepted).

### D7. Readiness details

- **Adapter loader.** The removed-names path is `join(cfg.adminRoot, '.mago-ski-removed-names.json')`.
  - Missing means empty. Unreadable or malformed sets `incomplete`.
  - It is read with `readRegularFile(…, 1 MiB)` and `parseStrictJson` with limits `{ maxBytes: 1 MiB, maxDepth: 4, maxMembers: 8192 + 4 }`.
  - The block message is NOT_ADMIN, as merged.
- **Install check.** It runs on the **staged** tree, after `installSkill` and before publish, against `<generationsDir>/<name>/<hex>/SKILL.md`. Reconcile checks the same published path. `status` reports `nameMismatch: string[]`.
- **Host field.** `GateServiceConfig.host?: 'claude-code' | 'codex'`. `gate init` always sets it. When it is absent, the service treats the instance as Codex if `managedDir` ends with `/codex/skills`. `doctor` FAILs when it is absent.
- **The new generator.** `codexManagedConfigToml(): string` takes no input and returns the C1 text. Its output path is `/etc/codex/managed_config.toml`.
- **Homes and `CODEX_HOME`.** `--user-home DIR` and `--codex-home DIR` can both be repeated. `--codex-home` covers a non-default `CODEX_HOME`. The guide says the profile covers only listed homes and default or listed `CODEX_HOME`s.
- **Before C2.1 merges,** the coder confirms in `ext/skills/src/loader/host.rs` that the default name comes from the realpath's basename, and cites the line. A live test confirms `$<digest>` is the name Codex gives a Skill without a `name:` line.
- **Tests.** C7 plus: a name different from the install name; null names; BOM; a bare `\r` and CRLF; a stale `.system`; `project_root_markers` from a subdirectory; the menu route (D1); a full removed-names file; prune; reinstall with the same and a new digest.
