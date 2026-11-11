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

## Decisions (v3)

These decisions resolve the v2 confirmation. Where they differ from earlier sections, v3 wins.

### E1. The menu route: detected, optionally narrowed, not prevented (HIGH-1)

- **The route.** A Skill folder an employee creates after a check is listed by Codex, and picking it from Codex's menu reaches the model with no hook involved. mago-ski can detect this, but cannot prevent it inside Codex.
- **C6 and D1 wording.** C6 and D1 are reworded to say exactly that. The guide puts this first, as the main residual.
- **Detection:**
  - `gate doctor` FAILs (D1), and can be run on a timer by the organisation.
  - The GitHub Action checks repositories.
  - The decision log has no decision for a menu-picked Skill, which an audit can notice.
- **Narrowing, optional: `gate init --host codex --lock-user-skill-folders`.** For each listed home:
  - it creates `~/.agents/skills` and `~/.codex/skills` as empty, root-owned `0755` folders, and sets the immutable attribute (`chattr +i`) on both and on `~/.agents`;
  - an immutable folder cannot be renamed, deleted or added to, even by its parent folder's owner.
  - A failure to set the attribute (an unsupported filesystem) stops the command.

  It is printed in the plan, and `doctor` WARNs when the lock is not present. The guide says the lock does **not** cover:
  - a `CODEX_HOME` the user points elsewhere;
  - repository folders.

  That is why repositories still need the GitHub Action check.

### E2. Reconcile fails closed, and runs in the queue (blockers 1 and 2)

- **When reconcile runs.** The periodic reconcile (every 60 s) runs inside `serial()`, the admin queue, like every admin command.
- **When trust is not ready, in enforce mode.** This covers an expired list or trust root, a clock moved backwards, and corrupt or missing state. Reconcile **hides** every installed Skill with `hostLink(name, null)`. The install record and its generation are kept. It writes a durable decision-log record of kind `reconcile`, with `{ action: 'hide-all', reason }`.
- **When trust is ready again,** reconcile re-links every installed Skill whose verdict is VERIFIED, and logs `{ action: 'restore', names }`.
- **Unreadable evidence** for one Skill (a `catch` at `service.ts:524` today) hides that Skill and logs it. It no longer skips the Skill.
- **In shadow mode,** reconcile hides nothing and logs what it would have hidden.
- **Logging.** Every uninstall or hide by reconcile is now a durable decision-log record, as well as the in-memory `autoUninstalled` list.

### E3. Nested Skill files (blocker 3)

- **At install,** an install refuses any tree with a file named `SKILL.md` (case-insensitive) other than the top-level one. The refusal is `the Skill contains another SKILL.md at <path>; a nested Skill would be loaded without being approved`.
- **At reconcile,** existing installs with such a file are hidden by reconcile and logged.
- **Hosts.** This applies to every host, because Claude Code also discovers nested Skills.

### E4. Keying every admin Skill (HIGH-2 a–c)

- **Collisions.** Two admin directory names that are equal ignoring case set `incomplete`.
- **Invariant.** Every admin entry maps its directory key, its digest key and its plain-name key, or sets `incomplete`. Any error reading `SKILL.md` sets `incomplete`: a throw, a file over 64 KiB, a non-regular file, or `EACCES`.
- **Digest key.** This is the 64-hex digest folder name, lower case, without `sha256:`.
- **Default name (HIGH-2c).** Before C2 merges, the coder reads the call site of `default_skill_name` (`ext/skills/src/loader/host.rs:396-407`) and the code that discovers each Skill's path. The aim is to establish whether the parent folder is the link name or the realpath's.
  - If it is the link name, the digest key is unnecessary and is dropped.
  - If it is the realpath's, the digest key stays.

  A live test settles it either way.

### E5. Whitelist corrections (MEDIUM-4)

- **Reserved words.** The `null`, `bool` and number list is compared case-insensitively. It is: `null`, `~`, `true`, `false`, `yes`, `no`, `on`, `off`, `y` and `n`.
- **Name shape.** A `name` value must start with a letter (`^[A-Za-z][A-Za-z0-9._-]*$`) and pass `validateSkillName`.
- **Boundaries.** The frontmatter boundaries follow Codex's `extract_frontmatter` (`skills/src/parser.rs:200-216`). The first line, trimmed, is `---`, and so is a later line, trimmed. The whitelist requires both to be exactly `---`, which is stricter.
- **Oracle corpus.** It includes documents that trigger Codex's repair step (`parser.rs:50-57, 98-180`), such as duplicate non-name keys and values with `: `, so that the oracle reflects the full parse path.

### E6. Smaller corrections

- **Removed-names size.** The cap is **4096 entries**. Each entry is about 160 bytes of canonical JSON, under the 1 MiB read limit. C7's "not evicted" and its prune test are replaced by D6.
- **`prune-removed`** runs inside `serial()`. `older_than_days` must be an integer of at least 7; otherwise the reply is `older_than_days must be at least 7`.
- **Install name check placement.** The check runs after `installSkill` stages the tree, and **before** `storeCertificate` and `hostLink` (`service.ts:592-593`). On failure, the staged generation is removed and nothing is linked.
- **No host field.** The install name check and the nested-file check run for every host, because both hosts name Skills from frontmatter. The `host` field and its fallback (D7) are withdrawn.
- **Status.** Reconcile's name-mismatch finding is reported in `status` as `nameMismatch: string[]`, and `doctor` FAILs on it. No automatic action is taken.
- **Guide (MEDIUM-5).** The guide also says the adapter scans every parent folder for repo Skills, while Codex scans only the working folder. A Skill folder in a parent folder therefore blocks bare mentions without being loaded by Codex.
- **Tests.** In addition to D7's list:
  - reconcile while trust is stale hides everything, and restores it later;
  - a directory-name case collision;
  - a `nameKey` read error;
  - a removed-names file with 4096 entries;
  - an install racing reconcile;
  - a nested `SKILL.md` refused, and hidden on reconcile;
  - the `--lock-user-skill-folders` plan, and its refusal when the attribute cannot be set.

## Decisions (v4)

These decisions resolve the v3 confirmation review. Where they differ from earlier sections, v4 wins.

### Terms

| Term | Meaning |
|---|---|
| `found` | The adapter's walk saw at least one non-admin Skill folder: a user root, a listed `CODEX_HOME`, or a repo folder from the working folder upward. |
| `incomplete` | The walk could not finish or could not key an admin entry (E4). It is treated like `found`. |
| MASKED | A bare `$name` mention while `found \|\| incomplete` is blocked, because Codex might resolve it to a non-admin Skill. |
| servable | An installed Skill whose verdict is VERIFIED, with no nested `SKILL.md`, and whose plain `name:` equals the install name. |

X1, T2 and the other X and Y items are in `docs/design/codex-gate-findings.md` (merged).

### F1. Restore uses "servable", not VERIFIED (blocker 1)

E2's restore re-links only **servable** Skills, and so does every reconcile pass. A Skill with a nested `SKILL.md` or a name mismatch therefore stays hidden after trust recovers.

Test: an install with a nested `SKILL.md` is hidden, trust goes stale and recovers, and the Skill is still hidden.

### F2. Admin Skills from the menu: the honest window (blocker 2)

D1's "always VERIFIED" is replaced by the following:
- **A revocation** takes effect when the gate receives it. `gate trust` and `gate refresh` reconcile at once, inside the same `serial()` call.
- **An expiry** takes effect at the next reconcile, at most 60 s later.
- **While the service is down,** nothing is reconciled. Links stay as they were, and the hook blocks typed uses, because the decision socket is unreachable. A menu pick of an installed Skill during the outage is not checked. The unit uses `Restart=always`, and `doctor` FAILs when the service is down.

The guide states all three.

The live test drives the TUI (D1): revoke during an open session, then pick the Skill from the menu, and check nothing is injected. If the harness cannot drive the TUI, the route is recorded as untested and the guide says so. The claim is then made only for typed mentions.

### F3. Linked mentions (blocker 3)

The merged adapter resolves a linked mention by path. F3 makes this explicit:
- The adapter takes `realpath` of the linked file.
- The mention is asked only when that realpath is `<real of a current admin entry>/SKILL.md`. Anything else is NOT_ADMIN: another generation, an uninstalled Skill's generation, or a hidden entry.
- The text of the mention never selects the Skill.

Tests cover a linked mention with an approved name and a path to an unlisted Skill, to an old generation, and to a hidden entry.

### F4. Unlisted homes (blocker 4)

C6's "typed `$name` … blocked" is qualified: **for listed homes and listed `CODEX_HOME`s**.

When the hook's own `CODEX_HOME` or `HOME` is not listed in the instance config, the walk sets `incomplete`, so bare mentions are blocked. The guide keeps the start-up tricks row.

Test: an unlisted `CODEX_HOME` makes a bare mention blocked.

### F5. Where `.system` goes (blocker 5)

- **The backup.** `gate init` moves `.codex/skills/.system` to `<home>/.codex/mago-ski-backup/system-<UTC>`, outside every Skill root.
- **`--keep-system`** is dropped, because `doctor` would FAIL on it.

Test: `gate init` on a home with `.system`, then `doctor`: the `.system` check passes.

### F6. Smaller decisions

1. **The digest key** is kept unconditionally. E4's "dropped if the link name" branch is removed. The live test still records which name Codex uses.
2. **The install check** reads `SKILL.md` from the generation path that will be linked: `<generationsDir>/<name>/<hex>/SKILL.md`. The generations tree is root-owned `0755` inside the service's own state. Only the root service writes there, so there is no writer race to test (missing test 11 rejected).
3. **The C6 table row 1** becomes: *"A Skill folder created after a check is listed, and a menu pick of it reaches the model with no hook. Detected by `doctor` on a timer, the GitHub Action and the decision log; optionally narrowed by `--lock-user-skill-folders`. Not prevented."*
4. **Shadow mode.**
   - Revocation uninstalls in every mode, as merged today.
   - The new actions run only in enforce mode: hide-all, uninstall on expiry, and hiding a nested or mismatched Skill.
   - In shadow mode they are logged as `would-hide` and `would-uninstall`.
5. **A non-whitelisted frontmatter line** in an installed Skill still sets `incomplete` (fail closed), and `nameMismatch` makes `doctor` FAIL (finding 6 rejected). New installs cannot reach this state, because install refuses non-plain names. A duplicate key of any kind makes `plainNameLine` return `null`.
6. **Pruning.** It is by age only (D6). The CLI is `mago-ski gate prune-removed --host codex --older-than-days N`. The `parseStrictJson` limit is `maxMembers: 4096 + 4`.
7. **The guide adds two residuals**, both covered by the menu-route row:
   - a user can rename `~/.codex`, taking the locked `skills` child with it, and create a new one. `~/.codex` itself cannot be locked, because Codex writes there. `doctor` detects the new folder.
   - the GitHub Action sees only committed files, so an untracked `.agents/skills` in a working copy is not seen by it. The adapter's `found` still blocks typed bare mentions there.
8. **More tests:**
   - dot-prefixed Skill folders in user and admin roots: whether Codex loads them (live) and that the adapter skips them;
   - `deny_read` through a symlink and a relative path (live);
   - plugin, cloud and executor Skills planted before the menu test (live);
   - each managed key's live effect (live);
   - mention-token boundaries such as `$a.b`, `$a-b` and `$a:b`;
   - shadow mode: reconcile hides nothing, and an unapproved mention is logged and not blocked.

   Differential fuzzing against the loader (missing test 9) is rejected. The loader takes the name from the same parser the oracle already calls.
