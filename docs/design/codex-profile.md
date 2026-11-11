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
