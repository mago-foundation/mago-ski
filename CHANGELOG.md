# Changelog

All notable changes to mago-ski are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/). Before 1.0, minor releases may change formats and commands.

## [Unreleased]

### Added

- Desktop GUI in English and Korean: a language switch in the header (system language by default, stored in `settings.json`), one message catalog, and README screenshots.
- Claude Code interception spike (`docs/spikes/`): which hooks and settings can enforce Skill approval on Claude Code, and the resulting adapter design.
- **Root recovery** ([spec](docs/spec/root-recovery-v1.md), now normative). Policy `mago.policy/v2` pins a recovery set (1-16 offline keys with a rotate and a revoke threshold) next to the root fingerprint. Recovery keys sign numbered root events in a root event log: `revoke` stops hosts trusting the root key, `rotate` replaces it (and optionally the recovery set or the timestamp key). A leaked root key no longer means editing every host's policy. Implemented in the CLI, the Pi host and the GitHub Action.
- **Freshness** (optional, in `mago.policy/v2`): a separate timestamp key signs a short-lived statement of the exact root event log, trust root and revocation list. A host fed old files stops trusting anything once the newest timestamp expires (24 hours by default, at most 7 days).
- Commands: `recovery init`, `root-events init | prepare-revoke | prepare-rotate | show | sign | append` (`show` and `sign` print what the event does; with `--policy` they check it is the next event of the published log), `timestamp sign`, `root adopt` (re-sign the trust documents with the new root after a rotate) and `policy check` (check a policy the way a host does, without writing host state).
- Host state `mago.host-state/v2`: root event progress per pinned root (rollback and fork detection, and whether the root was left revoked) and timestamp versions per timestamp key. Hosts keep writing v1 until they apply a root event or timestamp. Before writing, a host re-reads the state file and merges it, so processes sharing one state file cannot erase each other's progress.
- Live tests of the E3 gate with the real hosts (root, Linux; not part of `npm test`; `MAGO_LIVE_USER` runs the host as an unprivileged user):
  - Claude Code (`npm run test:live:claude-code`, [results](docs/spikes/claude-code-gate-live.md)): on 2.1.318 the gate's symlinked managed Skills load, the managed-settings locks hide project, user and bundled Skills, and the hooks deny planted, revoked and unverifiable Skills on both the Skill tool and `/name`.
  - Codex (`CODEX_BIN=… npm run test:live:codex`, [results](docs/spikes/codex-gate-live.md)): on 0.163.0 and 0.166.0 the hooks block repo, user, revoked and unverifiable Skills and fail closed. Two design assumptions did not hold: `deny_read` does not hide user Skills from Codex's catalog (the user route is hook-only), and because Codex always installs its bundled Skills, admin Skills work only through their linked mention, never a bare `$name`. The comments in `codex-requirements.ts` and `codex.ts`, and the generated requirements file's comment, are corrected.

- GUI administration rack, phase 1 ([spec](docs/spec/gui-admin-rack-v1.md); GUI PoC, not published): a 관리 (administration) tab with six fixed templates. *Approve a Skill version* works: IDENTITY → INSPECT → APPROVE → POLICY CHECK. The organisation is read only from the admin-owned pin `/etc/mago-ski/policy.json`; a role is recognised only by proof of possession of a key the pin's documents name; the key stays in the main process and is re-checked before every signature. The other five templates are shown for later phases.
- `approveSkill` accepts an already-loaded `approverKey` instead of `approverKeyPath` (exactly one).
- `approveSkill` options `expectName` (refuse a Skill whose signed name differs from the reviewed one), `outDir` (write `<outDir>/<signed name>.cert.json`) and `beforeSign` (awaited just before the certificate is written; a throw writes nothing).
- Engine: `loadPolicyRoot` (the root-event part of `loadPolicyTrust`, sharing one pure check), `TimestampRollbackError`, and typed `rollback` and `stateError` fields on trust failures. Messages are unchanged.
- GUI administration rack, phase 1.1 ([design](docs/design/gui-admin-hardening.md)): signing needs two native dialogs answered by a human (a review of the exact version, then the signature with everything it contains), with a 10 second cooldown after a cancel and a 120 second timeout. Disarm is synchronous, operations carry a key generation and run in a queue, and a pin change or a lost role disarms within about 5 seconds. A user-namespace hurdle and the macOS `/etc` mapping for the pin. The GUI keeps its own rollback memory (`admin-state.json`) so older trust roots, revocation lists and root event logs are refused. Keys inside Skill folders are refused; key errors no longer show paths; reasons need three real letters or digits.

- GUI administration rack, phase 2a ([design](docs/design/gui-admin-phase2.md)): the engine for every root and timestamp write (`prepareTrustRootChange` / `commitTrustRoot`, `prepareRevocationsChange` / `commitRevocations`, `prepareTimestamp` / `commitTimestamp`, `signPrepared*`; `addApprover`, `removeApprover`, `updateRevocations` and `signPolicyTimestamp` are rebuilt on them with the same output), `writeFileAtomic` with `expectSha256` (and `FileChangedError`), `StaleDocumentError` and `DocumentChangedError`, `recordDocumentVersions`, `readHostState`, `memoryMinimums`, `loadTrustForPreview` (GUI preview only), `forbiddenApproverKeys`, `RootWalk.retired` and `RootWalk.formerRecovery`, and `isDisplaySafeText` (new approver names and revocation reasons must be display-safe). The GUI's *Manage approvers* template (TRUST ROOT, POLICY CHECK): add, replace, remove and renew approvers, with the consequence for every Skill folder shown before a native signing dialog, a second confirmation for the last approver, a native public-key picker and an offline-computer question when a root or recovery key is armed.
- CLI: `root renew --root-key FILE --trust-root FILE --expires DUR [--out FILE]` and `root add-approver --policy FILE` (refuse keys that hold or held another role in this organisation).

### Changed

- **Hosts refuse a trust root that lists an approver whose key has held the root or timestamp role** in the root events they walked (`trust root lists approver <id>, which has held the root or timestamp role; a key that left those roles never takes another`; `UNVERIFIABLE`). Hosts refuse re-enrolment of a key retired in walked events; former recovery keys are refused only as new approvers, by the GUI and by `--policy`. Upgrade note:

> Before upgrading hosts, open the TRUST ROOT view in a GUI of the new version: it marks any approver whose key has held the root or timestamp role. Remove those approvers (`mago-ski root remove-approver`), and in an organisation that uses timestamps, sign a new timestamp afterwards (`mago-ski timestamp sign`). In an organisation that uses timestamps, remove the approvers and sign the new timestamp in one sitting: between the two, hosts block every Skill. Hosts that use `loadPolicyTrust` (the CLI, Pi, the GitHub Action and the gate's verifier) refuse a trust root that still lists such an approver, and in enforce mode block every Skill. The gate's trust store does not check this.

- Codex adapter: plugin-namespaced mentions (`$ns:name`) and links that do not resolve to an approved Skill file are now blocked in enforce mode even when no other Skill is present; shell-command checks cover every tool with a command and normalise repeated slashes; new NOT_ADMIN block message.
- GUI administration rack, code review fixes ([design v5.1](docs/design/gui-admin-hardening.md)): state writes to one host state file are serialised within a process, and a state file that exists but cannot be read is no longer treated as absent when writing; `stateError` now tells `corrupt` (moved aside) from `unreadable` (retried 3 times, never moved) from `write`. The key file picker counts as a dialog, the key is read once from one opened file, and the key file must be the same file and must not be inside a Skill, both before the dialog and immediately before signing; only one dialog is ever open, the lifetime check uses the refreshed expiry, the key location is re-checked at signing, a stuck dialog stops blocking others after its timeout plus 5 seconds, `dialogSafe` covers all format, private-use and unassigned code points, and a refused reset says why. CLI behaviour and output are unchanged.
- A failure of the trust documents is reported **once per host** instead of once per Skill: one decision record (`event` `root-revoked` or `trust-unavailable`, empty `skill`, null `digest`), one Pi notice and a status-bar message, one `verify-all` line, and one GitHub Action summary line with no per-Skill rows. Scripts that counted per-Skill `UNVERIFIABLE` lines for a broken trust root need updating.
- A root key revoked by a root event blocks every Skill **in shadow mode too**, on every host, and keeps blocking if the log is later missing, malformed, rolled back or forked. Other trust failures still follow the mode.

### Not yet covered

- The E3 gate service keeps its own pinned root fingerprint; root events and timestamps in its inbox are a follow-up.

## [0.2.0] - 2026-10-30

Adds `approve --expect-digest` and the desktop GUI proof of concept (in the repository, not in the npm package), and includes the fixes from the Codex Security review of 0.1.0.

### Added

- `approve --expect-digest DIGEST` (and `expectDigest` in `approveSkill`): refuses to sign when the Skill's bytes are no longer the reviewed version, checked against the same bytes that would be signed. Review tools can pin an approval to exactly what the approver saw.
- `loadPolicyTrust(policy, now, { recordVersions: false })`: reads the host state file and applies its rollback minimums without writing it, for observers that must not move a host's rollback memory.
- GUI PoC (`gui/`, not published): an Electron desktop companion that discovers installed Pi and Agent Skills, remembers each version, shows what changed (file, section, line, executable bit and HTTP(S) origin evidence from the engine diff) and projects the host policy's PKI verdicts read-only. See [gui/README.md](gui/README.md).

### Security

Fixes for the ten findings of the Codex Security review of 0.1.0.

- Release: the manual `workflow_dispatch` trigger is removed. A manual run could select any branch and execute that branch's copy of the workflow, with its tag and ancestry checks. Releases now run only from `v*` tag pushes and publish only through npm trusted publishing (no `NPM_TOKEN` fallback).
- Policy: `decision_log` and `state_file` must name files inside the policy file's directory (symlinks resolved), and may not be the policy file, `trust_root`, `revocations`, each other or a file under `certificate_dirs`. The decision log is opened without following symbolic links and must be a regular file; control, bidi and Unicode line-separator characters in records are escaped. A checkout-controlled policy could append to arbitrary files.
- Certificate discovery is bounded to 64 candidate files and 32 MiB per Skill, and candidates are evaluated one at a time instead of being held in memory.
- `approve` refuses PGP private key blocks, SSH2 and PuTTY private keys and age secret keys, in addition to the PEM and OpenSSH headers it already refused. The scan is linear in the input size.
- CLI: `verify` and `verify-all` no longer trust `.mago-ski/policy.json` from the current directory, where a checkout could choose its own root of trust.
- Pi: a Skill's path reaches the model only if it uses plain characters (outside the working and home directories); other Skills are not advertised or expanded, with a message to rename or move them. `find` and `ls` results no longer list the names of unverified Skills.
- `SKILL.md` is read only if it is a regular file within the size limit, before name resolution.
- Pi: a relative `MAGO_SKI_POLICY`, or a policy inside the project, is refused instead of being resolved against the working directory.
- Skill discovery stops, and fails closed, above 1,000 Skills or 50,000 directory entries.

### Upgrading from 0.1.0

Verdicts, exit codes and every signed format (tree digest, certificate, trust root, revocation list, policy schema) are unchanged; existing certificates verify as before. Check these before upgrading:

- **Node.js:** requires 22.23.4, 24.22.1 or 26.12.1 or newer in its line (`engines`), the October 2026 Node.js security releases. The GitHub Action now runs on Node.js 22.23.4.
- **Policy location:** the CLI no longer reads `.mago-ski/policy.json` from the current directory. `verify` and `verify-all` use `--policy FILE`, else `MAGO_SKI_POLICY` (an absolute path, or starting with `~/`), else `~/.mago-ski/policy.json`. The exported `DEFAULT_POLICY_PATH` is replaced by `defaultPolicyPath()`.
- **Policy contents:** a policy whose `decision_log` or `state_file` points outside the policy file's directory, or at a file the policy reads, no longer loads. In Pi enforce mode that blocks every Skill, so move those files next to the policy first.
- **Pi:** a relative or in-project `MAGO_SKI_POLICY` is refused (every Skill is blocked, with a message). A verified Skill whose path below the working or home directory has characters outside `[A-Za-z0-9._/~@+-]` is not advertised; rename or move it.
- **Reason text:** `UNAPPROVED_CHANGE` reasons now read `Skill changed since approval: …` and name the changed files in quotes. Scripts that match the old `Skill bytes changed since approval` text need updating.
- **Limits:** discovery stops, failing closed, at 1,000 Skills or 50,000 directory entries; at most 64 certificate candidates (32 MiB) are read per Skill; the GitHub Action summary lists at most 200 Skills (failures first) and emits at most 50 annotations.
- **Support:** only 0.2.x receives security fixes ([SECURITY.md](SECURITY.md)).

### Changed

- `UNAPPROVED_CHANGE` reasons name what changed since approval: content, executable bit, added or removed files, for example `Skill changed since approval: executable bit changed on "run.sh" (now executable) (…)`. A mode-only change no longer reads "Skill bytes changed"; a file whose content changed and that became executable reports both; added executables are marked. File names are quoted, with DEL, C1 controls and bidirectional or invisible characters escaped as `\uXXXX`, so a name cannot imitate the reason's wording or reach a terminal or annotation unescaped.
- `approve` takes the Skill name from the same `SKILL.md` bytes it hashes and signs, instead of reading the file a second time.
- Clearer errors: a missing Skill directory reads `Skill directory not found: PATH` (a file: `Skill path is not a directory`) in `digest`, `verify`, `diff` and `approve`; a missing `--policy` file reads `Policy file not found: PATH`; `mago-ski diff A B` explains that the directories go in `--base` and `--candidate`. Each replaced a raw `ENOENT` or a generic argument error.
- `mago-ski --help` is a grouped command index; `mago-ski <command> --help` gives each command's options.
- Releases are re-run with "Re-run jobs" on the tag's workflow run (manual dispatch is removed, see Security).
- Docs: the README Quickstart creates the example Skill before approving it; added [SECURITY.md](SECURITY.md), the [root recovery proposal](docs/spec/root-recovery-v1.md) (not implemented), and the GUI ontology, product plan and preview under `docs/`.
- CI: a `gui` job type-checks, tests and builds the GUI on Linux and macOS; tests run on Node.js 22.23.4 and the latest 24.

## [0.1.0] - 2026-10-09

First release, published to npm as `@mago-foundation/mago-ski`.

### Added

- Skill tree digest `mago.skill-tree/v2`: covers every byte of every covered file and its executable bit; `SKILL.md` is always covered; symlinks are rejected.
- Skill certificates: an in-toto Statement in a DSSE envelope, signed with Ed25519, binding a Skill name, an exact tree digest, an approver and an expiry.
- Trust hierarchy: a root-signed, versioned trust root with approvers limited by Skill-name scopes and expiry.
- Signed revocation lists for approver keys and Skill digests, with expiry (30 days by default).
- Rollback protection through a host state file that rejects older trust roots and revocation lists.
- Seven verdicts: `VERIFIED`, `UNAPPROVED_CHANGE`, `NO_CERTIFICATE`, `UNTRUSTED_SIGNER`, `REVOKED`, `EXPIRED`, `UNVERIFIABLE`.
- Policy file with shadow and enforce modes, and a JSONL decision log.
- CLI: `keygen`, `root`, `revoke`, `approve`, `verify`, `verify-all`, `digest`, `diff`, `inspect`, with help for every command.
- Pi extension: in enforce mode, unverified Skills are not advertised, `/skill:` cannot load them, file tools refuse their files, and verified files are re-hashed on read.
- GitHub Action that checks Skills in pull requests, reading trust from the base revision.
- Specifications, threat model, test vectors for other implementations, and demos.
- Linux and macOS support. Windows is not supported in 0.1.

[Unreleased]: https://github.com/mago-foundation/mago-ski/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/mago-foundation/mago-ski/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/mago-foundation/mago-ski/releases/tag/v0.1.0
