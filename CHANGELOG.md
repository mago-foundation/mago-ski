# Changelog

All notable changes to mago-ski are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/). Before 1.0, minor releases may change formats and commands.

## [Unreleased]

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

### Changed

- The CLI no longer reads policy from the current directory. `verify` and `verify-all` use `--policy FILE`, else `MAGO_SKI_POLICY` (an absolute path, or starting with `~/`), else `~/.mago-ski/policy.json`. The exported `DEFAULT_POLICY_PATH` is replaced by `defaultPolicyPath()`.
- A policy whose `decision_log` or `state_file` points outside its own directory, or at a file the policy reads, no longer loads.
- Pi refuses a relative or in-project policy path, and does not advertise or expand a Skill whose path (below the working or home directory) has characters outside `[A-Za-z0-9._/~@+-]`.
- Limits: discovery stops at 1,000 Skills or 50,000 directory entries; at most 64 certificate candidates (32 MiB) are read per Skill; the GitHub Action summary lists at most 200 Skills (failures first) and emits at most 50 annotations.
- Manual release dispatch is removed; re-run a failed release with "Re-run jobs" on the tag's workflow run.

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

[Unreleased]: https://github.com/mago-foundation/mago-ski/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/mago-foundation/mago-ski/releases/tag/v0.1.0
