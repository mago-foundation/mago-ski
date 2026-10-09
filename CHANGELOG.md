# Changelog

All notable changes to mago-ski are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/). Before 1.0, minor releases may change formats and commands.

## [Unreleased]

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
