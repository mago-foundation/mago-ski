# Design: Codex gate live-test findings (bare mentions, silent blocks, labels)

Status: draft v1, for Goldfish review.

Source: [the Codex live test](../spikes/codex-gate-live.md), findings 2, 5 and 6. Code: `src/gate/adapters/codex.ts`. Codex source read for this design: `openai/codex` tag `rust-v0.166.0`, `codex-rs/skills/src/parser.rs`, `selection.rs`, `name_counts.rs`, `codex-rs/ext/skills/src/loader/environment.rs`, `loader/namespace.rs`, `codex-rs/hooks/src/events/user_prompt_submit.rs`.

## Problem

1. **Finding 2: a bare `$name` for an admin Skill never works.** MASKING blocks a bare admin mention whenever any non-admin `SKILL.md` exists. Codex writes its bundled Skills to `<codex_home>/skills/.system` at every start, so one always exists. Users must type `[$name](/etc/codex/skills/name/SKILL.md)`.
2. **Finding 5: a blocked prompt is silent in `codex exec`.** Codex records the hook's reason as the run's `stop_reason` (`user_prompt_submit.rs`), but `codex exec` prints only `hook: UserPromptSubmit Blocked` and exits 0.
3. **Finding 6: `NOT_ADMIN_ROOT` reads like a verdict.** It is an adapter label, printed in the same slot as the seven verdicts.

## What Codex does (rust-v0.166.0)

- **Name.** `parse_skill_frontmatter_metadata(contents, default_name)`:
  - frontmatter = the lines between a first line whose `trim()` is `---` and the next such line (Rust `str::lines`, `str::trim`);
  - parsed with `serde_yaml`, and on failure once more after a line-oriented repair that only re-quotes values containing `: ` or invalid flow-like values;
  - `name` = `sanitize_single_line(name)` (whitespace runs collapsed to one space), else the parent folder's base name sanitised the same way, else `skill`;
  - a `name` over 64 characters, or a missing `description`, makes the file not a Skill.
- **Namespace.** A Skill under a plugin root gets `<namespace>:<base>` (`environment.rs:256`). An admin name never contains `:` (`validateSkillName`), so a namespaced Skill never shares an admin Skill's name.
- **Selection.** A bare `$x` selects a Skill only when exactly one enabled Skill has that name and no connector has that slug (`selection.rs:191`); counts are kept exact and lower-cased (`name_counts.rs`).
- **Hook reasons.** Exit 2 with stderr, and stdout JSON `{"decision":"block","reason":…}`, both set `stop_reason`; neither is printed by `codex exec`.

## Technical plan

### 1. Precise masking (finding 2)

- **Names.** The non-admin walk records each found `SKILL.md`'s path. For each, the adapter computes a **known name** with a strict reader (§2) or marks it **unknown**.
- **Collision.** Masking (block with `MASKED`) applies to a bare or unlinked admin mention when the walk is incomplete, when any found Skill's name is unknown, or when a known name equals the admin name (lower-case comparison).
- **Other tokens.** A token that is not an admin name is handled as today when the walk is incomplete or a name is unknown (validate, then ask the service or block). Otherwise:
  - a token containing `:` is blocked in enforce whenever any non-admin Skill exists, because it may name a namespaced one;
  - a token whose lower-case form equals a known name is blocked in enforce with the label message (§4);
  - any other token passes unasked (prose `$5`, `$HOME`-like words).
- **Linked mentions** are unchanged: a link into a non-admin root is blocked, and a link that resolves to the admin file is checked with the service.
- **Effect.** With only Codex's bundled Skills present (simple frontmatter, names unlike admin names), bare `$alpha` is asked of the service and served when VERIFIED.

### 2. The strict name reader

`readKnownName(dirName: string, bytes: Buffer): string | null | undefined` (`dirName` = base name of the folder holding the `SKILL.md`) returns a name only when the frontmatter is inside a subset where `serde_yaml` with the repair step cannot give a different `name`. Otherwise it returns `undefined` (unknown), or `null` when Codex would not load the file as a Skill (rule 2). Rules, in order:

1. Split `contents` like Rust `str::lines`: on `\n`, and remove one trailing `\r` from each line. Any other `\r`, any tab, a NUL, a U+FEFF anywhere, or a byte sequence that is not UTF-8 makes it unknown. The adapter reads the file as bytes, at most 64 KiB; a larger file is unknown.
2. The first line, with ASCII spaces removed at both ends, must be exactly `---`, and a later line must be exactly `---` in the same way. Otherwise the file is not a Skill: return `null`, which counts as no name and no collision. Rust's `trim` also removes Unicode white space; a line that contains any non-ASCII white space before or after `---` is unknown.
3. The lines between the markers form the frontmatter. Each line is one of:
   - empty, or only spaces;
   - a **top-level key line**, matching `^[a-z][a-z0-9_-]*:( .*)?$`;
   - an **indented line** starting with at least one space.

   The first non-empty line must be a top-level key line. Any other line makes the file unknown: comments, `?`, `-`, `<<`, `%`, flow starts, quotes at column 0, and `...`.
4. Exactly one top-level key line has the key `name`; zero or more than one makes it unknown. With none, `sanitize(base name of the parent folder)` is used if that base name matches `^[A-Za-z0-9][A-Za-z0-9._-]*$`; otherwise unknown.
5. The `name` value is the text after `name: `, with trailing spaces removed. It must match `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`: no quotes, no `#`, no `:`, no `!`, `&`, `*`, `|`, `>`, `{`, `[`. The line right after it must not be an indented line, so no continuation is possible.
6. The value is the known name. The reader does not check `description`: a file Codex rejects is not a Skill, so treating it as a named Skill only over-blocks.

### 3. Silent blocks (finding 5)

The adapter keeps exit 2 with the stderr reason, because Codex records it. The design adds two things.

- **Spike** (part of this work, recorded in `docs/spikes/codex-gate-live.md`): run a blocked prompt with `codex exec --json`, and with `codex exec` plus `-c hooks.…`/default flags, on 0.166.0. Record whether the reason or `stop_reason` appears anywhere in stdout. Also test `--output-last-message`.
- **Documentation.** The Codex host page and the adapter comment state that `codex exec` hides the reason and exits 0. They give the `--json` field from the spike if one carries it, or else say that no mode shows it. Scripts should treat `hook: UserPromptSubmit Blocked` on stderr as a block.

### 4. Labels (finding 6)

Two new messages replace `notApproved('NOT_ADMIN_ROOT')`. The seven-verdict message stays for real verdicts.

- **Non-admin Skill use.** This covers a linked mention into a non-admin root, a token equal to a known non-admin name, a `:` token, and a shell command touching a non-admin Skill location:
  `This Skill is not one of your organisation's approved Skills, so it is blocked. Approved Skills are installed in <admin_root>.`
  Here `<admin_root>` is the configured admin root.
- **Invalid name token** (a token that is not a valid engine Skill name, while the walk is incomplete or a name is unknown): the same message.

Tests change from `MSG_APPROVED` with `NOT_ADMIN_ROOT` to a new `MSG_NOT_ADMIN = /not one of your organisation's approved Skills/u`.

## Alternatives considered

- **Exempt `.system` entirely.** Rejected: the folder is user-writable, so an employee could plant an `alpha` there.
- **Rename admin Skills on install** (for example `org-alpha`). Rejected: it changes Skill names that people and other hosts use, and a repo could still add `org-alpha`.
- **Parse the frontmatter with a full YAML library.** Rejected: it must match `serde_yaml` plus the repair step exactly, and any mismatch would let a crafted file hide a collision. The strict subset gives "unknown" instead of guessing.
- **Print the reason to `/dev/tty`.** Rejected: hooks may have no terminal, and it would bypass Codex's own output.

## Implementation plan

- `src/gate/adapters/codex.ts`:
  - `Scan` gains `files: string[]`, holding the paths of plain-file `SKILL.md` entries (`found` stays).
  - New exported `readKnownName(dirName: string, bytes: Buffer): string | null | undefined`: `null` for not a Skill, `undefined` for unknown, a string for the known name.
  - `findSkills` reads each file (`open` + read at most 65 537 bytes; over 65 536 is unknown; a read error is unknown). It returns `Found` with `names: Set<string>` (lower-case known names) and `unknownName: boolean`.
  - `runHookInner` applies the §1 rules.
  - `notApproved('NOT_ADMIN_ROOT')` is replaced by `notAdmin(cfg.adminRoot)`.
  - The header comments for MASKING and RESIDUAL OVER-BLOCKING are updated, citing rust-v0.166.0. They state that the rule is verified for 0.163.0 and 0.166.0 only.
- `tests/gate-adapter-codex.test.ts`:
  - The existing masking tests keep a colliding user Skill. One test gets a non-colliding user Skill, which must now pass a bare admin mention.
  - Label assertions change to `MSG_NOT_ADMIN`.
  - New `readKnownName` table tests cover each rule in §2, with one row per refusal: tab, `\r` in the middle, BOM, duplicate `name`, quoted name, `name: a # c`, a continuation line, a missing name with a valid and an invalid folder name, more than 64 KiB, missing markers (`null`), and `  ---  ` markers.
  - A `.system`-like fixture holds two bundled-style Skills, and bare `$alpha` is VERIFIED.
  - A `:` token is blocked when a non-admin Skill exists and passes when none exists.
- `tests/live/codex-gate.live.ts`: the bare-mention scenario now expects served, given no colliding Skill. A new scenario adds a repo Skill named `alpha` and expects masked. The spike in §3 is added as a recorded observation, not an assertion.
- Docs:
  - `docs/spikes/codex-gate-live.md`: findings 2, 5 and 6 are marked resolved or documented, with the spike result.
  - The Codex host documentation (wherever `docs/` describes the Codex gate; find it with `grep -rl "Codex" docs/`): bare mentions now work unless a same-name Skill exists; the exec silence; the new message.
  - `CHANGELOG.md` gets a gate entry.
