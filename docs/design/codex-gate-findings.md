# Design: Codex gate live-test findings (bare mentions, bypasses, silent blocks, labels)

Status: draft v3, for Goldfish review. Precedence: [Decisions (v3)](#decisions-v3) > the v2 text below. v1 passed comprehension but was NO-GO on readiness. Its antagonistic review found two live bypasses in today's adapter (H1, H2), five ways the strict reader disagreed with Codex (H3–H6, M1), and showed that the fix did not help a stock install (H8). This version is a rewrite.

Sources:
- [the Codex live test](../spikes/codex-gate-live.md), findings 2, 5 and 6;
- the adapter, `src/gate/adapters/codex.ts`;
- `openai/codex` tag `rust-v0.166.0`:
  - `codex-rs/skills/src/{parser,selection,name_counts,mentions}.rs`;
  - `codex-rs/ext/skills/src/loader/{host,environment,namespace,discovery}.rs`;
  - `codex-rs/hooks/src/events/user_prompt_submit.rs`.

The review's tools are in `/var/tmp/review-codex-scratch/` (not committed):
- a `serde_yaml` oracle built from `parser.rs` (`yamlprobe/`);
- a mutation fuzzer;
- `codex debug prompt-input` catalog scripts;
- an end-to-end mock Responses server.

## Problem

1. **Bypasses in today's adapter (security, fix first).**
   - **H2.** Plugin Skills (`$CODEX_HOME/plugins/cache/...`, named `<plugin>:<skill>`) are outside the walk. With `[skills.bundled] enabled = false`, no `.system` folder exists, so the walk finds nothing. `$acme:search` is then allowed unasked, and its body reaches the model. This was reproduced on 0.166.0.
   - **H1.** `linkInRoots` skips `skill://` links (`codex.ts:313`). Codex selects a linked mention by path, so `[$x](skill://…/plugin-or-unscanned/SKILL.md)` reaches the model whenever the walk is empty or the path lies outside the scanned roots.
2. **Finding 2: a bare `$name` for an admin Skill never works.** Codex's bundled Skills always make a non-admin Skill exist.
3. **Finding 5: `codex exec` hides the block reason.** The live test saw only `hook: UserPromptSubmit Blocked` and exit 0. The review could not reproduce a block with a user-level hook, because non-managed hooks need trust. The spike must use the managed hook (§5).
4. **Finding 6: `NOT_ADMIN_ROOT` reads like a verdict.**

## What Codex does (rust-v0.166.0, verified by the review)

- **Name.**
  - Codex takes the frontmatter between `---` lines, where "`---`" means Rust `str::trim()` equals `---`. Lines come from Rust `str::lines`.
  - It parses that frontmatter with `serde_yaml` 0.9.34. On failure it repairs the text once (re-quoting `key: value: x` values) and parses again.
  - `name` = the whitespace-collapsed `name` value. When it is absent or null (`null`, `Null`, `NULL`, `~`, empty), the name is the base name of the **canonical** (realpath) Skill folder (`host.rs:194-207`, `:374`, `:396`).
  - A missing `description`, or a name over 64 characters, makes the file not a Skill.
- **Line breaks.** YAML also breaks lines at U+0085, U+2028 and U+2029. Rust `lines()` does not. Rust `trim()` removes all Unicode white space, including `\f` and `\v`.
- **Namespace.** A plugin Skill is `<namespace>:<base>` (`host.rs:318-320`). Admin names never contain `:`.
- **Selection.**
  - A bare `$x` selects a Skill only when exactly one enabled Skill has exactly that name and no connector has that slug. The comparison is case-sensitive (`selection.rs:181-191`, `mentions.rs:18-20`).
  - A linked mention `[$x](path)` selects by path, including `skill://` paths.
- **Sources outside any folder the adapter scans.** These are plugin Skills, cloud Skills (where enabled), and app-server `skills/extraRoots/set`.
- **Catalog caching.** Codex caches its Skill catalog per working directory, and watches only the non-plugin, non-system roots for changes.
- **Hook reasons.** An exit 2 with a stderr reason, or `{"decision":"block","reason":…}`, sets `stop_reason`.

## Technical plan

### 1. Decision table (enforce mode, replaces today's prompt branch)

Definitions:
- `admin` is the set of admin directory names, with dot-entries ignored.
- `removed` is the set of removed names (§3).
- `known` is the set of known names of found non-admin `SKILL.md` files (§2).
- `unknown` is true when any found file's name is unknown.
- `incomplete` is the walk-incomplete flag, which now also covers §4.
- `exists` is true when any non-admin `SKILL.md` was found, whether its name is known, unknown or `null` (as `anySkill` today), or `incomplete` is true.

Rules, applied per mention in this order. The first match decides:

| # | Mention | Condition | Result |
|---|---|---|---|
| L1 | linked `[$x](link)` with link `app://`, `mcp://` or `plugin://` | — | not a Skill mention; ignore |
| L2 | any other linked mention | the link, resolved like Codex (`skill://` and `file://` stripped, relative to cwd), has a realpath equal to `<admin_root>/<n>/SKILL.md`'s realpath for some admin `n` | ask the service for `n` |
| L3 | any other linked mention | — | **block** NOT_ADMIN |
| T1 | token containing `:` | — | **block** NOT_ADMIN |
| T2 | token `t`, where `t.toLowerCase()` is an admin name (key `k`) | plain mention, or not linked to that admin file | `incomplete` or `unknown`: **block** MASKED_UNKNOWN. A `known` name equals `k` (lower-case): **block** MASKED. Otherwise: ask the service for the admin name |
| T3 | token `t` in `removed` (exact) | — | ask the service for `t` |
| T4 | token `t` | `incomplete` or `unknown` | not a valid engine name: **block** NOT_ADMIN. Otherwise: ask the service for `t` |
| T5 | token `t` | `t.toLowerCase()` is in `known` | **block** NOT_ADMIN |
| T6 | token `t` | — | allow (prose such as `$5` or `$word`) |

Notes on the table:
- **L3** replaces `linkInRoots`. A link that does not resolve exactly to an admin file is never trusted on the strength of its text (H1). Prose with markdown links written as `[$x](...)` is rare, and blocking it is accepted.
- **Tokens from links.** The mention grammar (`extractMentions`) is unchanged. A link's name tokens are still produced, and T-rules apply to the plain tokens only. `plain` keeps its meaning.
- **Service answers.** An answer that is not VERIFIED blocks, using the existing verdict or could-not-verify texts.
- **Shadow mode** applies the same table, but every block becomes allow, as today.

### 2. Strict name reader

`readKnownName(walkDirName: string, realDirName: string, bytes: Buffer): string | null | undefined` returns:
- a string, the known name;
- `null`, when Codex would not load the file as a Skill;
- `undefined`, when the name is unknown.

The reference implementation is the reviewer's `reader2.mjs`. It had 0 mismatches against the `serde_yaml` oracle over 22 018 documents Codex loads, and it matches all five stock `.system` Skills. The rules, in order:

1. **Bytes.**
   - More than 65 536 bytes is unknown. Bytes that are not valid UTF-8 (fatal decode) are unknown.
   - Split on `\n`, drop a final empty element, and remove one trailing `\r` per line.
   - A line containing `\r`, a tab, NUL, U+FEFF, U+0085, U+2028, U+2029, U+000B or U+000C makes the file unknown.
2. **Markers.**
   - A *marker* is a line equal to `---` after removing ASCII spaces at both ends.
   - An *ambiguous* line is one that Rust `trim()` reduces to `---` but that is not a marker. Rust `trim()` here means removing ASCII `\t\n\v\f\r ` and U+0085, U+00A0, U+1680, U+2000–U+200A, U+2028, U+2029, U+202F, U+205F and U+3000.
   - No lines: `null`.
   - The first line not a marker: unknown if it is ambiguous, else `null`.
   - The first marker after line 1 closes the frontmatter. An ambiguous line before it is unknown. No closing marker: `null`.
3. **Frontmatter lines.**
   - Lines of only spaces are skipped.
   - The first other line must be a key line matching `^[a-z][a-z0-9_-]*:( .*)?$`.
   - Every key line sets `nested` = whether its value, after `: `, is empty or a block-scalar header matching `^[|>][+-]?[0-9]?( #.*)?$`.
   - A line starting with a space is allowed only while `nested` is true.
   - Any other line is unknown.
4. **The `name` key.**
   - More than one top-level key line with key `name` is unknown.
   - With none, the result is the default name. If `walkDirName !== realDirName`, it is unknown (H6). Otherwise it is `realDirName` if that matches `^[A-Za-z0-9][A-Za-z0-9._-]*$`, and unknown otherwise.
5. **The `name` value.**
   - The line must start with `name: `. The value is the rest, with trailing spaces removed. A value wrapped in matching `"…"` or `'…'` is unwrapped.
   - The value must match `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`, and must not be `null`, `Null` or `NULL`. Otherwise it is unknown.
6. **Result.** The value is the known name. `description` is not checked: a file Codex rejects only over-blocks.

### 3. Removed names (revocation keeps blocking)

- **The file.** When it uninstalls a Skill (admin uninstall or auto-uninstall on revoke), the gate service adds the name to `<managedDir>/.mago-ski-removed-names.json` after removing the link. When it installs the name again, it removes the name from the file.
  - Content: canonical JSON `{ "type": "mago-ski.gate.removed-names.v1", "names": [...] }`. `names` is in removal order, oldest first, with no duplicates; a name removed again moves to the end.
  - The file is written atomically, mode `0644`, owned by root.
  - It holds at most 4096 names. When full, the oldest is dropped.
- **Reading it.** The adapter reads the file from `admin_root`.
  - The file must be a root-owned regular file of at most 256 KiB, with the exact keys above.
  - A missing file means an empty set. Any other problem sets `incomplete`.
- **The admin set.** `listRoot(adminRoot)` ignores dot-entries, so this file and the service's `.name.*.tmp` links are not admin names.
- **Why.** A name the service removed is still asked, and answered `NO_CERTIFICATE`. A revoked Skill is therefore blocked at its next mention in an open session, as `docs/capabilities.md` promises.

### 4. Sources outside the walk (H2, M3)

The walk is marked `incomplete` when any of the following is true:
- `<codex_home>/plugins` exists and is not an empty directory (plugins installed or cached);
- `<codex_home>/config.toml` cannot be read as a regular file of at most 1 MiB;
- that file contains the bytes `skills` together with `cloud`, or the bytes `extra_roots`. This is a byte check, not a TOML parse. Over-blocking only.

App-server `skills/extraRoots/set` and structured selection stay listed as residuals that no hook can see. They are now stated next to the TOCTOU residual (§6).

`.system` is no longer assumed to exist. With bundled Skills disabled and no other Skill, `exists` is false.

### 5. Silent blocks (finding 5)

The adapter keeps exit 2 with a stderr reason. The spike is part of this work and is recorded in the spike doc:

- **Harness.** `tests/live/codex-gate.live.ts`, which writes the managed requirements file and hook config, as the existing scenarios do.
- **Command.** The harness's argv, `codex exec --json --skip-git-repo-check -s workspace-write '<prompt>'`, with the prompt `use [$x](./.agents/skills/x/SKILL.md)`, which L3 blocks.
- **Run it three times:**
  1. as is;
  2. without `--json`;
  3. with `--output-last-message <tmpdir>/last.txt`.
- **Record, per run:**
  - the exit code;
  - whether the NOT_ADMIN text appears in stdout, in stderr, or in `last.txt`;
  - the stream `hook: UserPromptSubmit Blocked` is on.
- **Documentation follows the result.** If a run shows the reason, the docs name that mode for scripts. If none does, the docs state that `codex exec` hides the reason and exits 0, and that scripts should detect the `Blocked` line on the recorded stream.

### 6. Residuals stated in the adapter header and the docs

- **TOCTOU.** A Skill created, renamed or edited after the walk and before Codex's own load is not seen. Codex caches its catalog per working directory (H7).
- **Structured selection.** `UserInput::Skill` and `skill://` structured selection are not visible to the hook, nor is the app-server's `skills/extraRoots/set` call.
- **Tested versions.** The name rule is verified for 0.163.0 and 0.166.0 only.
- **Service naming.** The service names admin Skills by its own frontmatter rule (`names.ts`). Codex uses YAML and the canonical folder, which here is the digest folder of the generation. An approved Skill without a `name:` field is therefore named by its digest in Codex (L2). Admin Skills should always set `name:`, and the install docs say so.

### 7. Labels (finding 6) and messages

Three messages; the existing verdict and could-not-verify texts are unchanged.

| Name | Text |
|---|---|
| NOT_ADMIN | `This Skill is not one of your organisation's approved Skills, so it is blocked. Approved Skills are installed in <admin_root>.` (`<admin_root>` is the configured admin root) |
| MASKED | unchanged: `A Skill with this name also exists outside your organisation's approved Skills, so a plain mention is blocked. Mention the approved Skill by its link, or remove the other Skill.` |
| MASKED_UNKNOWN | `mago-ski could not check every Skill outside your organisation's approved Skills, so a plain mention of an approved Skill is blocked. Mention the approved Skill by its link.` |

A `$5` token gets `NO_CERTIFICATE` when T4 applies. This is accepted, and documented as over-blocking on machines with unreadable Skills.

## Alternatives considered

- **Exempt `.system`.** Rejected: the folder is user-writable, and it may not exist at all.
- **Rename admin Skills.** Rejected: it changes names that people and other hosts use.
- **A full YAML parser.** Rejected: it would have to match `serde_yaml` and the repair step exactly. The strict subset answers "unknown" instead of guessing.
- **Ask the service for every token.** Rejected: prose `$word` would be blocked as `NO_CERTIFICATE` again.
- **Scan `plugins/cache`.** Deferred: plugin layout and namespaces add another name source to match. Marking the walk incomplete is fail-closed and simple.

## Implementation plan

Order: **the bypass fixes first, in their own commit** (L3, T1, §4), then §2–§3, then the docs.

### `src/gate/adapters/codex.ts`

- `Scan` gains `files: Array<{ path: string; walkDir: string }>`. A file is pushed when `ls.isFile()` is true (`codex.ts:193-196`).
- `readKnownName` is exported (§2).
- `findSkills` reads each file:
  - It opens the file with `O_RDONLY | O_NOFOLLOW | O_NONBLOCK`. On the handle, it checks `isFile()` and a size of at most 65 536, then reads.
  - `realDirName` = `path.basename(await realpath(path.dirname(file)))`.
  - Any error makes that file unknown.
  - Budget: at most 2000 files. Any file beyond that sets `incomplete`.
  - Files are read only when the prompt has at least one token or link, as today.
- `Found` becomes `{ admin; adminReal; removed: Set<string>; known: Set<string>; unknown: boolean; exists: boolean; incomplete: boolean; cwd }`. `anySkill` is renamed `exists`, and `roots` is no longer needed by `linkInRoots`, which is deleted.
- `runHookInner`'s prompt branch is the §1 table. The bash branch uses NOT_ADMIN in place of `notApproved('NOT_ADMIN_ROOT')`.
- `listRoot` drops entries whose name starts with `.`.
- Removed names are read with the config's ownership rules (`loadConfig`'s root-owner check reused).
- The header comments (MASKING, RESIDUAL OVER-BLOCKING and RESIDUALS) are rewritten to §1, §4 and §6, and cite rust-v0.166.0.

### `src/gate/service.ts`

- The removed-names file (§3) is updated in `hostLink(name, null)`, after the `unlink`, and in install, after the link is published.
- There is one writer, through the service's admin queue.

### Tests

**`tests/gate-adapter-codex.test.ts`, existing tests.**
- Colliding user Skill: the tests at lines 142, 143, 352 and 574 need a user Skill with `name: alpha` to keep expecting MASKED. The tests at 523–528 already collide.
- Label: the expectations at lines 145, 146, 148–150, 334, 355, 527 and 563 become `MSG_NOT_ADMIN = /not one of your organisation's approved Skills/u`.
- Line 170 becomes MSG_NOT_ADMIN, because L3 fires before the service.
- The tests at lines 300–321, 357, 458 and 477 had non-colliding Skills with known names, so `$5` and `$anything` now pass (T6). Update each expectation to allow, and add one case with an unknown-name file that still blocks (T4).
- Line 155 (revoke): the Skill is uninstalled, so its name is in `removed`, and it is asked (T3) and blocked with the `NO_CERTIFICATE` text. Assert that text.

**`tests/gate-adapter-codex.test.ts`, new tests.**
- Table rows L1–L3 and T1–T6, one test each. These include:
  - a `skill://` link to an unscanned path (H1, blocked);
  - `$acme:search` with an empty walk (H2, blocked);
  - `plugins/` non-empty, giving `incomplete` (MASKED_UNKNOWN for `$alpha`).
- A `.system`-like fixture with the real stock `name: "imagegen"` style frontmatter: bare `$alpha` is asked and VERIFIED (`service(t)`, `install('alpha')`, START first).
- A symlinked Skill folder (H6) gives unknown.

**`tests/codex-names.test.ts` (new).**
- Table tests for `readKnownName`, one row per rule with its expected value. The table includes:
  - every repro from H3–H6 and M1, all unknown;
  - quoted names, known;
  - `name: null`, unknown;
  - `\r\n` endings, known;
  - a 64-character name, known, and a 65-character name, unknown;
  - missing markers, `null`;
  - `  ---  ` markers, accepted;
  - `\f---`, unknown.
- A golden corpus `tests/fixtures/codex-names.json`: at least 500 documents from the review's fuzzer, each with `walkDir`, `realDir`, the content (base64) and Codex's name or `"NOT_SKILL"` per the `yamlprobe` oracle. The test asserts that `readKnownName` never returns a known name different from Codex's, and never `null` for a document Codex loads. Unknown is always allowed. The fixture is generated once with `/var/tmp/review-codex-scratch/yamlprobe` and committed with a README line saying how it was made.

**`tests/gate-service*.test.ts`.** Uninstall adds the name to the removed-names file, reinstall removes it, and the cap drops the oldest name.

**`tests/live/codex-gate.live.ts`.**
1. The `mention-bare-approved` scenario moves from `known` to `expect: served`. A failure means Codex disagrees, which is the point.
2. A new scenario installs admin `alpha` in a `before` hook and adds a repo Skill `.agents/skills/a2/SKILL.md` with `name: alpha`. It expects blocked. The harness cannot tell MASKED from other blocks, so the scenario says so in its `what`.
3. A new scenario has `plugins/` populated, using a local marketplace like the review's. `$acme:search` is expected blocked.
4. The spike (§5) is recorded as observations.
5. `SKILLS` gains `alpha`.

### Docs

- **`docs/spikes/codex-gate-live.md`.**
  - Findings 2, 5 and 6: resolved, documented or resolved respectively, with the spike result.
  - The summary line and rows 26 and 29 are updated, and a row is added for H1 and H2.
  - The date and versions are updated.
  - "Not covered" is updated.
- **`docs/hosts/adapter-interface.md:39`:** bare mentions work unless a same-name or unreadable Skill exists.
- **`docs/capabilities.md:61-68, 80`:** the same change; revocation still blocks in open sessions; the plugin and cloud fail-closed; the §6 residuals.
- **`CHANGELOG.md` `[Unreleased]`:**
  - **Security:** the Codex adapter no longer allows plugin-namespaced mentions, or `skill://` links that point outside the admin root.
  - **Changed:** bare mentions of approved Skills work on a stock Codex install; new block messages.

## Decisions (v3)

These decisions resolve the v2 reviews:
- **Readiness:** R1–R8 and the test, live and spike notes.
- **Antagonistic:** H1, H2, M1–M7 and L1–L6.

### X1. The decision table, final (R1, R4, R5, R6, H1, M4)

**Order of evaluation.**
1. First every entry of `links` in prompt order, with rules L1–L3.
2. Then every entry of `plain` in prompt order, with rules T1–T6.

The first block stops evaluation, and its message is the one shown. Asks are collected and sent afterwards, as today. Path-derived names from links (`names` minus `plain`) decide nothing. All name comparisons use `fold(x) = x.toLowerCase()` on both sides, and `known` stores folded names.

**Rules.**
- **L1:** links starting with `app://`, `mcp://` or `plugin://` are ignored.
- **L2:** the link is resolved, then compared with each admin entry's resolved `SKILL.md` by realpath. Resolution:
  1. Strip a leading `skill://` or `file://`. A `file://` with a host part goes to L3.
  2. A relative link resolves against `cwd`. Without a usable `cwd` it goes to L3.
  3. Then `realpath`.

  On a match, ask the service for the admin name. `adminLinkName` is changed to this rule (today it rejects `skill://`).
- **L3:** every other link: **block** NOT_ADMIN.
- **T1:** a token containing a `:` followed by a non-colon character (`/:[^:]/u`): **block** NOT_ADMIN. Tokens whose only colons are trailing (`$5:`, `$alpha:`) fall through to T2–T6 unchanged. Codex looks those up literally and no Skill name contains `:`.
- **T2:** `fold(t)` is an admin key:
  - with `incomplete` or `unknown`: **block** MASKED_UNKNOWN;
  - with `known.has(fold(t))`: **block** MASKED;
  - otherwise: ask the service for the admin name.
- **T3:** `t` is in `removed` (exact or folded): ask the service for `t`.
- **T4:** with `incomplete` or `unknown`: an invalid engine name gets **block** NOT_ADMIN; otherwise ask the service for `t`.
- **T5:** `known.has(fold(t))`, or some `k` in `known` with `fold(t).startsWith(k)`: **block** NOT_ADMIN. The prefix part covers multi-text input that the hook sees joined (M4).
- **T6:** allow.

`exists` is deleted.

### X2. The reader (R3, H2, L4)

The reference is `reader3.mjs` from the v2 review, which is `reader2.mjs` plus the H2 quote rule. §2 changes as follows:

- **Rule 1.** Decode with `new TextDecoder('utf-8', { fatal: true, ignoreBOM: true })`, so a leading U+FEFF stays in the text and makes the file unknown.
- **Rule 2 wording.** Scan from line 2 to the first marker or EOF.
  - An ambiguous line seen before the marker makes the file unknown.
  - No marker and no ambiguous line: `null`.
- **Rule 3 additions.**
  - A key line whose value, after `: `, starts with `"` must match `^"(?:[^"\\]|\\.)*"( #.*)?$`.
  - A value starting with `'` must match `^'(?:[^']|'')*'( #.*)?$`.
  - A value starting with any of `[ { ! & * ? % @` or a backtick makes the file unknown.
- **Rule 4 addition.** A default name longer than 64 code points (`[...realDirName].length`) makes the file unknown.
- **H6 check.** `walkDirName !== realDirName` makes the file unknown. It is kept as a conservative addition beyond the reference.
- **Exported functions.**
  - `readKnownName(walkDirName, realDirName, bytes)` is the wrapper.
  - `readKnownNameCore(dirName, bytes)` is the reference port, exported for the golden test.
- **The invariant**, as stated and tested. For every document Codex loads (oracle gives a name), `readKnownName` returns either that name exactly or `undefined`. For documents Codex rejects (oracle `ERR` or `NOT_SKILL`), any result is allowed, because a wrong known name there only over-blocks.

### X3. Sources outside the walk, rewritten (M5, L1, R2, R8)

§4's plugin and `config.toml` rules are **dropped**.
- Plugin Skills are always `ns:base` (`loader/namespace.rs:176-181`), and T1 blocks those.
- Rust-v0.166.0 has no config key that adds a Skill root.
- A missing `config.toml` therefore needs no handling.

The Skill sources the hook cannot see are listed as endpoint preconditions in the adapter header and `docs/capabilities.md`:
- app-server `skills/extraRoots/set`;
- executor capability roots (`provider/executor.rs:95-135`);
- cloud Skills;
- structured `UserInput::Skill` and `UserInput::Mention` selection.

Organisations must not enable these on enforce endpoints, or must restrict the clients that can use them.

### X4. Removed names (R7, M2, L2, L3)

- **Order.**
  - **Uninstall** (`uninstall`, `service.ts:599-605`) and **reconcile** (`reconcileOnce`, `:527-531`) record the name first, with an atomic write, and only then call `hostLink(name, null)`. If the write fails, the operation fails and the link stays.
  - **Install** removes the name from the file only after `admission.publish` succeeds (`:594-595`).
  - **Rollback** (`:596`) touches neither.
- **Cap.** The cap is 2048 names, which at 64 bytes each is well under the 256 KiB read limit. When full, the oldest name is dropped and a warning is logged in the decision log.
  - The revoked Skill's link is already removed, and Codex reads bodies at injection, so the dropped name loses only the message, not the block.
  - A pure helper, `addRemoved(list: string[], name: string, cap = 2048): string[]`, is tested directly.
- **Reading.** New helper `readRootOwnedFile(file, rootUid, maxBytes)`:
  1. `lstat`: it must be a regular file, with uid = `rootUid` and `mode & 0o022` = 0.
  2. `readRegularFile` with `maxBytes`.

  `ENOENT` gives an empty set. Other errors set `incomplete`. The content is parsed with `parseCanonicalJsonBytes` and `exactKeys`, with `validateSkillName` on each name, at most 2048 names and no duplicates. It is not read through `loadConfig`.

### X5. Install-time name rule (M3)

The gate service refuses to install a Skill unless its `SKILL.md` gives `readKnownNameCore(name, bytes) === name`, where `name` is the Skill name. The refusal message is `SKILL.md must set name: <name> in plain frontmatter, so every host names it the same`. This affects all hosts, and the install docs state it.

Codex then always names an admin Skill by its Skill name, and the digest-folder default name (L2 of review 1) cannot occur.

### X6. Shell commands (M1, M7)

- **Which tools.** `parseHookInput` treats any PreToolUse whose `tool_input.command` is a string as a shell command, whatever its `tool_name`.
- **Path normalisation.** `inspectCommand` collapses runs of `/` to one before matching.
- **The rogue check.** A command is rogue if it matches either of these:
  - `/\.(agents|codex)(?![A-Za-z0-9_-])/u`;
  - `/skill\.md/iu` at a position not inside a `<admin_root>/<name>/SKILL.md` occurrence.
- **Over-blocking.** Editing `~/.codex/config.toml` through the agent is blocked in enforce mode. This is accepted and documented.
- **Documentation.** The adapter header and `docs/capabilities.md` keep saying the shell check is best-effort defence in depth: globs, variables and scripts can still bypass it.

### X7. Residual wording (L5, M6)

- **TOCTOU.** "A Skill created, renamed or edited after the hook's walk is not seen. Codex caches its catalog per working directory and reloads it when its watcher fires, so a Skill added between that load and the hook's walk can differ from what the hook saw."
- **Structured selection.** It is listed in X3 as an endpoint precondition.

### X8. Tests, corrected (readiness notes)

**`tests/gate-adapter-codex.test.ts`:**
- Lines 143, 525 and 528 become `MSG_NOT_ADMIN`, because they are L3.
- Line 170 becomes `MSG_NOT_ADMIN` through T5, because `repo-skill` is known.
- Line 155 is an L2 ask answered `NO_CERTIFICATE`.
- Line 563 stays `MSG_NOT_ADMIN` through T5.
- Line 576 filters dot-entries from `readdir(managed)`.
- The R2 list of 17 assertions needs no change, because X3 drops the `config.toml` rule.
- The 300–321, 357, 458 and 477 changes are as planned in v2.

**New table rows:**
- `$Alpha`, with a user Skill named `name: Alpha`, is blocked (T5).
- `$MixedName` is blocked.
- Joined `$alphax`, with a known `alpha`, is blocked (T5 prefix).
- `$alpha: step 1` falls through to T2 and is asked.
- `$acme:search` is blocked (T1).
- A `skill://` link to an unscanned path is blocked (L3).
- An absolute `skill://` link to the admin file is asked (L2).
- A relative link without a `cwd` is blocked (L3).
- The H2 multi-line quoted description gives `unknown`, so a bare admin mention gets MASKED_UNKNOWN.
- The PreToolUse shell check covers a `tool_name` other than `Bash`, the `//` path form, and `.agents/*/x/SKILL.md`.

**`tests/codex-names.test.ts`:**
- The v2 rows, plus BOM, a 65-character folder name, no description (any result allowed), and the H2 shapes in double and single quotes.
- The golden corpus generator is committed under `tests/fixtures/codex-names/generator/`: the yamlprobe Rust source, its `Cargo.toml`, and the fuzz scripts. A README explains how to regenerate the corpus. It is not run in CI.
- The corpus is at least 1000 documents and includes the quoted and flow mutation classes.

**`tests/gate-service.test.ts`:**
- `addRemoved` cap and order.
- Uninstall writes the file before the unlink.
- A failed write keeps the link.
- Install with a `name:` mismatch is refused (X5).

**`tests/live/codex-gate.live.ts`:**
- `Run` gains `repoSkill?: { folder: string; name: string; mark: string }`, `json?: boolean` (default true) and `lastMessage?: boolean`.
- Raw stdout and stderr are written to the run's folder.
- The alpha-collision scenario runs **last**: it installs `alpha` in `before`, adds `repoSkill { folder: 'a2', name: 'alpha', mark: 'SECRET-BODY-repo-a2' }`, uses the prompt `use $alpha now`, and expects blocked with neither mark reached. The plugin scenario is dropped (X3).
- **The spike (§5)** runs as three scenarios, `json: true`, `json: false` and `lastMessage: true`, each with the L3 prompt. Each records, for every stream (stdout, stderr and the last-message file): the exit code, whether the NOT_ADMIN text appears, and whether `/hook: UserPromptSubmit Blocked/` appears. It also records the `tool_name` of one PreToolUse shell call (M7).

### X9. Docs, with the texts

- **`docs/hosts/adapter-interface.md:39`** becomes: "An admin Skill can be invoked by a bare `$name` or by its linked mention. A bare mention is blocked when a Skill outside the admin root has the same name, or when the adapter cannot read every Skill's name."
- **`docs/capabilities.md:68`** becomes: "Users call an installed Skill by `$name`. If another Skill with the same name exists, or one cannot be checked, the bare form is blocked and the linked form `[$name](/etc/codex/skills/name/SKILL.md)` works."
- **`docs/capabilities.md:80`** adds the T1 and X6 over-blocking and the X3 endpoint preconditions.
- **`docs/spikes/codex-gate-live.md`:**
  - "4 bundled Skills" becomes 5, at lines 20 and 24.
  - Row 26 becomes `Served (bare mention, no same-name Skill)`.
  - Row 29 gets the NOT_ADMIN text.
  - A new row is added: `Plugin-namespaced and skill:// mentions outside the admin root | enforce | Blocked (fixed in this change; earlier versions allowed them when no other Skill existed) | Hook`.
  - Findings 2 and 6 are marked resolved. Finding 5 is marked documented, with the spike result.
- **`CHANGELOG.md` `[Unreleased]`:**
  - A new `### Security` heading: "Codex adapter: block plugin-namespaced mentions and links to Skills outside the admin root, which earlier versions allowed when no other Skill was present."
  - Line 16's "never a bare `$name`" becomes the X9 adapter-interface sentence.

### X10. Commit order

1. **Commit 1, the security commit.** It contains L3 (with the L2 `skill://` resolution), T1, X6, and the X1 table with case folding and the prefix rule. T2–T5 keep today's `wide` behaviour, with `unknown` = true for every found file. This closes H1 and H2 of review 1 without the reader, and allows nothing today's adapter blocks.
2. **Commit 2.** The reader (X2) and `known` / `unknown`, which enable the precise T2, T4 and T5.
3. **Commit 3.** Removed names (X4) and the install-time name rule (X5).
4. **Then** the live tests, spike and docs.
