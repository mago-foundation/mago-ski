# Design: hardening the administration rack (phase 1.1)

Status: v5, ready for implementation, for Goldfish review (Elephant/Goldfish model: the design passes the comprehension, antagonistic and readiness checks before any code). v1 failed comprehension and two antagonistic reviews; v2 failed comprehension and readiness. **[Decisions and exact details (v3)](#decisions-and-exact-details-v3) and [Readiness addenda (v4)](#readiness-addenda-v4) settle every open point; v4 wins over v3, and both win over earlier sections.**

## Problem

An independent review of phase 1 (`docs/spec/gui-admin-rack-v1.md`, merged in mago-foundation/mago-ski#15) confirmed these findings:

| # | Severity | Finding |
|---|---|---|
| F1 | high | "I reviewed this version" is an IPC call; a compromised renderer with an armed key can review and sign any in-scope version |
| F2 | medium | An unprivileged Linux user namespace can present a fake root-owned pin |
| F3 | medium | Older signed trust roots and revocation lists replay in admin mode (no rollback memory) |
| F4 | medium | An older root event log replays, making a rotated-out root key active again |
| F5 | medium | A key stored inside a Skill folder is accepted (the CLI refuses it) |
| F6 | low | A signature completes after eject or after the approver is revoked during hashing |
| F7 | low | One inspection record can be used by two concurrent approves, or by a different approver armed meanwhile |
| F8 | low | The scope check and the signed name come from different reads of `SKILL.md` |
| F9 | low | A key load error shows the key file's path in the window |
| F10 | low | Pin change and role loss do not disarm until the next operation; status keeps showing the role |
| F11 | low | On macOS `/etc` is a symbolic link, so the pin is always refused |
| F12 | low | A blank reason is accepted |
| F13 | low | INSPECT's verdict can describe different bytes than the digest it shows |

Phase 2 adds root-key operations to the same mechanism, so these are fixed first.

## Goals, non-goals and threat model

**Goals.** A certificate is written only after two native main-process dialogs, both answered by a human: one that records the review of an exact version, one that authorises the signature and shows everything signed. No certificate is written after a disarm (eject, idle, pin or role change, window reload or crash) that happened before the final pre-write check. The GUI refuses documents older than it has already seen in this user's profile. Every finding has a regression test.

**Non-goals.** Stopping a key holder from signing with the CLI: authority is cryptographic and hosts decide. Protecting against the user at the keyboard tampering with their own machine, same-user malware, or root. Making the user-namespace check unforgeable: it cannot be, see item 3. Hardware keys.

**Threat model for the window.** The renderer is sandboxed, has a strict CSP and builds the DOM from text nodes only; compromising it needs a separate bug. The design still assumes it can be compromised and gives it no way to cause a signature without the two dialogs.

## Technical plan

### 1. Two native dialogs (F1)

- **Review dialog.** The renderer's "I reviewed this version" button calls `admin:review(instanceId)`. The main process re-reads the Skill (one `collectSkillTree` with contents), then shows a native dialog: Skill name, folder path, digest in full, number of covered files, and the question "이 정확한 버전의 파일을 모두 검토했나요?" with buttons 취소 (default, cancel) and 검토함. Only 검토함 records the review. The old `admin:confirm-inspected` IPC is removed.
- **Signing dialog.** `approve` shows a second native dialog with: action, Skill name, folder path, the reviewed digest, the digest about to be signed (they must be equal, else refuse before showing), lifetime and resulting expiry date, reason, and the armed key's role, name and key id. Buttons 취소 (default) and 서명.
- **Cooldown.** After a cancel or a timeout of either dialog, `review` and `approve` are refused for 10 seconds ("잠시 후 다시 시도하세요"), so a compromised renderer cannot spam dialogs until one is clicked by accident.
- **Timeout.** A dialog unanswered for 120 seconds is treated as a cancel (the dialog is closed by destroying its parent-less modal, or the result is ignored and the cooldown applies).
- **Text.** Every field is shown in full (the reason up to its 1024-unit limit, never cut). Paths and reasons pass through `dialogSafe` (see v3 D14).

### 2. Synchronous disarm and a queue for the rest (F6, F7, F10)

- `dropKey(reason)` is private and **synchronous**: `armed = null`, `generation += 1`, `reviews.clear()`, clear the idle timer. It is never queued and is safe to call from anywhere, including inside queued work and from event handlers. The public `disarm()` calls it directly.
- `arm`, `review`, `approve` and `resetMemory` run through one promise queue (`serial`). `status`, `inspect` and `check` are **not** queued and never wait for a dialog; they do write the GUI memory through `readPin` (v3 D3).
- Every queued operation captures `const op = { keyId: armed.keyId, generation }` before its first `await`, and every later step compares `op.generation === this.generation`; a mismatch ends the operation with "키가 빠졌어요" and writes nothing.
- **Idle.** Only `arm`, `review` and `approve` refresh `lastUsed`; `status`, `inspect` and `check` never do. The idle timer calls `dropKey('idle')`.
- **Status re-check.** `status()` calls `recheck()`, which reads the pin and recomputes the role without throwing; on a pin hash change or a role change it calls `dropKey`. The renderer polls `admin:status` every 5 seconds while the 관리 tab is visible, so a pin change or revocation disarms within about 5 seconds even without an operation.
- **Window events.** In `main.ts`, `webContents.on('did-start-navigation')`, `on('render-process-gone')`, `on('destroyed')` and every `on('did-finish-load')` after the first call `admin.disarm()`.

### 3. Pin location and the user-namespace hurdle (F2, F11)

- **macOS.** `mapPinPath(file, platform, readlink)` is a pure exported function. On `darwin`, if `file` starts with `/etc/`, it requires that `/etc` is a symbolic link whose target is exactly `private/etc` (and owned by root, checked by the walk on `/private`), and returns `/private/etc/...`. Other platforms return `file` unchanged. The ownership walk then runs on the returned path; the rule "no component is a symbolic link" applies to that path.
- **Linux user namespaces.** On `linux`, `pinOwnershipProblem` refuses unless `<procDir>/self/uid_map` and `<procDir>/self/gid_map` each read exactly one line equal to `0 0 4294967295` after whitespace normalisation. An unreadable file refuses. **This is a hurdle, not a boundary:** a user can bind-mount over these files inside their own namespace (shown by the review), so the spec states that the pin's protection against the user themself ends where the operating system's does. It still refuses accidental and casual cases, and it refuses Flatpak, rootless containers and user-namespace CI runners, which the spec lists as unsupported for the administration rack.
- **NixOS.** `environment.etc` links files into the store, so the pin must be installed as a real file (`environment.etc."mago-ski/policy.json".mode = "0644"`). The spec says so.

### 4. GUI rollback memory (F3, F4)

- The memory file is `<stateDir>/admin-state.json`, `stateDir` being the GUI's user data folder. It uses the engine's host state format (`mago.host-state/v1|v2`) and is written only by the engine.
- `readPin` loads the pin's policy, then builds `const memoryPolicy: Policy = { ...policy, statePath: memoryFile, decisionLogPath: null }` and calls `loadPolicyRoot(memoryPolicy, now, { recordVersions: true })` and `loadPolicyTrust(memoryPolicy, now, { recordVersions: true })` in that order. The organisation's own `state_file` is never read or written by the GUI.
- **First run.** `stateDir` is created with mode `0700` if missing. The first load records whatever the pin's documents are; there is no floor before that.
- **Corrupt file.** If the engine reports that the state file cannot be parsed, `readPin` renames it to `admin-state.json.unreadable-<timestamp>`, records a `memoryReset` notice (shown in the 관리 tab until dismissed) and loads again with an empty memory.
- **Legitimate reset.** When an organisation re-initialises with the same root key (versions restart), loads fail as rollback. The 관리 tab then shows "이 컴퓨터의 기록보다 오래된 문서예요" with a 기록 초기화 button, which shows a native confirmation and on 확인 renames the file aside as above.
- **Failed write.** A failure to write the memory makes the pin `invalid` with the reason, and any armed key is dropped (v3 D4).
- **What it protects.** Accidental replay and replay by a third party who can change the documents but not this user's profile. It does not protect against the user, who can delete or move it (including with `MAGO_SKI_GUI_DATA`). With `freshness` in the pin, the timestamp bounds replay for everyone.

### 5. `loadPolicyRoot` and a shared pure check (F4)

- In `src/policy.ts`, the root-event part of `loadPolicyTrust` (lines that walk the log, compare with `state.rootEvents`, record progress and detect a revoked root) moves into a **pure** internal function:
  ```ts
  // Superseded by v3 D6 and D9 (exact signature there).
  ```
  It does no I/O. `progress` is the entry to record (or null). `loadPolicyTrust` reads the state and the log as today, calls it, applies `progress` to its `state` and keeps its save, merge and message logic unchanged.
- New export:
  ```ts
  export type PolicyRootResult =
    | { ok: true; walk: RootWalk | null; activeRootKeyId: string }
    | { ok: false; reason: string; rootRevoked: boolean };
  export async function loadPolicyRoot(policy: Policy, now: Date, options?: { recordVersions?: boolean }): Promise<PolicyRootResult>;
  ```
  It reads the state file and the log, calls `checkRootEvents`, and when `options.recordVersions !== false` and `policy.statePath` is set, saves `progress` with the same merge-before-write as `loadPolicyTrust`. For a policy without `recovery` it returns `{ ok: true, walk: null, activeRootKeyId: policy.rootKeyId }` without reading anything.
- Every existing test of `loadPolicyTrust` passes unmodified; new tests compare `loadPolicyRoot` and `loadPolicyTrust` results and state bytes on v1, v2, rollback, fork and revoked root.

### 6. Keys outside Skills (F5)

- `arm` refuses a key whose canonical path (realpath) is inside any of: the GUI's discovery roots, every discovered Skill folder, the pin policy's `skill_dirs`, and the host policy's `skill_dirs`. The message is fixed text without the path.
- `approve` passes the armed key's canonical path to `resolveOutside(keyPath, skillDir, ...)` before signing, and maps its error to fixed text.
- **Limits stated in the spec.** A copy or hard link of the key inside a Skill is not detected (a moved key fails the stored-path check at signing); the private-key scan at signing covers digest-covered files only, as in the CLI.

### 7. One read for the name, and the moment of signing (F6, F8, F13)

- `approveSkill` gains three options: `expectName?: string` (refuse when the name derived from the signed `SKILL.md` differs), `outDir?: string` (write to `<outDir>/<signed name>.cert.json`; mutually exclusive with `out`), and `beforeSign?: (info: { skillName: string; digest: string }) => void | Promise<void>`, awaited after `issueCertificate` and immediately before `writeFileAtomic`. A throw writes nothing.
- INSPECT and the review dialog take the name and digest from one `collectSkillTree(dir, { includeContents: true })` and `skillNameFromSkillFile` on those bytes. INSPECT's verdict is shown only when the verdict's digest equals the shown digest; otherwise it shows "읽는 동안 바뀌었어요 · 다시 검토하세요" and no verdict.
- `approve` passes `expectDigest` (the reviewed digest), `expectName` (the reviewed name), `outDir` (the pin's first `certificate_dirs` entry, if any) and `beforeSign`, which re-runs the role check for the captured key, compares the generation and checks the approver's scopes against `info.skillName`.
- **Remaining window.** `writeFileAtomic` awaits a few file operations after `beforeSign` returns; a disarm in that window still lets the write finish. The certificate binds the reviewed digest, so the effect is a certificate the approver authorised a moment earlier. The spec states it.

### 8. Order inside `approve`

1. Capture `op` (key id, generation). Refuse if no approver is armed or the cooldown is active.
2. Find the review record for `${keyId}|${generation}|${instanceId}`; refuse if absent or its digest differs from the request.
3. Validate the reason (item 9) and the lifetime; refuse if lifetime exceeds the key's expiry.
4. Re-run the role check; check scopes against the reviewed name.
5. Claim the record (delete it) synchronously, then show the signing dialog.
6. On cancel or timeout: restore the record if `op.generation` is still current, start the cooldown, return `{ ok: false, message: '서명을 취소했어요' }`.
7. On 서명: call `approveSkill` with the options of item 7. On any failure, return its message mapped to fixed text where it could carry a path; the record stays consumed.

### 9. Smaller fixes (F9, F12)

- **Key errors.** `arm` maps every key load error to one of: "키 파일을 읽을 수 없어요", "키 파일 권한이 너무 넓어요 (chmod 600)", "Ed25519 개인 키가 아니에요"; never the raw message.
- **Reason.** In the main process: trim; at most 1024 characters; `requireDisplaySafeText`; and at least 3 characters that are letters or digits (`\p{L}` or `\p{N}`), not counting Hangul fillers (U+115F, U+1160, U+3164, U+FFA0) and Braille blank (U+2800).
- **Key bytes.** `loadPrivateKey` already zeroes its PEM buffer; the spec's "the bytes are zeroed" becomes "best effort: the file buffer is zeroed; copies inside the crypto library cannot be". No `sensitive` read option is added.

## Alternatives considered

- **Require `freshness` for any admin role.** Rejected as the default: it forces every organisation, including a solo developer, to run a timestamp job. Revisit after persona tests.
- **A single signing dialog.** Rejected: the review and the signature attest different things, and a renderer-asserted review was the high finding.
- **Queueing disarm.** Rejected: it deadlocks or arrives after the signature (both reviews showed it).
- **Mount-namespace checks via `/proc/self/mountinfo`.** Rejected: readable and forgeable from the same namespace, like `uid_map`.
- **Scanning excluded paths for private keys at signing.** Deferred: it changes CLI behaviour and costs time on large `.git` folders; tracked as a follow-up.

## Implementation plan (files and signatures)

### Engine

- `src/admin.ts`: `approveSkill` options gain `expectName?: string`, `outDir?: string`, `beforeSign?: (info: { skillName: string; digest: string }) => void | Promise<void>`. `out` and `outDir` together throw "Pass at most one of out and outDir".
- `src/policy.ts`: `checkRootEvents` (internal, pure), `PolicyRootResult`, `loadPolicyRoot` (exported), `loadPolicyTrust` refactored to use `checkRootEvents`. `HostState` stays exported as today.

### GUI service

- `gui/src/service/types.ts`:
  - `AdminSignSummary = { action: 'approve'; skillName: string; skillPath: string; reviewedDigest: string; digest: string; lifetime: AdminLifetime; expiresAt: string; reason: string; role: AdminRole; keyName: string | null; keyId: string }`.
  - `AdminReviewSummary = { skillName: string; skillPath: string; digest: string; files: number }`.
  - `AdminStatusView` gains `memoryReset: { at: string; backup: string } | null` and `rollback: boolean` (documents older than this computer's memory).
  - `RendererApi.admin`: remove `confirmInspected`; add `review(instanceId: string): Promise<AdminActionResult>` and `resetMemory(): Promise<AdminStatusView>`.
- `gui/src/service/admin.ts`:
  - exports `mapPinPath(file: string, platform: NodeJS.Platform, readlink: (p: string) => string): string`;
  - `pinOwnershipProblem(file, rootUid, trustedBase = '/', env: { platform: NodeJS.Platform; procDir: string } = { platform: process.platform, procDir: '/proc' })`;
  - `AdminSessionOptions` gains `confirmReview: (s: AdminReviewSummary) => Promise<boolean>`, `confirmSign: (s: AdminSignSummary) => Promise<boolean>`, `confirmReset: () => Promise<boolean>` (all required), `stateDir: string`, `discoveryRoots: () => string[]`, `hostSkillDirs: () => string[]`, test-only `platform`, `procDir`, `dialogTimeoutMs` (default 120000), `cooldownMs` (default 10000);
  - `PinState.loaded` gains `root: PolicyRootResult` and `memoryFile: string`, and drops `walk`/`walkError`; `roleOf` uses `root`;
  - `AdminSession` methods: `status()`, `arm(keyPath)`, `disarm()`, `inspect(id)`, `review(id)`, `approve(id, digest, lifetime, reason)`, `check(id)`, `resetMemory()`; private `dropKey`, `serial`, `recheck`, `withTimeout`.
- `gui/src/main/main.ts`: implements the three confirm functions with `dialog.showMessageBox(window, { type: 'warning', buttons: ['취소', <action>], defaultId: 0, cancelId: 0, noLink: true, title, message, detail })`; passes `stateDir: app.getPath('userData')`, `discoveryRoots`, `hostSkillDirs`; registers `admin:review` and `admin:reset-memory`, removes `admin:confirm-inspected`; wires the window events of item 2.
- `gui/src/preload/preload.cts`: matches `RendererApi`.
- `gui/src/renderer/admin.ts`: the review button calls `review`; status polling every 5 s while the tab is visible; the memory-reset notice and the 기록 초기화 button; cancel and cooldown messages.

### Spec (`docs/spec/gui-admin-rack-v1.md`)

- Organisation pin: macOS mapping; the user-namespace hurdle and its limit; unsupported sandboxes (Flatpak, rootless containers, user-namespace CI); NixOS; replace "The pin is read without recording versions" with the GUI memory; correct "a forged or swapped document fails verification" to cover forgery only.
- Identity and armed key: synchronous disarm, generations, the queue, idle counting, status re-check and polling, window events, best-effort zeroing.
- Approve: the two dialogs, the order of section 8, `expectName`, `outDir`, `beforeSign`, cooldown and timeout, the remaining write window.
- New section "Replay and this computer's memory".
- Process boundaries: replace `admin:confirm-inspected` with `admin:review`; add `admin:reset-memory`; correct the `admin:disarm` row; replace "at worst" with "no signature without both native dialogs".
- Limits: key holders can always use the CLI; the user-namespace hurdle; hard links.

### Tests

- Seams: `AdminSession` takes the three confirm functions (tests pass promise-gated fakes), `procDir` and `platform`; `approveSkill`'s `beforeSign` is the seam for races; promise gates, never sleeps. `gui/tests/admin.test.ts`'s `world()` helper is updated to pass the new required options (that file is edited; every other existing test passes unmodified).
- `gui/tests/admin.test.ts`, one test per finding: F1 approve without a review dialog answer refused, review cancel records nothing, sign cancel restores the record and starts the cooldown; F2 fake `procDir` with a non-identity `uid_map`, and an unreadable one; F3 older trust root after a newer one refused, corrupt memory renamed aside, reset; F4 replayed root event log gives no root role; F5 key inside a discovery root, a Skill folder and a pin `skill_dirs`; F6 disarm inside `beforeSign` writes nothing, disarm during an open sign dialog writes nothing; F7 two concurrent approves with one review sign once, and a review by key A cannot be used by key B; F8 `SKILL.md` swapped to another name before signing is refused by `expectName`; F9 key errors carry no path; F10 status disarms after the pin changes and after the approver is removed; F11 `mapPinPath` on `darwin` with a fake readlink, and refusal when `/etc` points elsewhere; F12 blank, filler-only and two-letter reasons refused; F13 a change between INSPECT's tree and verdict shows no verdict.
- `tests/approve-expect-digest.test.ts`: `expectName` mismatch, `outDir`, `beforeSign` throwing writes nothing.
- `tests/root-recovery.test.ts`: `loadPolicyRoot` equals the root part of `loadPolicyTrust` (result and state bytes) on v1, v2, rollback, fork and revoked root.

## Changes from v1

- The review is a native dialog, not a renderer call; two dialogs, cooldown and timeout (antagonistic A1, comprehension 5 and 6).
- Disarm is synchronous and outside the queue; operations capture key and generation; idle counting and status polling are defined (A2, B1, comprehension 1 and 2).
- The user-namespace check is a stated hurdle, not a boundary; unsupported sandboxes and NixOS are named; an unreadable `/proc` refuses (A3, B6).
- The memory's protection is stated honestly; first run, corrupt file, legitimate reset and failed writes are defined (A4, B2).
- One read for name and digest; `expectName` and `outDir` (B3, comprehension 15).
- Order inside `approve` is explicit; claim before the dialog and restore on cancel (B4, comprehension 5).
- Key location covers both policies' `skill_dirs`; limits stated (B5, A7).
- `loadPolicyRoot` shares a pure `checkRootEvents` with `loadPolicyTrust`; the state handoff is defined (comprehension 8, A9).
- Reasons need real letters or digits; fillers do not count (A6, comprehension 13).
- No `sensitive` read option; zeroing is best effort (A8, comprehension 3).
- Test seams and the edited helper are named; findings are numbered (B7, B8, comprehension 11 and 12).
- The spec changes list covers every sentence the design overturns (B9, comprehension 10).

## Decisions and exact details (v3)

This section wins over every earlier section. "D" numbers answer the v2 comprehension check; "R" numbers answer the v2 readiness check.

### Roles, root and memory

- **D1 Revoked root.** `PolicyRootResult`'s failure variant carries `walk: RootWalk | null` (the walk up to and including the revoke, or null when the log could not be walked). `roleOf`: the root role requires `pin.root.ok` and `pin.root.activeRootKeyId === keyId`; recovery and timestamp roles use `pin.root.walk` whenever it is non-null (so trustees can sign the rotation after a revoke); `activeRoot(pin)` returns null when `!pin.root.ok`.
- **D2 Typed failures (R3).** Engine failure results gain optional typed fields, messages unchanged: `TrustContextResult`'s failure variant and `PolicyRootResult`'s failure variant get `rollback?: true` (set wherever a version, sequence or timestamp version is lower than the state's: `loadTrustContext`'s minimum checks in `src/verify.ts`, the root-event rollback in `checkRootEvents`, the timestamp minimum in `loadPolicyTrust`) and `stateError?: 'unreadable' | 'write'` (set at the existing `readState` catch and at the save failure). The GUI matches only these fields, never message text.
- **D3 Who writes the memory.** Every `readPin` call records (`recordVersions: true`), queued or not; concurrent writes are safe within one process; see Known limit.
- **D4 Memory write failure.** `stateError: 'write'` makes `readPin` return `{ kind: 'invalid', reason: '이 컴퓨터의 기록을 저장하지 못했어요: ' + reason }`; `recheck` and `current` drop the key on any non-`loaded` pin.
- **D5 Corrupt memory.** `stateError: 'unreadable'` makes `readPin` rename the file to `admin-state.json.unreadable-<ISO time with ':' replaced by '-'>`, set `AdminSession.memoryReset = { at, backup }` and load again once. **Rollback** (`rollback: true` from either result) makes `AdminStatusView.rollback = true`; the tab shows `이 컴퓨터가 이미 본 것보다 오래된 문서예요. 조직이 문서를 다시 만들었다면 기록을 초기화하세요.` and the 기록 초기화 button.
- **D6 `checkRootEvents` exact signature.**
  ```ts
  type RootEventLog = { bytes: Buffer } | { error: string } | null; // null: policy has no recovery
  type RootProgress = { sequence: number; event_digest: string; revoked?: true };
  function checkRootEvents(policy: Policy, state: HostState, log: RootEventLog, now: Date):
    | { ok: true; walk: RootWalk | null; activeRootKeyId: string; progress: RootProgress | null }
    | { ok: false; reason: string; rootRevoked: boolean; rollback?: true; walk: RootWalk | null; progress: RootProgress | null };
  ```
  `{ error }` reproduces today's "root event log: <error>" failure including the rule that a recorded revoke survives an unreadable log (`rootRevoked: true`). Callers that apply a non-null `progress` set `state.rootEvents[policy.rootKeyId] = progress`, `state.v2 = true` and mark the state changed, exactly as today's lines do.
- **D7 Reset.** `resetMemory()` needs no armed key (it only discards this computer's memory), is queued, opens a native confirmation (`기록 초기화` / `이 컴퓨터가 기억하는 조직 문서 버전을 지울까요? 오래된 문서를 다시 받아들일 수 있게 돼요.`, buttons `취소`, `초기화`), and on 초기화 renames the file aside as in D5 and drops any armed key. `admin:dismiss-memory-reset` clears `memoryReset` (copy of `history:dismiss-reset`).

### Dialogs, queue and approve

- **D8 Dialog timeout.** `withTimeout(p, ms)` resolves `false` after `dialogTimeoutMs`; the dialog may stay on screen and a late answer is ignored. Cooldown and "dialog open" state use `Date.now()`, not `options.now`.
- **D9 Cooldown and one dialog at a time.** `review`, `approve` and `resetMemory` are refused while any admin dialog is open (`다른 확인 창이 열려 있어요`) and for `cooldownMs` after any cancel or timeout (`잠시 후 다시 시도하세요`).
- **D10 Review role.** `review` requires the approver role (phase 1). It records `{ digest, name, keyId, generation }` under key `` `${keyId}|${generation}|${instanceId}` ``.
- **D11 Approve, exact order** (replaces section 8): 1. capture `op = { keyId: armed.key.keyId, generation }`; refuse with `승인자 키를 먼저 불러오세요` if no approver is armed, D9 refusals. 2. record lookup; absent or digest differs → `먼저 이 정확한 버전을 검토하세요`. 3. reason (D15) and lifetime; lifetime past key expiry → `이 기간은 승인자 키의 만료(<date>)를 넘어요. 더 짧게 고르세요.` 4. `current('approver')` re-check; scopes against `record.name` → `범위(<scopes>)가 Skill 이름 "<name>"을 포함하지 않아요`. 5. read the Skill once (`collectSkillTree` with contents, `skillNameFromSkillFile`); digest ≠ record.digest or name ≠ record.name → `검토한 뒤 Skill이 바뀌었어요. 다시 검토하세요`. 6. claim (delete) the record, open the signing dialog showing that read's digest. 7. cancel or timeout: restore the record if `op.generation === this.generation`; cooldown; `서명을 취소했어요`. 8. 서명: `approveSkill({ skillDir, approverKey, now, expires, reason, expectDigest: record.digest, expectName: record.name, outDir?, beforeSign })`. `approveSkill` checks `expectDigest` first, then `expectName` (`Refusing to approve: the Skill name is "<x>", not the reviewed "<y>"`). `beforeSign` refuses with `키가 빠졌어요` on generation mismatch and re-runs the role and scope checks. 9. failure: return the engine message unless it contains `/`, else `서명하지 못했어요. Skill을 다시 검토하세요.`
- **D12 Status re-check.** A role "change" is any difference in role kind, key id, scopes or expiry. `hostSkillDirs` returns `[]` when the host policy is missing or invalid; arm proceeds.
- **D13 INSPECT verdict.** `AdminInspectView` gains `verdictStale: boolean`: true when the verdict's `digest` is non-null and differs from the shown digest; the renderer then hides the verdict and shows `읽는 동안 바뀌었어요 · 다시 검토하세요`. A null verdict digest (trust failures, unverifiable) shows the verdict. INSPECT keeps the name fallback to the instance name if `SKILL.md` cannot be read.
- **D14 `dialogSafe(text)`.** Replaces C0/C1 controls (except none), U+2028–U+202E, U+2066–U+2069, U+200B–U+200F and U+FEFF with `⟨U+XXXX⟩`. Applied to paths, names and reasons in every dialog.
- **D15 Reason rule, in `AdminSession.approve`.** Trim; at most 1024 UTF-16 units (`이유는 1024자 이하여야 해요`); `requireDisplaySafeText`; at least 3 code points matching `/[\p{L}\p{N}]/u` other than U+115F, U+1160, U+3164, U+FFA0, U+2800 (`이유에 글자나 숫자를 3개 이상 적으세요`).

### Inputs, types and text (R4, R5, R8)

- `ObservationService` (`gui/src/service/service.ts`) gains `hostSkillDirs(): string[]` returning `this.host?.policy?.skillDirs ?? []`. `AdminSessionOptions` gains `skillFolders: () => string[]` (main passes `svc.view().instances.map((i) => i.path)`).
- `readPin(options: { path: string; rootUid: number; trustedBase?: string; now: Date; memoryFile: string; platform: NodeJS.Platform; procDir: string; readlink: (p: string) => string })`.
- `Armed` gains `keyPath: string` (canonical, never sent anywhere); key id is `armed.key.keyId`.
- `mapPinPath` on `darwin` when `/etc` is not a link to exactly `private/etc`: returns the path unchanged (the walk then refuses it as a symbolic link).
- `main.ts`: when `window` is null, `dialog.showMessageBox(options)` without a parent.
- Exact dialog text. Review: title `Skill 검토 확인`, message `이 정확한 버전의 파일을 모두 검토했나요?`, detail lines `Skill: <name>`, `폴더: <path>`, `버전: <digest>`, `파일: <n>개`, buttons `취소`, `검토함`. Sign: title `인증서 서명`, message `이 Skill 버전에 인증서를 서명할까요?`, detail lines `Skill: <name>`, `폴더: <path>`, `검토한 버전: <reviewed digest>`, `서명할 버전: <digest>`, `기간: <lifetime> (만료 <date>)`, `이유: <reason>`, `키: <role> · <name> · <key id>`, buttons `취소`, `서명`.
- Refusal text: review cancel `검토를 기록하지 않았어요`; uid map `이 실행 환경(사용자 네임스페이스)에서는 조직 고정 정책을 믿을 수 없어요`; unreadable map `실행 환경을 확인할 수 없어 조직 고정 정책을 쓰지 않아요`; key inside a Skill `Skill 폴더 안에 있는 키는 쓸 수 없어요. 키를 Skill 밖으로 옮기세요.`; key load errors: missing or unreadable (ENOENT, EACCES, not a regular file) `키 파일을 읽을 수 없어요`, permissions `키 파일 권한이 너무 넓어요 (chmod 600)`, "not a valid PKCS#8 key" or "not Ed25519" `Ed25519 개인 키가 아니에요`; memory-reset notice `이 컴퓨터의 관리 기록을 읽을 수 없어서 따로 보관하고 새로 시작했어요 (<backup>)`.

### Tests (R1, R7)

- `gui/tests/admin.test.ts` is rewritten where needed: every `confirmInspected(id, digest)` becomes `review(id)` with `confirmReview` resolving `true`; `world()` and the stand-alone session pass all required options, including a `procDir` fixture (a temp dir with `self/uid_map` and `self/gid_map` containing `0 0 4294967295`), `platform: 'linux'`, `stateDir` in a temp dir, and confirm fakes that resolve `true` unless a test overrides them.
- Seams: `AdminSessionOptions.hooks?: { afterInspectTree?: () => Promise<void>; beforeSign?: () => Promise<void> }` (test-only; called between INSPECT's tree read and its verdict, and at the start of the session's `beforeSign`). F13 uses `afterInspectTree` to change `SKILL.md`; F6 uses `hooks.beforeSign` to call `disarm()` and asserts no certificate is written, and separately disarms from inside the `confirmSign` fake.
- `setupRecoveryOrg` moves from `tests/root-recovery.test.ts` to `tests/helpers.ts` (exported) so `gui/tests/admin.test.ts` can build a v2 organisation for F4; `tests/root-recovery.test.ts` imports it.
- Files edited in total: `src/admin.ts`, `src/policy.ts`, `src/verify.ts`, `gui/src/service/admin.ts`, `gui/src/service/types.ts`, `gui/src/service/service.ts`, `gui/src/main/main.ts`, `gui/src/preload/preload.cts`, `gui/src/renderer/admin.ts`, `gui/src/renderer/app.ts` (start and stop the 5-second status poll when the 관리 tab is shown or hidden), `docs/spec/gui-admin-rack-v1.md`, `gui/README.md`, `CHANGELOG.md`, and the tests named above. The spec's `admin:disarm` row becomes: `Drops the armed key at once (synchronous; ends any operation in progress)`.

## Readiness addenda (v4)

Wins over every earlier section, including v3. Numbers answer the v3 readiness check.

1. **Timestamp rollback.** `src/timestamp.ts` exports `class TimestampRollbackError extends Error {}`; `verifyTimestamp` throws it (same message) for a version below `minimumVersion`. `loadPolicyTrust`'s freshness catch sets `rollback: true` when the error is a `TimestampRollbackError`. `src/timestamp.ts` is added to the edited files.
2. **F8 test.** Engine test in `tests/approve-expect-digest.test.ts`: unchanged Skill, `expectName: 'other'`, expects `Refusing to approve: the Skill name is "docs-helper", not the reviewed "other"`. GUI test: swap `SKILL.md` between `review` and `approve`; expects `검토한 뒤 Skill이 바뀌었어요`.
3. **Edits to existing assertions in `gui/tests/admin.test.ts`** (these lines change; nothing else in existing tests): the public-key-as-private-key assertion becomes `/키 파일 권한이 너무 넓어요/u`; "inspect this exact version first" assertions become `/먼저 이 정확한 버전을 검토하세요/u`; the scope assertion `/Skill 이름 "pdf-tools"을 포함하지 않아요/u`; "changed since it was reviewed" `/검토한 뒤 Skill이 바뀌었어요/u`; "outlast your approver key" `/승인자 키의 만료/u`; every `confirmInspected` call becomes `review(id)`. `world()` passes `discoveryRoots: () => [skills]`.
4. **Key-load mapping with a default.** Error code `ENOENT` or `EACCES`, and any error not matched below → `키 파일을 읽을 수 없어요`; message containing `Private key permissions` → `키 파일 권한이 너무 넓어요 (chmod 600)`; containing `not a valid PKCS#8 key` or `not Ed25519` → `Ed25519 개인 키가 아니에요`.
5. **Reason order.** Trim first; an empty result → `이유에 글자나 숫자를 3개 이상 적으세요`; then length (`이유는 1024자 이하여야 해요`), `requireDisplaySafeText`, then the letter-or-digit count. The F12 test includes whitespace-only input. `main.ts` checks only `typeof reason === 'string'` and a raw length of at most 4096 (English error is fine there); the 1024 rule lives in `AdminSession`.
6. **Key location in `approve`.** After D11 step 4, call `resolveOutside(armed.keyPath, skill.path, 'Approver private key')`; any error → `Skill 폴더 안에 있는 키는 쓸 수 없어요. 키를 Skill 밖으로 옮기세요.` D11 step 1 refuses with `승인자 키를 먼저 불러오세요` only when **no key** is armed; an armed key of another role gets `current('approver')`'s message `this needs the approver role; the armed key is <role>` (kept in English, as the existing test expects).
7. **Order inside `review` and `arm`.**
   - `review(id)`: D9 refusals; capture `op`; `current('approver')` (or, from phase 2, the role the caller passes); read the tree with contents and derive the name; `await withTimeout(confirmReview(summary), dialogTimeoutMs)`; if `true` and `op.generation === this.generation`, record and return `{ ok: true }`; otherwise start the cooldown and return `{ ok: false, message: '검토를 기록하지 않았어요' }`.
   - `arm(path)`: `dropKey('arm')`; `readPin`; non-`loaded` pin → refuse with its reason; load the key (mapped errors, item 4); canonical path; key-location check (§6); `roleOf`; `proveIdentity`; set `armed = { key, keyPath, role, pinSha, lastUsed: Date.now() }`.
8. **Dismissing the memory notice.** `RendererApi.admin.dismissMemoryReset(): Promise<AdminStatusView>`; preload `ipcRenderer.invoke('admin:dismiss-memory-reset')`; main handler calls `session.dismissMemoryReset()` then returns `session.status()`; `AdminSession.dismissMemoryReset(): void` sets `memoryReset = null`.
9. **Wiring.** main passes `discoveryRoots: () => svc.view().roots.map((r) => r.path)`, `skillFolders`, `hostSkillDirs: () => svc.hostSkillDirs()`. `AdminSession` passes `readlink: (p) => readlinkSync(p)` (node:fs) to `readPin`; `mapPinPath` treats a thrown `readlink` as "not a link" (returns the path unchanged).
10. **Exact result types.**
    ```ts
    export type PolicyRootResult =
      | { ok: true; walk: RootWalk | null; activeRootKeyId: string }
      | { ok: false; reason: string; rootRevoked: boolean; walk: RootWalk | null; rollback?: true; stateError?: 'unreadable' | 'write' };
    ```
    `TrustContextResult`'s failure variant (`src/verify.ts`) gains `rollback?: true; stateError?: 'unreadable' | 'write'`.
11. **`inspected` in INSPECT.** `inspect()` sets `inspected: this.armed !== null && this.reviews.get(\`${this.armed.key.keyId}|${this.generation}|${instanceId}\`)?.digest === tree.digest`.

Further decisions:

- `withTimeout` clears its timer when the promise settles and calls `unref()` on it.
- "A dialog is open" means a dialog promise has not settled yet (a counter in `AdminSession`), not that an operation is unfinished.
- `checkRootEvents` catches errors thrown by the walk itself and returns them as `root event log: <message>`, as today's `try` does.
- `pinView.reason` uses `pin.root.ok ? null : 'root event log: ' + pin.root.reason` when the pin is loaded; `roleOf`'s notes use `pin.root` in place of `walkError` (the root-revoked note uses `pin.root.walk?.revoked`).
- `Key` and `RecoveryOrg` move to `tests/helpers.ts` together with `setupRecoveryOrg`.
- `dialogSafe` is exported from `gui/src/service/admin.ts`.
- Known limit, stated in the spec: an unqueued `status` poll that overlaps a load while the root event log grows can report a transient rollback; the next poll clears it.

### Readiness addenda (v5)

Wins over everything above. Answers the v4 readiness check; with these the design is ready for implementation.

1. **Absent roots in `arm`.** `arm` checks the key against each root (`discoveryRoots()`, `skillFolders()`, the pin's `skillDirs`, `hostSkillDirs()`) with `isInside(await realpathAllowingMissing(root), keyCanonical)`, both exported by `src/fs-safe.ts`. A root whose resolution throws is skipped. `resolveOutside` is used in `approve` only (v4 item 6).
2. **`loadPolicyRoot` equality test.** For each case compare results: on success `activeRootKeyId` (for v2 also `walk.count` against `context.root.sequence`); on failure `reason`, `rootRevoked`, `rollback`. For state, compare only the parsed `root_events` and `v2` fields of each file, an absent file reading as none.
3. **Reasons and rollback in `checkRootEvents`.** The error, rollback and fork branches keep calling today's `blocked()` (so a recorded revoke still yields "revoked by root event N, and the root event log cannot be checked now", as `tests/root-recovery.test.ts` expects). The post-merge rollback in the save returns `rollback: true` in both `loadPolicyTrust` and `loadPolicyRoot`.
4. **`roleOf` notes**, replacing the `walkError` branch: `if (!pin.root.ok && pin.root.walk === null) note = \`the root event log cannot be checked (${pin.root.reason}), so root and recovery roles are not recognised\`; else if (pin.root.walk?.revoked && pin.root.walk.activeRootKeyId === key.keyId) note = \`this root key was revoked by root event ${pin.root.walk.revoked.sequence}\`;` then today's trust and default branches unchanged.
5. **Small decisions.** The `pinOwnershipProblem` assertions in `gui/tests/admin.test.ts` pass the `procDir` fixture and `platform: 'linux'`. F13 asserts `verdictStale === true`. `memoryReset.backup` is an absolute path. `resetMemory()` returns `AdminStatusView` (main returns it). On darwin, `PinState.path` and `AdminPinView.path` hold the mapped path; `hostPolicyDiffers` compares the host policy's realpath with it.


### Code review fixes (v5.1)

The two Goldfish code reviews of `fcc8192` found no HIGH findings. The fixes below take precedence over v5 where they differ. **S** findings come from the security review and **C** findings from the correctness review.

1. **Serialised state writes (S2, C-F1).**
   - **Serialise per file.** `persistState` in `src/policy.ts` is serialised per canonical `statePath` with a module-level promise chain (`Map<string, Promise<unknown>>`). Each call waits for the previous one on the same path, runs its own read-merge-write, and releases the chain whether it succeeds or fails.
   - **Read errors.** Inside `persistState`, only `ENOENT` counts as "no disk state". Any other read error fails the write, with `stateError: 'write'` and the existing message.
   - **Cross-process residual.** Two processes sharing one state file are still not serialised. The spec says so in its "Known limit" bullet: *two processes that load at the same moment while a document changes can lower a recorded version until the newer document is loaded again.* The bullet replaces the transient-rollback sentence (C-F6).
2. **Moving the memory aside (S1, C-F4).**
   - **The error split.** `readState` throws `HostStateFormatError` (new, exported) for:
     - a JSON parse error;
     - an exact-keys or format error;
     - a bad counter;
     - a file over the size limit;
     - a path that exists but is not a regular file.

     Every other error, I/O errors included, is rethrown unchanged.
   - **The failure kinds.** `stateError` becomes `'corrupt' | 'unreadable' | 'write'`. `'corrupt'` is set only for `HostStateFormatError`; `'unreadable'` is set for any other read error.
   - **`readPin` handling.**
     - On `'corrupt'`, `readPin` renames the memory aside, as D5 says today.
     - On `'unreadable'`, it retries the whole read 3 times, after 50, 100 and 200 ms. If the read still fails, the pin is `invalid` with `이 컴퓨터의 관리 기록을 지금 읽을 수 없어요. 잠시 후 다시 시도하세요.`, and nothing is renamed.

     The error `<label> changed while being read` (`fs-safe.ts`) is an `'unreadable'` error.
3. **Key-file picker (S3).** The picker opens through `AdminSession.pickFile(open: () => Promise<string | null>): Promise<string | null>`. It applies the D9 refusal (one dialog open), counts in `dialogsOpen`, and starts the cooldown on cancel. Refusals use the existing D9 and cooldown texts, returned to the renderer as `{ ok: false, reason }`. `admin:arm` in `main.ts` calls `session.pickFile(() => dialog.showOpenDialog(...))`, then `session.arm(path)`.
4. **`dialogSafe` (S4).** The character class becomes `/[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Cn}\p{Zl}\p{Zp}]/gu`, with the same `⟨U+XXXX⟩` replacement. A code point above U+FFFF is shown with `codePointAt`, padded to at least 4 hex digits.
5. **One key file (S6).**
   - **At arm.** `arm` first computes `canonical = await realpath(keyPath)`. It opens `canonical` with `O_NOFOLLOW`, checks `isFile()` on the handle, and reads at most 64 KiB from that handle. It loads the key from those bytes, and stores `canonical` together with the handle's `dev` and `ino`.
   - **Before signing.** `approve` runs `lstat(canonical)`. If the path is not a regular file with the same `dev` and `ino`, the key is dropped and approve returns `키 파일이 바뀌었어요. 다시 불러오세요.`
   - **Bytes loader.** The engine needs a bytes loader (`loadPrivateKeyBytes(bytes: Buffer): PrivateKeyInfo`) if one does not exist yet. The existing path loader then calls it.
6. **Lifetime against the armed key (C-F2).** After `current()` in `approve`, the lifetime check uses `armed.role.expiresAt` as `current()` refreshed it. It refuses with the existing D11 lifetime message.
7. **Key inside Skills at signing (C-F3).** Before the signing dialog, and in `beforeSign`, `approve` re-runs the arm-time check with the current roots: `keyInsideSkills(armed.keyPath, pin)`. If the key now lies inside a Skill, it refuses with `KEY_IN_SKILL`. That matches spec line 82.
8. **Dialog counter liveness (C-F8).** `ask()` releases its `dialogsOpen` slot when the dialog settles or `dialogTimeoutMs + 5000` ms after it opened, whichever comes first. The spec states that a dialog stuck past that time no longer blocks other dialogs, and that its late answer is ignored.
9. **Renderer ordering (C-F7, C-F9).**
   - **Status responses.** `admin.ts` in the renderer numbers its status requests and adopts a response only if it is the newest one sent.
   - **Skill selection.** `selectSkill` sets `skillId` inside `run()`, after the busy check.
10. **Reset feedback (C-F10).** `resetMemory()` returns `{ ok: true; status: AdminStatusView } | { ok: false; message: string; status: AdminStatusView }`. A refusal carries the D9 or cooldown text, and the renderer shows the message.
11. **Tests (C-F5).** Add these tests:
    - a `confirmSign` fake that changes `SKILL.md`, after which approve refuses;
    - an approver re-added with a new expiry or narrower scopes, after which `status()` shows `armed: null`;
    - a `readPin`-level memory write failure, using a read-only memory file and not a failed `mkdir`;
    - a reset while a key is armed, after which `armed` is `null`;
    - the concurrent-`persistState` test: two overlapping loads with a document change never lower a version, using the reviewer's scratch recipe;
    - an `'unreadable'` error that is retried and does not rename, and a `'corrupt'` error that renames;
    - the picker refused while a dialog is open;
    - the `dialogSafe` code points U+061C, U+2060, U+FFF9, U+180E and U+00AD;
    - a key file swapped after arm, refused with the new message;
    - a lifetime past the refreshed expiry, refused;
    - a key folder that becomes a discovery root after arm, refused.

    Replace the 80 ms sleep in the idle test with mock timers.
12. **Spec.** Update the following:
    - lines 82 and 148 of `docs/spec/gui-admin-rack-v1.md` (items 1 and 7);
    - the memory paragraph, for items 1 and 2;
    - the dialogs paragraph, for items 3 and 8;
    - D3's "concurrent writes are safe", which becomes *safe within one process; see Known limit*.

### Review of v5.1 (v5.2)

The review of `21b4504..7802a6c` found no HIGH findings. These changes take precedence over v5.1. The reviewer's verified candidate fixes are in `/var/tmp/review-v51-scratch/mut4`.

1. **One dialog at the moment it opens (F1).**
   - `approve` calls `this.requireNoDialog()` again immediately before it claims the review record (before the signing dialog).
   - `review` calls it again immediately before `ask(confirmReview)`.

   So the check runs when the dialog is shown, not only when the operation starts. Test: a queued approve that yields, plus a `pickFile` call, never has two dialogs open.
2. **Key file identity after the dialog (F2).**
   - `approve` awaits `requireSameKeyFile(armed)` before the `resolveOutside` and `keyInsideSkills` checks.
   - `beforeSign` awaits `requireSameKeyFile(latest.armed)` again.

   A key moved away or swapped then returns `키 파일이 바뀌었어요. 다시 불러오세요.` and drops the key. Test `admin.test.ts:242` expects that message, no longer `KEY_IN_SKILL`. New tests cover:
   - a key moved into a digest-excluded folder (`.git`) during the dialog is refused and no certificate is written;
   - a key moved away before the dialog gives the swap message and the key is dropped.
3. **Canonical chain key (F3).** The `persistState` chain is keyed by `await canonicalOrLexical(statePath)`. Test: two spellings of the same file, through a symlinked folder, never lower a version.
4. **Renderer (F4).** Every renderer call that sets status (disarm, reset, dismiss, fetch) goes through the request counter.
5. **`dialogSafe` (F5).** The variation selectors U+FE00–U+FE0F and U+E0100–U+E01EF, U+034F, U+3164 and U+2800 are added to the replaced set. The rest of `\p{Mn}` is not added, so decomposed accents are kept.
6. **Unreadable memory recovery (F7).** The `기록 초기화` button is also shown when the pin is invalid with `MEMORY_BUSY`. A rename needs no read permission.
7. **Known limit restored (F8).** The spec's Known limit again says that an unqueued status poll that overlaps a load while the root event log grows can report a transient rollback.
8. **Tests (F9).**
   - `tests/root-recovery.test.ts:725` must reach the write path: corrupt the file after the first load, then load again with a newer document, and check that the corrupt bytes are unchanged.
   - `admin.test.ts:709` adds the folder to `discoveryRoots`, through a mutable world option, and no longer to `hostSkillDirs`.
9. **Wording (F10).**
   - The design, spec and CHANGELOG say "the key file must be the same file, and must not be inside a Skill, both before the dialog and immediately before signing".
   - "canonical" is now true.
   - The spec says "mock timers" in place of "promise gate".
   - `resetMemory`'s `ok` is documented as "not refused": a cancel is `ok: true`.
