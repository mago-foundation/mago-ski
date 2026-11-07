# Design: hardening the administration rack (phase 1.1)

Status: draft v2, for Goldfish review (Elephant/Goldfish model: the design passes the comprehension, antagonistic and readiness checks before any code). v1 failed the comprehension check and two antagonistic reviews found gaps; this version resolves them (see [Changes from v1](#changes-from-v1)).

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
- **Text.** Every field shown in a dialog is already display-safe (Skill names are ASCII by `validateSkillName`; the reason passes `requireDisplaySafeText`; paths are shown as they are; long text is cut at 300 characters with an ellipsis).

### 2. Synchronous disarm and a queue for the rest (F6, F7, F10)

- `dropKey(reason)` is private and **synchronous**: `armed = null`, `generation += 1`, `reviews.clear()`, clear the idle timer. It is never queued and is safe to call from anywhere, including inside queued work and from event handlers. The public `disarm()` calls it directly.
- `arm`, `review` and `approve` run through one promise queue (`serial`). `status` and `inspect` and `check` are **not** queued (they only read) and never wait for a dialog.
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
- **Failed write.** A failure to write the memory makes the pin `invalid` with the reason; it does not disarm by itself (the next re-check does if the role is gone).
- **What it protects.** Accidental replay and replay by a third party who can change the documents but not this user's profile. It does not protect against the user, who can delete or move it (including with `MAGO_SKI_GUI_DATA`). With `freshness` in the pin, the timestamp bounds replay for everyone.

### 5. `loadPolicyRoot` and a shared pure check (F4)

- In `src/policy.ts`, the root-event part of `loadPolicyTrust` (lines that walk the log, compare with `state.rootEvents`, record progress and detect a revoked root) moves into a **pure** internal function:
  ```ts
  function checkRootEvents(policy: Policy, state: HostState, logBytes: Buffer | null, now: Date):
    | { ok: true; walk: RootWalk | null; activeRootKeyId: string; progress: HostState['rootEvents'][string] | null }
    | { ok: false; reason: string; rootRevoked: boolean; progress: HostState['rootEvents'][string] | null };
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
- **Limits stated in the spec.** A hard link to the key elsewhere, or a key moved into a Skill after arming, is not detected; the private-key scan at signing covers digest-covered files only, as in the CLI.

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
