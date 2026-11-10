# Design: administration rack phase 2 (approvers, revocation, refresh, timestamp)

Status: v10, 2a ready for implementation. Precedence: [Decisions (v10)](#decisions-v10) > [Decisions (v9)](#decisions-v9) > [Decisions (v8)](#decisions-v8) > [Decisions (v7)](#decisions-v7) > [Decisions (v6)](#decisions-v6) > [Decisions (v5)](#decisions-v5) > [Decisions (v4)](#decisions-v4) > [Decisions (v3)](#decisions-v3) > earlier sections.

Builds on [the hardening design](gui-admin-hardening.md) (phase 1.1; its v5 > v4 > v3 > earlier sections), which must be merged first: native dialogs with cooldown, timeout and one-dialog-at-a-time (D8, D9); the queue, synchronous `dropKey` and generations; `dialogSafe`; typed engine failures; the GUI rollback memory (`admin-state.json`); `review` records. Behaviour: [`docs/spec/gui-admin-rack-v1.md`](../spec/gui-admin-rack-v1.md), whose phase 2 sections this design updates (see [Spec changes](#spec-changes)).

## Problem

Root administrators need the CLI for every routine operation besides approving. Phase 2 brings approver management, revocation, revocation-list refresh and timestamp signing into the GUI, without letting it sign anything other than what the administrator saw, and without weakening the offline-root model.

## Threat model

As in phase 1.1, plus: a third party who can write the organisation's document folder (the paths the pin names) between the dialog and the write, and the timestamp key's online exposure. Same non-goals: the user at the keyboard tampering with their own machine, same-user malware, root, and key holders using the CLI.

## Technical plan

### 1. Prepare, confirm, commit

Every root and timestamp write is two engine calls:

- `prepare*` reads the current document once, verifies it under the active root, applies the change and returns a `Prepared*` object: the exact unsigned payload to sign (already including version, `issued_at`, `expires_at`), the SHA-256 of the bytes it read (`baseSha256`), and a summary for the dialog. It never signs or writes.
- After the native dialog, `commit*(prepared, key, { beforeWrite })` re-reads the document and refuses if its SHA-256 is not `baseSha256` (`문서가 그 사이에 바뀌었어요. 다시 준비하세요.`); signs **exactly** `prepared.payload` (no recomputation, one `now`); calls `beforeWrite`; then writes with `writeFileAtomic(path, bytes, mode, { expectSha256: baseSha256 })`, which re-hashes the current file immediately before the rename and refuses on a mismatch. A small window between that final hash and the rename remains and is stated in the spec.

### 2. Versions and the GUI rollback memory

- **Refuse stale bases.** `prepare*` refuses (`이 컴퓨터가 본 것보다 오래된 문서예요. 최신 문서를 되돌려 놓으세요.`) when the document's version is below the GUI memory's version for that key (`roots[activeRoot]` for trust root and revocation list, `timestamps[timestampKey]` for the timestamp).
- **Next version.** `max(document version, memory version) + 1`.
- **Record on write.** After a successful commit, the GUI records the new version in its memory with a new engine helper `recordDocumentVersions` (§Engine), even when the organisation's trust cannot fully load yet (freshness mismatch).
- **Memory reset** (hardening D7) is still offered, but its native dialog now says that root writes then accept whatever is on disk as the base.

### 3. Freshness consequences

In an organisation whose pin has `freshness`, any trust-root or revocation-list write makes hosts refuse every Skill until a new timestamp naming the new documents is signed (hosts check digests). Therefore:

- every root signing dialog in a freshness organisation adds the line `이 조직은 타임스탬프를 써요: 새 타임스탬프를 서명할 때까지 enforce 모드의 호스트는 모든 Skill을 막아요.`;
- each root template ends with POLICY CHECK, which in a freshness organisation reports the timestamp mismatch as expected and points to the *Sign timestamp* template;
- the expected POLICY CHECK result after a revoke is `REVOKED` without freshness, and "trust unavailable until a new timestamp" with it.

### 4. Templates (replaces the spec's three phase 2 templates)

The online timestamp key must not be armed in the same session as the offline root key, so *Publish* is split:

| Template | Chain | Role |
|---|---|---|
| Manage approvers | IDENTITY → TRUST ROOT → POLICY CHECK | Root |
| Revoke | IDENTITY → TARGET → REVOKE → POLICY CHECK | Root |
| Refresh revocation list | IDENTITY → REVOCATION REFRESH → POLICY CHECK | Root |
| Sign timestamp | IDENTITY → TIMESTAMP → POLICY CHECK | Timestamp signer |

- **Arming a root or recovery key** opens a native dialog first: `루트 키와 복구 키는 오프라인 관리용 컴퓨터에서만 써야 해요. 이 컴퓨터가 그런 컴퓨터인가요?` (buttons `취소`, `예, 오프라인 관리용이에요`). It counts as a dialog for D8 and D9.
- **Choosing an approver's public key** (`pickPublicKey`) counts as a dialog for D9.

### 5. Role separation and retired keys

- `RootWalk` gains `retired: string[]`: every key that left the root or timestamp role in the walked events (the walker already tracks it).
- **Host fix (all hosts, not only the GUI):** `loadPolicyTrust` refuses a trust root that lists an approver whose key id is in `walk.retired` (`trust root lists approver <id>, which has held the root or timestamp role; a key that left those roles never takes another`), as UNVERIFIABLE. This closes the reproduced re-enrolment of a rotated-out root key, which today verifies.
- **Engine:** `prepareTrustRootChange` takes `forbidden: { keyId: string; why: string }[]` and refuses an added approver in it. The GUI passes the active root, the active recovery set, the active timestamp key, `walk.retired`, and every key in the revocation list. The CLI's `root add-approver` gains an optional `--policy FILE` that computes the same list; without it, behaviour is unchanged except the existing root check.
- **Add-approver refused when the root event log cannot be walked** (`루트 이벤트 기록을 확인할 수 없어서 승인자를 추가하지 않아요`).

### 6. Consequences shown before signing

`prepare*` returns, and the dialog shows, the consequence computed over **every configured folder**: the GUI's discovery roots, the pin's `skill_dirs`, the host policy's `skill_dirs`, plus the pin's `certificate_dirs` for certificate lookup. For each discovered Skill, the verdict under the current trust context and under the prepared one (built from the prepared payload in memory). The dialog shows `영향받는 Skill: <n>개 (VERIFIED → <verdict>)`. Removing the last approver adds `남는 승인자가 없어요`; adding an approver that already exists shows `이미 승인자예요: 범위 <old> → <new>, 만료 <old> → <new>`; a scope `*` adds `모든 Skill을 승인할 수 있는 범위예요`.

### 7. Revocation targets

TARGET offers, and REVOKE accepts, only: a digest the armed key reviewed this generation (hardening D10, with the root role allowed to review), or a key id that is a current approver in the trust root, or the `approverKeyId` of a certificate found in any configured folder. A key id already revoked is refused before the dialog. The dialog states permanence: `폐기는 되돌릴 수 없어요. 이 키가 서명한 모든 인증서가 영구히 검증되지 않아요.` (key) or `… 이 버전의 모든 인증서가 …` (digest).

### 8. Timestamp

`prepareTimestamp` verifies that the trust root and revocation list on disk load under the active root (`loadTrustContext`, expiry included) and are not older than the GUI memory; refuses otherwise. The dialog shows each document's version and SHA-256 and whether this computer has seen it before (`이 컴퓨터가 처음 보는 문서` when not in the memory). Version: hardening memory rule (§2). The lifetime is capped at `freshness.max_lifetime`. The key comes from the armed timestamp signer (its `PublicKeyInfo` is in the prepared object).

### 9. States the GUI must name

- **Expired trust root:** TRUST ROOT shows `신뢰 루트가 만료됐어요` and offers Renew first; add and remove ask for a new trust-root lifetime too.
- **Documents signed by a previous root** (after a rotation the documents were not adopted): every writer is disabled before any dialog with `문서가 이전 루트 키로 서명돼 있어요. 루트 사고 대응 템플릿에서 새 루트로 옮기세요 (3단계).`

### 10. Defaults

Approver key lifetime 90 days (choices 90, 180, 365); revocation list 30 days (choices 7, 30); timestamp 6 hours (choices 6, 12, 24); trust root 365 days (choices 180, 365).

## Alternatives considered

- **Signing in one engine call after the dialog** (v1). Rejected: the bytes signed were re-read and could differ from what was shown.
- **Keeping Publish as one template with a key change.** Rejected: it arms the online timestamp key in the offline root session.
- **Requiring root-owned document folders.** Deferred: many organisations publish from a git checkout; the base hash and memory checks cover the swap without it. Revisit after persona tests.
- **Proof of possession for new approvers.** Deferred: the approver proves possession when arming in phase 1; enrolment of a wrong public key only means that approver cannot sign.

## Implementation plan

### Engine

- `src/fs-safe.ts`: `writeFileAtomic(filePath, bytes, mode?, options?: { expectSha256?: string })`: with `expectSha256`, read and hash the existing file right before `rename` and throw `File changed before it could be replaced` on a mismatch (a missing file is a mismatch).
- `src/root-events.ts`: `RootWalk.retired: string[]` (sorted).
- `src/policy.ts`: the retired-approver host check (§5) in `loadPolicyTrust`, next to the existing collision check. New `export async function recordDocumentVersions(statePath: string, rootKeyId: string, versions: { trustRoot?: number; revocations?: number; timestampKeyId?: string; timestamp?: number }): Promise<void>` (merge-before-write, never lowers a version).
- `src/admin.ts`:
  ```ts
  export interface PreparedTrustRoot { kind: 'trust-root'; path: string; baseSha256: string; payload: TrustRoot; current: TrustRoot; change: TrustRootChange; replaces: Approver | null }
  export type TrustRootChange =
    | { kind: 'add'; publicKey: PublicKeyInfo; name: string; scopes: string[]; expires: string; trustRootExpires?: string }
    | { kind: 'remove'; keyId: string; trustRootExpires?: string }
    | { kind: 'renew'; expires: string };
  export async function prepareTrustRootChange(o: { rootKeyId: string; trustRootPath: string; now: Date; change: TrustRootChange; forbidden?: { keyId: string; why: string }[]; minimumVersion?: number }): Promise<PreparedTrustRoot>;
  export async function commitTrustRoot(p: PreparedTrustRoot, rootKey: PrivateKeyInfo, o?: { beforeWrite?: () => void | Promise<void> }): Promise<{ version: number; path: string; sha256: string }>;
  export interface PreparedRevocations { kind: 'revocations'; path: string; baseSha256: string; payload: Revocations; current: Revocations; change: { kind: 'key'; keyId: string; reason: string } | { kind: 'digest'; digest: string; reason: string } | { kind: 'refresh' } }
  export async function prepareRevocationsChange(o: { rootKeyId: string; rootPublicKey: KeyObject; revocationsPath: string; now: Date; expires: string; change: PreparedRevocations['change']; minimumVersion?: number }): Promise<PreparedRevocations>;
  export async function commitRevocations(p: PreparedRevocations, rootKey: PrivateKeyInfo, o?: { beforeWrite?: () => void | Promise<void> }): Promise<{ version: number; path: string; sha256: string }>;
  ```
  `addApprover`, `removeApprover`, `updateRevocations` are reimplemented on top of these (one `now`, same messages, same CLI behaviour); the CLI keeps loading keys from paths. New `renewTrustRoot` and CLI `root renew --root-key FILE --trust-root FILE --expires DUR [--out FILE]`.
- `src/recovery-admin.ts`: `PreparedTimestamp { kind: 'timestamp'; path: string; baseSha256: string | null; payload: Timestamp; documents: { rootEvents: { sha256: string; count: number }; trustRoot: { sha256: string; version: number }; revocations: { sha256: string; version: number } } }`; `prepareTimestamp(o: { policy: Policy; key: PublicKeyInfo; now: Date; expires: string; minimumVersion?: number }): Promise<PreparedTimestamp>`; `commitTimestamp(p, key: PrivateKeyInfo, o?: { beforeWrite? }): Promise<{ version: number; path: string }>`. `signPolicyTimestamp` is reimplemented on top of them.

### GUI service

- `gui/src/service/types.ts`: `AdminTrustRootView`, `AdminRevocationsView`, `AdminTimestampView`, `AdminVerifyAllView` (as in v1, plus `stale: boolean` and `signedByPreviousRoot: boolean` on the trust-root view), `AdminConsequence = { skills: number; transitions: Array<{ name: string; from: Verdict; to: Verdict | 'TRUST_UNAVAILABLE' }> }`, lifetimes `AdminApproverLifetime = '90d'|'180d'|'365d'`, `AdminTrustRootLifetime = '180d'|'365d'`, `AdminListLifetime = '7d'|'30d'`, `AdminTimestampLifetime = '6h'|'12h'|'24h'`. `AdminSignSummary` becomes a discriminated union over `action: 'approve' | 'add-approver' | 'remove-approver' | 'renew-trust-root' | 'revoke-key' | 'revoke-digest' | 'refresh-revocations' | 'sign-timestamp'` with each action's fields from §6–§8 and `freshnessBlock: boolean`.
- `gui/src/service/admin.ts`: methods `trustRoot()`, `addApprover({ name, scopes, lifetime, trustRootLifetime? })`, `removeApprover(keyId, trustRootLifetime?)`, `renewTrustRoot(lifetime)`, `revocationTargets()`, `revoke(target, reason, lifetime)`, `revocations()`, `refreshRevocations(lifetime)`, `timestamp()`, `signTimestamp(lifetime)`, `verifyAll()`. Every signing method: D9 refusals; capture `op`; role check; prepare (with `minimumVersion` from the memory and `forbidden` from §5); consequence (§6); native dialog; on confirm `commit*` with `beforeWrite` comparing the generation and re-running the role check; `recordDocumentVersions`. `review` accepts the root role. Views (`trustRoot`, `revocations`, `timestamp`, `verifyAll`) are unqueued and do not refresh the idle timer.
- `gui/src/main/main.ts`, `preload.cts`: IPC `admin:trust-root`, `admin:add-approver`, `admin:remove-approver`, `admin:renew-trust-root`, `admin:revocation-targets`, `admin:revoke`, `admin:revocations`, `admin:refresh-revocations`, `admin:timestamp`, `admin:sign-timestamp`, `admin:verify-all`; every object argument checked with an exact key set and types (key ids `^sha256:[0-9a-f]{64}$`, lifetimes from the lists, names ≤ 128, reasons ≤ 4096 raw, scopes ≤ 64 entries of ≤ 128 characters); `pickPublicKey` and the offline-machine dialog.
- `gui/src/renderer/admin.ts`: the four templates; devices TRUST ROOT, TARGET, REVOKE, REVOCATION REFRESH, TIMESTAMP and their POLICY CHECKs; stale-base, expired, previous-root and freshness messages.

### Spec changes

`docs/spec/gui-admin-rack-v1.md`: the templates table (four phase 2 templates, Publish split); prepare/confirm/commit and the remaining write window; versions and memory on writes; freshness consequences; the offline-machine dialog; role separation including retired keys and the host check; revocation targets and permanence; consequence counts; expired and previous-root states; defaults; the IPC rows; "with the GUI memory" replaces "without recording versions" for admin checks. `docs/spec/trust-documents-v1.md` and `docs/spec/root-recovery-v1.md`: the retired-approver host check. CLI docs: `root renew`, `root add-approver --policy`.

### Tests

- Fixture: `tests/helpers.ts` gains `setupOrg(t, { recovery?: boolean; freshness?: boolean })` options (v2 policy, recovery keys, timestamp key and a signed timestamp), reused by `gui/tests/admin.test.ts`.
- Engine: prepare/commit equivalence with the old functions; commit refuses a changed base (swap between prepare and commit, and inside `expectSha256`); stale base refused; version = max + 1; host refuses a trust root listing a retired key (re-enrolment after rotation, reproduced by the review); `root renew`; `--policy` forbidden keys.
- GUI: each template's happy path; freshness-block line present and POLICY CHECK reporting the mismatch until *Sign timestamp*; same-version restore refused; revoke target limits and permanence text; last-approver and replace texts; consequence counts over pin and host `skill_dirs`; expired trust root offers renew; previous-root state disables writers; timestamp refused when a document is older than memory; offline dialog on arming root; cancel, timeout and disarm during each dialog write nothing.

## Decisions (v3)

v2 failed comprehension (24 guesses) and readiness (gaps B1–B13). This section resolves them and takes precedence over every earlier section. Code references are to the hardened tree (`fix/gui-admin-hardening`, `fcc8192`).

### V0. Precondition and delivery

- **Depends on** the hardening PR being merged into `dev`. Phase 2 branches from `dev` after that merge.
- **Delivery in two PRs.**
  - **2a:** the whole engine (V1–V9), the spec changes, and the GUI *Manage approvers* template.
  - **2b:** the GUI *Revoke*, *Refresh revocation list* and *Sign timestamp* templates.

  The engine is complete in 2a, so 2b is GUI-only.

### V1. `writeFileAtomic` (B1)

`writeFileAtomic(filePath: string, bytes: Buffer, mode = 0o644, options: { expectSha256?: string | null } = {}): Promise<string>`.

- `undefined` means no check, as today.
- A string `sha256:<64 hex>` means the existing path must be a regular file with that SHA-256.
- `null` means the path must not exist (`lstat` gives `ENOENT`).

The check runs after the temporary file is written and immediately before `rename`. A mismatch removes the temporary file and throws `Error('File changed before it could be replaced')`. Documents keep mode `0o644`.

The remaining window, between the final hash and the `rename`, is stated in the spec: "a process that can write the document folder can still replace the file in the instant between the last check and the write; a later load then shows a signature or version error".

### V2. Retired keys (B7, guess 7, guess 8)

- **The walk.** `RootWalk` gains `retired: string[]` (sorted, unique). It is filled from `WalkState.retired`, and `cloneWalk` copies it.
- **The host check.** In `loadPolicyTrust`'s `if (walk)` block, after the existing collision check, a trust root that lists an approver whose key id is in `walk.retired` fails with the trust reason `trust root lists approver <id>, which has held the root or timestamp role; a key that left those roles never takes another`. The failure has the same shape as the collision failure.
- **Scope, stated in both specs and the CHANGELOG:**
  - Only keys retired in events this host walked (after `root_events_after`) are known. A key retired before that is not.
  - The gate trust store (`src/gate/trust-store.ts`) calls `loadTrustContext` directly and is out of scope.
  - On upgrade, a trust root that already lists such a key stops loading. The fix is `root remove-approver`.
- **No word "closes".** The design and the specs say "refuses re-enrolment of a key retired in walked events".

### V3. Host state helpers (guess 2, guess 3, B5)

The GUI memory (`admin-state.json`) already uses the host state format, through `loadPolicyTrust` with `statePath = memoryFile`. `src/policy.ts` adds three exports:

- **`readHostState(statePath: string): Promise<HostState>`** is the current `readState`. A missing file is empty state.
- **`recordDocumentVersions(statePath: string, v: { rootKeyId?: string; trustRoot?: number; revocations?: number; timestamp?: { keyId: string; version: number } }): Promise<void>`**:
  1. Reads the state with `readHostState`.
  2. Builds `ours`. A root entry for `rootKeyId` gets each given half, and a missing half is `1`. `1` is the lowest valid value, and merging keeps maxima, so it never lowers anything.
  3. `timestamp` sets `timestamps[keyId]`, and then `v2 = true`.
  4. Writes `stateBytes(mergeHostState(ours, disk))` the same way `loadPolicyTrust` saves state, with the same mode and atomic write.

  `rootKeyId` is required when `trustRoot` or `revocations` is given. A read error throws, and the GUI shows `stateError: 'write'`.
- **`memoryMinimums(state: HostState, rootKeyId: string, timestampKeyId: string | null): { trustRoot: number; revocations: number; timestamp: number }`** returns 0 for each counter that is absent.

Which minimum applies to which document:
- trust root: `roots[activeRoot].trust_root_version`;
- revocation list: `roots[activeRoot].revocations_version`;
- timestamp: `timestamps[activeTimestampKey].version`.

### V4. Errors

`src/admin.ts` exports two error classes, which the GUI maps to Korean text:

- **`StaleDocumentError`** (`<label> version <n> is older than version <m> this computer has seen`) maps to `이 컴퓨터가 본 것보다 오래된 문서예요. 최신 문서를 되돌려 놓으세요.`
- **`DocumentChangedError`** (`<label> changed after it was prepared; prepare again`), and the `writeFileAtomic` mismatch, map to `문서가 그 사이에 바뀌었어요. 다시 준비하세요.`

Every other engine message reaches the GUI in English, through `dialogSafe`.

### V5. Trust root prepare and commit (B2, B3, guess 13, guess 16, guess 17)

```ts
export type TrustRootChange =
  | { kind: 'add'; publicKey: PublicKeyInfo; name: string; scopes: string[]; expires: string; trustRootExpires?: string }
  | { kind: 'remove'; keyId: string; trustRootExpires?: string }
  | { kind: 'renew'; trustRootExpires: string };
export interface ForbiddenKey { keyId: string; why: 'root' | 'recovery' | 'timestamp' | 'retired' | 'revoked' }
export interface PreparedTrustRoot {
  kind: 'trust-root';
  source: string;               // the trust root read
  target: string;               // out ?? source
  baseSha256: string;           // sha256:<hex> of source as read
  targetBase: string | null;    // when target !== source: its sha256 at prepare, or null when absent
  rootKeyId: string;
  current: TrustRoot;
  payload: TrustRoot;           // exactly what commit signs
  change: TrustRootChange;
  replaces: TrustRoot['approvers'][number] | null;
}
export async function prepareTrustRootChange(o: {
  rootKeyId: string; trustRootPath: string; out?: string; now: Date;
  change: TrustRootChange; forbidden?: ForbiddenKey[]; minimumVersion?: number;
}): Promise<PreparedTrustRoot>;
export async function commitTrustRoot(p: PreparedTrustRoot, rootKey: PrivateKeyInfo, o?: { beforeWrite?: () => void | Promise<void> }): Promise<{ version: number; path: string; sha256: string }>;
```

**Prepare** reads the source once and runs `readTrustRootForUpdate(bytes, rootKeyId)`, which checks the signature and the root, as today. It does not check expiry, so an expired trust root can be renewed. It then does the following:

1. A current version below `minimumVersion` throws `StaleDocumentError`. A version equal to it is accepted: that is the normal case.
2. It applies the change exactly as `updateTrustRoot`'s mutators do today. That keeps the messages, the root-as-approver refusal and the approver cap.
3. The version is `current.version + 1`. The memory rule in v2 §2 is replaced by (1) plus this, so there is no "max".
4. `trustRootExpires` sets the expiry. Without it the current expiry stays, and a result that is already expired throws the existing `The trust root would already be expired; pass --expires to extend it`.
5. **`forbidden`:** if any approver in the payload is in `forbidden`, it throws `Approver <id> cannot stay or be added: it is <why text>`. The why texts are `the root key`, `a recovery key`, `the timestamp key`, `a key that held the root or timestamp role` and `a revoked key`. This covers add, remove and renew. Removing the forbidden key itself is allowed, because it is no longer in the payload.
6. `replaces` is the existing approver with the added key id, or `null`.

**Commit:**

1. It refuses when `rootKey.keyId !== p.rootKeyId` (`Key does not match the prepared root key`).
2. It re-reads the source, and throws `DocumentChangedError` when the hash is not `baseSha256`.
3. It signs `p.payload` unchanged with `signTrustRoot`.
4. It awaits `beforeWrite`.
5. It calls `writeFileAtomic(p.target, bytes, 0o644, { expectSha256: p.target === p.source ? p.baseSha256 : p.targetBase })`.

**CLI.** `addApprover`, `removeApprover` and `updateTrustRoot` are reimplemented as prepare followed by commit, and their signatures (`src/admin.ts:149`, `:206`) and outputs are unchanged. The CLI passes no `forbidden` unless `--policy` is given (V8) and no `minimumVersion`.

### V6. Revocation list prepare and commit

```ts
export type RevocationChange =
  | { kind: 'key'; keyId: string; reason: string }
  | { kind: 'digest'; digest: string; reason: string }
  | { kind: 'refresh' };
export interface PreparedRevocations {
  kind: 'revocations'; source: string; target: string; baseSha256: string; targetBase: string | null;
  rootKeyId: string; current: Revocations; payload: Revocations; change: RevocationChange;
}
export async function prepareRevocationsChange(o: {
  rootKeyId: string; revocationsPath: string; out?: string; now: Date; expires: string;
  change: RevocationChange; minimumVersion?: number;
}): Promise<PreparedRevocations>;
export async function commitRevocations(p: PreparedRevocations, rootKey: PrivateKeyInfo, o?: { beforeWrite?: () => void | Promise<void> }): Promise<{ version: number; path: string; sha256: string; expiresAt: Date }>;
```

- **Checks.** These are the same as `updateRevocations` today: reason rules, limits, and the signature under `rootKeyId`. An expired current list is accepted, since a refresh fixes it.
- **Already revoked.** A key or digest that is already revoked throws `<Key|Digest> <id> is already revoked`. Today's CLI behaviour for this case is kept if it differs: the implementer checks `updateRevocations` and keeps it.
- **Commit and the CLI.** Commit works as in V5. `updateRevocations` is reimplemented on these two functions, with its signature (`src/admin.ts:234`) unchanged.

### V7. Timestamp prepare and commit (guess 4, B1, B6)

```ts
export interface PreparedTimestamp {
  kind: 'timestamp'; path: string; baseSha256: string | null; keyId: string;
  payload: Timestamp;            // built with src/timestamp.ts as signPolicyTimestamp does today
  documents: {
    rootEvents:  { path: string; sha256: string; count: number };
    trustRoot:   { path: string; sha256: string; version: number };
    revocations: { path: string; sha256: string; version: number };
  };
}
export async function prepareTimestamp(o: {
  policy: Policy; keyId: string; now: Date; expires?: string; version?: number;
  minimumVersions?: { trustRoot: number; revocations: number; timestamp: number };
}): Promise<PreparedTimestamp>;
export async function commitTimestamp(p: PreparedTimestamp, key: PrivateKeyInfo, o?: { beforeWrite?: () => void | Promise<void> }): Promise<{ path: string; timestamp: Timestamp }>;
```

**Prepare** does what `signPolicyTimestamp` does today: the walk, the check that the active timestamp key is `keyId`, the default lifetime, the `max_lifetime` cap, and the `version` rules, including the rule for an earlier timestamp signed by another key. Then:

- With `minimumVersions`, the trust root, the revocation list and the timestamp's own version must each be at least their minimum, or it throws `StaleDocumentError`. For the timestamp's own version this applies only to the existing file of the same key.
- With `minimumVersions` (the GUI path), it also runs `loadTrustContext` on the documents as read, at `now`, with expiry checked, and refuses with that reason. The CLI path is unchanged.
- An existing timestamp file that cannot be read: the CLI keeps today's rule. The GUI refuses with `현재 타임스탬프를 읽을 수 없어요. CLI에서 --version으로 서명하세요.`

**Commit:**

1. It checks the key id.
2. It re-hashes the three named documents and the timestamp file. Any difference throws `DocumentChangedError`.
3. It signs, then awaits `beforeWrite`.
4. It calls `writeFileAtomic(p.path, bytes, 0o644, { expectSha256: p.baseSha256 })`. A `null` base means the file must still be absent.

`signPolicyTimestamp` is reimplemented as prepare followed by commit, with its signature (`src/recovery-admin.ts:234`) unchanged.

### V8. Renew and `--policy` (B4, guess 9)

- **`renewTrustRoot`.** `src/admin.ts` gains `renewTrustRoot(o: { rootKeyPath: string; trustRootPath: string; out?: string; now: Date; expires: string }): Promise<{ version: number; path: string; expiresAt: Date }>`, built as prepare (`renew`) followed by commit.
- **CLI `root renew`.**
  - Command: `mago-ski root renew --root-key FILE --trust-root FILE --expires DUR [--out FILE]`. `--expires` is required.
  - Output: `{ "status": "TRUST_ROOT_RENEWED", "trust_root_version": n, "trust_root": path, "expires_at": iso }`, exit 0. Errors exit 2 through the existing handler.
  - Help text: `Usage: mago-ski root renew --root-key FILE --trust-root FILE --expires DUR [--out FILE]\n\nRe-signs the trust root with a new expiry and the same approvers.`
  - It is added to the `root` command list as `root renew             Extend the trust root's lifetime`.
- **`forbiddenApproverKeys`.** `src/policy.ts` gains `forbiddenApproverKeys(policy: Policy, now: Date): Promise<ForbiddenKey[]>`. It returns the pin root, the active root, the active recovery keys, the active timestamp key, `walk.retired` and every key in the revocation list. When `checkRootEvents` (through `loadPolicyRoot`) is not ok, it throws `Cannot check the root event log, so no approver is added: <reason>`. A v1 policy gives only the root and the revoked keys.
- **CLI `--policy`.** `root add-approver` gains `--policy FILE`, which passes `forbidden = await forbiddenApproverKeys(loadPolicy(FILE), now)`. Its help line is `--policy FILE   refuse keys that hold or held another role in this organisation (recommended)`.
- **Without `--policy`,** behaviour is exactly today's.

### V9. Display safety (guess 19)

- **The rule.** `src/text-safety.ts` (new) exports `isDisplaySafe(s: string): boolean`. It is false for C0, DEL, C1, U+2028/2029, the bidi controls U+061C, U+200E/200F, U+202A–202E and U+2066–2069, and U+FEFF.
- **Where it applies.** `addApprover` (and prepare `add`) refuses a name that fails it: `Approver name contains characters that cannot be shown safely`. Revocation reasons are checked the same way.
- **Existing documents.** Documents already on disk are not re-validated, but the GUI shows every name and reason through `dialogSafe`.

### V10. Consequences (guess 1, B3, guess 11, guess 12)

Consequences are computed in the GUI service, not in prepare.

**`AdminSession.consequence(prepared): Promise<AdminConsequence>`:**

1. **Skills.** It runs `findSkillDirs` over `discoveryRoots() ∪ pin.skillDirs ∪ hostSkillDirs()` and de-duplicates them by realpath. A `DiscoveryBudgetError` refuses the write with `폴더가 너무 많아서 영향을 계산할 수 없어요. 폴더 수를 줄이세요.`
2. **Two contexts.** The current context is `loadPolicyTrust(memoryPolicy)`. The prepared context is the same context with the written document replaced in memory by `prepared.payload`, so it holds the new trust root with the current list, or the current trust root with the new list.
3. **Verdicts.** For each Skill, it computes `verifyWithPolicy` against both contexts. Certificates come from the pin's `certificate_dirs` and the Skill's own folder, as `verifyWithPolicy` finds them.
4. **Freshness.** When the pin has `freshness` and the write is a trust-root or revocation write, every Skill whose current verdict is VERIFIED gets `to: 'BLOCKED_UNTIL_TIMESTAMP'`. `freshnessBlock` is true.
5. **Counts.** `changed` = the number of Skills whose `from !== to`. `lines` = the first 5 changed Skills, sorted by name.

```ts
export interface AdminConsequence { skills: number; changed: number; lines: Array<{ name: string; from: Verdict; to: Verdict | 'BLOCKED_UNTIL_TIMESTAMP' }>; freshnessBlock: boolean }
```

**Dialog lines:**
- `영향받는 Skill: <changed>개 (전체 <skills>개)`;
- each line `<name>: <from> → <to>`, where `BLOCKED_UNTIL_TIMESTAMP` is shown as `타임스탬프 전까지 차단`;
- `외 <changed-5>개` when more Skills changed than are listed.

**Spec change.** "show every certificate that stops verifying" becomes "show every discovered Skill whose verdict changes".

### V11. Types and IPC (B8, guess 15)

`gui/src/service/types.ts`:

```ts
export type AdminApproverLifetime  = '90d' | '180d' | '365d';
export type AdminTrustRootLifetime = '180d' | '365d';
export type AdminListLifetime      = '7d' | '30d';
export type AdminTimestampLifetime = '6h' | '12h' | '24h';
export interface AdminApproverView { keyId: string; name: string; scopes: string[]; expiresAt: string; expired: boolean; forbidden: string | null }
export type AdminTrustRootView =
  | { ok: true; path: string; sha256: string; version: number; expiresAt: string; expired: boolean; approvers: AdminApproverView[]; stale: boolean; signedByPreviousRoot: boolean }
  | { ok: false; message: string };
export type AdminRevocationsView =
  | { ok: true; path: string; sha256: string; version: number; expiresAt: string; expired: boolean;
      keys: Array<{ keyId: string; reason: string; revokedAt: string }>; digests: Array<{ digest: string; reason: string; revokedAt: string }>;
      stale: boolean; signedByPreviousRoot: boolean }
  | { ok: false; message: string };
export type AdminTimestampView =
  | { ok: true; configured: false }
  | { ok: true; configured: true; path: string; keyId: string | null; version: number | null; expiresAt: string | null; matches: boolean; maxLifetime: string; readable: boolean }
  | { ok: false; message: string };
export type AdminRevocationTarget =
  | { kind: 'key'; keyId: string; label: string; source: 'approver' | 'certificate' }
  | { kind: 'digest'; digest: string; skillName: string; instanceId: string };
export interface AdminVerifyAllView { skills: number; counts: Partial<Record<Verdict, number>>; trustOk: boolean; trustNote: string | null; needsTimestamp: boolean }
export type AdminWriteResult =
  | { ok: true; version: number; path: string; needsTimestamp: boolean; memoryWarning: boolean }
  | { ok: false; message: string };
```

The view fields work as follows:
- `forbidden` is the Korean why text: `루트 키`, `복구 키`, `타임스탬프 키`, `예전에 루트나 타임스탬프 역할을 했던 키` or `폐기된 키`.
- `stale` is true when the version is below the memory version.
- `signedByPreviousRoot` is true when the document's root key id is not the active root.
- `matches` is true when the timestamp names the documents now on disk.

`AdminSignSummary` becomes a union. The existing `approve` member is unchanged. Every new member has `keyId: string; keyName: string | null; document: { path: string; baseSha256: string | null; versionFrom: number | null; versionTo: number; expiresAt: string }` and the members below:

```ts
| { action: 'add-approver'; newKeyId: string; name: string; scopes: string[]; approverExpiresAt: string;
    replaces: { name: string; scopes: string[]; expiresAt: string } | null; consequence: AdminConsequence; … }
| { action: 'remove-approver'; removedKeyId: string; name: string; lastApprover: boolean; consequence: AdminConsequence; … }
| { action: 'renew-trust-root'; expiresFrom: string; freshnessBlock: boolean; … }
| { action: 'revoke-key'; targetKeyId: string; label: string; reason: string; consequence: AdminConsequence; … }
| { action: 'revoke-digest'; digest: string; skillName: string; reason: string; consequence: AdminConsequence; … }
| { action: 'refresh-revocations'; expiresFrom: string; freshnessBlock: boolean; … }
| { action: 'sign-timestamp'; documents: Record<'rootEvents' | 'trustRoot' | 'revocations', { sha256: string; counter: number; firstSeen: boolean }> }
```

`firstSeen` is true when the document's version, or the root-event count, is above this computer's memory for that counter. Memory holds versions, not digests (guess 23).

**IPC (main.ts and preload; every argument checked with exact keys and types):**

| Channel | Arguments | Result |
|---|---|---|
| `admin:trust-root` | none | `AdminTrustRootView` |
| `admin:add-approver` | `{ name: string ≤128, scopes: string[1..64] each ≤128, lifetime: AdminApproverLifetime, trustRootLifetime?: AdminTrustRootLifetime }` | `AdminWriteResult` (the public key is picked in main, V13) |
| `admin:remove-approver` | `{ keyId: string, trustRootLifetime?: AdminTrustRootLifetime }` | `AdminWriteResult` |
| `admin:renew-trust-root` | `{ lifetime: AdminTrustRootLifetime }` | `AdminWriteResult` |
| `admin:revocations` | none | `AdminRevocationsView` |
| `admin:revocation-targets` | none | `AdminRevocationTarget[]` |
| `admin:revoke` | `{ target: AdminRevocationTarget (kind + keyId, or kind + digest + instanceId only), reason: string ≤4096 raw, lifetime: AdminListLifetime }` | `AdminWriteResult` |
| `admin:refresh-revocations` | `{ lifetime: AdminListLifetime }` | `AdminWriteResult` |
| `admin:timestamp` | none | `AdminTimestampView` |
| `admin:sign-timestamp` | `{ lifetime: AdminTimestampLifetime }` | `AdminWriteResult` |
| `admin:verify-all` | none | `AdminVerifyAllView` |

Key ids must match `^sha256:[0-9a-f]{64}$`, and digests the engine's digest format. `RendererApi` gains one method for each channel, with the same names in camelCase.

### V12. Signing methods (B9, guess 5, guess 20)

Every phase 2 signing method on `AdminSession` runs in the queue and follows these steps:

1. **Refusals and capture.** It applies the D9 refusals and captures `op` (generation).
2. **Role.** It runs `current('root' | 'timestamp', op)`.
3. **Previous root.** It refuses when `signedByPreviousRoot` (V16).
4. **Inputs.** It computes `forbidden` (add only: `forbiddenApproverKeys`) and the minimums (`memoryMinimums(readHostState(memoryFile), …)`).
5. **Prepare.** It runs prepare, then `consequence`.
6. **Dialog.** It opens the native `confirmSign(summary)`.
7. **Last approver.** For `remove-approver` with `lastApprover`, it opens the second confirm `confirmLastApprover()` (V13).
8. **Commit.** It commits, with `beforeWrite` checking the generation and re-running the role check.
9. **Memory.** It runs `recordDocumentVersions`. A failure there gives `memoryWarning: true`, shown as `서명은 됐지만 이 컴퓨터의 기록을 갱신하지 못했어요.`
10. **Result.** It returns `AdminWriteResult`. `needsTimestamp` is the pin's `freshness`, for a trust-root or revocation write.

Cancel, timeout and disarm follow hardening D8 and D11, using the approve texts.

- **Review.** The role comes from the armed key, which may be the approver or the root. The IPC is unchanged. Hardening v4 item 7's "role the caller passes" means the armed key's role.
- **Revoke-digest.** It needs a review record for (armed key, generation, instance, digest), the same as approve, and it **claims** that record on confirm. A cancelled dialog keeps the record, as in approve. The digest revoked is the reviewed digest, not the Skill's current one.
- **D9.** Arming, the offline dialog, `pickPublicKey`, the last-approver confirm and every signing dialog each count as a dialog. While one is open, `arm`, `review`, `approve`, `resetMemory` and every phase 2 signing method refuse with the existing D9 text.

### V13. Dialogs, verbatim (guess 6, B10, guess 21)

**The signing dialog.** `confirmBox` is reused.

- **Title:** `인증서 서명` for approve, as today; `조직 문서 서명` for everything else.
- **Message:**
  - add: `승인자를 추가할까요?`, or `승인자 정보를 바꿀까요?` when `replaces`;
  - remove: `승인자를 뺄까요?`;
  - renew: `신뢰 루트 기간을 연장할까요?`;
  - revoke-key and revoke-digest: `폐기할까요? 되돌릴 수 없어요.`;
  - refresh: `폐기 목록을 다시 서명할까요?`;
  - timestamp: `타임스탬프를 서명할까요?`.
- **Action button:** `폐기` for revoke, `서명` otherwise.
- **Detail lines,** in this order, each value through `dialogSafe`:
  1. `문서: <path>`
  2. `현재 SHA-256: <baseSha256 or 없음>`
  3. `버전: <versionFrom or 없음> → <versionTo>`
  4. `만료: <expiresAt>`
  5. The action lines:
     - add: `새 승인자: <name> <newKeyId>`, `범위: <scopes joined by ", ">`, `승인자 키 만료: <approverExpiresAt>`; with `replaces`, `이미 승인자예요: 범위 <old> → <new>, 만료 <old> → <new>`; when scopes contain `*`, `모든 Skill을 승인할 수 있는 범위예요`;
     - remove: `뺄 승인자: <name> <removedKeyId>`;
     - renew: `이전 만료: <expiresFrom>`;
     - revoke-key: `폐기할 키: <label> <targetKeyId>`, `사유: <reason>`;
     - revoke-digest: `폐기할 버전: <skillName> <digest>`, `사유: <reason>`;
     - refresh: `이전 만료: <expiresFrom>`;
     - timestamp: three lines `<루트 이벤트|신뢰 루트|폐기 목록>: <counter> <sha256>`, each followed by `(이 컴퓨터가 처음 보는 버전)` when `firstSeen`.
  6. `서명 키: <keyName or ''> <keyId>`
  7. The consequence lines (V10).
  8. The permanence line:
     - revoke-key: `폐기는 되돌릴 수 없어요. 이 키가 서명한 모든 인증서가 영구히 검증되지 않아요.`;
     - revoke-digest: `폐기는 되돌릴 수 없어요. 이 버전의 모든 인증서가 영구히 검증되지 않아요.`
  9. The freshness line (v2 §3), when `freshnessBlock`.

**The other dialogs:**

- **Last approver:** title `마지막 승인자`, message `남는 승인자가 없어요. 새 승인자를 추가할 때까지 어떤 Skill도 새로 승인할 수 없어요. 계속할까요?`, button `계속`.
- **Offline:** title `오프라인 확인`, message as in v2 §4, empty detail, buttons `['취소', '예, 오프라인 관리용이에요']`. It is shown in `arm` after proof of possession and `roleOf`, and before `armed` is set, only for the root and recovery roles. Cancel drops the key and returns `{ ok: false, reason: 'cancelled' }`.

  The spec's "templates do not refuse an online machine" sentence is replaced by: "Arming a root or recovery key asks, in a native dialog, whether this is the offline administration computer; answering no or closing it does not arm the key."
- **`pickPublicKey`:** a main-process open dialog titled `승인자 공개 키 선택 (PEM)`, with filters PEM and `모든 파일`. It reads at most 16 KiB with `loadPublicKey`. A failure gives `공개 키를 읽을 수 없어요`, and cancel gives the result `cancelled`.

  `AdminSessionOptions` gains three test seams:
  - `pickPublicKey: () => Promise<{ ok: true; key: PublicKeyInfo } | { ok: false; reason: string }>`;
  - `confirmOffline: () => Promise<boolean>`;
  - `confirmLastApprover: () => Promise<boolean>`.
- **Memory reset:** detail `초기화하면 루트 문서를 쓸 때 지금 디스크에 있는 문서를 기준으로 삼아요.`, replacing the empty detail.

### V14. Revoke targets (guess 5, guess 11)

`revocationTargets()` returns:

- **Approvers:** each current approver, with `source: 'approver'` and `label` = name.
- **Certificate keys:** each `approverKeyId` of a certificate found by `discoverCertificates` over the pin's `certificate_dirs` and every discovered Skill, that is not already listed. `source: 'certificate'`, and `label` = the certificate's Skill name.
- **Digests:** each digest the armed key reviewed in this generation (`kind: 'digest'`).

It excludes:
- keys and digests that are already revoked;
- the root, recovery and timestamp keys, which `revoke` refuses with `루트·복구·타임스탬프 키는 여기서 폐기할 수 없어요.`

`revoke` re-derives the list and refuses any target not in it with `현재 승인자나 찾은 인증서의 키만 폐기할 수 있어요`. An already-revoked target is refused with `이미 폐기됐어요`. The reason follows the hardening reason rule, with a maximum of 512 (the engine's limit) and V9.

### V15. Defaults (guess 22)

| Item | Default | Choices |
|---|---|---|
| Approver key | 90d | 90d, 180d, 365d |
| Trust root | 365d | 180d, 365d |
| Revocation list | 30d | 7d, 30d |
| Timestamp | 24h, capped at `max_lifetime` | 6h, 12h, 24h |

The timestamp default follows `root-recovery-v1` and the CLI.

### V16. States (guess 14)

- **Previous root.** `signedByPreviousRoot` on the trust root or the revocation list disables every writer before any dialog, with `문서가 이전 루트 키로 서명돼 있어요. CLI에서 root adopt로 새 루트 키로 옮기세요. (GUI 지원은 3단계)`.
- **Expired trust root.** TRUST ROOT shows `신뢰 루트가 만료됐어요` and makes the trust-root lifetime required for add and remove. Renew is always available.
- **Expired revocation list.** REVOCATION REFRESH shows `폐기 목록이 만료됐어요`. Sign timestamp refuses with `폐기 목록이 만료됐어요. 먼저 폐기 목록 새로 고침을 실행하세요.`, and with `신뢰 루트가 만료됐어요. 먼저 승인자 관리에서 연장하세요.` for an expired trust root.
- **Forbidden approver.** An approver with `forbidden` is marked `<why>: 이 승인자는 빼야 해요`, and only Remove is offered for it. Any other write refuses, through V5's rule.
- **No freshness.** In a pin without `freshness`, the *Sign timestamp* template is disabled with `이 조직은 타임스탬프를 쓰지 않아요.`

### V17. POLICY CHECK per template (guess 18)

- **Manage approvers, Revoke and Refresh revocation list.** POLICY CHECK calls `verifyAll()`: counts by verdict over the V10 Skill set, plus the trust note. When `needsTimestamp` is set, it adds `타임스탬프가 새 문서를 가리키지 않아요. 타임스탬프 서명 템플릿을 실행하세요.`
- **Sign timestamp.** The same, without the timestamp line. `trustOk` is true when the timestamp matches.

### V18. Renderer (B10)

- **Template keys:** `'approve' | 'approvers' | 'revoke' | 'refresh' | 'timestamp'`.
- **Labels:** `승인자 관리`, `폐기`, `폐기 목록 새로 고침` and `타임스탬프 서명`.
- **Device names:** `IDENTITY`, `TRUST ROOT`, `TARGET`, `REVOKE`, `REVOCATION REFRESH`, `TIMESTAMP` and `POLICY CHECK`.
- **Buttons:** `추가`, `빼기`, `연장`, `폐기`, `다시 서명` and `서명`.
- **Locked and waiting texts** reuse the approve template's helpers, with the role names `루트` and `타임스탬프 서명자`.
- **Messages.** Every message in V4, V12, V13, V14 and V16 is shown as given.

### V19. Tests (B11)

**Fixtures:**
- Engine tests use `setupRecoveryOrg(t, { freshness, rotate })`, which hardening exported from `tests/helpers.ts`.
- GUI tests gain `writeV2Pin(world, org: RecoveryOrg)` in `gui/tests/admin.test.ts`. It writes a root-owned-style pin (test pin path) naming the recovery org's documents.

**Engine tests (`tests/admin-prepare-commit.test.ts`, new):**
- Prepare followed by commit gives bytes equal to the old path for add, remove, renew, revoke and refresh.
- Commit refuses:
  - a source swapped between prepare and commit;
  - a swap inside `writeFileAtomic`, through a test hook or a second process;
  - a wrong key.
- `null` base: the first timestamp succeeds; a file created after prepare is refused.
- A version below the minimum is refused; an equal version is accepted and gives +1.
- `forbidden` covers add, remove-other and renew, and allows removing the forbidden key itself.
- Display safety for names and reasons.

**`tests/root-recovery.test.ts`:**
- **Re-enrolment recipe:**
  1. `setupRecoveryOrg({ rotate: 1 })`.
  2. `addApprover` with the old root's public key, with no `--policy`, succeeds.
  3. `loadPolicyTrust` then fails with the V2 message.
- `forbiddenApproverKeys` returns each category, and throws on a forked log.
- `recordDocumentVersions` covers a missing half, never lowering, and v2 for timestamps.

**`tests/cli.test.ts`:**
- `root renew` output and exit codes.
- `root add-approver --policy` refuses the old root with `Approver <id> cannot stay or be added: it is a key that held the root or timestamp role`.

**GUI (2a and 2b):**
- Each template's happy path.
- The freshness line, and POLICY CHECK reporting `needsTimestamp` until *Sign timestamp*.
- A lower version than memory is refused, and an equal one accepted.
- Revoke target limits, permanence texts, and review claim.
- The last-approver double confirm, and the replace and `*` lines.
- Consequence counts over the pin's and the host's `skill_dirs`.
- Expired trust root: renew is offered.
- Previous root: writers are disabled.
- Timestamp is refused for a stale or expired document.
- The offline dialog when arming root.
- Cancel, timeout and disarm during each dialog write nothing.
- `memoryWarning` is set when the memory write fails.

### V20. Spec changes (B12, guess 24)

`docs/spec/gui-admin-rack-v1.md`:

- The templates table: four phase 2 templates, with Publish split.
- Spec line 123 (remove confirmation) becomes V13 Last approver.
- Spec line 124 (renew via add or remove) becomes "Renew uses `root renew`".
- Spec line 139 (ticked confirmation) becomes "the native dialog replaces the tick".
- Spec line 144 (POLICY CHECK for key targets) becomes V17.
- Spec line 152 (the not-used rule) moves to *Sign timestamp* (V16).
- Spec lines 183–185 (phases): phase 2a and phase 2b, as in V0.

Plus: the IPC rows (V11), the remaining write window (V1), the offline sentence (V13), the consequence sentence (V10) and the retired-key scope (V2). `docs/spec/trust-documents-v1.md` and `docs/spec/root-recovery-v1.md` get V2. The CLI help gets V8.

## Decisions (v4)

These decisions resolve the v3 comprehension check (B1–B11 and m1–m15) and the v3 readiness check (G1–G13). Where they differ from V0–V20, they win. Baseline:
- code: `fix/gui-admin-hardening` with the v5.1 fixes;
- spec: the hardened `docs/spec/gui-admin-rack-v1.md`.

### W1. Base and v5.1 integration (G1, G2, m4)

- **Base.** 2a starts from `dev` after the hardening PR, v5.1 code included, is merged. `feat/gui-admin-phase2` is recreated from that `dev`. This design file is carried over, and the old spec copy on that branch is dropped.
- **Memory chain.** `recordDocumentVersions` runs inside the same per-`statePath` chain as `persistState`.
- **v5.1 key checks.** Every phase 2 signing method runs these checks in step 1, again just before the dialog, and in `beforeWrite`:
  - the armed key file still has the same `dev` and `ino`;
  - the key is not inside a Skill (`keyInsideSkills`).
- **Dialogs.** Every new dialog goes through `ask()`. The public-key picker goes through `AdminSession.pickFile`.

### W2. Typed errors (m7)

- **`FileChangedError`.** `src/fs-safe.ts` exports `class FileChangedError extends Error`. The `writeFileAtomic` mismatch throws it, with the same message as V1.
- **Error mapping.** The GUI maps `FileChangedError`, `DocumentChangedError` and `StaleDocumentError` by class. It never matches on text.
- **Expired documents.** The GUI checks expiry itself, from the view fields, before calling prepare. The engine's English expiry messages are only a backstop.

### W3. Building contexts for consequences (B1, G6, G7)

- **`contextFromBytes`.** `src/policy.ts` exports `contextFromBytes(o: { trustRoot: Buffer; revocations: Buffer; rootKeyId: string; rootPublicKey: KeyObject; now: Date }): TrustContextResult`. It runs `loadTrustContext` on the bytes, with expiry, and without freshness, memory or a state write.
- **`from`.**
  - For root-document writes, `from` is each Skill's verdict under `contextFromBytes` of the on-disk trust root and revocation list.
  - When that fails, `from` is `UNVERIFIABLE` for every Skill. The dialog then adds `현재 문서로는 검증할 수 없어요: <reason>`.
- **`to`.** For a trust-root write, `to` is the verdict under `contextFromBytes`. It uses the prepared payload, signed in memory with the armed key (never written), and the on-disk list. For a revocation write, it uses the on-disk trust root and the signed prepared list.
- **Freshness.** When the pin has `freshness` and the write is a root document, **every** Skill's `to` is `BLOCKED_UNTIL_TIMESTAMP`, whatever `from` is. The line `서명 후 결과(타임스탬프 뒤): <verdict>` is shown beneath, so no false gain is shown.
- **Timestamp signing.** `from` is the host view: `loadPolicyTrust` with the memory policy, freshness included. A failure makes every Skill `UNVERIFIABLE`. `to` is `contextFromBytes` of the documents the timestamp names.
- **Renew and refresh** use the same rules. A renew of an expired trust root usually shows `UNVERIFIABLE → VERIFIED`.
- **Too-deep folders.** Each `tooDeep` directory counts as one entry, with `from = to = 'UNVERIFIABLE'`, and the dialog line `너무 깊어서 확인하지 않은 폴더: <n>개`.
- **One consequence type.** Every one of the 7 new `AdminSignSummary` members has `consequence: AdminConsequence`. The `AdminConsequence` in the v2 "GUI service" types bullet is deleted. V10's definition is the only one.

### W4. Input binding at commit (B9)

At prepare, the GUI captures `inputs: Array<{ path: string; sha256: string | null }>`. That covers the pin file, the trust root, the revocation list, the root event log (if any) and the timestamp (if configured). Its `beforeWrite` re-hashes each input and throws `DocumentChangedError` on any change. The consequence shown is therefore what is signed, up to the V1 window.

### W5. Timestamp rules (B2, B3, B11, G4, m13)

- **The key.** `prepareTimestamp` takes `key: PublicKeyInfo` in place of `keyId`, and `keyId = key.keyId`. The GUI passes the armed key's public part.
- **The version (GUI path, `minimumVersions` given).** `max(version of the existing file if it is signed by this key, else 0; minimumVersions.timestamp) + 1`. An absent file, with memory at `k`, gives `k + 1`. The CLI path is unchanged.
- **The lifetime.** The GUI offers only the choices from 6h, 12h and 24h that are within `max_lifetime`. The default is the largest one offered. When none fits, the template is disabled with `조직의 최대 타임스탬프 기간이 6시간보다 짧아요. CLI를 쓰세요.` The engine keeps refusing a lifetime above the maximum, and does not cap it.
- **Revoked root.** When the pin's root is revoked (`rootRevoked`), *Sign timestamp* is disabled with `루트 키가 폐기됐어요. 루트 사고 대응이 필요해요 (3단계).`

### W6. Forbidden keys (B4, B5, G5, G9a, m8, m9)

- **Which actions.** `forbidden` is computed for add, remove and renew. V5 rule 5 holds: the payload must not list a forbidden key.
  - With a forbidden approver listed, only removing that approver is possible. Add, removing another approver, and renew refuse with `<why>: 이 승인자를 먼저 빼세요`.
  - V16's "Renew is always available" becomes "Renew is offered".
- **`forbiddenApproverKeys(policy, now)`.**
  - It calls `loadPolicyRoot(policy, now, { recordVersions: false })`.
  - It reads the revocation list with `readRevocationsForUpdate(bytes, activeRootKeyId, activeRootPublicKey)`, with no expiry check. The active root's public key comes from the walk, or from the pin root for v1.
  - An unreadable or invalid list throws `Cannot read the revocation list, so no approver is added: <reason>`.
  - The GUI passes its memory policy (`memoryPolicy(pin)`, factored out of `readPin`). The CLI passes the `--policy` file. Neither writes any state.
- **Recovery keys (B5).**
  - The walker adds to `retired` every recovery key that a walked rotate removes from the recovery set, and the revoked root at revoke time (m9).
  - The walker refuses a rotate whose `new_recovery` or `new_timestamp` names a key in `retired`, with `Root event <n>: rotate names key <id>, which was retired by an earlier event`. That enforces `root-recovery-v1` line 174 for walked events.
  - The V2 host message becomes `trust root lists approver <id>, which has held the root, recovery or timestamp role; a key that left those roles never takes another`.
  - The forbidden why text `a key that held the root or timestamp role` becomes `a key that held the root, recovery or timestamp role`, and its Korean form `예전에 루트·복구·타임스탬프 역할을 했던 키`.
- **Gate (m9).** `verifier-worker.ts` uses `loadPolicyTrust`, so it refuses. `trust-store.ts` does not, as V2 states.

### W7. Display safety (B6, V9 replaced)

- **The rule.** V9's `isDisplaySafe` and `src/text-safety.ts` are dropped. `src/root-events.ts` exports `isDisplaySafeText(s: string): boolean`, the predicate behind `requireDisplaySafeText`.
- **New text.** New approver names, in `addApprover` and prepare `add`, must pass it: `Approver name contains characters that cannot be shown safely`. So must new revocation reasons, in `updateRevocations` and prepare `key` or `digest`: `Revocation reason contains characters that cannot be shown safely`.
- **Existing documents** are not re-validated. The GUI shows them through `dialogSafe`, as fixed in v5.1.

### W8. Views read the documents directly (B7, G10, m15)

- **`trustRoot()`.**
  1. It reads the trust root file and runs `readTrustRootForUpdate(bytes, activeRootKeyId)`, with no expiry check. The view is `ok: true` whenever that succeeds, whether or not `pin.trust` is ok.
  2. `forbidden` marks come from `forbiddenApproverKeys(memoryPolicy(pin), now)`. If it throws, every approver shows `forbidden: null`, and the view adds `note: '승인자 역할을 확인할 수 없어요: <reason>'`, a new field `note: string | null`. Then add, remove and renew are refused with the same text.
  3. On failure, the GUI parses the file as JSON without verifying it, and reads its root key id field (the one `readTrustRootForUpdate` compares). If that field names a key in `walk.retired`, the view is `{ ok: false, message: <V16 previous-root text> }` and `signedByPreviousRoot` is implied. Otherwise it is `{ ok: false, message: <engine reason via dialogSafe> }`.
- **`revocations()`.** The same, with `readRevocationsForUpdate`.
- **Certificates.** The consequence uses only the pin's `certificate_dirs`. A host may have others, and the spec states this limit.
- **Scopes.** The IPC scope limit is the engine's own `validateScope` limit, not 128.

### W9. Memory snapshot (B8, G8)

`signTimestamp` reads `snapshot = await readHostState(memoryFile)` before `current()`. `firstSeen` compares against `snapshot`:
- for the trust root and the revocation list, `roots[activeRoot]`;
- for the root events, `rootEvents[pinRoot].sequence`;
- for the timestamp itself, `timestamps[keyId]`.

### W10. Texts and lifetimes (B10, B11, m11, m12)

- **Last approver.** `남는 승인자가 없어요. 지금 승인된 모든 Skill이 검증되지 않게 되고(UNTRUSTED_SIGNER), 새 승인자를 추가할 때까지 어떤 Skill도 승인할 수 없어요. 계속할까요?`
- **Trust-root lifetime for add and remove.** The control `신뢰 루트 기간` offers `유지` (the default while the trust root has not expired), `180d` and `365d`. `유지` sends no `trustRootLifetime`.
  - While the trust root has expired, `유지` is not offered.
  - A request without a lifetime is refused with `신뢰 루트가 만료됐어요. 신뢰 루트 기간을 고르세요.`
  - V15's trust-root default of 365d applies to Renew only.
- **Replace line.** `이미 승인자예요: 이름 <old> → <new>, 범위 <old> → <new>, 만료 <old> → <new>`.
- **Revoke-digest review record.** It is claimed before the dialog and restored on cancel, as in approve (D11).
- **Revoke reason.** The maximum is 512 (`checkReason(reason, 512)`), and approve keeps 1024.
- **Reviewing in TARGET.** TARGET lists the discovered Skills. Selecting one shows its digest and a `검토` button, which runs `review(instanceId)` with the armed root key, using the same review dialog. After that, the digest is offered as a target.

### W11. Public-key picker (m10)

`addApprover` follows this order:
1. D9 refusals;
2. the role check;
3. `pickFile`, with the title `승인자 공개 키 선택 (PEM)`;
4. `readRegularFile` of the chosen path, at most 64 KiB (`loadPublicKey`'s own limit; the 16 KiB in V13 is dropped), then the public-key load from those bytes (`loadPublicKeyBytes`, added beside `loadPrivateKeyBytes` if absent);
5. prepare.

A failed load gives `공개 키를 읽을 수 없어요`. Cancel gives `{ ok: false, message: '취소했어요' }` and starts the cooldown.

The offline dialog comes after proof of possession, as V13 says (v2 §4's "first" is dropped).

### W12. Names (m5, m6, m14)

- **Renew field.** `renewTrustRoot`'s `expires` is passed as the change's `trustRootExpires`.
- **Memory write failure.** A read error inside `recordDocumentVersions` gives `memoryWarning: true`. There is no `stateError` on that path.
- **Timestamp mismatch.** `AdminVerifyAllView.needsTimestamp` is renamed `timestampMismatch: boolean`. It is true when the pin has `freshness` and the timestamp on disk does not name the documents now on disk.

### W13. Renderer texts (G13)

- **Template cards.** `TemplateKey` keeps `'setup' | 'incident'`, shown as phase 3 cards as today.
- **Role name.** The root is called `ROLE_NAME.root` (`루트 관리자`) everywhere, so V18's `루트` becomes `루트 관리자`.
- **Device texts.** The failed text of every device is the result message.

| Device | Ready | Done |
|---|---|---|
| TRUST ROOT | `승인자 <n>명 · 버전 <v> · 만료 <date>` | `서명했어요: 버전 <v>` |
| TARGET | `폐기할 대상을 고르세요` | `<label> 선택됨` |
| REVOKE | `사유와 기간을 적고 폐기하세요` | `폐기했어요: 버전 <v>` |
| REVOCATION REFRESH | `폐기 목록 버전 <v> · 만료 <date>` | `다시 서명했어요: 버전 <v>` |
| TIMESTAMP | `타임스탬프 버전 <v or 없음> · 만료 <date or 없음>` | `서명했어요: 버전 <v>` |
| POLICY CHECK | `검사 중…` | `VERIFIED <n>개 · 그 외 <m>개`, then one line per other verdict, `<verdict> <k>개` |

### W14. Tests (G11, m2)

- **Golden fixtures.** Before reimplementing anything, `tests/fixtures/admin-golden/` holds bytes signed by the current code (`fcc8192` plus v5.1). The signatures are deterministic Ed25519, with fixed keys and a fixed `now`, for add, remove, revoke-key, revoke-digest and refresh. The new tests compare prepare followed by commit against these bytes. Renew has no golden file, because it is new.
- **Re-enrolment recipe.**
  1. Rotate and adopt as in the rotation steps of the hardened `gui/tests/admin.test.ts`: the test that sets up a rotated root with `root rotate` events and `root adopt`.
  2. Call `addApprover({ rootKeyPath: newRoot.priv, publicKeyPath: oldRoot.pub, … })` with no `--policy`. It succeeds.
  3. `loadPolicyTrust` then fails with the W6 host message.
  4. Repeat with a recovery key removed by the rotate.
  5. A rotate that names a retired key in `new_recovery` is refused by the walker.
- **Recovery world.** `gui/tests/admin.test.ts` gains `recoveryWorld(t, { freshness })`. It builds on `setupRecoveryOrg`, writes the v2 pin, and calls `signPolicyTimestamp` when `freshness` is set.

### W15. Spec baseline (G12, m3)

V20 is re-keyed by heading against the hardened spec:
- **Templates:** the table under the templates heading;
- **Phases:** the phases list;
- **Memory:** the GUI memory paragraph.

The phase 2 sections (Shared rules, Manage approvers, Revoke, Publish) are added as new text, written to V and W. They are not copied from the old copy. Also updated:
- `CHANGELOG.md`;
- the CLI help (V8);
- `docs/spec/trust-documents-v1.md` and `docs/spec/root-recovery-v1.md` (V2 and W6, including the walker's new refusal);
- `docs/capabilities.md`, if it describes the admin rack.

## Decisions (v5)

These decisions bring the design up to date with `dev` at `890fe40`. Since v4, the hardening (v5.1 and v5.2), the Codex gate fix and the English/Korean GUI have all been merged. Where v5 differs from W1–W15, v5 wins.

### Z1. Base

- **Branch.** Phase 2 is built on `feat/gui-admin-phase2-v2`, which was created from `dev` at `890fe40`. The old `feat/gui-admin-phase2` branch is retired.
- **Delivery.** It is still two PRs (W1):
  - **2a:** the engine, the spec changes and *Manage approvers*;
  - **2b:** *Revoke*, *Refresh revocation list* and *Sign timestamp*.
- **Hardening rules.** The v5.1 and v5.2 hardening rules apply to every phase 2 signing method. W1's list grows by one check: `requireNoDialog()` runs again immediately before each dialog opens (v5.2 item 1).

### Z2. Every text goes in the catalog, in both languages

- **Where.** Every user-visible phase 2 text is a key in `gui/src/i18n/messages.ts`, under both `ko` and `en`. That covers:
  - device labels and states;
  - dialog titles, messages, detail lines and buttons;
  - refusals and notes.
- **The Korean value** of each key is the text quoted in V and W, byte for byte. The Korean quotes in this document are the `ko` catalog entries.
- **The English value** is written to the glossary in `docs/design/gui-i18n.md` §4. It must state the same facts and warnings. The permanence lines, the freshness line and the last-approver confirm are security text.
- **Key names.** Keys use these prefixes:
  - `admin.p2.<device>.<state>` for device texts;
  - `admin.dialog.<action>.<part>` for dialogs;
  - `admin.p2.err.<name>` for refusals.
- **Dialog builders.** Every new native dialog has a builder in `gui/src/main/dialog-text.ts`. That covers the per-action signing dialog, the last-approver confirm, the offline confirm and the public-key picker title. Each builder takes `(lang, summary)` and applies `dialogSafe` to every inserted value.
- **The signing dialog.** `signDialog(lang, summary)` switches on `summary.action`, and its Korean output for `approve` stays exactly as today.
- **Session messages.** Refusals from `AdminSession` use `this.lang()`, as the hardened session already does.
- **Engine messages.** English engine messages (V4, V5, V8) stay English in both languages, shown through `dialogSafe`, as today.
- **Tests.** The catalog test (both languages have the same keys and placeholders, and no Hangul in `en`) covers the new keys automatically. `dialog-text.test.ts` gains, for each new builder:
  - the `ko` output equals the Korean texts in V13 and W10 exactly;
  - the `en` output contains every inserted value.

### Z3. Code locations that changed since v4

- **Native dialog texts** now live in `gui/src/main/dialog-text.ts`. `gui/src/main/main.ts` only wires them.
- **`AdminSessionOptions`** already has `lang`, `stateDir`, `discoveryRoots`, `skillFolders`, `hostSkillDirs`, `pickFile` (through the session) and the test seams. Phase 2 adds `confirmOffline`, `confirmLastApprover` and `pickPublicKey` (W11) next to them.
- **The engine's state helpers** already serialise writes per canonical path (`persistState` chain, hardening v5.2 item 3). `recordDocumentVersions` (V3, W1) joins that same chain.
- **Screenshots.** After 2a and again after 2b, `gui/scripts/screenshots.ts` gains one shot per new template, in English, and the READMEs show them.

## Decisions (v6)

These decisions resolve:
- the v5 readiness check: B1, B2 and N1–N10;
- the v5 comprehension check: blocking points 1–7 and the minor points.

Where v6 differs from V, W or Z, v6 wins.

### A1. One view for consequences: the host's own checks (comprehension 1, readiness B1)

`contextFromBytes` (W3) is dropped. Consequences use the same function hosts use:

- **The new option.** `loadPolicyTrust(policy, now, options)` gains `options.override?: { trustRoot?: Buffer; revocations?: Buffer; timestamp?: Buffer }`. A given buffer replaces the bytes read from that document's path. Everything else runs as for a host:
  - the root-event walk;
  - the retired and collision checks;
  - freshness;
  - the minimums from the state file.
- **What the consequence calls.** It always passes `recordVersions: false` and the memory policy, so it never writes.
- **`from`.** Each Skill's verdict under `loadPolicyTrust(memoryPolicy(pin), now, { recordVersions: false })`. When that fails, `from` is `UNVERIFIABLE` with the failure reason, as in W3.
- **`to`, for a trust-root or revocation write.** The same call with `override` set to the prepared document, signed in memory with the armed key.
  - In a freshness organisation that call fails the freshness check. W3's rule stands: every Skill's `to` is `BLOCKED_UNTIL_TIMESTAMP`.
  - The line beneath it, "result after timestamp", comes from the same call plus a test-only flag `skipFreshness: true`. It is engine-internal, exported only for this preview.
- **`to`, for a timestamp.** The same call with `override.timestamp` set to the timestamp signed in memory.
- **Removing a retired approver.** `from` now shows what hosts show: `UNVERIFIABLE`, because of the V2 check. `to` shows the recovery.

### A2. No change to how hosts treat recovery keys (comprehension 2, readiness N6)

W6's walker change is **withdrawn**. The walker and the V2 host check stay as follows:
- `retired` holds only root and timestamp keys, as today;
- hosts do not refuse a trust root that lists a former recovery key;
- the walker's existing rotate refusals (`root-events.ts:334, 342`) and their messages are unchanged.

`RootWalk` gains `formerRecovery: string[]`, every key that was in a recovery set and left it in walked events. Only `forbiddenApproverKeys` uses it, so the GUI and `root add-approver --policy` refuse such a key as an approver. Its why text is `a former recovery key` / `예전 복구 키`.

No host refuses a document it accepted before. The specs and CHANGELOG say: "Former recovery keys are refused as new approvers by the GUI and by `--policy`; hosts do not check this."

### A3. English security texts, given and tested exactly (comprehension 3)

The English catalog values below are fixed. `dialog-text.test.ts` asserts the full `en` string for each, not just "contains the values".

| Key (meaning) | ko (from V/W) | en |
|---|---|---|
| permanence, key | 폐기는 되돌릴 수 없어요. 이 키가 서명한 모든 인증서가 영구히 검증되지 않아요. | Revocation cannot be undone. Every certificate this key signed will permanently fail verification. |
| permanence, digest | 폐기는 되돌릴 수 없어요. 이 버전의 모든 인증서가 영구히 검증되지 않아요. | Revocation cannot be undone. Every certificate for this version will permanently fail verification. |
| freshness line | 이 조직은 타임스탬프를 써요: 새 타임스탬프를 서명할 때까지 enforce 모드의 호스트는 모든 Skill을 막아요. | This organisation uses timestamps: hosts in enforce mode block every Skill until a new timestamp is signed. |
| last approver | (W10 text) | No approvers will remain. Every approved Skill will stop verifying (UNTRUSTED_SIGNER), and no Skill can be approved until you add a new approver. Continue? |
| previous root | 문서가 이전 루트 키로 서명돼 있어요. CLI에서 root adopt로 새 루트 키로 옮기세요. (GUI 지원은 3단계) | These documents are signed by a previous root key. Move them to the new root key with `root adopt` in the CLI. (GUI support comes in phase 3.) |
| offline confirm | 루트 키와 복구 키는 오프라인 관리용 컴퓨터에서만 써야 해요. 이 컴퓨터가 그런 컴퓨터인가요? | Root and recovery keys must only be used on an offline administration computer. Is this such a computer? / buttons: Cancel, Yes, it is offline |
| changed | 문서가 그 사이에 바뀌었어요. 다시 준비하세요. | The document changed in the meantime. Prepare it again. |
| stale | 이 컴퓨터가 본 것보다 오래된 문서예요. 최신 문서를 되돌려 놓으세요. | This document is older than one this computer has already seen. Put the newest document back. |
| consequence head | 영향받는 Skill: {changed}개 (전체 {skills}개) | Skills affected: {changed} (of {skills}) |
| blocked until timestamp | 타임스탬프 전까지 차단 | blocked until a timestamp |
| after reset (A7) | 이 컴퓨터의 기록을 초기화한 뒤 첫 서명이에요: 디스크의 문서가 최신인지 확인하세요. | This is the first signature since this computer's memory was reset: make sure the documents on disk are the newest. |

Every other new text is written to the glossary in `gui-i18n.md` §4 and checked by the catalog parity test.

### A4. What the preview binds (comprehension 4, 5)

- **W4 binding.** W4's sentence "the consequence shown is what is signed" is replaced by: "The documents named in the dialog are bound at commit. The consequence counts are computed when the change is prepared, from the Skill folders and certificates found then. They are not re-checked at commit." The spec states this as a limit.
- **Certificates.** Certificates come from the pin's `certificate_dirs` **and** each Skill's own folder, as V10 and `verifyWithPolicy` say. W8's "only the pin's" is corrected.

### A5. Timestamp signed by another key (comprehension 6)

- **The version line.** When the existing timestamp is signed by a key other than the armed one, `versionFrom` is `null`, so the dialog line reads `버전: 없음 → 1` / `Version: none → 1`.
- **An extra line** is added: `이전 타임스탬프는 다른 키({keyId})가 서명했어요.` / `The previous timestamp was signed by another key ({keyId}).`

### A6. Active root public key (readiness B1)

- **Where it comes from.** The active root's public key is `readTrustRootForUpdate(trustRootBytes, activeRootKeyId).root.publicKey`, the same source `signPolicyTimestamp` uses. If the trust root is signed by another root, that call throws, and the views show the previous-root state (V16).
- **`prepareRevocationsChange`** gains `rootPublicKey: KeyObject`.
  - For writes, the GUI passes the armed key's public key.
  - The CLI passes the loaded root key's public key, as `updateRevocations` does today.
- **Other users of the key.** `forbiddenApproverKeys`, `revocations()` and the revocation consequence get the key from the trust root, as above.

### A7. Memory reset trade-off (comprehension 7)

Accepted as designed (D7). After a reset, the first root or timestamp signature in that GUI session adds the "after reset" line (A3) to its dialog.

### A8. Spec edits by heading (readiness B2, comprehension minor)

V20 and W15 are replaced by these edits to `docs/spec/gui-admin-rack-v1.md`:
- **`## Templates` table.**
  - The Revoke row becomes `IDENTITY → TARGET → REVOKE → POLICY CHECK`.
  - The Publish row is split into *Refresh revocation list* (`IDENTITY → REVOCATION REFRESH → POLICY CHECK`) and *Sign timestamp* (`IDENTITY → TIMESTAMP → POLICY CHECK`).
- **`## Phases`.** The phase 2 item becomes 2a and 2b, as in V0.
- **`## Replay and this computer's memory`.** It gains the write window (V1), version recording on writes (V3, W9) and the reset line (A7).
- **`## Limits`.** It gains the retired-key scope (V2), the former-recovery-key rule (A2) and the consequence limits (A4).
- **New sections.**
  - *Manage approvers*, *Revoke*, *Refresh revocation list* and *Sign timestamp*, written to V, W and A.
  - Dialog texts are quoted in Korean, with a note that the English is in the catalog.
- **Other docs.**
  - `docs/spec/trust-documents-v1.md` and `docs/spec/root-recovery-v1.md`: V2 and A2.
  - CLI help: `src/cli.ts` command list (lines 34–35) and usage (line 98). Add `root renew` there, and `--policy` to the `root add-approver` usage.
  - The five phrases V20 cited that are not in the spec are dropped.

### A9. Readiness N1–N10 and comprehension minor points

1. **Revoking a key and a digest in one call.** The CLI's `updateRevocations` can revoke a key and a digest in one call. `RevocationChange` gains `{ kind: 'both'; keyId: string; digest: string; reason: string }`. Only the CLI uses it.
2. **`recordDocumentVersions`.** The v2 Engine-section signature is deleted, and V3's signature applies. `recordDocumentVersions` throws when the write fails; inside, it uses the `persistState` chain and turns `{ error }` into a thrown `Error`.
3. **`checkReason`.** It becomes `checkReason(reason: string, max: number)`. Approve passes 1024 and revoke passes 512.
4. **`memoryPolicy(pin)`** is extracted from `readPin` into a named, exported function in `gui/src/service/admin.ts`.
5. **Exports.** `readHostState`, `recordDocumentVersions`, `memoryMinimums`, `forbiddenApproverKeys` and the `loadPolicyTrust` options are exported. `persistState`, `cloneWalk`, `readState` and `stateBytes` stay private.
6. **(A2.)**
7. **Freshness text in 2a.** Until 2b ships, 2a's POLICY CHECK freshness note names the CLI: `타임스탬프가 새 문서를 가리키지 않아요. CLI에서 mago-ski timestamp sign을 실행하세요.` / `The timestamp does not name the new documents. Run mago-ski timestamp sign in the CLI.` 2b changes it to the template text (V17).
8. **Scopes.** IPC scopes are checked with `validateScope`.
9. **CLI test.** A `root renew --help` test is added to `tests/cli.test.ts`.
10. **Golden fixtures.** The first 2a commit creates `tests/fixtures/admin-golden/` from the current code, before anything is reimplemented (W14).

Minor points:

- **Timestamp lifetime.** It is refused above `max_lifetime`, never capped (W5).
- **Refusal wording.** The forbidden refusal for remove and renew reads `Cannot check the root event log, so the trust root is not changed: <reason>`. Add keeps its own text.
- **Review claim.** If a commit is refused after confirm (changed document, stale document, key moved), the claimed review record is restored when the generation is unchanged.
- **Already revoked (V6).** The engine throws `<Key|Digest> <id> is already revoked`, and the CLI behaves the same way.
- **Re-enrolment test recipe.** It uses the rotate-then-adopt pattern from `tests/root-recovery.test.ts` (the test that drives a whole revoke and rotate). Not `setupRecoveryOrg({ rotate })`, which sets the threshold.
- **Branch and base.** Z1 wins: `feat/gui-admin-phase2-v2`, whose base is `dev` plus `c4e3170`.
- **Signing key line.** Every new signing dialog uses the existing `admin.dialog.sign.key` format, `키: {role} · {name} · {keyId}`, with `-` for a missing name.
- **Public-key picker.** The `pickPublicKey` seam returns a key. In production, `main.ts` implements it by calling `session.pickFile`, then reading and loading the key (W11).
- **Timestamp view.** It reads with `recordVersions: false`.
- **Revoking a current approver's key.** It leaves the approver in the trust root. TRUST ROOT then marks it forbidden (`revoked`) and offers Remove.
- **Old test line.** The v2 §Tests line "same-version restore refused" is deleted.
- **First seen.** A counter missing from the memory snapshot counts as first seen (`firstSeen = true`).

## Decisions (v7)

These decisions resolve the v6 readiness check (gaps 1–7) and the v6 comprehension check (B1–B3, m1–m7). Where v7 differs from an earlier section, v7 wins.

### R1. The preview has its own function (readiness 1, 2)

- **No new host options.** `loadPolicyTrust`'s public options stay `{ recordVersions?, override? }`. A1's `skipFreshness` option on that function is withdrawn.
- **New function.** `src/policy.ts` adds `loadTrustForPreview(policy, now, o: { override?: { trustRoot?: Buffer; revocations?: Buffer; timestamp?: Buffer }; skipFreshness?: boolean }): Promise<TrustContextResult>`. It shares one body with `loadPolicyTrust` and never records versions.
  - With `skipFreshness`, it skips the timestamp read and verify (`policy.ts:574-592`) and the binding check (`:606-607`), and it sets `context.root.timestamp` to `null`.
  - Override buffers are subject to the same size limits as files.
- **Only the GUI may import it.** A test (`tests/preview-import.test.ts`) asserts that no file under `src/` other than `src/policy.ts` imports `loadTrustForPreview`. Under `gui/`, only `gui/src/service/admin.ts` may.
- **How each side of the preview is computed.**
  - `from` is one `loadTrustForPreview(memoryPolicy(pin), now)` call.
  - `to` is one call with the override.
  - "Result after timestamp" is one call with the override and `skipFreshness: true`.
  - Each Skill's verdict is `verifyWithPolicy(policy, dir, { now, context })` with the context from that side's single load. Nothing reloads per Skill.

### R2. Scope of "former recovery key" (readiness 4, comprehension B1)

- **What it holds.** `formerRecovery` holds keys that left a recovery set in walked events, after `root_events_after`. That is the same scope as `retired` (V2).
- **Wiring.**
  1. Add a `WalkState.formerRecovery` field.
  2. In the rotate branch (`root-events.ts:323`, where `newRecovery` is known), add `current.keyIds.filter((k) => !newRecovery.keyIds.includes(k))`.
  3. Add it to the explicit rotate `next` literal (`:359-366`).
  4. Return it in `RootWalk` (`:408-416`).
  5. Copy it in `cloneWalk` (`:441-447`).
- **Test.** A key rotated out of the recovery set is in `formerRecovery`, including on a walk-cache hit, and `forbiddenApproverKeys` refuses it.
- **Deliberate strictness (B1).** The GUI, and `root add-approver --policy`, are stricter than hosts on purpose. While a former recovery key is listed as an approver:
  - the GUI marks it and allows only removing it;
  - hosts keep accepting the trust root;
  - CLI `root renew` and `root remove-approver` do not check it.

  The spec states this.

### R3. Upgrade note for retired keys (comprehension B2)

A2's sentence becomes: "For former recovery keys, no host refuses a document it accepted before."

The V2 check, which refuses a trust root that lists a retired root or timestamp key, is the one deliberate exception. The 0.3.0 CHANGELOG entry and the spec's Limits section say:

> Before upgrading hosts, remove any approver whose key has held the root or timestamp role (`mago-ski root remove-approver`). After the upgrade, a trust root that still lists one stops loading, and enforce-mode hosts block every Skill until it is removed. The GUI's TRUST ROOT view marks such approvers.

### R4. Every phase 2 security text, both languages, with catalog keys (readiness 3, 7; comprehension B3)

This table **replaces** A3 and is complete for phase 2. `gui/tests/dialog-text.test.ts`, and a new `gui/tests/p2-texts.test.ts` for non-dialog texts, assert the exact `en` and `ko` values for every key below. The other phase 2 texts (device states, labels) follow the glossary and the catalog parity test.

| Key | ko | en |
|---|---|---|
| `admin.p2.permanence.key` | 폐기는 되돌릴 수 없어요. 이 키가 서명한 모든 인증서가 영구히 검증되지 않아요. | Revocation cannot be undone. Every certificate this key signed will permanently fail verification. |
| `admin.p2.permanence.digest` | 폐기는 되돌릴 수 없어요. 이 버전의 모든 인증서가 영구히 검증되지 않아요. | Revocation cannot be undone. Every certificate for this version will permanently fail verification. |
| `admin.p2.freshnessBlock` | 이 조직은 타임스탬프를 써요: 새 타임스탬프를 서명할 때까지 enforce 모드의 호스트는 모든 Skill을 막아요. | This organisation uses timestamps: hosts in enforce mode block every Skill until a new timestamp is signed. |
| `admin.dialog.lastApprover.title` | 마지막 승인자 | Last approver |
| `admin.dialog.lastApprover.message` | 남는 승인자가 없어요. 지금 승인된 모든 Skill이 검증되지 않게 되고(UNTRUSTED_SIGNER), 새 승인자를 추가할 때까지 어떤 Skill도 승인할 수 없어요. 계속할까요? | No approvers will remain. Every approved Skill will stop verifying (UNTRUSTED_SIGNER), and no Skill can be approved until you add a new approver. Continue? |
| `admin.dialog.lastApprover.action` | 계속 | Continue |
| `admin.dialog.offline.title` | 오프라인 확인 | Offline check |
| `admin.dialog.offline.message` | 루트 키와 복구 키는 오프라인 관리용 컴퓨터에서만 써야 해요. 이 컴퓨터가 그런 컴퓨터인가요? | Root and recovery keys must only be used on an offline administration computer. Is this such a computer? |
| `admin.dialog.offline.action` | 예, 오프라인 관리용이에요 | Yes, it is offline |
| `admin.dialog.publicKey.title` | 승인자 공개 키 선택 (PEM) | Choose the approver's public key (PEM) |
| `admin.p2.err.previousRoot` | 문서가 이전 루트 키로 서명돼 있어요. CLI에서 root adopt로 새 루트 키로 옮기세요. (GUI 지원은 3단계) | These documents are signed by a previous root key. Move them to the new root key with root adopt in the CLI. (GUI support comes in phase 3.) |
| `admin.p2.err.changed` | 문서가 그 사이에 바뀌었어요. 다시 준비하세요. | The document changed in the meantime. Prepare it again. |
| `admin.p2.err.stale` | 이 컴퓨터가 본 것보다 오래된 문서예요. 최신 문서를 되돌려 놓으세요. | This document is older than one this computer has already seen. Put the newest document back. |
| `admin.p2.err.noFreshness` | 이 조직은 타임스탬프를 쓰지 않아요. | This organisation does not use timestamps. |
| `admin.p2.err.rootRevoked` | 루트 키가 폐기됐어요. 루트 사고 대응이 필요해요 (3단계). | The root key is revoked. A root incident response is needed (phase 3). |
| `admin.p2.err.rolesUnknown` | 승인자 역할을 확인할 수 없어요: {reason} | The approver roles could not be checked: {reason} |
| `admin.p2.err.trustRootUnchanged` | 루트 이벤트 기록을 확인할 수 없어서 신뢰 루트를 바꾸지 않았어요: {reason} | Cannot check the root event log, so the trust root is not changed: {reason} |
| `admin.p2.memoryWarning` | 서명은 됐지만 이 컴퓨터의 기록을 갱신하지 못했어요. | The signature was made, but this computer's memory could not be updated. |
| `admin.p2.afterReset` | 이 컴퓨터의 기록을 초기화한 뒤 첫 서명이에요: 디스크의 문서가 최신인지 확인하세요. | This is the first signature since this computer's memory was reset: make sure the documents on disk are the newest. |
| `admin.p2.consequence.head` | 영향받는 Skill: {changed}개 (전체 {skills}개) | Skills affected: {changed} (of {skills}) |
| `admin.p2.consequence.blocked` | 타임스탬프 전까지 차단 | blocked until a timestamp |
| `admin.p2.consequence.after` | 서명 후 결과(타임스탬프 뒤): {verdict} | Result after the timestamp: {verdict} |
| `admin.p2.consequence.fromFailed` | 현재 문서로는 검증할 수 없어요: {reason} | The current documents do not verify: {reason} |
| `admin.p2.freshnessCli` (2a) | 타임스탬프가 새 문서를 가리키지 않아요. CLI에서 mago-ski timestamp sign을 실행하세요. | The timestamp does not name the new documents. Run mago-ski timestamp sign in the CLI. |
| `admin.p2.freshnessTemplate` (2b) | 타임스탬프가 새 문서를 가리키지 않아요. 타임스탬프 서명 템플릿을 실행하세요. | The timestamp does not name the new documents. Run the Sign timestamp template. |
| `admin.p2.forbidden.root` | 루트 키 | the root key |
| `admin.p2.forbidden.recovery` | 복구 키 | a recovery key |
| `admin.p2.forbidden.timestamp` | 타임스탬프 키 | the timestamp key |
| `admin.p2.forbidden.retired` | 예전에 루트나 타임스탬프 역할을 했던 키 | a key that held the root or timestamp role |
| `admin.p2.forbidden.formerRecovery` | 예전 복구 키 | a former recovery key |
| `admin.p2.forbidden.revoked` | 폐기된 키 | a revoked key |
| `admin.p2.forbidden.mustRemove` | {why}: 이 승인자는 빼야 해요 | {why}: this approver must be removed |
| `admin.p2.timestamp.otherKey` | 이전 타임스탬프는 다른 키({keyId})가 서명했어요 (버전 {version}). | The previous timestamp was signed by another key ({keyId}), version {version}. |
| `admin.p2.timestamp.doc.rootEvents` | 루트 이벤트 | Root events |
| `admin.p2.timestamp.doc.trustRoot` | 신뢰 루트 | Trust root |
| `admin.p2.timestamp.doc.revocations` | 폐기 목록 | Revocation list |
| `admin.p2.timestamp.firstSeen` | (이 컴퓨터가 처음 보는 버전) | (first seen by this computer) |
| `admin.dialog.reset.detailP2` | 초기화하면 루트 문서를 쓸 때 지금 디스크에 있는 문서를 기준으로 삼아요. | After a reset, root document writes take the documents now on disk as their base. |

The `retired` why text stays "root or timestamp" (m2): A2 keeps `retired` to those roles. The host message is V2's original text: `trust root lists approver <id>, which has held the root or timestamp role; a key that left those roles never takes another`. W6's change to that text is withdrawn.

### R5. Limits text (readiness 5, comprehension m5)

The spec's `## Limits` section gains:

> The consequence shown before signing is computed when the change is prepared, from the Skill folders and certificates found then, and with this computer's memory as the version minimums. A host with its own newer state, or with other certificate folders, can report different verdicts. Only the documents named in the dialog are bound at commit.

### R6. Sign timestamp without freshness (readiness 6)

- **The template.** It is disabled with `admin.p2.err.noFreshness` (V16).
- **The engine.** `prepareTimestamp` throws `The policy has no freshness timestamp`. The preview never builds a timestamp for such a pin.

### R7. Minor points

- **m1.** Hosts report a freshness failure as `UNVERIFIABLE`, with a reason starting `freshness:`. `from` shows exactly that. `BLOCKED_UNTIL_TIMESTAMP` is used only for `to`, as a label for "will fail freshness until a timestamp is signed".
- **m4.** Root review uses the hardening D10 record format (armed key, generation, instance). `review()` accepts the root role as well as the approver role. Tests cover a root review followed by revoke-digest, and an approver review that is **not** usable for revoke when another key is armed.
- **m6.** `admin.p2.timestamp.otherKey` shows the previous version (R4).
- **m7.** `setupRecoveryOrg`'s `rotate` is the recovery rotate threshold (`tests/helpers.ts:152`). The re-enrolment recipe uses the rotate-then-adopt test pattern from `tests/root-recovery.test.ts`, as A9 says.

## Decisions (v8)

This section resolves:
- the v7 readiness check: gaps 1–15;
- the v7 comprehension check: B1–B3 and the minor points.

Where it differs from earlier sections, v8 wins.

### S1. Loader API (comprehension B3; readiness 9)

- **`loadPolicyTrust` is unchanged.** Its options stay `{ recordVersions? }`. A1's `override` on it is withdrawn.
- **`loadTrustForPreview`** is the only function that takes `override` and `skipFreshness` (R1).
- **What `skipFreshness` skips:**
  - the timestamp read (`policy.ts:568`);
  - its verification (`:574-592`), including the fail-closed guard at `:576-577`;
  - the binding check (`:606-607`).

  When `context.root` is present, it sets `context.root.timestamp = null`.
- **`skipFreshness` is a production preview option**, not a test flag; A1's wording is corrected.
- **Verdicts.** Each Skill's verdict passes `context: result.context`, from the ok branch, to `verifyWithPolicy`.
- **In-memory signing.** The engine exports `signPreparedTrustRoot(p, key): Buffer`, `signPreparedRevocations(p, key): Buffer` and `signPreparedTimestamp(p, key): Buffer`.
  - They are pure: they sign `p.payload` and nothing else.
  - The preview uses them to build override bytes.
  - `commit*` uses the same functions, so the bytes previewed and the bytes written come from one code path.

### S2. Consequence lines (comprehension B1)

- **"Changed" is defined** as `from !== after`, where `after` is the verdict under the "result after timestamp" load (or under `to` without freshness). In a freshness organisation, the count no longer reads M of M.
- **Head line:** `admin.p2.consequence.head` (unchanged).
- **One line per changed Skill**, at most 5, sorted by name:
  - without freshness, `admin.p2.consequence.line`: `{name}: {from} → {to}`;
  - with freshness, `admin.p2.consequence.lineBlocked`: `{name}: {from} → 타임스탬프 전까지 차단 (타임스탬프 뒤 {after})` / `{name}: {from} → blocked until a timestamp (after the timestamp: {after})`.
- **More than 5:** `admin.p2.consequence.more`: `외 {n}개` / `and {n} more`.
- **Too deep:** `admin.p2.consequence.tooDeep`: `너무 깊어서 확인하지 않은 폴더: {n}개` / `Folders too deep to check: {n}`.
- **Every other Skill** is still blocked until a timestamp. The freshness line, `admin.p2.freshnessBlock`, says so once.
- **Withdrawn:** `admin.p2.consequence.blocked` and `admin.p2.consequence.after`.

### S3. Complete text list (readiness 1, 2, 12–15; comprehension B2)

**Key prefixes.**
- Z2's prefixes stand.
- Dialog texts are `admin.dialog.<action>.<part>`.
- Notices and lines inside dialogs are `admin.p2.notice.<name>`.
- Refusals are `admin.p2.err.<name>`.
- Device texts are `admin.p2.<device>.<state>`.

The R4 keys are renamed as follows; their texts are unchanged.

| R4 key | New key |
|---|---|
| `admin.p2.permanence.key` | `admin.p2.notice.permanenceKey` |
| `admin.p2.permanence.digest` | `admin.p2.notice.permanenceDigest` |
| `admin.p2.freshnessBlock` | `admin.p2.notice.freshnessBlock` |
| `admin.p2.memoryWarning` | `admin.p2.notice.memoryWarning` |
| `admin.p2.afterReset` | `admin.p2.notice.afterReset` |
| `admin.p2.consequence.*` | `admin.p2.notice.consequence*` |
| `admin.p2.timestamp.*` | `admin.p2.notice.timestamp*` |
| `admin.p2.forbidden.*` | `admin.p2.forbidden.*` (kept) |
| `admin.dialog.reset.detailP2` | `admin.dialog.reset.detail` |
| `admin.p2.freshnessCli` | kept for 2a, deleted in 2b with its use |

**Additional texts.** All are exact, and the tests assert both languages.

| Key | ko | en |
|---|---|---|
| `admin.dialog.doc.title` | 조직 문서 서명 | Sign an organisation document |
| `admin.dialog.doc.action` | 서명 | Sign |
| `admin.dialog.doc.actionRevoke` | 폐기 | Revoke |
| `admin.dialog.addApprover.message` | 승인자를 추가할까요? | Add this approver? |
| `admin.dialog.replaceApprover.message` | 승인자 정보를 바꿀까요? | Change this approver? |
| `admin.dialog.removeApprover.message` | 승인자를 뺄까요? | Remove this approver? |
| `admin.dialog.renew.message` | 신뢰 루트 기간을 연장할까요? | Extend the trust root's lifetime? |
| `admin.dialog.revoke.message` | 폐기할까요? 되돌릴 수 없어요. | Revoke? This cannot be undone. |
| `admin.dialog.refresh.message` | 폐기 목록을 다시 서명할까요? | Re-sign the revocation list? |
| `admin.dialog.timestamp.message` | 타임스탬프를 서명할까요? | Sign the timestamp? |
| `admin.dialog.doc.lineDocument` | 문서: {path} | Document: {path} |
| `admin.dialog.doc.lineSha` | 현재 SHA-256: {sha} | Current SHA-256: {sha} |
| `admin.dialog.doc.lineVersion` | 버전: {from} → {to} | Version: {from} → {to} |
| `admin.dialog.doc.lineExpires` | 만료: {date} | Expires: {date} |
| `admin.dialog.doc.none` | 없음 | none |
| `admin.dialog.addApprover.lineNew` | 새 승인자: {name} {keyId} | New approver: {name} {keyId} |
| `admin.dialog.addApprover.lineScopes` | 범위: {scopes} | Scopes: {scopes} |
| `admin.dialog.addApprover.lineKeyExpires` | 승인자 키 만료: {date} | Approver key expires: {date} |
| `admin.p2.notice.replace` | 이미 승인자예요: 이름 {oldName} → {newName}, 범위 {oldScopes} → {newScopes}, 만료 {oldExpires} → {newExpires} | Already an approver: name {oldName} → {newName}, scopes {oldScopes} → {newScopes}, expiry {oldExpires} → {newExpires} |
| `admin.p2.notice.scopeAll` | 모든 Skill을 승인할 수 있는 범위예요 | This scope lets the approver approve every Skill |
| `admin.dialog.removeApprover.line` | 뺄 승인자: {name} {keyId} | Approver to remove: {name} {keyId} |
| `admin.dialog.renew.lineFrom` | 이전 만료: {date} | Previous expiry: {date} |
| `admin.dialog.revoke.lineKey` | 폐기할 키: {label} {keyId} | Key to revoke: {label} {keyId} |
| `admin.dialog.revoke.lineDigest` | 폐기할 버전: {skill} {digest} | Version to revoke: {skill} {digest} |
| `admin.dialog.revoke.lineReason` | 사유: {reason} | Reason: {reason} |
| `admin.dialog.timestamp.line` | {label}: {counter} {sha} | {label}: {counter} {sha} |
| `admin.p2.err.timestampUnreadable` | 현재 타임스탬프를 읽을 수 없어요. CLI에서 --version으로 서명하세요. | The current timestamp cannot be read. Sign it in the CLI with --version. |
| `admin.p2.err.tooManyFolders` | 폴더가 너무 많아서 영향을 계산할 수 없어요. 폴더 수를 줄이세요. | There are too many folders to work out the effect. Reduce the number of folders. |
| `admin.p2.err.cannotRevokeRole` | 루트·복구·타임스탬프 키는 여기서 폐기할 수 없어요. | Root, recovery and timestamp keys cannot be revoked here. |
| `admin.p2.err.notATarget` | 현재 승인자나 찾은 인증서의 키만 폐기할 수 있어요 | Only the keys of current approvers or of certificates found can be revoked |
| `admin.p2.err.alreadyRevoked` | 이미 폐기됐어요 | Already revoked |
| `admin.p2.err.trustRootExpired` | 신뢰 루트가 만료됐어요 | The trust root has expired |
| `admin.p2.err.revocationsExpired` | 폐기 목록이 만료됐어요 | The revocation list has expired |
| `admin.p2.err.revocationsExpiredRefresh` | 폐기 목록이 만료됐어요. 먼저 폐기 목록 새로 고침을 실행하세요. | The revocation list has expired. Run Refresh revocation list first. |
| `admin.p2.err.trustRootExpiredRenew` | 신뢰 루트가 만료됐어요. 먼저 승인자 관리에서 연장하세요. | The trust root has expired. Renew it in Manage approvers first. |
| `admin.p2.err.maxLifetimeShort` | 조직의 최대 타임스탬프 기간이 6시간보다 짧아요. CLI를 쓰세요. | The organisation's maximum timestamp lifetime is under 6 hours. Use the CLI. |
| `admin.p2.err.removeFirst` | {why}: 이 승인자를 먼저 빼세요 | {why}: remove this approver first |
| `admin.p2.err.pickLifetime` | 신뢰 루트가 만료됐어요. 신뢰 루트 기간을 고르세요. | The trust root has expired. Choose a trust root lifetime. |
| `admin.p2.err.publicKeyUnreadable` | 공개 키를 읽을 수 없어요 | The public key cannot be read |
| `admin.p2.err.cancelled` | 취소했어요 | Cancelled |
| `admin.p2.trustRoot.lifetime` | 신뢰 루트 기간 | Trust root lifetime |
| `admin.p2.trustRoot.keep` | 유지 | Keep |

The offline dialog's cancel button reuses `admin.dialog.cancel`.

**Device and template texts (W13, V18).** These are exact in Korean as quoted. Their English follows the glossary, and the code review checks it.

| Key | ko | en |
|---|---|---|
| `admin.template.approvers` | 승인자 관리 | Manage approvers |
| `admin.template.revoke` | 폐기 | Revoke |
| `admin.template.refresh` | 폐기 목록 새로 고침 | Refresh revocation list |
| `admin.template.timestamp` | 타임스탬프 서명 | Sign timestamp |
| `admin.p2.btn.add` | 추가 | Add |
| `admin.p2.btn.remove` | 빼기 | Remove |
| `admin.p2.btn.renew` | 연장 | Renew |
| `admin.p2.btn.revoke` | 폐기 | Revoke |
| `admin.p2.btn.resign` | 다시 서명 | Re-sign |
| `admin.p2.btn.sign` | 서명 | Sign |
| `admin.p2.btn.review` | 검토 | Review |
| `admin.p2.trustRoot.ready` | 승인자 {n}명 · 버전 {v} · 만료 {date} | Approvers: {n} · version {v} · expires {date} |
| `admin.p2.trustRoot.done` | 서명했어요: 버전 {v} | Signed: version {v} |
| `admin.p2.target.ready` | 폐기할 대상을 고르세요 | Choose what to revoke |
| `admin.p2.target.done` | {label} 선택됨 | {label} selected |
| `admin.p2.revoke.ready` | 사유와 기간을 적고 폐기하세요 | Enter a reason and lifetime, then revoke |
| `admin.p2.revoke.done` | 폐기했어요: 버전 {v} | Revoked: version {v} |
| `admin.p2.refresh.ready` | 폐기 목록 버전 {v} · 만료 {date} | Revocation list version {v} · expires {date} |
| `admin.p2.refresh.done` | 다시 서명했어요: 버전 {v} | Re-signed: version {v} |
| `admin.p2.timestamp.ready` | 타임스탬프 버전 {v} · 만료 {date} | Timestamp version {v} · expires {date} |
| `admin.p2.timestamp.done` | 서명했어요: 버전 {v} | Signed: version {v} |
| `admin.p2.check.ready` | 검사 중… | Checking… |
| `admin.p2.check.done` | VERIFIED {n}개 · 그 외 {m}개 | VERIFIED {n} · other {m} |
| `admin.p2.check.line` | {verdict} {k}개 | {verdict} {k} |

**Closing rule.**
- Any other Korean text quoted in this document that is not in R4 or S3 becomes a catalog key under the prefixes above. Its English follows the glossary.
- The Goldfish code review of each PR lists every new key with both values and checks them for meaning.
- A key missing from this rule, or an English text that drops a fact, is a review finding, not a design gap.

### S4. Types and steps (readiness 3–8, 10, 11)

- **`ForbiddenKey.why`** adds `'formerRecovery'`.
- **`AdminTrustRootView` and `AdminRevocationsView`.**
  - `ok: false` members carry `signedByPreviousRoot: boolean`.
  - `AdminTrustRootView`'s `ok: true` member carries `note: string | null` (W8).
- **`AdminVerifyAllView`** uses `timestampMismatch: boolean` (W12). `AdminWriteResult` keeps `needsTimestamp`. V17 reads `timestampMismatch`.
- **`Verdict` in GUI types.** `gui/src/service/types.ts` adds `type AdminVerdictTo = Verdict | 'BLOCKED_UNTIL_TIMESTAMP'` for consequence lines. `Verdict` itself is unchanged.
- **V12 step 4.** `forbidden` is computed for add, remove and renew (W6).
- **V15.** The timestamp row reads: "the largest of 6h, 12h and 24h that is not above `max_lifetime`; disabled below 6h (W5)."
- **V7.**
  - The timestamp's own-version `StaleDocumentError` branch is deleted. The version is computed as in W5, so the branch is unreachable.
  - The trust-root and revocation minimums stay.
  - The signature is `prepareTimestamp(o: { policy; key: PublicKeyInfo; now; expires?; version?; minimumVersions? })`.
- **The revocation list version** is `current + 1` after the minimum check, the same rule as the trust root (V5).
- **R2 wiring** also needs:
  - `formerRecovery: new Set()` in the initial `WalkState` literal (`root-events.ts:398-405`);
  - `formerRecovery: Set<string>` declared in `WalkState` (`:260-268`);
  - `retired: string[]` and `formerRecovery: string[]` declared in `RootWalk` (`:65-74`).

  The rotate step unions with `state.formerRecovery`.
- **R6.** The engine keeps today's message, `Policy <path> has no "freshness" block` (`recovery-admin.ts:244`). R6's new English is withdrawn. The GUI shows `admin.p2.err.noFreshness`.
- **W13 role name.** It refers to the existing `ROLE_NAME_KEY` map (`gui/src/renderer/admin.ts:33`).

### S5. Wording fixes (comprehension minor points)

- **V1 window sentence** becomes:

  > A process that can write the document folder can still replace the file in the instant between the last hash check and the rename. Its write is then lost, or a later write replaces it. Hosts verify every document's signature and version, so the result is never an unsigned or older-than-memory document being accepted by this computer.
- **Revocation and review records.** A successful revoke-digest commit consumes the claimed review record.
- **R3 upgrade note** becomes:

  > Before upgrading hosts, open the TRUST ROOT view in a GUI of the new version: it marks any approver whose key has held the root or timestamp role. Remove those approvers (`mago-ski root remove-approver`), and in an organisation that uses timestamps, sign a new timestamp afterwards (`mago-ski timestamp sign`). Hosts that use `loadPolicyTrust` (the CLI, Pi, the GitHub Action and the gate's verifier) refuse a trust root that still lists such an approver, and in enforce mode block every Skill. The gate's trust store does not check this.
- **firstSeen** follows V11: above memory, with the key `admin.p2.notice.timestampFirstSeen`.

## Decisions (v9)

These decisions resolve:
- the v8 readiness check: B1–B6 and the minor points;
- the v8 comprehension check: B1, B2 and m1–m5.

Where v9 differs from an earlier section, v9 wins.

### T1. Active root public key (readiness B1)

There is one source, the trust root itself, as `signPolicyTimestamp` does it (`recovery-admin.ts:259-260`):

```ts
readTrustRootForUpdate(await readFile(policy.trustRootPath), activeRootKeyId).root.publicKey
```

Here `activeRootKeyId` comes from `loadPolicyRoot`. If the read fails, the caller refuses:
- in the GUI with `admin.p2.err.previousRoot` when the file's root id is a retired key;
- otherwise with `admin.p2.err.rolesUnknown`.

`RootWalk` gets no public key field. W6's "comes from the walk" is withdrawn.

### T2. Consequence keys (readiness B2, comprehension m1)

S2 and R4 use the S3 names. The final keys, with their texts:

| Key | ko | en |
|---|---|---|
| `admin.p2.notice.consequenceHead` | 영향받는 Skill: {changed}개 (전체 {skills}개) | Skills affected: {changed} (of {skills}) |
| `admin.p2.notice.consequenceLine` | {name}: {from} → {to} | {name}: {from} → {to} |
| `admin.p2.notice.consequenceLineBlocked` | {name}: {from} → 타임스탬프 전까지 차단 (타임스탬프 뒤 {after}) | {name}: {from} → blocked until a timestamp (after the timestamp: {after}) |
| `admin.p2.notice.consequenceMore` | 외 {n}개 | and {n} more |
| `admin.p2.notice.consequenceTooDeep` | 너무 깊어서 확인하지 않은 폴더: {n}개 | Folders too deep to check: {n} |
| `admin.p2.notice.consequenceFromFailed` | 현재 문서로는 검증할 수 없어요: {reason} | The current documents do not verify: {reason} |
| `admin.p2.notice.consequenceToFailed` | 서명 후 문서가 검증되지 않아요: {reason} | After signing, the documents would not verify: {reason} |
| `admin.p2.notice.freshnessBlock` | (R4 text) | (R4 text) |

### T3. Prefix rule (readiness B3)

| Prefix | Used for |
|---|---|
| `admin.dialog.<action>.title` / `.message` / `.action` | a dialog's title, message and button |
| `admin.dialog.<action>.line*` | a detail line in that dialog |
| `admin.dialog.doc.*` | detail lines shared by all document dialogs |
| `admin.p2.notice.*` | notices that may appear in several dialogs or views |
| `admin.p2.err.*` | refusals |
| `admin.p2.forbidden.*` | forbidden-key labels |
| `admin.p2.btn.*` | buttons |
| `admin.p2.label.*` | form labels |
| `admin.p2.<device>.ready` / `.done` | device states |
| `admin.template.*` | template names |

Renames:
- `admin.p2.trustRoot.lifetime` becomes `admin.p2.label.trustRootLifetime`;
- `admin.p2.trustRoot.keep` becomes `admin.p2.label.keep`;
- the timestamp document labels are `admin.p2.notice.timestampDocRootEvents`, `admin.p2.notice.timestampDocTrustRoot` and `admin.p2.notice.timestampDocRevocations`;
- the others are `admin.p2.notice.timestampOtherKey` and `admin.p2.notice.timestampFirstSeen`.

### T4. Engine signatures (readiness B4, B5)

```ts
export function signPreparedTrustRoot(p: PreparedTrustRoot, key: PrivateKeyInfo): Buffer;
export function signPreparedRevocations(p: PreparedRevocations, key: PrivateKeyInfo): Buffer;
export function signPreparedTimestamp(p: PreparedTimestamp, key: PrivateKeyInfo): Buffer;
```

- **Signing functions.** These are pure. Key-id checks stay in `commit*`.
- **Shared loader body.** `src/policy.ts` gets a private `loadTrustBody(policy: Policy, now: Date, o: { record: boolean; override?: { trustRoot?: Buffer; revocations?: Buffer; timestamp?: Buffer }; skipFreshness?: boolean }): Promise<TrustContextResult>`.
  - It holds today's body of `loadPolicyTrust`.
  - `override` replaces the three reads at `policy.ts:566-568`, and keeps their size limits (`MAX_TRUST_ROOT_BYTES`, `MAX_REVOCATIONS_BYTES`, `MAX_TIMESTAMP_BYTES`, or the constants used there).
- **Two wrappers:**
  - `loadPolicyTrust(policy, now, opts)` is `loadTrustBody(policy, now, { record: opts.recordVersions !== false })`;
  - `loadTrustForPreview(policy, now, o)` is `loadTrustBody(policy, now, { record: false, ...o })`.

### T5. Consequence failure cases (readiness B6)

- **`from` load fails.** The dialog shows only `consequenceFromFailed`: no head, no lines.
- **`to` load fails for a reason other than freshness**, for example the V2 retired-key refusal, or an expired document the change does not fix. The dialog shows `consequenceToFailed`, and Sign is disabled: `ask()` is not called, and the method returns `{ ok: false, message: consequenceToFailed }`.
- **Removing the last forbidden approver** makes `to` pass, so this does not block the fix.

### T6. Sign timestamp's own preview (comprehension B1)

- **The rule.** `consequenceLineBlocked` and `freshnessBlock` apply only to trust-root and revocation writes. For a timestamp write:
  - `to` is the override load with the signed timestamp, with freshness checked (A1);
  - lines use `consequenceLine`;
  - "changed" is `from !== to`;
  - no freshness line is shown.
- **The type.** V11's `sign-timestamp` summary member has `consequence` with `freshnessBlock: false`.

### T7. Root-event counter in memory (comprehension B2)

- **New field.** V3's `recordDocumentVersions` gains `rootEvents?: { rootKeyId: string; sequence: number; eventDigest: string }`. It is merged as `mergeHostState` merges `rootEvents`: the higher sequence wins.
- **Recording after a timestamp.** After a timestamp commit, the GUI records `timestamp`, and also `rootEvents` from the walk the prepare used.
- **Recording after a root write.** After a trust-root or revocation commit, it records `trustRoot` or `revocations` as before.
- **Clearing the marker.** firstSeen for root events then clears after the first timestamp (W9).

### T8. Placement and wording (comprehension m2–m5; readiness minor points)

- **Detail-line order** for every document dialog:
  1. document lines (`doc.*`);
  2. action lines (`line*`), with the replace and scope `*` notices directly after the line they qualify;
  3. the timestamp lines, each with its firstSeen marker on the same line;
  4. `timestampOtherKey`;
  5. the key line;
  6. the consequence (head, lines, more, tooDeep, or `fromFailed` / `toFailed`);
  7. the permanence line;
  8. `freshnessBlock`;
  9. `afterReset`.
- **A5 example.** `none → 1` holds when the key has no memory. Otherwise it reads `none → memory + 1` (W5).
- **Upgrade note (S5).** It adds: "In an organisation that uses timestamps, remove the approvers and sign the new timestamp in one sitting. Between the two, hosts block every Skill."
- **Freshness add dialog.** In a freshness add, the head can read `0 (of N)` while `freshnessBlock` says every Skill is blocked until a timestamp. This is intended: the head counts changes after the timestamp.
- **Tests.**
  - The re-enrolment recipe is `setupRecoveryOrg(t, { freshness })` plus the rotate-then-adopt pattern (A9). The `t` was missing.
  - The `RootWalk` return literal and `cloneWalk` carry `retired` and `formerRecovery` (R2, S4).
  - V17's `needsTimestamp` reads `timestampMismatch` (S4).

## Decisions (v10)

These decisions resolve the v9 readiness confirmation. Where they differ from earlier sections, v10 wins.

### U1. Root walk refusal and the Sign button (T5)

- **The root walk must load.** Every trust-root and revocation write, and every timestamp write, first runs `loadPolicyRoot(memoryPolicy(pin), now, { recordVersions: false })` (W6, through `forbiddenApproverKeys` for trust-root writes; directly for the others).
- **When it does not load** (rollback, fork, unreadable log or revoked root), the write is refused before any dialog. The refusal is `admin.p2.err.trustRootUnchanged` with the reason, and for a revoked root `admin.p2.err.rootRevoked`.
- **Sign stays enabled when `from` fails.** `from` failing is the normal state after a root write in a freshness organisation, and for an expired document that the write fixes. The dialog shows `consequenceFromFailed`.
- **Sign is disabled** only by U1's refusal and by `consequenceToFailed` (T5).

### U2. Wording fixes for T1 and T4

- **T1.** The trust root is read with `readRegularFile(policy.trustRootPath, 'Trust root', 4 * 1024 * 1024)`, as `recovery-admin.ts:256` does.
- **The previous-root case.** It is detected before the verified read. The GUI parses the file as JSON without verifying it, and compares its `root_key_id` field (or the field `readTrustRootForUpdate` compares) with the walk's `retired`. A match gives `admin.p2.err.previousRoot`. Any other read failure gives `admin.p2.err.rolesUnknown`.
- **T4.** `loadTrustBody` records only when `o.record && policy.statePath !== null`, as today's `policy.ts:515` does.
- **Size limits.** The override buffers use the same literals as the reads they replace: 4 MiB for the trust root, 8 MiB for the revocations, and `MAX_TIMESTAMP_BYTES` (exported from `src/timestamp.ts`).

### U3. Root-event memory after a timestamp (T7)

T7's shape and source are replaced:

- **The source.** The timestamp prepare uses the walk from U1's memory-checked `loadPolicyRoot`, not `walkFromPolicy`. The commit's `beforeWrite` runs that check again, and refuses if the walk changed.
- **The memory update.** After the commit, the GUI records root-event progress by calling `loadPolicyRoot(memoryPolicy(pin), now, { recordVersions: true })` once. It uses the existing progress rule (`checkRootEvents`) and the existing `HostState.rootEvents` shape: keyed by root id, holding `{ sequence, event_digest, revoked? }`.
- **`recordDocumentVersions`** gets no `rootEvents` field. T7's field is withdrawn.

### U4. Timestamp dialog conflicts (T6, T8, V11)

- **No freshness line.** The timestamp dialog never shows `freshnessBlock`. T8's step 8 applies to trust-root and revocation dialogs only.
- **When `from` fails in a timestamp dialog,** which is the stale-timestamp case:
  - the dialog shows `consequenceFromFailed`;
  - it also shows `to`'s per-verdict summary, `admin.p2.check.done` and `admin.p2.check.line` (the POLICY CHECK texts), for the Skills under the new timestamp.

  The admin therefore sees what signing restores.
- **The type.** V11's `sign-timestamp` member gets `consequence: AdminConsequence` (T6 is now in the type).
- **memoryWarning** is not a dialog line. It is shown after the commit, in the device's result.

### U5. Prefix stragglers (T3)

These keys are renamed; their texts are unchanged:

| Old key | New key |
|---|---|
| `admin.p2.check.*` | `admin.p2.policyCheck.*` (POLICY CHECK is a device) |
| `admin.p2.target.*` | kept (TARGET is a device) |
| `admin.dialog.doc.actionRevoke` | `admin.dialog.revoke.action` |
| `admin.dialog.reset.detail` | kept (an existing dialog) |
| `admin.p2.freshnessCli` | `admin.p2.notice.freshnessCli` |

## 2a code review fixes (v11)

These fixes come from the two Goldfish code reviews of `25ffd25..da58894`. Neither review found a HIGH issue. Where these fixes differ from an earlier section, they win.

1. **State writes across processes (security M1).**
   - `persistState` (`src/policy.ts`) becomes a compare-and-swap loop, used by `recordDocumentVersions` and the host save alike:
     1. read the raw bytes once (absent counts as `null`);
     2. parse and merge;
     3. call `writeFileAtomic(path, bytes, 0o600, { expectSha256: sha256(raw) or null })`;
     4. on `FileChangedError`, re-read, merge and retry, up to 5 times with 10–80 ms jittered waits;
     5. then fail, with `stateError: 'write'` for the existing failure paths. `recordDocumentVersions` throws.
   - The in-process chain stays.
   - The doc comments that claim "never lowers" are corrected to say "within the retry budget; fails closed otherwise". The stale "unreadable file is replaced" comment goes.
   - Test: two processes recording ascending versions never leave a lower value on disk (the reviewer's `race.ts` recipe).
2. **Expired trust root lifetime (security LOW-1, correctness L8).**
   - The renderer coercion (`if (v.expired && trustLifetime === '') trustLifetime = '365d'`) is removed.
   - While the trust root has expired, the lifetime control offers no `유지` / `Keep`, and no value is preselected. Add and Remove stay disabled until a lifetime is picked.
   - `trustLifetime` resets to `''` (Keep) after every successful write.
   - The engine's `admin.p2.err.pickLifetime` refusal stays as the backstop.
3. **Snapshot first (security LOW-2, correctness L1).** `inputsOf(pin)` is called before `trustRootDocument`, `loadPolicyRoot` and `forbiddenApproverKeys`, so the commit guard sees any change made after the forbidden list was computed.
4. **Picker after the refusals (correctness M1).** For add, the public-key picker runs after:
   - the role check;
   - the previous-root check (`trustRootDocument`);
   - the root-walk refusal;
   - the forbidden-list computation;
   - the `leftOver` refusal.

   `requireNoDialog()` stays immediately before `ask()`.
5. **One root-walk refusal (correctness M3).** The add path's separate English `rootCheck` is deleted. `trustRootDocument` refuses first with `admin.p2.err.trustRootUnchanged` for every write. No hard-coded English refusal remains on the add path.
6. **`timestampMismatch` (correctness M2).** It is true only when the host-view failure is the binding check: the timestamp names other document digests or versions (`policy.ts` ~709 and the digest comparison). An expired, missing or unreadable timestamp sets `timestampMismatch: false`, and POLICY CHECK shows the trust note (the host's reason) instead.
7. **Forbidden keys and the revocation minimum (security LOW-3).**
   - `forbiddenApproverKeys(policy, now, o?: { minimumRevocations?: number })` refuses a revocation list below the minimum with `StaleDocumentError`.
   - The GUI passes `memoryMinimums(...).revocations`. The CLI passes nothing, which keeps today's behaviour.
8. **Renderer display (security LOW-4; correctness L2, L3, L4, L5, L7).**
   - Approver names in the TRUST ROOT list go through `dialogSafe`, the same function the dialogs use. Move it to `gui/src/i18n` or a shared renderer util if needed.
   - The add form clears only when the add result is `ok` (L2).
   - The trust root path is shown under a new label, `admin.p2.label.trustRootPath`: `신뢰 루트 파일` / `Trust root file` (L3).
   - `admin.p2.err.notRoot` gets the localised role name from the existing `admin.role.*` keys (L4).
   - New catalog keys replace the hard-coded `TRUST ROOT`, `POLICY CHECK`, `SHA-256` and `Key ID` labels: `admin.p2.dev.trustRoot`, `admin.p2.dev.policyCheck`, `admin.p2.label.sha256`, `admin.p2.label.keyId`. Device names stay the same English words in both languages, as in phase 1 (L5).
   - `loadTrustView` shows the failure with `admin.p2.err.rolesUnknown` and the reason, not a stuck `검사 중…` (L7).
9. **Engine English (correctness L6).** Accepted. Engine messages reach the GUI in English through `dialogSafe`, as Z2 says.
10. **Tests (correctness M4, L9).**
    - A GUI test: a rolled-back root event log refuses add, remove and renew before any dialog opens, and no picker is called.
    - A GUI test: an expired revocation list that the trust-root change does not fix makes Sign refuse with `consequenceToFailed`, and no signing dialog opens.
    - `tests/preview-import.test.ts` also scans `.mjs`, `.cjs` and `gui/tests`.
    - Tests for items 2, 3, 6 and 7.
