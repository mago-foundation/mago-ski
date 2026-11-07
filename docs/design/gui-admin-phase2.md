# Design: administration rack phase 2 (approvers, revocation, refresh, timestamp)

Status: draft v2, for Goldfish review. v1 failed comprehension; two antagonistic reviews found that root writes signed documents read after the dialog, ignored the GUI's rollback memory, and could re-enrol retired keys. This version is a rewrite.

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
