# Design: administration rack phase 2 (manage approvers, revoke, publish)

Status: draft v1, for Goldfish review. Builds on [the hardening design](gui-admin-hardening.md) (phase 1.1), which must be merged first: it provides the native dialogs, cooldown and one-dialog-at-a-time rule, the queue, synchronous `dropKey` with generations, `withTimeout`, `dialogSafe`, the GUI rollback memory and typed engine failures. The behaviour is specified in [`docs/spec/gui-admin-rack-v1.md`](../spec/gui-admin-rack-v1.md) ("Shared rules for phases 2 and 3", "Manage approvers", "Revoke", "Publish"); this document says how to build it.

## Problem

Phase 1 lets an approver sign certificates in the GUI. Root administrators still need the CLI for every other routine operation: adding, removing and renewing approvers, revoking a version or a key, refreshing the revocation list and signing timestamps. Phase 2 brings those into three fixed templates.

## Technical plan

1. **Engine: in-memory keys and a pre-write hook.** Every engine operation the templates run takes an already-loaded key and a `beforeWrite` hook, mirroring phase 1's `approverKey` and phase 1.1's `beforeSign`. The CLI keeps passing paths; nothing changes for it.
2. **One signing pattern for all root operations.** Each signing method of `AdminSession` follows the same order as phase 1.1's `approve` (D11): capture `op`; refuse without the right role, while a dialog is open or in cooldown; validate inputs; re-check the role (`current(role)`); compute exactly what will be written (a preview from the engine, without signing); open the native signing dialog showing it; on cancel or timeout, cooldown; on confirm, call the engine with the loaded key and `beforeWrite` that compares the generation and re-runs `current(role)`.
3. **Previews.** The dialog must show what is signed. For a trust root change: the action, the approver's name, key id, scopes and expiry (add), the approver being removed (remove), the new expiry (renew), and the new version number. For a revocation: the target (digest or key id, and for a key its name and how many discovered Skills it signed), the reason and the new list's expiry. For a refresh: the new version and expiry. For a timestamp: the version, expiry and the three document digests.
4. **Templates in the renderer.** The three template cards become active. Each renders its chain with the phase 1 faceplate and detail-pane pattern. *Publish* has a second IDENTITY step (spec: "Changing key mid-chain").
5. **Freshness notice.** After any root write, if the pin has `freshness`, the device shows `이 조직은 타임스탬프를 써요. 게시 템플릿에서 새 타임스탬프를 서명할 때까지 호스트는 문서를 믿지 않아요.`

## Alternatives considered

- **One generic "sign document" IPC.** Rejected: each operation has different inputs and checks, and a generic call widens what a compromised renderer can request.
- **Writing documents to a staging folder for an administrator to copy.** Rejected for phase 2: the CLI writes in place, and the spec says root devices write the documents the pin names. Organisations that publish from a separate location point the pin at it.
- **Choosing the approver's public key by pasting text.** Rejected: the renderer would carry key material and paths; the main process opens a file dialog instead, as for private keys.

## Implementation plan (files and signatures)

### Engine

- `src/admin.ts`:
  - `addApprover`, `removeApprover`: options gain `rootKey?: PrivateKeyInfo` (exactly one of `rootKeyPath` and `rootKey`, else throw `Pass exactly one of rootKeyPath and rootKey`), `publicKey?: PublicKeyInfo` for `addApprover` (exactly one of `publicKeyPath` and `publicKey`), and `beforeWrite?: (next: TrustRoot) => void | Promise<void>`, awaited after the new trust root is built and signed and immediately before `writeFileAtomic`; a throw writes nothing.
  - New `renewTrustRoot(options: { rootKeyPath?: string; rootKey?: PrivateKeyInfo; trustRootPath: string; now: Date; expires: string; beforeWrite?: (next: TrustRoot) => void | Promise<void> }): Promise<{ version: number; path: string; expiresAt: Date }>`: next version, same approvers, new expiry.
  - New `previewTrustRootChange(options: { rootKeyId: string; trustRootPath: string; now: Date; change: { kind: 'add'; publicKey: PublicKeyInfo; name: string; scopes: string[]; expires: string } | { kind: 'remove'; keyId: string } | { kind: 'renew'; expires: string } }): Promise<{ version: number; expiresAt: Date; approver?: { keyId: string; name: string; scopes: string[]; expiresAt: Date } }>`: reads and verifies the current trust root (`readTrustRootForUpdate`), applies the change to a copy, and returns what would be signed, without signing or writing. It throws with the same messages as the real operation (role-separation, duplicate, unknown key).
  - `updateRevocations`: options gain `rootKey?: PrivateKeyInfo` (exactly one with `rootKeyPath`) and `beforeWrite?: (next: Revocations) => void | Promise<void>`.
  - New `previewRevocationsChange(options: { rootKeyId: string; rootPublicKey: KeyObject; revocationsPath: string; now: Date; expires: string; revokeKey?: string; revokeDigest?: string; reason?: string }): Promise<{ version: number; expiresAt: Date }>`, same messages as `updateRevocations` for an already revoked target.
- `src/recovery-admin.ts`: `signPolicyTimestamp` options gain `key?: PrivateKeyInfo` (exactly one with `keyPath`) and `beforeWrite?: (next: Timestamp) => void | Promise<void>`; new `previewPolicyTimestamp(options: { policy: Policy; keyId: string; now: Date; expires?: string; version?: number }): Promise<Timestamp>` (the timestamp that would be signed, without the signature).
- Every new option is covered in `tests/` next to the existing tests of the same function; existing tests pass unmodified.

### GUI service (`gui/src/service/admin.ts`, `types.ts`)

- New view types:
  ```ts
  interface AdminTrustRootView { version: number; issuedAt: string; expiresAt: string; rootKeyId: string; approvers: Array<{ keyId: string; name: string; scopes: string[]; expiresAt: string; expired: boolean; revoked: boolean; signedSkills: string[] }> }
  interface AdminRevocationsView { version: number; issuedAt: string; expiresAt: string; daysLeft: number; keys: Array<{ keyId: string; reason: string; revokedAt: string }>; digests: Array<{ digest: string; reason: string; revokedAt: string }> }
  interface AdminPublishView { freshness: boolean; timestamp: { version: number; expiresAt: string; matches: boolean } | null; trustRoot: { version: number; expiresAt: string } | null; revocations: { version: number; expiresAt: string } | null }
  interface AdminVerifyAllView { counts: Partial<Record<Verdict, number>>; skills: Array<{ name: string; verdict: Verdict; reason: string }> }
  type AdminRootLifetime = '90d' | '180d' | '365d';         // approver key lifetimes
  type AdminTrustRootLifetime = '180d' | '365d';
  type AdminListLifetime = '7d' | '30d';
  type AdminTimestampLifetime = '6h' | '12h' | '24h';
  ```
  `AdminSignSummary` becomes a union with `action: 'approve' | 'add-approver' | 'remove-approver' | 'renew-trust-root' | 'revoke-digest' | 'revoke-key' | 'refresh-revocations' | 'sign-timestamp'` and the preview fields of each.
- New `AdminSession` methods (signing ones queued and following plan item 2):
  - `trustRoot(): Promise<AdminTrustRootView>` (root role; `signedSkills` from verifying discovered Skills under the pin with the trust context, matching certificate approver key ids);
  - `addApprover(input: { name: string; scopes: string[]; lifetime: AdminRootLifetime }): Promise<AdminActionResult>`: the public key file is chosen by a new `pickPublicKey: () => Promise<string | null>` option (main opens a native dialog); refuse a key that is the active root, a recovery key or the active timestamp key (`이 키는 이미 다른 역할을 맡고 있어요`); name 1–128 characters, `requireDisplaySafeText`; each scope validated with the engine's `validateScope`;
  - `removeApprover(keyId: string)`, `renewTrustRoot(lifetime: AdminTrustRootLifetime)`;
  - `revocations(): Promise<AdminRevocationsView>`;
  - `revoke(input: { kind: 'digest'; instanceId: string; digest: string } | { kind: 'key'; keyId: string }, reason: string, lifetime: AdminListLifetime, acknowledged: boolean)`: `acknowledged` must be true (the renderer's consequence checkbox); a digest target must have been reviewed with `review` by this key in this generation, as in phase 1.1; the reason rule of phase 1.1 D15 with a 512-unit limit;
  - `refreshRevocations(lifetime: AdminListLifetime)`;
  - `publish(): Promise<AdminPublishView>`, `signTimestamp(lifetime: AdminTimestampLifetime)` (timestamp role; lifetime capped at `freshness.max_lifetime`, else `이 기간은 정책의 최대 수명(<max>)을 넘어요`);
  - `verifyAll(): Promise<AdminVerifyAllView>` (pin policy, trust context loaded with the GUI memory, every discovered Skill).
- `review(id)` accepts the root role too (revoke uses it); approve still requires the approver role.

### Main, preload, renderer

- `main.ts`: `pickPublicKey` with `dialog.showOpenDialog` (`공개 키 선택 (PEM)`); IPC `admin:trust-root`, `admin:add-approver`, `admin:remove-approver`, `admin:renew-trust-root`, `admin:revocations`, `admin:revoke`, `admin:refresh-revocations`, `admin:publish`, `admin:sign-timestamp`, `admin:verify-all`, each validating its arguments (key ids `^sha256:[0-9a-f]{64}$`, lifetimes from the fixed lists, names and reasons by length, scopes at most 64 entries of at most 128 characters, booleans strictly boolean). The signing dialog's detail lines for each action are listed in the spec update.
- `preload.cts`, `types.ts`: matching `RendererApi.admin` methods.
- `gui/src/renderer/admin.ts`: the three templates active; devices TRUST ROOT, REVOKE (with INSPECT choosing a version or an approver key), REVOCATION REFRESH, IDENTITY (timestamp), TIMESTAMP and the phase 2 POLICY CHECKs; the freshness notice; the consequence checkbox `이 키가 서명한 모든 인증서가 더 이상 검증되지 않는다는 것을 이해했어요` (key) or `이 버전의 모든 인증서가 더 이상 검증되지 않는다는 것을 이해했어요` (digest).

### Spec

- `docs/spec/gui-admin-rack-v1.md`: the signing dialog text per action; the new IPC rows; status of phase 2.

### Tests

- `gui/tests/admin.test.ts` (new `describe`-style group per template), each using the phase 1.1 seams: add, remove and renew change the trust root on disk and the next `status` reflects it; a role-separation refusal; revoke digest then POLICY CHECK says `REVOKED`; revoke key then `verifyAll` reports the key's Skills as `REVOKED`; revoke refused without `acknowledged` and without a review; refresh increments the version; timestamp signed with the timestamp key after a root write makes `publish().timestamp.matches` true; the timestamp lifetime cap; cancel and disarm during each signing dialog write nothing; a removed approver's `signedSkills` count.
- Engine tests for every new option and preview function.
