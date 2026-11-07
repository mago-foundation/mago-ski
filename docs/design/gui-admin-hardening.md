# Design: hardening the administration rack (phase 1.1)

Status: draft, for Goldfish review. Elephant/Goldfish model: this document is the design; code follows only after it passes the comprehension, antagonistic and readiness checks.

## Problem

An independent review of phase 1 (`docs/spec/gui-admin-rack-v1.md`, merged in mago-foundation/mago-ski#15) confirmed 13 findings with proof-of-concept scripts. The approver's "I reviewed this version" is an IPC call, so a compromised renderer with an armed key can sign any in-scope version (high). An unprivileged Linux user namespace can fake the root-owned pin; older signed documents and an older root event log replay in admin mode because the GUI keeps no rollback memory; a key stored inside a Skill folder is accepted (medium). Races let a sign complete after eject or revocation, the scope check and the signed name come from different reads of `SKILL.md`, an error message carries the key path, status does not disarm until the next operation, macOS can never use the pin, a blank reason is accepted, and INSPECT's verdict can describe different bytes than its digest (low). Phase 2 adds root-key operations to the same mechanism, so these are fixed first.

## Goals and non-goals

Goals: a signature happens only after a human gesture in the main process that shows exactly what is signed; the pin cannot be faked from a user namespace; the GUI refuses documents older than it has already seen; no signature completes after eject, disarm, pin change or role loss; every finding has a regression test.

Non-goals: stopping a key holder from signing with the CLI (authority is cryptographic; hosts decide); protecting against same-user malware or root (stated limits); hardware keys.

## Technical plan

1. **Native confirmation before every signature.** `AdminSession` takes a `confirm` dependency. `approve` calls it after all checks and before signing, with a summary (Skill name, full digest, lifetime, reason, the armed key's name and key id). In Electron, `main.ts` implements it with `dialog.showMessageBox(window, { type: 'warning', buttons: ['취소', '서명'], defaultId: 0, cancelId: 0, noLink: true, message, detail })`; only button index 1 signs. The renderer's INSPECT confirmation stays as a UI step but is no longer sufficient.
2. **User-namespace check.** On Linux, the pin is refused unless `/proc/self/uid_map` and `/proc/self/gid_map` are the identity map (`0 0 4294967295`), which they are only outside a user namespace. Other platforms skip it.
3. **macOS `/etc`.** On macOS `/etc` is a root-owned symlink to `private/etc`. Before the ownership walk the pin path is mapped to `/private/etc/mago-ski/policy.json`, after checking that `/etc` is a symbolic link owned by root whose target is exactly `private/etc`.
4. **GUI rollback memory.** The GUI keeps its own host-state file, `<GUI data dir>/admin-state.json` (format `mago.host-state/v1|v2`, written by the engine). The pin's policy is loaded with that file as its `statePath` and `recordVersions: true`, so trust root and revocation versions, root events (rollback and fork) and timestamp versions are remembered and older documents are refused. This is per user: a same-user attacker can delete it; the spec says so. The organisation's host state (`state_file`) is still never written.
5. **Rollback-checked root.** The root event walk and its rollback, fork and revoked checks move out of `loadPolicyTrust` into a new exported engine function `loadPolicyRoot`, which `loadPolicyTrust` calls first. `readPin` uses `loadPolicyRoot` with the GUI's state file, so a replayed log is refused and roles come only from a checked walk.
6. **Keys outside Skills.** `arm` refuses a key whose canonical path is inside any discovery root or discovered Skill directory; `approve` re-checks with the engine's `resolveOutside` against the Skill being signed.
7. **One operation at a time, and a generation.** Every public `AdminSession` method runs through one promise queue. A `generation` counter increases on every arm and disarm. Inspection records are keyed by `keyId`, generation and instance id, and an approve claims (deletes) its record synchronously before its first `await`.
8. **Re-check at the moment of signing.** `approveSkill` gains an optional `beforeSign` callback, called after the bytes, name and digest are final and immediately before the certificate is written. `AdminSession` uses it to re-run the role check (`current`), compare the generation, and check the approver's scopes against the name taken from the signed `SKILL.md` bytes. Any failure throws and nothing is written.
9. **Smaller fixes.** Key load errors map to fixed text without paths. `status` runs the same re-check and disarms on pin or role change. Reasons are trimmed and must be non-empty in the main process. INSPECT compares the verdict's digest with the displayed digest and says "changed while reading" if they differ. `readRegularFile` gains a `sensitive` option that zeroes its read chunks; `loadPrivateKey` uses it. The main process disarms when the renderer reloads, navigates or crashes.

## Alternatives considered

- **Require `freshness` for any admin role** (the reviewer's first fix for replay). Rejected as the default: it forces every organisation, including a solo developer, to run a timestamp job. Freshness is still honoured when present, and the GUI's rollback memory covers the rest. Revisit if persona tests show organisations want it mandatory.
- **Record the INSPECT confirmation from a native dialog instead of at signing.** Rejected: two dialogs for one approval; the signing dialog shows the full summary, which is what the human must agree to.
- **Mount-namespace checks via `/proc/self/mountinfo`.** Rejected: changing mounts without a user namespace needs root, which is out of scope.
- **Re-reading `SKILL.md` for the scope check.** Rejected in favour of `beforeSign` with the name from the signed bytes, which removes the race instead of narrowing it.

## Implementation plan (files and signatures)

### Engine

- `src/fs-safe.ts`: `readRegularFile(filePath: string, label: string, maxBytes?: number, options?: { sensitive?: boolean }): Promise<Buffer>`. With `sensitive`, every chunk buffer is zero-filled after the final buffer is assembled.
- `src/keys.ts`: `loadPrivateKey` calls `readRegularFile(filePath, 'Private key', MAX_KEY_FILE_BYTES, { sensitive: true })`.
- `src/admin.ts`: `approveSkill` options gain `beforeSign?: (info: { skillName: string; digest: string; certificateBytes: Buffer }) => void | Promise<void>`, awaited after `issueCertificate` and before `writeFileAtomic`. A throw propagates; no file is written.
- `src/policy.ts`: new
  ```ts
  export type PolicyRootResult =
    | { ok: true; walk: RootWalk | null; activeRootKeyId: string }
    | { ok: false; reason: string; rootRevoked: boolean };
  export async function loadPolicyRoot(policy: Policy, now: Date, options?: { recordVersions?: boolean }): Promise<PolicyRootResult>;
  ```
  It contains steps 1 to 3 of the current `loadPolicyTrust` (read state, walk the log, rollback and fork checks, record event progress, revoked root); for a policy without `recovery` it returns `{ ok: true, walk: null, activeRootKeyId: policy.rootKeyId }`. `loadPolicyTrust` calls it and keeps its behaviour and messages unchanged (all existing tests must pass unmodified).

### GUI service (`gui/src/service/admin.ts`)

- `AdminSessionOptions` gains `confirm: (summary: AdminSignSummary) => Promise<boolean>` (required), `stateDir: string` (the GUI data dir; the memory file is `path.join(stateDir, 'admin-state.json')`), `discoveryRoots: () => string[]`, and test-only `platform?: NodeJS.Platform` and `procDir?: string` (default `/proc`).
- `AdminSignSummary` (in `types.ts`): `{ action: 'approve'; skillName: string; digest: string; lifetime: AdminLifetime; reason: string; keyId: string; approverName: string | null }`.
- `pinOwnershipProblem(file, rootUid, trustedBase?, env?: { platform: NodeJS.Platform; procDir: string })`: adds the identity-map check (Linux) and the macOS `/etc` mapping.
- `readPin(options)` builds `const memoryPolicy = { ...policy, statePath: path.join(stateDir, 'admin-state.json'), decisionLogPath: null }`, calls `loadPolicyRoot(memoryPolicy, now, { recordVersions: true })` and `loadPolicyTrust(memoryPolicy, now, { recordVersions: true })`. `PinState.loaded` replaces `walk`/`walkError` with `root: PolicyRootResult`. `activeRoot(pin)` returns `pin.root.ok ? pin.root.activeRootKeyId : null`; recovery and timestamp roles use `pin.root.ok && pin.root.walk`.
- `class AdminSession`: private `queue: Promise<unknown>`, `generation: number`, `armed.keyPath: string` (canonical path; never leaves the process), inspected records `Map<string, string>` keyed `` `${keyId}|${generation}|${instanceId}` ``. A private `serial<T>(fn: () => Promise<T>): Promise<T>` wraps every public method. `approve` claims the record before its first await, trims and checks the reason, builds the summary, `await this.options.confirm(summary)` (false → `{ ok: false, message: 'cancelled' }`), then calls `approveSkill` with `beforeSign` that re-runs `current('approver')`, compares the generation and checks scopes against `info.skillName`.
- `status()` calls a non-throwing `recheck()` that disarms on pin hash or role change.

### Main process (`gui/src/main/main.ts`)

- Passes `confirm` implemented with `dialog.showMessageBox` as above (text in Korean, with the digest in full), `stateDir: app.getPath('userData')` and `discoveryRoots: () => svc.view().roots.map((r) => r.path)`.
- `win.webContents.on('did-start-navigation' | 'render-process-gone' | 'destroyed', () => admin?.disarm())`, and disarm before `win.webContents.reload` handlers fire (any `did-finish-load` after the first load also disarms).

### Renderer (`gui/src/renderer/admin.ts`)

- After a cancelled native dialog, shows "서명을 취소했어요" and keeps the form.

### Spec (`docs/spec/gui-admin-rack-v1.md`)

- Identity and Approve sections: the native confirmation; the generation and queue; `beforeSign`.
- Organisation pin: the user-namespace check and the macOS mapping.
- New subsection "Replay": the GUI's rollback memory, its per-user limit, and that freshness, when configured, bounds replay for everyone.
- Limits: remove the claim that "a forged or swapped document fails verification" for replays; state that a key holder can always sign with the CLI.

### Tests

- `gui/tests/admin.test.ts`: one regression test per finding 1 to 13 (renderer-only confirmation refused without `confirm` true; a fake `procDir` with a non-identity `uid_map`; replay of an older trust root after a newer one was seen; replayed root event log; key inside a discovery root; eject during a slow approve via `beforeSign` timing; concurrent approves with one confirmation; scope race via a `SKILL.md` swap in `beforeSign`; error text without path; status disarm; macOS mapping with a fake `platform`; blank reason; INSPECT digest mismatch).
- `tests/approve-expect-digest.test.ts`: `beforeSign` throwing writes nothing.
- `tests/root-recovery.test.ts`: `loadPolicyRoot` for v1, v2, rollback, fork, revoked.
- All existing tests pass unmodified.
