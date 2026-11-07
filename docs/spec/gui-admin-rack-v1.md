# GUI administration rack v1

Status: **draft.** Phase 1, hardened in phase 1.1 ([design](../design/gui-admin-hardening.md)), (the organisation pin, identity, the template framework and the *Approve a Skill version* template) is implemented in the GUI proof of concept (`gui/src/service/admin.ts`, `gui/src/renderer/admin.ts`, tests in `gui/tests/admin.test.ts`). Phases 2 and 3 are specified here and not yet implemented. The CLI stays the reference for every operation: each device calls the same engine functions as the CLI command it names.

The [GUI](../../gui/README.md) began as a read-only companion: it showed how installed Skills change and what the host policy decides, and never signed anything. This document adds an **administration rack**, so approvers and administrators can do in the GUI everything they can do with the CLI, in fixed chains of devices (templates), next to the observation rack.

## Principles

1. **Authority is cryptographic.** What an approver or administrator can do is decided by the private keys they hold and by the signed trust documents, exactly as for the CLI. Hosts accept a certificate, trust root, revocation list or root event only if its signature verifies against the organisation's root. The GUI recognising a role is guidance and a safety interlock, never a source of authority: a modified GUI that shows an employee the root devices still cannot produce a document any host accepts.
2. **The organisation is identified by an admin-owned pin**, never by a file the person at the keyboard can edit (see [Organisation pin](#organisation-pin)).
3. **Fixed templates, not free patching.** The order of operations is part of a procedure (inspect before approving, check the policy after changing it). Each template is a fixed chain; devices cannot be reordered, skipped or added. This follows the ontology's rule that editing "must not allow arbitrary execution ordering that breaks mandatory gates" ([ontology §24.2](../mago-ski-ontology.md)).
4. **Enforcement is untouched.** The observation rack's APPROVAL GATE stays a locked device. Nothing in the administration rack changes what a host blocks except through signed documents, which hosts verify as before.
5. **Every signature binds what was shown, and needs two human answers.** A certificate is signed only for the exact digest and name a native review dialog recorded (the engine's `expectDigest` and `expectName`), and only after a second native dialog shows everything that is signed. Both dialogs belong to the main process; the page can ask, never answer. A changed Skill must be reviewed again.

## Organisation pin

The organisation pin is a **policy file** (`mago.policy/v1` or `mago.policy/v2`, [trust documents](trust-documents-v1.md)) at a fixed, admin-owned location:

| Platform | Path |
|---|---|
| Linux, macOS | `/etc/mago-ski/policy.json` |

The GUI reads the organisation's identity only from this file: `root_fingerprint`, and for a v2 policy the recovery set, `root_events_after`, `root_events` and `freshness`. There is no environment variable, setting or dialog to point it elsewhere, because anything the person at the keyboard can change could name a root they own.

**Ownership rules.** The pin is used only if:

- it is a regular file, not a symbolic link;
- it and every directory above it are owned by root (uid 0) and are not writable by group or others;
- no component of its path is a symbolic link;
- it loads as a valid policy;
- on Linux, the process is not in a user namespace: `/proc/self/uid_map` and `/proc/self/gid_map` each read exactly `0 0 4294967295` (whitespace aside). An unreadable map refuses too.

Otherwise admin roles are not recognised, and the administration rack says which rule failed and how to install the pin. Its documents (`trust_root`, `revocations`, `root_events`, `freshness.timestamp`) may live anywhere, because they are signed: a *forged* document fails verification against the pinned root. A genuine but *older* document still verifies; see [Replay and this computer's memory](#replay-and-this-computers-memory).

**macOS.** `/etc` is a symbolic link to `private/etc`. When `/etc` is a link whose target is exactly `private/etc`, the ownership walk runs on `/private/etc/mago-ski/policy.json` (and `/private` must be root-owned like any directory); the GUI shows that path. Any other `/etc` link is refused as a symbolic link.

**The user-namespace check is a hurdle, not a boundary.** A user in their own user namespace can map themself to uid 0 and own files that look root-owned, and can bind-mount over the map files inside that namespace. The check refuses the accidental and casual cases, and it refuses Flatpak, rootless containers and CI runners that use user namespaces: the administration rack is **not supported** in those. The pin's protection against the person at the keyboard ends where the operating system's does.

**NixOS.** `environment.etc` links files into the store, which the no-symbolic-link rule refuses. Install the pin as a real file: `environment.etc."mago-ski/policy.json".mode = "0644"`.

**Why a separate location.** The Pi host reads `$MAGO_SKI_POLICY` or `~/.mago-ski/policy.json`, which the user can edit. An employee who writes their own policy pinning their own key would be, to a GUI reading that file, the root of an organisation of their own. A root-owned pin removes that. A deployment that wants the employee's Pi to follow the same organisation sets `MAGO_SKI_POLICY=/etc/mago-ski/policy.json` for them. The GUI's observation rack keeps reading the policy Pi reads; when that differs from the pin, the administration rack says so.

Admin mode never reads or writes the policy's own host state (`state_file`) or the decision log. It keeps its own rollback memory in the GUI's user data folder; see [Replay and this computer's memory](#replay-and-this-computers-memory).

## Roles

The **role** of a key is computed from the pin and the signed documents each time it is needed:

| Role | The key is | Read from |
|---|---|---|
| **Root administrator** | the active root key: `root_fingerprint`, replaced by each rotate root event; and not revoked by a root event | pin; root event log |
| **Approver** | an approver in the trust root, verified under the active root; not expired; key not revoked in the revocation list | trust root; revocation list |
| **Recovery trustee** | in the active recovery set | pin; root event log |
| **Timestamp signer** | the active timestamp key | pin; root event log |
| none | none of the above | |

The trust documents already forbid one key from holding two of these roles, so a key has at most one. An approver role carries the approver's name, scopes and expiry. A root administrator whose trust root or revocation list does not verify is still recognised, because fixing those documents is that role's job.

## Identity: the IDENTITY device

Every administration template starts with an IDENTITY device. It is the only place a private key enters the app.

1. The user chooses a private key file in a **native file dialog owned by the main process**. The renderer never sends a path and never receives key material.
2. The main process loads it with the engine's rules: regular non-symlink file, mode `0600` (no group or other access), PKCS#8 Ed25519.
3. **Proof of possession.** The main process signs a fresh 32-byte random challenge with the loaded key, under the domain-separated message `mago-ski gui identity v1\n<pinned root fingerprint>\n<challenge hex>\n`. It verifies the signature with the public key the documents name for the candidate role: the trust root's root or approver entry, a root event's `new_root`, a recovery or timestamp key's revealed public key. If no document carries the public key yet, it verifies with the public key derived from the private key, which must hash to the pinned fingerprint. A public key file, a key for another organisation, or a corrupt file fails here.
4. The device shows the role, the key id and, for an approver, the name, scopes and expiry. The key is now **armed**.

**Armed key lifetime.** The key object stays in the main process's memory only. It is never written to disk, logged, put on the clipboard or sent to the renderer. It is dropped when the user ejects it, when the template is closed or changed, after 15 minutes without an operation, when the pin changes or the key loses its role, when the window navigates, reloads, crashes or is destroyed, and when the app quits. Zeroing is best effort: the buffer the file was read into is zeroed after parsing; copies inside the crypto library cannot be.

**Synchronous disarm.** Dropping the key is one synchronous step: no key, a new *generation* number, no recorded reviews, no idle timer. It is never queued, so it cannot arrive after a signature. `disarm` (the eject button, a window event, the idle timer) calls it directly.

**Generations and the queue.** `arm`, `review`, `approve` and `reset-memory` run one after another through a queue. Each operation notes the armed key and the generation before its first wait and compares them after every later wait; a mismatch ends it with "키가 빠졌어요" and writes nothing. `status`, `inspect` and `check` are not queued and never wait for a dialog.

**Idle.** Only `arm`, `review` and `approve` count as use. `status`, `inspect` and `check` do not extend the idle time.

**Status re-check and polling.** `status` reads the pin and recomputes the role of the armed key; a change of the pin's bytes, or of the role's kind, key, scopes or expiry, drops the key. The page asks for the status every 5 seconds while the 관리 tab is visible, so a changed pin or a removed approver disarms within about 5 seconds without any operation.

**Window events.** The main process disarms on every navigation start, render-process crash, window destruction and every page load after the first.

**Re-check before every signature.** Before the signing dialog, and again inside the engine immediately before the certificate file is written (`beforeSign`), the main process recomputes the role from the current documents and the generation. An approver removed or revoked since arming cannot sign.

**Keys outside Skills.** A key whose real path is inside a discovery root, a discovered Skill folder, the pin's `skill_dirs` or the host policy's `skill_dirs` is refused when loading, as the CLI refuses it at signing ("Skill 폴더 안에 있는 키는 쓸 수 없어요. 키를 Skill 밖으로 옮기세요."); the same check runs against the stored path before signing. Key load errors are fixed text and never carry the file's path.

**Root and recovery keys.** The root key's protection is that it stays offline. Templates that need a root or recovery key show, before arming: *use this on an offline administration machine.* They do not refuse an online machine, but an organisation should not load its root key on a machine used for everyday work.

## Templates

A template is a fixed chain of devices. Each device has typed inputs, produced by the device before it, and shows one of these states:

| State | Meaning |
|---|---|
| locked | The armed key does not hold the role this device needs (says which role) |
| waiting | An input is missing (says which, e.g. "inspect a version first") |
| ready | All inputs are present; the device can run |
| done | It ran; shows the result (a digest, a file written, a verdict) |
| failed | It ran and failed; shows the engine's error |

Changing an input (another Skill, a new digest) resets every device after it.

| Template | Chain | Role | CLI | Phase |
|---|---|---|---|---|
| **Approve a Skill version** | IDENTITY → INSPECT → APPROVE → POLICY CHECK | Approver | `digest --explain`, `diff`, `inspect`, `approve --expect-digest`, `verify` | 1 |
| **Manage approvers** | IDENTITY → TRUST ROOT → POLICY CHECK | Root | `root show`, `root add-approver`, `root remove-approver`, `policy check` | 2 |
| **Revoke** | IDENTITY → INSPECT → REVOKE → POLICY CHECK | Root | `inspect`, `revoke key`, `revoke digest`, `policy check` | 2 |
| **Publish** | IDENTITY → REVOCATION REFRESH → TIMESTAMP → POLICY CHECK | Root, then timestamp signer | `revoke refresh`, `timestamp sign`, `policy check`, `verify-all` | 2 |
| **Set up an organisation** | KEYS → ROOT INIT → RECOVERY SET → POLICY CHECK | none (creates the keys) | `keygen`, `root init`, `recovery init`, `root-events init`, `policy check` | 3 |
| **Root incident** | IDENTITY → ROOT EVENT → ADOPT → POLICY CHECK | Recovery trustees, then the new root | `root-events prepare-revoke`, `prepare-rotate`, `show`, `sign`, `append`, `root adopt`, `policy check` | 3 |

Every CLI command has a device: the observation rack's APPROVAL GATE already covers `verify`. *Set up an organisation* is the only template that runs without a pin, because there is no organisation yet; it ends by showing how to install the pin.

### Approve a Skill version (phase 1)

**IDENTITY** needs the Approver role.

**INSPECT** takes one Skill the GUI has discovered. It shows:

- the current tree digest and every covered file with its SHA-256, size and executable bit, plus the paths excluded from the digest (`digest --explain`);
- the change from the version the GUI remembered, when there is one (`diff`);
- the certificate the Skill carries, if any, decoded and verified (`inspect` and `verify`).

The digest, the name and the verdict are taken from one read of the Skill; if the verdict was computed for different bytes than the digest shown, the verdict is hidden ("읽는 동안 바뀌었어요 · 다시 검토하세요").

**Review dialog.** The page's *I reviewed this version* button only asks (`admin:review`). The main process re-reads the Skill and opens a **native dialog** (Skill name, folder, full digest, number of covered files; "이 정확한 버전의 파일을 모두 검토했나요?"; buttons 취소, the default, and 검토함). Only 검토함 records the review for that key, generation and Skill. If the Skill's bytes change afterwards, the review is void.

**APPROVE** takes the inspected digest. It shows the Skill name the certificate will carry (from `SKILL.md`, as `approve` does) and refuses to run if the approver's scopes do not cover that name. The approver picks a lifetime (30, 90 or 180 days, never past the approver key's own expiry) and writes a reason (trimmed; at most 1024 characters; plain text; at least 3 letters or digits, where Hangul fillers and the Braille blank do not count).

**Order inside `approve`.** (1) Note the armed key and generation; refuse if none is armed, if a dialog is open or in the cooldown. (2) Find the review record for this key, generation and Skill with the requested digest. (3) Check the reason and lifetime. (4) Re-check the role and the scopes against the reviewed name; check the key is still outside the Skill. (5) Read the Skill once; its digest and name must equal the review's. (6) Claim the record (so a second approve cannot use it) and open the **signing dialog**: Skill, folder, reviewed digest, digest to be signed, lifetime and expiry, reason, and the key's role, name and id; buttons 취소 (default) and 서명. (7) On cancel or timeout, restore the record if the generation is unchanged and start the cooldown. (8) On 서명, call the engine's `approveSkill` with `expectDigest`, `expectName`, `outDir` and `beforeSign`. (9) A failure returns the engine's message, or fixed text if it could carry a path; the record stays consumed.

`expectName` refuses a Skill whose signed `SKILL.md` yields another name; `outDir` writes `<outDir>/<signed name>.cert.json` (the first `certificate_dirs` entry of the pin) from the name that was signed; `beforeSign` runs after the certificate is built and just before the file is written, and a throw writes nothing. Without `certificate_dirs` the certificate is written to `<Skill>/.mago-ski-cert.json`. The device shows the certificate id and path.

**Cooldown and timeout.** After a cancel or a timeout of either dialog, `review`, `approve` and `reset-memory` are refused for 10 seconds ("잠시 후 다시 시도하세요"), and while any dialog is open ("다른 확인 창이 열려 있어요"), so a compromised page cannot spam dialogs until one is clicked by mistake. A dialog unanswered for 120 seconds counts as a cancel; it may stay on screen, and a late answer is ignored.

**The remaining window.** `writeFileAtomic` awaits a few file operations after `beforeSign` returns. A disarm in that window does not stop the write. The certificate binds the reviewed digest, so the effect is a certificate the approver authorised a moment earlier.

**POLICY CHECK** verifies the Skill under the pin's policy, without recording versions, and shows the verdict. After a successful APPROVE it should be `VERIFIED`; anything else is shown with the engine's reason. It also shows the policy's trust status.

## Replay and this computer's memory

Signed documents say what was true when they were signed; a genuine older copy still verifies. A third party who can replace the documents (a share, a mirror) could replay an older trust root, revocation list or root event log, and bring back a removed approver or a rotated-out root key.

The GUI therefore keeps its own memory of the highest versions it has seen: `<user data folder>/admin-state.json`, in the engine's host state format (`mago.host-state/v1|v2`), written only by the engine. Every read of the pin records the versions of the root event log, trust root, revocation list and (with `freshness`) timestamp it accepted, and refuses older ones as a rollback. The organisation's own `state_file` is never read or written by admin mode.

- **First run.** The folder is created with mode `0700`; the first load records whatever the documents are.
- **Corrupt memory.** The unreadable file is renamed to `admin-state.json.unreadable-<time>`, the 관리 tab shows "이 컴퓨터의 관리 기록을 읽을 수 없어서 따로 보관하고 새로 시작했어요 (<path>)" until dismissed (`admin:dismiss-memory-reset`), and loading starts again with an empty memory.
- **Legitimate reset.** If an organisation is re-initialised with the same root key, versions restart and the documents look older. The tab then says "이 컴퓨터가 이미 본 것보다 오래된 문서예요. 조직이 문서를 다시 만들었다면 기록을 초기화하세요." with a 기록 초기화 button, which asks in a native dialog and renames the memory aside.
- **A memory that cannot be written** makes the pin unusable ("이 컴퓨터의 기록을 저장하지 못했어요") and drops the armed key.
- **What it protects.** Accidental replay and replay by someone who can change the documents but not this user's profile. It does not protect against the user, who can delete or move it (including with `MAGO_SKI_GUI_DATA`). With `freshness` in the pin, the timestamp bounds replay for everyone.
- **Known limit.** An unqueued `status` poll that overlaps a load while the root event log grows can report a transient rollback; the next poll clears it.

## Process boundaries

The window is sandboxed as before (context isolation, no Node integration, CSP `default-src 'none'; script-src 'self'; style-src 'self'`). Phase 1 adds these IPC calls; each checks that the call comes from the app's own page:

| Call | Arguments | Effect |
|---|---|---|
| `admin:status` | none | The pin's state and the armed role (never key material) |
| `admin:arm` | none | Opens the key dialog in the main process; returns the role or why it failed |
| `admin:disarm` | none | Drops the armed key at once (synchronous; ends any operation in progress) |
| `admin:inspect` | instance id | The INSPECT view of that Skill's current version |
| `admin:review` | instance id | Opens the native review dialog; records the review only if the human answers 검토함 |
| `admin:approve` | instance id, digest, lifetime, reason | Opens the native signing dialog and signs only after it is confirmed, if the digest is the recorded reviewed digest and the role re-check passes |
| `admin:check` | instance id | POLICY CHECK for that Skill |
| `admin:reset-memory` | none | Opens a native confirmation, then moves this computer's admin memory aside |
| `admin:dismiss-memory-reset` | none | Clears the notice that the memory was moved aside |

The renderer cannot name a file, a key or a directory in any of them. A compromised renderer cannot cause a signature without both native dialogs being answered by a human: it can ask for them, and after a cancel or a timeout it is refused for 10 seconds.

## Limits

- **A compromised machine sees an armed key.** Same-user malware can read the main process's memory while a key is armed. Arm keys briefly; never arm the root key on a machine used for everyday work.
- **The pin's protection is file ownership.** Anyone with root on the machine can replace the pin, as they can replace the host policy.
- **Pi with a user-writable policy stays user-trusted.** The pin protects the GUI's notion of the organisation, not a Pi host whose own policy the employee controls; point Pi at the pin (`MAGO_SKI_POLICY`) or use the [gate](../hosts/adapter-interface.md).
- **Key holders can always use the CLI.** The GUI's dialogs and checks bind the GUI, not the key: whoever holds an approver key can sign with `mago-ski approve`. Authority is cryptographic.
- **The user-namespace check is a hurdle**, not a boundary (see [Organisation pin](#organisation-pin)); Flatpak, rootless containers and user-namespace CI runners are unsupported.
- **A copy or hard link of the key inside a Skill is not detected.** A moved key fails the stored-path check at signing. The private-key scan at signing covers the files the digest covers, as in the CLI.
- **The memory does not protect against the user** (see above).
- **No hardware keys yet.** Keys are PEM files, as for the CLI.

## Phases

1. This document; the organisation pin; IDENTITY; the template framework; *Approve a Skill version*.
2. *Manage approvers*, *Revoke*, *Publish*.
3. *Set up an organisation*, *Root incident*.
