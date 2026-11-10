# GUI administration rack v1

Status: **draft.** Phase 1, hardened in phase 1.1 ([design](../design/gui-admin-hardening.md)), (the organisation pin, identity, the template framework and the *Approve a Skill version* template) and phase 2a ([design](../design/gui-admin-phase2.md): the engine for every root and timestamp write, and the *Manage approvers* template) are implemented in the GUI proof of concept (`gui/src/service/admin.ts`, `gui/src/renderer/admin.ts`, tests in `gui/tests/admin.test.ts`). Phase 2b (*Revoke*, *Refresh revocation list*, *Sign timestamp*) and phase 3 are specified here and not yet implemented. The CLI stays the reference for every operation: each device calls the same engine functions as the CLI command it names.

The [GUI](../../gui/README.md) began as a read-only companion: it showed how installed Skills change and what the host policy decides, and never signed anything. This document adds an **administration rack**, so approvers and administrators can do in the GUI everything they can do with the CLI, in fixed chains of devices (templates), next to the observation rack.

The GUI shows every text in Korean or English (see [the i18n design](../design/gui-i18n.md)); the Korean texts quoted in this spec are the Korean catalog entries in `gui/src/i18n/messages.ts`.

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

1. The user chooses a private key file in a **native file dialog owned by the main process**. The dialog counts as a dialog like the others: it is refused while another dialog is open, counts as open while it is shown, and a cancel starts the cooldown (the refusal texts are those under *Cooldown and timeout*). The renderer never sends a path and never receives key material.
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

**Keys outside Skills.** A key whose real path is inside a discovery root, a discovered Skill folder, the pin's `skill_dirs` or the host policy's `skill_dirs` is refused when loading, as the CLI refuses it at signing ("Skill 폴더 안에 있는 키는 쓸 수 없어요. 키를 Skill 밖으로 옮기세요."); the same check runs again against the stored path, with the roots as they are then, before the signing dialog and in `beforeSign`. A key folder that became a discovery root after arming refuses with the same text.

**One key file.** `arm` resolves the chosen path to its real path, opens that with `O_NOFOLLOW`, checks on the open handle that it is a regular file, reads at most 64 KiB from that handle and loads the key from those bytes; it remembers the real path with the file's device and inode. The key file must be the same file, and must not be inside a Skill, both before the dialog and immediately before signing: `approve` checks that the path is still a regular file with the same device and inode (before the Skill-location checks, and again in `beforeSign`); otherwise the key is dropped and approve says "키 파일이 바뀌었어요. 다시 불러오세요."

**Lifetime.** The lifetime check uses the approver's expiry as the status re-check has just refreshed it, not the expiry seen at arming. Key load errors are fixed text and never carry the file's path.

**Root and recovery keys.** The root key's protection is that it stays offline. Arming a root or recovery key asks, in a native dialog, whether this is the offline administration computer; answering no or closing it does not arm the key. The dialog is shown after proof of possession and the role check, and before the key is armed. It counts as a dialog for the one-dialog and cooldown rules. A computer cannot prove it is offline: the dialog is a prompt, and an organisation should not load its root key on a machine used for everyday work.

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
| **Manage approvers** | IDENTITY → TRUST ROOT → POLICY CHECK | Root | `root show`, `root add-approver`, `root remove-approver`, `root renew`, `policy check` | 2a |
| **Revoke** | IDENTITY → TARGET → REVOKE → POLICY CHECK | Root | `revoke key`, `revoke digest`, `policy check` | 2b |
| **Refresh revocation list** | IDENTITY → REVOCATION REFRESH → POLICY CHECK | Root | `revoke refresh`, `policy check` | 2b |
| **Sign timestamp** | IDENTITY → TIMESTAMP → POLICY CHECK | Timestamp signer | `timestamp sign`, `policy check`, `verify-all` | 2b |
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

**Order inside `approve`.** (1) Note the armed key and generation; refuse if none is armed, if a dialog is open or in the cooldown. (2) Find the review record for this key, generation and Skill with the requested digest. (3) Check the reason and lifetime. (4) Re-check the role and the scopes against the reviewed name; the key file must be the same file and still outside every Skill. (5) Read the Skill once; its digest and name must equal the review's. (6) Check again that no dialog is open, claim the record (so a second approve cannot use it) and open the **signing dialog**: Skill, folder, reviewed digest, digest to be signed, lifetime and expiry, reason, and the key's role, name and id; buttons 취소 (default) and 서명. (7) On cancel or timeout, restore the record if the generation is unchanged and start the cooldown. (8) On 서명, call the engine's `approveSkill` with `expectDigest`, `expectName`, `outDir` and `beforeSign`. (9) A failure returns the engine's message, or fixed text if it could carry a path; the record stays consumed.

`expectName` refuses a Skill whose signed `SKILL.md` yields another name; `outDir` writes `<outDir>/<signed name>.cert.json` (the first `certificate_dirs` entry of the pin) from the name that was signed; `beforeSign` runs after the certificate is built and just before the file is written, and a throw writes nothing. Without `certificate_dirs` the certificate is written to `<Skill>/.mago-ski-cert.json`. The device shows the certificate id and path.

**Cooldown and timeout.** After a cancel or a timeout of either dialog, `review`, `approve` and `reset-memory` are refused for 10 seconds ("잠시 후 다시 시도하세요"), and while any dialog is open ("다른 확인 창이 열려 있어요"), so a compromised page cannot spam dialogs until one is clicked by mistake. A dialog unanswered for 120 seconds counts as a cancel; it may stay on screen, and a late answer is ignored. A dialog still open 5 seconds after that (125 seconds after it opened) no longer counts as open, so it cannot block other dialogs for ever.

**The remaining window.** `writeFileAtomic` awaits a few file operations after `beforeSign` returns. A disarm in that window does not stop the write. The certificate binds the reviewed digest, so the effect is a certificate the approver authorised a moment earlier.

**POLICY CHECK** verifies the Skill under the pin's policy, without recording versions, and shows the verdict. After a successful APPROVE it should be `VERIFIED`; anything else is shown with the engine's reason. It also shows the policy's trust status.

## Manage approvers (phase 2a)

Chain: IDENTITY → TRUST ROOT → POLICY CHECK. It needs the root role, which is also the role that may *review* (the review record format is the approve one: armed key, generation, instance). The online timestamp key is never armed in this session, which is why timestamps are their own template.

**Prepare, confirm, commit.** Every root and timestamp write is two engine calls. `prepare*` reads the current document once, verifies it under the active root, applies the change and returns the exact unsigned payload (version, `issued_at`, `expires_at` included), the SHA-256 of the bytes it read and what the dialog needs; it never signs or writes. After the native dialog, `commit*` re-reads the document and refuses if its SHA-256 changed (*The document changed in the meantime. Prepare it again.*), signs exactly the prepared payload, awaits the generation and role re-check (`beforeWrite`), and writes with `writeFileAtomic(..., { expectSha256 })`, which hashes the current file immediately before the rename. The documents named in the dialog are bound at commit. The GUI also hashes the pin, trust root, revocation list, root event log and timestamp when it prepares and again in `beforeWrite`.

**The remaining window.** A process that can write the document folder can still replace the file in the instant between the last hash check and the rename. Its write is then lost, or a later write replaces it. Hosts verify every document's signature and version, so the result is never an unsigned or older-than-memory document being accepted by this computer.

**TRUST ROOT** shows the approvers (name, scopes, expiry, key id), the version and the expiry, read directly from the file under the active root (no expiry check, so an expired trust root can be renewed). It offers:

- **Add**: the public key is chosen in a native open dialog (*Choose the approver's public key (PEM)*; it counts as a dialog), then name, scopes and a lifetime (90, 180 or 365 days, default 90). A key that is already an approver is *replaced*, and the dialog says so with the old and new name, scopes and expiry. A scope `*` adds *This scope lets the approver approve every Skill*.
- **Remove**: removing the last approver asks a second native confirmation (*No approvers will remain...*).
- **Renew**: re-signs the trust root with a new expiry (180 or 365 days, default 365) and the same approvers (`root renew` in the CLI).
- **Trust root lifetime** for add and remove: *Keep* (the default while the trust root has not expired), 180 or 365 days. While the trust root has expired, *Keep* is not offered, no value is preselected, and Add and Remove stay disabled until a lifetime is picked (the engine refuses a request without one). The choice returns to *Keep* after every successful write.

**Role separation.** The trust root may not list the root key, a recovery key, the timestamp key, a key that left the root or timestamp role in the walked root events, a key that left a recovery set in them, or a revoked key. The GUI computes this list (`forbiddenApproverKeys`) and refuses an add, a remove of another approver and a renew while such a key is listed; TRUST ROOT marks it (*<why>: this approver must be removed*) and offers only Remove for it. The CLI's `root add-approver --policy FILE` computes the same list; without `--policy` it behaves as before. When the root event log cannot be walked (rollback, fork, unreadable log, revoked root), every trust-root, revocation and timestamp write is refused before any dialog (*Cannot check the root event log, so the trust root is not changed* / *The root key is revoked...*).

**Versions and memory.** `prepare*` refuses a document older than this computer's memory (*This document is older than one this computer has already seen...*); an equal version is the normal case. The new version is the document's version plus one. After a successful commit the GUI records the new version in its memory (`recordDocumentVersions`), even when the organisation's trust cannot fully load yet. A failure to record gives *The signature was made, but this computer's memory could not be updated.* The memory reset dialog says that root document writes then take the documents now on disk as their base, and the first root or timestamp signature after a reset adds *This is the first signature since this computer's memory was reset...* to its dialog.

**Consequence.** Before signing, the dialog shows what the change does to the Skills this computer can see, computed the way hosts compute verdicts: one `loadPolicyTrust`-equivalent load of the current documents (*from*), one with the prepared document substituted in memory (*to*), and, when the pin has `freshness`, a third with the timestamp check skipped (the result once a new timestamp exists). The Skill set is every discovery root, the pin's `skill_dirs` and the host policy's `skill_dirs`, plus certificates from the pin's `certificate_dirs` and each Skill's own folder. The head reads *Skills affected: N (of M)*, followed by at most 5 lines `name: from → to` sorted by name and *and K more*. In an organisation with `freshness`, every Skill is blocked until a new timestamp: each line reads `name: from → blocked until a timestamp (after the timestamp: X)`, and the dialog adds *This organisation uses timestamps: hosts in enforce mode block every Skill until a new timestamp is signed.* When the current documents do not verify, the dialog shows *The current documents do not verify: <reason>* instead and Sign stays enabled. When the documents after the change would not verify for a reason a timestamp does not fix, the dialog is not opened and the write is refused with *After signing, the documents would not verify: <reason>*. Removing the last forbidden approver makes the *to* side pass, so this never blocks that fix.

**Dialog texts** are quoted in Korean in [the design](../design/gui-admin-phase2.md#decisions-v8); the English values are in the catalog. The signing dialog's lines, in order: document, current SHA-256, version, expiry, the action lines, the key line, the consequence, the permanence line (revoke only) and the freshness line.

**Expired and previous-root states.** An expired trust root shows *The trust root has expired* and Renew first. Documents signed by a previous root key (after a rotation they were not adopted) disable every writer before any dialog: *These documents are signed by a previous root key. Move them to the new root key with root adopt in the CLI. (GUI support comes in phase 3.)*

**POLICY CHECK** shows the counts by verdict over the same Skill set, the trust note, and, in an organisation with `freshness` whose timestamp does not name the new documents, *The timestamp does not name the new documents. Run the Sign timestamp template.*

## Revoke, Refresh revocation list and Sign timestamp (phase 2b)

The engine for these is complete in phase 2a (`prepareRevocationsChange`, `commitRevocations`, `prepareTimestamp`, `commitTimestamp`, `signPrepared*`). Every signing follows *Prepare, confirm, commit* above, with the same checks in the same places: the D9 refusals, the role check, the key file and key location checks, an input snapshot taken first, the root-walk refusal, the memory minimums, the consequence, the native dialog, and `beforeWrite` repeating the checks. Dialog texts are quoted in Korean in [the design](../design/gui-admin-phase2.md#decisions-v8) (v8 S3 and v12 P6/P8); the English values are in the catalog.

**When the current documents do not verify** (the normal state after a root write in a freshness organisation, and for an expired document the write fixes), every signing dialog shows *The current documents do not verify: <reason>* and then the result under the documents as they will be after signing: *VERIFIED n · other m* and one line per other verdict. It shows no consequence head, no lines and no *and K more* line. Sign stays enabled. For a trust-root or revocation write in a freshness organisation the counts are taken with the timestamp check skipped, and the freshness line is still shown.

### Revoke

Chain: IDENTITY → TARGET → REVOKE → POLICY CHECK. Role: root.

**TARGET** offers, and REVOKE accepts, only:

- **A current approver** in the trust root (label: the approver's name).
- **A digest the armed key reviewed in this generation.** The list shows every discovered Skill (`admin:revocation-skills`: instance id, name, tree digest or the read error, and whether a review record exists for the armed key, the generation, the instance and that digest), sorted by name and then id. Choosing one that is not reviewed shows its digest and a *Review* button, which opens the same native review dialog as *Approve* (the root role may review). After that the digest is offered. The digest revoked is the reviewed digest, not the Skill's current one.
- **Another key**, chosen with *Revoke another key...*: the button only chooses this target; the public-key picker opens (it counts as a dialog) when Revoke is pressed, after the refusals, and the target is that key's id, labelled *<key id> · not a current approver*. The dialog adds *Certificates naming this key: n*, the number of certificates found in the configured folders whose `approver_key_id` is that key. Targets are not taken from certificates: a certificate names only a key id, so the GUI cannot tell that a key it names is genuine, and a planted certificate must not be able to put a key on the list. The administrator chooses the key file deliberately.

The root, the recovery keys and the timestamp key are refused (*Root, recovery and timestamp keys cannot be revoked here.*); so is a key or digest that is already revoked (*Already revoked*) and a target that is none of the three above. A former root, timestamp or recovery key that signs certificates is revocable. A revoked approver stays in the trust root; TRUST ROOT then marks it and offers Remove.

**REVOKE** takes a reason (at most 512 characters, trimmed, display-safe, at least three letters or digits) and the new list's lifetime (7 or 30 days, default 30). Its dialog quotes the document, version, expiry, the key or version being revoked, the reason, the key line, the consequence and the permanence line (*Revocation cannot be undone. Every certificate this key signed will permanently fail verification.* or *... for this version ...*). Revoking a digest **claims** the review record before the dialog; if the dialog is cancelled, or the commit is refused while the generation is unchanged, the record is restored; a successful commit consumes it. *Approve* restores its claimed record in the same way.

### Refresh revocation list

Chain: IDENTITY → REVOCATION REFRESH → POLICY CHECK. Role: root. It re-signs the revocation list with the same entries, the next version and a new expiry (7 or 30 days, default 30; `revoke refresh` in the CLI). An expired list is accepted as the base, since refreshing is how it is fixed. The dialog shows the previous expiry, and in a freshness organisation the freshness line.

### Sign timestamp

Chain: IDENTITY → TIMESTAMP → POLICY CHECK. Role: timestamp signer. It is its own template because the online timestamp key must not be armed in the offline root session. The method refuses in this order, and the first failure decides:

1. the armed key does not hold the timestamp role;
2. the pin has no `freshness` (*This organisation does not use timestamps.*; the template is disabled);
3. the root is revoked (*The root key is revoked...*);
4. the trust root has expired (*The trust root has expired. Renew it in Manage approvers first.*);
5. the revocation list has expired (*...Run Refresh revocation list first.*);
6. no lifetime among 6, 12 and 24 hours is within `max_lifetime` (*The organisation's maximum timestamp lifetime is under 6 hours. Use the CLI.*; the template is disabled);
7. `prepareTimestamp` with the memory minimums: an unreadable current timestamp gives *The current timestamp cannot be read. Sign it in the CLI with --version.*, and a document older than memory gives the stale text;
8. the documents after signing would not verify (*After signing, the documents would not verify: <reason>*).

The root event walk used is the memory-checked one (`loadPolicyRoot` with `recordVersions: false`), repeated in `beforeWrite`. The dialog shows, for the root events, the trust root and the revocation list, a counter and the SHA-256, each marked *(first seen by this computer)* when the counter is above this computer's memory. The root-event counter is the walk's last sequence number; the trust root and revocation counters are their versions. A timestamp previously signed by another key is named (*The previous timestamp was signed by another key (<id>), version <n>.*) and the version line reads `none → memory + 1`. The dialog never shows the freshness line. The lifetime choices are those of 6, 12 and 24 hours within `max_lifetime` (default: the largest); the engine refuses a lifetime above the maximum.

After a timestamp commit the GUI records the timestamp version and then root-event progress by calling `loadPolicyRoot` once with `recordVersions: true`, so the first-seen marker for root events clears. If recording fails, the result says *The signature was made, but this computer's memory could not be updated.*

**TIMESTAMP** shows the key id, version and expiry parsed from the file without any key check, whether it parses, whether the documents it names are those on disk (`loadTrustForPreview` with the timestamp check on), and the maximum lifetime.

### Common to the three

**TRUST ROOT, REVOCATIONS and the preview never write.** A preview (`loadTrustForPreview`) and a refused write leave `admin-state.json` unchanged; only reads of the pin (`pin()`) record versions, as phase 1.1 decided, and signing methods use `recordVersions: false` for their own checks.

**POLICY CHECK** is the same view as in *Manage approvers*. When the timestamp does not name the new documents it says *The timestamp does not name the new documents. Run the Sign timestamp template.*

**Limits.** The consequence is a preview (see Limits). A planted certificate cannot make a key appear in TARGET; it only changes the certificate count for a key the administrator picked.

## Replay and this computer's memory

Signed documents say what was true when they were signed; a genuine older copy still verifies. A third party who can replace the documents (a share, a mirror) could replay an older trust root, revocation list or root event log, and bring back a removed approver or a rotated-out root key.

The GUI therefore keeps its own memory of the highest versions it has seen: `<user data folder>/admin-state.json`, in the engine's host state format (`mago.host-state/v1|v2`), written only by the engine. Every read of the pin records the versions of the root event log, trust root, revocation list and (with `freshness`) timestamp it accepted, and refuses older ones as a rollback. The organisation's own `state_file` is never read or written by admin mode.

- **First run.** The folder is created with mode `0700`; the first load records whatever the documents are.
- **Corrupt memory.** A memory file that does not parse, has the wrong format or counters, is over the size limit or is not a regular file is *corrupt*: it is renamed to `admin-state.json.unreadable-<time>`, the 관리 tab shows "이 컴퓨터의 관리 기록을 읽을 수 없어서 따로 보관하고 새로 시작했어요 (<path>)" until dismissed (`admin:dismiss-memory-reset`), and loading starts again with an empty memory.
- **Unreadable memory.** Any other read error (an I/O error, a permission error, a file that changes while being read) is *unreadable*, and nothing is renamed. The whole read is retried 3 times, after 50, 100 and 200 ms; if it still fails, the pin is invalid with "이 컴퓨터의 관리 기록을 지금 읽을 수 없어요. 잠시 후 다시 시도하세요."
- **Writes record versions.** After a successful trust root, revocation list or timestamp write the GUI records the new version in the memory (`recordDocumentVersions`: merge before write; a counter is not lowered within the retry budget described under *Writes*, and the write fails closed otherwise), so the next write starts from it. Admin checks use this memory (`loadPolicyTrust` with the memory as state file), not "without recording versions". A reset says that root document writes then take the documents now on disk as their base, and the next root or timestamp signature after it shows a warning in its dialog.
- **Legitimate reset.** If an organisation is re-initialised with the same root key, versions restart and the documents look older. The tab then says "이 컴퓨터가 이미 본 것보다 오래된 문서예요. 조직이 문서를 다시 만들었다면 기록을 초기화하세요." with a 기록 초기화 button, which asks in a native dialog and renames the memory aside.
- **A memory that cannot be written** makes the pin unusable ("이 컴퓨터의 기록을 저장하지 못했어요") and drops the armed key.
- **What it protects.** Accidental replay and replay by someone who can change the documents but not this user's profile. It does not protect against the user, who can delete or move it (including with `MAGO_SKI_GUI_DATA`). With `freshness` in the pin, the timestamp bounds replay for everyone.
- **Writes.** Writes to one memory file are serialised within the process (keyed by the file's canonical path, so two spellings of one file share a queue). Across processes each write is a compare-and-swap: it reads the raw bytes once, merges, and replaces the file only if it still has those bytes; if another process changed it, the write re-reads, merges and retries, up to 5 times with 10 to 80 ms jittered waits, then fails (the pin is unusable, as for any memory that cannot be written). Only a missing file counts as no memory when writing; any other read error fails the write.
- **Known limit.** The retry budget can run out under sustained contention from other processes; the write then fails rather than lowering a recorded version. Within one process, an unqueued status poll that overlaps a load while the root event log grows can report a transient rollback.

## Process boundaries

The window is sandboxed as before (context isolation, no Node integration, CSP `default-src 'none'; script-src 'self'; style-src 'self'`). Phase 1 adds these IPC calls; each checks that the call comes from the app's own page:

| Call | Arguments | Effect |
|---|---|---|
| `admin:status` | none | The pin's state and the armed role (never key material) |
| `admin:arm` | none | Opens the key dialog in the main process (refused like any dialog); returns the role or why it failed |
| `admin:disarm` | none | Drops the armed key at once (synchronous; ends any operation in progress) |
| `admin:inspect` | instance id | The INSPECT view of that Skill's current version |
| `admin:review` | instance id | Opens the native review dialog; records the review only if the human answers 검토함 |
| `admin:approve` | instance id, digest, lifetime, reason | Opens the native signing dialog and signs only after it is confirmed, if the digest is the recorded reviewed digest and the role re-check passes |
| `admin:check` | instance id | POLICY CHECK for that Skill |
| `admin:reset-memory` | none | Opens a native confirmation, then moves this computer's admin memory aside, drops an armed key; a refusal returns its message; `ok` means "not refused", so a cancel is `ok: true` |
| `admin:dismiss-memory-reset` | none | Clears the notice that the memory was moved aside |
| `admin:trust-root` | none | The TRUST ROOT view (unqueued; does not extend the idle time) |
| `admin:add-approver` | `{ name ≤ 128, scopes (1 to 64, each valid per the engine's scope rules), lifetime: 90d \| 180d \| 365d, trustRootLifetime?: 180d \| 365d }` | Opens the public-key picker, then the native signing dialog; writes the trust root only after it is confirmed |
| `admin:remove-approver` | `{ keyId, trustRootLifetime? }` | The same, for a removal (a second dialog for the last approver) |
| `admin:renew-trust-root` | `{ lifetime: 180d \| 365d }` | The same, for a renewal |
| `admin:verify-all` | none | POLICY CHECK over every Skill (unqueued) |
| `admin:revocations` | none | The revocation list view (unqueued) |
| `admin:revocation-skills` | none | The discovered Skills for TARGET: instance id, name, digest or error, reviewed (unqueued) |
| `admin:revocation-targets` | none | The targets REVOKE accepts: current approvers and reviewed digests (unqueued) |
| `admin:revoke` | `{ target: { kind: 'key', keyId } \| { kind: 'digest', digest, instanceId } \| { kind: 'other' }, reason ≤ 4096 raw, lifetime: 7d \| 30d }` | Opens the native signing dialog (and, for `other`, the public-key picker first); writes the revocation list only after it is confirmed |
| `admin:refresh-revocations` | `{ lifetime: 7d \| 30d }` | The same, for a refresh |
| `admin:timestamp` | none | The TIMESTAMP view (unqueued) |
| `admin:sign-timestamp` | `{ lifetime: 6h \| 12h \| 24h }` | The same, for a timestamp; needs the timestamp role |

The renderer cannot name a file, a key or a directory in any of them. A compromised renderer cannot cause a signature without both native dialogs being answered by a human: it can ask for them, and after a cancel or a timeout it is refused for 10 seconds.

## Limits

- **A compromised machine sees an armed key.** Same-user malware can read the main process's memory while a key is armed. Arm keys briefly; never arm the root key on a machine used for everyday work.
- **The pin's protection is file ownership.** Anyone with root on the machine can replace the pin, as they can replace the host policy.
- **Pi with a user-writable policy stays user-trusted.** The pin protects the GUI's notion of the organisation, not a Pi host whose own policy the employee controls; point Pi at the pin (`MAGO_SKI_POLICY`) or use the [gate](../hosts/adapter-interface.md).
- **Key holders can always use the CLI.** The GUI's dialogs and checks bind the GUI, not the key: whoever holds an approver key can sign with `mago-ski approve`. Authority is cryptographic.
- **The user-namespace check is a hurdle**, not a boundary (see [Organisation pin](#organisation-pin)); Flatpak, rootless containers and user-namespace CI runners are unsupported.
- **A copy or hard link of the key inside a Skill is not detected.** A moved key fails the stored-path check at signing. The private-key scan at signing covers the files the digest covers, as in the CLI.
- **The memory does not protect against the user** (see above).
- **Retired keys are known only from walked events.** A key retired before `root_events_after` is not known to a host or to the GUI. The host check refuses a trust root that lists a key retired in the events the host walked (`trust root lists approver <id>, which has held the root or timestamp role; a key that left those roles never takes another`); the gate's trust store (`src/gate/trust-store.ts`) calls `loadTrustContext` directly and does not check this.
- **Former recovery keys.** The GUI and `root add-approver --policy` refuse a key that left a recovery set in the walked events as an approver; hosts do not check this. For former recovery keys, no host refuses a document it accepted before. While a former recovery key is listed as an approver, the GUI marks it and allows only removing it, hosts keep accepting the trust root, and `root renew` and `root remove-approver` in the CLI do not check it.
- **Upgrade note for retired keys.** The host check for retired root and timestamp keys is the one deliberate exception to "no host refuses a document it accepted before":

> Before upgrading hosts, open the TRUST ROOT view in a GUI of the new version: it marks any approver whose key has held the root or timestamp role. Remove those approvers (`mago-ski root remove-approver`), and in an organisation that uses timestamps, sign a new timestamp afterwards (`mago-ski timestamp sign`). In an organisation that uses timestamps, remove the approvers and sign the new timestamp in one sitting: between the two, hosts block every Skill. Hosts that use `loadPolicyTrust` (the CLI, Pi, the GitHub Action and the gate's verifier) refuse a trust root that still lists such an approver, and in enforce mode block every Skill. The gate's trust store does not check this.
- **The consequence is a preview.** The consequence shown before signing is computed when the change is prepared, from the Skill folders and certificates found then, and with this computer's memory as the version minimums. A host with its own newer state, or with other certificate folders, can report different verdicts. Only the documents named in the dialog are bound at commit.
- **No hardware keys yet.** Keys are PEM files, as for the CLI.

## Phases

1. This document; the organisation pin; IDENTITY; the template framework; *Approve a Skill version*.
2. **2a:** the engine for every root and timestamp write (prepare, commit, `root renew`, `root add-approver --policy`, retired-key host check), these spec changes, and *Manage approvers*. **2b:** *Revoke*, *Refresh revocation list*, *Sign timestamp* (GUI only; the engine is complete in 2a; built).
3. *Set up an organisation*, *Root incident*.
