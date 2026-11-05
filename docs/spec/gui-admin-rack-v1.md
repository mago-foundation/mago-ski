# GUI administration rack v1

Status: **draft.** Phases 1 to 3 are specified here; none is implemented yet. Phase 1 is the organisation pin, identity, the template framework and the *Approve a Skill version* template. The CLI stays the reference for every operation: each device calls the same engine functions as the CLI command it names.

The [GUI](../../gui/README.md) began as a read-only companion: it showed how installed Skills change and what the host policy decides, and never signed anything. This document adds an **administration rack**, so approvers and administrators can do in the GUI everything they can do with the CLI, in fixed chains of devices (templates), next to the observation rack.

## Principles

1. **Authority is cryptographic.** What an approver or administrator can do is decided by the private keys they hold and by the signed trust documents, exactly as for the CLI. Hosts accept a certificate, trust root, revocation list or root event only if its signature verifies against the organisation's root. The GUI recognising a role is guidance and a safety interlock, never a source of authority: a modified GUI that shows an employee the root devices still cannot produce a document any host accepts.
2. **The organisation is identified by an admin-owned pin**, never by a file the person at the keyboard can edit (see [Organisation pin](#organisation-pin)).
3. **Fixed templates, not free patching.** The order of operations is part of a procedure (inspect before approving, check the policy after changing it). Each template is a fixed chain; devices cannot be reordered, skipped or added. This follows the ontology's rule that editing "must not allow arbitrary execution ordering that breaks mandatory gates" ([ontology §24.2](../mago-ski-ontology.md)).
4. **Enforcement is untouched.** The observation rack's APPROVAL GATE stays a locked device. Nothing in the administration rack changes what a host blocks except through signed documents, which hosts verify as before.
5. **Every signature binds what was shown.** A certificate is signed only for the exact digest the INSPECT device showed (`approve --expect-digest`); a changed Skill must be inspected again.

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
- it loads as a valid policy.

Otherwise admin roles are not recognised, and the administration rack says which rule failed and how to install the pin. Its documents (`trust_root`, `revocations`, `root_events`, `freshness.timestamp`) may live anywhere, because they are signed: a forged or swapped document fails verification against the pinned root.

**Why a separate location.** The Pi host reads `$MAGO_SKI_POLICY` or `~/.mago-ski/policy.json`, which the user can edit. An employee who writes their own policy pinning their own key would be, to a GUI reading that file, the root of an organisation of their own. A root-owned pin removes that. A deployment that wants the employee's Pi to follow the same organisation sets `MAGO_SKI_POLICY=/etc/mago-ski/policy.json` for them. The GUI's observation rack keeps reading the policy Pi reads; when that differs from the pin, the administration rack says so.

The pin is read without recording versions: admin mode never writes host state (`state_file`) or the decision log.

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

**Armed key lifetime.** The key object stays in the main process's memory only. It is never written to disk, logged, put on the clipboard or sent to the renderer. It is dropped when the user ejects it, when the template is closed or changed, after 15 minutes without an operation, when the pin changes, and when the app quits. The bytes read from the file are zeroed after parsing.

**Re-check before every signature.** Immediately before signing, the main process recomputes the role from the current documents. An approver removed or revoked since arming cannot sign.

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

The approver confirms *"I reviewed exactly this version"*, which records the digest shown, in the main process, as the inspected digest of that Skill. If the Skill's bytes change afterwards, the confirmation is void.

**APPROVE** takes the inspected digest. It shows the Skill name the certificate will carry (from `SKILL.md`, as `approve` does) and refuses to run if the approver's scopes do not cover that name. The approver picks a lifetime (30, 90 or 180 days, never past the approver key's own expiry) and writes a reason (required, at most 1024 characters, plain text). The main process re-checks the role, then calls the engine's `approveSkill` with `expectDigest` set to the inspected digest, so a Skill that changed since INSPECT is refused. The certificate is written where `approve` writes it by default: `<Skill>/.mago-ski-cert.json`, or `<first certificate_dirs entry>/<name>.cert.json` when the pin's policy has `certificate_dirs`. The device shows the certificate id and path.

**POLICY CHECK** verifies the Skill under the pin's policy, without recording versions, and shows the verdict. After a successful APPROVE it should be `VERIFIED`; anything else is shown with the engine's reason. It also shows the policy's trust status.

## Process boundaries

The window is sandboxed as before (context isolation, no Node integration, CSP `default-src 'none'; script-src 'self'; style-src 'self'`). Phase 1 adds these IPC calls; each checks that the call comes from the app's own page:

| Call | Arguments | Effect |
|---|---|---|
| `admin:status` | none | The pin's state and the armed role (never key material) |
| `admin:arm` | none | Opens the key dialog in the main process; returns the role or why it failed |
| `admin:disarm` | none | Drops the armed key |
| `admin:inspect` | instance id | The INSPECT view of that Skill's current version |
| `admin:confirm-inspected` | instance id, digest | Records the digest as inspected if it is still the current one |
| `admin:approve` | instance id, digest, lifetime, reason | Signs, only if the digest is the recorded inspected digest and the role re-check passes |
| `admin:check` | instance id | POLICY CHECK for that Skill |

The renderer cannot name a file, a key or a directory in any of them. A compromised renderer could, at worst, ask for a certificate on the version of a discovered Skill that the approver already confirmed as inspected, with a reason of its choosing, while a key is armed.

## Limits

- **A compromised machine sees an armed key.** Same-user malware can read the main process's memory while a key is armed. Arm keys briefly; never arm the root key on a machine used for everyday work.
- **The pin's protection is file ownership.** Anyone with root on the machine can replace the pin, as they can replace the host policy.
- **Pi with a user-writable policy stays user-trusted.** The pin protects the GUI's notion of the organisation, not a Pi host whose own policy the employee controls; point Pi at the pin (`MAGO_SKI_POLICY`) or use the [gate](../hosts/adapter-interface.md).
- **No hardware keys yet.** Keys are PEM files, as for the CLI.

## Phases

1. This document; the organisation pin; IDENTITY; the template framework; *Approve a Skill version*.
2. *Manage approvers*, *Revoke*, *Publish*.
3. *Set up an organisation*, *Root incident*.
