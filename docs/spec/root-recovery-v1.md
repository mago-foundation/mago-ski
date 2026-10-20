# Root recovery v1

Status: **proposal, not implemented.** Nothing in mago-ski 0.1 reads the fields or documents described here. Once implemented, this page becomes normative and the changes listed under [Changes to other documents](#changes-to-other-documents) are applied.

In v1, every host trusts one pinned root key and nothing above it. If the root private key leaks, whoever holds the copy can sign trust roots and revocation lists that every host accepts, and the only remedy is to edit the policy on every host by hand ([threat model](../threat-model.md)).

This proposal adds a **recovery set**: a few keys, held by different people and kept offline, that hosts pin in advance. The recovery set cannot approve Skills or sign trust roots. It can do exactly two things, both recorded as signed, numbered **root events**:

- **revoke**: stop hosts trusting the current root key. A small number of recovery keys is enough (by default one), so any single trustee can stop the damage quickly. The worst a stolen recovery key can do with this is make hosts block everything until a rotation (an outage, never a takeover).
- **rotate**: replace the root key, and optionally the recovery set or the timestamp key. This needs a larger number of recovery keys (for example two of three), plus signatures from the new keys.

Two further rules make a revocation hard to escape:

- **A revoked root blocks in every mode**, shadow mode included, and is reported once per host rather than once per Skill. See [Revoked root](#revoked-root-blocked-in-every-mode).
- **Freshness (optional, recommended):** a separate, automated key re-signs a short-lived timestamp of the current documents. A host that is fed old files stops trusting anything within a day, instead of never noticing. See [Freshness](#freshness).

The design follows [TUF](https://theupdateframework.io/)'s root and timestamp roles. See [Rationale](#rationale-tuf-and-keri) for why this was chosen over a KERI-style pre-rotated successor.

## Roles

| Key | Signs | Used | Hosts know it from |
|---|---|---|---|
| Recovery keys (1-16) | Root events only | Only in an incident or a planned rotation | Their fingerprints in the host policy |
| Root key | Trust root and revocation list | Every 30 days or so (revocation list refresh) | `root_fingerprint` in the policy, then rotate events |
| Timestamp key (optional) | Timestamps only | Automatically, every few hours | `freshness.key_id` in the policy, then rotate events |
| Approver keys | Skill certificates | Every approval | The trust root |

No key may hold two roles. A recovery key must not be the root key, the timestamp key or an approver; the timestamp key must not be the root key or an approver; and the root key must not be an approver (as in v1).

## How a recovery works

Example organization: root key `R0`; recovery keys `A`, `B`, `C` held by three people; rotation needs 2 of them, revocation needs 1; timestamp key `T` used by an automated job.

1. **Setup.** Every host's policy pins `R0`, the fingerprints of `A`, `B` and `C`, and `T`. The organization publishes an empty root event log next to the trust root, and the job re-signs a 24-hour timestamp every 6 hours.
2. **Leak.** `R0`'s private key turns up in a public CI log.
3. **Revoke (minutes).** Trustee A signs event 1, `revoke R0`, and appends it to the log. Each host that reads the new log blocks every Skill, in shadow mode too, and shows one alarm. A host the thief can feed old files does not see event 1, but its timestamp expires within 24 hours, after which it trusts nothing.
4. **Rotate (hours).** The organization creates a new root key `R1`. Trustees A and B sign event 2, `rotate R0 -> R1`, keeping the same recovery set and timestamp key, and `R1` signs it too. `R1` then signs a trust root and a revocation list, listing the same approvers as before.
5. **Back to normal.** Hosts read event 2, trust `R1`, and accept its documents. Existing certificates keep verifying: they are signed by approver keys and do not name the root. No host policy was edited.

The thief, holding only `R0`, cannot undo event 1 or produce event 2: both need recovery keys.

## Host policy v2

A policy that uses recovery declares `mago.policy/v2`. A v2 host accepts v1 policies unchanged; they have no recovery set and behave exactly as today.

```json
{
  "policy_version": "mago.policy/v2",
  "mode": "enforce",
  "root_fingerprint": "sha256:<root key id at setup>",
  "recovery": {
    "key_ids": ["sha256:<A>", "sha256:<B>", "sha256:<C>"],
    "rotate_threshold": 2,
    "revoke_threshold": 1
  },
  "root_events": "root-events.json",
  "freshness": {
    "timestamp": "timestamp.json",
    "key_id": "sha256:<T>",
    "max_lifetime": "24h"
  },
  "trust_root": "trust-root.json",
  "revocations": "revocations.json",
  "state_file": "state.json"
}
```

| Field | Required | Meaning |
|---|---|---|
| `root_fingerprint` | yes | The root key trusted before any root event. It does not change after a rotation |
| `recovery` | no | The recovery set trusted before any root event. When absent, the policy behaves as v1, and `root_events` and `freshness` must be absent too |
| `recovery.key_ids` | yes | Fingerprints of the recovery keys: sorted, unique, 1-16, none equal to `root_fingerprint` |
| `recovery.rotate_threshold` | yes | Recovery signatures a rotate event needs: `1 <= revoke_threshold <= rotate_threshold <= len(key_ids)` |
| `recovery.revoke_threshold` | yes | Recovery signatures a revoke event needs |
| `root_events` | with `recovery` | The root event log. Required when `recovery` is present, and the file must exist: an organization with no events publishes an empty log. A missing file is `UNVERIFIABLE`, so deleting it cannot hide a revocation |
| `root_events_after` | no | How many events `root_fingerprint`, `recovery` and `freshness.key_id` already reflect (default 0). A host set up after a rotation pins the current keys and this number, and starts walking at the next event. A log with fewer events than this is `UNVERIFIABLE` |
| `freshness` | no | Turns on the [freshness](#freshness) check. Requires `recovery`, so that a leaked timestamp key can be replaced |
| `freshness.timestamp` | yes | The timestamp file. It must exist |
| `freshness.key_id` | yes | The timestamp key trusted before any root event. Not `root_fingerprint` and not in `recovery.key_ids` |
| `freshness.max_lifetime` | no | The longest timestamp lifetime hosts accept, as a duration such as `24h` (default `24h`, at most `7d`). It caps the damage a leaked timestamp key can do by signing long-lived timestamps |

Only fingerprints are pinned. A key's public half is revealed in the first event or timestamp it signs, and must hash to its fingerprint.

## Root event log

Canonical JSON, not signed as a whole (each event is signed):

```json
{"events":[{"payload":"<base64>","payloadType":"application/vnd.mago-ski.root-event+json","signatures":[{"keyid":"sha256:<A>","sig":"<base64>"}]}],"type":"mago.root-events/v1"}
```

- `events`: DSSE envelope objects in order. The event at index `i` has `sequence` `i + 1`.
- The log only grows. An organization never removes or rewrites an event, even an unwanted one (see [Rollback and forks](#rollback-and-forks)).
- At most 256 events; the file is at most 4 MiB.

## Root events

Envelopes are DSSE, as for [certificates](skill-certificate-v1.md), with one difference: a root event carries **one signature per signer** instead of exactly one. Signatures are sorted by `keyid`, unique, and every one must be valid; an envelope with an unknown or invalid signature is rejected even if enough valid ones remain.

`payloadType`: `application/vnd.mago-ski.root-event+json`

### Revoke

```json
{
  "type": "mago.root-event/v1",
  "sequence": 1,
  "action": "revoke",
  "root_key_id": "sha256:<R0>",
  "issued_at": "2026-11-02T09:00:00Z",
  "reason": "root.pem appeared in a public CI log",
  "signers": [
    { "key_id": "sha256:<A>", "public_key": "<base64 DER SPKI>" }
  ]
}
```

### Rotate

```json
{
  "type": "mago.root-event/v1",
  "sequence": 2,
  "action": "rotate",
  "root_key_id": "sha256:<R0>",
  "issued_at": "2026-11-02T15:30:00Z",
  "reason": "replace leaked root",
  "new_root": { "key_id": "sha256:<R1>", "public_key": "<base64 DER SPKI>" },
  "new_recovery": {
    "key_ids": ["sha256:<A>", "sha256:<B>", "sha256:<C>"],
    "rotate_threshold": 2,
    "revoke_threshold": 1
  },
  "signers": [
    { "key_id": "sha256:<A>", "public_key": "<base64 DER SPKI>" },
    { "key_id": "sha256:<B>", "public_key": "<base64 DER SPKI>" }
  ]
}
```

### Fields

| Field | Meaning |
|---|---|
| `sequence` | Position in the log, starting at 1, with no gaps |
| `action` | `revoke` or `rotate` |
| `root_key_id` | The root key the host trusts just before this event (see [Host processing](#host-processing)). A revoke names the key it revokes; a rotate names the key it replaces |
| `issued_at` | UTC timestamp. Not more than 5 minutes in the future, and not earlier than the previous event's `issued_at` |
| `reason` | Non-empty text, at most 1024 characters, no control characters. Shown in verdict reasons |
| `signers` | The recovery keys that sign: sorted by `key_id`, unique. Each `public_key` must hash to its `key_id` |
| `new_root` | Rotate only. The new root key; `public_key` must hash to `key_id` |
| `new_recovery` | Rotate only. The recovery set trusted after this event, with the same rules as the policy's `recovery`. It may equal the current set |
| `new_timestamp` | Rotate only, optional. A new timestamp key, `{ "key_id", "public_key" }`. When absent, the timestamp key does not change. Hosts without `freshness` check the field and its signature but otherwise ignore it |

### Who must sign

Let *current set* be the recovery set in force just before the event.

| Action | Signatures required |
|---|---|
| `revoke` | At least `revoke_threshold` keys of the current set |
| `rotate` | At least `rotate_threshold` keys of the current set, **and** at least the new `rotate_threshold` keys of `new_recovery`, **and** `new_root`, **and** `new_timestamp` if present |

- A key in both sets counts toward both thresholds, so a rotate that keeps the same set needs no extra recovery signatures.
- Every key in `signers` must belong to the current set or to `new_recovery`. The envelope's signatures are exactly the `signers`, plus `new_root` and `new_timestamp` for a rotate.
- The signatures from new keys prove that those keys exist and are held. A typo in a fingerprint cannot leave the organization with a recovery set nobody can use, or a root or timestamp key nobody can sign with. This is TUF's rule that new root metadata is signed by both the old and the new root keys.

### Rules for a rotate

- `new_root.key_id` must not be in the current recovery set or in `new_recovery`.
- `new_root.key_id` must not be any key that an earlier event revoked or replaced. A key that has left the root role never returns.
- `new_root.key_id` may equal `root_key_id` only if that key is not revoked. This changes the recovery set or the timestamp key without changing the root (for example, when a trustee leaves or the timestamp key leaks).
- `new_timestamp.key_id` must not be the current or new root key, must not be in the current or new recovery set, and must not be a timestamp key that an earlier event replaced.

### Rules for a revoke

- The key named in `root_key_id` must not already be revoked.
- After a revoke, the next event, if any, must be a rotate naming the same `root_key_id`.

## Freshness

Optional, turned on per policy with `freshness`, and recommended for hosts in enforce mode.

Without it, a host acts on whatever files reach it. Someone who controls how files reach a host (a sync job, a mirror, a network path) can keep feeding it an old log that lacks a revoke. If they also hold the leaked root key, they can keep signing fresh trust roots for it indefinitely. Freshness closes this gap: a separate **timestamp key**, used by an automated job, regularly signs a short-lived statement of exactly which files are current. A host rejects files that do not match a timestamp that is still valid.

### Timestamp document

A DSSE envelope with exactly one signature, by the timestamp key.

`payloadType`: `application/vnd.mago-ski.timestamp+json`

```json
{
  "type": "mago.timestamp/v1",
  "version": 412,
  "issued_at": "2026-11-02T06:00:00Z",
  "expires_at": "2026-11-03T06:00:00Z",
  "timestamp_key": { "key_id": "sha256:<T>", "public_key": "<base64 DER SPKI>" },
  "root_events": { "sha256": "<64 hex>", "count": 2 },
  "trust_root": { "sha256": "<64 hex>", "version": 7 },
  "revocations": { "sha256": "<64 hex>", "version": 31 }
}
```

| Field | Meaning |
|---|---|
| `version` | Positive integer, increased with every timestamp |
| `issued_at` | Not more than 5 minutes in the future |
| `expires_at` | Later than `issued_at`, at most `max_lifetime` after it, and later than the host's current time |
| `timestamp_key` | Must be the active timestamp key (below); `public_key` must hash to `key_id`, which must equal the envelope's `keyid` |
| `root_events` | SHA-256 of the root event log file's bytes, and its number of events |
| `trust_root`, `revocations` | SHA-256 of each document file's bytes, and the `version` inside it |

### What a host checks

The *active timestamp key* is `freshness.key_id`, replaced by each rotate event that carries `new_timestamp`. A host:

- reads each file once, and hashes and parses the same bytes;
- verifies the timestamp's signature with the active timestamp key;
- checks the times above and that `version` is not lower than the host state records;
- checks that the three digests, the event count and the two versions match the files it read.

Any failure is `UNVERIFIABLE`, and follows the configured mode (see [Reporting trust failures](#reporting-trust-failures-once)).

### What it guarantees

- **A frozen host stops trusting.** A host that is fed old files rejects them once the newest timestamp naming them expires: at most `max_lifetime` (24 hours by default). It then trusts nothing until it receives current files.
- **A leaked root key alone does not reach freshness-checking hosts.** The timestamp names exact file digests, so a trust root signed with a leaked root key is accepted only if it has been published at the place the timestamp job reads from. Someone who can only tamper with the files on their way to a host cannot get it accepted.
- **A leaked timestamp key alone forges nothing.** It cannot sign events or trust documents. Combined with control over delivery to a host, it can keep that host on the documents it already has; see [What each leak allows](#what-each-leak-allows).

The longest time a revoked approver key or digest can still pass also drops, from the revocation list's lifetime (30 days by default) to `max_lifetime`.

### Publishing

- The timestamp job runs every 6 hours with a 24-hour lifetime. If it stalls, hosts start failing 18 hours after its first missed run, which leaves time to notice and fix it.
- It reads the published files, hashes them, and signs. It publishes the timestamp together with any new documents: write everything to a new directory, then switch to it in one step. A host that reads mid-update sees a mismatch, which is `UNVERIFIABLE` until its next load.
- The timestamp key is online, so treat it as the key most likely to leak. Keep it in a different system from the root key, never in the same CI secret store.

## Host processing

### Walking the log

At every trust check, before reading the trust root, a host with a v2 recovery policy:

1. Starts from the policy: *active root* = `root_fingerprint`, *recovery set* = `recovery`, *timestamp key* = `freshness.key_id`, *revoked* = false.
2. Reads `root_events`. A missing, malformed or oversized log is `UNVERIFIABLE`.
3. For each event after the first `root_events_after`, in order, checks every rule above against the current state, then applies it:
   - revoke: *revoked* = true.
   - rotate: *active root* = `new_root.key_id`, *recovery set* = `new_recovery`, *timestamp key* = `new_timestamp.key_id` if present, *revoked* = false.
4. Any event that breaks a rule makes the whole log `UNVERIFIABLE`. The host does not skip it or stop early with the events before it.

Walking the full log keeps hosts without state correct, but hosts load trust documents often: the Pi host does so before every agent run and on every tool call that re-verifies a Skill. A worst-case log (256 events of 34 signatures) costs about 8,700 signature checks per walk, over a second on a laptop. So a host caches each **successful** walk, keyed by the policy's starting point (`root_fingerprint`, `recovery`, `freshness.key_id`, `root_events_after`) and the log's SHA-256, and walks again only when one of them changes. An unchanged log then costs one SHA-256 over at most 4 MiB. Failed walks are not cached, because an event that is too far in the future now may be valid later. The rollback and fork checks below run on every load; they only compare a number and a digest.

### Order of checks

1. Walk the root event log. Otherwise `UNVERIFIABLE`.
2. Check rollback and forks against the host state. Otherwise `UNVERIFIABLE`.
3. If the active root is revoked, every Skill is blocked: see [Revoked root](#revoked-root-blocked-in-every-mode). Nothing else is read.
4. With `freshness`, check the timestamp against the files. Otherwise `UNVERIFIABLE`.
5. Check the trust root and the revocation list as in v1, except that they must be signed by the **active root** instead of `root_fingerprint`. The trust root is also `UNVERIFIABLE` if any approver's key is in the active recovery set or is the active timestamp key.
6. Record the new state.

### Revoked root: blocked in every mode

When the active root is revoked:

- Every Skill is blocked, in **both `enforce` and `shadow` mode**. No policy setting changes this.
- The reason names the event, for example `root key sha256:... was revoked by root event 1 (root.pem appeared in a public CI log); waiting for a rotation`.
- The only way back is a rotate event. Switching the policy to shadow mode does not help.

Shadow mode means "approvals may be incomplete, so observe instead of blocking". It assumes the trust anchor is sound. A revoke is a signed statement by the organization's trustees that the anchor is not, so observing is no longer a safe choice. Making the block independent of the mode also removes the tempting shortcut during the outage, "switch to shadow so people can work", which would let through anything the leaked key signed.

Only a revoke, a signed and deliberate statement, overrides the mode. Failures that might have an innocent cause (an unreadable log, an expired timestamp from a stalled job) follow the configured mode.

### Reporting trust failures once

A failure in the trust documents affects every Skill at once. Reporting it once per Skill would bury it among dozens of identical warnings, along with any Skill a thief has planted. So hosts report these failures **once per host**:

| Failure | Event name | Enforce mode | Shadow mode |
|---|---|---|---|
| The active root is revoked | `root-revoked` | block | **block** |
| Root event log missing or invalid, rollback, fork | `trust-unavailable` | block | would-block |
| Timestamp missing, invalid, expired or not matching the files | `trust-unavailable` | block | would-block |
| Trust root or revocation list invalid or expired (as in v1) | `trust-unavailable` | block | would-block |

While such a failure lasts:

- **Pi host:** one notice when it starts or changes, and the status bar shows it (for example `mago-ski: ROOT KEY REVOKED - all Skills blocked`). `root-revoked` is always an error, whatever the mode. No per-Skill notices are shown.
- **Decision log:** one record when it starts or changes. It carries the event name, empty `skill` and `skill_dir`, null `digest` and `certificate_id`, verdict `UNVERIFIABLE`, the action from the table and the reason. No per-Skill records are written.
- **CLI** (`verify`, `verify-all`, `policy check`): prints the failure once and exits non-zero.
- **GitHub Action:** one summary line and no per-Skill rows. It fails the check on `root-revoked` in both modes; on `trust-unavailable` it follows the mode.

### Rollback and forks

Host state version 2:

```json
{
  "type": "mago.host-state/v2",
  "roots": { "sha256:<R1>": { "trust_root_version": 1, "revocations_version": 1 } },
  "root_events": { "sha256:<R0>": { "sequence": 2, "event_digest": "sha256:<hex>" } },
  "timestamps": { "sha256:<T>": { "version": 412 } }
}
```

(Written as canonical JSON; shown indented here.)

- `root_events` has one entry per pinned `root_fingerprint`. `event_digest` is `sha256:` + the hex SHA-256 of the last applied event's envelope, serialized as canonical JSON with its trailing LF.
- **Rollback:** if the log has fewer events than the recorded `sequence`, it is `UNVERIFIABLE`. This stops a host from being moved back to a log without the revoke.
- **Fork:** if the event at the recorded `sequence` has a different digest, it is `UNVERIFIABLE`. Two valid but different events with the same number mean that two trustees prepared events at the same time, or that recovery keys were misused. Hosts fail closed until people sort it out. To avoid the honest case, trustees always prepare events against the published log, never a private copy.
- **Versions are per key.** `roots` is keyed by the root key that signed the documents, as in v1, and `timestamps` by the timestamp key. A new key starts its own count, so a thief who signed a document with a huge `version` using a leaked key cannot lock out its successor.
- Hosts without a state file (the GitHub Action) still walk and check the log and the timestamp, but have no rollback or fork protection, as for v1 documents. The Action reads them from the protected base revision.

An unwanted but valid event, such as a revoke signed with a stolen recovery key, is not rewritten. The organization appends a rotate after it. Because a revoke only removes trust, keeping it in the log is harmless.

## What each leak allows

With `k` = `rotate_threshold` and `r` = `revoke_threshold`:

| Leaked | The thief can | The organization |
|---|---|---|
| The root key | Sign trust roots and revocation lists. Freshness-checking hosts accept them only if the thief can also publish at the place the timestamp job reads; other hosts accept them until they read a revoke | Any `r` trustees revoke; `k` trustees rotate |
| The timestamp key | Nothing by itself. With control over delivery to a host: keep that host on the documents it already has, by re-signing timestamps for them | `k` trustees rotate with `new_timestamp`; hosts that receive the log directly pick it up at once |
| The root key and the timestamp key | As the root key on a host without freshness | Revoke, then rotate both keys |
| Fewer than `r` recovery keys | Nothing | Optionally rotates to a recovery set without the leaked keys |
| `r` to `k - 1` recovery keys | Revoke the active root: an outage, not a takeover | `k` other trustees rotate, dropping the leaked keys from the set |
| The root key and fewer than `k` recovery keys | Both of the above | Revokes, then rotates to a new root and a set without the leaked keys |
| `k` or more recovery keys | Rotate to a root of their choosing: a takeover | Out of scope. Pin new keys on every host by hand |

A revocation, like a revocation list, reaches a host only when the host reads the new log. With freshness, a host that is fed old files stops trusting anything once its last timestamp expires, unless whoever feeds it also holds the timestamp key. Without freshness, a thief who holds the root key and controls delivery can keep a host on the old log indefinitely.

## Limits

| Item | Limit |
|---|---|
| Recovery keys per set | 16 |
| Events per log | 256 |
| Log file size | 4 MiB |
| Signatures per event | 34 (16 current + 16 new recovery keys + the new root + the new timestamp key) |
| `reason` | 1024 characters |
| Timestamp file size | 64 KiB |
| `max_lifetime` | 7 days |

## Recommended setups

| Organization | Recovery set | Why |
|---|---|---|
| Team or company | 3 keys, `rotate_threshold` 2, `revoke_threshold` 1, held by three people | Any one person can stop trust quickly; no single stolen or lost key prevents recovery or allows a takeover |
| One maintainer | 3 keys, `rotate_threshold` 2, `revoke_threshold` 1, stored in three places (for example a home safe, a bank box, a trusted person) | Same properties with one person. A 1-of-1 set is allowed but makes the single recovery key as powerful as the root |

Recovery private keys never sit next to `root.pem`, never in CI, and are used only to sign root events. Each trustee also keeps a printed copy of their key's fingerprint, so a signed event can be checked by eye.

For freshness, run the timestamp job every 6 hours with a 24-hour lifetime, and keep the timestamp key in a different system from the root key.

## Commands (informative)

Proposed CLI shape; names may change during implementation. Rotations need several trustees who may be in different places, so signing is split into *prepare*, *sign* and *append*, like a TUF root signing ceremony:

```
mago-ski recovery init --public-key a.pub --public-key b.pub --public-key c.pub \
    --rotate-threshold 2 --revoke-threshold 1          # prints the policy "recovery" block
mago-ski root-events init --out root-events.json       # empty log

# Revoke: one trustee is enough with revoke_threshold 1
mago-ski root-events prepare-revoke --events root-events.json --reason TEXT --out proposal.json
mago-ski root-events sign proposal.json --key a.pem
mago-ski root-events append proposal.json --events root-events.json

# Rotate: the new root and two trustees sign the same proposal
mago-ski root-events prepare-rotate --events root-events.json --new-root-public r1.pub \
    [--new-recovery-public KEY.pub ... --rotate-threshold N --revoke-threshold N] \
    [--new-timestamp-public t2.pub] --reason TEXT --out proposal.json
mago-ski root-events sign proposal.json --key r1.pem
mago-ski root-events sign proposal.json --key a.pem
mago-ski root-events sign proposal.json --key b.pem
mago-ski root-events append proposal.json --events root-events.json

# Freshness: run by the timestamp job every 6 hours
mago-ski timestamp sign --policy policy.json --key timestamp.pem --expires 24h
```

`append` checks every rule a host would check, so a log that `append` accepts is a log hosts accept. `timestamp sign` reads the files the policy names, signs their digests with the next `version`, and writes the policy's `freshness.timestamp` file.

Before rolling a v2 policy out to hosts, or after appending an event, the organization checks it the way a host would:

```
mago-ski policy check --policy policy.json
```

`policy check` loads the policy, walks the root event log, checks the timestamp if `freshness` is set, verifies that the trust root and revocation list are signed by the active root and that no approver holds another role, and prints the active keys and both thresholds. It exits non-zero on any problem, so it can gate the rollout.

## Changes to other documents

When this is implemented:

- **[Trust documents](trust-documents-v1.md):** the root-key line under *Key rotation* points here. The host policy and host state sections gain the v2 fields. The decision log section gains the `root-revoked` and `trust-unavailable` records.
- **[Verification](verification.md):** *Order of checks* starts with the steps in [Order of checks](#order-of-checks) above, and step 1 checks against the active root instead of the pinned fingerprint. The note on shadow mode gains the revoked-root exception.
- **[Pi host](../hosts/pi.md):** the *What it does* table gains a row for a revoked root (blocked in both modes), and the notification text describes the single report for trust failures.
- **[GitHub Action](../hosts/github-action.md):** a revoked root fails the check in shadow mode too, with one summary line.
- **[Threat model](../threat-model.md):** "A compromised root key" moves from *What it does not protect against* to the protections table, limited by the [leak table](#what-each-leak-allows) above. *Revocation timing* gains the freshness bound.
- **Migration:** every existing host's policy is edited once, to `mago.policy/v2` with a `recovery` block, an empty log and, ideally, `freshness`, after `mago-ski policy check` passes on it.

## Rationale: TUF and KERI

Both TUF and KERI address key compromise, and their ideas are compatible; this design takes its structure from TUF and one idea from KERI.

**What TUF contributes.** TUF separates a *root role* (a threshold of offline keys, used rarely) from the keys that sign day-to-day metadata. When a day-to-day key leaks, the root role signs new metadata naming its replacement; clients walk the chain of root versions from the one they shipped with. In mago-ski, the root key is the day-to-day key: it signs a revocation list every 30 days, often from automation. So the recovery set plays TUF's root role, root events are the chain of root versions, and the rule that a rotation is signed by both the old and the new keys is TUF's. The freshness check is TUF's *timestamp role*: an online key that frequently re-signs a short-lived statement naming the current metadata, so a client cannot be kept on old metadata unnoticed (a *freeze attack*). TUF secures Sigstore's root of trust and, as Uptane, software updates in vehicles, and PyPI adopted it in PEP 458. mago-ski already follows TUF elsewhere: expiring signed metadata, version-based rollback protection, and short revocation-list lifetimes.

**What KERI contributes.** KERI commits to the next keys by their digests, so a key's public half is revealed only when it is used (*pre-rotation*). This design keeps that property in the form mago-ski already uses everywhere: hosts pin recovery and timestamp keys by fingerprint, and public keys appear only in what they sign.

**What KERI would add, and why this design does not take it.**

- *A single pre-rotated successor key* (rotate by revealing the next key; the next key becomes the root). Simple, but whoever steals the successor from storage can take over, with no threshold to stop them.
- *Several pre-rotated next keys with a threshold*, which KERI also supports. This is close to the recovery set, with one difference: each set of next keys is used once. Every rotation reveals them and commits to new ones, so all the trustees' keys are replaced at every rotation. The recovery set, like TUF's root role, keeps its keys across rotations until the organization chooses to change them.
- *Key event logs with witnesses and watchers.* KERI is built for self-certifying identifiers with no central authority, where many parties must agree on a key's history. mago-ski always has a central authority (the organization that publishes the policy and the documents), which is the setting TUF was built for. The root event log is enough.

**Alternatives considered.**

- *A threshold on every root signature* (k-of-n to sign each trust root and revocation list). It would protect against a root leak too, but would need `k` people every 30 days for the revocation list.
- *A revocation-only key*, separate from rotation. Kept, as `revoke_threshold`: setting it to 1 gives any one trustee a fast emergency stop whose worst misuse is an outage.
- *Cross-signing by the old root* (the plan in v1). Useful for planned rotations, but a thief holding the old root can cross-sign their own key, so it does not help after a leak.
- *Freshness by minimum versions instead of exact digests.* Simpler to publish, because a new document would not need a new timestamp. But it only stops freezes: a thief with the root key and control over delivery could hand a host any trust root with a high enough version. Exact digests also stop that.
- *A revoked root that follows the mode.* Rejected: see [Revoked root](#revoked-root-blocked-in-every-mode).

**Cost.** Freshness adds one signature check and hashes of files the host has already read: about 0.2 ms per trust load, measured on a laptop. Root events cost one SHA-256 of the log per trust load once a walk is cached. The real cost of freshness is operational: an automated job with its own key, and an outage if that job stops for longer than `max_lifetime`.

## Open questions

1. **Gaps while publishing.** A host that reads the files in the middle of a publish sees a mismatch until its next load. Is atomic publishing (a new directory, then one switch) enough, or should a timestamp also accept the previous set of digests for a short time?
2. **Early warning.** Should hosts warn when the timestamp is close to expiring (for example, with less than a quarter of its lifetime left), so a stalled job is fixed before it causes an outage?
