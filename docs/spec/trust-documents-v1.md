# Trust documents v1

Status: draft, implemented by mago-ski 0.1. Test vectors: [`tests/vectors/`](../../tests/vectors/).

An organization's trust is anchored in one **root key**, kept offline. Hosts pin the root key's fingerprint (its key id). The root signs two documents: the trust root (who may approve what) and the revocation list (what is no longer trusted). Both are DSSE envelopes signed by the root key, in the same envelope format as [certificates](skill-certificate-v1.md), with canonical JSON payloads.

## Trust root

`payloadType`: `application/vnd.mago-ski.trust-root+json`

```json
{
  "type": "mago.trust-root/v1",
  "version": 3,
  "issued_at": "2026-10-09T12:00:00Z",
  "expires_at": "2027-10-09T12:00:00Z",
  "root": { "key_id": "sha256:<hex>", "public_key": "<base64 DER SPKI>" },
  "approvers": [
    { "key_id": "sha256:<hex>", "public_key": "<base64 DER SPKI>", "name": "Platform reviewers",
      "scopes": ["docs-*", "pdf-tools"], "expires_at": "2027-04-07T12:00:00Z" }
  ]
}
```

- `version`: positive integer, increased on every change. Hosts with a configured state file reject versions lower than those recorded there.
- `root.public_key` must hash to `root.key_id`, which must equal the pinned fingerprint and the envelope's `keyid`.
- `approvers`: sorted by `key_id`, unique, at most 256. The root key may not also be an approver.
- `scopes`: sorted, unique, 1–64 per approver. `*` matches every Skill name; `prefix*` matches names starting with `prefix`; anything else matches one exact name.

## Revocation list

`payloadType`: `application/vnd.mago-ski.revocations+json`

```json
{
  "type": "mago.revocations/v1",
  "version": 2,
  "issued_at": "2026-10-09T12:00:00Z",
  "expires_at": "2026-11-08T12:00:00Z",
  "root_key_id": "sha256:<hex>",
  "revoked_keys": [{ "key_id": "sha256:<hex>", "reason": "laptop lost", "revoked_at": "2026-10-09T12:00:00Z" }],
  "revoked_digests": [{ "digest": "sha256:<hex>", "reason": "exfiltration found", "revoked_at": "2026-10-09T12:00:00Z" }]
}
```

- Required: a host with no valid, unexpired revocation list verifies nothing. The short default lifetime (30 days) forces the organization to republish it, so a host cannot be kept on a stale list indefinitely.
- A revoked key invalidates every certificate it signed. A revoked digest invalidates that approved version whoever signed it.
- `revoked_keys` sorted by `key_id`, `revoked_digests` by `digest`, both unique.

## Host policy

Hand-edited JSON, read by hosts and the CLI. Paths are relative to the policy file.

```json
{
  "policy_version": "mago.policy/v1",
  "mode": "shadow",
  "root_fingerprint": "sha256:<hex>",
  "trust_root": "trust-root.json",
  "revocations": "revocations.json",
  "certificate_dirs": ["certs"],
  "skill_dirs": ["../skills"],
  "state_file": "state.json",
  "decision_log": "decisions.jsonl"
}
```

| Field | Required | Meaning |
|---|---|---|
| `mode` | yes | `shadow`: allow and log what would be blocked. `enforce`: block |
| `root_fingerprint` | yes | Pinned root key id |
| `trust_root`, `revocations` | yes | Signed documents |
| `certificate_dirs` | no | Extra certificate locations |
| `skill_dirs` | no | Directories scanned by `verify-all` and the GitHub Action |
| `state_file` | no | Rollback protection (below). Strongly recommended on hosts |
| `decision_log` | no | JSON Lines file of decisions |

The policy itself decides who is trusted, so it must live where the code under review cannot change it. The Pi host reads it only from `MAGO_SKI_POLICY` or `~/.mago-ski/policy.json`; the GitHub Action reads it from the pull request's base revision.

## Host state (rollback protection)

Canonical JSON written by the host:

```json
{"roots":{"sha256:<root key id>":{"revocations_version":2,"trust_root_version":3}},"type":"mago.host-state/v1"}
```

The host records the highest versions it has accepted for each root and rejects older documents as `UNVERIFIABLE` (rollback). Without a state file, a host can be given an older, still-unexpired trust root or revocation list.

## Decision log

One JSON object per line:

```json
{"timestamp":"2026-10-09T12:00:00Z","host":"laptop-7","mode":"enforce","action":"block","event":"tool:read","skill":"pdf-tools","skill_dir":"/home/a/.agents/skills/pdf-tools","digest":"sha256:...","certificate_id":"sha256:...","verdict":"UNAPPROVED_CHANGE","reason":"..."}
```

`action` is `allow`, `block` or `would-block` (shadow mode). `certificate_id` is the SHA-256 of the certificate file.

## Key rotation

- **Approver keys:** add the new key (`root add-approver`), re-approve the Skills, then remove the old key (`root remove-approver`). Certificates from a removed approver stop verifying once a host reads the updated trust root; revoke the old key instead if it may be compromised.
- **Root key:** not implemented in v1. Planned design: the new root's first trust root is also signed by the old root, and hosts that pin the old fingerprint accept the new one only through that cross-signed document. Until then, replacing the root means distributing a new fingerprint to every host.
