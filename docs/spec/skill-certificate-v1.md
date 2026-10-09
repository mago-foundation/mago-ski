# Skill certificate v1

Status: draft, implemented by mago-ski 0.1. This page's URL is the certificate's `predicateType`. Test vectors: [`tests/vectors/certificates/`](../../tests/vectors/certificates/).

A Skill certificate records that an approver approved one exact version of one Skill until a stated time. It does **not** state that the Skill is safe.

## Envelope

A [DSSE](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md) envelope, serialized as canonical JSON (sorted keys, no whitespace, one trailing LF):

```json
{"payload":"<base64>","payloadType":"application/vnd.in-toto+json","signatures":[{"keyid":"sha256:<hex>","sig":"<base64>"}]}
```

- Exactly one signature, Ed25519 over the DSSE pre-authentication encoding `DSSEv1 <len(type)> <type> <len(payload)> <payload>`.
- `keyid` is `sha256:` + hex SHA-256 of the signer's DER SubjectPublicKeyInfo.

## Payload: in-toto Statement v1

The payload is canonical JSON:

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [{ "name": "pdf-tools", "digest": { "magoSkillTreeV2": "<64 hex>" } }],
  "predicateType": "https://github.com/mago-foundation/mago-ski/blob/main/docs/spec/skill-certificate-v1.md",
  "predicate": {
    "tree_profile": "mago.skill-tree/v2",
    "files": [{ "path": "SKILL.md", "size": 412, "sha256": "<64 hex>", "exec": false }],
    "approval": {
      "approver_key_id": "sha256:<hex>",
      "issued_at": "2026-10-09T12:00:00Z",
      "expires_at": "2027-01-07T12:00:00Z",
      "reason": "Reviewed scripts and network use"
    },
    "previous_digest": "sha256:<hex>"
  }
}
```

| Field | Rule |
|---|---|
| `subject` | Exactly one. `name`: 1–128 ASCII letters, digits, `.`, `_`, `-`, starting with a letter or digit. `digest.magoSkillTreeV2`: the [tree digest](skill-tree-v2.md) without the `sha256:` prefix |
| `files` | The per-file records of the tree, sorted as in the digest. Must include `SKILL.md`. Their digest must equal the subject digest |
| `approver_key_id` | Must equal the envelope's `keyid` |
| `issued_at`, `expires_at` | UTC, second precision, `YYYY-MM-DDTHH:MM:SSZ`; `expires_at` after `issued_at` |
| `reason` | Free text, 1–1024 characters, no control characters |
| `previous_digest` | The previously approved digest of this Skill, or `null`. Informational: it forms a readable update history, it does not grant anything |

No other fields are allowed anywhere. Unknown fields make the certificate unverifiable.

## Where certificates live

A host looks for certificates for Skill `NAME`, in this order:

1. a file named explicitly by the caller;
2. `<certificate_dir>/NAME.cert.json` for each `certificate_dirs` entry in the policy (for Skills the organization does not modify);
3. `.mago-ski-cert.json` in the Skill root (excluded from the tree digest).

If any candidate verifies, the Skill is verified. Otherwise the most specific failure is reported (see [verification](verification.md)).
