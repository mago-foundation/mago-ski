# Verification

Status: draft, implemented by mago-ski 0.1 (`src/verify.ts`). Verdict test vectors: [`tests/vectors/cases.json`](../../tests/vectors/cases.json).

## Verdicts

| Verdict | Meaning | What to do |
|---|---|---|
| `VERIFIED` | A certificate from an in-scope, trusted, unrevoked approver covers these exact bytes and has not expired | Nothing |
| `UNAPPROVED_CHANGE` | A valid certificate exists for this Skill, but the bytes differ from what it approved (including a single sentence or the executable bit) | Review the change and issue a new certificate |
| `NO_CERTIFICATE` | No certificate names this Skill | Review and approve it, or remove it |
| `UNTRUSTED_SIGNER` | The signer is not an approver in the trust root, is outside its scopes, or signed after its own expiry | Get it approved by an authorized approver |
| `REVOKED` | The approver key or the approved digest is on the revocation list | Do not use; re-approve a fixed version with another key |
| `EXPIRED` | The certificate, the approver key, the trust root or the revocation list has expired | Renew the expired item |
| `UNVERIFIABLE` | Something could not be checked: malformed or tampered documents, a trust root not signed by the pinned key, rollback, unreadable Skill files | Fix the input; treat as blocked |

Every verdict except `VERIFIED` blocks in enforce mode and is logged as `would-block` in shadow mode.

## Order of checks

Trust documents, once per host check:

1. The trust root's envelope is signed by the pinned root fingerprint, names that root, and its signature is valid. Otherwise `UNVERIFIABLE`.
2. The trust root has not expired. Otherwise `EXPIRED`.
3. The revocation list is signed by the same root and has not expired. Otherwise `UNVERIFIABLE` or `EXPIRED`.
4. Neither document's version is lower than the host state records. Otherwise `UNVERIFIABLE` (rollback). Accepted higher versions are recorded.

Each certificate, for a Skill named `NAME` whose current tree digest is `D`:

1. The certificate parses, its file list hashes to its subject digest, and `approver_key_id` matches the envelope `keyid`. Otherwise `UNVERIFIABLE`.
2. The subject name is `NAME`. Otherwise `NO_CERTIFICATE` for this candidate.
3. The approver key is not revoked. Otherwise `REVOKED`.
4. The approver key is in the trust root. Otherwise `UNTRUSTED_SIGNER`.
5. One of the approver's scopes matches `NAME`. Otherwise `UNTRUSTED_SIGNER`.
6. The signature is valid for the approver's key. Otherwise `UNVERIFIABLE`.
7. `issued_at` is not more than 5 minutes in the future (`UNVERIFIABLE`) and is before the approver's `expires_at` (`UNTRUSTED_SIGNER`).
8. The approver key and the certificate have not expired. Otherwise `EXPIRED`.
9. The approved digest is not revoked. Otherwise `REVOKED`.
10. The approved digest equals `D`. Otherwise `UNAPPROVED_CHANGE`.
11. `VERIFIED`.

If any candidate is `VERIFIED`, the Skill is verified. Otherwise the result is the first match in this order: `REVOKED`, `UNAPPROVED_CHANGE`, `EXPIRED`, `UNTRUSTED_SIGNER`, `UNVERIFIABLE`, `NO_CERTIFICATE`.

## Skill name

The name checked against the certificate is, in order: the name the host gives (the Pi host passes the name Pi loaded), the `name` field in `SKILL.md` frontmatter, or the directory name.
