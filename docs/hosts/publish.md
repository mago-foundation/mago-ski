# Publish Action: keyless published-by attestations

A Skill author's release workflow can state, with the repository's own GitHub identity, which exact Skill bytes it published. Nobody has to create or keep a key. On public repositories the statement is recorded in the public Sigstore transparency log, which nobody, including the Mago Foundation, can edit. The statement is verified against public Sigstore infrastructure, not against a Mago server.

A published-by attestation says who published these bytes, from which repository, workflow and commit. It does not say that the Skill is safe.

## Set up

```yaml
# .github/workflows/publish-skills.yml
name: publish skills
on:
  release:
    types: [published]
permissions:
  contents: read
  id-token: write       # lets actions/attest request a short-lived signing certificate
  attestations: write   # lets it store the attestation on GitHub
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
        with:
          persist-credentials: false
      - uses: mago-foundation/mago-ski/publish@v0.5.0-beta.1
```

Inputs: `path` and `require-manifest`, as in the [Skill check Action](skill-check.md). Outputs: `bundle-path` (the Sigstore bundle) and `attestation-url`.

What it does:

1. It runs the Skill check on every Skill. If any Skill fails, nothing is signed.
2. It writes one in-toto statement. Its subjects are the Skills' tree digests ([skill-tree v2](../spec/skill-tree-v2.md)), and its predicate (`https://magofoundation.dev/attestation/published-by/v1`) records each Skill's path, the SHA-256 of its `SKILL.md`, its USF declaration as read (or why there is none), and its [observed profile](../spec/observed-profile-v1.md).
3. It signs the statement with GitHub's [`actions/attest`](https://github.com/actions/attest) (pinned by commit). On public repositories this uses the public-good Sigstore instance; on private repositories it uses GitHub's own instance (GitHub Enterprise Cloud).

Run it on release, or on pushes to a protected branch, so that the signing workflow cannot be changed by an unreviewed pull request. The Action refuses to run on `pull_request`, `pull_request_target` and `workflow_run` events. Pin it to a full commit SHA rather than a tag.

## Verifying

Anyone can check an attestation for the bytes they have, offline:

```sh
cosign trusted-root create --with-default-services --out trusted_root.json   # once; this step uses the network
mago-ski attestation verify ./skills/release-notes \
  --bundle release-notes.sigstore.json --trusted-root trusted_root.json --cosign ./cosign \
  --repo acme/skills --workflow .github/workflows/publish-skills.yml --repo-id 123456789
```

The bundle comes from the Action's `bundle-path` output, or from GitHub (`gh attestation download`, or the `/repos/OWNER/NAME/attestations/sha256:DIGEST` API, where DIGEST is the Skill's tree digest from `mago-ski digest`).

The command:

- recomputes the Skill's tree digest from the bytes;
- runs Cosign v3.1.3 (its SHA-256 must match the official release) against the trusted root, with no network access needed. Cosign checks the signature, the certificate chain, the transparency-log proof, that the signer is a GitHub Actions workflow of `--repo` (and `--workflow`), that the statement is a published-by statement, and that it names this digest;
- reads the signer's identity from the certificate: repository, numeric repository id, owner id, workflow, commit, ref, trigger and runner. `--repo` must match both the signing workflow's repository and the repository whose code ran (with a reusable workflow from another repository they differ, and the attestation is refused), and `--workflow` the top-level workflow. `--repo-id` pins the numeric id. The id survives renames, and a fork or a new repository with the same name cannot have it;
- recomputes the observed profile and the declaration, and reports any difference from what the publisher recorded.

Result: `PUBLISHED_BY` (exit 0) with the facts, `RECORD_MISMATCH` (exit 1) when the record does not match the bytes, or `NOT_VERIFIED` (exit 1) with the reason.

## Limits

- `--repo` is compared with the workflow identity as GitHub spells it, case included. Prefer `--repo-id`.
- A compromised publisher account or workflow can still publish. Reviews, revocation and the organisation's rules (next step of 0.5.0) limit how far that reaches.
- The statement records what the files contained; it says nothing about whether the Skill is safe.
