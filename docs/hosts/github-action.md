# GitHub Action

In enforce mode, fails the check when a Skill found under the policy's `skill_dirs` is not covered by a valid certificate for its exact bytes.

```yaml
# .github/workflows/skills.yml
name: skills
on: [pull_request]
permissions:
  contents: read
jobs:
  verify:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: mago-foundation/mago-ski@<full commit sha>
        with:
          policy: .mago-ski/policy.json
```

Pin the action to a full commit SHA: the verifier runs from the action's own checkout, so the pin decides which verifier code runs.

## Repository layout

```
.mago-ski/
  policy.json          # mode, root_fingerprint, trust_root, revocations, skill_dirs, certificate_dirs
  trust-root.json
  revocations.json
  certs/               # optional: <skill-name>.cert.json
skills/
  pdf-tools/
    SKILL.md
    .mago-ski-cert.json   # or keep certificates in .mago-ski/certs/
```

On pull requests, `policy.json`, `trust-root.json` and `revocations.json` are read from the **base** revision. A pull request can add or update certificates (they are signed), but changes it makes to the trust documents take effect only after merge, so a pull request cannot add its own approver. Certificate directories and Skill directories are read from the pull request.

Symlinked Skill directories and symlinked `SKILL.md` files are reported as `UNVERIFIABLE`, not skipped (Pi follows such links). Discovery searches up to 16 directory levels below each `skill_dirs` entry. Anything deeper is reported as `UNVERIFIABLE` instead of being skipped: it fails the check in `enforce` mode and is reported in `shadow` mode. Policy, trust and Skill directories must resolve inside their checkout.

The action writes a summary table to the job summary and an annotation on each failing Skill's `SKILL.md`. In `shadow` mode it reports but does not fail. CI keeps no state file; rollback protection comes from reading trust documents from the protected base revision.

Run it alongside a capability scanner such as SkilLock: the scanner explains what changed, mago-ski makes sure someone approved exactly that.
