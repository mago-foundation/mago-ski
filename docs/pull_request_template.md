<!--
PR title: Conventional Commits format, in English, starting with an imperative verb
(e.g. "fix(pi): block grep over Skills with excluded files").
These comments are not shown in the PR description. Do not delete sections that don't apply; write "N/A".
Keep it skimmable in about a minute. Split large changes into smaller PRs.
-->

## Summary

<!-- 2–4 sentences: what changed and **why**. Do not paste the diff. -->


## Type of Change

<!-- Keep one, delete the rest. -->

- [ ] Feature (`feat`)
- [ ] Bug fix (`fix`)
- [ ] Security fix (`fix(security)`)
- [ ] Refactor / cleanup (`refactor`, `chore`)
- [ ] Documentation (`docs`)
- [ ] Tests / CI / build (`test`, `ci`, `build`)

## Related Issues & Documentation

<!-- Issues (e.g. `Closes #123`), specs (`docs/spec/...`), reviews or plans. Otherwise "N/A". -->


## Changes

<!-- Key changes by area, e.g.:
- Verifier: ... (`src/verify.ts`)
- Pi host: ... (`hosts/pi/`)
- GitHub Action: ... (`hosts/github/`, `action.yml`)
- Formats / specs: ... (`docs/spec/`, `tests/vectors/`)
-->


## Notes for Reviewers

<!-- Where to look hardest, trade-offs and rejected alternatives, known limits, suggested commit reading order. -->


## Testing

<!-- Exact commands and results. "Tested" alone is not enough. -->

- [ ] `npm run check` passes (type-check + all tests; state pass/skip counts)
- [ ] `npm run build` succeeds
- [ ] Added tests for new behavior. Bug and security fixes include a regression test that fails without the fix. If omitted, say why:
- [ ] Format change: regenerated vectors (`node scripts/vectors.ts --write`) and the vectors test passes
- [ ] Pi host change: Pi host tests pass on the Pi version in `devDependencies` (state the version)

## Impact & Risks

<!-- Fill in what applies; "N/A" for the rest. -->

- **Formats & compatibility:** <!-- Tree digest, certificate, trust root, revocation list, policy or host state. Do existing certificates still verify? If a format changed, bump its version and update `docs/spec/`. -->
- **User-facing / breaking changes:** <!-- CLI flags, verdicts, exit codes, policy fields, Action inputs. "None" if none. -->
- **Security boundary:** <!-- Does this change what counts as VERIFIED, what a host blocks, or what a pull request can influence? If yes, request an independent security review. -->
- **Host compatibility:** <!-- Pi version, Node version, OS. -->
- **Release & rollback:** <!-- Anything beyond reverting the commit? -->

## Design Invariants

<!-- Check each one. If it doesn't apply, check it and append "(N/A)". If an invariant is broken, leave it unchecked and explain why. -->

- [ ] **Exact digest:** Approval binds an exact tree digest. No change (text, capability-neutral or otherwise) is waived.
- [ ] **Root of trust:** Hosts trust only the pinned root; approvers act within their scopes and expiry.
- [ ] **Fail closed:** Anything that cannot be checked is `UNVERIFIABLE` and blocks in enforce mode.
- [ ] **No credentials to the model:** Keys and secrets never reach the model, logs, outputs or Skill trees.
- [ ] **No safety claims:** Code and docs do not claim that a certificate makes a Skill safe, or claim OWASP compliance/endorsement.

## Documentation

- [ ] Specs, threat model and host docs match the new behavior.
- [ ] `README.md` updated if usage changed.
- [ ] No documentation changes.

## Pre-Merge Checklist

- [ ] Branch is up to date with its target (`git merge origin/dev`, or `origin/main` for release PRs).
- [ ] PRs into `main` are releases: approved by the release owner, CI green.

## AI Usage

<!-- If coding agents were used: one line on where and how, and confirm you reviewed and verified the diff yourself. Otherwise "None". -->
