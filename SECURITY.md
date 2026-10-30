# Security policy

mago-ski decides whether an agent host may load a Skill, so we treat security reports as the highest priority.

## Supported versions

| Version | Supported |
|---|---|
| 0.2.x | Yes |
| 0.1.x | No |

Before 1.0, only the latest 0.x release line receives security fixes. Upgrade to the latest patch release before reporting.

## Reporting a vulnerability

**Do not open a public issue, discussion or pull request for a vulnerability.**

Report it privately through GitHub: the repository's **Security** tab → **Report a vulnerability** ([direct link](https://github.com/mago-foundation/mago-ski/security/advisories/new)).

Please include:

- the affected version (`mago-ski --version`) and host (CLI, Pi with its version, or the GitHub Action);
- what you expected and what happened, for example the verdict you got and the one you expected;
- minimal steps or files that reproduce it (a Skill tree, certificate, trust root, policy);
- the impact as you understand it.

Do not include real private keys or tokens. Use keys made with `mago-ski keygen` for the report.

## What counts

In scope, for example:

- an input that makes the verifier return `VERIFIED` when it should not;
- a way for a pull request to change who is trusted in the GitHub Action;
- a way for an unverified Skill, or bytes outside a certificate, to reach the model in Pi enforce mode;
- a way to roll a host back to an older trust root or revocation list;
- exposure of private keys through output, logs, decision records or Skill trees;
- a problem in the published npm package or release process, such as a tarball that does not match its provenance.

Out of scope: limits already listed under "What it does not protect against" in the [threat model](docs/threat-model.md), such as shell commands that reach Skill files indirectly, hostile code running in the same agent process, or a compromised host or root key. A report that shows one of those limits is broader than documented is in scope.

## What happens next

1. We acknowledge the report within 7 days.
2. We confirm or rule out the issue and keep you updated in the private advisory.
3. We fix confirmed issues in a private fork, with a regression test, and publish a patch release.
4. We publish a GitHub security advisory (with a CVE where appropriate) when the fix is released, and credit you unless you ask us not to.

We ask that you give us 90 days from your report, or until a fix is released if that is sooner, before disclosing the issue publicly. If a fix needs longer, we will tell you why and agree on a date with you.

## Verifying releases

Releases are built and published from GitHub Actions with npm provenance. To check an installed copy:

```bash
npm audit signatures
```

Each GitHub release also lists the tarball's SHA-256 and attaches a `SHA256SUMS` file.
