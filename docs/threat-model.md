# Threat model

mago-ski answers one question: **is the Skill this agent is about to use the exact version someone in my organization approved, and is that approval still valid?** It does not decide whether a Skill is safe or benign.

## What it protects against

| Threat | How |
|---|---|
| **Silent update ("rug pull")**: a Skill that was fine is changed, possibly by one sentence, and the agent picks up the new version | The tree digest covers every byte and the executable bit. Any change, including prose-only changes with identical capabilities, gives `UNAPPROVED_CHANGE` until someone approves the new version |
| **Unreviewed Skills**: a Skill installed outside any review process (`npx skills`, copied into `~/.agents/skills`, auto-updated) | No certificate, `NO_CERTIFICATE`. The Pi host does not advertise it and refuses its files in enforce mode |
| **Rogue or over-reaching approver**: someone signs with a key the organization never authorized, or an authorized team approves outside its area | Hosts trust only the pinned root. Approver keys must be in the root-signed trust root, and scopes limit which Skill names each key may approve: `UNTRUSTED_SIGNER` |
| **Compromised approver key** | Revoking the key invalidates every certificate it signed: `REVOKED`. This takes effect on each host once it has the updated revocation list (see *Revocation timing* below) |
| **Bad version discovered after approval** | Revoking the digest: `REVOKED` |
| **Stale trust**: keeping a host on an old revocation list or trust root | Revocation lists expire (30 days by default). The host state file rejects older versions: `UNVERIFIABLE` (rollback) |
| **Swap after verification**: a file replaced between the check and its use | The Pi host re-hashes each Skill file on read against the certificate's file list, expands `/skill:` from the bytes it verified, and re-verifies before `grep` and shell commands that touch a Skill |
| **Hiding the instructions from the digest**: `.skilldigestignore` listing `SKILL.md` | Rejected. `SKILL.md` is always covered, and certificates without it are `UNVERIFIABLE` |
| **Exposing uncovered files**: `.git` or ignored files in a verified Skill | The Pi host refuses `read` of any file not in the certificate and refuses `grep` over Skills that have excluded files |
| **Symlinks**: a linked Skill directory, a linked `SKILL.md`, or a link inside a Skill pointing elsewhere | Digests reject symlinks. Discovery (CLI, GitHub Action) reports linked Skills as `UNVERIFIABLE` instead of skipping them. The Pi host matches tool paths both before and after resolving links |
| **Verification errors** | The Pi host fails closed in enforce mode: a Skill that cannot be checked is `UNVERIFIABLE`, and if checking crashes outright, file and shell tools that touch any Skill path are blocked |
| **Pull request trusting itself**: a PR adds its own root or approver | The GitHub Action reads policy, trust root and revocation list from the protected base revision |
| **Tampered documents** | Canonical JSON with exact fields and Ed25519 signatures over DSSE: any change is `UNVERIFIABLE` |

## What it does not protect against

- **Malicious first versions and fooled reviewers.** A certificate records a decision; it does not make the decision correct. Review quality is the organization's job.
- **Prompt injection at runtime.** A verified Skill can still be steered by untrusted data it reads (the confused-deputy problem). Runtime evaluation of tool calls against the approved contract is a separate layer (Mago's CLEAR), not part of mago-ski.
- **Shell commands that reach Skill files indirectly.** In Pi, `bash` and `powershell` are checked by matching Skill paths in the command text. Relative paths after `cd`, globs, variables or encoded paths can evade it. The guarantees that hold are: unverified Skills are not advertised, `/skill:` cannot load them, and the structured file tools (`read`, `grep`, `edit`, `write`, `find`, `ls`) refuse their files. `find` and `ls` may still list file names inside verified Skills.
- **Other code in the agent process.** A hostile Pi extension, MCP server or custom tool runs with the same permissions as mago-ski and can read files directly or change the Skill list after mago-ski filters it. Load mago-ski last and only trusted extensions.
- **A compromised host.** Root or same-user malware can change files, the policy, the state file or the extension itself. This includes racing directory replacement between path resolution and reading; the digest re-checks file identity, but a same-user attacker controls the file system.
- **A compromised root key.** Everything chains to it. Keep it offline. Root key rotation is designed but not implemented in v1.
- **Files excluded from the digest** (`.skilldigestignore`, root `.git`) are not approved. The Pi host refuses to read them from a verified Skill, but other tools may still use them.
- **Windows executable bits.** Not covered on Windows (no POSIX modes); see the [digest spec](spec/skill-tree-v2.md).

## Revocation timing

Revocation is not instant everywhere. A host acts on a revocation once it reads the updated list. Until then it accepts its current list for as long as that list is unexpired, so the list's lifetime (30 days by default, set with `--expires`) is the longest a revoked certificate can still pass. Shorten it for high-risk organizations and republish often (`revoke refresh`). The host state file stops a host from being moved back to an older list. In CI there is no state file; the Action reads the list from the protected base revision, so a revocation applies to pull requests once it is merged there.

## Assumptions

- The root private key is offline and only its holder can sign trust documents.
- Approver private keys are kept by the people they name; `approve` refuses a key stored inside the Skill directory.
- The host policy, trust documents and state file are writable only by the user or administrator, not by the code under review. The Pi host never reads policy from the project directory.
- Clocks are roughly correct (5 minutes of skew is tolerated for issue times).
