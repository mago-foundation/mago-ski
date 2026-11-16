# Skill admission policy (design proposal)

Status: **proposed**, not implemented. Nothing on this page describes current behaviour; the released engine admits a Skill only through a valid certificate from the pinned trust root ([verification](../spec/verification.md)). Formats sketched here are illustrative and will change before a spec is written.

## 1. Scope

mago-ski is an **admission** system. It answers one question when a Skill is about to be loaded: *may this exact Skill version be used here, given the evidence about it?* Supported hosts (Pi, the gate for Claude Code and Codex, the GitHub Action) turn the answer into allow or block.

mago-ski does **not** evaluate what an agent does after a Skill is loaded. Tool calls, returned data, user intent, rate or budget limits and output filtering are runtime questions. They are outside mago-ski, its specs and its roadmap, and no part of mago-ski depends on a runtime product.

Public evidence services (signing, transparency logs, witnesses, an index) produce **attestations and records only**. They host no Skill content and enforce nothing.

## 2. Determinism

An admission verdict is a pure function of:

```
(Skill bytes, evidence documents, policy, trust documents, time) -> verdict
```

- **No model in the decision.** No LLM, classifier, similarity score or confidence threshold is part of verification or policy evaluation.
- **No network during evaluation.** Evidence is fetched beforehand into a bundle. Evaluation is offline, so every host and every third party gets the same verdict from the same inputs.
- **Reproducible by anyone.** Every input is a signed document or a hash of bytes. A developer outside any organisation can recompute a verdict, including "this Skill is unchanged since it was first seen".
- **Scanner evidence only tightens.** A `scanned-by` attestation is a signed fact ("scanner S at version V, run by identity I, reported R for digest D"). A policy may use it to flag, require review or block, never to admit. No scanner, model-based or not, can be the reason a Skill is allowed.
- **The language cannot express anything probabilistic.** A condition that cannot be decided exactly from the inputs is not in the language.

## 3. Evidence

Each kind of evidence is a narrow claim. None states that a Skill is safe.

| Evidence | Claim | Produced by |
|---|---|---|
| `published-by` | This identity published these exact bytes, with this declared manifest, from this repository, workflow and commit | The publisher's CI, signing keylessly with its OIDC identity |
| `reviewed-by` | This organisation's approver approved this exact version until this date | A [Skill certificate](../spec/skill-certificate-v1.md), as today |
| `scanned-by` | This scanner reported this result for this digest | Any scanner (tighten-only) |
| `witnessed-by` | This digest was observed at this source commit at this time | Independent witnesses reading public sources |

Publisher identities are normalised to (OIDC issuer, numeric repository id, workflow path, commit). They survive repository renames and cannot be claimed by forks. The policy language cannot refer to tags, so moving a tag cannot change a verdict.

## 4. Policy

A policy is a list of rules over **who** (publisher identity), **what** (name, digest, declared and observed capabilities), **evidence** (reviewed-by, scanned-by, witnessed-by, log inclusion) and **history** (the previously admitted version of the same Skill). Each rule has an action:

| Action | Meaning |
|---|---|
| `ALLOW` | Admit |
| `LOG_ONLY` | Admit and record |
| `FLAG` | Admit and raise for attention |
| `REQUIRE_REVIEW` | Do not admit until an approver issues `reviewed-by`; the record names what is missing |
| `BLOCK` | Do not admit |

Deny wins over allow. Every decision record names the rule that decided it (`rule_id`).

**Layers.** Policies stack: a baseline pack, then the organisation, team and host. A lower layer can only tighten a higher one; loosening is a compile error. Policies are signed trust documents with version rollback protection, like the trust root, never files a user can edit on a host.

**Existing seeds.** The trust root's `approvers[].scopes` with `expires_at` is already a one-rule policy ("this key may vouch for these names until this date"). A certificate is already the narrowest rule ("admit this exact digest, for this reason, until this date"). A host policy with no admission document keeps today's behaviour.

### Illustrative sketch

```yaml
policy_version: mago.admission/v0      # illustrative
extends: baseline@1                    # signed pack; this layer may only tighten it
mode: shadow
rules:
  - id: own-skills
    when:
      publisher: { repo: github.com/acme/skills, workflow: .github/workflows/publish.yml }
    action: ALLOW
  - id: third-party-needs-review
    when:
      publisher: { not_in_rule: own-skills }
      evidence: { reviewed_by: absent }
    action: REQUIRE_REVIEW
    reason: "Third-party Skills need an approver's review"
  - id: updates-without-escalation
    when:
      history:
        reviewed_base: present
        same_publisher: true
        capability_escalation: false
        automatic_hops: { max: 3 }
        days_since_review: { max: 90 }
        skill_md_changed_lines: { max: 20 }
    action: ALLOW
    otherwise: REQUIRE_REVIEW
```

## 5. Capabilities: declared and observed

A publisher's manifest declares what the Skill needs (files, network origins, shell, binaries), in a form mappable to the OWASP Universal Skill Format. A declaration alone can lie, so:

- **Observed profile.** A versioned, deterministic extractor records what the bytes show: executable files and shebangs, script languages, URL origins in any file, binaries named in SKILL.md code blocks. It extends the evidence the diff engine already extracts (executable bit, HTTP(S) origins).
- **Declared must cover observed.** The publish Action fails before signing when the content uses something the manifest does not declare.
- **The verifier recomputes the profile** from the bytes and never trusts the publisher's computation.
- **Escalation compares the union** of declared and observed capabilities between versions.

Natural-language instructions cannot be fully extracted by a deterministic tool. Non-escalation therefore never means "safe"; it only bounds automatic admission (section 6).

## 6. How the design limits its own risks

| Risk | Mechanism in the product | What remains |
|---|---|---|
| Misconfigured policy | Packs with parameters instead of a blank page; `policy propose` from shadow-mode records; `policy diff` replays past decisions and the signing dialog shows which would flip; complete static checks (unreachable or shadowed rules, wildcard publishers in enforce, loosening across layers, BLOCK without reason); every block names the missing evidence; policies are signed and versioned, so a bad one is reverted by signing | A deliberately weak choice stays possible, but it is visible, signed and replayed |
| Automatic admission drifting from review | Only updates to a human-reviewed base, from the same publisher identity, without capability escalation; bounded hops, age since review and SKILL.md change size; each record states the distance from the last review | A careful malicious update within the bounds can pass; the bounds limit how far and how long |
| Lying manifests | Observed profile, declared-covers-observed at publish, recomputation at verify | Instructions in prose |
| No publishers yet | Organisation review works without authors; witnesses record first-seen digests of public Skills; one command writes the publish workflow and a pre-filled manifest; warn by default, block on opt-in | Adoption still has to be earned repository by repository |
| One operator becomes the trust root | No Mago key in the default trust path for `published-by`; the index can be rebuilt from the public log; policies can require k-of-n independent witnesses; the baseline pack is replaceable | Spec governance needs a neutral home |
| Evidence read as safety | Output states facts, never a score; a test over every user-facing message rejects "safe", "trusted" and similar wording; badges state the claim (`published-by acme/skills@abc123`), never a bare "verified" | Readers may still over-trust |

## 7. Where it would land

- `policy.ts`: a host policy version that points to a signed admission document.
- `verify.ts`: split into *collect evidence* and *evaluate policy*. The verdict set stays closed; decision records gain `rule_id` and the automatic-admission chain.
- Gate: `contract.ts` and the generation rule are unchanged; evaluation runs inside the verifier worker, so policy changes take effect like revocations.
- GitHub Action: a publish job that signs `published-by` and checks declared against observed capabilities.
- GUI: a policy template in the administration rack (choose a pack, set parameters, view the replay, sign).

## 8. Open questions

- Whether the observed-profile extractor gets its own versioned spec (leaning yes, to keep the tree digest stable).
- Default bounds in the baseline pack.
- Whether `REQUIRE_REVIEW` follows the mode like every other verdict (leaning yes).
- Witness record format, and whether it is a transparency-log entry or a separate signed log.
