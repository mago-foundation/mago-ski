# Admission rules v0 (`mago.admission/v0`)

Status: draft, part of mago-ski 0.5.0.

An admission rule file is an organisation's short, readable statement of which evidence is enough to admit a Skill. It is the admission language only: it decides whether an exact Skill version may be loaded, and never describes what an agent may do while it works. That belongs to a separate runtime language under a different name.

## Determinism

A decision is a pure function of (facts, rules, time):

- No model, classifier, score or threshold anywhere in the decision.
- No network during the decision. Facts come from the Skill's bytes and from documents verified offline (a review certificate against the organisation's trust root; a published-by bundle against a local Sigstore trusted root).
- The same facts, rules and time give the same decision on any computer. `mago-ski admit --log` records the facts with each decision, so `mago-ski admission diff` can replay them.

## Facts

| Fact | Source |
|---|---|
| `profile` | the [observed profile](observed-profile-v1.md), computed from the bytes |
| `declaration` | the OWASP USF `permissions`/`requires` block as read (see [skill check](../hosts/skill-check.md)), or none |
| `reviewed_by` | a certificate that the organisation's trust root vouches for, for these exact bytes (`VERIFIED`), with its dates |
| `published_by` | a [published-by](../hosts/publish.md) bundle that verifies for these exact bytes and whose record matches them: numeric repository id, owner id, workflow path, commit |
| `base` | the same facts for the reviewed version this one updates, from its own bytes |

## File

```yaml
admission_version: mago.admission/v0
default: REQUIRE_REVIEW          # the action when no rule matches
rules:
  - id: our-own-skills           # lower-case letters, digits, dashes; unique
    when:
      publisher: { repository_id: "123456789", workflow: .github/workflows/publish.yml }
    action: ALLOW
  - id: reviewed
    when: { reviewed: true }
    action: ALLOW
  - id: plain-updates
    when:
      update: { same_publisher: true, max_days_since_review: 90 }
    action: ALLOW
  - id: shell-gets-a-flag
    when:
      capabilities: { shell: true }
    action: FLAG
  - id: blocked-site
    when:
      capabilities: { websites: [paste.example] }
    action: BLOCK
    reason: "This site is not allowed in our Skills"
```

The file is YAML 1.2 with unique keys and no aliases. Keys outside this schema are errors.

**Actions**, from least to most strict: `ALLOW`, `LOG_ONLY`, `FLAG`, `REQUIRE_REVIEW`, `BLOCK`. The first three admit the Skill.

**How a decision is made.** Rules with a `capabilities` condition are *tighteners*; all others are *basis* rules. The base decision is the strictest action among the matching basis rules, or `default` when none matches. The decision is the stricter of that and the strictest matching tightener. So deny wins, and a tightener can raise a decision but never admit a Skill the basis would stop: `capabilities: {shell: true}` with `FLAG` flags reviewed Skills that run code and leaves unreviewed ones at `REQUIRE_REVIEW`. Among rules with the same action, the first in the file names the decision.

**Conditions** (all given conditions must hold):

- `publisher`: `repository_id`, `owner_id` (numeric ids, quoted), `workflow` (a `.github/workflows/…` path, only together with `repository_id`), `branch` (the ref was `refs/heads/<branch>`) and `trigger` (a list of GitHub event names, such as `[release, push]`). It matches the verified published-by identity. Names and tags cannot be written: a rename or a moved tag cannot change a decision, and a fork or a new repository with the same name has another id.
- `reviewed`: `true` or `false`, whether `reviewed_by` exists.
- `capabilities`: `shell: true` (scripts or shell code are present, or the declaration asks for a shell); `websites: [hosts]` (it names or declares one of these hosts; `*.example.com` covers subdomains); `any_website: true`; `undeclared: true` (a declaration exists and does not cover the profile); `no_declaration: true`; `incomplete: true` (the profile is incomplete).
- `update`: `same_publisher: true` (required) and `max_days_since_review`. It matches when a base is supplied whose `reviewed_by` exists, the base is another digest of the same Skill name, both have the same publisher (repository id and workflow), the version does not escalate, and the base's review is at most that many days old. **Escalation** compares what the Skill can reach, declared and observed together: it escalates when it runs code or asks for a shell and the base did not, when it names or declares a host the base did not cover, when it declares `network.allow: "*"` and the base did not, when its profile is incomplete, when its declaration asks to read or write files, or for tools or programs, that the base's did not, when it stops protecting a file the base's `deny_write` listed, when it drops `network.deny: "*"`, when its declaration adds keys mago-ski does not know, when its shell code names programs the base's did not, when the base had a declaration and this version has none, or when this version's declaration cannot be read one way only. Changes to the instructions alone are not an escalation; a person's review of the base covers only the base.

**Checks at load time** (the linter): unknown keys, duplicate ids, `BLOCK`/`REQUIRE_REVIEW` without a `reason`, `ALLOW` with `capabilities` (no effect: tighteners cannot admit), and basis rules that admit (`ALLOW`, `LOG_ONLY`, `FLAG`) with `reviewed: false` or with no publisher, review or update condition (they would admit every Skill).

Replay refuses a log record with a missing or mistyped field rather than reading a missing review as present.

## Decision

```json
{ "action": "REQUIRE_REVIEW", "admitted": false, "rule_id": "default", "matched": [], "reason": null,
  "missing": "a review of this exact version (reviewed-by); it is not a plain update because it reaches new websites: new.example" }
```

`rule_id` names the rule behind the decision, so every decision can be explained.

## Not in v0

- Hosts (Pi, the company gate for Claude Code and Codex, the verify Action) do not read admission rules yet. In 0.5.0, decisions are made with `mago-ski admit` in CI or by an administrator.
- Rule files are plain files, not signed trust documents.
- Chains of automatic updates: an update is admitted only directly from a reviewed base (one hop).
- A bound on how many SKILL.md lines changed, layered packs (`extends`), and witnessed-by records.
