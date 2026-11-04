# What mago-ski can do

As of 2026-11-03.

mago-ski lets an organisation approve exact versions of AI Skills, and makes sure only those approved versions are used. Yes, it can approve Skills, and it can install approved Skills for users, but the installing part is built and not yet released.

The list has three parts: what works today in the released version (0.2.0), what is built but not released yet, and what mago-ski does not do.

## What works today (version 0.2.0, released)

Anyone can install this version for free. It runs on Linux and macOS.

**Setting up who can approve**

- mago-ski creates the organisation's keys: one main key, and one key for each person who approves Skills.
- It lets the organisation decide who may approve which Skills, and until what date.
- It can remove a person's right to approve.

**Approving Skills**

- mago-ski can approve a Skill. The approval covers that exact version, down to the last letter, and carries an end date and a reason.
- It notices any change to an approved Skill, even one added sentence. A changed Skill needs a new approval.
- It shows what changed between two versions of a Skill.

**Checking Skills**

- mago-ski checks a Skill and says whether it is approved exactly as it is. If not, it says why: changed, never approved, approved by the wrong person, approval taken back, or approval expired.
- It can check every Skill in a folder at once.

**Taking approval back**

- mago-ski can take back the approval of one Skill version.
- It can take back everything one person ever approved, in one step.
- Approvals and the list of taken-back approvals expire, so a machine cannot keep using an old list forever.
- It refuses to go back to an older copy of the approval files.

**Blocking and trying out**

- In the Pi coding agent, mago-ski blocks Skills that are not approved. The agent does not see them and cannot load them.
- On GitHub, mago-ski fails the check on a change that adds or edits a Skill without a valid approval. A change cannot approve itself.
- A trial mode records what would be blocked without blocking anything, so an organisation can test first.
- It keeps a record of each check.

**Desktop app (early preview, separate download)**

- The desktop app watches the Skills installed on a computer, shows what changed, and shows whether each one is approved. It never approves anything itself.

## Built, not released yet (the company gate)

This part is finished and tested on its own, on Linux only. It is not yet packaged, not yet part of the mago-ski command, and not yet tried with the real Claude Code and Codex.

**Installing Skills**

- mago-ski can install approved Skills for users, into a protected folder that only the administrator can change.
- It refuses to install a Skill that does not have a valid approval.
- It can remove an installed Skill.
- When an approval is taken back, it removes that Skill from the computer by itself.
- It picks up new approvals and taken-back approvals that the administrator hands it.

**Blocking in Claude Code and Codex**

- mago-ski checks every use of a Skill in Claude Code and in Codex.
- It blocks Skills that are not approved, changed since approval, taken back or expired.
- If it cannot check, it blocks rather than lets the Skill through.
- A Skill whose approval is taken back is blocked at its next use, even in a session that is already open. The session itself keeps running.
- It writes the administrator settings files that switch this on for Claude Code and Codex.

**Control and records**

- Trial mode is the default. Blocking starts only when the administrator switches it on.
- It keeps a protected record of every decision.

## What mago-ski does not do

- It does not decide whether a Skill is safe. An approval only records who approved which version.
- It does not run a central Skill store or download service. The administrator hands mago-ski the Skills and approvals.
- It cannot remove instructions that a session has already read. Those stay until the session is restarted.
- In Codex, it cannot fully stop Skills that did not come from the administrator, such as Skills inside a project folder. It notices them and blocks most uses, but a determined user can get around it.
- It does not work on Windows yet. The company gate works on Linux only so far.
- It does not work with Cursor or other coding tools yet.
