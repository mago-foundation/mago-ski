# What mago-ski can do

As of 2026-11-10.

mago-ski lets an organisation approve exact versions of AI Skills, and makes sure only those approved versions are used. It can approve Skills. It can also install approved Skills for users, but that part, the company gate for Claude Code and Codex, is built and not yet released.

This page has three parts: what works today in the released version (0.3.0), what is built but not released yet, and what mago-ski does not do.

## What works today (version 0.3.0, released)

Anyone can install this version for free. It runs on Linux and macOS.

**Setting up who can approve**

- mago-ski creates the organisation's keys: one main key, and one key for each person who approves Skills.
- It lets the organisation decide who may approve which Skills, and until what date.
- It can remove a person's right to approve, and extend how long the list of approvers stays valid.
- A key that has been the organisation's main key or timestamp key can never become an approver.

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

**If the main key is lost or stolen**

- An organisation can name a few recovery keys, kept offline. Together they can stop trust in a stolen main key, or replace it, without editing every computer's settings.
- An organisation can also require a short-lived timestamp. A computer fed old approval files then stops trusting anything once the newest timestamp expires.

**Blocking and trying out**

- In the Pi coding agent, mago-ski blocks Skills that are not approved. The agent does not see them and cannot load them.
- On GitHub, mago-ski fails the check on a change that adds or edits a Skill without a valid approval. A change cannot approve itself.
- A trial mode records what would be blocked without blocking anything, so an organisation can test first.
- It keeps a record of each check.

**Desktop app (early preview, separate download, in English and Korean)**

- The desktop app watches the Skills installed on a computer, shows what changed, and shows whether each one is approved.
- In its administration tab, the organisation's everyday tasks can be done without the command line:
  - an approver can approve a Skill version;
  - an administrator can add, remove and renew approvers, take back an approval or a key, and re-sign the list of taken-back approvals;
  - the person holding the timestamp key can sign the timestamp.
- Every signature needs a confirmation window that shows exactly what will be signed and which Skills it affects.
- The app checks that the key really belongs to someone in that role, using the organisation's settings file that only the administrator can change.
- Setting up a new organisation and recovering from a stolen main key still use the command line.

## Built, not released yet (the company gate)

This part is finished and tested on Linux only. It is not yet packaged and not yet part of the mago-ski command, so it cannot be switched on from a released version. It has been tried with the real Claude Code (version 2.1.318) and the real Codex (versions 0.163.0 and 0.166.0), in non-interactive sessions only.

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
- In Claude Code, Skills the administrator did not install are hidden from the AI as well as blocked.
- In Codex, they stay visible in its list of Skills and are only blocked when used.
- In Codex, users have to call an installed Skill by its full link (`[$name](/etc/codex/skills/name/SKILL.md)`), not just `$name`.
- In Codex, mentions from plugins and links that do not lead to an installed Skill are blocked.

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
