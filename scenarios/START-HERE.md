# Try the mago-ski live scenarios

This guide is for you and for Claude Code or Codex. After cloning the repository, open your agent in the checkout and ask:

> Read `scenarios/START-HERE.md` and help me run the first-release live scenarios for this host. Explain the results and anything that could not be checked.

Your open agent helps you follow the guide. The runner starts a **separate, fresh host process** for each experiment. It creates a temporary organization, test keys and sample Skills, then runs the real host and mago-ski gate against a **local scripted model endpoint**. It checks what reaches that endpoint; it does not call a real model or test the interactive Skill menu.

## Gather what you need

1. Use a disposable **Linux machine or VM**. The harness requires root, a private mount namespace, `unshare`, `mount` and `umount`. Some containers do not allow these operations. On Windows, run it on a suitable Linux machine or VM.
2. Install a Node version supported by this checkout (see `engines` in `package.json`), Git, and the real host you want to test. Codex requires its **native executable**, rather than a JavaScript launcher, because the gate checks the host's executable identity.
3. Clone the repository, check out the branch or release you want to try, and review its scripts. From the checkout, install dependencies and build:

   ```bash
   npm ci
   npm run build
   ```

4. Find your host executable. For Claude Code, `command -v claude` is usually enough. For Codex, find the native binary provided by your installation and note its absolute path. The live harness has been exercised against specific host versions; a result applies to the version you actually run.
5. Make sure the checkout and executable you are about to run are trusted. The next step requires administrator privileges. Do not use a real organization's keys or Skills.

## Inspect the plan

Choose your host and run one of these commands. They only print the plan; they do not start the gate or request root.

```bash
npm run live:scenarios -- --host claude-code
npm run live:scenarios -- --host codex
```

The four scenarios are `approved`, `unapproved`, `revoked` and `gate-down`. Review the plan before continuing.

## Run the experiments

The runner must run as root so it can start a private mount namespace. It bind-mounts a temporary managed-configuration folder over the host's `/etc` folder **inside that namespace**. It does not deliberately overwrite the machine's existing managed configuration. The harness may create an empty mount-point directory if one does not already exist; it attempts to remove it afterwards. Use a disposable machine because interrupted runs or operating-system restrictions can prevent cleanup.

For Claude Code, supply the absolute executable path if it is not on root's PATH:

```bash
sudo env CLAUDE_BIN=/absolute/path/to/claude "$(command -v node)" scripts/live-scenarios.mjs --host claude-code --run
```

For Codex, supply the absolute path to its native binary:

```bash
sudo env CODEX_BIN=/absolute/path/to/native/codex "$(command -v node)" scripts/live-scenarios.mjs --host codex --run
```

Replace the example path before running. The test host and hook run as root unless you set `MAGO_LIVE_USER` to an existing unprivileged account, in which case `setpriv` and `chown` are required. Codex's unprivileged sandbox also needs `bwrap` and working user namespaces. For example, add `MAGO_LIVE_USER=mago-live` after `sudo env` when that account already exists. The gate remains root. The runner does not create the account.

The command prints a JSON report. Add `--json` to suppress progress messages on stderr. No result is uploaded automatically. If a prerequisite or permission is missing, the runner reports a skip or an incomplete run; do not change the real machine's managed settings to work around it.

## What each experiment does

### 1. Use an approved Skill

1. The harness makes a temporary organization, approves a synthetic Skill and installs it in the temporary gate.
2. It starts a fresh host process and asks it to use the Skill: Claude Code through its Skill tool, Codex through a linked mention.
3. It looks for the Skill's marker at the local endpoint. The scenario passes when the marker reaches that endpoint.

### 2. Try an unapproved Skill

1. The harness puts a different synthetic Skill in the test project without approving or installing it through the gate.
2. It asks the fresh host to use that Skill: a Skill tool call for Claude Code or a typed project-Skill mention for Codex.
3. It looks for a refusal and checks that the unapproved Skill's marker did not reach the endpoint. A missing marker alone does not prove a refusal.

### 3. Revoke an approval

1. The harness installs a second approved sample Skill and revokes its approval in the temporary trust documents.
2. Claude Code attempts to use the Skill in the test session after revocation. Codex starts a new test session and attempts the linked mention.
3. The checks look for the expected refusal and absence of the marker; Codex also checks that the managed link was removed. This scenario uses enforce mode. Shadow mode does not uninstall revoked Skills.

### 4. Stop the gate

1. The harness installs the approved sample Skill and stops only the temporary gate service.
2. It asks a fresh host process to use the installed Skill.
3. It checks that the tested hook path refuses the attempt and the marker does not reach the endpoint. This does not test a host menu selection or a hook process crash or timeout.

## Read the report

- **PASS**: all checks for that scenario were observed.
- **FAIL**: the runner observed a result that disagrees with the expected checks.
- **SKIP**: a required platform, binary, privilege or dependency was unavailable.
- **INCONCLUSIVE**: the run did not provide enough evidence, for example when the host failed to start or a report was incomplete.

The report identifies the host, version when available, test account, checks and cleanup status. A non-pass exits nonzero. The runner omits raw host transcripts from its report and does not retain temporary keys intentionally. If a run is interrupted or cleanup is incomplete, inspect the disposable machine before running it again. Do not publish temporary keys or raw logs.

## Limits

These cases test specific non-interactive paths with synthetic data and a scripted endpoint. They do not establish what an interactive Codex menu, IDE/app-server input, a real model response, or a killed or timed-out hook will do. A successful run is evidence for the tested paths, host version and machine; it is not a claim that a Skill is safe.

## Instructions for the guiding agent

1. Read this guide and identify the host, operating system, Node version, host binary and build status. Show the plan first.
2. Do not silently install software, select a different binary, bypass a failed prerequisite, or modify production managed configuration. Explain the root command and let the user authorize any privileged action through the host's normal permission mechanism.
3. Run the four experiments only in a suitable disposable environment. Report each status and the actual checks; never turn a skip, an incomplete report or an absent observation into a pass.
4. Explain cleanup status and the limits above. Do not include private keys, real prompts or raw transcripts in the response.
