# Design: the company gate in the mago-ski command (0.4.0, stream 1)

Status: v1, for Goldfish review.

## Problem

The company gate is built and live-tested, but a user of a released version cannot switch it on. The gate is the root service that installs approved Skills and answers the Claude Code and Codex hooks (`src/gate/`).

- `mago-ski` has no command to set it up, start it or talk to it.
- There is no service unit, no hook or host configuration written for the administrator, and no setup guide.

Today only the live tests (`tests/live/gate-world.ts`) wire it together, by hand.

0.4.0 must let an administrator go from a released `mago-ski` to an enforcing gate for Claude Code and Codex on Linux with documented commands.

## Scope

- **In:** Linux, root-run service, Claude Code and Codex.
- **Out:**
  - macOS and Windows (`assertGatePlatform` refuses them, and `gate` commands say so);
  - Pi (it has its own extension) and other harnesses.
- **Codex.** The Codex-specific hardening is stream 2 (`docs/design/codex-full.md`, after its research spike). This design leaves the Codex host's extra files as a named hook point (§4).

## Technical plan

### 1. One gate instance per host

`GateServiceConfig` has one `managedDir`, and the two hosts load admin Skills from different folders:
- Claude Code reads `/etc/claude-code/.claude/skills`;
- Codex reads `/etc/codex/skills`.

So each host gets its own instance, named by host: `claude-code` or `codex`.

| Path | Holds |
|---|---|
| `/etc/mago-ski/gate/<host>.json` | instance config (root-owned, `0644`) |
| `/etc/mago-ski/gate/<host>-hook.json` | hook config, read by the hook (format of `loadConfig`, `src/gate/adapters/claude-code.ts:72`) |
| `/var/lib/mago-ski/gate/<host>/state` | service state directory, `0700` |
| `/var/lib/mago-ski/gate/<host>/generations` | generation store |
| `/run/mago-ski/gate/<host>/` | sockets: `decision.sock` (`0666`) and `admin.sock` (`0600`) |

- **Unit.** Each instance is a systemd template unit, `mago-ski-gate@<host>.service`.
- **Trust.** Both instances trust the same organisation: the same root fingerprint and the same trust documents.

### 2. The instance config file

The file is canonical JSON with these exact keys, read by `gate run` and by the admin commands:

```json
{ "v": 1, "host": "claude-code", "mode": "shadow",
  "root_fingerprint": "sha256:…", "host_exes": ["/usr/bin/claude"],
  "state_dir": "/var/lib/mago-ski/gate/claude-code/state",
  "generations_dir": "/var/lib/mago-ski/gate/claude-code/generations",
  "managed_dir": "/etc/claude-code/.claude/skills",
  "socket_dir": "/run/mago-ski/gate/claude-code",
  "inbox_dir": null, "build_id": "mago-ski 0.4.0" }
```

`gate run` maps it to `GateServiceConfig`:
- `decisionSocketDir` and `adminSocketDir` are both `socket_dir`;
- `rootUid` is 0;
- `inboxDir` is used only when `inbox_dir` is set.

Unknown keys or a wrong type are refused. The file must be root-owned and not group- or world-writable.

### 3. Commands

All commands are under `mago-ski gate`. Every command except `--help` refuses to run on a non-Linux platform, with the `assertGatePlatform` message. Every command except `status` and `doctor` refuses to run when not root: `the gate is administered as root; run this with sudo`.

| Command | Does |
|---|---|
| `gate init --host H --root-fingerprint ID [--mode shadow\|enforce] [--host-exe PATH] [--inbox DIR] [--force]` | Writes or rewrites the instance config, the hook config and the host's managed configuration (§4). Creates the state, generations, managed and socket directories with root ownership and the modes above. Writes the systemd unit file (§5). Re-running is the way to change mode or host binary. Prints the files written and the next commands. |
| `gate run --host H` | Foreground service for systemd: loads the instance config, `createGateService(...)`, `start()`, stops on SIGTERM/SIGINT, exits non-zero if start fails, with the error. |
| `gate trust --host H --trust-root FILE --revocations FILE` | Sends `accept-trust` to the admin socket (base64 of both files). Prints the result. |
| `gate install --host H SKILL_DIR --certificate FILE [--name NAME]` | Sends `install`. `NAME` defaults to the folder name. |
| `gate uninstall --host H NAME` | Sends `uninstall`. |
| `gate refresh --host H` | Sends `refresh` (re-reads the inbox). |
| `gate status --host H` | Sends `status` and prints it, as JSON with `--json`. When not root, it says that status needs root, because the admin socket is `0600`. |
| `gate doctor --host H` | Read-only checks (§6). Prints one PASS or FAIL line per check, and exits 1 if any check fails. |

- **Admin socket client.** A new module, `src/gate/admin-client.ts`, sends one request line on the admin socket and reads one reply line, mirroring `serveOnce`, with a 60 s deadline. Errors map to exit 2.
- **Output.** Commands print JSON with `--json`, or one short line per fact otherwise, as other commands do (`src/cli.ts` `print()`).

### 4. Host configuration written by `gate init`

| | Claude Code (`--host claude-code`) | Codex (`--host codex`) |
|---|---|---|
| Host binary default | `realpath(which claude)` | `realpath(which codex)` |
| Managed folder | `/etc/claude-code/.claude/skills` | `/etc/codex/skills` |
| Host config file | `/etc/claude-code/managed-settings.json` from `claudeCodeManagedSettings(...)` | `/etc/codex/requirements.toml` from `codexRequirementsToml(...)`, extended by stream 2 |
| Hook entry | `<install>/dist/src/gate/adapters/claude-code-hook.js` | `<install>/dist/src/gate/adapters/codex-hook.js` |

- **Hook entry location.** `<install>` is the root of the installed package, resolved from `import.meta.url`. `gate init` refuses if the hook entry, `process.execPath` (the node used for the hook) or any of their parent folders is not root-owned and non-writable by group and others. A hook an employee can edit would be a bypass.
- **Existing host files.** `gate init` will not overwrite a host config file it did not write. Files it writes carry a marker: for Claude Code a top-level `"_mago_ski": "gate 0.4.0"` key, if the settings schema allows unknown keys (to verify in implementation), and for Codex a first-line TOML comment `# written by mago-ski gate`. Without `--force`, a foreign file is refused with `<path> exists and was not written by mago-ski; merge it by hand (mago-ski gate init --print) or pass --force`.
- **`--print`.** Prints every file `gate init` would write, and writes nothing.
- **Timeouts.** `hookTimeoutSec` is 5 and `selfDeadlineMs` is 3000, the values the live tests ran with. `clientDeadlineMs` is 1500.
- **Codex.** Its requirements need the per-user Skill roots, and stream 2 decides how they are handled. Until then, `gate init --host codex` writes what `codexRequirementsToml` writes today, with an empty `userSkillRoots`. Stream 2 replaces this step.

### 5. Service unit

The repository gains `packaging/systemd/mago-ski-gate@.service`:

```ini
[Unit]
Description=mago-ski gate for %i
After=local-fs.target

[Service]
Type=simple
ExecStart=/usr/bin/env mago-ski gate run --host %i
Restart=on-failure
RuntimeDirectory=mago-ski/gate/%i
RuntimeDirectoryMode=0755
LimitNOFILE=4096
ProtectSystem=full
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
```

- **Installing it.** `gate init` writes it to `/etc/systemd/system/mago-ski-gate@.service`, with `ExecStart` set to the absolute path of the installed CLI. It does not run `systemctl`; it prints `systemctl enable --now mago-ski-gate@<host>`.
- **Why these settings.**
  - `LimitNOFILE=4096` meets the service's descriptor requirement (`service.ts` DEPLOYMENT REQUIREMENTS).
  - `ProtectSystem=full` keeps `/usr` read-only, but `/etc` and `/var/lib` writable.
- **Sockets.** The socket folder is the unit's `RuntimeDirectory`, so systemd creates it as root, `0755`.

### 6. `gate doctor` checks

The checks run in this order:
1. **Platform:** it is Linux.
2. **Instance config:** it exists, is root-owned and parses.
3. **Host binaries:** each one exists and is root-owned, and neither it nor its folders are writable by others.
4. **Hook entry and node:** as `gate init` checks them.
5. **Managed folder:** it exists, is root-owned and not group- or world-writable.
6. **Host config file:** it exists and is root-owned. Its content equals what `gate init` would write now for this config, ignoring the marker.
7. **Service:** the decision socket exists, and a `status` request answers. When not root, this check reports `SKIP (needs root)`.
8. **Trust:** `status` reports that trust is accepted and not expired.
9. **Mode:** it prints the mode. A `shadow` mode is a note, not a failure.

### 7. Docs

- **`docs/gate-setup.md` (new).** The administrator's guide: install, `gate init` per host, `gate trust`, approving and `gate install`, `doctor`, trial (`shadow`) then `enforce`, updating trust and revocations (the inbox, or `gate trust`), uninstalling.
- **`docs/hosts/claude-code.md` and `docs/hosts/codex.md` (new).** What is enforced on each host, the known limits, and the tested versions.
- **`README.md`.** "Where it runs" gains Claude Code and Codex rows, and the claims follow stream 2's outcome.
- **`docs/capabilities.md`.** The company gate moves to "works today" (0.4.0).
- **`CHANGELOG.md`** and the CLI help.

Docs are written by a separate subagent from the planner's ranked notes (process rule for 0.4.0).

## Alternatives considered

- **One service for both hosts.** Rejected for now: `GateServiceConfig` has one `managedDir`, and two instances keep each host's state, sockets and failures apart. Revisit if the overhead matters.
- **A `.deb` or `.rpm` package.** Deferred. An npm install plus `gate init` and a shipped unit file covers the first release, and packages can wrap the same commands later.
- **`gate init` running `systemctl` itself.** Rejected. An administrator should see and run the enable step, and some machines do not use systemd.

## Implementation plan

1. **`src/gate/instance.ts` (new):**
   - `InstanceConfig` type;
   - `readInstanceConfig(file)`;
   - `instanceToServiceConfig(cfg)`;
   - `instancePaths(host)`;
   - `HOSTS = ['claude-code', 'codex']`.
2. **`src/gate/admin-client.ts` (new):** `askAdmin(socketPath, command, deadlineMs)`.
3. **`src/gate/setup.ts` (new):**
   - `planInit(opts)`, which returns the list of `{ path, content, mode }` and the folders to create, with no writes;
   - `applyInit(plan, { force })`;
   - `checkRootOwnedChain(path)`;
   - `doctor(host)`.
4. **`src/cli.ts`:** the `gate` subcommands, their help text and their place in the main help (a "COMPANY GATE (Linux, root)" section).
5. **`packaging/systemd/mago-ski-gate@.service`.** Add `packaging/` to `package.json` `files`.
6. **Tests.**
   - `tests/gate-cli.test.ts`: `planInit` output for both hosts (golden file contents); refusal of foreign host files without `--force`; `--print` writes nothing; instance-config validation; admin client round trip against a started test service; `doctor` against a test layout (`rootUid` = test uid); the non-Linux refusal.
   - The live tests (`tests/live/*.live.ts`) switch to `planInit` and `applyInit`, so the commands shipped are the ones tested live.
7. **Docs** as in §7.

## Decisions (v2)

These decisions resolve the v1 Goldfish review (B1–B11 and the minor points). Where they differ from v1, v2 wins.

### G1. Sockets (B1)

- **Two directories.**
  - The instance config has `decision_socket_dir` = `/run/mago-ski/gate/<host>`. This is the unit's `RuntimeDirectory`, mode `0755`, and holds `decision.sock` (`0666`).
  - It also has `admin_socket_dir` = `/run/mago-ski/gate/<host>/admin`, which `start()` creates at `0700` and which holds `admin.sock` (`0600`).
- **Mapping.** `gate run` maps them to `decisionSocketDir` and `adminSocketDir`. The hook config's `socket` is `<decision_socket_dir>/decision.sock`. `gate init` does not create the run directories; systemd and `start()` do.

### G2. Unit hardening (B2, B3)

**`ExecStart`.** `gate init` writes the unit with `ExecStart=<process.execPath> <realpath of <install>/dist/src/cli.js> gate run --host %i`. It uses the same `node` as the hooks, and does not go through `env` or `PATH`.

**The template** (`mago-ski-gate@.service`) uses `ProtectSystem=strict`, `NoNewPrivileges=yes`, `LimitNOFILE=4096`, `Restart=on-failure`, `RuntimeDirectory=mago-ski/gate/%i` and `RuntimeDirectoryMode=0755`.

**Per host.** `gate init` also writes a drop-in, `/etc/systemd/system/mago-ski-gate@<host>.service.d/paths.conf`, with:
- `ReadWritePaths=/var/lib/mago-ski/gate/<host> <managed_dir>`;
- `ReadOnlyPaths=/etc/mago-ski` (a no-op under `strict`, stated for clarity).

**Unit text in code.** The unit and drop-in text is generated in code (`setup.ts`) and golden-tested. There is no `packaging/` folder, and `package.json` `files` is unchanged.

### G3. Paths with `@` (B4)

- `SAFE_PATH` in `claude-code-settings.ts` and `codex-requirements.ts` becomes `^\/[A-Za-z0-9._/@-]+$`. `@` is inert unquoted in `sh` and `bash`.
- Golden tests cover an `/usr/lib/node_modules/@mago-foundation/mago-ski/...` hook path for both generators.

### G4. Whole-tree trust check (B5)

- **The check.** `checkRootOwnedTree(dir, uid)` requires that every entry under `<install>/dist`, and every parent folder up to `/`, is owned by `uid` and not writable by group or others. Symlinks inside the tree are refused.
- **`process.execPath`** and its parent chain get the same treatment.
- **Where it runs.** `gate init` refuses on any failure. `doctor` repeats the check (step 4).
- **The message names the first bad path:** `<path> must be owned by root and not writable by others: an editable hook file would let a user bypass the gate`.

### G5. Ownership manifest, no in-file marker (B6, B7)

- **The manifest.** `gate init` writes `/etc/mago-ski/gate/<host>.manifest.json` as canonical JSON: `{ "v": 1, "files": [{ "path": "...", "sha256": "sha256:..." }] }`. It covers every file `gate init` wrote, the manifest itself excluded.
- **Ownership.** A host config file is "ours" when its current SHA-256 equals the manifest's. Host files carry no marker.
- **Foreign files.** `planInit` lists every existing file that is not ours, and the command refuses **before the first write**, naming all of them.
  - **With `--force`,** each foreign file is renamed to `<path>.mago-ski-bak-<YYYYMMDDTHHMMSSZ>` before writing. A failed rename stops the command. Both paths are printed.
- **`doctor`'s host file check** (step 6) compares the file's SHA-256 with what `planInit` would produce now.

### G6. Start errors are visible (B8)

- **`start()`.** When it catches a store or directory error, it keeps it as `startError: string`.
- **`status`.** When the service is not ready, `status` returns `{ ok: false, error: 'service is not ready: <startError>' }`. `gate run` also prints `startError` to stderr when start finishes not ready.
- **`gate init`** creates every directory with parents: parents are root-owned `0755`, and each leaf gets its stated mode.
- **`doctor`:**
  - It passes the service check only when `status` returns `ok: true` and `ready: true`.
  - It runs the root-owned chain check on `state_dir`, `generations_dir`, `managed_dir`, both socket directories (once they exist) and `/etc/mago-ski/gate`. The service header's deployment requirements become checked facts.
  - It also checks that `net.core.somaxconn` is at least 1024, and that `/proc` is not mounted with `hidepid`, as warnings.
  - It FAILs when the mode in `status` differs from the instance config, or from the mode in the host config file.

### G7. Test seams (B9)

- **Seam parameters.** `instancePaths(host, base = '/')`, `planInit(opts & { base?, rootUid?, platform? })`, `applyInit(plan, { force, base, rootUid })`, `doctor(host, { base, rootUid, platform, ask? })` and `checkRootOwnedTree(path, uid)`.
- **Defaults.** Production uses `base = '/'` and `rootUid = 0`. Tests pass a temporary base and `process.getuid()`.
- **`ask`** is the admin-client seam.

### G8. CLI parsing (B10)

- `--force` and `--print` join `BOOLEAN_FLAGS`.
- `gate` joins `hasSub`.
- `COMMAND_HELP` keys are `gate init`, `gate run`, `gate trust`, `gate install`, `gate uninstall`, `gate refresh`, `gate status` and `gate doctor`.
- The main help gains a `COMPANY GATE (Linux, run as root)` section.

### G9. What 0.4.0 stream 1 claims for Codex (B11)

Stream 1 ships the Codex host as **audit-level** until stream 2 lands:
- `gate init --host codex --mode enforce` is refused with `Codex enforcement is not complete yet (see docs/hosts/codex.md); use --mode shadow`. Stream 2 removes this refusal when it closes the gaps.
- The help text and `docs/hosts/codex.md` say so.

The 0.4.0 release claim "Codex, full" depends on stream 2, not on this stream.

### G10. Exact contracts (minor points)

**Admin requests**, one JSON line in and one JSON line out:

| Command | Request fields | Notes |
|---|---|---|
| `status` | `{ v: 1, cmd: 'status' }` | |
| `refresh` | `{ v: 1, cmd: 'refresh' }` | Without an inbox, the reply is `no inbox configured`, and the CLI prints it and exits 2. |
| `accept-trust` | `trust_root_b64`, `revocations_b64` | |
| `install` | `skill_name`, `source_dir` (absolute; the CLI resolves it), `certificate_b64` | |
| `uninstall` | `skill_name` | |

Replies are `{ v: 1, ok: true, … }` or `{ v: 1, ok: false, error }`.

**The hook config** is exactly `{ "v": 1, "socket": "<decision>/decision.sock", "mode": …, "host_exes": [...], "client_deadline_ms": 1500, "self_deadline_ms": 3000 }`. For Codex, the generator's extra keys are appended.

**Exit codes:**
- 0: success;
- 1: a doctor FAIL, or the service answered `ok: false`;
- 2: a usage, input or transport error.

`gate run` exits 1 when `start()` throws.

**Doctor output.** One line per check, `PASS|FAIL|SKIP|WARN <check>: <detail>`. SKIP and WARN never fail the run. With `--json`, the output is `[{ check, result, detail }]`.

**Smaller rules:**
- `--mode` defaults to `shadow`.
- A re-run of `gate init` prints `systemctl daemon-reload && systemctl restart mago-ski-gate@<host>`.
- A changed `--root-fingerprint` is written as given. Trust documents for the old root are then refused by the trust store, and `doctor` reports trust as not accepted until `gate trust` runs with the new documents.
- **Host binaries.**
  - The default is resolved with the invoking user's `SUDO_USER` login `PATH` when present, otherwise root's.
  - It must be root-owned, not writable by others, and an ELF executable, because a script would allowlist its interpreter.
  - It is refused otherwise, with a message saying to pass `--host-exe`.
- **The admin client deadline** is 65 s. On a timeout it says `the gate did not answer in time; run mago-ski gate status`.
- **Version.** `build_id` comes from `package.json` (`mago-ski <version>`), not a constant.
- **`gate install`** prints the digest and the managed path.

### G11. Docs additions

- **`docs/gate-setup.md` starts with a warning:**
  - enforce mode changes Claude Code for every user of the machine, because it applies the managed locks (managed hooks only, strict plugin customisation, no bundled Skills, plugins off);
  - Node must be installed system-wide and root-owned, so a per-user Node (nvm, volta) is refused by design.
- **`docs/hosts/claude-code.md`** names the tested version (2.1.318) and the interactive-session status (stream 4).

## Decisions (v3)

These decisions resolve the v2 confirmation. Where they differ from v1 or v2, v3 wins.

1. **Shared files (N1).** The template unit `mago-ski-gate@.service` is shared by both hosts. It is recorded in a shared manifest, `/etc/mago-ski/gate/shared.manifest.json`, with the same format as G5. A file counts as ours when its SHA-256 matches its entry in either the host's manifest or the shared manifest. Re-running `gate init` for either host rewrites the template, because it is identical for every host, and updates the shared manifest.
2. **Folder modes (N2).** Each leaf folder gets its own mode:

   | Folder | Mode |
   |---|---|
   | `state_dir` | `0700` |
   | `generations_dir` | `0755` |
   | `managed_dir` | `0755` |
   | `/etc/mago-ski/gate` | `0755` |

   Hosts run as the employee and must be able to follow `managed_dir` links into `generations_dir`. `generations.ts` already makes their contents `0555` and `0444`.
3. **Write order and failure (B7).** `applyInit` works in this order:
   1. Compute the whole plan, and refuse on any foreign file unless `--force` is given.
   2. With `--force`, rename the foreign files aside.
   3. Create the folders.
   4. Write each file with `writeFileAtomic`, in this order: instance config, hook config, unit and drop-in, then the host config file **last**.
   5. Write the manifests last of all.

   If a write fails after a foreign file was renamed aside, `applyInit` renames that file back before exiting non-zero. The host is then never left without its config. A file from a failed run is not in the manifest, so the next run treats it as foreign, and the message says to use `--force` after checking it.
4. **Test seam for the trust check (B9).**
   - `checkRootOwnedTree(path, uid, stopAt = '/')` stops walking parents at `stopAt`. Production passes `/`. Tests pass their temporary base, and skip the `process.execPath` chain with `checkExec: false`.
   - Service and doctor tests are marked `skip: LINUX_ONLY`.
   - Pure planning tests (`planInit` output, refusals, manifest logic) run on every platform, because `planInit` takes `platform` as a parameter.
5. **`gate run` when not ready (B8).** It stays up and is not ready: `start()` keeps listening, as today, so `status` can report `startError`. It prints the error once to stderr at start. It exits 1 only when `start()` throws.

   `doctor` fails the service check unless `ok`, `ready` and `log.state === 'ready'` are all true.
6. **Codex hook config.** It adds `admin_root` (= `managed_dir`) and `skill_roots` (`[]` until stream 2) to the shared keys. These are the keys `codex.ts` `loadCodexConfig` reads.
7. **`--host-exe`.** It can be repeated, and its values form `host_exes`.
8. **`ExecStart` paths.** The paths must match `SAFE_PATH` (G3), so they need no quoting. `gate init` refuses otherwise.
9. **Help.** A bare `mago-ski gate` or `mago-ski gate --help` prints the gate command list.
10. **Version and packaging.** `build_id` reads `package.json`. The version bump to 0.4.0 belongs to the release PR, not to this stream. `docs/gate-setup.md` is a repository doc, not a packaged file.
11. **Docs scope for Codex (B11).** Stream 1's docs describe the Codex host as audit-level, and `capabilities.md` keeps "Blocking in Claude Code and Codex" under *Built, not released* for Codex. Claude Code moves to *works today*. Stream 2 rewrites the Codex wording from its own design.
12. **Further `doctor` checks.** `doctor` also checks `<install>/package.json` and `/usr/bin/env` with the same ownership rule (B5 residual).

## Code review fixes (v4)

These fixes come from the two Goldfish code reviews of `215aad6..508fbd8`. Neither review found a HIGH. Where these fixes differ from earlier sections, they win.

1. **Host binary choice (security M1, M2, L1, L2).**
   - The `SUDO_USER` login-`PATH` lookup is removed.
   - The default host binary is `claude` or `codex` from root's own `PATH`. If none is found, `--host-exe` is required.
   - A binary is accepted only if it is a root-owned ELF executable whose realpath's basename starts with `claude` or `codex`. A binary named otherwise needs an explicit `--host-exe`.
   - `checkHostExe` reads only the first 4 bytes, through a file descriptor, after the owner check.
   - `gate init` prints the chosen `host_exes` in its summary.
2. **Rollback and the fail-open window (security M3, L9, L8, L10, L12).**
   - **Before any rename or write,** `applyInit` checks every planned folder and its existing ancestors (item 3).
   - **Backups.** A foreign file is first hard-linked to its backup path. The new content is then written with `writeFileAtomic`, whose atomic rename replaces the original in one step. The host never lacks a config file, even if the command is killed.
   - **Rollback after a failure.** The command restores a backup only over a path this run did **not** already write. It then reports exactly which files are new, which are restored and which stay as backups.
   - **Manifest paths** are included in foreign-file detection.
   - **The shared manifest** merges entries instead of overwriting.
3. **Folder ownership (security M4, correctness 1, L11).**
   - **Planned folders.** Before any write, `applyInit` runs `checkRootOwnedChain` on every planned folder that exists, and on each folder's existing ancestors. A folder that is not owned by root, or is writable by group or others, is refused, and is not chmodded.
   - **Mode changes** are made with `fchmod` on an open descriptor.
   - **Service start.** `service.start()` also checks `generationsDir` with `ownedDir`, at `0755`, not strict.
   - **Manifests** are read only if they are root-owned regular files.
4. **`gate run` after a failed start (correctness 2).** When `start()` throws, `gate run` calls `service.stop()` before returning 1, so no listener keeps the process alive.
5. **Trusting the socket (security L4).** `doctor` and the admin commands check that the admin socket folder is root-owned `0700`, and that the socket is a socket owned by root, before connecting. `doctor` skips the service queries when the folder checks fail.
6. **`doctor` coverage (security L5).**
   - It compares the unit and drop-in content with the plan.
   - It checks the hook config and the instance config with `lstat`: a root-owned regular file, not a symlink.
   - `status` gains `root_fingerprint`, and `doctor` FAILs when it differs from the instance config.
7. **Library surface (security L6).** `src/index.ts` does not export `runCli`'s gate seams. Tests import them from `src/cli.ts` directly.
8. **Exit codes and messages (security L7; correctness 5, 6, 7, 9).**
   - `gate init --print` exits 1 when the plan has problems that `init` would refuse, after printing everything.
   - A missing instance config gives `no gate instance for <host>; run mago-ski gate init --host <host>`, with exit 2.
   - `gate status` exits 1 when `ready` is not true, as its help says.
   - The unreachable JSON branch in `gate install` is removed.
   - `buildId()` throws when `package.json` cannot be read, instead of writing `unknown`.
9. **Gate-only flags (correctness 8).** `--force` and `--print` are accepted only by `gate init`. Every other command refuses them, as before 0.4.0.
10. **Tests (correctness 3, 4, and review item i).**
    - **Ownership.** A chain owned by another uid is refused. `doctor` FAILs with `rootUid + 1`. An existing `state` folder at `0755` becomes `0700`. A user-owned existing folder is refused before any write.
    - **Rollback.** A `--force` rollback test asserts the final content of each file. A rename-before-check test is added.
    - **Host binaries.** Choosing the host binary covers a `python3` symlink named `claude` (refused without `--host-exe`) and the printed `host_exes`.
    - **Live tests.** `tests/live/*.live.ts` switch to `planInit` and `applyInit` with a temporary `base` inside the existing private mount namespace, so the shipped commands are the ones tested live. If the whole-tree ownership check cannot be met in the live layout, the live harness passes `checkExec: false` only for the repository's own source tree, and says so in its header.
