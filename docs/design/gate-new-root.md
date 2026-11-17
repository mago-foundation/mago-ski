# Design: moving a gate to a new root (0.4.0)

Status: v1, implemented on `feat/0.4.0-gate-new-root`, for review. It replaces one sentence of [`gate-cli.md`](gate-cli.md) ("A changed `--root-fingerprint` is written as given. … until `gate trust` runs with the new documents"), which did not hold.

## Problem

An organisation replaces its root key with a rotate root event ([root recovery](../spec/root-recovery-v1.md)) and re-signs its trust root and revocation list with the new key (`mago-ski root adopt`). The CLI, the Pi host and the GitHub Action follow the event. The gate does not read root events: it keeps the root fingerprint it was given at `gate init`.

Before this change there was no working way to move a gate to the new root:

- `gate init` with the new fingerprint was accepted and written.
- After the restart, the trust store opened the documents it had committed under the old root, checked them against the new fingerprint, and reported `state-corrupt`.
- `gate trust` with the new documents was then refused: `existing trust state is corrupt; an administrator must reset it`. There was no reset command.
- In enforce mode every Skill was blocked, and reconcile hid every installed Skill.

The only way out was to delete `<state>/trust` by hand as root.

This design covers the move only. Reading root events and timestamps in the gate (so that it follows a rotation or a revocation by itself) stays a later piece of work.

## Decisions

### N1. One trust store per root

The trust store's folder is `<stateDir>/trust/<64 hex of the root fingerprint>` instead of `<stateDir>/trust`. `trustStoreDir(stateDir, rootFingerprint)` in `src/gate/service.ts` builds the path and refuses a fingerprint that is not `sha256:` plus 64 lower-case hex characters. The service creates `<stateDir>/trust` as a root-owned `0700` folder and opens the per-root folder with `openTrustStore`, which is unchanged.

Consequences:

- A gate started with a new root finds an empty store (`no-state`), not a corrupt one, and `gate trust` works.
- Nothing is deleted or moved. The old root's documents and its rollback memory stay where they were. A mistaken move is undone by moving back, and the gate then refuses anything older than what it had already accepted under that root.
- Rollback memory is per root key. This matches the engine's host state, which keeps its minimum versions per root key id.

### N2. A changed root is never silent

`gate init` reads the installed instance config. When its `root_fingerprint` differs from `--root-fingerprint`:

- without `--new-root`, init refuses and writes nothing: `this gate is set up for root <old>, not <new>; check the fingerprint, or pass --new-root to move the gate to the new root (after a root rotation). Until the new root's documents are sent with gate trust, enforce mode blocks every Skill`;
- with `--new-root`, the plan carries `rootChange: { from, to }`. `--print` shows it as a note, the summary prints one line, and `--json` has `root_change`.

`--new-root` with an unchanged fingerprint, or with no installed instance, is refused. An instance config that cannot be read gives nothing to compare with, and the run is treated like a first one, as before.

Why a flag when N1 already makes the move harmless to the stored state: a mistyped fingerprint in enforce mode would otherwise block every Skill after the restart, with no warning at the moment of the mistake.

### N3. Between the restart and `gate trust`

After the restart the new root has no documents, so trust is not ready. This is the existing fail-closed behaviour, unchanged:

- enforce: every use is blocked, and reconcile hides the installed Skills;
- shadow: nothing is blocked, and reconcile logs what it would have hidden.

When `gate trust` (or the inbox) delivers the documents signed by the new root, reconcile restores every installed Skill that is servable. Installs are not repeated: a certificate is signed by an approver, and `root adopt` keeps the approvers.

The administrator's steps, in order:

```bash
sudo mago-ski gate init --host H --root-fingerprint sha256:<new> --new-root   # plus the options of the original init
sudo systemctl daemon-reload && sudo systemctl restart mago-ski-gate@H
sudo mago-ski gate trust --host H --trust-root trust-root.json --revocations revocations.json
sudo mago-ski gate doctor --host H
```

`gate doctor`'s trust line names this case when the store is empty.

### N4. A store from before the per-root layout is carried over, or the start fails closed

A machine set up with a build from before N1 has its documents and manifest directly in `<stateDir>/trust`. Ignoring them would reset rollback protection even though the root did not change: the per-root store would start empty and accept an older, still valid trust root or revocation list, including one from before a revocation.

At start, before the store is opened, `migrateFlatTrustStore` (`src/gate/trust-store.ts`) looks at `<stateDir>/trust`. Per-root stores are folders; any other entry is the old store.

- **The old state verifies under the configured root, and the per-root store is empty.** The documents are copied, then the manifest (the commit point), with the same versions and the same highest trusted time. The copy is read back and verified, and only then are the old files removed, manifest first. A stop in between is finished at the next start.
- **Both hold state** (a build with N1 ran before this one and documents were accepted). The state that is at least as new in both documents is kept, with the later trusted time. So a per-root store that was filled with older documents after the upgrade is replaced by the state from before it.
- **Anything else: the service does not open a trust store.** This covers an old state that does not verify under the configured root (it belongs to another root, or is damaged), documents with no manifest, and two states that are each newer in one document. `gate status` reports the reason, enforce mode blocks every Skill, and `gate trust` is refused. The ways out are named in the message: start once with the root the old state belongs to, or remove the files (not the folders) in `<stateDir>/trust` to give that state up.

## What this does not do

- **The gate does not follow root events.** Each machine is moved by an administrator (or a fleet tool running the four commands). A root key that was revoked, and not yet replaced on a machine, is still the gate's root there.
- **The new root starts with empty rollback memory.** Until the first accepted documents set the minimum, the gate would accept any document pair validly signed by the new root, including an early one. Only documents signed after the adoption exist, and only root or the organisation's inbox can deliver them, so the window is small. Carrying the old root's version numbers forward as a floor was considered and left out: it would add a second kind of state to the trust store, and it would lock out an organisation that re-creates its documents from version 1.
- **There is no record of the move in the decision log.** The move is visible in `gate status` (`root_fingerprint`), in the instance config, and as `hide-all:trust-no-state` and `restore` reconcile records in enforce mode.
- **Old per-root folders are never removed.** They are small (two documents and a manifest).

## Tests

`tests/gate-new-root.test.ts`:

- `trustStoreDir` shape, and refusal of malformed fingerprints (upper case, short, a path separator).
- A rotation end to end with the real service: install under the old root; `root adopt` with a new key; restart with the new root gives `no-state`; the old documents are refused; the adopted documents are accepted; the Skill installed before the rotation is `VERIFIED` again without a re-install; both per-root folders exist; a restart under the old root is `ready`.
- Enforce mode: after the move reconcile hides the installed Skill, and restores it once the new documents are accepted.
- `planInit`: refusal without the flag (nothing written), the root change with it, refusal of `--new-root` with the same root or with no instance, and an ordinary re-run afterwards.
- The CLI: refusal text, the `--print` note and exit code, the summary line, `root_change` in `--json`, and that `--new-root` is refused by other gate commands.
- Migration (N4): an old flat store keeps its versions (an older list is still refused after the upgrade) and its trusted time; a per-root store filled with older documents is replaced; a newer per-root store is kept; a flat store of another root, or documents without a manifest, stop the start and keep the old files.
