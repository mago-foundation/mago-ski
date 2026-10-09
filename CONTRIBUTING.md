# Contributing to mago-ski

Thanks for helping. mago-ski is security tooling: it decides whether an agent host may load a Skill. Contributions are welcome, and they are held to that standard. Please read this guide before opening a pull request.

## Reporting security issues

**Do not open a public issue for a vulnerability.** Report it privately through GitHub's private vulnerability reporting (the repository's **Security** tab → **Report a vulnerability**). Examples: any input that makes the verifier return `VERIFIED` when it should not, a way for a pull request to change who is trusted in the GitHub Action, a way for an unverified Skill to reach the model in Pi enforce mode, or exposure of key material. Limits already listed in [docs/threat-model.md](docs/threat-model.md) are known and are not vulnerabilities on their own.

## Requirements

| Who | Node.js | Why |
|---|---|---|
| Users of the published package | **22.0 or newer** (`engines` in `package.json`) | The package ships compiled JavaScript in `dist/` |
| Contributors | **22.18 or newer** | Tests, scripts and the GitHub Action run the TypeScript sources directly with Node's built-in type stripping, which is on by default from 22.18 |

Supported platforms are **Linux and macOS**. Windows is not supported in 0.1 (it has no POSIX executable bit; see the [digest spec](docs/spec/skill-tree-v2.md)), and npm refuses to install the package there.

## Getting started

```bash
git clone https://github.com/mago-foundation/mago-ski
cd mago-ski
git switch dev
npm ci --ignore-scripts
npm run check        # type-check and run every test
bash examples/demo.sh
```

| Command | Does |
|---|---|
| `npm run typecheck` | `tsc --noEmit` over sources, hosts, tests and scripts |
| `npm test` | All tests with `node --test`, straight from the `.ts` sources |
| `npm run check` | Both of the above. This is the merge baseline |
| `npm run build` | Compiles to `dist/` (what the published package ships) |
| `node src/cli.ts --help` | Runs the CLI from source |
| `node scripts/vectors.ts --write` | Regenerates `tests/vectors/` after a format change |

One test needs the official, checksum-pinned Cosign v3.1.3 binary and is skipped without it: set `MAGO_COSIGN_BIN` to run it.

## Project layout

```
src/               verifier, formats, CLI (src/experimental/ is not on the verify path)
hosts/pi/          Pi extension (paths.ts mirrors Pi's own tool path resolution)
hosts/github/      GitHub Action runner (action.yml at the repo root)
tests/             node:test suites; tests/vectors/ holds the published test vectors
scripts/           vector generator
docs/spec/         formats and verification order
docs/hosts/        host integration docs
docs/threat-model.md
examples/demo.sh   runnable demos
```

## Branches and pull requests

- Work on a branch from **`dev`** and open your pull request against **`dev`**.
- **`main` is the release branch.** Only maintainers merge `dev` into `main`, as a release.
- Fill in the pull request template ([docs/pull_request_template.md](docs/pull_request_template.md)). Write "N/A" for sections that do not apply instead of deleting them.
- Keep pull requests small enough to review in one sitting. Split large changes.
- Bring your branch up to date with `dev` (`git merge origin/dev`) before asking for review.
- CI runs on Linux and macOS with Node 22.18 and 24; it must be green.

### Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/) in English, starting with an imperative verb:

```
feat(pi): refuse grep over Skills with excluded files
fix(verify): check revocation before digest comparison
docs(spec): describe the tree digest ignore file
test(action): cover symlinked Skill directories
```

Common types: `feat`, `fix`, `docs`, `test`, `refactor`, `chore`, `ci`, `build`. Use a scope (`verify`, `digest`, `cli`, `pi`, `action`, `spec`, …) when it helps.

## Code guidelines

- **TypeScript only.** Strict mode, and only erasable syntax (no `enum`, `namespace` or parameter properties), so Node can run the sources without a build step. Import local files with their `.ts` extension.
- **No runtime dependencies.** Use Node's standard library. Adding a dependency needs a strong reason and a maintainer's agreement; dev dependencies are fine when they serve tests or builds.
- **Fail closed.** Anything that cannot be checked must end as `UNVERIFIABLE` (and block in enforce mode), never as `VERIFIED`. Error paths must not fail open.
- **Treat inputs as hostile.** Skill trees, certificates, policy files, tool arguments in Pi, and anything in a pull request can be attacker-controlled. Validate exact fields, bound sizes, and avoid following symlinks unless the code says why.
- **Keep secrets away from everything.** Private keys and tokens must never reach Skill trees, logs, decision records, output or the model.
- **Match the surrounding code**: naming, comment density and structure. Comments explain why, not what.

### Changing a format

The tree digest, certificate, trust root, revocation list, policy and host state are specified in `docs/spec/`. If you change one:

1. Update its spec in the same pull request.
2. Bump its version identifier if existing documents would be read differently.
3. Regenerate the vectors (`node scripts/vectors.ts --write`) and commit them; the vectors test checks them byte for byte.

## Tests

- New behavior comes with tests.
- **Bug and security fixes come with a regression test that fails without the fix.** Say in the pull request that you checked this.
- Pi host changes: run the Pi tests (`tests/pi-host.test.ts`, `tests/pi-handlers.test.ts`) against the Pi version pinned in `devDependencies`, and note that version in the pull request.
- Tests must not touch real user files or the network. Use the temporary-directory helpers in `tests/helpers.ts`.

## Security-sensitive changes

A change is security-sensitive if it affects what counts as `VERIFIED`, what a host blocks, what a pull request can influence in the Action, or how keys are handled. For these:

- Check the design invariants in the pull request template.
- Update `docs/threat-model.md` if a guarantee or a known limit changes.
- Expect an independent security review before merge. Reviews may take more than one round.

## Documentation and wording

User-facing text (README, docs, CLI messages, Action metadata) must match what the code does:

- Do not claim a certificate makes a Skill safe or benign. It records who approved which exact version.
- Do not claim OWASP compliance, endorsement or "reference implementation" status, or USF metadata support.
- Qualify enforcement: it applies in enforce mode, on supported hosts, within the limits in the threat model.
- Do not claim support for hosts or platforms that are not supported yet.

## License

mago-ski is licensed under [Apache-2.0](LICENSE). Unless you state otherwise, any contribution you submit is licensed under the same terms (Apache-2.0, section 5).
