# Pi host

The Pi extension (`hosts/pi/index.ts`) enforces certificates inside a normal [Pi](https://github.com/earendil-works/pi) session. Tested with Pi 1.0.4 and 1.1.0.

## Install

```bash
pi install npm:@mago-foundation/mago-ski   # or for one session: pi -e npm:@mago-foundation/mago-ski
mkdir -p ~/.mago-ski
cp policy.json trust-root.json revocations.json ~/.mago-ski/
```

The extension reads its policy from `MAGO_SKI_POLICY` or `~/.mago-ski/policy.json`. It never reads policy from the project directory, because project files may be controlled by the code under review. Without a policy it warns once and checks nothing. If a policy exists but cannot be loaded, it blocks every Skill.

`MAGO_SKI_POLICY` (and the `policyPath` option of the extension) must be an absolute path, or start with `~/`. A relative path is refused, because it would resolve against whatever directory Pi was started in. A path that resolves inside the project is refused too: the session directory, or the repository containing it (the nearest `.git`, searched up to but not including your home directory), after following symlinks. Paths under `~/.mago-ski/` are always accepted. A refused path is treated like a policy that cannot be loaded: every Skill is blocked and Pi shows an error naming the reason. It never falls back to the home default.

Start in `"mode": "shadow"` to see what would be blocked (the decision log records `would-block`), then switch to `"enforce"`.

## What it does

| Pi event | Enforce mode | Shadow mode |
|---|---|---|
| Before each run (`before_agent_start`) | Verifies every discovered Skill; only `VERIFIED` Skills stay in the list sent to the model. Status bar: `mago-ski enforce: 3/4 Skills verified` | Same check, nothing removed |
| `/skill:name` (`input`) | Verified: re-verified and expanded from the verified bytes, so Pi never re-reads the file. Unverified: refused, the model is not called. Not seen yet in this session: rewritten into a plain request, so Pi does not expand it unchecked | Allowed |
| `read`, `find`, `ls`, `edit`, `write` (`tool_call`) | Refused for paths in unverified Skills. Paths are resolved the way Pi's tools resolve them (a leading `@`, `file://` URLs, `~`, Unicode spaces, Windows shell paths, and the filename variants `read` tries), and matched both before and after resolving symlinks. Reads from verified Skills are re-hashed against the certificate; changed files, files not in the certificate, and paths that leave the Skill through a link are refused. Edits to verified Skills are refused. `find` and `ls` of verified Skills are allowed (names only) | Logged |
| `find`, `ls` over a directory that contains unverified Skills (`tool_result`) | The call runs, but entries that are, or are inside, an unverified Skill are removed from the result before the model sees it (links into one included), and a fixed note says how many were hidden. A line that does not name a real path (part of a file name containing a newline) is removed as well. Verified Skills and everything else stay listed | Result unchanged; logged |
| `grep` | Refused when it searches in or over an unverified Skill, or a verified Skill that has files excluded from its certificate (`.git`, ignored files, or an in-tree `.mago-ski-cert.json` that is not the certificate that verified the Skill). Otherwise the Skill is re-verified first and its exclusions checked again | Logged |
| `bash`, `powershell` | Refused when the command names an unverified Skill's directory; verified Skills it names are re-verified first. Best-effort (see the [threat model](../threat-model.md)) | Logged |
| Verification error | A Skill that cannot be checked is `UNVERIFIABLE`. If checking crashes outright, no Skills are advertised and file and shell tools touching any Skill path are blocked for that run | Logged |

Skill paths are shown to the model in Pi's Skill list and in the `/skill:` block, but the certificate does not cover the Skill directory, so a contributor can rename it. Below your working directory and your home directory, a Skill path may therefore use only `A-Z a-z 0-9 . _ / ~ @ + -`. A verified Skill with any other character in its path (spaces, non-ASCII letters, newlines, quotes, angle brackets) is not advertised and `/skill:` refuses it with a notice; rename or move the directory. The working and home directories themselves may contain spaces, but not control, quote or angle-bracket characters. Skill names are already limited to ASCII letters, digits, `.`, `_` and `-`.

When a verdict changes, it is written to the policy's `decision_log` (if configured and writable; it must be a regular file inside the policy's directory) with the event, verdict and reason. Verdicts other than `VERIFIED` are also shown as a notification when Pi has a UI.

## Limits

- Linux and macOS only. On Windows the extension shows a warning: executable bits are not covered, so Skills approved elsewhere may not verify.
- Standalone Markdown Skills (a `.md` file without its own directory and `SKILL.md`) cannot be certified and are always unverified.
- Pi runs extensions in load order; another extension can change the Skill list after mago-ski. Load mago-ski last.
- Custom tools and MCP tools that read files are not checked.
- Path matching mirrors Pi 1.1's tool path resolution (`hosts/pi/paths.ts`). A future Pi version that resolves paths differently needs a matching update; the Pi host tests pin the Pi version.
