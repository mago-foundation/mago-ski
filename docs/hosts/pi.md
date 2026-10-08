# Pi host

The Pi extension (`hosts/pi/index.ts`) enforces certificates inside a normal [Pi](https://github.com/earendil-works/pi) session. Tested with Pi 1.0.4 and 1.1.0.

## Install

```bash
pi install git:github.com/mago-foundation/mago-ski@<commit>   # or: pi -e ./mago-ski for one session
mkdir -p ~/.mago-ski
cp policy.json trust-root.json revocations.json ~/.mago-ski/
```

The extension reads its policy from `MAGO_SKI_POLICY` or `~/.mago-ski/policy.json`. It never reads policy from the project directory, because project files may be controlled by the code under review. Without a policy it warns once and checks nothing. If a policy exists but cannot be loaded, it blocks every Skill.

Start in `"mode": "shadow"` to see what would be blocked (the decision log records `would-block`), then switch to `"enforce"`.

## What it does

| Pi event | Enforce mode | Shadow mode |
|---|---|---|
| Before each run (`before_agent_start`) | Verifies every discovered Skill; only `VERIFIED` Skills stay in the list sent to the model. Status bar: `mago-ski enforce: 3/4 Skills verified` | Same check, nothing removed |
| `/skill:name` (`input`) | Verified: re-verified and expanded from the verified bytes, so Pi never re-reads the file. Unverified: refused, the model is not called. Not seen yet in this session: rewritten into a plain request, so Pi does not expand it unchecked | Allowed |
| `read`, `find`, `ls`, `edit`, `write` (`tool_call`) | Refused for paths in unverified Skills. Paths are resolved the way Pi's tools resolve them (a leading `@`, `file://` URLs, `~`, Unicode spaces, Windows shell paths, and the filename variants `read` tries), and matched both before and after resolving symlinks. Reads from verified Skills are re-hashed against the certificate; changed files, files not in the certificate, and paths that leave the Skill through a link are refused. Edits to verified Skills are refused. `find` and `ls` of verified Skills are allowed (names only) | Logged |
| `grep` | Refused when it searches in or over an unverified Skill, or a verified Skill that has files excluded from its certificate (`.git`, ignored files). Otherwise the Skill is re-verified first | Logged |
| `bash`, `powershell` | Refused when the command names an unverified Skill's directory; verified Skills it names are re-verified first. Best-effort (see the [threat model](../threat-model.md)) | Logged |
| Verification error | A Skill that cannot be checked is `UNVERIFIABLE`. If checking crashes outright, no Skills are advertised and file and shell tools touching any Skill path are blocked for that run | Logged |

Each change of verdict is written to the policy's `decision_log` with the event, verdict and reason, and shown as a notification.

## Limits

- Standalone Markdown Skills (a `.md` file without its own directory and `SKILL.md`) cannot be certified and are always unverified.
- Pi runs extensions in load order; another extension can change the Skill list after mago-ski. Load mago-ski last.
- Custom tools and MCP tools that read files are not checked.
- Path matching mirrors Pi 1.1's tool path resolution (`hosts/pi/paths.ts`). A future Pi version that resolves paths differently needs a matching update; the Pi host tests pin the Pi version.
