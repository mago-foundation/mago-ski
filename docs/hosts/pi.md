# Pi host

The Pi extension (`hosts/pi/index.ts`) enforces certificates inside a normal [Pi](https://github.com/earendil-works/pi) session. Tested with Pi 1.0.4.

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
| `read`, `grep`, `find`, `ls`, `edit`, `write` (`tool_call`) | Refused for files of unverified Skills. Reads from verified Skills are re-hashed against the certificate; changed or uncovered files are refused. Edits to verified Skills are refused. `grep` over a directory containing an unverified Skill is refused | Logged |
| `bash` | Refused when the command names an unverified Skill's directory; verified Skills it names are re-verified first. Best-effort (see the [threat model](../threat-model.md)) | Logged |

Each change of verdict is written to the policy's `decision_log` with the event, verdict and reason, and shown as a notification.

## Limits

- Standalone Markdown Skills (a `.md` file without its own directory and `SKILL.md`) cannot be certified and are always unverified.
- Pi runs extensions in load order; another extension can change the Skill list after mago-ski. Load mago-ski last.
- Custom tools and MCP tools that read files are not checked.
