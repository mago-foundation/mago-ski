# Pi interception spike (WS0.1)

Date: 2026-10-08. Pi 1.0.4 (`@earendil-works/pi-coding-agent`), Node 24.18.

**Question:** can a Pi extension enforce Skill approval inside a normal Pi session, or does mago-ski need a separate verified-install store?

**Method:** [`pi-spike.mjs`](pi-spike.mjs) starts a real Pi `AgentSession` through the Pi SDK, with an inline extension, two Skills (`approved-skill`, `unapproved-skill`) and Pi's built-in faux model provider. The faux model asks to `read` and to `bash cat` the unapproved Skill's `SKILL.md`, and the user types `/skill:unapproved-skill`. The script imports Pi from the local Pi install (`~/.pi/agent/install/releases/1.0.4`); adjust the path to rerun it.

## Results

| Question | Hook | Observed |
|---|---|---|
| (a) Remove unapproved Skills from what the model is told | `before_agent_start`: `event.systemPromptOptions.skills` is a mutable `Skill[]` (`name`, `description`, `filePath`, `baseDir`, `sourceInfo`) | The system prompt sent to the model listed `approved-skill` but not `unapproved-skill` |
| (b) Block reading Skill files and running Skill scripts | `tool_call`: return `{ block: true, reason }`; `event.input` is typed per built-in tool | Both the `read` and the `bash` call were blocked; the Skill body never reached the model |
| (c) Intercept `/skill:name` | The `input` event fires **before** skill expansion; return `{ action: "handled" }` or `{ action: "transform", text }` | Handled; the model was never called |
| (d) Where Skill paths come from | The same `Skill[]` objects carry `baseDir` and `sourceInfo`; `resources_discover` can add paths | The extension sees every discovered Skill, including global `~/.agents/skills` ones |

**Decision:** (a) and (b) both work, so the verified-install store is optional. Phase 1's host is a Pi extension.

## Constraints the extension design must handle

1. **`/skill:` expansion re-reads the file.** Pi's `_expandSkillCommand` calls `readFileSync(skill.filePath)` after the `input` handler runs, which leaves a window to swap the file. The extension therefore expands `/skill:name` for approved Skills itself, from the bytes it verified, and returns `transform`, so Pi never re-reads the file.
2. **Bash blocking is best-effort.** Matching Skill paths in a shell command string can be evaded (relative paths after `cd`, globs, variables, encoded paths). The strong guarantees are that unverified Skills are not advertised, `/skill:` cannot load them, and the structured file tools refuse their files.
3. **Every file tool needs coverage:** `read`, `grep`, `find`, `ls`, `edit`, `write`, including nested calls (`parentToolCallId`, codemode). Custom and MCP tools that read files are opaque to the extension.
4. **Load order.** Other extensions run in load order and can change `systemPromptOptions.skills` after mago-ski does. The extension re-filters on every run and should load last; it cannot defend against a hostile extension in the same process.
5. **Cost.** `before_agent_start` fires on every run, so verification results are cached by file identity and re-checked on read.
6. **Failure handling.** An error thrown in a `tool_call` handler blocks the tool; errors in other handlers are reported and Pi continues. The extension's handlers must fail closed explicitly in enforce mode.
