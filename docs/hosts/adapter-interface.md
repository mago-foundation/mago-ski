# Host adapter interface

What a coding-agent host must let mago-ski do, so that Claude Code, Cursor and others can be added the way Pi was. The library calls are the same for every host; only the hook points differ.

## Required hook points

| # | Hook | Why | Pi 1.0.4 |
|---|---|---|---|
| H1 | **Change the Skill list before the model sees it**, with each Skill's name and directory | Unverified Skills must not be advertised | `before_agent_start` → `systemPromptOptions.skills` |
| H2 | **Intercept explicit Skill invocation before expansion**, and supply the expanded text | Stop unverified loads; expand verified Skills from verified bytes | `input` event (`handled` / `transform`) |
| H3 | **Block or allow file tool calls**, with the target path | Refuse unverified files; re-hash verified ones on read | `tool_call` (`block`) |
| H4 | **Block or allow shell commands**, with the command text | Best-effort coverage of scripts | `tool_call` for `bash` |
| H5 | **Report to the user** (notification, status) | Explain blocks and how to fix them | `ctx.ui.notify`, `ctx.ui.setStatus` |
| H6 | **Load configuration from a user- or admin-controlled location** | Policy must not come from the code under review | Extension reads `~/.mago-ski/policy.json` |

A host that lacks H1 or H2 can fall back to a **verified-install store**: copy verified Skills into a content-addressed directory and point the host's Skill path only there.

## Library calls

```ts
import { loadPolicy, loadPolicyTrust, verifyWithPolicy, hashFile, appendDecision, decisionRecord } from 'mago-ski';

const policy = await loadPolicy(policyPath);
const trust = await loadPolicyTrust(policy, new Date());      // once per run; enforces rollback state
const result = await verifyWithPolicy(policy, skillDir, { now: new Date(), skillName, context: trust.ok ? trust.context : undefined });
// result.verdict, result.reason, result.files (per-file hashes when VERIFIED)
const current = await hashFile(absolutePath, relativePath);  // compare with result.files on read
await appendDecision(policy.decisionLogPath, decisionRecord(result, policy.mode, 'advertise'));
```

## Claude Code (planned)

Claude Code hooks (`PreToolUse`, `UserPromptSubmit`) cover H2–H5. Whether H1 is possible (removing a Skill from what the model is told) needs the same spike Pi had; if not, the verified-install store applies.
