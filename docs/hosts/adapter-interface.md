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

## Claude Code (built, not yet tested live)

The [Claude Code spike](../spikes/claude-code-interception.md) found that no hook can change the Skill list (H1) and that a project's settings can turn user hooks off, so enforcement needs managed settings. Without them, only shadow mode is possible.

The company gate (`src/gate/`, Linux only, not yet released) follows that finding with one change of store. Instead of a mago-ski plugin holding verified copies (the spike's proposal), the gate service installs approved Skills into Claude Code's admin-managed Skill folder (each `<folder>/<name>` is a link to the verified, read-only copy, removed on uninstall or revocation), and the generated managed settings (`src/gate/adapters/claude-code-settings.ts`) set `strictPluginOnlyCustomization: ["skills", "hooks", "agents", "mcp"]`, an empty `strictKnownMarketplaces` and `disableSideloadFlags`, so only managed-folder Skills load. Managed `PreToolUse` (Skill tool) and `UserPromptExpansion` (`/name`) hooks ask the service about every use (H2–H5) and block when it cannot answer. The plugin store stays a possible alternative; both kinds of Skill ran under the lock in our earlier tests. Nothing here is a "works with Claude Code" claim until the live tests pass.
