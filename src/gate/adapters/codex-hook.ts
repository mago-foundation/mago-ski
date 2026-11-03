// Entry point of the Codex hook: `env -i node --no-addons codex-hook.js <config.json> <enforce|shadow>`.
// The config, socket directory and socket must be root-owned; see codex.ts.
import { runHook } from './codex.ts';
import { hookMain } from './hook-main.ts';

await hookMain(process.argv.slice(2, 4), {}, runHook);
