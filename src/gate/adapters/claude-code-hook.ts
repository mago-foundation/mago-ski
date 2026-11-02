// Entry point of the Claude Code hook: `env -i node --no-addons claude-code-hook.js <config.json> <enforce|shadow>`.
// The config, socket directory and socket must be root-owned; see claude-code.ts.
import { hookMain } from './hook-main.ts';

await hookMain(process.argv.slice(2, 4));
