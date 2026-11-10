// Test-only hook entry: like src/gate/adapters/claude-code-hook.ts, but the uid that must own the config and socket
// comes from argv[2] so tests can run as a non-root user. Never shipped or referenced by managed settings.
import { hookMain } from '../../src/gate/adapters/hook-main.ts';

const uid = process.argv[4] ?? '';
await hookMain(process.argv.slice(2, 4), /^[0-9]{1,10}$/u.test(uid) ? { rootUid: Number(uid) } : {});
