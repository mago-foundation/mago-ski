// Test-only Codex hook entry: like src/gate/adapters/codex-hook.ts, but the owner uid comes from argv[2].
import { runHook } from '../../src/gate/adapters/codex.ts';
import { hookMain } from '../../src/gate/adapters/hook-main.ts';

const uid = process.argv[4] ?? '';
await hookMain(process.argv.slice(2, 4), /^[0-9]{1,10}$/u.test(uid) ? { rootUid: Number(uid) } : {}, runHook);
