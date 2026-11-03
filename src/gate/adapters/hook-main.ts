// Shared process wrapper for the Claude Code hook: reads bounded stdin, runs the adapter, writes its outcome, exits.
import { MAX_STDIN_BYTES, runHook, type HookDeps } from './claude-code.ts';

async function readStdin(): Promise<Buffer | null> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of process.stdin as AsyncIterable<Buffer>) {
    size += chunk.length;
    if (size > MAX_STDIN_BYTES) return null;
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

export async function hookMain(argv: readonly string[], extra: Omit<HookDeps, 'readStdin'> = {},
  run: (argv: readonly string[], deps: HookDeps) => Promise<{ code: number; stdout: string; stderr: string; mode?: string }> = runHook): Promise<never> {
  let outcome: { code: number; stdout: string; stderr: string; mode?: string } =
    { code: 2, stdout: '', stderr: 'mago-ski could not verify this Skill; it is blocked until verification works.' };
  try { outcome = await run(argv, { ...extra, readStdin }); } catch { /* keeps the explicit block above */ }
  const shadow = outcome.mode === 'shadow';
  if (outcome.stderr) process.stderr.write(outcome.stderr);
  // A broken stdout must not turn an intended deny into an allow: exit 2 with a stderr reason (shadow: exit 0).
  // Exit 2 as a block is unverified (live check pending).
  process.stdout.on('error', () => {});
  return new Promise<never>(() => {
    process.stdout.write(outcome.stdout, (err) => {
      if (!err) return process.exit(outcome.code);
      if (!shadow) process.stderr.write('mago-ski could not deliver its decision; this Skill is blocked.');
      process.exit(shadow ? 0 : 2);
    });
  });
}
