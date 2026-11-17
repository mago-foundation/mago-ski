// Test-only Codex hook wrapper. It forwards the hook's streams and exit status and records
// only the event name, exit status and whether stderr contained a reason. Never record input.
import { spawn } from 'node:child_process';
import { appendFile, readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const config = JSON.parse(await readFile(`${fileURLToPath(import.meta.url)}.json`, 'utf8'));
const child = spawn(process.execPath, ['--no-addons', config.hook, ...process.argv.slice(2)], { stdio: ['pipe', 'pipe', 'pipe'] });
for (const signal of ['SIGTERM', 'SIGINT', 'SIGHUP']) process.once(signal, () => child.kill(signal));
let input = Buffer.alloc(0);
let overflow = false;
let reason = false;
process.stdin.on('data', (chunk) => {
  if (input.length + chunk.length <= 65536 && !overflow) input = Buffer.concat([input, chunk]);
  else { overflow = true; input = Buffer.alloc(0); }
});
process.stdin.pipe(child.stdin);
child.stdin.on('error', () => {});
child.stdout.pipe(process.stdout, { end: false });
child.stderr.on('data', (chunk) => { if (/\S/u.test(chunk.toString('utf8'))) reason = true; });
child.stderr.pipe(process.stderr, { end: false });
child.on('error', () => {});
const result = await new Promise((resolve) => child.on('close', (code, signal) => resolve({ code, signal })));
let event = null;
try {
  const value = JSON.parse(input.toString('utf8')).hook_event_name;
  if (['SessionStart', 'UserPromptSubmit', 'PreToolUse'].includes(value)) event = value;
} catch { /* A malformed or incomplete input is not evidence of a specific event. */ }
await appendFile(config.observations, `${JSON.stringify({ event, code: result.code, signal: result.signal, reason })}\n`).catch(() => {});
// Propagate signals and ordinary exits. A killed or crashed hook must never look like a denial.
if (result.signal) { process.removeAllListeners(result.signal); process.kill(process.pid, result.signal); }
else process.exitCode = result.code ?? 1;
