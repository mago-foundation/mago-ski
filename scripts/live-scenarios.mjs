#!/usr/bin/env node
// A narrow, user-facing wrapper around the live harnesses. No shell is used to start a host.
import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const scenarios = {
  'claude-code': [
    ['approved', 'skill-tool-approved'], ['unapproved', 'skill-tool-project'],
    ['revoked', 'revoke-mid-session'], ['gate-down', 'service-down'],
  ],
  codex: [
    ['approved', 'mention-linked-approved'], ['unapproved', 'mention-project'],
    ['revoked', 'revoked-new-session'], ['gate-down', 'service-down'],
  ],
};
const requiredChecks = {
  'claude-code': {
    approved: ['approved body reached the model'],
    unapproved: ['project body did not reach the model', 'the call returned an error'],
    revoked: ['other-skill was listed at start', 'its body did not reach the model after the revoke', 'the gate refused the call'],
    'gate-down': ['approved body did not reach the model', 'the gate could not verify the Skill'],
  },
  codex: {
    approved: ['approved body reached the model'],
    unapproved: ['project body did not reach the model', 'the prompt was blocked'],
    revoked: ['managed link was removed', 'its body did not reach the model', 'the prompt was blocked'],
    'gate-down': ['approved body did not reach the model', 'the prompt was blocked'],
  },
};

/** Do not treat a missing model request or an incomplete/malformed report as a successful denial. */
export function classify(host, id, harnessName, child) {
  if (child.error || child.signal || ![0, 1].includes(child.status)) return { id, status: 'INCONCLUSIVE', reason: 'The harness did not complete; inspect the local environment and try again.' };
  let doc;
  try { doc = JSON.parse(child.stdout); } catch { return { id, status: 'INCONCLUSIVE', reason: 'The harness did not produce a valid report.' }; }
  if (typeof doc.skipped === 'string') return { id, status: 'SKIP', reason: doc.skipped };
  if (!Array.isArray(doc.scenarios) || doc.scenarios.length !== 1) return { id, status: 'INCONCLUSIVE', reason: 'The requested scenario did not produce exactly one result.' };
  const item = doc.scenarios[0];
  if (item?.scenario !== harnessName || !item.checks || typeof item.checks !== 'object' || Array.isArray(item.checks) || !Object.keys(item.checks).length || !Object.values(item.checks).every((v) => typeof v === 'boolean') || typeof item.modelCalls !== 'number')
    return { id, status: 'INCONCLUSIVE', reason: 'The scenario report is incomplete.' };
  const checks = item.checks;
  const expected = requiredChecks[host]?.[id];
  if (!expected || expected.some((name) => !Object.hasOwn(checks, name))) return { id, status: 'INCONCLUSIVE', reason: 'A required scenario observation is missing.' };
  const hookObservations = host === 'codex' && Array.isArray(item.hookObservations)
    ? item.hookObservations.filter((o) => o && ['SessionStart', 'UserPromptSubmit', 'PreToolUse', null].includes(o.event)
      && (Number.isInteger(o.code) || o.code === null) && (o.signal === null || (typeof o.signal === 'string' && /^SIG[A-Z0-9]{1,16}$/u.test(o.signal)))
      && typeof o.reason === 'boolean').map((o) => ({ event: o.event, code: o.code, signal: o.signal, reason: o.reason }))
    : [];
  const evidence = host === 'codex' ? { hookObservations } : {};
  const pass = Object.values(checks).every(Boolean);
  // A Codex prompt can be blocked before the first request. Only explicit hook-block evidence establishes that case.
  const hookBlock = checks['the prompt was blocked'] === true && hookObservations.some((o) => o.event === 'UserPromptSubmit' && o.code === 2 && o.signal === null && o.reason);
  if (checks['the prompt was blocked'] === true && host === 'codex' && !hookBlock)
    return { id, status: 'INCONCLUSIVE', reason: 'The reported block lacks a completed hook denial.', checks, ...evidence };
  if (item.modelCalls === 0 && !hookBlock) return { id, status: 'INCONCLUSIVE', reason: 'No model-boundary request or confirmed hook block was observed.', checks, ...evidence };
  if (pass && child.status !== 0) return { id, status: 'INCONCLUSIVE', reason: 'The harness reported checks but did not exit successfully.', checks, ...evidence };
  return { id, status: pass ? 'PASS' : 'FAIL', checks, ...evidence };
}

function usage() {
  return 'Usage: node scripts/live-scenarios.mjs --host claude-code|codex [--run] [--json]\nWithout --run, prints the plan only.';
}

export function parseArgs(args) {
  let host, run = false, json = false;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--host' && !host) host = args[++i];
    else if (args[i] === '--run' && !run) run = true;
    else if (args[i] === '--json' && !json) json = true;
    else throw new Error(usage());
  }
  if (!Object.hasOwn(scenarios, host ?? '')) throw new Error(usage());
  return { host, run, json };
}

function executable(name) {
  const result = spawnSync('which', [name], { encoding: 'utf8', timeout: 5000 });
  return result.status === 0 ? result.stdout.trim().split('\n')[0] : '';
}

function preflight(host) {
  if (process.platform !== 'linux') return 'Linux is required for the isolated live harness.';
  if (process.getuid?.() !== 0) return 'Root is required to create the private mount namespace; review the plan before rerunning with sudo.';
  const [major, minor, patch] = process.versions.node.split('.').map(Number);
  const atLeast = (m, p) => minor > m || (minor === m && patch >= p);
  if (!((major === 22 && atLeast(23, 4)) || (major === 24 && atLeast(22, 1)) || (major === 26 && atLeast(12, 1)) || major > 26)) return 'This checkout requires Node ^22.23.4, ^24.22.1, or >=26.12.1.';
  if (!existsSync(path.join(root, 'dist', 'src', 'cli.js'))) return 'Build the checkout first: npm run build.';
  for (const command of ['unshare', 'mount', 'umount', 'chmod']) if (!executable(command)) return `Missing required program: ${command}.`;
  if (process.env.MAGO_LIVE_USER && (!executable('setpriv') || !executable('chown'))) return 'An unprivileged host user requires setpriv and chown.';
  const binary = host === 'codex' ? process.env.CODEX_BIN : (process.env.CLAUDE_BIN || executable('claude'));
  if (!binary || !path.isAbsolute(binary) || !existsSync(binary)) return host === 'codex' ? 'Set CODEX_BIN to the absolute path of the native Codex binary.' : 'Set CLAUDE_BIN to the absolute path of the Claude Code binary.';
  return null;
}

function main() {
  let opts;
  try { opts = parseArgs(process.argv.slice(2)); } catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 2; return; }
  const plan = { host: opts.host, mode: opts.run ? 'run' : 'plan', scenarios: scenarios[opts.host].map(([id]) => id), model: 'local scripted endpoint', isolation: 'Linux private mount namespace', note: 'Uses synthetic keys and Skills. Interactive menus and real model responses are not tested.' };
  if (!opts.run) { console.log(JSON.stringify(plan, null, 2)); return; }
  const problem = preflight(opts.host);
  if (problem) { console.log(JSON.stringify({ ...plan, results: plan.scenarios.map((id) => ({ id, status: 'SKIP', reason: problem })) }, null, 2)); process.exitCode = 2; return; }
  const script = path.join(root, 'tests', 'live', `${opts.host}-gate.live.ts`);
  // In particular, never inherit MAGO_LIVE_NS or MAGO_LIVE_KEEP: the harness must create its own namespace and remove its temporary keys.
  const env = { PATH: process.env.PATH ?? '/usr/bin:/bin' };
  for (const key of ['CODEX_BIN', 'CLAUDE_BIN', 'MAGO_LIVE_USER']) if (process.env[key]) env[key] = process.env[key];
  const results = [];
  for (const [id, name] of scenarios[opts.host]) {
    if (!opts.json) process.stderr.write(`Running ${id}...\n`);
    const child = spawnSync(process.execPath, [script, name], { cwd: root, env, encoding: 'utf8', timeout: 180000, maxBuffer: 4 * 1024 * 1024 });
    results.push(classify(opts.host, id, name, child));
  }
  const version = spawnSync(opts.host === 'codex' ? env.CODEX_BIN : (env.CLAUDE_BIN || executable('claude')), ['--version'], { encoding: 'utf8', timeout: 5000, env });
  console.log(JSON.stringify({ ...plan, node: process.version, hostVersion: version.status === 0 ? version.stdout.trim().slice(0, 120) : 'unknown', hostUser: env.MAGO_LIVE_USER ?? 'root', results, cleanup: results.every((r) => r.status === 'PASS' || r.status === 'FAIL') ? 'Harness completed its cleanup for each scenario.' : 'Some runs were incomplete; check the disposable test machine for remaining temporary resources.' }, null, 2));
  if (results.some((r) => r.status !== 'PASS')) process.exitCode = results.some((r) => r.status === 'FAIL') ? 1 : 2;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
