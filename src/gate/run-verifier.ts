// Parent side of the verifier: runs the worker as an isolated child and maps every failure to a closed
// gate-error. The child gets an empty environment (no NODE_OPTIONS, LD_PRELOAD, ...), its own process
// group (killed as a whole on deadline or overflow), and capped output.

import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { isRecord } from '../canonical-json.ts';
import { validateDigest } from '../names.ts';
import { VERDICTS, type Verdict } from '../verify.ts';
import type { GateErrorCode } from './contract.ts';
import { parseStrictJson } from './strict-json.ts';

export interface VerifierRequest {
  request_id:  string;
  skill_dir:   string;
  skill_name:  string;
  policy_path: string;
}

export interface VerifierOptions {
  nodePath:    string;
  deadlineMs:  number;
  /** Tests only: run this script instead of the real worker. */
  workerPathForTests?: string;
}

export type VerifierOutcome =
  | { kind: 'verdict'; verdict: Verdict; digest?: string }
  | { kind: 'gate-error'; code: GateErrorCode };

const MAX_STDOUT = 16 * 1024;
const MAX_STDERR = 4 * 1024;
const here       = fileURLToPath(import.meta.url);
const WORKER     = path.join(path.dirname(here), `verifier-worker${path.extname(here)}`);

function parseLine(bytes: Buffer, requestId: string): VerifierOutcome | undefined {
  if (bytes.length < 2 || bytes[bytes.length - 1] !== 0x0a || bytes.subarray(0, -1).includes(0x0a)) return undefined;
  try {
    const raw = parseStrictJson(bytes.subarray(0, -1));
    if (!isRecord(raw) || raw['v'] !== 1 || raw['request_id'] !== requestId) return undefined;
    const keys = Object.keys(raw).sort().join();
    if (keys !== 'request_id,v,verdict' && keys !== 'digest,request_id,v,verdict') return undefined;
    const verdict = raw['verdict'];
    if (typeof verdict !== 'string' || !(VERDICTS as readonly string[]).includes(verdict)) return undefined;
    if (!Object.hasOwn(raw, 'digest')) return verdict === 'VERIFIED' ? undefined : { kind: 'verdict', verdict: verdict as Verdict };
    return { kind: 'verdict', verdict: verdict as Verdict, digest: validateDigest(raw['digest']) };
  } catch {
    return undefined;
  }
}

export function runVerifier(request: VerifierRequest, options: VerifierOptions): Promise<VerifierOutcome> {
  if (!path.isAbsolute(options.nodePath)) throw new Error('nodePath must be absolute');
  if (!Number.isInteger(options.deadlineMs) || options.deadlineMs <= 0) throw new Error('deadlineMs must be a positive integer');

  return new Promise((resolve) => {
    // Empty env on purpose: the worker needs nothing from the parent's environment.
    const child = spawn(options.nodePath, ['--no-addons', options.workerPathForTests ?? WORKER], {
      shell: false, cwd: '/', env: {}, detached: true, stdio: ['pipe', 'pipe', 'pipe'],
    });
    const out: Buffer[] = [];
    let outSize = 0, errSize = 0;
    let settled = false;

    const settle = (outcome: VerifierOutcome): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(outcome);
    };
    // Resolve immediately: a descendant that escaped the group may hold the pipes open, so 'close' may never fire.
    const fail = (code: GateErrorCode): void => {
      settle({ kind: 'gate-error', code });
      try { process.kill(-(child.pid as number), 'SIGKILL'); } catch { /* already gone */ }
      child.stdout.destroy();
      child.stderr.destroy();
    };
    const timer = setTimeout(() => fail('verifier-timeout'), options.deadlineMs);

    child.once('error', () => fail('verifier-failed'));
    child.stdin.on('error', () => {});
    child.stdin.end(JSON.stringify({ v: 1, ...request }));
    child.stdout.on('data', (chunk: Buffer) => {
      if (settled) return; // late output is discarded
      outSize += chunk.length;
      if (outSize > MAX_STDOUT) return fail('verifier-failed');
      out.push(chunk);
    });
    child.stderr.on('data', (chunk: Buffer) => {
      errSize += chunk.length;
      if (errSize > MAX_STDERR) fail('verifier-failed');
    });
    // The deadline timer stays armed through 'exit' and is only cleared by settle().
    child.once('close', (code, signal) => {
      const parsed = code === 0 && signal === null ? parseLine(Buffer.concat(out), request.request_id) : undefined;
      settle(parsed ?? { kind: 'gate-error', code: 'verifier-failed' });
    });
  });
}
