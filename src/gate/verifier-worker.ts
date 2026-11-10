// Verifier child process: one bounded request on stdin, one result line on stdout. Read-only: trust is
// loaded without recording versions, and no decision log or state file is written (the parent owns that).
// Any internal failure writes nothing to stdout, a fixed line to stderr, and exits nonzero.

import path from 'node:path';
import { isRecord } from '../canonical-json.ts';
import { isMainModule } from '../main-module.ts';
import { validateSkillName } from '../names.ts';
import { loadPolicy, loadPolicyTrust, verifyWithPolicy } from '../policy.ts';
import { unverifiable } from '../verify.ts';
import { parseStrictJson } from './strict-json.ts';

const MAX_REQUEST_BYTES = 16 * 1024;
const TOKEN_PATTERN     = /^[A-Za-z0-9._:-]{1,128}$/u;

interface WorkerRequest {
  request_id:  string;
  skill_dir:   string;
  skill_name:  string;
  policy_path: string;
}

function absolutePath(value: unknown, label: string): string {
  if (typeof value !== 'string' || value.includes('\0') || !path.isAbsolute(value)
    || value.split('/').includes('..') || path.normalize(value) !== value)
    throw new Error(`${label} must be a normalised absolute path`);
  return value;
}

export function parseWorkerRequest(bytes: Uint8Array): WorkerRequest {
  const raw = parseStrictJson(bytes);
  if (!isRecord(raw) || raw['v'] !== 1) throw new Error('bad request');
  const keys = ['v', 'request_id', 'skill_dir', 'skill_name', 'policy_path'];
  if (Object.keys(raw).length !== keys.length || !keys.every((key) => Object.hasOwn(raw, key)))
    throw new Error('bad request');
  const id = raw['request_id'];
  if (typeof id !== 'string' || !TOKEN_PATTERN.test(id)) throw new Error('bad request_id');
  return {
    request_id:  id,
    skill_dir:   absolutePath(raw['skill_dir'], 'skill_dir'),
    skill_name:  validateSkillName(raw['skill_name']),
    policy_path: absolutePath(raw['policy_path'], 'policy_path'),
  };
}

async function readRequest(): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of process.stdin as AsyncIterable<Buffer>) {
    size += chunk.length;
    if (size > MAX_REQUEST_BYTES) throw new Error('request too large');
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

async function main(): Promise<void> {
  const request = parseWorkerRequest(await readRequest());
  const now     = new Date();
  const policy  = await loadPolicy(request.policy_path);
  const trust   = await loadPolicyTrust(policy, now, { recordVersions: false });
  // Without an explicit name the engine derives it from SKILL.md; it must equal the requested one.
  const result  = trust.ok
    ? await verifyWithPolicy(policy, request.skill_dir, { now, context: trust.context })
    : unverifiable(request.skill_dir, request.skill_name, trust.reason, now, trust.verdict);
  const mismatch = result.skillName !== request.skill_name;
  const verdict  = mismatch ? 'UNVERIFIABLE' : result.verdict;
  const digest   = mismatch ? null : result.digest;
  process.stdout.write(`${JSON.stringify({ v: 1, request_id: request.request_id, verdict, ...(digest ? { digest } : {}) })}\n`);
}

if (isMainModule(import.meta.url)) {
  main().catch(() => {
    process.stderr.write('verifier failed\n');
    process.exitCode = 1;
  });
}
