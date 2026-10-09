#!/usr/bin/env node
// GitHub Action runner. Trust comes from the protected base revision (policy, trust root,
// revocation list); Skills and certificates come from the pull request. A pull request can
// therefore add certificates but cannot change who is trusted to issue them.
import { appendFile, realpath } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { isInside } from '../../src/fs-safe.ts';
import { findSkillDirs, loadPolicy, loadPolicyTrust, tooDeepResult, verifyWithPolicy, type Policy } from '../../src/policy.ts';
import { unverifiable, type VerificationResult } from '../../src/verify.ts';

export interface GitHubCheckOptions {
  /** Checkout that supplies trust: the PR base revision, or the workspace for push events. */
  policyRoot: string;
  /** Checkout under review. */
  workspace: string;
  /** Policy path relative to both checkouts. */
  policy: string;
  now?: Date;
}

export interface GitHubCheckResult {
  mode: Policy['mode'];
  results: VerificationResult[];
  exitCode: number;
  summary: string;
}

/** Names and paths come from the pull request; keep them inert inside a Markdown table cell. */
export function markdownCell(value: string): string {
  return value
    .replace(/[\u0000-\u001f\u007f\u2028\u2029]+/gu, ' ')
    .replace(/[\\`*_[\]<>|#!~(){}]/gu, (char) => `\\${char}`)
    .slice(0, 500);
}

function within(root: string, target: string, label: string): string {
  if (!isInside(root, target)) throw new Error(`${label} must stay inside ${root}`);
  return target;
}

/** Containment on resolved paths, so a symlink cannot point a policy path outside its checkout. */
async function withinReal(root: string, target: string, label: string): Promise<string> {
  within(root, target, label);
  let resolved: string;
  try {
    resolved = await realpath(target);
  } catch (error) {
    if ((error as NodeJS.ErrnoException)?.code === 'ENOENT') return target;
    throw error;
  }
  if (!isInside(await realpath(root), resolved)) throw new Error(`${label} must stay inside ${root} (it resolves to ${resolved})`);
  return target;
}

/** Re-anchors a path from the policy checkout into the workspace checkout. */
async function toWorkspace(policyRoot: string, workspace: string, target: string, label: string): Promise<string> {
  const relative = path.relative(policyRoot, within(policyRoot, target, label));
  return await withinReal(workspace, path.join(workspace, relative), label);
}

export async function runGitHubCheck(options: GitHubCheckOptions): Promise<GitHubCheckResult> {
  const now = options.now ?? new Date();
  const policyRoot = path.resolve(options.policyRoot);
  const workspace = path.resolve(options.workspace);
  const policyPath = await withinReal(policyRoot, path.resolve(policyRoot, options.policy), 'policy');
  const base = await loadPolicy(policyPath);
  await withinReal(policyRoot, base.trustRootPath, 'trust_root');
  await withinReal(policyRoot, base.revocationsPath, 'revocations');
  const certificateDirs: string[] = [];
  for (const dir of base.certificateDirs) certificateDirs.push(await toWorkspace(policyRoot, workspace, dir, 'certificate_dirs'));
  const skillDirs: string[] = [];
  for (const dir of base.skillDirs) skillDirs.push(await toWorkspace(policyRoot, workspace, dir, 'skill_dirs'));
  const policy: Policy = {
    ...base,
    certificateDirs,
    skillDirs,
    // CI has no persistent host state; rollback protection comes from the protected base revision.
    statePath: null,
    decisionLogPath: null,
  };
  if (policy.skillDirs.length === 0) throw new Error('Policy has no skill_dirs; list the directories that hold Skills');
  const { skillDirs: found, tooDeep } = await findSkillDirs(policy.skillDirs);
  const trust = await loadPolicyTrust(policy, now);
  const results: VerificationResult[] = [];
  for (const skillDir of found) {
    results.push(trust.ok
      ? await verifyWithPolicy(policy, skillDir, { now, context: trust.context })
      : unverifiable(skillDir, path.basename(skillDir), trust.reason, now, trust.verdict));
  }
  for (const directory of tooDeep) results.push(tooDeepResult(directory, now));
  const failures = results.filter((result) => result.verdict !== 'VERIFIED');
  const rows = results.map((result) => {
    const relative = path.relative(workspace, result.skillDir) || '.';
    return `| ${result.verdict === 'VERIFIED' ? 'pass' : 'fail'} | ${markdownCell(result.skillName)} | ${markdownCell(relative)} | ${result.verdict} | ${markdownCell(result.reason)} |`;
  });
  const summary = [
    `### mago-ski: ${results.length - failures.length}/${results.length} Skills verified (${policy.mode} mode)`,
    '',
    '| | Skill | Path | Verdict | Detail |',
    '|---|---|---|---|---|',
    ...rows,
    '',
    failures.length > 0 && policy.mode === 'shadow' ? '_Shadow mode: failures are reported but do not fail the check._' : '',
  ].join('\n');
  return { mode: policy.mode, results, exitCode: failures.length > 0 && policy.mode === 'enforce' ? 1 : 0, summary };
}

function escapeAnnotation(value: string): string {
  return value.replace(/%/gu, '%25').replace(/\r/gu, '%0D').replace(/\n/gu, '%0A');
}

async function main(): Promise<void> {
  const [policyRoot, workspace, policy] = process.argv.slice(2);
  if (!policyRoot || !workspace || !policy) throw new Error('usage: run.ts POLICY_ROOT WORKSPACE POLICY');
  const result = await runGitHubCheck({ policyRoot, workspace, policy });
  for (const entry of result.results) {
    if (entry.verdict === 'VERIFIED') continue;
    const level = result.mode === 'enforce' ? 'error' : 'warning';
    const file = path.relative(path.resolve(workspace), path.join(entry.skillDir, 'SKILL.md'));
    process.stdout.write(`::${level} file=${escapeAnnotation(file)},title=mago-ski ${entry.verdict}::${escapeAnnotation(`${entry.skillName}: ${entry.reason}`)}\n`);
  }
  process.stdout.write(`${result.summary}\n`);
  if (process.env.GITHUB_STEP_SUMMARY) await appendFile(process.env.GITHUB_STEP_SUMMARY, `${result.summary}\n`);
  process.exitCode = result.exitCode;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error: unknown) => {
    process.stdout.write(`::error title=mago-ski::${escapeAnnotation((error as Error).message)}\n`);
    process.exitCode = 2;
  });
}
