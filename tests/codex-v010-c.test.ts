// Regression tests for Codex Security v0.1.0 findings 3 (certificate candidate budget), 7 (bounded SKILL.md read)
// and 9 (discovery budget).
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { cp, mkdir, readFile, rm, symlink, truncate, writeFile } from 'node:fs/promises';
import path from 'node:path';
import test, { type TestContext } from 'node:test';
import { runGitHubCheck, MAX_SUMMARY_ROWS } from '../hosts/github/run.ts';
import { runCli } from '../src/cli.ts';
import {
  DiscoveryBudgetError, findSkillDirs, loadPolicy, MAX_CERTIFICATE_CANDIDATES, MAX_CERTIFICATE_TOTAL_BYTES,
  MAX_DISCOVERED_SKILLS, verifyWithPolicy,
} from '../src/policy.ts';
import { MAX_FILE_BYTES } from '../src/tree-digest.ts';
import { approve, setupOrg, T0, tempDir, writeSkill, type Org } from './helpers.ts';

// --- Finding 7: SKILL.md is read through a bounded, no-follow, regular-file-only helper -------------------------

async function swapSkillMd(skill: string, make: (skillMd: string) => Promise<void>): Promise<void> {
  const skillMd = path.join(skill, 'SKILL.md');
  await rm(skillMd);
  await make(skillMd);
}

async function timed<T>(work: Promise<T>, ms = 5000): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const deadline = new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error('hung')), ms); });
  try {
    return await Promise.race([work, deadline]);
  } finally {
    clearTimeout(timer);
  }
}

test('a SKILL.md symlinked to /dev/zero is UNVERIFIABLE without reading it', async (t) => {
  const org = await setupOrg(t);
  const skill = await writeSkill(await tempDir(t), 'devzero');
  await swapSkillMd(skill, async (skillMd) => await symlink('/dev/zero', skillMd));
  const result = await timed(verifyWithPolicy(await loadPolicy(org.policyPath), skill, { now: T0 }));
  assert.equal(result.verdict, 'UNVERIFIABLE');
  assert.match(result.reason, /SKILL\.md must be a regular, non-symlink file/u);
});

test('a SKILL.md symlinked to another file or a FIFO is UNVERIFIABLE', async (t) => {
  const org = await setupOrg(t);
  const dir = await tempDir(t);
  const linked = await writeSkill(dir, 'linked');
  await swapSkillMd(linked, async (skillMd) => await symlink(path.join(dir, 'linked', 'other.md'), skillMd));
  await writeFile(path.join(linked, 'other.md'), '---\nname: linked\n---\n');
  const fifo = await writeSkill(dir, 'fifo');
  await swapSkillMd(fifo, async (skillMd) => { execFileSync('mkfifo', [skillMd]); });
  const policy = await loadPolicy(org.policyPath);
  for (const skill of [linked, fifo]) {
    const result = await timed(verifyWithPolicy(policy, skill, { now: T0 }));
    assert.equal(result.verdict, 'UNVERIFIABLE', skill);
    assert.match(result.reason, /SKILL\.md must be a regular, non-symlink file/u);
  }
});

test('an oversized regular SKILL.md is UNVERIFIABLE before it is read', async (t) => {
  const org = await setupOrg(t);
  const skill = await writeSkill(await tempDir(t), 'huge');
  await truncate(path.join(skill, 'SKILL.md'), MAX_FILE_BYTES + 1);
  const result = await timed(verifyWithPolicy(await loadPolicy(org.policyPath), skill, { now: T0 }));
  assert.equal(result.verdict, 'UNVERIFIABLE');
  assert.match(result.reason, /SKILL\.md exceeds the \d+-byte limit/u);
});

/** Base and PR checkouts with one approved Skill under skills/. */
async function repo(t: TestContext, org: Org, mode: 'shadow' | 'enforce' = 'enforce') {
  const base = await tempDir(t, 'mago-ski-base-');
  await mkdir(path.join(base, '.mago-ski'));
  await cp(org.trustRoot, path.join(base, '.mago-ski', 'trust-root.json'));
  await cp(org.revocations, path.join(base, '.mago-ski', 'revocations.json'));
  await writeFile(path.join(base, '.mago-ski', 'policy.json'), JSON.stringify({
    policy_version: 'mago.policy/v1', mode, root_fingerprint: org.rootKeyId,
    trust_root: 'trust-root.json', revocations: 'revocations.json', skill_dirs: ['../skills'],
  }));
  await approve(org, await writeSkill(path.join(base, 'skills'), 'repo-skill'));
  const pr = await tempDir(t, 'mago-ski-pr-');
  await cp(base, pr, { recursive: true });
  return { base, pr };
}

const check = (base: string, pr: string) => runGitHubCheck({ policyRoot: base, workspace: pr, policy: '.mago-ski/policy.json', now: T0 });

test('the GitHub Action reports a symlinked SKILL.md as a failure without hanging', async (t) => {
  const org = await setupOrg(t);
  const { base, pr } = await repo(t, org);
  const evil = await writeSkill(path.join(pr, 'skills'), 'evil');
  await swapSkillMd(evil, async (skillMd) => await symlink('/dev/zero', skillMd));
  const result = await timed(check(base, pr));
  assert.equal(result.exitCode, 1);
  const entry = result.results.find((item) => item.skillDir === evil);
  assert.equal(entry?.verdict, 'UNVERIFIABLE');
  assert.equal(result.results.find((item) => item.skillName === 'repo-skill')?.verdict, 'VERIFIED');
});

// --- Finding 3: certificate candidates are processed one at a time within a budget ----------------------------------

async function candidateDirs(base: string, count: number, skillName: string, content: (index: number) => Promise<string | undefined> | string | undefined) {
  const dirs: string[] = [];
  for (let index = 0; index < count; index += 1) {
    const dir = path.join(base, `certs-${index}`);
    await mkdir(dir, { recursive: true });
    const text = await content(index);
    if (text !== undefined) await writeFile(path.join(dir, `${skillName}.cert.json`), text);
    dirs.push(dir);
  }
  return dirs;
}

test('a valid certificate among several invalid candidates still verifies', async (t) => {
  const org = await setupOrg(t);
  const base = await tempDir(t);
  const skill = await writeSkill(base, 'multi');
  const good = path.join(base, 'good.cert.json');
  await approve(org, skill, { out: good });
  const text = await readFile(good, 'utf8');
  const dirs = await candidateDirs(path.join(base, 'dirs'), 5, 'multi', (index) => index === 3 ? text : 'not json');
  const policy = { ...(await loadPolicy(org.policyPath)), certificateDirs: dirs };
  const result = await verifyWithPolicy(policy, skill, { now: T0 });
  assert.equal(result.verdict, 'VERIFIED', result.reason);
  assert.equal(result.certificateSource, path.join(dirs[3]!, 'multi.cert.json'));
});

test('the first valid certificate ends the scan; later candidates are never read', async (t) => {
  const org = await setupOrg(t);
  const base = await tempDir(t);
  const skill = await writeSkill(base, 'early');
  const good = path.join(base, 'good.cert.json');
  await approve(org, skill, { out: good });
  const text = await readFile(good, 'utf8');
  // Far more candidates than the budget; the valid one comes first, so the budget is never reached.
  const dirs = await candidateDirs(path.join(base, 'dirs'), MAX_CERTIFICATE_CANDIDATES + 10, 'early', (index) => index === 0 ? text : 'not json');
  const result = await verifyWithPolicy({ ...(await loadPolicy(org.policyPath)), certificateDirs: dirs }, skill, { now: T0 });
  assert.equal(result.verdict, 'VERIFIED', result.reason);
});

test('when no candidate verifies, the existing verdict precedence still picks the most informative failure', async (t) => {
  const org = await setupOrg(t);
  const base = await tempDir(t);
  const skill = await writeSkill(base, 'prec');
  const good = path.join(base, 'good.cert.json');
  await approve(org, skill, { out: good });
  const text = await readFile(good, 'utf8');
  await writeFile(path.join(skill, 'extra.md'), 'changed after approval\n');
  const dirs = await candidateDirs(path.join(base, 'dirs'), 3, 'prec', (index) => index === 1 ? text : 'not json');
  const result = await verifyWithPolicy({ ...(await loadPolicy(org.policyPath)), certificateDirs: dirs }, skill, { now: T0 });
  assert.equal(result.verdict, 'UNAPPROVED_CHANGE');
});

test('more candidates than the budget is UNVERIFIABLE', async (t) => {
  const org = await setupOrg(t);
  const base = await tempDir(t);
  const skill = await writeSkill(base, 'many');
  const dirs = await candidateDirs(path.join(base, 'dirs'), MAX_CERTIFICATE_CANDIDATES + 1, 'many', () => 'not json');
  const result = await verifyWithPolicy({ ...(await loadPolicy(org.policyPath)), certificateDirs: dirs }, skill, { now: T0 });
  assert.equal(result.verdict, 'UNVERIFIABLE');
  assert.match(result.reason, new RegExp(`more than ${MAX_CERTIFICATE_CANDIDATES} certificate candidates`, 'u'));
});

test('exactly the candidate budget is still evaluated', async (t) => {
  const org = await setupOrg(t);
  const base = await tempDir(t);
  const skill = await writeSkill(base, 'edge');
  const dirs = await candidateDirs(path.join(base, 'dirs'), MAX_CERTIFICATE_CANDIDATES, 'edge', () => 'not json');
  const result = await verifyWithPolicy({ ...(await loadPolicy(org.policyPath)), certificateDirs: dirs }, skill, { now: T0 });
  assert.equal(result.verdict, 'UNVERIFIABLE');
  assert.match(result.reason, /malformed certificate/u);
});

test('more cumulative candidate bytes than the budget is UNVERIFIABLE', async (t) => {
  const org = await setupOrg(t);
  const base = await tempDir(t);
  const skill = await writeSkill(base, 'bytes');
  const size = 7 * 1024 * 1024;
  assert.ok(size * 5 > MAX_CERTIFICATE_TOTAL_BYTES);
  const dirs = await candidateDirs(path.join(base, 'dirs'), 5, 'bytes', () => '');
  for (const dir of dirs) await truncate(path.join(dir, 'bytes.cert.json'), size);
  const result = await verifyWithPolicy({ ...(await loadPolicy(org.policyPath)), certificateDirs: dirs }, skill, { now: T0 });
  assert.equal(result.verdict, 'UNVERIFIABLE');
  assert.match(result.reason, /exceed \d+ bytes in total/u);
});

// --- Finding 9: discovery has a Skill and entry budget -------------------------------------------------------

async function manySkills(root: string, count: number): Promise<void> {
  for (let index = 0; index < count; index += 1) {
    const dir = path.join(root, `s${index}`);
    await mkdir(dir, { recursive: true });
    await writeFile(path.join(dir, 'SKILL.md'), `---\nname: s${index}\n---\n`);
  }
}

test('findSkillDirs stops at the Skill limit and at the entry limit', async (t) => {
  const root = await tempDir(t);
  await manySkills(root, 5);
  const ok = await findSkillDirs([root], 16, { maxSkills: 5 });
  assert.equal(ok.skillDirs.length, 5);
  await assert.rejects(findSkillDirs([root], 16, { maxSkills: 4 }), (error: unknown) =>
    error instanceof DiscoveryBudgetError && /more than 4 Skills/u.test(error.message));
  await assert.rejects(findSkillDirs([root], 16, { maxEntries: 4 }), (error: unknown) =>
    error instanceof DiscoveryBudgetError && /more than 4 directory entries/u.test(error.message));
  // Non-Skill directories and plain files count as entries too.
  const wide = await tempDir(t);
  for (let index = 0; index < 20; index += 1) await writeFile(path.join(wide, `f${index}`), 'x');
  await assert.rejects(findSkillDirs([wide], 16, { maxEntries: 19 }), DiscoveryBudgetError);
  assert.equal((await findSkillDirs([wide], 16, { maxEntries: 20 })).skillDirs.length, 0);
});

test('directories reported as too deep and linked Skills count toward the Skill limit', async (t) => {
  const root = await tempDir(t);
  await mkdir(path.join(root, 'a', 'b'), { recursive: true });
  await mkdir(path.join(root, 'c', 'd'), { recursive: true });
  await assert.rejects(findSkillDirs([root], 1, { maxSkills: 1 }), DiscoveryBudgetError);
  const real = await tempDir(t);
  await manySkills(real, 1);
  await symlink(path.join(real, 's0'), path.join(root, 'link1'));
  await symlink(path.join(real, 's0'), path.join(root, 'link2'));
  await assert.rejects(findSkillDirs([root], 16, { maxSkills: 1 }), DiscoveryBudgetError);
});

test('the GitHub Action emits a bounded failure summary when discovery exceeds its budget', async (t) => {
  const org = await setupOrg(t);
  const { base, pr } = await repo(t, org);
  await manySkills(path.join(pr, 'skills'), MAX_DISCOVERED_SKILLS);
  const result = await check(base, pr);
  assert.equal(result.exitCode, 1);
  assert.ok(result.budgetExceeded);
  assert.equal(result.results.length, 1);
  assert.equal(result.results[0]?.verdict, 'UNVERIFIABLE');
  assert.ok(result.summary.length < 1000, result.summary.length.toString());
  assert.match(result.summary, /Skill discovery budget exceeded/u);
  assert.doesNotMatch(result.summary, /s17/u);
});

test('in shadow mode a discovery budget failure is reported but does not fail the check', async (t) => {
  const org = await setupOrg(t);
  const { base, pr } = await repo(t, org, 'shadow');
  await manySkills(path.join(pr, 'skills'), MAX_DISCOVERED_SKILLS);
  const result = await check(base, pr);
  assert.equal(result.exitCode, 0);
  assert.ok(result.budgetExceeded);
  assert.match(result.summary, /Shadow mode/u);
});

test('the GitHub Action summary lists a bounded number of rows and notes the truncation', async (t) => {
  const org = await setupOrg(t);
  const { base, pr } = await repo(t, org);
  const extra = MAX_SUMMARY_ROWS + 20;
  await manySkills(path.join(pr, 'skills'), extra);
  const result = await check(base, pr);
  assert.equal(result.budgetExceeded, undefined);
  assert.equal(result.exitCode, 1);
  const rows = result.summary.split('\n').filter((line) => line.startsWith('| fail ') || line.startsWith('| pass '));
  assert.equal(rows.length, MAX_SUMMARY_ROWS);
  assert.ok(rows.every((row) => row.startsWith('| fail ')), 'failures are listed first');
  assert.match(result.summary, /21 more Skills not listed/u);
  assert.match(result.summary, new RegExp(`1/${extra + 1} Skills verified`, 'u'));
});

test('mago-ski verify-all exits non-zero with a clear message when discovery exceeds its budget', async (t) => {
  const org = await setupOrg(t);
  const dir = await tempDir(t);
  const skills = path.join(dir, 'skills');
  await manySkills(skills, MAX_DISCOVERED_SKILLS + 1);
  const policy = path.join(path.dirname(org.policyPath), 'verify-all.json');
  await writeFile(policy, JSON.stringify({
    policy_version: 'mago.policy/v1', mode: 'enforce', root_fingerprint: org.rootKeyId,
    trust_root: 'trust-root.json', revocations: 'revocations.json', skill_dirs: [skills],
  }));
  await assert.rejects(runCli(['verify-all', '--policy', policy], T0), /more than 1000 Skills found under skill_dirs/u);
});
