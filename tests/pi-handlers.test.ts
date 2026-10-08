// Calls the Pi extension's handlers directly through a minimal fake ExtensionAPI.
// Covers cases a real Pi session cannot easily produce (PowerShell on Linux, verification errors).
import assert from 'node:assert/strict';
import { chmod, mkdir, readFile, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import test, { type TestContext } from 'node:test';
import { pathToFileURL } from 'node:url';
import { createMagoSkiExtension } from '../hosts/pi/index.ts';
import { IGNORE_FILENAME } from '../src/tree-digest.ts';
import { approve, setupOrg, T0, tempDir, writeSkill, type Org } from './helpers.ts';

type Handler = (event: any, ctx: any) => Promise<any> | any;

function fakePi() {
  const handlers = new Map<string, Handler[]>();
  const api = { on: (name: string, fn: Handler) => { handlers.set(name, [...(handlers.get(name) ?? []), fn]); return () => {}; } };
  const emit = async (name: string, event: any, ctx: any) => {
    let result;
    for (const fn of handlers.get(name) ?? []) result = await fn(event, ctx);
    return result;
  };
  return { api, emit };
}

async function setup(t: TestContext, mode: 'enforce' | 'shadow' = 'enforce') {
  const org: Org = await setupOrg(t);
  const policy = JSON.parse(await readFile(org.policyPath, 'utf8'));
  policy.mode = mode;
  await writeFile(org.policyPath, JSON.stringify(policy));
  const root = await tempDir(t, 'mago-ski-skills-');
  const approved = await writeSkill(root, 'approved-skill', { 'ref.md': 'REF\n' });
  await approve(org, approved);
  const unapproved = await writeSkill(root, 'unapproved-skill');
  const { api, emit } = fakePi();
  createMagoSkiExtension({ policyPath: org.policyPath, now: () => new Date(T0.getTime() + 60_000) })(api as never);
  const ctx = { cwd: root, hasUI: false, ui: { notify() {}, setStatus() {} } };
  const skill = (dir: string) => ({ name: path.basename(dir), filePath: path.join(dir, 'SKILL.md'), baseDir: dir });
  const run = async (dirs = [approved, unapproved]) => {
    const event = { systemPromptOptions: { skills: dirs.map(skill) } };
    await emit('before_agent_start', event, ctx);
    return event.systemPromptOptions.skills.map((entry: { name: string }) => entry.name);
  };
  const tool = (toolName: string, input: Record<string, unknown>) => emit('tool_call', { type: 'tool_call', toolCallId: 't1', toolName, input }, ctx);
  return { org, root, approved, unapproved, run, tool, ctx };
}

test('baseline: only the approved Skill stays advertised', async (t) => {
  const s = await setup(t);
  assert.deepEqual(await s.run(), ['approved-skill']);
});

test('F3: grep inside a verified Skill with ignored files is blocked', async (t) => {
  const s = await setup(t);
  await writeFile(path.join(s.approved, IGNORE_FILENAME), 'cache/\n');
  await mkdir(path.join(s.approved, 'cache'));
  await writeFile(path.join(s.approved, 'cache', 'secret.txt'), 'UNCERTIFIED\n');
  await approve(s.org, s.approved);
  await s.run();
  const result = await s.tool('grep', { pattern: 'UNCERTIFIED', path: s.approved });
  assert.equal(result?.block, true);
  assert.match(result.reason, /excluded from its certificate/u);
});

test('F3: grep inside a verified Skill whose files changed is blocked', async (t) => {
  const s = await setup(t);
  await s.run();
  await writeFile(path.join(s.approved, 'ref.md'), 'SWAPPED\n');
  const result = await s.tool('grep', { pattern: 'x', path: s.approved });
  assert.equal(result?.block, true);
});

test('F3: grep inside a clean verified Skill is allowed', async (t) => {
  const s = await setup(t);
  await s.run();
  assert.equal(await s.tool('grep', { pattern: 'REF', path: s.approved }), undefined);
});

test('F4: a powershell command naming an unverified Skill is blocked', async (t) => {
  const s = await setup(t);
  await s.run();
  const result = await s.tool('powershell', { command: `Get-Content ${path.join(s.unapproved, 'SKILL.md')}` });
  assert.equal(result?.block, true);
});

test('F5: when verification cannot even resolve Skill paths, file tools stay blocked', { skip: process.getuid?.() === 0 ? 'root ignores permissions' : false }, async (t) => {
  const s = await setup(t);
  await chmod(s.root, 0o000);
  let advertised: string[];
  let result;
  try {
    advertised = await s.run();
    result = await s.tool('read', { path: path.join(s.unapproved, 'SKILL.md') });
  } finally {
    await chmod(s.root, 0o755);
  }
  assert.deepEqual(advertised, []);
  assert.equal(result?.block, true);
  assert.match(result.reason, /mago-ski/u);
});

test('F6: a symlink inside an unverified Skill cannot be used to read outside content', async (t) => {
  const s = await setup(t);
  const outside = path.join(await tempDir(t), 'outside.txt');
  await writeFile(outside, 'OUTSIDE\n');
  await symlink(outside, path.join(s.unapproved, 'linked.md'));
  await s.run();
  const result = await s.tool('read', { path: path.join(s.unapproved, 'linked.md') });
  assert.equal(result?.block, true);
});

test('shadow mode never blocks', async (t) => {
  const s = await setup(t, 'shadow');
  assert.deepEqual(await s.run(), ['approved-skill', 'unapproved-skill']);
  assert.equal(await s.tool('powershell', { command: `cat ${s.unapproved}/SKILL.md` }), undefined);
});

// Review 002 residuals.
test('R2: grep after a newly excluded directory appears is blocked', async (t) => {
  const s = await setup(t);
  await writeFile(path.join(s.approved, IGNORE_FILENAME), 'cache/\n');
  await approve(s.org, s.approved);
  await s.run();
  await mkdir(path.join(s.approved, 'cache'));
  await writeFile(path.join(s.approved, 'cache', 'late.txt'), 'LATE-UNCERTIFIED\n');
  const result = await s.tool('grep', { pattern: 'LATE', path: s.approved });
  assert.equal(result?.block, true);
  assert.match(result.reason, /excluded from its certificate/u);
});

test('R3: Pi path aliases (@ prefix, file:// URL) cannot reach an unverified Skill', async (t) => {
  const s = await setup(t);
  await s.run();
  const target = path.join(s.unapproved, 'SKILL.md');
  for (const alias of [`@${target}`, pathToFileURL(target).href]) {
    const result = await s.tool('read', { path: alias });
    assert.equal(result?.block, true, alias);
  }
});

test('R3: read filename variants that Pi tries (NFD) cannot reach an unverified Skill', async (t) => {
  const s = await setup(t);
  const nfdDir = path.join(s.root, 'café-skill');
  await mkdir(nfdDir);
  await writeFile(path.join(nfdDir, 'SKILL.md'), '---\nname: cafe-skill\ndescription: x\n---\nNFD-BODY\n');
  await s.run([s.approved, s.unapproved, nfdDir]);
  const nfcPath = path.join(s.root, 'café-skill', 'SKILL.md');
  const result = await s.tool('read', { path: nfcPath });
  assert.equal(result?.block, true);
});

test('R4: after a refresh crash, the latch also blocks a Skill reached through its real path', async (t) => {
  const s = await setup(t);
  const aliasRoot = path.join(await tempDir(t), 'alias');
  await symlink(s.root, aliasRoot);
  s.ctx.hasUI = true;
  s.ctx.ui.notify = () => { throw new Error('ui exploded'); };
  // Pi reports the Skills through the symlinked alias; the request uses the real path.
  await s.run([path.join(aliasRoot, 'approved-skill'), path.join(aliasRoot, 'unapproved-skill')]).catch(() => {});
  const result = await s.tool('read', { path: path.join(s.unapproved, 'SKILL.md') });
  assert.equal(result?.block, true);
  assert.match(result.reason, /verification failed earlier/u);
});
