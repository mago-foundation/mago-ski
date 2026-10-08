// Integration tests: a real Pi 1.0.4 session (SDK), the mago-ski extension, and Pi's faux model.
import assert from 'node:assert/strict';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import test, { type TestContext } from 'node:test';
import { createAgentSession, DefaultResourceLoader, ModelRuntime, SessionManager } from '@earendil-works/pi-coding-agent';
import { createFauxCore, fauxAssistantMessage, fauxToolCall } from '@earendil-works/pi-ai';
import { createMagoSkiExtension } from '../hosts/pi/index.ts';
import { approve, setupOrg, T0, tempDir, writeSkill, type Org } from './helpers.ts';

interface Harness {
  prompt(text: string): Promise<void>;
  /** Text of every model request so far, as JSON. */
  requests: string[];
  /** Results of tool calls returned to the model. */
  toolResults(): string;
  respond(steps: Parameters<ReturnType<typeof createFauxCore>['setResponses']>[0]): void;
  calls(): number;
}

async function writePolicy(org: Org, mode: 'shadow' | 'enforce'): Promise<void> {
  const policy = JSON.parse(await readFile(org.policyPath, 'utf8'));
  policy.mode = mode;
  await writeFile(org.policyPath, JSON.stringify(policy));
}

async function harness(t: TestContext, org: Org, skillsRoot: string): Promise<Harness> {
  const home = await tempDir(t, 'mago-ski-home-');
  const previousHome = process.env.HOME;
  process.env.HOME = home; // keep the user's real global Skills out of the session
  t.after(() => { process.env.HOME = previousHome; });
  const agentDir = path.join(home, 'agent');
  await mkdir(agentDir);
  const requests: string[] = [];
  const core = createFauxCore({ provider: 'faux', models: [{ id: 'faux-1' }] });
  const runtime = await ModelRuntime.create({
    authPath: path.join(agentDir, 'auth.json'), modelsPath: null, modelsStorePath: path.join(agentDir, 'models-store.json'),
  });
  runtime.registerProvider('faux', {
    api: core.api, apiKey: 'test', baseUrl: 'http://127.0.0.1:9',
    streamSimple: (...args: Parameters<typeof core.streamSimple>) => {
      const [model, context, options] = args;
      requests.push(JSON.stringify(context));
      return core.streamSimple(model, context, options);
    },
    models: [{ id: 'faux-1', name: 'faux', api: core.api, reasoning: false, input: ['text'], cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 }, contextWindow: 100_000, maxTokens: 1_000 }],
  } as never);
  const loader = new DefaultResourceLoader({
    cwd: home, agentDir, additionalSkillPaths: [skillsRoot], noContextFiles: true,
    extensionFactories: [createMagoSkiExtension({ policyPath: org.policyPath, now: () => new Date(T0.getTime() + 60_000) })],
  });
  await loader.reload();
  const { session } = await createAgentSession({
    cwd: home, agentDir, resourceLoader: loader, sessionManager: SessionManager.inMemory(),
    model: runtime.getModel('faux', 'faux-1')!, modelRuntime: runtime,
  });
  await (session as unknown as { bindExtensions?: (options: object) => Promise<void> }).bindExtensions?.({});
  t.after(() => session.dispose());
  return {
    requests,
    prompt: async (text) => { await session.prompt(text); },
    toolResults: () => JSON.stringify(session.messages.filter((message: { role: string }) => message.role === 'toolResult')),
    respond: (steps) => core.setResponses(steps),
    calls: () => core.state.callCount,
  };
}

async function fixture(t: TestContext, mode: 'shadow' | 'enforce') {
  const org = await setupOrg(t);
  await writePolicy(org, mode);
  const skillsRoot = await tempDir(t, 'mago-ski-skills-');
  const approved = await writeSkill(skillsRoot, 'approved-skill', { 'ref.md': 'APPROVED-REFERENCE\n' });
  await writeFile(path.join(approved, 'SKILL.md'), '---\nname: approved-skill\ndescription: An approved Skill.\n---\n# approved\nAPPROVED-BODY\n');
  await approve(org, approved);
  const unapproved = await writeSkill(skillsRoot, 'unapproved-skill');
  await writeFile(path.join(unapproved, 'SKILL.md'), '---\nname: unapproved-skill\ndescription: Not approved.\n---\n# unapproved\nUNAPPROVED-BODY\n');
  const h = await harness(t, org, skillsRoot);
  return { org, approved, unapproved, h };
}

test('enforce: only verified Skills are advertised to the model', async (t) => {
  const { h } = await fixture(t, 'enforce');
  h.respond([fauxAssistantMessage('ok')]);
  await h.prompt('hello');
  const request = h.requests.at(-1)!;
  assert.match(request, /approved-skill/u);
  assert.doesNotMatch(request, /unapproved-skill/u);
});

test('enforce: /skill: for an unverified Skill is refused without calling the model', async (t) => {
  const { h } = await fixture(t, 'enforce');
  h.respond([fauxAssistantMessage('ok')]);
  await h.prompt('hello');
  const before = h.calls();
  await h.prompt('/skill:unapproved-skill do it');
  assert.equal(h.calls(), before);
});

test('enforce: /skill: before the first prompt is rewritten, not expanded by Pi', async (t) => {
  const { h } = await fixture(t, 'enforce');
  h.respond([fauxAssistantMessage('ok')]);
  await h.prompt('/skill:unapproved-skill do it');
  const request = h.requests.at(-1)!;
  assert.doesNotMatch(request, /UNAPPROVED-BODY/u);
  assert.match(request, /Use the \\"unapproved-skill\\" skill/u);
});

test('enforce: /skill: for a verified Skill expands from the verified bytes', async (t) => {
  const { h } = await fixture(t, 'enforce');
  h.respond([fauxAssistantMessage('ok'), fauxAssistantMessage('ok')]);
  await h.prompt('hello');
  await h.prompt('/skill:approved-skill go');
  assert.match(h.requests.at(-1)!, /APPROVED-BODY/u);
});

test('enforce: reads of unverified Skill files are blocked; verified files are allowed', async (t) => {
  const { h, approved, unapproved } = await fixture(t, 'enforce');
  h.respond([
    fauxAssistantMessage([
      fauxToolCall('read', { path: path.join(unapproved, 'SKILL.md') }),
      fauxToolCall('read', { path: path.join(approved, 'ref.md') }),
    ], { stopReason: 'toolUse' }),
    fauxAssistantMessage('done'),
  ]);
  await h.prompt('read both');
  const results = h.toolResults();
  assert.doesNotMatch(results, /UNAPPROVED-BODY/u);
  assert.match(results, /mago-ski: Skill \\"unapproved-skill\\" NO_CERTIFICATE/u);
  assert.match(results, /APPROVED-REFERENCE/u);
});

test('enforce: a verified file swapped after verification is blocked on read', async (t) => {
  const { h, approved } = await fixture(t, 'enforce');
  h.respond([
    // The swap happens after this run's verification and before the model's read.
    async () => {
      await writeFile(path.join(approved, 'ref.md'), 'SWAPPED-CONTENT\n');
      return fauxAssistantMessage([fauxToolCall('read', { path: path.join(approved, 'ref.md') })], { stopReason: 'toolUse' });
    },
    fauxAssistantMessage('done'),
  ]);
  await h.prompt('read it');
  const results = h.toolResults();
  assert.doesNotMatch(results, /SWAPPED-CONTENT/u);
  assert.match(results, /changed after verification/u);
});

test('enforce: bash referencing an unverified Skill and edits to an approved Skill are blocked', async (t) => {
  const { h, approved, unapproved } = await fixture(t, 'enforce');
  h.respond([
    fauxAssistantMessage([
      fauxToolCall('bash', { command: `cat ${path.join(unapproved, 'SKILL.md')}` }),
      fauxToolCall('write', { path: path.join(approved, 'new.md'), content: 'x' }),
    ], { stopReason: 'toolUse' }),
    fauxAssistantMessage('done'),
  ]);
  await h.prompt('try');
  const results = h.toolResults();
  assert.doesNotMatch(results, /UNAPPROVED-BODY/u);
  assert.match(results, /invalidate its certificate/u);
});

test('shadow: nothing is blocked, and would-block decisions are logged', async (t) => {
  const { h, org, unapproved } = await fixture(t, 'shadow');
  h.respond([
    fauxAssistantMessage([fauxToolCall('read', { path: path.join(unapproved, 'SKILL.md') })], { stopReason: 'toolUse' }),
    fauxAssistantMessage('done'),
  ]);
  await h.prompt('read');
  assert.match(h.requests[0]!, /unapproved-skill/u);
  assert.match(h.toolResults(), /UNAPPROVED-BODY/u);
  const log = (await readFile(org.logPath, 'utf8')).trim().split('\n').map((line) => JSON.parse(line));
  assert.ok(log.some((record) => record.action === 'would-block' && record.skill === 'unapproved-skill' && record.event === 'tool:read'));
  assert.ok(log.some((record) => record.action === 'allow' && record.skill === 'approved-skill' && record.event === 'advertise'));
});
