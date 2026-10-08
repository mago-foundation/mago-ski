import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import os from 'node:os'; import path from 'node:path';
const NM = path.join(os.homedir(), '.pi/agent/install/releases/1.0.4/node_modules/@earendil-works');
const pi = await import(path.join(NM, 'pi-coding-agent/dist/index.js'));
const ai = await import(path.join(NM, 'pi-ai/dist/index.js'));
const { createAgentSession, DefaultResourceLoader, SessionManager, ModelRuntime } = pi;

const root = await mkdtemp(path.join(os.tmpdir(), 'mago-spike-'));
const skills = path.join(root, 'skills'), agentDir = path.join(root, 'agent');
for (const name of ['approved-skill', 'unapproved-skill']) {
  await mkdir(path.join(skills, name), { recursive: true });
  await writeFile(path.join(skills, name, 'SKILL.md'), `---\nname: ${name}\ndescription: Spike skill ${name}. Use for spike testing.\n---\n# ${name}\nSECRET-BODY-${name}\n`);
}
await mkdir(agentDir, { recursive: true });
const BLOCKED = path.join(skills, 'unapproved-skill');
const log = { advertisedBefore: [], advertisedAfter: [], blockedTools: [], inputHandled: [] };

const ext = (api) => {
  api.on('before_agent_start', (e) => {
    log.advertisedBefore = e.systemPromptOptions.skills.map((s) => s.name);
    e.systemPromptOptions.skills = e.systemPromptOptions.skills.filter((s) => !s.baseDir.startsWith(BLOCKED));
    log.advertisedAfter = e.systemPromptOptions.skills.map((s) => s.name);
  });
  api.on('tool_call', (e) => {
    const target = e.toolName === 'read' ? path.resolve(e.input.path ?? '') : e.toolName === 'bash' ? String(e.input.command) : '';
    if (target.includes(BLOCKED)) { log.blockedTools.push(e.toolName); return { block: true, reason: 'mago-ski: unverified Skill' }; }
  });
  api.on('input', (e) => {
    if (e.text.startsWith('/skill:unapproved-skill')) { log.inputHandled.push(e.text); return { action: 'handled' }; }
    return { action: 'continue' };
  });
};

const core = ai.createFauxCore({ provider: 'faux', models: [{ id: 'faux-1' }] });
const runtime = await ModelRuntime.create({ agentDir });
runtime.registerProvider('faux', { api: core.api, apiKey: 'x', baseUrl: 'http://127.0.0.1:9', streamSimple: core.streamSimple,
  models: [{ id: 'faux-1', name: 'faux', api: core.api, reasoning: false, input: ['text'], cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 }, contextWindow: 100000, maxTokens: 1000 }] });
const model = runtime.getModel('faux', 'faux-1');
let seenSystem = '';
core.setResponses([
  (ctx) => { seenSystem = JSON.stringify(ctx).slice(0, 200000); return ai.fauxAssistantMessage([ai.fauxToolCall('read', { path: path.join(BLOCKED, 'SKILL.md') }), ai.fauxToolCall('bash', { command: `cat ${BLOCKED}/SKILL.md` })], { stopReason: 'toolUse' }); },
  (ctx) => { const s = JSON.stringify(ctx); log.leakedBody = s.includes('SECRET-BODY-unapproved'); return ai.fauxAssistantMessage('done'); },
]);
const loader = new DefaultResourceLoader({ cwd: root, agentDir, additionalSkillPaths: [skills], extensionFactories: [ext], noContextFiles: true });
await loader.reload();
const { session } = await createAgentSession({ cwd: root, agentDir, resourceLoader: loader, sessionManager: SessionManager.inMemory(), model, modelRuntime: runtime });
await session.bindExtensions?.({});
await session.prompt('/skill:unapproved-skill do it');
const callsAfterSkillCmd = core.state.callCount;
await session.prompt('please read the skill');
log.systemMentionsUnapproved = seenSystem.includes('unapproved-skill');
log.systemMentionsApproved = seenSystem.includes('approved-skill');
log.callsAfterSkillCmd = callsAfterSkillCmd;
console.log(JSON.stringify(log, null, 2));
session.dispose();
