import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { AdmissionRulesError, escalation, evaluate, parseRules, replay, type Facts, type SkillFacts } from '../src/admission.ts';
import { collectSkillFacts } from '../src/admission-evidence.ts';
import { loadPolicy } from '../src/policy.ts';
import { observeSkill } from '../src/profile.ts';
import { approve, daysAfter, setupOrg, T0, tempDir, writeSkill } from './helpers.ts';

const RULES = `admission_version: mago.admission/v0
default: REQUIRE_REVIEW
rules:
  - id: our-own-skills
    when:
      publisher: { repository_id: "111", workflow: .github/workflows/publish.yml }
    action: ALLOW
  - id: reviewed
    when: { reviewed: true }
    action: ALLOW
  - id: plain-updates
    when:
      update: { same_publisher: true, max_days_since_review: 90 }
    action: ALLOW
  - id: shell-is-flagged
    when:
      capabilities: { shell: true }
    action: FLAG
  - id: never-this-site
    when:
      capabilities: { websites: [evil.example] }
    action: BLOCK
    reason: "evil.example is blocked by policy"
`;

const profile = (hosts: string[] = [], scripts = 0) => ({
  profile: 'mago.observed-profile/v1' as const, digest: 'sha256:' + 'a'.repeat(64), web_hosts: hosts,
  scripts: Array.from({ length: scripts }, (_, i) => ({ path: `s${i}.sh`, reason: '.sh file' })), programs: [],
  not_searched: { media: [], unreadable: [], ignored: [] }, complete: true,
});
const publisher = (id = '111', workflow = '.github/workflows/publish.yml', ref = 'refs/heads/main', trigger = 'release') => ({ repository_id: id, owner_id: '9', repository: 'https://github.com/acme/skills', workflow, commit: 'c'.repeat(40), ref, trigger });
const skill = (over: Partial<SkillFacts> = {}): SkillFacts => ({ name: 'demo', digest: 'sha256:' + 'b'.repeat(64), profile: profile(), declaration: null, declaration_error: null, reviewed_by: null, published_by: null, ...over });
const review = { approver_key_id: 'k', certificate_id: 'c', issued_at: T0.toISOString(), expires_at: daysAfter(T0, 90).toISOString() };
const facts = (s: SkillFacts, base: SkillFacts | null = null): Facts => ({ skill: s, base });

test('the linter refuses what a closed language can catch', () => {
  const bad: Array<[string, RegExp]> = [
    ['admission_version: mago.admission/v1\ndefault: BLOCK\nrules: []\n', /admission_version/u],
    ['admission_version: mago.admission/v0\ndefault: MAYBE\nrules: []\n', /default must be one of/u],
    ['admission_version: mago.admission/v0\ndefault: BLOCK\nrules:\n  - { id: a, when: {}, action: ALLOW }\n', /would admit every Skill/u],
    ['admission_version: mago.admission/v0\ndefault: BLOCK\nrules:\n  - { id: a, when: { capabilities: { shell: true } }, action: ALLOW }\n', /only make a decision stricter/u],
    ['admission_version: mago.admission/v0\ndefault: BLOCK\nrules:\n  - { id: a, when: { reviewed: false }, action: ALLOW }\n', /cannot be a reason to admit/u],
    ['admission_version: mago.admission/v0\ndefault: BLOCK\nrules:\n  - { id: a, when: {}, action: BLOCK }\n', /needs a reason/u],
    ['admission_version: mago.admission/v0\ndefault: BLOCK\nrules:\n  - { id: a, when: { reviewed: true }, action: ALLOW }\n  - { id: a, when: { reviewed: true }, action: ALLOW }\n', /used twice/u],
    ['admission_version: mago.admission/v0\ndefault: BLOCK\nrules:\n  - { id: a, when: { publisher: { repository: acme/skills } }, action: ALLOW }\n', /unknown key "repository"/u],
    ['admission_version: mago.admission/v0\ndefault: BLOCK\nrules:\n  - { id: a, when: { publisher: { workflow: .github/workflows/x.yml } }, action: ALLOW }\n', /only means something with a repository_id/u],
    ['admission_version: mago.admission/v0\ndefault: BLOCK\nrules:\n  - { id: a, when: { publisher: { repository_id: 111 } }, action: ALLOW }\n', /numeric repository id, quoted/u],
    ['admission_version: mago.admission/v0\ndefault: BLOCK\nrules:\n  - { id: a, when: { tag: v1 }, action: ALLOW }\n', /unknown key "tag"/u],
  ];
  for (const [source, error] of bad) assert.throws(() => parseRules(source), (e: Error) => e instanceof AdmissionRulesError && error.test(e.message), source);
  const rules = parseRules(RULES);
  assert.deepEqual(rules.rules.map((r) => r.id), ['our-own-skills', 'reviewed', 'plain-updates', 'shell-is-flagged', 'never-this-site']);
  assert.match(rules.digest, /^sha256:[0-9a-f]{64}$/u);
});

test('decisions: publisher, review, default, and the strictest action wins', () => {
  const rules = parseRules(RULES);
  assert.deepEqual(evaluate(rules, facts(skill()), T0), { action: 'REQUIRE_REVIEW', admitted: false, rule_id: 'default', matched: [], reason: null, missing: 'a review of this exact version (reviewed-by)' });
  assert.equal(evaluate(rules, facts(skill({ published_by: publisher() })), T0).rule_id, 'our-own-skills');
  // Same repository name, another repository id (a new repository or fork): not ours.
  assert.equal(evaluate(rules, facts(skill({ published_by: publisher('222') })), T0).action, 'REQUIRE_REVIEW');
  assert.equal(evaluate(rules, facts(skill({ published_by: publisher('111', '.github/workflows/other.yml') })), T0).action, 'REQUIRE_REVIEW');
  assert.equal(evaluate(rules, facts(skill({ reviewed_by: review })), T0).rule_id, 'reviewed');
  const flagged = evaluate(rules, facts(skill({ reviewed_by: review, profile: profile([], 1) })), T0);
  assert.deepEqual([flagged.action, flagged.admitted, flagged.rule_id], ['FLAG', true, 'shell-is-flagged']);
  const blocked = evaluate(rules, facts(skill({ published_by: publisher(), reviewed_by: review, profile: profile(['cdn.evil.example', 'evil.example']) })), T0);
  assert.deepEqual([blocked.action, blocked.rule_id, blocked.reason], ['BLOCK', 'never-this-site', 'evil.example is blocked by policy']);
  assert.deepEqual(blocked.matched, ['our-own-skills', 'reviewed', 'never-this-site']);
});

test('updates: admitted only from a reviewed base, same publisher, no escalation, within the time bound', () => {
  const rules = parseRules(RULES);
  const base = skill({ digest: 'sha256:' + 'c'.repeat(64), reviewed_by: review, published_by: publisher('333'), profile: profile(['api.example.com']) });
  const next = skill({ published_by: publisher('333'), profile: profile(['api.example.com']) });
  assert.equal(evaluate(rules, facts(next, base), daysAfter(T0, 30)).rule_id, 'plain-updates');
  assert.equal(evaluate(rules, facts(next, base), daysAfter(T0, 91)).action, 'REQUIRE_REVIEW');
  assert.equal(evaluate(rules, facts(next, { ...base, reviewed_by: null }), T0).action, 'REQUIRE_REVIEW');
  assert.equal(evaluate(rules, facts({ ...next, published_by: publisher('444') }, base), T0).action, 'REQUIRE_REVIEW');
  const wider = { ...next, profile: profile(['api.example.com', 'new.example']) };
  assert.equal(escalation(base, wider), 'it reaches new websites: new.example');
  const decision = evaluate(rules, facts(wider, base), T0);
  assert.equal(decision.action, 'REQUIRE_REVIEW');
  assert.match(decision.missing!, /not a plain update because it reaches new websites: new\.example/u);
  // A declared host counts as reach, even when the files do not show it yet.
  const declared = { ...next, declaration: { files: { read: [], write: [], deny_write: [] }, network: { allow: ['later.example'], deny: '*' }, shell: false, tools: [], requires: { binaries: [], min_runtime_version: null }, unknownKeys: [] } };
  assert.match(escalation(base, declared)!, /later\.example/u);
  assert.match(escalation(base, { ...next, profile: profile(['api.example.com'], 1) })!, /runs code/u);
  assert.equal(evaluate(rules, facts(next, next), T0).action, 'REQUIRE_REVIEW');
});

test('replay lists exactly the decisions a new rule file would change', () => {
  const before = parseRules(RULES);
  const after = parseRules(RULES.replace('max_days_since_review: 90', 'max_days_since_review: 7'));
  const base = skill({ digest: 'sha256:' + 'c'.repeat(64), reviewed_by: review, published_by: publisher('333') });
  const records = [
    { decided_at: daysAfter(T0, 30).toISOString(), rules_digest: before.digest, facts: facts(skill({ published_by: publisher('333') }), base), decision: evaluate(before, facts(skill({ published_by: publisher('333') }), base), daysAfter(T0, 30)) },
    { decided_at: daysAfter(T0, 3).toISOString(), rules_digest: before.digest, facts: facts(skill({ published_by: publisher('333') }), base), decision: evaluate(before, facts(skill({ published_by: publisher('333') }), base), daysAfter(T0, 3)) },
    { decided_at: T0.toISOString(), rules_digest: before.digest, facts: facts(skill({ reviewed_by: review })), decision: evaluate(before, facts(skill({ reviewed_by: review })), T0) },
  ];
  const flips = replay(before, after, records);
  assert.equal(flips.length, 1);
  assert.deepEqual([flips[0]!.before.action, flips[0]!.after.action], ['ALLOW', 'REQUIRE_REVIEW']);
  assert.deepEqual(replay(before, before, records), []);
});

test('evidence: a review counts only for the exact bytes the trust root vouches for', async (t) => {
  const org = await setupOrg(t);
  const policy = await loadPolicy(org.policyPath);
  const dir = await writeSkill(await tempDir(t), 'docs-helper', { 'run.sh': 'curl https://api.example.com\n' });
  const none = await collectSkillFacts(dir, { policy }, undefined, T0);
  assert.equal(none.reviewed_by, null);
  assert.deepEqual(none.profile, await observeSkill(dir));
  await approve(org, dir);
  const reviewed = await collectSkillFacts(dir, { policy }, undefined, T0);
  assert.equal(reviewed.reviewed_by?.issued_at, T0.toISOString());
  assert.equal(reviewed.name, 'docs-helper');
  assert.equal(evaluate(parseRules(RULES), { skill: reviewed, base: null }, T0).action, 'FLAG');
  await writeFile(path.join(dir, 'run.sh'), 'curl https://other.example\n');
  assert.equal((await collectSkillFacts(dir, { policy }, undefined, T0)).reviewed_by, null);
  await assert.rejects(collectSkillFacts(dir, { publishedBy: '/nonexistent' }, undefined, T0), RangeError);
});

test('review 007: capability rules only tighten, even with an admitting action', () => {
  const rules = parseRules(RULES);
  // C1: shell code on an unreviewed Skill must not turn REQUIRE_REVIEW into FLAG.
  const unreviewed = evaluate(rules, facts(skill({ profile: profile([], 1) })), T0);
  assert.deepEqual([unreviewed.action, unreviewed.admitted, unreviewed.rule_id], ['REQUIRE_REVIEW', false, 'default']);
  const lenient = parseRules('admission_version: mago.admission/v0\ndefault: BLOCK\nrules:\n  - id: f\n    when: { capabilities: { shell: true } }\n    action: LOG_ONLY\n');
  assert.equal(evaluate(lenient, facts(skill({ profile: profile([], 1) })), T0).action, 'BLOCK');
  assert.throws(() => parseRules('admission_version: mago.admission/v0\ndefault: BLOCK\nrules:\n  - { id: a, when: { capabilities: { shell: true } }, action: ALLOW }\n'), /no effect/u);
});

test('review 007: updates that widen files, tools or programs, or come from another Skill, are not plain updates', () => {
  const rules = parseRules(RULES);
  const decl = (over: Record<string, unknown> = {}) => ({ files: { read: [], write: [], deny_write: ['SOUL.md'] }, network: { allow: [], deny: '*' }, shell: false, tools: [], requires: { binaries: [], min_runtime_version: null }, unknownKeys: [], ...over });
  const base = skill({ digest: 'sha256:' + 'c'.repeat(64), reviewed_by: review, published_by: publisher('333'), declaration: decl() });
  const next = (d: Record<string, unknown>) => skill({ published_by: publisher('333'), declaration: decl(d) });
  for (const [change, why] of [
    [{ files: { read: ['~/.ssh/id_rsa'], write: [], deny_write: ['SOUL.md'] } }, /read new files/u],
    [{ files: { read: [], write: ['~/.bashrc'], deny_write: ['SOUL.md'] } }, /write new files/u],
    [{ files: { read: [], write: [], deny_write: [] } }, /no longer protects/u],
    [{ tools: ['Bash'] }, /new tools/u],
    [{ requires: { binaries: ['curl'], min_runtime_version: null } }, /new programs/u],
  ] as const) {
    assert.match(escalation(base, next(change as Record<string, unknown>)) ?? '', why);
    assert.equal(evaluate(rules, facts(next(change as Record<string, unknown>), base), T0).action, 'REQUIRE_REVIEW');
  }
  assert.equal(evaluate(rules, facts(next({}), base), T0).rule_id, 'plain-updates');
  const other = evaluate(rules, facts({ ...next({}), name: 'other-skill' }, base), T0);
  assert.equal(other.action, 'REQUIRE_REVIEW');
  assert.match(other.missing!, /another Skill \(demo\)/u);
});

test('review 007: replay refuses incomplete log records instead of reading missing as present', () => {
  const rules = parseRules(RULES);
  const good = { decided_at: T0.toISOString(), rules_digest: rules.digest, facts: facts(skill()), decision: evaluate(rules, facts(skill()), T0) };
  const { reviewed_by: _drop, ...noReview } = good.facts.skill;
  for (const bad of [null, {}, { ...good, facts: { skill: {} } }, { ...good, facts: { skill: noReview, base: null } }, { ...good, decided_at: 'soon' }])
    assert.throws(() => replay(rules, rules, [bad]), /log record 1/u);
  assert.deepEqual(replay(rules, rules, [good]), []);
});

test('publisher conditions: branch and trigger', () => {
  const rules = parseRules('admission_version: mago.admission/v0\ndefault: REQUIRE_REVIEW\nrules:\n  - id: releases-from-main\n    when:\n      publisher: { repository_id: "111", branch: main, trigger: [release, push] }\n    action: ALLOW\n');
  assert.equal(evaluate(rules, facts(skill({ published_by: publisher() })), T0).action, 'ALLOW');
  assert.equal(evaluate(rules, facts(skill({ published_by: publisher('111', '.github/workflows/publish.yml', 'refs/heads/dev') })), T0).action, 'REQUIRE_REVIEW');
  assert.equal(evaluate(rules, facts(skill({ published_by: publisher('111', '.github/workflows/publish.yml', 'refs/heads/main', 'workflow_dispatch') })), T0).action, 'REQUIRE_REVIEW');
  assert.throws(() => parseRules('admission_version: mago.admission/v0\ndefault: BLOCK\nrules:\n  - { id: a, when: { publisher: { repository_id: "1", tag: v1 } }, action: ALLOW }\n'), /unknown key "tag"/u);
});

test('review 008: removed or unreadable declarations, new unknown keys and a dropped deny escalate', () => {
  const decl = { files: { read: [], write: [], deny_write: [] }, network: { allow: [], deny: '*' }, shell: false, tools: [], requires: { binaries: [], min_runtime_version: null }, unknownKeys: [] };
  const base = skill({ digest: 'sha256:' + 'c'.repeat(64), reviewed_by: review, published_by: publisher('333'), declaration: decl });
  const next = (over: Partial<SkillFacts>) => skill({ published_by: publisher('333'), ...over });
  assert.match(escalation(base, next({ declaration: null }))!, /no longer has a declaration/u);
  assert.match(escalation(base, next({ declaration: null, declaration_error: 'ambiguous' }))!, /cannot be read reliably/u);
  assert.match(escalation(skill({ ...base, declaration: null }), next({ declaration: null, declaration_error: 'ambiguous' }))!, /cannot be read reliably/u);
  assert.match(escalation(skill({ ...base, declaration: null, declaration_error: 'ambiguous' }), next({ declaration: null, declaration_error: 'ambiguous' }))!, /cannot be read reliably/u);
  assert.match(escalation(base, next({ declaration: { ...decl, unknownKeys: ['permissions.exec'] } }))!, /does not know/u);
  assert.match(escalation(base, next({ declaration: { ...decl, network: { allow: [], deny: null } } }))!, /network\.deny/u);
  assert.equal(escalation(base, next({ declaration: decl })), null);
});

test('review 008: admitting actions with no basis are lint errors; log records are checked field by field', () => {
  for (const act of ['LOG_ONLY', 'FLAG'])
    assert.throws(() => parseRules(`admission_version: mago.admission/v0\ndefault: BLOCK\nrules:\n  - { id: a, when: {}, action: ${act} }\n`), /would admit every Skill/u);
  assert.throws(() => parseRules('admission_version: mago.admission/v0\ndefault: BLOCK\nrules:\n  - { id: a, when: { reviewed: false }, action: FLAG }\n'), /cannot be a reason to admit/u);
  const rules = parseRules(RULES);
  const good = { decided_at: T0.toISOString(), rules_digest: rules.digest, facts: facts(skill({ reviewed_by: review })), decision: evaluate(rules, facts(skill()), T0) };
  const declaration = { files: { read: 'x', write: [], deny_write: [] }, network: { allow: [], deny: null }, shell: null, tools: [], requires: { binaries: [], min_runtime_version: null }, unknownKeys: [] };
  for (const bad of [
    { ...good, facts: facts(skill({ declaration: declaration as never })) },
    { ...good, facts: facts(skill({ reviewed_by: { ...review, issued_at: 'garbage' } })) },
  ]) assert.throws(() => replay(rules, rules, [bad]), /log record 1/u);
});
