import assert from 'node:assert/strict';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { diffSkillTrees } from '../src/diff.ts';
import { tempDir, writeSkill } from './helpers.ts';

// The "linear time" inputs below kept the old backtracking regexes busy for minutes to hours. A regression shows
// up as a hung test file, not a failed test: a test timeout cannot interrupt a synchronous regex.
const SKILL = '---\nname: demo\ndescription: Test Skill demo.\n---\n# demo\n\nFollow the steps.\n';

async function pair(t: Parameters<typeof tempDir>[0], base: Record<string, string>, candidate: Record<string, string>) {
  const dir = await tempDir(t);
  return diffSkillTrees(await writeSkill(path.join(dir, 'base'), 'demo', base), await writeSkill(path.join(dir, 'candidate'), 'demo', candidate));
}

test('diff reports unchanged trees, changed sections and added origins', async (t) => {
  const same = await pair(t, {}, {});
  assert.equal(same.result, 'UNCHANGED');
  assert.equal(same.recertification_required, false);
  assert.equal(same.capability_evidence.analysis_complete, true);

  const content = await pair(t, {}, { 'SKILL.md': SKILL.replace('Follow the steps.', 'Follow the steps!') });
  assert.equal(content.result, 'CONTENT_CHANGED');
  assert.deepEqual(content.files.map((file) => [file.path, file.changed_sections]), [['SKILL.md', ['# demo']]]);

  const capability = await pair(t, { 'run.sh': 'curl https://a.example/x\n' }, { 'run.sh': 'curl https://a.example/x https://B.example:8443/y.\n' });
  assert.equal(capability.result, 'CAPABILITY_CHANGED');
  assert.deepEqual(capability.capability_evidence.added_network_origins, ['https://b.example:8443']);
  assert.deepEqual(capability.capability_evidence.removed_network_origins, []);
});

test('a heading with a long run of blanks parses in linear time, and its label is capped', async (t) => {
  const result = await pair(t, {}, { 'SKILL.md': `${SKILL}# a${' '.repeat(200_000)}b\n` });
  const labels = result.files[0]!.changed_sections;
  assert.equal(labels.length, 1);
  assert.match(labels[0]!, /^# a {199}\.\.\.$/u);
});

test('a lone CR ends a line, and a long line before it parses in linear time', async (t) => {
  const result = await pair(t, {}, { 'SKILL.md': `${'a'.repeat(500_000)}\r# later\n` });
  assert.deepEqual(result.files[0]!.changed_sections, ['# demo', '# later', '(document body)']);
});

test('fenced code hides headings until a closing fence of the same character and at least the same length', async (t) => {
  const result = await pair(t, {}, { 'SKILL.md': `${SKILL}\n~~~~\n# hidden\n~~~\n## hidden too\n  ~~~~~  \n## shown\n` });
  // The fenced lines stay inside "# demo", so that section changes; neither hidden heading starts one.
  assert.deepEqual(result.files[0]!.changed_sections, ['# demo', '## shown']);
});

test('more sections than the index holds are reported as truncated', async (t) => {
  const headings = Array.from({ length: 5_000 }, (_, i) => `# h${i}\n`).join('');
  const result = await pair(t, {}, { 'SKILL.md': `${SKILL}${headings}` });
  assert.equal(result.files[0]!.sections_truncated, true);
  assert.equal(result.files[0]!.changed_sections.length, 32);
  assert.equal(result.diff_truncated, true);
});

test('Markdown section diffing stops at the total size budget', async (t) => {
  const dir = await tempDir(t);
  const roots: string[] = [];
  for (const side of ['base', 'candidate']) {
    const root = await writeSkill(path.join(dir, side), 'demo');
    await mkdir(path.join(root, 'docs'));
    // Nine files of exactly 1 MiB per side: the first eight spend the 16 MiB budget exactly.
    const marker = side === 'base' ? 'B' : 'C';
    for (let i = 0; i < 9; i += 1) await writeFile(path.join(root, 'docs', `${i}.md`), `# doc\n${marker}${'x'.repeat(1024 * 1024 - 8)}\n`);
    roots.push(root);
  }
  const result = await diffSkillTrees(roots[0]!, roots[1]!);
  assert.deepEqual(result.files.map((file) => file.changed_sections[0]), [...Array(8).fill('# doc'), '(whole file; total size limit)']);
  assert.equal(result.files[8]!.sections_truncated, true);
  assert.equal(result.capability_evidence.analysis_complete, false);
});

test('a URL followed by a long punctuation run is scanned in linear time', async (t) => {
  const result = await pair(t, {}, { 'notes.txt': `see http://a.example/${'.'.repeat(1_000_000)}x\n` });
  assert.deepEqual(result.capability_evidence.added_network_origins, ['http://a.example']);
  assert.equal(result.capability_evidence.analysis_complete, true);
});

test('origin scanning stops after 100,000 URL candidates per tree', async (t) => {
  const urls = (count: number) => Array.from({ length: count }, (_, i) => `http://a.example/${i}`).join('\n');
  const under = await pair(t, {}, { 'a.txt': urls(30_000), 'b.txt': urls(30_000), 'c.txt': urls(30_000) });
  assert.equal(under.capability_evidence.analysis_complete, true);
  const over = await pair(t, {}, { 'a.txt': urls(40_000), 'b.txt': urls(40_000), 'c.txt': urls(40_000) });
  assert.equal(over.capability_evidence.analysis_complete, false);
  assert.deepEqual(over.capability_evidence.added_network_origins, ['http://a.example']);
});

test('origins longer than any DNS name are left out and mark the analysis incomplete', async (t) => {
  const result = await pair(t, {}, { 'run.sh': `curl http://${'a.'.repeat(200)}example/ https://ok.example/\n` });
  assert.deepEqual(result.capability_evidence.added_network_origins, ['https://ok.example']);
  assert.equal(result.capability_evidence.analysis_complete, false);
});
