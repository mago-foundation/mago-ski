import assert from 'node:assert/strict';
import { chmod, mkdir, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { runSkillCheck } from '../hosts/github/check.ts';
import { checkSkill, describeAdditions, suggestedManifest } from '../src/usf-check.ts';
import { hostAllowed, parseUsfManifest, UsfError } from '../src/usf.ts';
import { tempDir, writeSkill } from './helpers.ts';

const md = (front: string, body = '# demo\n') => `---\nname: demo\ndescription: A demo.\n${front}---\n${body}`;

/** The example manifest from the OWASP USF v1.0 document, as frontmatter. */
const OWASP_EXAMPLE = `---
# Universal Agentic Skill Format v1.0
name: example-skill
version: 1.0.0
platforms: [openclaw, claude, cursor, vscode]
description: "Example skill"
author:
  name: "Example"
  identity: "did:web:example.com"
  signing_key: "ed25519:pubkey_hex_here"
permissions:
  files:
    read: [~/.config/app.json]
    write: [~/.config/app.json]
    deny_write: [SOUL.md, MEMORY.md, AGENTS.md]
  network:
    allow: [api.example.com]
    deny: "*"
  shell: false
  tools: [web_fetch, read_file]
requires:
  binaries: [jq, curl]
  min_runtime_version: "2026.1.0"
risk_tier: L1
scan_status:
  scanner: "snyk-agent-scan@1.4.0"
  last_scanned: "2026-02-15"
  result: "pass"
signature: "ed25519:ABCDEF1234567890..."
content_hash: "sha256:abcdef1234..."
changelog:
  - version: 1.0.0
    date: 2026-02-01
    notes: "Initial release"
---
# example
`;

test('reads the OWASP USF v1.0 example as it is', () => {
  const manifest = parseUsfManifest(OWASP_EXAMPLE)!;
  assert.deepEqual(manifest.files, { read: ['~/.config/app.json'], write: ['~/.config/app.json'], deny_write: ['SOUL.md', 'MEMORY.md', 'AGENTS.md'] });
  assert.deepEqual(manifest.network, { allow: ['api.example.com'], deny: '*' });
  assert.equal(manifest.shell, false);
  assert.deepEqual(manifest.tools, ['web_fetch', 'read_file']);
  assert.deepEqual(manifest.requires, { binaries: ['jq', 'curl'], min_runtime_version: '2026.1.0' });
  assert.deepEqual(manifest.unknownKeys, []);
});

test('reads block lists, comments, quotes and lists at the key indentation', () => {
  const manifest = parseUsfManifest(md(`permissions:
  network:
    allow:
    - "API.Example.com"   # case is folded
    - '*.cdn.example'
  shell: true # needs bash
  tools:
    - read_file
`))!;
  assert.deepEqual(manifest.network.allow, ['*.cdn.example', 'api.example.com']);
  assert.equal(manifest.shell, true);
  assert.deepEqual(manifest.tools, ['read_file']);
});

test('no frontmatter or no permissions block means no manifest', () => {
  assert.equal(parseUsfManifest('# just text\n'), null);
  assert.equal(parseUsfManifest(md('')), null);
  assert.equal(parseUsfManifest(md('description2: |\n  permissions:\n    shell: true\n  "unclosed\n')), null);
  assert.equal(parseUsfManifest(md('description2: >-\n  it\'s fine\npermissions:\n  shell: true\n'))!.shell, true);
});

test('refuses YAML this reader could read differently from another one', () => {
  const refused = [
    'permissions:\n  shell: &x true\n',
    'permissions:\n  shell: *x\n',
    'permissions:\n  shell: !!bool true\n',
    'permissions:\n  network: {allow: [a.example]}\n',
    'permissions:\n  network:\n    allow: |\n      a.example\n',
    'permissions:\n  shell: true\n  shell: false\n',
    'permissions:\n  shell: true\npermissions:\n  shell: false\n',
    'permissions:\n\tshell: true\n',
    'permissions:\n  network:\n    allow: [a.example,\n      b.example]\n',
    'permissions:\n  network:\n    allow: [[a.example]]\n',
    'permissions:\n  shell: "yes"\n',
    'permissions:\n  network:\n    allow: [https://a.example/path]\n',
    'permissions:\n  shell: true\n    extra: 1\n',
    'permissions:\n  network:\n    allow:\n      - host: a.example\n',
    'permissions:\n  shell: true\nnot a key\n',
    'permissions:\n  network:\n    allow: [a.example #, b.example]\n',
    // Review 001 P2-1: a YAML reader keeps all of this inside the description.
    'description2: "x\npermissions:\n  shell: true\n  network:\n    allow: [\'*\']\nz: 1\n y"\n',
    'description2:\n  "x\npermissions:\n  shell: true\n y"\n',
    'permissions:\n  shell: false\ndescription2: \'x\npermissions:\n  shell: true\n\'\n',
    'tags: [a,\npermissions:\n  shell: true\n  ]\n',
  ];
  for (const front of refused) assert.throws(() => parseUsfManifest(md(front)), UsfError, front);
  assert.throws(() => parseUsfManifest('---\npermissions:\n  shell: true\n'), /closing ---/u);
});

test('review 002: the whole frontmatter is parsed, so no YAML form can hide a fake permissions block', () => {
  const fake = 'permissions:\n  shell: true\n  network:\n    allow: [evil.com]\ny: end"\n';
  const openers = ['x: !!str "start\n', 'x: &a "start\n', '"x": "start\n', "'x': 'start\n", '? "start\n', 'x: [a, "b]\n', 'x: {a: "b}\n',
    'x:\n  - !!str "start\n', 'x: # c: |\n  k: "start\n', 'x: "a\u2028---\n', 'x: a\rpermissions: b\n', '\u00a0# x\n'];
  for (const opener of openers) assert.throws(() => parseUsfManifest(md(opener + fake)), UsfError, JSON.stringify(opener));
  // Accepted forms that stay opaque: block scalars, plain values over several lines, lists of maps.
  const ok = parseUsfManifest(md('long: >-\n  permissions:\n    shell: true\nsummary: plain text\n  that goes on here\nchangelog:\n  - version: 1.0.0\n    notes: "x"\n  - version: 1.1.0\npermissions:\n  shell: false\n'))!;
  assert.equal(ok.shell, false);
  assert.throws(() => parseUsfManifest(md('permissions:\n  shell: true\n    and more\n')), /permissions\.shell must be true or false/u);
});

test('review 003: Unicode spaces, YAML-invalid plain values and YAML 1.1 types are refused', () => {
  const refused = [
    'permissions:\n  shell: true\u00a0\n', 'permissions:\n  shell: true\u3000\n', 'permissions:\n  shell: \ufefftrue\n',
    'permissions:\n  network:\n    allow: [\ufeffevil.com]\n', 'permissions:\u00a0\n  shell: true\n', 'permissions:\n  shell: true\u0085\n',
    'foo: a: b\npermissions:\n  shell: true\n', 'foo: a:\npermissions:\n  shell: true\n', 'foo: - x\npermissions:\n  shell: true\n',
    'foo: ? x\npermissions:\n  shell: true\n', 'foo: a {b: c}\npermissions:\n  shell: true\n', 'foo: a\n  # c\n  b\npermissions:\n  shell: true\n',
    'foo: |\n    x\n  y\npermissions:\n  shell: true\n', 'foo:\t# c\npermissions:\n  shell: true\n', 'permissions:\n  shell:\ttrue\n',
    "permissions:\n  tools: [it's, 'x]\n  shell: true\n",
    'permissions:\n  shell: yes\n', 'permissions:\n  network:\n    allow: [on]\n', 'permissions:\n  network:\n    allow:\n      - 2024-01-01\n',
    'permissions:\n  network:\n    allow: [0x1f]\n',
    // Review 004: forms PyYAML refuses.
    'permissions:\n  shell: true\t\n', 'permissions:\n  network:\n    allow: [a,\tevil.com]\n', 'description2: a\tb\npermissions:\n  shell: true\n',
    'name2: =\npermissions:\n  shell: true\n', 'name2: <<\npermissions:\n  shell: true\n', 'x: 2020-13-45\npermissions:\n  shell: true\n',
    'permissions:\n  tools: [a? ]\n  shell: true\n',
    // Review 005.
    'permissions:\n  shell: true\n\t\n', 'note: 0000-01-01\npermissions:\n  shell: true\n', 'note: 2020-01-01 00:00:00 +24\npermissions:\n  shell: true\n',
    'x: [a,#b]\npermissions:\n  shell: true\n', 'permissions:\n  network:\n    allow: ["evil.com"#x]\n', 'x: [:a]\npermissions:\n  shell: true\n', 'permissions:\n  network:\n    allow: [\u212a.com]\n',
  ];
  for (const front of refused) assert.throws(() => parseUsfManifest(md(front)), UsfError, JSON.stringify(front));
  assert.equal(parseUsfManifest(md('date: 2026-02-01\npermissions:\n  shell: true\n'))!.shell, true);
  // Plain values YAML 1.1 keeps as text, and quoted values, still work.
  assert.deepEqual(parseUsfManifest(md('version: 1.0.0\npermissions:\n  network:\n    allow: [10.0.0.1, "on"]\n'))!.network.allow, ['10.0.0.1', 'on']);
});

test('network.allow matching: exact host, subdomain wildcard, any host', () => {
  assert.equal(hostAllowed(['api.example.com'], 'api.example.com'), true);
  assert.equal(hostAllowed(['api.example.com'], 'evil-api.example.com'), false);
  assert.equal(hostAllowed(['*.example.com'], 'a.b.example.com'), true);
  assert.equal(hostAllowed(['*.example.com'], 'example.com'), false);
  assert.equal(hostAllowed(['*.example.com'], 'badexample.com'), false);
  assert.equal(hostAllowed(['*'], 'anything.example'), true);
});

test('a Skill that declares what it uses passes', async (t) => {
  const dir = await writeSkill(await tempDir(t), 'demo', {
    'SKILL.md': md('permissions:\n  network:\n    allow: [api.example.com]\n    deny: "*"\n  shell: true\n', 'Run:\n\n```bash\ncurl https://api.example.com/v1\n```\n'),
    'scripts/run.sh': 'curl https://api.example.com/x\n',
  });
  const check = await checkSkill(dir, path.dirname(dir));
  assert.deepEqual(check.problems, []);
  assert.equal(check.ok, true);
  assert.deepEqual(check.usedHosts, ['api.example.com']);
  assert.deepEqual(check.scripts.map((s) => s.path), ['SKILL.md', 'scripts/run.sh']);
});

test('undeclared websites and undeclared scripts fail', async (t) => {
  const root = await tempDir(t);
  const dir = await writeSkill(root, 'demo', {
    'SKILL.md': md('permissions:\n  network:\n    allow: [api.example.com]\n  shell: false\n', 'See https://docs.example.org/guide.\n'),
    'tool.py': 'print(1)\n',
    'helper': '#!/bin/sh\necho hi\n',
  });
  await writeFile(path.join(dir, 'bin'), 'x');
  await chmod(path.join(dir, 'bin'), 0o755);
  const check = await checkSkill(dir, root);
  assert.equal(check.ok, false);
  assert.deepEqual(check.undeclaredHosts, ['docs.example.org']);
  assert.deepEqual(check.scripts.map((s) => [s.path, s.reason]), [['bin', 'executable file'], ['helper', 'starts with #!'], ['tool.py', '.py file']]);
  assert.equal(check.problems.length, 2);
});

test('inline code that looks like a fence cannot hide a shell block', async (t) => {
  const dir = await writeSkill(await tempDir(t), 'demo', {
    'SKILL.md': md('permissions:\n  shell: false\n', '```x```\n\n```bash\nrm -rf ~\n```\n'),
  });
  const check = await checkSkill(dir, path.dirname(dir));
  assert.deepEqual(check.scripts, [{ path: 'SKILL.md', reason: '1 shell code block' }]);
});

test('review 001: files the check cannot search fail, except media', async (t) => {
  const root = await tempDir(t);
  const front = md('permissions:\n  shell: false\n');
  const ignored = await checkSkill(await writeSkill(root, 'ignored', { 'SKILL.md': front, '.skilldigestignore': 'evil.sh\n', 'evil.sh': 'curl https://evil.example\n' }), root);
  assert.equal(ignored.ok, false);
  assert.match(ignored.problems.join('\n'), /left out by \.skilldigestignore cannot be checked: evil\.sh/u);
  const binary = await checkSkill(await writeSkill(root, 'binary', { 'SKILL.md': front, 'notes.md': 'see https://evil.example/x\n\0' }), root);
  assert.match(binary.problems.join('\n'), /cannot be searched .*notes\.md/u);
  const dir = await writeSkill(root, 'media', { 'SKILL.md': front });
  await writeFile(path.join(dir, 'logo.png'), Buffer.from([0x89, 0x50, 0x4e, 0x47, 0, 1]));
  const media = await checkSkill(dir, root);
  assert.equal(media.ok, true);
  assert.match(media.notes.join('\n'), /logo\.png/u);
});

test('review 001: shell fences inside lists, quotes and attribute braces are found', async (t) => {
  const body = '- step\n\n    ```sh\n    ls\n    ```\n\n> ```bash\n> ls\n> ```\n\n```{.bash}\nls\n```\n\n```shellscript\nls\n```\n';
  const dir = await writeSkill(await tempDir(t), 'demo', { 'SKILL.md': md('permissions:\n  shell: false\n', body), Makefile: 'all:\n\techo\n' });
  const check = await checkSkill(dir, path.dirname(dir));
  assert.deepEqual(check.scripts, [{ path: 'Makefile', reason: 'build or task file' }, { path: 'SKILL.md', reason: '4 shell code blocks' }]);
});

test('the suggested block lists only plain host names', () => {
  assert.equal(suggestedManifest({ manifest: null, scripts: [], usedHosts: ['a```.example', 'ok.example'] }).split('\n')[2], '    allow: ["ok.example"]');
});

test('a Skill with no manifest fails, and a broken manifest fails with the reason', async (t) => {
  const root = await tempDir(t);
  const none = await checkSkill(await writeSkill(root, 'none'), root);
  assert.equal(none.ok, false);
  assert.match(none.problems[0]!, /no USF "permissions" block/u);
  const broken = await checkSkill(await writeSkill(root, 'broken', { 'SKILL.md': md('permissions:\n  shell: maybe\n') }), root);
  assert.equal(broken.ok, false);
  assert.match(broken.problems[0]!, /permissions\.shell must be true or false/u);
});

test('describes what a change adds in plain words', async (t) => {
  const root = await tempDir(t);
  const base = await checkSkill(await writeSkill(path.join(root, 'base'), 'demo', { 'SKILL.md': md('permissions:\n  shell: false\n') }), path.join(root, 'base'));
  const head = await checkSkill(await writeSkill(path.join(root, 'head'), 'demo', {
    'SKILL.md': md('permissions:\n  network:\n    allow: [new.example]\n  shell: true\n  tools: [web_fetch]\n', 'Fetch https://new.example/a\n'),
    'run.sh': 'echo\n',
  }), path.join(root, 'head'));
  assert.deepEqual(describeAdditions(base, head), [
    'uses new websites: new.example',
    'declares permission for new websites: new.example',
    'asks for permission to run commands (shell: true)',
    'adds scripts or shell commands: run.sh',
    'asks for new tools: web_fetch',
  ]);
  assert.deepEqual(describeAdditions(null, head), ['adds this Skill']);
  assert.deepEqual(describeAdditions(head, head), []);
});

test('the Action runner: summary, exit code, base comparison and suggested block', async (t) => {
  const workspace = await tempDir(t);
  const baseRoot = await tempDir(t);
  await writeSkill(path.join(baseRoot, 'skills'), 'good', { 'SKILL.md': md('permissions:\n  shell: false\n') });
  await writeSkill(path.join(workspace, 'skills'), 'good', { 'SKILL.md': md('permissions:\n  shell: false\n') });
  await writeSkill(path.join(workspace, 'skills'), 'bad', { 'SKILL.md': md('', 'Use https://x.example/`a`|b\n') });
  const result = await runSkillCheck({ workspace, searchPath: '.', baseRoot });
  assert.equal(result.exitCode, 1);
  assert.deepEqual(result.checks.map((c) => [c.dir, c.ok]), [['skills/bad', false], ['skills/good', true]]);
  assert.deepEqual(result.additions.get('skills/bad'), ['adds this Skill']);
  assert.deepEqual(result.additions.get('skills/good'), []);
  assert.match(result.summary, /1\/2 Skills match what they declare/u);
  assert.match(result.summary, /```yaml\npermissions:\n {2}network:\n {4}allow: \["x\.example"\]\n {4}deny: "\*"\n {2}shell: false\n```/u);

  assert.equal((await runSkillCheck({ workspace, searchPath: 'skills/good' })).exitCode, 0);
  const outside = await runSkillCheck({ workspace, searchPath: '..' });
  assert.equal(outside.exitCode, 2);
  await mkdir(path.join(workspace, 'empty'));
  assert.equal((await runSkillCheck({ workspace, searchPath: 'empty' })).exitCode, 2);
});

test('a symlinked Skill folder is not followed', async (t) => {
  const workspace = await tempDir(t);
  const elsewhere = await writeSkill(await tempDir(t), 'outside', { 'SKILL.md': md('permissions:\n  shell: false\n') });
  await mkdir(path.join(workspace, 'skills'));
  await symlink(elsewhere, path.join(workspace, 'skills', 'linked'));
  const result = await runSkillCheck({ workspace, searchPath: 'skills' });
  assert.equal(result.exitCode, 1);
  assert.match(result.checks[0]!.problems[0]!, /could not be read: Skill root must be a real directory/u);
});
