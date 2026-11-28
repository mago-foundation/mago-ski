import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { chmod, lstat, mkdir, readFile, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { pathToFileURL } from 'node:url';
import { promisify } from 'node:util';
import { buildBaseRepoUrl, checkoutBaseRevision, validateBaseSha } from '../hosts/github/check-base.ts';
import { runSkillCheck } from '../hosts/github/check.ts';
import { observeSkill } from '../src/profile.ts';
import { checkSkill, describeAdditions, suggestedManifest } from '../src/usf-check.ts';
import { hostAllowed, readUsf } from '../src/usf.ts';
import { tempDir, writeSkill } from './helpers.ts';

const md = (front: string, body = '# demo\n') => `---\nname: demo\ndescription: A demo.\n${front}---\n${body}`;
const manifestOf = (front: string) => readUsf(md(front));

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
  const reading = readUsf(OWASP_EXAMPLE);
  assert.equal(reading.error, null);
  const manifest = reading.manifest!;
  assert.deepEqual(manifest.files, { read: ['~/.config/app.json'], write: ['~/.config/app.json'], deny_write: ['SOUL.md', 'MEMORY.md', 'AGENTS.md'] });
  assert.deepEqual(manifest.network, { allow: ['api.example.com'], deny: '*' });
  assert.equal(manifest.shell, false);
  assert.deepEqual(manifest.tools, ['web_fetch', 'read_file']);
  assert.deepEqual(manifest.requires, { binaries: ['jq', 'curl'], min_runtime_version: '2026.1.0' });
});

test('real-world frontmatter that YAML readers accept is read, with or without a declaration', () => {
  const realWorld = [
    // Ordinary Agent Skills frontmatter: no USF.
    'name: pdf\ndescription: Use this skill whenever the user wants to do anything with PDF files, such as reading or merging them.\n',
    'name: x\ndescription: "A quoted description\n  that goes on over\n  several lines"\nlicense: Proprietary. LICENSE.txt has complete terms\n',
    "name: x\ndescription: >-\n  Folded text with: colons, # hashes and 'quotes'.\n  More text.\nallowed-tools: Bash(git:*), Read\n",
    'name: x\ndescription: |\n  Literal\n  \ttext with a tab\nmetadata:\n  version: 1.0\n  tags: [a, b]\n',
    'name: x\ndescription: Ünïcödé — with a no-break space and 日本語\n',
    'name: x\ndescription: anchors &a in text\nbase: &defaults\n  k: v\nother:\n  <<: *defaults\n',
    'name: x\r\ndescription: CRLF line endings\r\n',
  ];
  for (const front of realWorld) {
    const reading = readUsf(`---\n${front}---\n# body\n`);
    assert.deepEqual({ error: reading.error, declared: reading.declared }, { error: null, declared: false }, JSON.stringify(front));
  }
  const declared = readUsf('---\nname: x\ndescription: "multi\n  line"\npermissions:\n  shell: true\n  network:\n    allow:\n      - api.example.com # comment\n---\n');
  assert.equal(declared.manifest?.shell, true);
  assert.deepEqual(declared.manifest?.network.allow, ['api.example.com']);
});

test('a field that YAML 1.1 (PyYAML) and YAML 1.2 read differently is ambiguous, not guessed', () => {
  for (const front of ['permissions:\n  shell: yes\n', 'permissions:\n  network:\n    allow: [on]\n', 'permissions:\n  tools: [n]\n']) {
    const reading = manifestOf(front);
    assert.equal(reading.manifest, null, front);
    assert.equal(reading.declared, true);
    assert.ok(reading.ambiguous.length > 0, front);
    assert.match(reading.error!, /YAML 1\.1/u);
  }
  // Quoted, both readings agree.
  assert.deepEqual(manifestOf('permissions:\n  network:\n    allow: ["on"]\n').manifest?.network.allow, ['on']);
});

test('broken or hostile frontmatter never throws and never yields a declaration', () => {
  const cases = [
    'permissions:\n  shell: true\n  shell: false\n',
    'permissions:\n  shell: true\npermissions:\n  shell: false\n',
    'permissions: [\n',
    'a: &a [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]\nb: &b [*a, *a, *a, *a, *a, *a, *a, *a, *a, *a]\nc: [*b, *b, *b, *b, *b, *b, *b, *b, *b, *b, *b, *b]\nd: [*b, *b, *b, *b, *b, *b, *b, *b, *b, *b, *b, *b]\npermissions:\n  shell: true\n',
    'permissions:\n  network:\n    allow: [https://a.example/path]\n',
    'permissions:\n  shell: "true"\n',
  ];
  for (const front of cases) {
    const reading = manifestOf(front);
    assert.equal(reading.manifest, null, front);
    assert.equal(reading.declared, true, front);
    assert.ok(reading.error, front);
  }
  assert.equal(readUsf('---\nname: x\n').error, 'SKILL.md frontmatter has no closing --- line');
  assert.equal(readUsf('# no frontmatter\n').declared, false);
});

test('review 006: directives, tags, ? keys, collection keys, tab before ":" and huge key counts are refused', () => {
  for (const front of [
    '%YAML 1.1\n--- #c\npermissions:\n  shell: y\n', '--- !!map\npermissions:\n  shell: true\n', 'permissions:\n  shell: true\n...\n',
    'permissions\t:\n  shell: true\n', 'permissions:\n  network:\n    allow: [!x a.com]\n', 'permissions:\n  shell: !!bool true\n',
    '? [a]\n: b\npermissions:\n  shell: true\n', '[c]: d\npermissions:\n  shell: true\n',
    '"permissions": {shell: true}\n"permissions": {shell: false}\n',
    Array.from({ length: 2001 }, (_, i) => `k${i}: v\n`).join('') + 'permissions:\n  shell: true\n',
  ]) {
    const reading = manifestOf(front);
    assert.equal(reading.manifest, null, front.slice(0, 60));
    assert.equal(reading.declared, true, front.slice(0, 60));
  }
  assert.deepEqual(manifestOf('permissions:\n  network:\n    allow: ["[::ffff:169.254.169.254]"]\n').manifest?.network.allow, ['[::ffff:a9fe:a9fe]']);
});

test('review 007: tabs outside block text, control characters and Unicode line breaks are refused; block text keeps its tabs', () => {
  for (const front of ['permissions:\n  shell:\ttrue\n', 'a: 1\n\t\npermissions:\n  shell: true\n', 'permissions:\n  shell: true\n  x\u000b: 1\n', 'permissions:\n  shell: true\u2028\n', '? permissions:\n  shell: true\n', '!!str permissions:\n  shell: true\n']) {
    const reading = manifestOf(front);
    assert.equal(reading.manifest, null, JSON.stringify(front));
    assert.equal(reading.declared, true, JSON.stringify(front));
  }
  assert.equal(manifestOf('long: |\n  x\n  \ty\npermissions:\n  shell: true\n').manifest?.shell, true);
  // Review 008: tabs in plain values and keys, and a ":" without a key.
  for (const front of ['k: a\tb\npermissions:\n  shell: true\n', 'x\ty: 1\npermissions:\n  shell: true\n', 'k: [a\tb]\npermissions:\n  shell: true\n', 'permissions:\n  shell: true\n:\n'])
    assert.equal(manifestOf(front).manifest, null, JSON.stringify(front));
  assert.equal(manifestOf('k: "a\tb"\npermissions:\n  shell: true\n').manifest?.shell, true);
});

test('network.allow matching: exact host, subdomain wildcard, any host', () => {
  assert.equal(hostAllowed(['api.example.com'], 'api.example.com'), true);
  assert.equal(hostAllowed(['api.example.com'], 'evil-api.example.com'), false);
  assert.equal(hostAllowed(['*.example.com'], 'a.b.example.com'), true);
  assert.equal(hostAllowed(['*.example.com'], 'example.com'), false);
  assert.equal(hostAllowed(['*.example.com'], 'badexample.com'), false);
  assert.equal(hostAllowed(['*'], 'anything.example'), true);
  assert.match(manifestOf('permissions:\n  network:\n    allow: ["K.com"]\n').error!, /not a host name/u);
});

test('the observed profile: websites, scripts, shell code blocks, programs', async (t) => {
  const dir = await writeSkill(await tempDir(t), 'demo', {
    'SKILL.md': md('', 'Run:\n\n```bash\n$ sudo FOO=1 /usr/bin/curl https://api.example.com/v1\njq .x # parse\n```\n\n> ```sh\n> ls\n> ```\n\n```{.bash}\nrm -rf x\n```\n\n```python\nprint(1)\n```\n'),
    'scripts/run.sh': 'curl https://api.example.com/x\n',
    'helper': '#!/bin/sh\necho hi\n',
    Makefile: 'all:\n\techo\n',
    'notes.md': 'see https://docs.example.org/guide.\n',
  });
  await writeFile(path.join(dir, 'bin'), 'x');
  await chmod(path.join(dir, 'bin'), 0o755);
  await writeFile(path.join(dir, 'logo.png'), Buffer.from([0x89, 0x50, 0x4e, 0x47, 0, 1]));
  const profile = await observeSkill(dir);
  assert.equal(profile.profile, 'mago.observed-profile/v1');
  assert.match(profile.digest, /^sha256:[0-9a-f]{64}$/u);
  assert.deepEqual(profile.web_hosts, ['api.example.com', 'docs.example.org']);
  assert.deepEqual(profile.scripts.map((s) => [s.path, s.reason]), [
    ['Makefile', 'build or task file'], ['SKILL.md', '3 shell code blocks'], ['bin', 'executable file'], ['helper', 'starts with #!'], ['scripts/run.sh', '.sh file'],
  ]);
  assert.deepEqual(profile.programs, ['curl', 'jq', 'ls', 'rm']);
  assert.deepEqual(profile.not_searched, { media: ['logo.png'], unreadable: [], ignored: [] });
  assert.equal(profile.complete, true);
});

test('review 006: fences after list markers, shell-family languages and IPv6 addresses are found', async (t) => {
  const dir = await writeSkill(await tempDir(t), 'demo', {
    'SKILL.md': md('', '1. ```bash\n   curl x\n   ```\n- ```sh\n  ls\n  ```\n> - ```bash-session\n> $ git status\n```shell-script\nmake\n```\nhttp://[2001:db8::1]/x and https://[::ffff:169.254.169.254]:8080/\n'),
  });
  const profile = await observeSkill(dir);
  assert.deepEqual(profile.scripts, [{ path: 'SKILL.md', reason: '4 shell code blocks' }]);
  assert.deepEqual(profile.programs, ['curl', 'git', 'ls', 'make']);
  assert.deepEqual(profile.web_hosts, ['[2001:db8::1]', '[::ffff:a9fe:a9fe]']);
  const check = await checkSkill(dir, path.dirname(dir));
  assert.equal(check.ok, true);
  const declared = await writeSkill(await tempDir(t), 'declared', { 'SKILL.md': md('permissions:\n  shell: true\n  network:\n    allow: ["[2001:db8::1]"]\n', 'http://[2001:db8::1]/x and http://[::1]/\n') });
  assert.deepEqual((await checkSkill(declared, path.dirname(declared))).undeclaredHosts, ['[::1]']);
});

test('review 007: an address with a backslash lists the host each URL parser reads', async (t) => {
  const dir = await writeSkill(await tempDir(t), 'demo', { 'SKILL.md': md('permissions:\n  network:\n    allow: [api.github.com]\n', 'https://api.github.com\\@evil.example/x\n') });
  const check = await checkSkill(dir, path.dirname(dir));
  assert.deepEqual(check.profile?.web_hosts, ['api.github.com', 'evil.example']);
  assert.deepEqual(check.undeclaredHosts, ['evil.example']);
});

test('review 008: percent-encoded and IPv6 hosts after a backslash are listed', async (t) => {
  const dir = await writeSkill(await tempDir(t), 'demo', { 'SKILL.md': md('', 'https://ok.example\\@ev%69l.example/ and https://ok.example\\@[::1]/\n') });
  assert.deepEqual((await observeSkill(dir)).web_hosts, ['[::1]', 'evil.example', 'ok.example']);
});

test('inline code that looks like a fence cannot hide a shell block', async (t) => {
  const dir = await writeSkill(await tempDir(t), 'demo', { 'SKILL.md': md('', '```x```\n\n```bash\nrm -rf ~\n```\n') });
  assert.deepEqual((await observeSkill(dir)).scripts, [{ path: 'SKILL.md', reason: '1 shell code block' }]);
});

test('a Skill without a manifest passes with its profile, unless a manifest is required', async (t) => {
  const root = await tempDir(t);
  const dir = await writeSkill(root, 'plain', { 'SKILL.md': md('', 'Fetch https://x.example/a\n'), 'run.sh': 'echo\n' });
  const plain = await checkSkill(dir, root);
  assert.equal(plain.ok, true);
  assert.deepEqual(plain.profile?.web_hosts, ['x.example']);
  assert.match(plain.notes.join('\n'), /no USF "permissions" block/u);
  assert.equal((await checkSkill(dir, root, { requireManifest: true })).ok, false);
  // Broken YAML without a declaration is a note: hosts may fail to read it, but nothing was declared.
  const broken = await checkSkill(await writeSkill(root, 'broken', { 'SKILL.md': '---\nname: x\ndescription: [unclosed\n---\n' }), root);
  assert.equal(broken.ok, true);
  assert.match(broken.notes.join('\n'), /not valid YAML/u);
});

test('a manifest must cover the profile: undeclared websites and scripts fail', async (t) => {
  const root = await tempDir(t);
  const good = await checkSkill(await writeSkill(root, 'good', {
    'SKILL.md': md('permissions:\n  network:\n    allow: [api.example.com]\n    deny: "*"\n  shell: true\n', '```bash\ncurl https://api.example.com/v1\n```\n'),
  }), root);
  assert.deepEqual(good.problems, []);
  const bad = await checkSkill(await writeSkill(root, 'bad', {
    'SKILL.md': md('permissions:\n  network:\n    allow: [api.example.com]\n  shell: false\n', 'See https://docs.example.org/guide.\n'),
    'tool.py': 'print(1)\n',
  }), root);
  assert.equal(bad.ok, false);
  assert.deepEqual(bad.undeclaredHosts, ['docs.example.org']);
  assert.equal(bad.problems.length, 2);
  const ambiguous = await checkSkill(await writeSkill(root, 'ambiguous', { 'SKILL.md': md('permissions:\n  shell: yes\n') }), root);
  assert.equal(ambiguous.ok, false);
  assert.match(ambiguous.problems[0]!, /cannot be read reliably/u);
});

test('review 001: with a manifest, files the profile cannot cover fail', async (t) => {
  const root = await tempDir(t);
  const front = md('permissions:\n  shell: false\n');
  const ignored = await checkSkill(await writeSkill(root, 'ignored', { 'SKILL.md': front, '.skilldigestignore': 'evil.sh\n', 'evil.sh': 'curl https://evil.example\n' }), root);
  assert.equal(ignored.ok, false);
  assert.match(ignored.problems.join('\n'), /left out by \.skilldigestignore: evil\.sh/u);
  const binary = await checkSkill(await writeSkill(root, 'binary', { 'SKILL.md': front, 'notes.md': 'see https://evil.example/x\n\0' }), root);
  assert.match(binary.problems.join('\n'), /cannot be searched .*notes\.md/u);
  assert.equal(binary.profile?.complete, false);
});

test('the suggested block lists only plain host names', () => {
  const profile = { web_hosts: ['a```.example', 'ok.example'], scripts: [] } as never;
  assert.equal(suggestedManifest({ manifest: null, profile }).split('\n')[2], '    allow: ["ok.example"]');
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
  await writeSkill(path.join(workspace, 'skills'), 'plain', { 'SKILL.md': md('', 'Use https://x.example/`a`|b\n') });
  await writeSkill(path.join(workspace, 'skills'), 'bad', { 'SKILL.md': md('permissions:\n  shell: false\n', 'Use https://y.example/\n') });
  const result = await runSkillCheck({ workspace, searchPath: '.', baseRoot });
  assert.equal(result.exitCode, 1);
  assert.deepEqual(result.checks.map((c) => [c.dir, c.ok]), [['skills/bad', false], ['skills/good', true], ['skills/plain', true]]);
  assert.deepEqual(result.additions.get('skills/plain'), ['adds this Skill']);
  assert.deepEqual(result.additions.get('skills/good'), []);
  assert.match(result.summary, /2\/3 Skills pass/u);
  assert.match(result.summary, /Websites in its files: x\.example/u);
  assert.match(result.summary, /```yaml\npermissions:\n {2}network:\n {4}allow: \["x\.example"\]\n {4}deny: "\*"\n {2}shell: false\n```/u);

  assert.equal((await runSkillCheck({ workspace, searchPath: 'skills/plain', requireManifest: true })).exitCode, 1);
  assert.equal((await runSkillCheck({ workspace, searchPath: 'skills/good' })).exitCode, 0);
  assert.equal((await runSkillCheck({ workspace, searchPath: '..' })).exitCode, 2);
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

const execFileAsync = promisify(execFile);

test('check-base validates SHAs and GitHub repository URLs', () => {
  const sha1 = 'a'.repeat(40);
  const sha256 = '0123456789abcdef'.repeat(4);
  assert.equal(validateBaseSha(sha1), sha1);
  assert.equal(validateBaseSha(sha256), sha256);
  for (const badSha of [undefined, '', 'A'.repeat(40), 'a'.repeat(39), '--upload-pack=x', 'refs/heads/main']) {
    assert.throws(() => validateBaseSha(badSha), /invalid pull request base revision/u);
  }

  assert.deepEqual(buildBaseRepoUrl('https://github.com', 'mago-foundation/mago-ski'), {
    repoUrl: 'https://github.com/mago-foundation/mago-ski.git',
    authScope: 'https://github.com',
  });
  assert.deepEqual(buildBaseRepoUrl('https://github.example.com/sub/', 'org.1/repo_2'), {
    repoUrl: 'https://github.example.com/sub/org.1/repo_2.git',
    authScope: 'https://github.example.com/sub',
  });
  for (const [server, repo] of [
    [undefined, 'org/repo'],
    ['http://github.com', 'org/repo'],
    ['https://user:pass@github.com', 'org/repo'],
    ['https://github.com?x=1', 'org/repo'],
    ['https://github.com#frag', 'org/repo'],
    ['https://github.com', undefined],
    ['https://github.com', 'org'],
    ['https://github.com', 'org/repo/extra'],
    ['https://github.com', '../repo'],
    ['https://github.com', 'org/-repo'],
  ] as const) {
    assert.throws(() => buildBaseRepoUrl(server, repo), /invalid GitHub/u);
  }
});

test('check-base checks out an older base revision without persisting credentials and cleans up on error', async (t) => {
  const root = await tempDir(t);
  const work = path.join(root, 'work');
  const bare = path.join(root, 'bare.git');
  const dest = path.join(root, 'dest');
  await mkdir(work);

  const git = (cwd: string, ...args: string[]) => execFileAsync('git', ['-C', cwd, ...args]);
  await git(work, 'init', '--quiet');
  await git(work, 'config', 'user.name', 'Test User');
  await git(work, 'config', 'user.email', 'test@example.com');
  await writeSkill(path.join(work, 'skills'), 'demo', { 'SKILL.md': md('permissions:\n  shell: false\n', 'base body\n') });
  await git(work, 'add', '.');
  await git(work, 'commit', '--quiet', '-m', 'base commit');
  const baseSha = (await git(work, 'rev-parse', 'HEAD')).stdout.trim();

  await writeSkill(path.join(work, 'skills'), 'demo', { 'SKILL.md': md('permissions:\n  shell: true\n', 'head body\n') });
  await git(work, 'add', '.');
  await git(work, 'commit', '--quiet', '-m', 'head commit');

  await execFileAsync('git', ['clone', '--quiet', '--bare', work, bare]);
  await git(bare, 'config', 'uploadpack.allowAnySHA1InWant', 'true');

  const secretToken = 'ghs_secret_test_token_value';
  const out = await checkoutBaseRevision({
    repoUrl: pathToFileURL(bare).href,
    baseSha,
    destination: dest,
    token: secretToken,
    authScope: 'https://github.com',
  });
  assert.equal(out, dest);
  assert.equal((await git(dest, 'rev-parse', 'HEAD')).stdout.trim(), baseSha);
  assert.match(await readFile(path.join(dest, 'skills', 'demo', 'SKILL.md'), 'utf8'), /base body/u);
  const gitConfig = await readFile(path.join(dest, '.git', 'config'), 'utf8');
  assert.equal(gitConfig.includes('extraheader'), false);
  assert.equal(gitConfig.includes(secretToken), false);

  await assert.rejects(
    checkoutBaseRevision({
      repoUrl: pathToFileURL(bare).href,
      baseSha: '0'.repeat(40),
      destination: dest,
      token: secretToken,
      authScope: 'https://github.com',
    }),
    (err: Error) => !err.message.includes(secretToken),
  );
  await assert.rejects(lstat(dest), { code: 'ENOENT' });
});

test('check/action.yml fetches the base revision via check-base.ts instead of actions/checkout', async () => {
  const actionYml = await readFile(path.resolve(import.meta.dirname, '..', 'check', 'action.yml'), 'utf8');
  assert.equal(actionYml.includes('actions/checkout'), false);
  assert.match(actionYml, /hosts\/github\/check-base\.ts/u);
});
