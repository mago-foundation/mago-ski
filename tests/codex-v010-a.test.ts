// Regression tests for the Codex Security v0.1.0 report, findings 2 (decision-log path), 4 (private-key guard)
// and 5 (CLI default policy). Finding 1 is a workflow change and has no unit test.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { cp, lstat, mkdir, readFile, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { approveSkill, containsPrivateKey } from '../src/admin.ts';
import { appendToRegularFile } from '../src/fs-safe.ts';
import { appendDecision, decisionRecord, defaultPolicyPath, loadPolicy } from '../src/policy.ts';
import { unverifiable } from '../src/verify.ts';
import { approve, setupOrg, T0, tempDir, writeSkill, type Org } from './helpers.ts';

const cli = fileURLToPath(new URL('../src/cli.ts', import.meta.url));

function runCli(args: string[], options: { cwd?: string; home: string; policyEnv?: string }) {
  const env: NodeJS.ProcessEnv = { ...process.env, HOME: options.home };
  delete env.MAGO_SKI_POLICY;
  if (options.policyEnv !== undefined) env.MAGO_SKI_POLICY = options.policyEnv;
  const result = spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8', cwd: options.cwd, env });
  return { code: result.status, stdout: result.stdout, stderr: result.stderr };
}

async function rewritePolicy(org: Org, changes: Record<string, unknown>): Promise<void> {
  const policy = JSON.parse(await readFile(org.policyPath, 'utf8'));
  await writeFile(org.policyPath, JSON.stringify({ ...policy, ...changes }));
}

// ---- Finding 5: the CLI does not trust a policy that the checkout under review supplies ----

test('F5: a checkout-controlled .mago-ski/policy.json is not used when --policy is omitted', async (t) => {
  // The attacker's checkout carries its own root, approver, trust documents and a certificate that verifies under them.
  const org = await setupOrg(t, { now: new Date() });
  const checkout = await tempDir(t, 'mago-ski-checkout-');
  await cp(path.dirname(org.policyPath), path.join(checkout, '.mago-ski'), { recursive: true });
  const skill = await writeSkill(checkout, 'self-approved');
  await approve(org, skill, { now: new Date() });
  const home = await tempDir(t, 'mago-ski-home-');
  const policyInCheckout = path.join(checkout, '.mago-ski', 'policy.json');

  // Control: naming that policy explicitly is the operator's choice and verifies.
  const explicit = runCli(['verify', skill, '--json', '--policy', policyInCheckout], { cwd: checkout, home });
  assert.equal(explicit.code, 0, explicit.stderr + explicit.stdout);
  assert.equal(JSON.parse(explicit.stdout).verdict, 'VERIFIED');

  // Without --policy the current directory is never consulted.
  for (const args of [['verify', skill, '--json'], ['verify-all', '--json']]) {
    const implicit = runCli(args, { cwd: checkout, home });
    assert.equal(implicit.code, 2, args[0]);
    assert.doesNotMatch(implicit.stdout, /VERIFIED/u);
    assert.match(implicit.stderr, /No policy at .*mago-ski[\\/]policy\.json/u);
    assert.ok(implicit.stderr.includes(path.join(home, '.mago-ski', 'policy.json')));
  }
});

test('F5: the default policy is $MAGO_SKI_POLICY, else ~/.mago-ski/policy.json', async (t) => {
  const org = await setupOrg(t, { now: new Date() });
  const skill = await writeSkill(await tempDir(t), 'team-skill');
  await approve(org, skill, { now: new Date() });
  const home = await tempDir(t, 'mago-ski-home-');
  const elsewhere = await tempDir(t, 'mago-ski-cwd-');

  const viaEnv = runCli(['verify', skill, '--json'], { cwd: elsewhere, home, policyEnv: org.policyPath });
  assert.equal(viaEnv.code, 0, viaEnv.stderr);
  assert.equal(JSON.parse(viaEnv.stdout).verdict, 'VERIFIED');

  await cp(path.dirname(org.policyPath), path.join(home, '.mago-ski'), { recursive: true });
  const viaHome = runCli(['verify', skill, '--json'], { cwd: elsewhere, home });
  assert.equal(viaHome.code, 0, viaHome.stderr);
  assert.equal(JSON.parse(viaHome.stdout).verdict, 'VERIFIED');
});

test('F5: a relative MAGO_SKI_POLICY is rejected', async (t) => {
  const org = await setupOrg(t, { now: new Date() });
  const skill = await writeSkill(await tempDir(t), 'team-skill');
  const home = await tempDir(t, 'mago-ski-home-');
  const result = runCli(['verify', skill], { cwd: path.dirname(org.policyPath), home, policyEnv: 'policy.json' });
  assert.equal(result.code, 2);
  assert.match(result.stderr, /MAGO_SKI_POLICY must be an absolute path/u);
  assert.throws(() => defaultPolicyPath({ MAGO_SKI_POLICY: '.mago-ski/policy.json' }, '/home/u'), /absolute/u);
  assert.equal(defaultPolicyPath({}, '/home/u'), path.join('/home/u', '.mago-ski', 'policy.json'));
  assert.equal(defaultPolicyPath({ MAGO_SKI_POLICY: '' }, '/home/u'), path.join('/home/u', '.mago-ski', 'policy.json'));
  assert.equal(defaultPolicyPath({ MAGO_SKI_POLICY: '/etc/mago/policy.json' }, '/home/u'), '/etc/mago/policy.json');
});

// ---- Finding 2: decision_log and state_file are confined to the policy directory ----

for (const field of ['decision_log', 'state_file']) {
  test(`F2: ${field} outside the policy directory is a policy load error`, async (t) => {
    const org = await setupOrg(t);
    const outside = await tempDir(t, 'mago-ski-outside-');
    for (const value of [path.join(outside, 'target'), '../escape.log', 'logs/../../escape.log', '.', '', '/etc/passwd']) {
      await rewritePolicy(org, { [field]: value });
      await assert.rejects(loadPolicy(org.policyPath), /Policy (decision_log|state_file)/u, `${field}=${JSON.stringify(value)}`);
    }
    await assert.rejects(lstat(path.join(path.dirname(org.policyPath), '..', 'escape.log')), { code: 'ENOENT' });
  });

  test(`F2: ${field} cannot escape through a symlinked directory or file`, async (t) => {
    const org = await setupOrg(t);
    const policyDir = path.dirname(org.policyPath);
    const outside = await tempDir(t, 'mago-ski-outside-');
    await symlink(outside, path.join(policyDir, 'linked-dir'));
    await symlink(path.join(outside, 'not-created-yet'), path.join(policyDir, 'dangling-dir'));
    await writeFile(path.join(outside, 'victim'), 'keep\n');
    await symlink(path.join(outside, 'victim'), path.join(policyDir, 'linked-file'));
    for (const value of ['linked-dir/log.jsonl', 'dangling-dir/log.jsonl', 'linked-file']) {
      await rewritePolicy(org, { [field]: value });
      await assert.rejects(loadPolicy(org.policyPath), Error, `${field}=${value}`);
    }
    assert.equal(await readFile(path.join(outside, 'victim'), 'utf8'), 'keep\n');
  });

  test(`F2: ${field} that is a directory or FIFO is a policy load error`, async (t) => {
    const org = await setupOrg(t);
    const policyDir = path.dirname(org.policyPath);
    await mkdir(path.join(policyDir, 'a-directory'));
    assert.equal(spawnSync('mkfifo', [path.join(policyDir, 'a-fifo')]).status, 0);
    for (const value of ['a-directory', 'a-fifo']) {
      await rewritePolicy(org, { [field]: value });
      await assert.rejects(loadPolicy(org.policyPath), /regular/u, `${field}=${value}`);
    }
  });

  test(`F2: ${field} may name a file in a subdirectory of the policy directory`, async (t) => {
    const org = await setupOrg(t);
    await mkdir(path.join(path.dirname(org.policyPath), 'logs'));
    await rewritePolicy(org, { [field]: 'logs/out.jsonl' });
    const policy = await loadPolicy(org.policyPath);
    assert.equal(field === 'decision_log' ? policy.decisionLogPath : policy.statePath, path.join(path.dirname(org.policyPath), 'logs', 'out.jsonl'));
  });
}

test('F2: appendDecision refuses a symlink, a directory and a FIFO even if the path was not checked at load', async (t) => {
  const dir = await tempDir(t);
  const victim = path.join(dir, 'victim');
  await writeFile(victim, 'keep\n');
  await symlink(victim, path.join(dir, 'link'));
  await mkdir(path.join(dir, 'dir'));
  assert.equal(spawnSync('mkfifo', [path.join(dir, 'fifo')]).status, 0);
  const record = decisionRecord(unverifiable('/x', 'x', 'why', T0), 'shadow', 'test', 'host');
  for (const name of ['link', 'dir', 'fifo']) {
    await assert.rejects(appendDecision(path.join(dir, name), record), Error, name);
  }
  await assert.rejects(appendToRegularFile(path.join(dir, 'link'), 'x\n', 'Log'), Error);
  assert.equal(await readFile(victim, 'utf8'), 'keep\n');
});

test('F2: hostile Skill names and paths stay inside one JSON string on one log line', async (t) => {
  const dir = await tempDir(t);
  const log = path.join(dir, 'decisions.jsonl');
  const hostile = 'x$(touch pwn)`id`;\nsecond line\r\n{"action":"allow"}\u2028\u2029\u0085\u0000"\\';
  const result = unverifiable(`/skills/${hostile}`, hostile, `reason ${hostile}`, T0);
  await appendDecision(log, decisionRecord(result, 'enforce', 'test', hostile));
  await appendDecision(log, decisionRecord(result, 'enforce', 'test', hostile));
  const text = await readFile(log, 'utf8');
  assert.match(text, /\n$/u);
  assert.doesNotMatch(text, /[\r\u0085\u2028\u2029\u0000]/u);
  const lines = text.slice(0, -1).split('\n');
  assert.equal(lines.length, 2);
  for (const line of lines) {
    const parsed = JSON.parse(line);
    assert.equal(parsed.skill, hostile);
    assert.equal(parsed.skill_dir, `/skills/${hostile}`);
    assert.equal(parsed.action, 'block');
  }
  assert.equal((await lstat(log)).mode & 0o777, 0o600);
});

test('F2: verify-all logs a Skill directory named with newlines and shell syntax as a single JSON line', async (t) => {
  const org = await setupOrg(t, { now: new Date() });
  const policyDir = path.dirname(org.policyPath);
  await rewritePolicy(org, { skill_dirs: ['skills'] });
  const name = 'bad$(touch pwned)\nname';
  await writeSkill(path.join(policyDir, 'skills'), name);
  const home = await tempDir(t, 'mago-ski-home-');
  const result = runCli(['verify-all', '--json', '--policy', org.policyPath], { cwd: policyDir, home });
  assert.equal(result.code, 1, result.stderr);
  const lines = (await readFile(org.logPath, 'utf8')).trimEnd().split('\n');
  assert.equal(lines.length, 1);
  assert.equal(JSON.parse(lines[0]!).skill, name);
  await assert.rejects(lstat(path.join(policyDir, 'pwned')), { code: 'ENOENT' });
});

// ---- Finding 4: the approval guard recognizes common private-key encodings ----

const bech32 = 'Q'.repeat(58);
const PRIVATE = {
  'PKCS#8 PEM': '-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIA==\n-----END PRIVATE KEY-----\n',
  'RSA PEM': '-----BEGIN RSA PRIVATE KEY-----\nMIIB\n-----END RSA PRIVATE KEY-----\n',
  'EC PEM': '-----BEGIN EC PRIVATE KEY-----\nMHcC\n-----END EC PRIVATE KEY-----\n',
  'DSA PEM': '-----BEGIN DSA PRIVATE KEY-----\nMIIB\n-----END DSA PRIVATE KEY-----\n',
  'encrypted PKCS#8 PEM': '-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIF\n-----END ENCRYPTED PRIVATE KEY-----\n',
  'OpenSSH': '-----BEGIN OPENSSH PRIVATE KEY-----\nb3Bl\n-----END OPENSSH PRIVATE KEY-----\n',
  'SSH2 encrypted': '---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----\nComment: "x"\n',
  'PGP armor': '-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nlQcYBF\n=abcd\n-----END PGP PRIVATE KEY BLOCK-----\n',
  'PuTTY .ppk': 'PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\nComment: x\nPublic-Lines: 2\n',
  'age secret key': `# created: 2026-10-01\n# public key: age1xyz\nAGE-SECRET-KEY-1${bech32}\n`,
};
const NOT_PRIVATE = {
  'PEM public key': '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA\n-----END PUBLIC KEY-----\n',
  'PGP public key': '-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmDMEZ\n-----END PGP PUBLIC KEY BLOCK-----\n',
  'certificate': '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n',
  'SSH public key': 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA user@host\n',
  'age recipient': 'age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq\n',
  'prose': 'Never commit a private key or a PGP PRIVATE KEY BLOCK; the AGE-SECRET-KEY is secret.\n',
};

for (const [label, content] of Object.entries(PRIVATE)) {
  test(`F4: approve refuses a Skill containing a ${label} private key`, async (t) => {
    const org = await setupOrg(t);
    const skill = await writeSkill(await tempDir(t), 'leaky', { 'references/notes.txt': content });
    assert.equal(containsPrivateKey(Buffer.from(content)), true);
    await assert.rejects(approve(org, skill), /contains a private key/u);
    await assert.rejects(lstat(path.join(skill, '.mago-ski-cert.json')), { code: 'ENOENT' });
  });
}

test('F4: a private key inside SKILL.md is refused too', async (t) => {
  const org = await setupOrg(t);
  const skill = await writeSkill(await tempDir(t), 'leaky-md');
  await writeFile(path.join(skill, 'SKILL.md'), `---\nname: leaky-md\ndescription: x\n---\n${PRIVATE['PGP armor']}`);
  await assert.rejects(approveSkill({ skillDir: skill, approverKeyPath: org.approverKey, now: T0, expires: '1d', reason: 'x' }), /contains a private key/u);
});

for (const [label, content] of Object.entries(NOT_PRIVATE)) {
  test(`F4: approve accepts a Skill containing a ${label}`, async (t) => {
    const org = await setupOrg(t);
    const skill = await writeSkill(await tempDir(t), 'fine', { 'references/notes.txt': content });
    assert.equal(containsPrivateKey(Buffer.from(content)), false);
    await approve(org, skill);
  });
}

// ---- Review follow-ups ----

test('F4: the private-key scan is linear on adversarial input (no ReDoS)', () => {
  const MB = 1024 * 1024;
  const inputs = {
    dashes: '-'.repeat(MB),
    'BEGIN repeated': 'BEGIN '.repeat(MB / 6),
    'dashes then BEGIN repeated': `---${'BEGIN '.repeat(MB / 6)}`,
    'dash/space runs': '--- '.repeat(MB / 4),
    'BEGIN then spaces': `--- BEGIN ${' '.repeat(MB)}`,
    'age prefix repeated': 'AGE-SECRET-KEY-1'.repeat(MB / 16),
    'PuTTY prefix repeated': 'PuTTY-User-Key-File-'.repeat(MB / 20),
  };
  for (const [label, text] of Object.entries(inputs)) {
    const started = performance.now();
    containsPrivateKey(Buffer.from(text, 'latin1'));
    const elapsed = performance.now() - started;
    assert.ok(elapsed < 1000, `${label} took ${Math.round(elapsed)} ms`);
  }
  // Still found inside large input.
  assert.equal(containsPrivateKey(Buffer.from(`${'-'.repeat(MB)} BEGIN RSA PRIVATE KEY-----`)), true);
});

test('F2: decision_log and state_file cannot name a file the policy reads or each other', async (t) => {
  const org = await setupOrg(t);
  const policyDir = path.dirname(org.policyPath);
  await mkdir(path.join(policyDir, 'certs', 'nested'), { recursive: true });
  await symlink(org.policyPath, path.join(policyDir, 'alias.json'));
  const cases: Array<[string, Record<string, unknown>, RegExp]> = [
    ['policy file', { decision_log: 'policy.json' }, /must not be the policy file/u],
    ['policy file (state)', { state_file: 'policy.json' }, /must not be the policy file/u],
    ['trust root', { decision_log: 'trust-root.json' }, /must not be trust_root/u],
    ['revocations', { state_file: 'revocations.json' }, /must not be revocations/u],
    ['same file', { decision_log: 'shared.json', state_file: 'shared.json' }, /same file as state_file/u],
    ['certificate dir', { decision_log: 'certs/log.jsonl' }, /certificate_dirs/u],
    ['nested certificate dir', { state_file: 'certs/nested/state.json' }, /certificate_dirs/u],
    ['dot-dot spelling', { decision_log: 'certs/../policy.json' }, /must not be the policy file/u],
    ['symlink spelling', { decision_log: 'alias.json' }, /regular|policy file/u],
  ];
  for (const [label, changes, message] of cases) {
    await rewritePolicy(org, { state_file: 'state.json', decision_log: 'decisions.jsonl', ...changes });
    await assert.rejects(loadPolicy(org.policyPath), message, label);
  }
  // The untouched defaults still load.
  await rewritePolicy(org, { state_file: 'state.json', decision_log: 'decisions.jsonl' });
  await loadPolicy(org.policyPath);
  assert.equal((await readFile(org.policyPath, 'utf8')).includes('policy_version'), true);
});

test('F2: C1 controls, DEL and bidi controls are escaped in decision-log JSON', async (t) => {
  const log = path.join(await tempDir(t), 'decisions.jsonl');
  const hostile = 'a\u007fb\u0080c\u009fd‪e‮f⁦g⁩h‏i';
  await appendDecision(log, decisionRecord(unverifiable('/s', hostile, 'r', T0), 'shadow', 'test', 'h'));
  const text = await readFile(log, 'utf8');
  assert.doesNotMatch(text, /[\u007f-\u009f‪-‮⁦-⁩]/u);
  for (const escape of ['\\u007f', '\\u0080', '\\u009f', '\\u202a', '\\u202e', '\\u2066', '\\u2069']) assert.ok(text.includes(escape), escape);
  assert.equal(JSON.parse(text.trimEnd()).skill, hostile);
  assert.equal(text.trimEnd().split('\n').length, 1);
});

test('F5: MAGO_SKI_POLICY may start with ~/ ; other relative values are still rejected', () => {
  assert.equal(defaultPolicyPath({ MAGO_SKI_POLICY: '~/org/policy.json' }, '/home/u'), path.join('/home/u', 'org', 'policy.json'));
  assert.equal(defaultPolicyPath({ MAGO_SKI_POLICY: '~' }, '/home/u'), '/home/u');
  for (const value of ['org/policy.json', './policy.json', '~user/policy.json', '~policy.json']) {
    assert.throws(() => defaultPolicyPath({ MAGO_SKI_POLICY: value }, '/home/u'), /absolute/u, value);
  }
});

test('F4: a huge run after an age key prefix neither throws nor stalls, and a real-shaped key still matches', () => {
  const started = performance.now();
  assert.doesNotThrow(() => containsPrivateKey(Buffer.from(`AGE-SECRET-KEY-1${'A'.repeat(8 * 1024 * 1024)}`)));
  assert.doesNotThrow(() => containsPrivateKey(Buffer.from(`PuTTY-User-Key-File-${'1'.repeat(8 * 1024 * 1024)}`)));
  assert.ok(performance.now() - started < 1000);
  // Bech32 age secret key: "AGE-SECRET-KEY-1" plus 58 characters.
  assert.equal(containsPrivateKey(Buffer.from(`AGE-SECRET-KEY-1${'QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L'.slice(0, 29).repeat(2)}\n`)), true);
  assert.equal(containsPrivateKey(Buffer.from('age-secret-key-1qpzry9x8gf2tvdw0s3jn54khce6mua7lqpzry9x8gf2tvdw0s3jn54khce')), true);
  assert.equal(containsPrivateKey(Buffer.from('AGE-SECRET-KEY-1SHORT')), false);
});
