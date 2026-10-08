import assert from 'node:assert/strict';
import { chmod, mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { buildVectors, trees, VECTOR_DIR, type VerdictCase } from '../scripts/vectors.ts';
import { collectSkillTree } from '../src/tree-digest.ts';
import { decide, loadTrustContext } from '../src/verify.ts';
import { tempDir } from './helpers.ts';

test('committed vectors match the generator byte for byte', async () => {
  for (const [relative, bytes] of buildVectors()) {
    const committed = await readFile(path.join(VECTOR_DIR, relative)).catch(() => Buffer.alloc(0));
    assert.ok(committed.equals(bytes), `${relative} is stale; run: node scripts/vectors.ts --write`);
  }
});

async function materialize(root: string, name: string): Promise<string> {
  const tree = trees().find((entry) => entry.name === name)!;
  const dir = path.join(root, name, 'vector-skill');
  for (const file of tree.files) {
    const target = path.join(dir, file.path);
    await mkdir(path.dirname(target), { recursive: true });
    await writeFile(target, file.content);
    await chmod(target, file.exec ? 0o755 : 0o644);
  }
  return dir;
}

test('tree vectors produce the expected file lists and digests', { skip: process.platform === 'win32' ? 'exec bit' : false }, async (t) => {
  const root = await tempDir(t);
  for (const vector of trees()) {
    const tree = await collectSkillTree(await materialize(root, vector.name));
    assert.deepEqual(tree.files, vector.expected_files, vector.name);
    assert.equal(tree.digest, vector.expected_digest, vector.name);
  }
});

test('verdict cases produce the expected verdicts', { skip: process.platform === 'win32' ? 'exec bit' : false }, async (t) => {
  const root = await tempDir(t);
  const spec = JSON.parse(await readFile(path.join(VECTOR_DIR, 'cases.json'), 'utf8')) as { root_fingerprint: string; skill_name: string; cases: VerdictCase[] };
  const trustRootBytes = await readFile(path.join(VECTOR_DIR, 'trust-root.json'));
  for (const entry of spec.cases) {
    const now = new Date(entry.now);
    const context = loadTrustContext({
      trustRootBytes, revocationsBytes: await readFile(path.join(VECTOR_DIR, entry.revocations)), rootKeyId: spec.root_fingerprint, now,
    });
    assert.ok(context.ok, `${entry.name}: ${context.ok ? '' : context.reason}`);
    const skillDir = await materialize(path.join(root, entry.name), entry.tree);
    const result = decide({
      skillDir, skillName: spec.skill_name, tree: await collectSkillTree(skillDir), now, context: context.context,
      certificates: [{ source: entry.certificate, bytes: await readFile(path.join(VECTOR_DIR, 'certificates', entry.certificate)) }],
    });
    assert.equal(result.verdict, entry.expected_verdict, `${entry.name}: ${result.reason}`);
  }
});
