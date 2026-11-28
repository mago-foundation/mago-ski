#!/usr/bin/env node
// Runner for the publish Action (publish/action.yml): checks every Skill like the Skill check Action, and when all
// pass, writes the published-by predicate and the subject list that actions/attest then signs with the repository's
// own GitHub identity. Nothing is signed when any Skill fails its check.
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { isMainModule } from '../../src/main-module.ts';
import { describeSkill, packageVersion, subjectChecksums, type PublishedByPredicate } from '../../src/published-by.ts';
import { escapeAnnotation } from './run.ts';
import { runSkillCheck } from './check.ts';

export async function preparePublish(workspace: string, searchPath: string, outDir: string, requireManifest: boolean): Promise<{ exitCode: number; summary: string; predicate?: PublishedByPredicate }> {
  const result = await runSkillCheck({ workspace, searchPath, requireManifest });
  if (result.exitCode !== 0) return { exitCode: result.exitCode, summary: `${result.summary}\n_Nothing was signed: every Skill must pass the check first._\n` };
  const root = path.resolve(workspace);
  const skills = [];
  for (const check of result.checks) {
    const skill = await describeSkill(path.join(root, check.dir), root);
    // Sign only the bytes that were checked.
    if (skill.digest !== check.profile?.digest) return { exitCode: 2, summary: `${result.summary}\n_Nothing was signed: ${check.dir} changed after it was checked._\n` };
    skills.push(skill);
  }
  const predicate: PublishedByPredicate = { generator: { name: 'mago-ski', version: packageVersion() }, skills };
  await mkdir(outDir, { recursive: true, mode: 0o700 });
  await writeFile(path.join(outDir, 'predicate.json'), `${JSON.stringify(predicate)}\n`, { mode: 0o600 });
  await writeFile(path.join(outDir, 'subjects.txt'), subjectChecksums(skills), { mode: 0o600 });
  const rows = skills.map((skill) => `| \`${skill.path.replace(/[`|\\]/gu, '_')}\` | \`${skill.digest}\` |`);
  return {
    exitCode: 0,
    predicate,
    summary: [result.summary, '', `### mago-ski publish: ${skills.length} Skill${skills.length === 1 ? '' : 's'} to sign as published-by`, '', '| Skill | Digest |', '|---|---|', ...rows, ''].join('\n'),
  };
}

async function main(): Promise<void> {
  const [workspace, searchPath, requireManifest, outDir] = process.argv.slice(2);
  if (!workspace || !searchPath || !outDir || (requireManifest !== 'true' && requireManifest !== 'false')) throw new Error('usage: publish.ts WORKSPACE PATH true|false OUT_DIR');
  const result = await preparePublish(workspace, searchPath, outDir, requireManifest === 'true');
  process.stdout.write(`${result.summary}\n`);
  if (process.env.GITHUB_STEP_SUMMARY) {
    const { appendFile } = await import('node:fs/promises');
    await appendFile(process.env.GITHUB_STEP_SUMMARY, `${result.summary}\n`);
  }
  process.exitCode = result.exitCode;
}

if (isMainModule(import.meta.url)) {
  main().catch((error: unknown) => {
    process.stdout.write(`::error title=mago-ski publish::${escapeAnnotation((error as Error).message)}\n`);
    process.exitCode = 2;
  });
}
