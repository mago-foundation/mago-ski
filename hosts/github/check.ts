#!/usr/bin/env node
// Runner for the free Skill check Action (check/action.yml). No keys, no accounts, no network: it reads the
// repository, compares each Skill's USF manifest with its files, and on pull requests lists what the change adds.
// The pass/fail result depends only on the pull request's own files; the base revision only feeds the list of additions.
import { appendFile, lstat } from 'node:fs/promises';
import path from 'node:path';
import { isMainModule } from '../../src/main-module.ts';
import { findSkillDirs } from '../../src/policy.ts';
import { checkSkill, describeAdditions, suggestedManifest, type SkillCheck } from '../../src/usf-check.ts';
import { annotationLine, escapeAnnotation, markdownCell, MAX_ANNOTATIONS, MAX_SUMMARY_ROWS, withinReal } from './run.ts';

export interface SkillCheckRunOptions {
  /** Checkout under review. */
  workspace: string;
  /** Where to look for Skills, relative to the workspace. */
  searchPath: string;
  /** Checkout of the pull request's base revision, when there is one. */
  baseRoot?: string;
  /** Fail Skills without a readable USF manifest. */
  requireManifest?: boolean;
}

export interface SkillCheckRun {
  checks: SkillCheck[];
  additions: Map<string, string[]>;
  /** Set when the run could not check the repository at all. */
  error?: string;
  exitCode: number;
  summary: string;
}

async function isDirectory(target: string): Promise<boolean> {
  try {
    return (await lstat(target)).isDirectory();
  } catch {
    return false;
  }
}

export async function runSkillCheck({ workspace, searchPath, baseRoot, requireManifest = false }: SkillCheckRunOptions): Promise<SkillCheckRun> {
  const root = path.resolve(workspace);
  const additions = new Map<string, string[]>();
  const failed = (error: string): SkillCheckRun => ({
    checks: [], additions, error, exitCode: 2, summary: `### mago-ski skill check: could not run\n\n${markdownCell(error)}\n`,
  });

  let skillDirs: string[];
  let tooDeep: string[];
  try {
    const searchRoot = await withinReal(root, path.resolve(root, searchPath), 'path');
    ({ skillDirs, tooDeep } = await findSkillDirs([searchRoot]));
  } catch (error) {
    // DiscoveryBudgetError, a path outside the workspace, or an unreadable folder.
    if (error instanceof Error) return failed(error.message);
    throw error;
  }
  if (skillDirs.length === 0 && tooDeep.length === 0) return failed(`no Skill (a folder with SKILL.md) was found under ${searchPath}`);

  const checks: SkillCheck[] = [];
  for (const skillDir of skillDirs) {
    const check = await checkSkill(skillDir, root, { requireManifest });
    checks.push(check);
    if (baseRoot !== undefined) {
      const baseDir = path.join(path.resolve(baseRoot), check.dir);
      // The base is only described, never trusted; a Skill missing there is new.
      const base = (await isDirectory(baseDir)) ? await checkSkill(baseDir, path.resolve(baseRoot)) : null;
      additions.set(check.dir, describeAdditions(base, check));
    }
  }
  for (const directory of tooDeep) {
    checks.push({
      format: 'owasp.usf/v1.0', dir: path.relative(root, directory), ok: false, profile: null, manifest: null, declared: false, manifestError: null, undeclaredHosts: [],
      problems: ['this folder is too deeply nested; Skills below it were not checked. Point the path input closer to the Skills'], notes: [],
    });
  }

  const failures = checks.filter((check) => !check.ok);
  const ordered = [...failures, ...checks.filter((check) => check.ok)];
  const shown = ordered.slice(0, MAX_SUMMARY_ROWS);
  const lines = [
    `### mago-ski skill check: ${checks.length - failures.length}/${checks.length} Skills pass`,
    '',
    '_Shows what each Skill\'s files contain, and, for Skills that declare their needs in an OWASP Universal Skill Format manifest, whether the declaration covers it. It does not say a Skill is safe._',
    '',
  ];
  for (const check of shown) {
    lines.push(`#### ${check.ok ? 'pass' : 'fail'}: ${markdownCell(check.dir)}`, '');
    for (const problem of check.problems) lines.push(`- ${markdownCell(problem)}`);
    if (check.profile) {
      const p = check.profile;
      const none = (values: readonly string[]) => (values.length === 0 ? 'none' : values.slice(0, 20).join(', ') + (values.length > 20 ? ` and ${values.length - 20} more` : ''));
      lines.push(`- Websites in its files: ${markdownCell(none(p.web_hosts))}`);
      lines.push(`- Scripts and shell code: ${markdownCell(none(p.scripts.map((s) => `${s.path} (${s.reason})`)))}`);
      if (p.programs.length > 0) lines.push(`- Programs named in shell code: ${markdownCell(none(p.programs))}`);
      lines.push(`- Declared in USF: ${check.manifest ? 'yes' : check.declared ? 'unreadable' : 'no'}`);
    }
    const added = additions.get(check.dir);
    if (added && added.length > 0) {
      lines.push('', 'This change:');
      for (const line of added) lines.push(`- ${markdownCell(line)}`);
    }
    for (const note of check.notes) lines.push(`- _note:_ ${markdownCell(note)}`);
    if ((check.profile !== null && !check.declared) || (!check.ok && check.manifest !== null)) {
      // suggestedManifest lists only plain host names, which cannot close this fence.
      lines.push('', `To declare what was found, add this to the SKILL.md frontmatter (review it first: it lists what the files contain, not what the Skill should be allowed to do):`, '', '```yaml', suggestedManifest(check), '```');
    }
    lines.push('');
  }
  if (ordered.length > MAX_SUMMARY_ROWS) lines.push(`_${ordered.length - MAX_SUMMARY_ROWS} more Skills not listed (failures are listed first)._`, '');
  return { checks, additions, exitCode: failures.length > 0 ? 1 : 0, summary: lines.join('\n') };
}

async function main(): Promise<void> {
  const [workspace, searchPath, requireManifest, baseRoot] = process.argv.slice(2);
  if (!workspace || !searchPath || (requireManifest !== 'true' && requireManifest !== 'false')) throw new Error('usage: check.ts WORKSPACE PATH true|false [BASE_ROOT]');
  const result = await runSkillCheck({ workspace, searchPath, requireManifest: requireManifest === 'true', ...(baseRoot ? { baseRoot } : {}) });
  if (result.error) process.stdout.write(`::error title=mago-ski skill check::${escapeAnnotation(result.error)}\n`);
  let annotations = 0;
  for (const check of result.checks) {
    if (check.ok) continue;
    if (annotations >= MAX_ANNOTATIONS) {
      process.stdout.write(`::notice title=mago-ski skill check::${MAX_ANNOTATIONS} annotations shown; see the job summary for the rest\n`);
      break;
    }
    annotations += 1;
    process.stdout.write(annotationLine('error', path.join(check.dir, 'SKILL.md'), 'skill check', check.problems.join('; ')));
  }
  process.stdout.write(`${result.summary}\n`);
  if (process.env.GITHUB_STEP_SUMMARY) await appendFile(process.env.GITHUB_STEP_SUMMARY, `${result.summary}\n`);
  process.exitCode = result.exitCode;
}

if (isMainModule(import.meta.url)) {
  main().catch((error: unknown) => {
    process.stdout.write(`::error title=mago-ski skill check::${escapeAnnotation((error as Error).message)}\n`);
    process.exitCode = 2;
  });
}
