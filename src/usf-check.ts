// The free Skill check. Every Skill gets its observed profile (what its bytes show). When the Skill also declares
// its needs in an OWASP USF manifest, the declaration must cover the profile: a web address on a site that
// `network.allow` does not list, or scripts and shell code while `shell` is not true, fail the check.
// A Skill without a manifest passes with its profile shown, unless the repository requires a manifest.
import path from 'node:path';
import { profileTree, type ObservedProfile } from './profile.ts';
import { collectSkillTree, SKILL_FILENAME } from './tree-digest.ts';
import { hostAllowed, readUsf, USF_FORMAT, type UsfManifest } from './usf.ts';

export interface CheckOptions {
  /** Fail Skills that have no USF manifest (or one that cannot be read). Default false: they are reported. */
  requireManifest?: boolean;
}

export interface SkillCheck {
  format: typeof USF_FORMAT;
  /** Directory relative to the checked root. */
  dir: string;
  ok: boolean;
  /** Null only when the Skill folder could not be read at all. */
  profile: ObservedProfile | null;
  manifest: UsfManifest | null;
  /** Whether SKILL.md has a `permissions` block, readable or not. */
  declared: boolean;
  manifestError: string | null;
  undeclaredHosts: string[];
  /** Plain-word reasons the check failed; empty when it passed. */
  problems: string[];
  /** Plain-word remarks that do not fail the check. */
  notes: string[];
}

function list(values: readonly string[], limit = 10): string {
  const shown = values.slice(0, limit).join(', ');
  return values.length > limit ? `${shown} and ${values.length - limit} more` : shown;
}

/** The `permissions` block a Skill could paste, filled in from its profile. */
export function suggestedManifest(check: Pick<SkillCheck, 'profile' | 'manifest'>): string {
  // Host names pass the URL parser, which still allows characters such as backticks; only plain names are suggested.
  const hosts = [...new Set([...(check.manifest?.network.allow ?? []), ...(check.profile?.web_hosts ?? [])])]
    .filter((host) => /^(?:\*|(?:\*\.)?[a-z0-9.-]+|\[[0-9a-f:.]+\])$/u.test(host)).sort();
  const shell = check.manifest?.shell === true || (check.profile?.scripts.length ?? 0) > 0;
  return [
    'permissions:',
    '  network:',
    `    allow: [${hosts.map((host) => JSON.stringify(host)).join(', ')}]`,
    '    deny: "*"',
    `  shell: ${shell}`,
  ].join('\n');
}

export async function checkSkill(skillDir: string, root: string, options: CheckOptions = {}): Promise<SkillCheck> {
  const result: SkillCheck = {
    format: USF_FORMAT, dir: path.relative(root, skillDir) || '.', ok: false, profile: null, manifest: null, declared: false,
    manifestError: null, undeclaredHosts: [], problems: [], notes: [],
  };
  let tree;
  try {
    tree = await collectSkillTree(skillDir, { includeContents: true });
  } catch (error) {
    result.problems.push(`the Skill folder could not be read: ${(error as Error).message}`);
    return result;
  }
  const profile = profileTree(tree);
  result.profile = profile;
  const reading = readUsf(tree.contents!.get(SKILL_FILENAME)!.toString('utf8'));
  result.manifest = reading.manifest;
  result.declared = reading.declared;
  result.manifestError = reading.error;

  const gaps: string[] = [];
  if (profile.not_searched.unreadable.length > 0) gaps.push(`files that cannot be searched (binary, not UTF-8 text, or larger than 2 MiB): ${list(profile.not_searched.unreadable)}`);
  if (profile.not_searched.ignored.length > 0) gaps.push(`files left out by .skilldigestignore: ${list(profile.not_searched.ignored)}`);
  if (!profile.complete && gaps.length === 0) gaps.push('too many web addresses to check them all (more than 128 different sites, or more than 100,000 addresses)');
  if (profile.not_searched.media.length > 0) result.notes.push(`images, fonts and media files were not searched: ${list(profile.not_searched.media)}`);

  const manifest = reading.manifest;
  if (manifest) {
    // A declaration is only worth something when it covers everything: gaps fail here.
    result.problems.push(...gaps.map((gap) => `the declaration cannot be checked against ${gap}`));
    result.undeclaredHosts = profile.web_hosts.filter((host) => !hostAllowed(manifest.network.allow, host));
    if (result.undeclaredHosts.length > 0)
      result.problems.push(`uses web addresses on sites it does not declare in permissions.network.allow: ${list(result.undeclaredHosts)}`);
    if (manifest.shell !== true && profile.scripts.length > 0)
      result.problems.push(`contains scripts or shell commands, but permissions.shell is ${manifest.shell === false ? 'false' : 'not set'}: ${list(profile.scripts.map((script) => `${script.path} (${script.reason})`), 5)}`);
    const undeclaredPrograms = profile.programs.filter((program) => !manifest.requires.binaries.includes(program));
    if (manifest.requires.binaries.length > 0 && undeclaredPrograms.length > 0)
      result.notes.push(`shell code blocks name programs not in requires.binaries (not checked): ${list(undeclaredPrograms)}`);
    if (manifest.network.allow.includes('*')) result.notes.push('declares that it may contact any website (network.allow: "*")');
    if (manifest.network.deny !== null && manifest.network.deny !== '*') result.notes.push(`network.deny is "${manifest.network.deny}"; USF expects "*"`);
    if (manifest.unknownKeys.length > 0) result.notes.push(`keys this check does not know were not checked: ${list(manifest.unknownKeys)}`);
  } else if (reading.declared) {
    // The author meant to declare, but the declaration cannot be read one way only.
    result.problems.push(`the USF declaration in ${SKILL_FILENAME} cannot be read reliably: ${reading.error}`);
  } else {
    if (reading.error) result.notes.push(`${SKILL_FILENAME} frontmatter: ${reading.error}. Hosts may not read this Skill's name and description`);
    const missing = `${SKILL_FILENAME} has no USF "permissions" block, so only what its files show is reported`;
    if (options.requireManifest) result.problems.push(missing, ...gaps);
    else result.notes.push(missing, ...gaps);
  }
  result.ok = result.problems.length === 0;
  return result;
}

/** What a pull request adds to a Skill, in plain words, compared with the base revision. */
export function describeAdditions(base: SkillCheck | null, head: SkillCheck): string[] {
  if (base === null) return ['adds this Skill'];
  const added = (before: readonly string[], after: readonly string[]) => after.filter((value) => !before.includes(value));
  const lines: string[] = [];
  const before = base.manifest;
  const after = head.manifest;
  const newSites = added(base.profile?.web_hosts ?? [], head.profile?.web_hosts ?? []);
  if (newSites.length > 0) lines.push(`uses new websites: ${list(newSites)}`);
  const newAllowed = added(before?.network.allow ?? [], after?.network.allow ?? []);
  if (newAllowed.length > 0) lines.push(`declares permission for new websites: ${list(newAllowed)}`);
  if (before?.shell !== true && after?.shell === true) lines.push('asks for permission to run commands (shell: true)');
  const newScripts = added((base.profile?.scripts ?? []).map((script) => script.path), (head.profile?.scripts ?? []).map((script) => script.path));
  if (newScripts.length > 0) lines.push(`adds scripts or shell commands: ${list(newScripts)}`);
  const newPrograms = added(base.profile?.programs ?? [], head.profile?.programs ?? []);
  if (newPrograms.length > 0) lines.push(`names new programs in shell code: ${list(newPrograms)}`);
  const newReads = added(before?.files.read ?? [], after?.files.read ?? []);
  if (newReads.length > 0) lines.push(`asks to read new files: ${list(newReads)}`);
  const newWrites = added(before?.files.write ?? [], after?.files.write ?? []);
  if (newWrites.length > 0) lines.push(`asks to write new files: ${list(newWrites)}`);
  const unprotected = (before?.files.deny_write ?? []).filter((file) => !(after?.files.deny_write ?? []).includes(file));
  if (unprotected.length > 0) lines.push(`no longer protects these files from writes: ${list(unprotected)}`);
  const newTools = added(before?.tools ?? [], after?.tools ?? []);
  if (newTools.length > 0) lines.push(`asks for new tools: ${list(newTools)}`);
  const newBinaries = added(before?.requires.binaries ?? [], after?.requires.binaries ?? []);
  if (newBinaries.length > 0) lines.push(`needs new programs: ${list(newBinaries)}`);
  return lines;
}
