const SKILL_NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;
const SCOPE_PATTERN = /^(?:\*|[A-Za-z0-9][A-Za-z0-9._-]{0,127}\*?)$/u;
const DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/u;

export function validateSkillName(value: unknown, label = 'Skill name'): string {
  if (typeof value !== 'string' || !SKILL_NAME_PATTERN.test(value)) {
    throw new Error(`${label} must be 1-128 ASCII letters, digits, dot, underscore or hyphen, starting with a letter or digit`);
  }
  return value;
}

/** Scopes: "*" (every Skill), "prefix*" (names starting with prefix), or an exact Skill name. */
export function validateScope(value: unknown, label = 'scope'): string {
  if (typeof value !== 'string' || !SCOPE_PATTERN.test(value)) {
    throw new Error(`${label} must be "*", an exact Skill name, or a name prefix ending in "*"`);
  }
  return value;
}

export function scopeMatches(scope: string, skillName: string): boolean {
  if (scope === '*') return true;
  if (scope.endsWith('*')) return skillName.startsWith(scope.slice(0, -1));
  return scope === skillName;
}

export function validateDigest(value: unknown, label = 'digest'): string {
  if (typeof value !== 'string' || !DIGEST_PATTERN.test(value)) throw new Error(`${label} must be sha256:<64 lowercase hex>`);
  return value;
}

/** Reads the `name` field from SKILL.md frontmatter, if present. */
export function skillNameFromFrontmatter(text: string): string | undefined {
  const match = /^---\r?\n([\s\S]*?)\r?\n---(?:\r?\n|$)/u.exec(text);
  if (!match) return undefined;
  for (const line of match[1]!.split(/\r?\n/u)) {
    const field = /^name:\s*(?:"([^"]*)"|'([^']*)'|(\S+))\s*$/u.exec(line);
    if (field) return field[1] ?? field[2] ?? field[3];
  }
  return undefined;
}
