// `plainNameLine`: the whitelist that decides whether mago-ski can name a Codex Skill from its SKILL.md without a YAML parser
// (design docs/design/codex-profile.md D4, E5, F6.5). It returns the `name:` value only when the file is in a tiny, unambiguous
// subset of the frontmatter syntax, in which Codex's own parser (parse_skill_frontmatter_metadata, skills/src/parser.rs,
// rust-v0.166.0) is known to give the same name. Anything else returns null. Refusing is always allowed; accepting a file whose
// Codex name differs is never allowed. The oracle test (tests/gate-codex-names.test.ts, tests/fixtures/codex-names/) pins it.
import { validateSkillName } from '../../names.ts';

const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
const KEY_LINE = /^([a-z][a-z0-9_-]*): ([A-Za-z0-9 ._/,()-]*)$/u;
const NAME_VALUE = /^[A-Za-z][A-Za-z0-9._-]*$/u;
const RESERVED = new Set(['null', '~', 'true', 'false', 'yes', 'no', 'on', 'off', 'y', 'n']);

export function plainNameLine(bytes: Uint8Array): string | null {
  let text: string;
  try { text = decoder.decode(bytes); } catch { return null; }
  if (text.charCodeAt(0) === 0xfeff) return null;
  const lines = text.split('\n').map((l) => (l.endsWith('\r') ? l.slice(0, -1) : l));
  if (lines[0] !== '---') return null;
  const end = lines.indexOf('---', 1);
  if (end < 0) return null;
  const seen = new Map<string, string>();
  for (const line of lines.slice(1, end)) {
    if (line === '') continue;
    if (/[^\x20-\x7e]/u.test(line)) return null; // non-ASCII, tab, a bare \r or any control byte
    const m = KEY_LINE.exec(line);
    if (!m) return null;
    const [, key, value] = m as unknown as [string, string, string];
    if (seen.has(key)) return null; // a duplicate key of any kind
    seen.set(key, value);
  }
  const name = seen.get('name');
  const description = seen.get('description');
  if (name === undefined || description === undefined) return null;
  if (!NAME_VALUE.test(name) || RESERVED.has(name.toLowerCase())) return null;
  try { validateSkillName(name); } catch { return null; }
  if (description.trim() === '' || RESERVED.has(description.trim().toLowerCase())) return null;
  return name;
}
