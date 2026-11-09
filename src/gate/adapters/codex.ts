// Codex hook adapter (E3 packet 9b). Pure of process I/O: codex-hook.ts feeds it stdin via hook-main.ts.
//
// WHAT IS ENFORCED AND WHAT IS NOT. Codex has no admin-only Skill lock (cx0.1/cx0.2, Codex 0.163.0 / Linux; unverified for
// other versions) and its hooks fail OPEN on crash, timeout or any exit other than 2. The primary control is therefore
// the requirements file (codex-requirements.ts: managed hooks only, deny_read on fixed user Skill roots) plus the
// service uninstalling revoked Skills. This adapter is the explicit-use gate on top of that and is partly best-effort:
//   * UserPromptSubmit: parser-independent rule. We do NOT parse Skill names: Codex qualifies names with a plugin
//     namespace from the nearest .codex-plugin/.claude-plugin/.cursor-plugin plugin.json (an untrusted repo can add one,
//     so `$acme:foo` can select a Skill we never listed) and reads frontmatter with a full YAML parser (flow mappings,
//     escapes, anchors, bare \r breaks), which a line scan cannot match. Instead the non-admin roots are walked like
//     Codex only to answer "does ANY SKILL.md exist there?" (plus `incomplete`: unreadable entry, symlinked SKILL.md,
//     FIFO, cap hit, bad root, ancestor cap hit, missing/relative cwd, unreadable host environment). If any exists or the
//     walk is incomplete, EVERY `$token` is treated as possibly naming a non-admin Skill (see MASKING below); a token that
//     is not a valid engine Skill name is blocked without asking; anything not VERIFIED is blocked in enforce.
//     Independent of the walk: a token with a plugin namespace (`$acme:search`, `:` followed by a non-colon) is always
//     blocked (NOT_ADMIN), and a link is checked first: only a link that resolves (realpath, `skill://` and `file://` accepted)
//     to an approved `<admin_root>/<name>/SKILL.md` is asked; every other link is blocked (NOT_ADMIN), because Codex selects
//     a linked mention by path (design docs/design/codex-gate-findings.md, Y1/X1: L1-L3, T1).
//     On a clean machine only tokens equal to an admin-root directory name are asked, so `$5` in prose passes. RESIDUAL
//     OVER-BLOCKING: on a machine with any user/repo Skill, `$word` prose is blocked in enforce. KNOWN LIMIT (live test):
//     admin Skills are named here by the engine's frontmatter rule, Codex uses YAML; a mismatch can only affect
//     admin-approved bytes, which the service uninstalls on revoke.
//   * MASKING. Codex keeps same-name Skills; in rust-v0.163.0 a plain name shared by several Skills selects none
//     (selection.rs skill_name_counts), but other versions or selectors may pick the repo one, so a bare `$alpha` is not
//     trusted to mean the approved admin Skill `alpha`. Therefore, when a
//     non-admin Skill exists or the walk is incomplete, a bare `$name` that equals an admin Skill name is BLOCKED; only a
//     linked mention `[$alpha](<admin_root>/alpha/SKILL.md)` whose path resolves (realpath) to exactly that file is checked
//     with the service. USABILITY COST: in a repo that ships its own Skills, admin Skills must be invoked by link (or the
//     repo Skills removed). LIVE TEST (0.163.0 and 0.166.0, docs/spikes/codex-gate-live.md): Codex writes its bundled
//     Skills to <codex_home>/skills/.system at startup, so a non-admin Skill always exists and EVERY bare mention of an
//     admin Skill is blocked; in practice only the linked form works.
//   * PreToolUse (any tool whose tool_input.command is a string; repeated slashes are collapsed; any `.agents`/`.codex` or
//     SKILL.md text outside an admin Skill path is blocked): matching command text is BYPASSABLE (globs, variables, scripts) = defence in depth only.
//   * Non-admin roots are walked like Codex (depth 6, hidden dirs skipped, directory symlinks followed with loop
//     detection, cap 2000 dirs). A Skill created after
//     the walk is a race the filesystem deny is meant to cover.
//   * Repo roots: `.codex/skills` and `.agents/skills` in EVERY ancestor of cwd up to `/` (at most 64 levels, more =
//     incomplete). Project-root markers are NOT used: `project_root_markers` is employee-controllable (user config.toml,
//     CLI flags), so any marker-bounded scan could be moved above the adapter's bound. Over-blocking only.
//   * User roots follow the host's environment, which the employee controls. The adapter runs with an empty environment
//     but as the same user as the host, so it reads /proc/<host pid>/environ (bounded to 256 KiB) for CODEX_HOME and HOME
//     and scans <CODEX_HOME or HOME/.codex>/skills, .../skills/.system and <HOME>/.agents/skills, in addition to the
//     configured `skill_roots`. environ shows the environment at the host's exec time, which is what Codex reads at
//     startup, except that Codex then loads <codex_home>/.env and may set HOME from it (not CODEX_*); so a .env that
//     contains the bytes "HOME", or that is not a plain readable file, makes the walk incomplete. Both values must be
//     absolute; an unreadable or invalid environment, or a missing HOME, makes the walk incomplete (fail closed). Values
//     are never logged.
//   * In enforce, mentions of system Skills are blocked unless installed as admin Skills.
//   * Other tools than Bash (and Bash used indirectly) are allowed unasked.
//
// RESIDUALS (not fixable inside this hook):
//   (a) Structured Skill selection (`UserInput::Skill`, `skill://` mentions sent by non-TUI clients or the app-server API)
//       and the app-server `skills/extraRoots/set` call are not visible to the UserPromptSubmit hook; the adapter cannot
//       gate them. Endpoint requirement: restrict app-server and non-TUI Codex clients.
//   (b) Codex scans each text item separately while the hook sees them joined, so a token split across items can differ
//       (needs a multi-text client).
//   (c) The PreToolUse shell check is best-effort.
//   (d) In enforce mode Codex coverage is weaker than Claude Code. The live test showed that deny_read does not hide user
//       Skills from Codex's catalog, so the repo and user routes are both hook-only: audit-level.
//   (e) Startup state (founder decision 2026-11-03, accepted limit): Codex fixes HOME, CODEX_HOME (canonicalised) and
//       `<codex_home>/.env` once at startup; the hook only sees their state now. An employee can start Codex pointed at
//       unapproved Skills (via .env HOME, or a CODEX_HOME symlink) and undo it before prompting. Needs an endpoint control
//       (e.g. an admin-owned, employee-unwritable CODEX_HOME) before the user routes can be called enforced.
//
// HOST SCHEMA (Codex rust-v0.163.0, hooks/src/schema.rs): stdin JSON with `hook_event_name` = "SessionStart" |
//   "UserPromptSubmit" (+ `prompt`, `cwd`, schema.rs:566-583) | "PreToolUse" (+ `tool_name`, `tool_input`, `cwd`,
//   schema.rs:280-295; Bash reports `tool_input.command`, cx0.1). Other fields (session_id, turn_id, model, ...) are
//   ignored: never used, never logged. Block = exit 2 with a non-empty stderr reason (events/pre_tool_use.rs:262-270;
//   live-verified for PreToolUse and UserPromptSubmit in cx0.1). Allow = exit 0, no output. Any other exit code or an
//   empty stderr with exit 2 is NOT a block in Codex, so the adapter always writes a reason with its 2.
// MODE/CONFIG/OWNERSHIP rules are the Claude adapter's (claude-code.ts): argv[1] is the mode, enforce wins, config and
// socket must be root-owned, the adapter's own environment is not read. Extra config keys: `admin_root` (default
// /etc/codex/skills; must be the gate service's `managedDir`) and `skill_roots` (extra absolute non-admin roots).
import { lstat, open, readdir, readFile, realpath, stat } from 'node:fs/promises';
import path from 'node:path';
import { isRecord } from '../../canonical-json.ts';
import { validateSkillName } from '../../names.ts';
import type { Mode } from '../../policy.ts';
import { decideAction, type GateRequest } from '../contract.ts';
import { parseStrictJson, type StrictJsonLimits } from '../strict-json.ts';
import { askService, newRequestId } from './client.ts';
import { loadConfig, MAX_STDIN_BYTES, type HookConfig, type HookDeps, type HookOutcome } from './claude-code.ts';
import { findHostPid } from './host-pid.ts';

const DEFAULT_SELF_DEADLINE_MS = 3000;
const INPUT_LIMITS: StrictJsonLimits = { maxBytes: MAX_STDIN_BYTES, maxDepth: 16, maxMembers: 256, maxStringLength: 128 * 1024 };
export const DEFAULT_ADMIN_ROOT = '/etc/codex/skills';
const MAX_ANCESTORS = 64;
const MAX_ADMIN_NAMES = 16;
const MAX_ENVIRON_BYTES = 256 * 1024;

const COULD_NOT_VERIFY = 'mago-ski could not verify this Skill; it is blocked until verification works.';
const MASKED = 'A Skill with this name also exists outside your organisation\'s approved Skills, so a plain mention is blocked. Mention the approved Skill by its link, or remove the other Skill.';
const notAdmin = (adminRoot: string): string =>
  `This Skill is not one of your organisation's approved Skills, so it is blocked. Approved Skills are installed in ${adminRoot}.`;
const notApproved = (verdict: string): string =>
  `This Skill is not approved by your organisation (mago-ski: ${verdict}). If it was updated, restart the session to use the new version.`;

type Kind = 'SessionStart' | 'UserPromptSubmit' | 'PreToolUse';
const KINDS: readonly string[] = ['SessionStart', 'UserPromptSubmit', 'PreToolUse'];
type Parsed =
  | { kind: 'start' }
  | { kind: 'prompt'; prompt: string; cwd?: string }
  | { kind: 'bash'; command: string }
  | { kind: 'other-tool' };

// --- `$name` mention grammar: a port of codex-rs/skills/src/mentions.rs (rust-v0.163.0) --------------------------------
// Name bytes are [A-Za-z0-9_:-] (is_mention_name_char, :226); `$name` is a mention unless the upper-cased name is one of
// the common env vars (is_common_env_var, :208-224); `[$name](path)` (parse_linked_tool_mention, :151-206) is a mention
// of `name` unless the path starts with app://, mcp:// or plugin:// (extract_tool_mentions_with_sigil, :88-149).
// Addition (not in Codex): for a skill-kind path (skill:// or a SKILL.md file name, :43-60) the Skill folder name in the
// path is also a candidate, because Codex matches linked mentions by path.
const ENV_VARS = new Set(['PATH', 'HOME', 'USER', 'SHELL', 'PWD', 'TMPDIR', 'TEMP', 'TMP', 'LANG', 'TERM', 'XDG_CONFIG_HOME']);
const isNameChar = (c: string | undefined): boolean => c !== undefined && /^[A-Za-z0-9_:-]$/u.test(c);

function nameAt(text: string, start: number): number { // end index of the name starting at `start`, or start if none
  let end = start;
  while (isNameChar(text[end])) end += 1;
  return end;
}

export function extractMentions(text: string, links?: string[], plain?: Set<string>, linkNames?: string[]): Set<string> {
  const names = new Set<string>();
  let i = 0;
  while (i < text.length) {
    if (text[i] === '[' && text[i + 1] === '$') {
      const nameEnd = nameAt(text, i + 2);
      let p = nameEnd + 1;
      if (nameEnd > i + 2 && text[nameEnd] === ']') {
        while (p < text.length && ' \t\n\f\r'.includes(text[p]!)) p += 1; // ASCII whitespace only
        const close = text[p] === '(' ? text.indexOf(')', p + 1) : -1;
        const link = close >= 0 ? text.slice(p + 1, close).trim() : '';
        if (link !== '') {
          const name = text.slice(i + 2, nameEnd);
          links?.push(link);
          linkNames?.push(name); // the link text's name, env-var names included (parallel to `links`)
          if (!ENV_VARS.has(name.toUpperCase())) {
            if (!/^(app|mcp|plugin):\/\//u.test(link)) names.add(name);
            const stem = link.replace(/^skill:\/\//u, '').split(/[/\\]/u);
            if (/^skill:\/\//u.test(link) || /^skill\.md$/iu.test(stem.at(-1) ?? '')) {
              if (/^skill\.md$/iu.test(stem.at(-1) ?? '')) stem.pop();
              const dir = stem.at(-1);
              if (dir) names.add(dir);
            }
          }
          i = close + 1;
          continue;
        }
      }
    }
    if (text[i] !== '$') { i += 1; continue; }
    const end = nameAt(text, i + 1);
    if (end === i + 1) { i += 1; continue; }
    const name = text.slice(i + 1, end);
    if (!ENV_VARS.has(name.toUpperCase())) { names.add(name); plain?.add(name); }
    i = end;
  }
  return names;
}

// --- Skill roots -------------------------------------------------------------------------------------------------------
// ADMIN root: directory names only (the service installs it; a directory name is the Skill name there).
// NON-ADMIN roots (config skill_roots plus repo roots) mirror Codex's discovery (ext/skills/src/loader/discovery.rs +
// exec-server/src/local_file_system.rs walk, rust-v0.163.0): breadth-first from the root, root = depth 0; a directory
// entry is expanded only while the depth of the directory being read is < MAX_SCAN_DEPTH (loader/mod.rs:31 = 6), so a
// SKILL.md up to 6 directories below the root is found and one at 7 is not (the tests pin this); hidden directories
// (name starts with '.') are listed but not entered (local_file_system.rs:827; the root itself may be hidden, e.g. an
// explicitly listed `.system`); directory symlinks are followed for user/repo/admin scope (host.rs:165) with loops cut
// by realpath (:830-850). Only existence is recorded; file contents are never read. The file name is matched
// case-insensitively (conservative; Codex's exact-case rule is not verified here, over-matching only over-blocks).
// FAIL CLOSED: anything unreadable or over the caps sets `incomplete` (see runHook).
const MAX_SCAN_DEPTH = 6;
const MAX_DIRS = 2000;

interface Scan { found: boolean; realRoots: string[]; incomplete: boolean; dirs: number }
const gone = (e: unknown): boolean => ['ENOENT', 'ENOTDIR'].includes((e as NodeJS.ErrnoException).code ?? '');

async function scanRoot(root: string, scan: Scan): Promise<void> {
  let real: string;
  try {
    const st = await lstat(root);
    if (!st.isDirectory()) { scan.incomplete = true; return; } // symlinked or non-directory root: not followed, fail closed
    real = await realpath(root);
  } catch (e) { if (!gone(e)) scan.incomplete = true; return; }
  if (real.includes('\uFFFD')) { scan.incomplete = true; return; } // non-UTF-8 real path: cannot be compared reliably
  scan.realRoots.push(real);
  const seen = new Set([real]);
  const queue = [{ dir: root, depth: 0 }];
  scan.dirs += 1;
  for (let q = 0; q < queue.length; q += 1) {
    const { dir, depth } = queue[q]!;
    let entries: string[];
    try { entries = (await readdir(dir)).sort(); } catch { scan.incomplete = true; continue; }
    for (const name of entries) {
      if (name.includes('\uFFFD')) { scan.incomplete = true; continue; } // non-UTF-8 name: lstat would miss it (lossy decode)
      const p = path.join(dir, name);
      let isDir: boolean;
      try {
        const ls = await lstat(p);
        isDir = ls.isDirectory();
        if (/^skill\.md$/iu.test(name) && !isDir) {
          scan.found = true;
          if (!ls.isFile()) scan.incomplete = true; // symlink, FIFO, ...: present but not a plain file
          continue;
        }
        if (ls.isSymbolicLink()) isDir = (await stat(p)).isDirectory();
      } catch (e) { if (!gone(e)) scan.incomplete = true; continue; } // a dangling link is ignored, as in Codex
      if (!isDir || name.startsWith('.') || depth >= MAX_SCAN_DEPTH) continue;
      try {
        const r = await realpath(p);
        if (r.includes('\uFFFD')) { scan.incomplete = true; continue; } // lossy: distinct targets would share one key
        if (seen.has(r)) continue;
        seen.add(r);
      } catch { scan.incomplete = true; continue; }
      if (scan.dirs >= MAX_DIRS) { scan.incomplete = true; continue; }
      scan.dirs += 1;
      queue.push({ dir: p, depth: depth + 1 });
    }
  }
}

/** Every ancestor of cwd up to "/" (cwd first). Markers are ignored: they are employee-controlled. */
function ancestors(cwd: string, scan: Scan): string[] {
  const chain: string[] = [];
  for (let d = path.normalize(cwd); chain.length < MAX_ANCESTORS; d = path.dirname(d)) {
    chain.push(d);
    if (path.dirname(d) === d) return chain;
  }
  scan.incomplete = true; // deeper than the cap: the rest of the chain is not scanned
  return chain;
}

/** What the adapter learns of the host's environment (values are never logged). */
export interface HostEnv { codexHome?: string; home?: string }

/** Reads CODEX_HOME and HOME from /proc/<pid>/environ (first occurrence, as getenv). Throws on any problem. */
export async function readProcEnviron(pid: number): Promise<HostEnv> {
  const fh = await open(`/proc/${pid}/environ`, 'r');
  let buf: Buffer;
  try {
    buf = Buffer.alloc(MAX_ENVIRON_BYTES + 1);
    const { bytesRead } = await fh.read(buf, 0, buf.length, 0);
    if (bytesRead > MAX_ENVIRON_BYTES) throw new Error('environ too large');
    buf = buf.subarray(0, bytesRead);
  } finally { await fh.close(); }
  const env: HostEnv = {};
  for (const entry of buf.toString('utf8').split('\0')) {
    if (entry.startsWith('CODEX_HOME=') && env.codexHome === undefined) env.codexHome = entry.slice(11);
    else if (entry.startsWith('HOME=') && env.home === undefined) env.home = entry.slice(5);
  }
  return env;
}

/**
 * Codex loads `<codex_home>/.env` at startup (arg0/src/lib.rs load_dotenv, rust-v0.163.0) and sets every key except
 * CODEX_*, so it can change HOME after exec, which /proc/<pid>/environ does not show. dotenvy keys are bare identifiers
 * (no escapes), so a file without the bytes "HOME" cannot set it. True = cannot rule it out (fail closed).
 */
async function dotenvMayMoveHome(codexHome: string): Promise<boolean> {
  const file = `${codexHome}/.env`;
  try {
    const st = await lstat(file);
    if (!st.isFile() || st.size > MAX_ENVIRON_BYTES) return true; // symlink, FIFO, directory, huge: not inspected
    return (await readFile(file)).includes('HOME');
  } catch (e) { return (e as NodeJS.ErrnoException).code !== 'ENOENT'; }
}

interface Found {
  /** admin directory entry names, lower-cased key */ admin: Map<string, string>; adminReal: string | undefined;
  anySkill: boolean; roots: string[]; incomplete: boolean; cwd: string | undefined;
}

async function findSkills(cfg: CodexConfig, cwd: string | undefined, env: HostEnv | undefined): Promise<Found> {
  const scan: Scan = { found: false, realRoots: [], incomplete: false, dirs: 0 };
  const admin = new Map((await listRoot(cfg.adminRoot)).map((e) => [e.toLowerCase(), e]));
  const adminReal = await realpath(cfg.adminRoot).catch(() => undefined);
  const roots = new Set(cfg.skillRoots);
  // U+FFFD: Codex hands the hook a lossily decoded cwd, and environ is decoded here as UTF-8, so a non-UTF-8 path would be
  // scanned at a name that does not exist. Fail closed instead.
  const usable = (v: string | undefined): v is string => v !== undefined && v !== '' && path.isAbsolute(v) && !/[\0\uFFFD]/u.test(v);
  const absDir = (v: string | undefined): string | undefined => usable(v) ? path.normalize(v).replace(/(?<=.)\/+$/u, '') : undefined;
  const home = absDir(env?.home);
  // Codex canonicalises a set CODEX_HOME (utils/home-dir find_codex_home), so `..` after a symlink resolves physically.
  const codexHome = env?.codexHome === undefined || env.codexHome === ''
    ? (home === undefined ? undefined : `${home}/.codex`)
    : usable(env.codexHome) ? await realpath(env.codexHome).then((r) => (usable(r) ? r : undefined), () => undefined) : undefined;
  if (env === undefined || home === undefined || codexHome === undefined) scan.incomplete = true; // fail closed
  else if (await dotenvMayMoveHome(codexHome)) scan.incomplete = true;
  else for (const r of [`${codexHome}/skills`, `${codexHome}/skills/.system`, `${home}/.agents/skills`]) roots.add(r);
  const validCwd = usable(cwd);
  if (!validCwd) scan.incomplete = true;
  else for (const d of ancestors(cwd, scan)) for (const sub of ['.codex/skills', '.agents/skills']) roots.add(path.join(d, sub));
  for (const r of roots) await scanRoot(r, scan);
  return { admin, adminReal, anySkill: scan.found, roots: [...roots, ...scan.realRoots], incomplete: scan.incomplete, cwd: validCwd ? cwd : undefined };
}

/**
 * The admin Skill (actual directory name) that a link `[$x](path)` resolves to by realpath, exactly `<admin>/<name>/SKILL.md`
 * (rule L2). A leading `skill://` or `file://` is stripped; a `file://` with a host part, a relative link without a usable
 * cwd, any other scheme and anything that does not resolve all give undefined (rule L3: not an approved Skill file).
 */
async function adminLinkName(link: string, f: Found): Promise<string | undefined> {
  if (f.adminReal === undefined || /^[a-z][a-z0-9+.-]*:\/\//iu.test(link) && !/^(file|skill):\/\//iu.test(link)) return undefined;
  const stripped = link.replace(/^(file|skill):\/\//iu, '');
  if (/^file:\/\//iu.test(link) && !stripped.startsWith('/')) return undefined; // file://host/...
  if (!path.isAbsolute(stripped) && f.cwd === undefined) return undefined;
  try {
    const real = await realpath(path.resolve(f.cwd ?? '/', stripped));
    // The service publishes each admin entry as a symlink to its generation (service.ts HOST-VISIBLE SKILLS), so the link
    // is compared with the resolved `<admin>/<name>/SKILL.md` of each admin entry, not with a path under the admin root.
    for (const name of f.admin.values())
      if (await realpath(path.join(f.adminReal, name, 'SKILL.md')).catch(() => undefined) === real) return name;
    return undefined;
  } catch { return undefined; }
}

async function listRoot(root: string): Promise<string[]> {
  let st;
  try { st = await lstat(root); } catch (e) { if ((e as NodeJS.ErrnoException).code === 'ENOENT') return []; throw e; }
  if (!st.isDirectory()) throw new Error('Skill root is not a real directory'); // a symlinked root is not followed: fail closed
  return readdir(root);
}

// --- Bash command text (best-effort) -----------------------------------------------------------------------------------
function inspectCommand(raw: string, cfg: CodexConfig): { rogue: boolean; admin: string[] } {
  const command = raw.replace(/\/{2,}/gu, '/'); // `.agents//skills` is the same path
  const collapse = (v: string): string => v.replace(/\/{2,}/gu, '/');
  const esc = collapse(cfg.adminRoot).replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
  // Any mention of a user/repo Skill location in any spelling (~, $HOME, relative), or of a SKILL.md file other than an
  // admin Skill's own `<admin_root>/<name>/SKILL.md`.
  const start = '(?<=^|[\\s\'"`=;|&()<>])'; // the admin path must start a word: `<other>/<admin>/x/SKILL.md` is not admin
  const outsideAdmin = command.replace(new RegExp(`${start}${esc}/[A-Za-z0-9][A-Za-z0-9._-]*/SKILL\\.md`, 'giu'), '');
  const rogue = /\.(agents|codex)(?![A-Za-z0-9_-])/u.test(command) || /skill\.md/iu.test(outsideAdmin)
    || cfg.skillRoots.some((r) => command.includes(collapse(r)));
  const admin = new Set<string>();
  for (const m of command.matchAll(new RegExp(`${start}${esc}/([A-Za-z0-9][A-Za-z0-9._-]*)`, 'gu'))) admin.add(m[1]!);
  return { rogue, admin: [...admin] };
}

// --- config and parsing -------------------------------------------------------------------------------------------------
interface CodexConfig extends HookConfig { adminRoot: string; skillRoots: string[] }

/** Codex adapter dependencies: the shared hook ones plus a reader of the host's environment (tests inject it). */
export interface CodexDeps extends HookDeps { readHostEnv?: (pid: number) => Promise<HostEnv> }

async function loadCodexConfig(file: string, uid: number): Promise<CodexConfig> {
  const cfg = await loadConfig(file, uid, ['admin_root', 'skill_roots']);
  const { admin_root: admin = DEFAULT_ADMIN_ROOT, skill_roots: roots = [] } = cfg.raw;
  const abs = (v: unknown): v is string => typeof v === 'string' && path.isAbsolute(v) && !v.includes('\0');
  if (!abs(admin) || !Array.isArray(roots) || roots.length > 64 || !roots.every(abs)) throw new Error('bad Skill roots');
  return { ...cfg, adminRoot: admin.replace(/\/+$/u, ''), skillRoots: roots.map((r) => r.replace(/\/+$/u, '')) };
}

function parseHookInput(bytes: Buffer, peek: (k: Kind) => void): Parsed {
  const raw = parseStrictJson(bytes, INPUT_LIMITS);
  if (!isRecord(raw)) throw new Error('input must be an object');
  const name = raw['hook_event_name'];
  if (typeof name !== 'string' || !KINDS.includes(name)) throw new Error('unknown event');
  peek(name as Kind);
  if (name === 'SessionStart') return { kind: 'start' };
  const cwd = raw['cwd'];
  if (cwd !== undefined && typeof cwd !== 'string') throw new Error('bad cwd');
  if (name === 'UserPromptSubmit') {
    if (typeof raw['prompt'] !== 'string') throw new Error('missing prompt');
    return { kind: 'prompt', prompt: raw['prompt'], ...(cwd !== undefined ? { cwd } : {}) };
  }
  if (typeof raw['tool_name'] !== 'string' || !isRecord(raw['tool_input'])) throw new Error('bad tool call');
  const command = raw['tool_input']['command'];
  if (typeof command === 'string') return { kind: 'bash', command }; // any tool with a string command is a shell command
  if (Array.isArray(command) && command.length > 0 && command.every((c) => typeof c === 'string'))
    return { kind: 'bash', command: command.join(' ') }; // argv-style commands are inspected the same way
  if (raw['tool_name'] === 'Bash') throw new Error('missing command');
  return { kind: 'other-tool' };
}

const OK: HookOutcome = { code: 0, stdout: '', stderr: '' };
const block = (message: string): HookOutcome => ({ code: 2, stdout: '', stderr: message });

/** Never throws and never outlives the self-deadline. */
export async function runHook(argv: readonly string[], deps: CodexDeps): Promise<HookOutcome> {
  let mode: Mode = 'enforce';
  const out = await runHookInner(argv, deps, (m) => { mode = m; });
  return { ...out, mode };
}

async function runHookInner(argv: readonly string[], deps: CodexDeps, setMode: (m: Mode) => void): Promise<HookOutcome> {
  const uid = deps.rootUid ?? 0; // never from argv
  let mode: Mode = argv[1] === 'shadow' ? 'shadow' : 'enforce';
  let kind: Kind | undefined;
  let cfg: CodexConfig | undefined;
  try { cfg = await loadCodexConfig(argv[0] ?? '', uid); } catch { cfg = undefined; }
  if (cfg?.mode === 'enforce') mode = 'enforce';
  setMode(mode);
  const fail = (message: string): HookOutcome => (mode === 'shadow' || kind === 'SessionStart' ? OK : block(message));

  const work = async (): Promise<HookOutcome> => {
    const bytes = await deps.readStdin();
    if (!bytes) return fail(COULD_NOT_VERIFY);
    let parsed: Parsed;
    try { parsed = parseHookInput(bytes, (k) => { kind = k; }); } catch { return fail(COULD_NOT_VERIFY); }
    if (!cfg) return fail(COULD_NOT_VERIFY);

    // The host pid is needed both for the environment read (prompts with mentions) and for the service session.
    let hostPid: Promise<number> | undefined;
    const host = (): Promise<number> => (hostPid ??= (deps.findHost ?? findHostPid)(cfg.hostExes));

    // What to ask the service about: [skill, event]. Nothing to ask for an ordinary prompt or command.
    const asks: { skill: string; event: GateRequest['event'] }[] = [];
    if (parsed.kind === 'prompt') {
      const links: string[] = [];
      const plain = new Set<string>();
      const linkNames: string[] = [];
      const names = extractMentions(parsed.prompt, links, plain, linkNames);
      if (names.size > 0 || links.length > 0) { // a link decides even when its name is an env var
        let env: HostEnv | undefined;
        try { env = await (deps.readHostEnv ?? readProcEnviron)(await host()); } catch { env = undefined; } // fail closed in findSkills
        const f = await findSkills(cfg, parsed.cwd, env);
        const wide = f.anySkill || f.incomplete; // a non-admin Skill may exist: any token could name it
        // Links first, in prompt order (design Y1/X1): L1 ignored, L2 resolves to an admin Skill file (asked), L3 blocked.
        for (const [i, l] of links.entries()) {
          if (/^(app|mcp|plugin):\/\//u.test(l)) continue; // L1 (exact lower-case schemes, as Codex matches them)
          const a = await adminLinkName(l, f);
          // L2 also needs the link text to name that same admin Skill; `[$rogue](<admin>/alpha/SKILL.md)` is L3.
          const text = linkNames[i] ?? '';
          if (a === undefined || text.toLowerCase() !== a.toLowerCase()) {
            if (mode === 'enforce') return block(notAdmin(cfg.adminRoot)); // L3
            continue;
          }
          asks.push({ skill: validateSkillName(a), event: 'prompt-expansion' });
        }
        // Then the plain tokens in prompt order (T1-T6, "wide" form).
        for (const n of plain) {
          if (/:[^:]/u.test(n)) { // T1: a plugin-namespaced token can select a Skill the walk never lists
            if (mode === 'enforce') return block(notAdmin(cfg.adminRoot));
            continue;
          }
          const adminName = f.admin.get(n.toLowerCase());
          if (adminName === undefined && !wide) continue; // T6
          // T2: under wide, an admin name may really select a same-name repo/user Skill.
          if (wide && adminName !== undefined && mode === 'enforce') return block(MASKED);
          let skill: string;
          try { skill = validateSkillName(adminName ?? n); } catch {
            if (mode === 'enforce') return block(notAdmin(cfg.adminRoot)); // T4: e.g. `alpha:` under wide
            continue;
          }
          asks.push({ skill, event: 'prompt-expansion' });
        }
      }
    } else if (parsed.kind === 'bash') {
      const c = inspectCommand(parsed.command, cfg);
      if (c.rogue && mode === 'enforce') return block(notAdmin(cfg.adminRoot));
      if (c.admin.length > MAX_ADMIN_NAMES) return fail(COULD_NOT_VERIFY);
      for (const skill of c.admin) asks.push({ skill: validateSkillName(skill), event: 'skill-invoke' });
    }
    if (parsed.kind !== 'start' && asks.length === 0) return OK;
    let pid: number;
    try { pid = await host(); } catch { return fail(COULD_NOT_VERIFY); }
    const session = `pid:${pid}`;
    const ask = async (request: Omit<GateRequest, 'v' | 'request_id' | 'session'>) =>
      (deps.ask ?? askService)(cfg.socket, { v: 1, request_id: newRequestId(), session, ...request } as GateRequest, cfg.clientDeadlineMs, cfg.rootUid);
    if (parsed.kind === 'start') { await ask({ event: 'session-start' }); return OK; } // never blocks
    for (const a of asks) {
      const answer = await ask({ event: a.event, skill: a.skill });
      const result = answer.ok ? answer.result : { kind: 'parse-failure' as const };
      if (decideAction(result, mode) === 'deny')
        return block(result.kind === 'verdict' && result.verdict !== 'UNVERIFIABLE' ? notApproved(result.verdict) : COULD_NOT_VERIFY);
    }
    return OK;
  };

  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<HookOutcome>((resolve) => {
    timer = setTimeout(() => resolve(fail(COULD_NOT_VERIFY)), cfg?.selfDeadlineMs ?? DEFAULT_SELF_DEADLINE_MS);
  });
  try { return await Promise.race([work().catch(() => fail(COULD_NOT_VERIFY)), timeout]); }
  finally { clearTimeout(timer); }
}
