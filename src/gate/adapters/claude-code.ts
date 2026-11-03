// Claude Code hook adapter (E3 packet 9a, profile 1: plain managed-directory Skill names only). Pure of process I/O:
// claude-code-hook.ts feeds it stdin and writes its outcome.
//
// HOST SCHEMA (the one place). These shapes are what the cc0.3/cc0.4 spikes observed on Claude Code CLI 2.1.296 / Linux
// (.agent/reviews/cc0.4-fixtures/gate.py and cc0.4-enforcement-verification.md). They are NOT a verified complete host
// API and are unverified for any other version; re-check them before widening the supported matrix.
//   stdin   PreToolUse:          { hook_event_name: "PreToolUse", tool_name: "Skill", tool_input: { skill: "<name>", ... }, ... }
//           UserPromptExpansion: { hook_event_name: "UserPromptExpansion", command_name: "<name or /name>", ... }
//           SessionStart:        { hook_event_name: "SessionStart", ... }
//           Other outer fields (session_id, cwd, transcript_path, ...) are ignored: never used, never logged.
//           UNVERIFIED: whether command_name carries a leading "/" (a single one is stripped), whether built-in slash
//           commands (/help, ...) also reach UserPromptExpansion (they would be denied in enforce: NO_CERTIFICATE).
//   block   PreToolUse:          stdout {"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny",
//                                "permissionDecisionReason":<msg>}}, exit 0 (observed to block in cc0.4)
//           UserPromptExpansion: stdout {"decision":"block","reason":<msg>}, exit 0 (observed to block in cc0.4)
//           Primary block mechanism = these JSON answers with exit 0, because they are the only ones the evidence shows
//           working. Exit 2 + stderr is used ONLY when the event cannot be told (unparseable stdin, unknown event); it is
//           the host's generic block but UNVERIFIED here (live check pending; that exit 2 blocks is not evidenced).
//           If the strict parse fails but a lenient byte scan still finds a known blockable event name, that event's
//           deny body is emitted (a spoofed name can only produce a deny). SessionStart is never blocked.
//   allow   exit 0, no output.
//
// MODE. The managed settings pass the mode as argv[1] (`enforce`|`shadow`) as well as in the config file: if the
// config is unreadable or invalid, argv decides, and anything but exactly `shadow` is enforce. Enforce wins if either
// source says enforce (decideAction additionally never lets a service answer downgrade it).
// The adapter reads no environment variables. The config, its socket directory and the socket must be owned by root
// (uid 0); argv cannot change that (tests inject a uid through HookDeps via their own entry point).
import { lstat, readFile } from 'node:fs/promises';
import path from 'node:path';
import { isRecord } from '../../canonical-json.ts';
import { validateSkillName } from '../../names.ts';
import type { Mode } from '../../policy.ts';
import { decideAction, type GateRequest } from '../contract.ts';
import { parseStrictJson, type StrictJsonLimits } from '../strict-json.ts';
import { askService, DEFAULT_CLIENT_DEADLINE_MS, newRequestId, type AskResult } from './client.ts';
import { findHostPid } from './host-pid.ts';

export const MAX_STDIN_BYTES = 256 * 1024;
const DEFAULT_SELF_DEADLINE_MS = 3000;
// Matched to the stdin cap (the default 64 KiB / 16 KiB limits would deny legitimate long prompts).
const INPUT_LIMITS: StrictJsonLimits = { maxBytes: MAX_STDIN_BYTES, maxDepth: 16, maxMembers: 256, maxStringLength: 128 * 1024 };

export interface HookConfig {
  socket: string;
  mode: Mode;
  hostExes: string[];
  clientDeadlineMs: number;
  selfDeadlineMs: number;
  rootUid: number;
  /** The validated config object, for adapters that add their own keys (see `extraKeys`). */
  raw: Record<string, unknown>;
}

export interface HookOutcome { code: number; stdout: string; stderr: string; mode?: Mode }
export interface HookDeps {
  /** Resolves the whole stdin, or null if it exceeded MAX_STDIN_BYTES. */
  readStdin: () => Promise<Buffer | null>;
  findHost?: typeof findHostPid;
  ask?: (socket: string, request: GateRequest, deadlineMs: number, rootUid: number) => Promise<AskResult>;
  /** Uid that must own the config, socket directory and socket. Production: always 0 (tests inject their own). */
  rootUid?: number;
}

type HookKind = 'PreToolUse' | 'UserPromptExpansion' | 'SessionStart';
const KINDS: readonly string[] = ['PreToolUse', 'UserPromptExpansion', 'SessionStart'];

const COULD_NOT_VERIFY = 'mago-ski could not verify this Skill; it is blocked until verification works.';
const notApproved = (verdict: string): string =>
  `This Skill is not approved by your organisation (mago-ski: ${verdict}). If it was updated, restart the session to use the new version.`;

/** Strict, closed config: root-owned in production (a deployment requirement; here only "not group/other writable"). */
export async function loadConfig(file: string, rootUid = 0, extraKeys: readonly string[] = []): Promise<HookConfig> {
  if (!path.isAbsolute(file)) throw new Error('config path must be absolute');
  const st = await lstat(file);
  if (!st.isFile() || (st.mode & 0o022) !== 0 || st.uid !== rootUid) throw new Error('config must be a regular, root-owned, non-writable file');
  const raw = parseStrictJson(await readFile(file));
  if (!isRecord(raw)) throw new Error('config must be an object');
  const allowed = ['v', 'socket', 'mode', 'host_exes', 'client_deadline_ms', 'self_deadline_ms', ...extraKeys];
  if (Object.keys(raw).some((k) => !allowed.includes(k)) || raw['v'] !== 1) throw new Error('config has unknown fields or version');
  const { socket, mode, host_exes: exes } = raw;
  if (typeof socket !== 'string' || !path.isAbsolute(socket) || socket.length > 107) throw new Error('bad socket');
  if (mode !== 'enforce' && mode !== 'shadow') throw new Error('bad mode');
  const dir = await lstat(path.dirname(socket)); // the socket directory must not be replaceable by other users
  if (!dir.isDirectory() || dir.isSymbolicLink() || (dir.mode & 0o022) !== 0 || dir.uid !== rootUid) throw new Error('bad socket directory');
  if (!Array.isArray(exes) || exes.length === 0 || !exes.every((e) => typeof e === 'string' && path.isAbsolute(e))) throw new Error('bad host_exes');
  const ms = (v: unknown, dflt: number): number => {
    if (v === undefined) return dflt;
    if (typeof v !== 'number' || !Number.isInteger(v) || v < 50 || v > 60_000) throw new Error('bad deadline');
    return v;
  };
  return {
    socket, mode, hostExes: exes as string[], rootUid, raw,
    clientDeadlineMs: ms(raw['client_deadline_ms'], DEFAULT_CLIENT_DEADLINE_MS),
    selfDeadlineMs: ms(raw['self_deadline_ms'], DEFAULT_SELF_DEADLINE_MS),
  };
}

type Parsed = { kind: 'session-start' } | { kind: 'skill'; event: 'skill-invoke' | 'prompt-expansion'; skill: string };

/** Closed per-event schemas; `peek` receives the event kind as soon as it is known, even if the rest is invalid. */
function parseHookInput(bytes: Buffer, peek: (k: HookKind) => void): Parsed {
  const raw = parseStrictJson(bytes, INPUT_LIMITS);
  if (!isRecord(raw)) throw new Error('input must be an object');
  const name = raw['hook_event_name'];
  if (typeof name !== 'string' || !KINDS.includes(name)) throw new Error('unknown event');
  peek(name as HookKind);
  if (name === 'SessionStart') return { kind: 'session-start' };
  let skill: unknown;
  if (name === 'PreToolUse') {
    const input = raw['tool_input'];
    if (raw['tool_name'] !== 'Skill' || !isRecord(input)) throw new Error('not a Skill call');
    skill = input['skill'];
  } else {
    skill = raw['command_name'];
  }
  if (typeof skill !== 'string') throw new Error('missing Skill name');
  // A plugin-namespaced name (`plugin:name`) fails validateSkillName: unsupported in profile 1, so denied.
  return {
    kind: 'skill', event: name === 'PreToolUse' ? 'skill-invoke' : 'prompt-expansion',
    skill: validateSkillName(skill.startsWith('/') ? skill.slice(1) : skill),
  };
}

function block(kind: HookKind | undefined, message: string): HookOutcome {
  if (kind === 'PreToolUse')
    return { code: 0, stderr: '', stdout: JSON.stringify({ hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: message } }) };
  if (kind === 'UserPromptExpansion') return { code: 0, stderr: '', stdout: JSON.stringify({ decision: 'block', reason: message }) };
  if (kind === 'SessionStart') return { code: 0, stdout: '', stderr: '' };
  return { code: 2, stdout: '', stderr: message }; // event unknown: the host's generic block (unverified)
}

/** Lenient scan for a blockable event name in bytes the strict parser rejected. */
function scanKind(bytes: Buffer): HookKind | undefined {
  const text = bytes.toString('latin1');
  // Exactly one hook_event_name in the raw bytes: a second one (e.g. nested in model-controlled tool_input) makes the
  // event ambiguous, so fall back to exit 2 rather than risk the wrong event's block body.
  if ((text.match(/"hook_event_name"/gu) ?? []).length !== 1) return undefined;
  const m = /"hook_event_name"\s*:\s*"(PreToolUse|UserPromptExpansion)"/u.exec(text);
  return m ? (m[1] as HookKind) : undefined;
}

const OK: HookOutcome = { code: 0, stdout: '', stderr: '' };

/** Never throws and never outlives the self-deadline. */
export async function runHook(argv: readonly string[], deps: HookDeps): Promise<HookOutcome> {
  let mode: Mode = 'enforce';
  const out = await runHookInner(argv, deps, (m) => { mode = m; });
  return { ...out, mode };
}

async function runHookInner(argv: readonly string[], deps: HookDeps, setMode: (m: Mode) => void): Promise<HookOutcome> {
  const uid = deps.rootUid ?? 0; // never from argv: a non-root uid here would let that user run a fake service
  let mode: Mode = argv[1] === 'shadow' ? 'shadow' : 'enforce';
  let kind: HookKind | undefined;
  let cfg: HookConfig | undefined;
  try { cfg = await loadConfig(argv[0] ?? '', uid); } catch { cfg = undefined; } // lstat first, so a FIFO cannot hang it
  if (cfg?.mode === 'enforce') mode = 'enforce';
  setMode(mode);
  const fail = (message: string): HookOutcome => (mode === 'shadow' ? OK : block(kind, message));

  const work = async (): Promise<HookOutcome> => {
    const bytes = await deps.readStdin();
    if (!bytes) return fail(COULD_NOT_VERIFY);
    let parsed: Parsed;
    try { parsed = parseHookInput(bytes, (k) => { kind = k; }); } catch { kind ??= scanKind(bytes); return fail(COULD_NOT_VERIFY); }
    if (!cfg) return fail(COULD_NOT_VERIFY);
    let pid: number;
    try { pid = await (deps.findHost ?? findHostPid)(cfg.hostExes); } catch { return fail(COULD_NOT_VERIFY); }
    const request: GateRequest = {
      v: 1, request_id: newRequestId(), session: `pid:${pid}`,
      event: parsed.kind === 'session-start' ? 'session-start' : parsed.event,
      ...(parsed.kind === 'skill' ? { skill: parsed.skill } : {}),
    };
    const answer = await (deps.ask ?? askService)(cfg.socket, request, cfg.clientDeadlineMs, cfg.rootUid);
    if (parsed.kind === 'session-start') return OK; // never blocks; an unknown session is denied by the service later
    const result = answer.ok ? answer.result : { kind: 'parse-failure' as const };
    if (decideAction(result, mode) !== 'deny') return OK;
    return block(kind, result.kind === 'verdict' && result.verdict !== 'UNVERIFIABLE' ? notApproved(result.verdict) : COULD_NOT_VERIFY);
  };

  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<HookOutcome>((resolve) => {
    timer = setTimeout(() => resolve(fail(COULD_NOT_VERIFY)), cfg?.selfDeadlineMs ?? DEFAULT_SELF_DEADLINE_MS);
  });
  try { return await Promise.race([work().catch(() => fail(COULD_NOT_VERIFY)), timeout]); }
  finally { clearTimeout(timer); }
}
