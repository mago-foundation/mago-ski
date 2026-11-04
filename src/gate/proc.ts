// Kernel facts for the gate service (Linux only, pure Node). Everything here comes from /proc, never from a request.
import { readFile, readlink } from 'node:fs/promises';

// shortcut: CLK_TCK is 100 on all mainstream Linux architectures; `getconf CLK_TCK` would need a shell. Upgrade if an
// architecture with another USER_HZ must be supported.
const CLK_TCK = 100;
const BOOT_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u;

/** The pid is readable but is not a plain host process (a thread id, a nested pid namespace): definitively not a live session. */
export class NotLiveError extends Error {}

export interface ProcessInfo { startedBootMs: number; exe: string; uid: number }

/**
 * Throws a clear error on any platform but Linux. Everything in this module reads /proc, so the gate service checks this
 * before it touches the disk; otherwise a non-Linux host would fail later with an unexplained ENOENT on a /proc path.
 */
export function assertGatePlatform(platform: NodeJS.Platform = process.platform): void {
  if (platform !== 'linux') throw new Error(`the mago-ski gate service runs on Linux only (this is ${platform})`);
}

export async function bootId(): Promise<string> {
  const id = (await readFile('/proc/sys/kernel/random/boot_id', 'utf8')).trim();
  if (!BOOT_ID.test(id)) throw new Error('unexpected boot_id format');
  return id;
}

/** Milliseconds since boot (CLOCK_BOOTTIME, so suspend counts and wall-clock steps do not matter). */
export async function bootMs(): Promise<number> {
  const first = (await readFile('/proc/uptime', 'utf8')).split(' ')[0] ?? '';
  if (!/^\d+\.\d+$/u.test(first)) throw new Error('unexpected /proc/uptime format');
  return Math.floor(Number(first) * 1000);
}

/**
 * Start time and uid of a PROCESS (a thread-group leader), without its exe. Throws if gone, unreadable, a thread id
 * (a thread starts later than its process, which would shorten a session's generation set) or a process of a nested
 * pid namespace (NSpid has more than one entry; unsupported, since pids in requests would not match this /proc).
 */
export async function processFacts(pid: number): Promise<{ startedBootMs: number; uid: number }> {
  if (!Number.isSafeInteger(pid) || pid < 1) throw new Error('invalid pid');
  const uid = parseStatus(await readFile(`/proc/${pid}/status`, 'utf8'), pid);
  const stat = await readFile(`/proc/${pid}/stat`, 'utf8');
  // comm sits in parentheses and may contain spaces and ')': the fields after it start behind the LAST ')'.
  const rest = stat.slice(stat.lastIndexOf(')') + 2).split(' ');
  const ticks = Number(rest[19]); // field 22 overall; field 3 (state) is rest[0]
  if (!Number.isSafeInteger(ticks) || ticks < 0) throw new Error('unexpected stat format');
  return { startedBootMs: Math.floor((ticks * 1000) / CLK_TCK), uid };
}

/** Checks a /proc/<pid>/status text (process, not a thread, not nested, not a zombie or dead) and returns the real uid. */
export function parseStatus(text: string, pid: number): number {
  const status = text.split('\n');
  const field = (name: string): string[] | undefined => status.find((l) => l.startsWith(`${name}:`))?.slice(name.length + 1).trim().split(/\s+/u);
  const state = field('State')?.[0];
  if (state === 'Z' || state === 'X') throw new NotLiveError('zombie or dead process'); // a zombie keeps its /proc entry but runs nothing
  if (Number(field('Tgid')?.[0]) !== pid) throw new NotLiveError('not a process (thread id)');
  if ((field('NSpid')?.length ?? 1) !== 1) throw new NotLiveError('nested pid namespace is unsupported');
  const uid = Number(field('Uid')?.[0]);
  if (!Number.isSafeInteger(uid)) throw new Error('unexpected status format');
  return uid;
}

/** processFacts plus the exe link. Throws if the process is gone or /proc is unreadable. */
export async function processInfo(pid: number): Promise<ProcessInfo> {
  const facts = await processFacts(pid);
  return { ...facts, exe: await readlink(`/proc/${pid}/exe`) };
}

/** Soft RLIMIT_NOFILE of this process (`Infinity` when unlimited), from /proc/self/limits. */
export async function nofileSoftLimit(): Promise<number> {
  const line = (await readFile('/proc/self/limits', 'utf8')).split('\n').find((l) => l.startsWith('Max open files'));
  const soft = line?.slice('Max open files'.length).trim().split(/\s+/u)[0];
  if (soft === 'unlimited') return Infinity;
  const n = Number(soft);
  if (!soft || !Number.isSafeInteger(n) || n < 1) throw new Error('unexpected /proc/self/limits format');
  return n;
}
