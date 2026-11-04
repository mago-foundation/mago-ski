// Names the host process (claude) that spawned a hook: walks the parent chain and returns the first ancestor whose
// /proc/<pid>/exe is allowlisted. Only a pointer for the service, which re-verifies the pid from the kernel.
import { readFile, readlink } from 'node:fs/promises';

const MAX_LEVELS = 8;

export async function findHostPid(hostExes: readonly string[], startPid: number = process.ppid): Promise<number> {
  let pid = startPid;
  for (let level = 0; level < MAX_LEVELS && pid > 1; level += 1) {
    let exe = await readlink(`/proc/${pid}/exe`).catch(() => '');
    if (exe.endsWith(' (deleted)')) exe = exe.slice(0, -' (deleted)'.length); // same acceptance as service.ts
    if (hostExes.includes(exe)) return pid;
    const stat = await readFile(`/proc/${pid}/stat`, 'utf8').catch(() => '');
    // comm may hold spaces and ')': fields start behind the LAST ')'; rest[0] is the state, rest[1] the ppid.
    pid = Number(stat.slice(stat.lastIndexOf(')') + 2).split(' ')[1]);
    if (!Number.isSafeInteger(pid)) break;
  }
  throw new Error('host process not found');
}
