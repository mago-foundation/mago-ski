// Client of the gate service's admin socket: one JSON request line out, one JSON reply line back (mirrors `serveOnce`
// in service.ts). Transport problems throw; an `ok: false` reply is returned as data.
import { lstat } from 'node:fs/promises';
import net from 'node:net';
import path from 'node:path';
import { parseStrictJson } from './strict-json.ts';

/** The service's admin processing deadline is 60 s; the client waits a little longer (design G10). */
export const ADMIN_DEADLINE_MS = 65_000;
const MAX_REPLY_BYTES = 1024 * 1024;

export type AdminReply = { v: 1; ok: true; [key: string]: unknown } | { v: 1; ok: false; error: string };
export type AskAdmin = (socketPath: string, command: Record<string, unknown>, deadlineMs?: number) => Promise<AdminReply>;

export const TIMEOUT_MESSAGE = 'the gate did not answer in time; run mago-ski gate status';

export const askAdmin: AskAdmin = (socketPath, command, deadlineMs = ADMIN_DEADLINE_MS) =>
  new Promise<AdminReply>((resolve, reject) => {
    const sock = net.connect(socketPath);
    const chunks: Buffer[] = [];
    let size = 0;
    let settled = false;
    const finish = (fn: () => void): void => { if (settled) return; settled = true; clearTimeout(timer); sock.destroy(); fn(); };
    const timer = setTimeout(() => finish(() => reject(new Error(TIMEOUT_MESSAGE))), deadlineMs);
    sock.on('error', (e: NodeJS.ErrnoException) => finish(() => reject(new Error(
      e.code === 'ENOENT' || e.code === 'ECONNREFUSED' ? `cannot reach the gate at ${socketPath} (${e.code}); is the service running?`
        : e.code === 'EACCES' ? `cannot open ${socketPath}: permission denied (the admin socket is for root)` : `gate socket error: ${e.message}`))));
    sock.on('connect', () => sock.write(`${JSON.stringify({ v: 1, ...command })}\n`));
    sock.on('data', (chunk: Buffer) => {
      const nl = chunk.indexOf(0x0a);
      size += nl < 0 ? chunk.length : nl;
      if (size > MAX_REPLY_BYTES) return finish(() => reject(new Error('the gate reply is too large')));
      chunks.push(nl < 0 ? chunk : chunk.subarray(0, nl));
      if (nl < 0) return;
      finish(() => {
        try {
          const bytes = Buffer.concat(chunks);
          parseStrictJson(bytes, { maxBytes: MAX_REPLY_BYTES, maxDepth: 16, maxMembers: 256, maxStringLength: MAX_REPLY_BYTES }); // duplicate keys, depth
          const reply = JSON.parse(bytes.toString('utf8')) as AdminReply; // the same text, as ordinary objects
          if (typeof reply !== 'object' || reply === null || typeof reply.ok !== 'boolean') throw new Error('shape');
          resolve(reply);
        } catch { reject(new Error('the gate sent a reply that is not valid JSON')); }
      });
    });
    sock.on('close', () => finish(() => reject(new Error('the gate closed the connection without a reply'))));
  });

/**
 * Before connecting: the admin socket's folder is a real folder owned by `uid` with mode 0700, and the socket in it is a
 * socket owned by `uid`. A folder or socket someone else could replace is not trusted with a trust root or a Skill.
 */
export async function checkAdminSocket(adminDir: string, uid: number): Promise<void> {
  const dir = await lstat(adminDir).catch((e: NodeJS.ErrnoException) => { throw new Error(`cannot reach the gate: ${adminDir}: ${e.code ?? 'error'}; is the service running?`); });
  if (dir.isSymbolicLink() || !dir.isDirectory()) throw new Error(`${adminDir} must be a real folder`);
  if (dir.uid !== uid || (dir.mode & 0o777) !== 0o700) throw new Error(`${adminDir} must be owned by root with mode 0700; the admin socket is not trusted`);
  const sock = path.join(adminDir, 'admin.sock');
  const info = await lstat(sock).catch((e: NodeJS.ErrnoException) => { throw new Error(`cannot reach the gate: ${sock}: ${e.code ?? 'error'}; is the service running?`); });
  if (!info.isSocket()) throw new Error(`${sock} is not a socket; the admin socket is not trusted`);
  if (info.uid !== uid) throw new Error(`${sock} must be owned by root; the admin socket is not trusted`);
}
