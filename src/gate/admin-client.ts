// Client of the gate service's admin socket: one JSON request line out, one JSON reply line back (mirrors `serveOnce`
// in service.ts). Transport problems throw; an `ok: false` reply is returned as data.
import net from 'node:net';
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
