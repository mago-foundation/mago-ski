// Decision-socket client shared by all harness adapters. One strict request line out, one bounded answer line in,
// its own deadline. It never throws for transport or parse problems; the adapter turns any failure into a deny
// (service.ts ADAPTER CONTRACT).
import { randomBytes } from 'node:crypto';
import { lstat } from 'node:fs/promises';
import net from 'node:net';
import { parseGateResult, serializeGateRequest, type GateRequest, type GateResult } from '../contract.ts';

export type ClientFailure = 'no-answer' | 'late' | 'malformed' | 'connect-failed';
export type AskResult = { ok: true; result: GateResult } | { ok: false; failure: ClientFailure };

export const MAX_ANSWER_BYTES = 4096;
export const DEFAULT_CLIENT_DEADLINE_MS = 1500;

export const newRequestId = (): string => randomBytes(16).toString('hex');

export async function askService(
  socketPath: string, request: GateRequest, deadlineMs = DEFAULT_CLIENT_DEADLINE_MS, rootUid = 0,
): Promise<AskResult> {
  // Right before connecting: the path must be a socket owned by the service's uid (not a planted file or symlink).
  const st = await lstat(socketPath).catch(() => undefined);
  if (!st || !st.isSocket() || st.uid !== rootUid) return { ok: false, failure: 'connect-failed' };
  return new Promise((resolve) => {
    let done = false;
    let connected = false;
    const chunks: Buffer[] = [];
    let size = 0;
    const sock = net.connect(socketPath);
    const finish = (r: AskResult): void => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      sock.destroy();
      resolve(r);
    };
    const timer = setTimeout(() => finish({ ok: false, failure: connected ? 'late' : 'connect-failed' }), deadlineMs);
    const parse = (line: Buffer): void => {
      try { finish({ ok: true, result: parseGateResult(line, request.request_id) }); }
      catch { finish({ ok: false, failure: 'malformed' }); }
    };
    sock.on('connect', () => { connected = true; sock.write(`${serializeGateRequest(request)}\n`); });
    sock.on('error', () => finish({ ok: false, failure: connected ? 'no-answer' : 'connect-failed' }));
    sock.on('data', (d: Buffer) => {
      chunks.push(d);
      size += d.length;
      const all = Buffer.concat(chunks);
      const nl = all.indexOf(0x0a);
      if (nl >= 0) return parse(all.subarray(0, nl));
      if (size > MAX_ANSWER_BYTES) finish({ ok: false, failure: 'malformed' });
    });
    sock.on('close', () => {
      if (done) return;
      finish({ ok: false, failure: size === 0 ? 'no-answer' : 'malformed' });
    });
  });
}
