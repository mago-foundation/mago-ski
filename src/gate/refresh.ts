// Root-only inbox for signed trust documents (E3 packet 7). The customer's distribution (any transport) drops
// `trust-root.json` and `revocations.json` here; the service reads them and offers them to the trust store, which
// alone decides acceptance. No network code. The inbox directory must be a real directory owned by `rootUid` and not
// group/world-writable; files must be regular non-symlinks within the document size limit.
import { lstat } from 'node:fs/promises';
import path from 'node:path';
import { MAX_CANONICAL_JSON_BYTES } from '../canonical-json.ts';
import { readRegularFile } from '../fs-safe.ts';

export type InboxRead =
  | { kind: 'docs'; trustRootBytes: Buffer; revocationsBytes: Buffer }
  | { kind: 'absent' }
  | { kind: 'unsafe'; reason: string };

export async function readInbox(dir: string, rootUid: number): Promise<InboxRead> {
  try {
    const info = await lstat(dir).catch((e: NodeJS.ErrnoException) => { if (e.code === 'ENOENT') return undefined; throw e; });
    if (!info) return { kind: 'absent' };
    if (info.isSymbolicLink() || !info.isDirectory()) return { kind: 'unsafe', reason: 'inbox must be a real directory' };
    if (info.uid !== rootUid) return { kind: 'unsafe', reason: `inbox must be owned by uid ${rootUid}` };
    if ((info.mode & 0o022) !== 0) return { kind: 'unsafe', reason: 'inbox must not be group- or world-writable' };
    const read = (name: string): Promise<Buffer | undefined> =>
      readRegularFile(path.join(dir, name), name, MAX_CANONICAL_JSON_BYTES).catch((e: NodeJS.ErrnoException) => { if (e.code === 'ENOENT') return undefined; throw e; });
    const trustRootBytes = await read('trust-root.json');
    const revocationsBytes = await read('revocations.json');
    return trustRootBytes && revocationsBytes ? { kind: 'docs', trustRootBytes, revocationsBytes } : { kind: 'absent' };
  } catch (e) {
    return { kind: 'unsafe', reason: e instanceof Error ? e.message : 'unreadable inbox' };
  }
}
