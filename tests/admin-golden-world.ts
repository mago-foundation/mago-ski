import { createHash } from 'node:crypto';
import { chmod, mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { addApprover, initRoot, removeApprover, updateRevocations } from '../src/admin.ts';
import { loadPrivateKey } from '../src/keys.ts';

/** Fixed-seed Ed25519 keys and a fixed clock, so the documents signed by the admin functions are byte-reproducible. */
export const GOLDEN_NOW = new Date('2026-10-01T00:00:00Z');
export const GOLDEN_DIR = path.join(import.meta.dirname, 'fixtures', 'admin-golden');
const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

function seedOf(name: string): Buffer {
  return createHash('sha256').update(`mago-ski admin golden ${name}`).digest();
}

export interface GoldenKeys { root: string; approverA: string; approverB: string; rootPub: string; aPub: string; bPub: string }

export async function writeGoldenKeys(dir: string): Promise<GoldenKeys> {
  const { createPrivateKey, createPublicKey } = await import('node:crypto');
  await mkdir(dir, { recursive: true });
  const out: Record<string, string> = {};
  for (const name of ['root', 'approverA', 'approverB']) {
    const der = Buffer.concat([PKCS8_ED25519_PREFIX, seedOf(name)]);
    const priv = createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
    const pem = priv.export({ type: 'pkcs8', format: 'pem' });
    out[name] = path.join(dir, `${name}.pem`);
    await writeFile(out[name]!, pem, { mode: 0o600 });
    await chmod(out[name]!, 0o600);
    out[`${name}Pub`] = path.join(dir, `${name}.pub`);
    await writeFile(out[`${name}Pub`]!, createPublicKey(priv).export({ type: 'spki', format: 'pem' }));
  }
  return { root: out.root!, approverA: out.approverA!, approverB: out.approverB!, rootPub: out.rootPub!, aPub: out.approverAPub!, bPub: out.approverBPub! };
}

const DIGEST = `sha256:${'ab'.repeat(32)}`;

export interface GoldenStep { file: string; run: (c: { keys: GoldenKeys; trustRoot: string; revocations: string; at: (days: number) => Date }) => Promise<unknown> }

/** Each step runs on the output of the previous one and leaves the document named by `file` for comparison. */
export const GOLDEN_STEPS: GoldenStep[] = [
  { file: 'trust-root-1-init.json', run: async () => undefined },
  { file: 'trust-root-2-add.json', run: async (c) => await addApprover({ rootKeyPath: c.keys.root, trustRootPath: c.trustRoot, now: c.at(1), publicKeyPath: c.keys.aPub, name: 'Reviewer A', scopes: ['*'], expires: '90d' }) },
  { file: 'trust-root-3-add-second.json', run: async (c) => await addApprover({ rootKeyPath: c.keys.root, trustRootPath: c.trustRoot, now: c.at(2), publicKeyPath: c.keys.bPub, name: 'Reviewer B', scopes: ['pdf-*', 'docs'], expires: '180d', trustRootExpires: '180d' }) },
  { file: 'trust-root-4-replace.json', run: async (c) => await addApprover({ rootKeyPath: c.keys.root, trustRootPath: c.trustRoot, now: c.at(3), publicKeyPath: c.keys.aPub, name: 'Reviewer A2', scopes: ['docs'], expires: '365d' }) },
  { file: 'trust-root-5-remove.json', run: async (c) => await removeApprover({ rootKeyPath: c.keys.root, trustRootPath: c.trustRoot, now: c.at(4), keyId: (await loadPrivateKey(c.keys.approverB)).keyId }) },
  { file: 'revocations-1-init.json', run: async () => undefined },
  { file: 'revocations-2-key.json', run: async (c) => await updateRevocations({ rootKeyPath: c.keys.root, revocationsPath: c.revocations, now: c.at(5), expires: '7d', revokeKey: `sha256:${'cd'.repeat(32)}`, reason: 'lost laptop' }) },
  { file: 'revocations-3-digest.json', run: async (c) => await updateRevocations({ rootKeyPath: c.keys.root, revocationsPath: c.revocations, now: c.at(6), revokeDigest: DIGEST, reason: 'bad version' }) },
  { file: 'revocations-4-both.json', run: async (c) => await updateRevocations({ rootKeyPath: c.keys.root, revocationsPath: c.revocations, now: c.at(7), expires: '30d', revokeKey: `sha256:${'ef'.repeat(32)}`, revokeDigest: `sha256:${'12'.repeat(32)}`, reason: 'both at once' }) },
  { file: 'revocations-5-refresh.json', run: async (c) => await updateRevocations({ rootKeyPath: c.keys.root, revocationsPath: c.revocations, now: c.at(8), expires: '7d' }) },
];

export async function initGolden(dir: string, keys: GoldenKeys): Promise<{ trustRoot: string; revocations: string }> {
  const trustRoot = path.join(dir, 'trust-root.json');
  const revocations = path.join(dir, 'revocations.json');
  await initRoot({ rootKeyPath: keys.root, trustRootOut: trustRoot, revocationsOut: revocations, now: GOLDEN_NOW });
  return { trustRoot, revocations };
}

export const goldenAt = (days: number): Date => new Date(GOLDEN_NOW.getTime() + days * 86_400_000);
