export * from './canonical-json.ts';
export * from './tree-digest.ts';
export * from './keys.ts';
export * from './dsse.ts';
export * from './time.ts';
export * from './names.ts';
export * from './trust-root.ts';
export * from './revocations.ts';
export * from './certificate.ts';
export * from './verify.ts';
export * from './root-events.ts';
export * from './timestamp.ts';
export * from './policy.ts';
export * from './admin.ts';
export * from './diff.ts';
import { runCli as runCliWithSeams } from './cli.ts';

/** The command line entry. The gate's test seams (a fake root uid, base folder, admin client) are not part of the library surface. */
export const runCli = (argv?: string[], now?: Date): Promise<number> => runCliWithSeams(argv, now);
