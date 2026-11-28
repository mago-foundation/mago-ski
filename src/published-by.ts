// published-by (mago.published-by/v1): a publisher's CI states, with its own repository identity and no stored key,
// "this repository published these exact Skill bytes, with this declaration as read and this observed profile".
// Signing is done by GitHub's actions/attest (keyless Sigstore, public log for public repositories); this module
// builds the statement's content and verifies a bundle offline. A verifier recomputes everything from the bytes and
// never trusts what the publisher's CI computed. The output is facts about who published what; never "safe".
import { createHash, X509Certificate } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import os from 'node:os';
import path from 'node:path';
import { verifySigstoreAttestation } from './experimental/sigstore.ts';
import { readRegularFile } from './fs-safe.ts';
import { profileTree, type ObservedProfile } from './profile.ts';
import { collectSkillTree, SKILL_FILENAME } from './tree-digest.ts';
import { readUsf, type UsfManifest } from './usf.ts';

export const PUBLISHED_BY_PREDICATE_TYPE = 'https://magofoundation.dev/attestation/published-by/v1';
export const GITHUB_OIDC_ISSUER = 'https://token.actions.githubusercontent.com';
const IN_TOTO_STATEMENT_V1 = 'https://in-toto.io/Statement/v1';
const IN_TOTO_PAYLOAD_TYPE = 'application/vnd.in-toto+json';
const MAX_BUNDLE_BYTES = 16 * 1024 * 1024;

export interface PublishedSkill {
  /** Skill folder, relative to the repository root, with `/` separators. */
  path: string;
  /** Tree digest (mago.skill-tree/v2): the attestation subject. */
  digest: string;
  skill_md_sha256: string;
  /** The USF declaration as read (see usf.ts), or null with the reason. */
  declaration: UsfManifest | null;
  declaration_error: string | null;
  profile: ObservedProfile;
}

export interface PublishedByPredicate {
  generator: { name: 'mago-ski'; version: string };
  skills: PublishedSkill[];
}

export function packageVersion(): string {
  return (createRequire(import.meta.url)('#package.json') as { version?: string }).version ?? 'unknown';
}

/** The record for one Skill folder, computed from its bytes. */
export async function describeSkill(skillDir: string, root: string): Promise<PublishedSkill> {
  const tree = await collectSkillTree(skillDir, { includeContents: true });
  const skillMd = tree.contents!.get(SKILL_FILENAME)!;
  const reading = readUsf(skillMd.toString('utf8'));
  return {
    path: path.relative(root, skillDir).split(path.sep).join('/') || '.',
    digest: tree.digest,
    skill_md_sha256: `sha256:${createHash('sha256').update(skillMd).digest('hex')}`,
    declaration: reading.manifest,
    declaration_error: reading.error,
    profile: profileTree(tree),
  };
}

/** Subject lines for actions/attest's `subject-checksums` input: `<hex>  <name>`. */
export function subjectChecksums(skills: readonly PublishedSkill[]): string {
  return skills.map((skill) => {
    const name = `skill:${skill.path}`;
    // One subject per line: a name with a line break (or other control character) would add a subject.
    if (/[\u0000-\u001f\u007f]/u.test(name)) throw new Error(`Skill path ${JSON.stringify(skill.path)} contains a control character`);
    return `${skill.digest.slice('sha256:'.length)}  ${name}\n`;
  }).join('');
}

/* ********************************************  */
/*        Reading a bundle (after Cosign)        */
/* ********************************************  */

interface Statement { subject: { name?: unknown; digest?: { sha256?: unknown } }[]; predicateType: unknown; predicate: unknown }

function parseJson(bytes: Buffer, label: string): unknown {
  try {
    return JSON.parse(bytes.toString('utf8'));
  } catch {
    throw new Error(`${label} is not JSON`);
  }
}

function bundleParts(bundle: unknown): { statement: Statement; certificate: Buffer } {
  const b = bundle as { verificationMaterial?: { certificate?: { rawBytes?: unknown }; x509CertificateChain?: { certificates?: { rawBytes?: unknown }[] } }; dsseEnvelope?: { payload?: unknown; payloadType?: unknown } };
  const envelope = b?.dsseEnvelope;
  if (typeof envelope?.payload !== 'string' || envelope.payloadType !== IN_TOTO_PAYLOAD_TYPE) throw new Error('the bundle holds no in-toto DSSE envelope');
  const raw = b.verificationMaterial?.certificate?.rawBytes ?? b.verificationMaterial?.x509CertificateChain?.certificates?.[0]?.rawBytes;
  if (typeof raw !== 'string') throw new Error('the bundle holds no signing certificate');
  const statement = parseJson(Buffer.from(envelope.payload, 'base64'), 'the in-toto statement') as Statement & { _type?: unknown };
  if (statement?._type !== IN_TOTO_STATEMENT_V1 || !Array.isArray(statement.subject)) throw new Error('the payload is not an in-toto v1 statement');
  return { statement, certificate: Buffer.from(raw, 'base64') };
}

/* ********************************************  */
/*        Fulcio certificate extensions          */
/* ********************************************  */

interface Tlv { tag: number; start: number; end: number; next: number }

function tlv(der: Buffer, offset: number, limit: number): Tlv {
  if (offset + 2 > limit) throw new Error('certificate DER is truncated');
  const tag = der[offset]!;
  let length = der[offset + 1]!;
  let start = offset + 2;
  if (length & 0x80) {
    const bytes = length & 0x7f;
    if (bytes === 0 || bytes > 4 || start + bytes > limit) throw new Error('certificate DER has an unsupported length');
    length = 0;
    for (let index = 0; index < bytes; index += 1) length = length * 256 + der[start + index]!;
    start += bytes;
  }
  if (start + length > limit) throw new Error('certificate DER is truncated');
  return { tag, start, end: start + length, next: start + length };
}

function children(der: Buffer, parent: Tlv): Tlv[] {
  const out: Tlv[] = [];
  for (let offset = parent.start; offset < parent.end; offset = out[out.length - 1]!.next) out.push(tlv(der, offset, parent.end));
  return out;
}

function oidString(bytes: Buffer): string {
  const parts = [Math.floor(bytes[0]! / 40), bytes[0]! % 40];
  let value = 0;
  for (const byte of bytes.subarray(1)) {
    value = value * 128 + (byte & 0x7f);
    if ((byte & 0x80) === 0) { parts.push(value); value = 0; }
  }
  return parts.join('.');
}

const FULCIO = '1.3.6.1.4.1.57264.1.';
/** Fulcio's provider-neutral extensions (1.3.6.1.4.1.57264.1.8 onwards), each a DER UTF8String. */
const FULCIO_FIELDS: Record<string, string> = {
  '8': 'issuer', '9': 'build_signer_uri', '10': 'build_signer_digest', '11': 'runner_environment', '12': 'source_repository_uri',
  '13': 'source_repository_digest', '14': 'source_repository_ref', '15': 'source_repository_id', '16': 'source_repository_owner_uri',
  '17': 'source_repository_owner_id', '18': 'build_config_uri', '19': 'build_config_digest', '20': 'build_trigger', '21': 'run_invocation_uri',
};

/** The Fulcio identity fields of a signing certificate. The certificate itself was verified by Cosign. */
export function fulcioIdentity(certificateDer: Buffer): Record<string, string> {
  const certificate = tlv(certificateDer, 0, certificateDer.length);
  const tbs = children(certificateDer, certificate)[0];
  if (!tbs) throw new Error('certificate has no TBSCertificate');
  const extensionsWrapper = children(certificateDer, tbs).find((item) => item.tag === 0xa3);
  const fields: Record<string, string> = {};
  if (!extensionsWrapper) return fields;
  const [extensions] = children(certificateDer, extensionsWrapper);
  for (const extension of extensions ? children(certificateDer, extensions) : []) {
    const parts = children(certificateDer, extension);
    const oid = parts[0];
    const value = parts[parts.length - 1];
    if (!oid || oid.tag !== 0x06 || !value || value.tag !== 0x04) continue;
    const id = oidString(certificateDer.subarray(oid.start, oid.end));
    if (!id.startsWith(FULCIO)) continue;
    const name = FULCIO_FIELDS[id.slice(FULCIO.length)];
    if (!name) continue;
    const inner = tlv(certificateDer, value.start, value.end);
    if (inner.tag !== 0x0c) continue;
    fields[name] = certificateDer.subarray(inner.start, inner.end).toString('utf8');
  }
  return fields;
}

/* ********************************************  */
/*                  Verification                 */
/* ********************************************  */

export interface VerifyPublishedByOptions {
  bundlePath: string;
  trustedRootPath: string;
  cosignPath: string;
  /** The publishing repository, `OWNER/NAME`; the signer's workflow must belong to it. Without it any GitHub repository is accepted and reported. */
  repository?: string;
  /** Optional workflow file inside it, e.g. `.github/workflows/publish.yml`. */
  workflow?: string;
  /** Optional numeric repository id: survives renames and cannot be claimed by a fork or a new repository of the same name. */
  repositoryId?: string;
}

/** The normalised publisher identity (R7): ids and the workflow path survive renames; names are informational. */
export interface Publisher { repository_id: string; owner_id: string; repository: string; workflow: string; commit: string; ref: string; trigger: string }

export function publisherOf(fields: Record<string, string>): Publisher {
  const config = /^https:\/\/github\.com\/[^/]+\/[^/]+\/(\.github\/workflows\/[^@]+)@/u.exec(fields.build_config_uri ?? '');
  const required = {
    repository_id: fields.source_repository_id, owner_id: fields.source_repository_owner_id, repository: fields.source_repository_uri,
    workflow: config?.[1], commit: fields.source_repository_digest, ref: fields.source_repository_ref, trigger: fields.build_trigger,
  };
  for (const [name, value] of Object.entries(required)) if (!value) throw new Error(`the signing certificate has no ${name}`);
  return required as Publisher;
}

export interface PublishedByFacts {
  digest: string;
  publisher: Record<string, string>;
  /** The record the publisher's CI wrote for these bytes. */
  recorded: PublishedSkill;
  /** Differences between that record and what this verifier computed; empty when they agree. */
  differences: string[];
}

const escapeRegexp = (text: string) => text.replace(/[\\^$.*+?()[\]{}|/]/gu, '\\$&');

/**
 * Checks a published-by bundle for a Skill folder. Throws when the bundle does not verify for these exact bytes and
 * this publisher. Returns the publisher facts and any difference between the recorded and the recomputed record.
 */
export async function verifyPublishedBy(skillDir: string, options: VerifyPublishedByOptions): Promise<PublishedByFacts> {
  if (options.repository !== undefined && !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u.test(options.repository)) throw new RangeError('--repo must be OWNER/NAME');
  if (options.workflow !== undefined && !/^\.github\/workflows\/[A-Za-z0-9_.\-/]+\.ya?ml$/u.test(options.workflow)) throw new RangeError('--workflow must be a path such as .github/workflows/publish.yml');
  if (options.repositoryId !== undefined && !/^[0-9]{1,20}$/u.test(options.repositoryId)) throw new RangeError('--repo-id must be the numeric repository id');

  const mine = await describeSkill(skillDir, path.dirname(path.resolve(skillDir)));
  const digestHex = mine.digest.slice('sha256:'.length);

  // Cosign checks a private copy, and the statement is read from the same bytes: the file cannot change in between.
  const bytes = await readRegularFile(options.bundlePath, 'Sigstore bundle', MAX_BUNDLE_BYTES);
  const parts = bundleParts(parseJson(bytes, 'the Sigstore bundle'));
  const scratch = await mkdtemp(path.join(os.tmpdir(), 'mago-ski-bundle-'));
  try {
    const copy = path.join(scratch, 'bundle.json');
    await writeFile(copy, bytes, { mode: 0o600, flag: 'wx' });
    const workflow = options.workflow === undefined ? '\\.github/workflows/[^@]+' : escapeRegexp(options.workflow);
    await verifySigstoreAttestation({
      binaryPath: options.cosignPath, bundlePath: copy, trustedRootPath: options.trustedRootPath, digestHex,
      predicateType: PUBLISHED_BY_PREDICATE_TYPE, issuer: GITHUB_OIDC_ISSUER,
      identityRegexp: `^https://github\\.com/${options.repository === undefined ? '[^/]+/[^/]+' : escapeRegexp(options.repository)}/${workflow}@`,
    });
  } finally {
    await rm(scratch, { recursive: true, force: true });
  }

  const { statement, certificate } = parts;
  if (statement.predicateType !== PUBLISHED_BY_PREDICATE_TYPE) throw new Error('the statement is not a published-by statement');
  if (!statement.subject.some((subject) => subject?.digest?.sha256 === digestHex)) throw new Error('the statement does not name this Skill\'s digest');
  const predicate = statement.predicate as Partial<PublishedByPredicate> | null;
  const recorded = Array.isArray(predicate?.skills) ? predicate.skills.find((skill) => skill?.digest === mine.digest) : undefined;
  if (!recorded) throw new Error('the statement has no record for this Skill\'s digest');

  new X509Certificate(certificate); // a parse check only: Cosign verified the chain
  const publisher = fulcioIdentity(certificate);
  if (publisher.issuer !== GITHUB_OIDC_ISSUER) throw new Error('the signing certificate was not issued for a GitHub Actions identity');
  // Cosign matched the signing workflow (the certificate's SAN). The repository whose code ran and the top-level workflow
  // are separate fields: with a reusable workflow they differ, so both are required to match as well.
  const normalised = publisherOf(publisher);
  const asciiLower = (value: string) => value.replace(/[A-Z]/gu, (c) => c.toLowerCase());
  if (options.repository !== undefined && asciiLower(normalised.repository) !== asciiLower(`https://github.com/${options.repository}`))
    throw new Error(`the signed code came from ${normalised.repository}, not ${options.repository}`);
  if (options.workflow !== undefined && normalised.workflow !== options.workflow)
    throw new Error(`the top-level workflow is ${normalised.workflow}, not ${options.workflow}`);
  if (options.repositoryId !== undefined && publisher.source_repository_id !== options.repositoryId)
    throw new Error(`the signer's repository id is ${publisher.source_repository_id ?? 'missing'}, not ${options.repositoryId}`);

  const differences: string[] = [];
  const same = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);
  if (recorded.profile?.profile !== mine.profile.profile) differences.push(`the record uses ${String(recorded.profile?.profile)}; this verifier computes ${mine.profile.profile}`);
  else if (!same(recorded.profile, mine.profile)) differences.push('the recorded observed profile differs from the one computed from these bytes');
  if (!same(recorded.declaration, mine.declaration)) differences.push('the recorded declaration differs from the one read from these bytes');
  if (recorded.skill_md_sha256 !== mine.skill_md_sha256) differences.push('the recorded SKILL.md hash differs');
  return { digest: mine.digest, publisher, recorded, differences };
}
