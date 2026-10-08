import { canonicalBytes, exactKeys, isRecord, parseCanonicalJsonBytes, requireArray, requireString } from './canonical-json.ts';
import { envelopeBytes, parseEnvelope, signEnvelope } from './dsse.ts';
import type { PrivateKeyInfo } from './keys.ts';
import { validateDigest, validateSkillName } from './names.ts';
import { formatTimestamp, parseTimestamp } from './time.ts';
import { digestFileList, MAX_RELATIVE_PATH_BYTES, MAX_TREE_FILES, sha256Hex, TREE_PROFILE, type TreeFile } from './tree-digest.ts';

export const STATEMENT_TYPE = 'https://in-toto.io/Statement/v1';
export const STATEMENT_PAYLOAD_TYPE = 'application/vnd.in-toto+json';
export const CERTIFICATE_PREDICATE_TYPE = 'https://github.com/mago-foundation/mago-ski/blob/main/docs/spec/skill-certificate-v1.md';
/** in-toto DigestSet algorithm name for the mago.skill-tree/v2 digest. */
export const SUBJECT_DIGEST_ALGORITHM = 'magoSkillTreeV2';

export interface Certificate {
  /** sha256 of the certificate file bytes; used in logs. */
  id: string;
  skillName: string;
  digest: string;
  files: TreeFile[];
  approverKeyId: string;
  issuedAt: Date;
  expiresAt: Date;
  reason: string;
  previousDigest: string | null;
  envelope: ReturnType<typeof parseEnvelope>;
}

export interface IssueOptions {
  skillName: string;
  digest: string;
  files: TreeFile[];
  approver: PrivateKeyInfo;
  issuedAt: Date;
  expiresAt: Date;
  reason: string;
  previousDigest?: string | null;
}

export function issueCertificate(options: IssueOptions): Buffer {
  validateSkillName(options.skillName);
  if (digestFileList(options.files) !== options.digest) throw new Error('File list does not match the tree digest');
  if (options.expiresAt <= options.issuedAt) throw new Error('Certificate must expire after it is issued');
  const statement = {
    _type: STATEMENT_TYPE,
    subject: [{ name: options.skillName, digest: { [SUBJECT_DIGEST_ALGORITHM]: options.digest.slice('sha256:'.length) } }],
    predicateType: CERTIFICATE_PREDICATE_TYPE,
    predicate: {
      tree_profile: TREE_PROFILE,
      files: options.files.map((file) => ({ path: file.path, size: file.size, sha256: file.sha256, exec: file.exec })),
      approval: {
        approver_key_id: options.approver.keyId,
        issued_at: formatTimestamp(options.issuedAt),
        expires_at: formatTimestamp(options.expiresAt),
        reason: requireString(options.reason, 'reason', 1024),
      },
      previous_digest: options.previousDigest == null ? null : validateDigest(options.previousDigest, 'previous digest'),
    },
  };
  const payload = canonicalBytes(statement);
  return envelopeBytes(signEnvelope(STATEMENT_PAYLOAD_TYPE, payload, options.approver.keyId, options.approver.privateKey));
}

function parseFiles(value: unknown, label: string): TreeFile[] {
  return requireArray(value, label, MAX_TREE_FILES).map((item, index) => {
    const entry = exactKeys(item, ['path', 'size', 'sha256', 'exec'], `${label}[${index}]`);
    const filePath = entry.path;
    if (
      typeof filePath !== 'string' || filePath.length === 0 || Buffer.byteLength(filePath) > MAX_RELATIVE_PATH_BYTES ||
      filePath.startsWith('/') || filePath.includes('\\') || filePath.split('/').some((part) => part === '' || part === '.' || part === '..')
    ) {
      throw new Error(`${label}[${index}] path is not a safe relative path`);
    }
    if (typeof entry.size !== 'number' || !Number.isSafeInteger(entry.size) || entry.size < 0) throw new Error(`${label}[${index}] size is invalid`);
    if (typeof entry.sha256 !== 'string' || !/^[0-9a-f]{64}$/u.test(entry.sha256)) throw new Error(`${label}[${index}] sha256 is invalid`);
    if (typeof entry.exec !== 'boolean') throw new Error(`${label}[${index}] exec must be a boolean`);
    return { path: filePath, size: entry.size, sha256: entry.sha256, exec: entry.exec };
  });
}

/** Parses a certificate's structure. Signature and trust are checked by the verifier. */
export function parseCertificate(bytes: Uint8Array): Certificate {
  const label = 'certificate';
  const envelope = parseEnvelope(bytes, label);
  if (envelope.payloadType !== STATEMENT_PAYLOAD_TYPE) throw new Error(`${label} has the wrong payload type`);
  const statement = exactKeys(parseCanonicalJsonBytes(envelope.payloadBytes, `${label} statement`),
    ['_type', 'subject', 'predicateType', 'predicate'], `${label} statement`);
  if (statement._type !== STATEMENT_TYPE) throw new Error(`${label} is not an in-toto v1 statement`);
  if (statement.predicateType !== CERTIFICATE_PREDICATE_TYPE) throw new Error(`${label} has an unsupported predicateType`);
  const subjects = requireArray(statement.subject, `${label} subject`, 1);
  if (subjects.length !== 1) throw new Error(`${label} must have exactly one subject`);
  const subject = exactKeys(subjects[0], ['name', 'digest'], `${label} subject`);
  const skillName = validateSkillName(subject.name, `${label} subject name`);
  const digestSet = exactKeys(subject.digest, [SUBJECT_DIGEST_ALGORITHM], `${label} subject digest`);
  const digest = validateDigest(`sha256:${String(digestSet[SUBJECT_DIGEST_ALGORITHM])}`, `${label} subject digest`);
  const predicate = exactKeys(statement.predicate, ['tree_profile', 'files', 'approval', 'previous_digest'], `${label} predicate`);
  if (predicate.tree_profile !== TREE_PROFILE) throw new Error(`${label} uses unsupported tree profile ${String(predicate.tree_profile)}`);
  const files = parseFiles(predicate.files, `${label} files`);
  if (digestFileList(files) !== digest) throw new Error(`${label} file list does not match its subject digest`);
  const approval = exactKeys(predicate.approval, ['approver_key_id', 'issued_at', 'expires_at', 'reason'], `${label} approval`);
  const approverKeyId = String(approval.approver_key_id);
  if (approverKeyId !== envelope.signatures[0].keyid) throw new Error(`${label} approver_key_id does not match the signing key`);
  const issuedAt = parseTimestamp(approval.issued_at, `${label} issued_at`);
  const expiresAt = parseTimestamp(approval.expires_at, `${label} expires_at`);
  if (expiresAt <= issuedAt) throw new Error(`${label} expires before it is issued`);
  const previous = predicate.previous_digest;
  if (previous !== null && isRecord(previous)) throw new Error(`${label} previous_digest is invalid`);
  return {
    id: `sha256:${sha256Hex(bytes)}`,
    skillName,
    digest,
    files,
    approverKeyId,
    issuedAt,
    expiresAt,
    reason: requireString(approval.reason, `${label} reason`, 1024),
    previousDigest: previous === null ? null : validateDigest(previous, `${label} previous_digest`),
    envelope,
  };
}
