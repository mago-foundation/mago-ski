// Argument checks for the phase 2 IPC channels: exact key sets and types, so a compromised page cannot smuggle extra
// fields or odd values into a signing request. Pure, so they can be tested without Electron.
import { validateDigest, validateScope } from '../../../src/names.ts';
import { APPROVER_LIFETIMES, MAX_APPROVER_NAME, REVOCATION_LIFETIMES, TIMESTAMP_LIFETIMES, TRUST_ROOT_LIFETIMES } from '../service/admin.ts';
import type { AdminApproverLifetime, AdminListLifetime, AdminRevokeRequest, AdminTimestampLifetime, AdminTrustRootLifetime } from '../service/types.ts';

export const KEY_ID = /^sha256:[0-9a-f]{64}$/u;
const MAX_SCOPES_PER_APPROVER = 64;
/** A discovered instance id, as the observation service makes them. */
export const INSTANCE_ID = /^[A-Za-z0-9-]{1,80}$/u;
/** A revocation reason as it crosses the IPC boundary; the session applies the real limit (512) after trimming. */
export const MAX_RAW_REVOKE_REASON = 4096;

function exact(value: unknown, required: readonly string[], optional: readonly string[] = []): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new Error('invalid arguments');
  const keys = Object.keys(value);
  if (!required.every((key) => keys.includes(key)) || !keys.every((key) => required.includes(key) || optional.includes(key))) throw new Error('invalid arguments');
  return value as Record<string, unknown>;
}

function oneOf<T extends string>(value: unknown, allowed: readonly T[], label: string): T {
  if (typeof value !== 'string' || !(allowed as readonly string[]).includes(value)) throw new Error(`invalid ${label}`);
  return value as T;
}

export function parseAddApprover(value: unknown): { name: string; scopes: string[]; lifetime: AdminApproverLifetime; trustRootLifetime?: AdminTrustRootLifetime } {
  const o = exact(value, ['name', 'scopes', 'lifetime'], ['trustRootLifetime']);
  if (typeof o.name !== 'string' || o.name.length > MAX_APPROVER_NAME) throw new Error('invalid name');
  if (!Array.isArray(o.scopes) || o.scopes.length < 1 || o.scopes.length > MAX_SCOPES_PER_APPROVER) throw new Error('invalid scopes');
  const scopes = o.scopes.map((scope: unknown) => {
    if (typeof scope !== 'string') throw new Error('invalid scopes');
    return validateScope(scope);
  });
  return {
    name: o.name, scopes, lifetime: oneOf(o.lifetime, APPROVER_LIFETIMES, 'lifetime'),
    ...(o.trustRootLifetime === undefined ? {} : { trustRootLifetime: oneOf(o.trustRootLifetime, TRUST_ROOT_LIFETIMES, 'trust root lifetime') }),
  };
}

export function parseRemoveApprover(value: unknown): { keyId: string; trustRootLifetime?: AdminTrustRootLifetime } {
  const o = exact(value, ['keyId'], ['trustRootLifetime']);
  if (typeof o.keyId !== 'string' || !KEY_ID.test(o.keyId)) throw new Error('invalid key id');
  return {
    keyId: o.keyId,
    ...(o.trustRootLifetime === undefined ? {} : { trustRootLifetime: oneOf(o.trustRootLifetime, TRUST_ROOT_LIFETIMES, 'trust root lifetime') }),
  };
}

export function parseRenew(value: unknown): { lifetime: AdminTrustRootLifetime } {
  const o = exact(value, ['lifetime']);
  return { lifetime: oneOf(o.lifetime, TRUST_ROOT_LIFETIMES, 'lifetime') };
}

export function parseRevoke(value: unknown): { target: AdminRevokeRequest; reason: string; lifetime: AdminListLifetime } {
  const o = exact(value, ['target', 'reason', 'lifetime']);
  if (typeof o.reason !== 'string' || o.reason.length > MAX_RAW_REVOKE_REASON) throw new Error('invalid reason');
  const kind = (typeof o.target === 'object' && o.target !== null && !Array.isArray(o.target) ? (o.target as { kind?: unknown }).kind : undefined);
  let target: AdminRevokeRequest;
  if (kind === 'key') {
    const t = exact(o.target, ['kind', 'keyId']);
    if (typeof t.keyId !== 'string' || !KEY_ID.test(t.keyId)) throw new Error('invalid key id');
    target = { kind: 'key', keyId: t.keyId };
  } else if (kind === 'digest') {
    const t = exact(o.target, ['kind', 'digest', 'instanceId']);
    if (typeof t.instanceId !== 'string' || !INSTANCE_ID.test(t.instanceId)) throw new Error('invalid instance id');
    target = { kind: 'digest', digest: validateDigest(t.digest), instanceId: t.instanceId };
  } else if (kind === 'other') {
    exact(o.target, ['kind']);
    target = { kind: 'other' };
  } else {
    throw new Error('invalid target');
  }
  return { target, reason: o.reason, lifetime: oneOf(o.lifetime, REVOCATION_LIFETIMES, 'lifetime') };
}

export function parseRefresh(value: unknown): { lifetime: AdminListLifetime } {
  const o = exact(value, ['lifetime']);
  return { lifetime: oneOf(o.lifetime, REVOCATION_LIFETIMES, 'lifetime') };
}

export function parseSignTimestamp(value: unknown): { lifetime: AdminTimestampLifetime } {
  const o = exact(value, ['lifetime']);
  return { lifetime: oneOf(o.lifetime, TIMESTAMP_LIFETIMES, 'lifetime') };
}
