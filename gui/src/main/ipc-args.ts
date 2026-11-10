// Argument checks for the phase 2 IPC channels: exact key sets and types, so a compromised page cannot smuggle extra
// fields or odd values into a signing request. Pure, so they can be tested without Electron.
import { validateScope } from '../../../src/names.ts';
import { APPROVER_LIFETIMES, MAX_APPROVER_NAME, TRUST_ROOT_LIFETIMES } from '../service/admin.ts';
import type { AdminApproverLifetime, AdminTrustRootLifetime } from '../service/types.ts';

export const KEY_ID = /^sha256:[0-9a-f]{64}$/u;
const MAX_SCOPES_PER_APPROVER = 64;

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
