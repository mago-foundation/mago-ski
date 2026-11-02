// Harness-neutral, versioned, closed contracts between hook adapters and the
// gate service. No transport, no file system. Parsing is strict: unknown or
// missing fields, wrong types and a mismatched request_id are errors, and there
// is no status field or any other fallback.

import { isRecord } from '../canonical-json.ts';
import { validateSkillName } from '../names.ts';
import type { Mode } from '../policy.ts';
import { VERDICTS, type Verdict } from '../verify.ts';
import { parseStrictJson } from './strict-json.ts';

export const GATE_EVENTS = ['skill-invoke', 'prompt-expansion', 'session-start'] as const;
export type GateEvent = (typeof GATE_EVENTS)[number];

export const GATE_ERROR_CODES = [
  'bad-request', 'verifier-failed', 'verifier-timeout',
  'no-session-record', 'trust-unavailable', 'internal',
] as const;
export type GateErrorCode = (typeof GATE_ERROR_CODES)[number];

export const MODES: readonly Mode[] = ['shadow', 'enforce'];

export interface GateRequest {
  v: 1;
  request_id: string;
  event: GateEvent;
  skill?: string;
  session: string;
}

export type GateResult =
  | { v: 1; request_id: string; kind: 'verdict'; verdict: Verdict; mode: Mode }
  | { v: 1; request_id: string; kind: 'gate-error'; code: GateErrorCode; mode: Mode }
  /** Reply to session-start only. It carries no verdict and is never permission (decideAction denies/observes it). */
  | { v: 1; request_id: string; kind: 'ack'; mode: Mode };

/** Any failure to obtain a valid GateResult (transport error, timeout, parse error). */
export interface ParseFailure {
  kind: 'parse-failure';
}

export type GateAction = 'allow' | 'deny' | 'observe';

const TOKEN_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/u;

function token(value: unknown, label: string): string {
  if (typeof value !== 'string' || !TOKEN_PATTERN.test(value))
    throw new Error(`${label} must be 1-128 ASCII letters, digits, dot, underscore, colon or hyphen`);
  return value;
}

function closed<T extends string>(value: unknown, allowed: readonly T[], label: string): T {
  if (typeof value !== 'string' || !(allowed as readonly string[]).includes(value))
    throw new Error(`${label} is not an allowed value`);
  return value as T;
}

function record(value: unknown, keys: readonly string[], label: string): Record<string, unknown> {
  if (!isRecord(value)) throw new Error(`${label} must be an object`);
  const extra = Object.keys(value).filter((key) => !keys.includes(key));
  if (extra.length > 0) throw new Error(`${label} has unknown fields`);
  if (value['v'] !== 1) throw new Error(`${label} version must be 1`);
  return value;
}

export function parseGateRequest(bytes: Uint8Array): GateRequest {
  const raw    = record(parseStrictJson(bytes), ['v', 'request_id', 'event', 'skill', 'session'], 'request');
  const event  = closed(raw['event'], GATE_EVENTS, 'event');
  const hasSkill = Object.hasOwn(raw, 'skill');
  if (event === 'session-start' ? hasSkill : !hasSkill)
    throw new Error('skill must be present except for session-start, where it must be absent');
  const request: GateRequest = {
    v: 1,
    request_id: token(raw['request_id'], 'request_id'),
    event,
    session: token(raw['session'], 'session'),
  };
  if (hasSkill) request.skill = validateSkillName(raw['skill']);
  return request;
}

export function parseGateResult(bytes: Uint8Array, expectedRequestId: string): GateResult {
  const parsed = parseStrictJson(bytes);
  if (!isRecord(parsed)) throw new Error('result must be an object');
  const kind = parsed['kind'];
  const raw  = record(parsed, kind === 'verdict'
    ? ['v', 'request_id', 'kind', 'verdict', 'mode']
    : kind === 'ack' ? ['v', 'request_id', 'kind', 'mode']
    : ['v', 'request_id', 'kind', 'code', 'mode'], 'result');
  const requestId = token(raw['request_id'], 'request_id');
  if (requestId !== expectedRequestId) throw new Error('result request_id does not match the request');
  const mode = closed(raw['mode'], MODES, 'mode');
  if (kind === 'verdict')
    return { v: 1, request_id: requestId, kind, verdict: closed(raw['verdict'], VERDICTS, 'verdict'), mode };
  if (kind === 'ack') return { v: 1, request_id: requestId, kind, mode };
  if (kind === 'gate-error')
    return { v: 1, request_id: requestId, kind, code: closed(raw['code'], GATE_ERROR_CODES, 'code'), mode };
  throw new Error('result kind is not an allowed value');
}

/**
 * Only a VERIFIED verdict allows (an ack never does). Anything else denies when enforce applies and is observed
 * (would-deny, never blocked) when it does not. Enforce applies if the local configuration says
 * enforce (or holds anything other than exactly 'shadow') or the service's result says enforce,
 * so nothing in a result can downgrade local enforce. A parse failure carries no mode and
 * follows the local configuration.
 */
export function decideAction(result: GateResult | ParseFailure, configuredMode: Mode): GateAction {
  const ok = result.kind === 'verdict' && result.verdict === 'VERIFIED';
  if (ok) return 'allow';
  // Enforce wins if either side says so: a result can never downgrade local enforce.
  // Any configured value other than exactly 'shadow' fails closed to enforce.
  const enforce = configuredMode !== 'shadow' || (result.kind !== 'parse-failure' && result.mode === 'enforce');
  return enforce ? 'deny' : 'observe';
}

export function serializeGateRequest(request: GateRequest): string {
  return JSON.stringify(request);
}

export function serializeGateResult(result: GateResult): string {
  return JSON.stringify(result);
}
