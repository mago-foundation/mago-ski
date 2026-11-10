import assert from 'node:assert/strict';
import test from 'node:test';
import {
  GATE_ERROR_CODES, decideAction, parseGateRequest, parseGateResult, serializeGateRequest, serializeGateResult,
  type GateRequest, type GateResult,
} from '../src/gate/contract.ts';
import { VERDICTS } from '../src/verify.ts';

const enc = (s: string): Uint8Array => new TextEncoder().encode(s);
const req = (o: object): Uint8Array => enc(JSON.stringify(o));
const base = { v: 1, request_id: 'r1', event: 'skill-invoke', skill: 'my-skill', session: 's1' };
const okResult = { v: 1, request_id: 'r1', kind: 'verdict', verdict: 'VERIFIED', mode: 'enforce' };

test('request round-trips', () => {
  const a: GateRequest = { v: 1, request_id: 'r1', event: 'prompt-expansion', skill: 'a.b_c-1', session: 'abc:1' };
  const b: GateRequest = { v: 1, request_id: 'r2', event: 'session-start', session: 'abc:1' };
  for (const r of [a, b]) {
    const line = serializeGateRequest(r);
    assert.ok(!line.includes('\n'));
    assert.deepEqual({ ...parseGateRequest(enc(line)) }, r);
  }
});

test('request rejects non-objects, wrong types, missing and unknown fields', () => {
  for (const v of ['[]', '1', 'null', '"x"', 'true']) assert.throws(() => parseGateRequest(enc(v)));
  for (const k of ['v', 'request_id', 'event', 'skill', 'session']) {
    const o: Record<string, unknown> = { ...base };
    delete o[k];
    assert.throws(() => parseGateRequest(req(o)), k);
  }
  assert.throws(() => parseGateRequest(req({ ...base, extra: 1 })));
  assert.throws(() => parseGateRequest(req({ ...base, v: '1' })));
  assert.throws(() => parseGateRequest(req({ ...base, v: 2 })));
  assert.throws(() => parseGateRequest(req({ ...base, session: 5 })));
  assert.throws(() => parseGateRequest(req({ ...base, event: 'other' })));
  assert.throws(() => parseGateRequest(req({ ...base, session: 'has space' })));
  assert.throws(() => parseGateRequest(req({ ...base, request_id: 'x'.repeat(129) })));
});

test('request: duplicates, trailing data, concatenated objects rejected', () => {
  assert.throws(() => parseGateRequest(enc(JSON.stringify(base).replace('"v":1', '"v":1,"v":1'))));
  assert.throws(() => parseGateRequest(enc(`${JSON.stringify(base)}${JSON.stringify(base)}`)));
  assert.throws(() => parseGateRequest(enc(`${JSON.stringify(base)} x`)));
  assert.throws(() => parseGateRequest(enc('{"__proto__":1}')));
});

test('session-start must not carry a skill; others require a valid one', () => {
  assert.throws(() => parseGateRequest(req({ ...base, event: 'session-start' })));
  for (const skill of ['-x', '../a', 'a/b', '', '.hidden'])
    assert.throws(() => parseGateRequest(req({ ...base, skill })), skill);
});

test('result round-trips for every verdict and error code in both modes', () => {
  for (const mode of ['shadow', 'enforce'] as const) {
    const results: GateResult[] = [
      ...VERDICTS.map((verdict) => ({ v: 1 as const, request_id: 'r1', kind: 'verdict' as const, verdict, mode })),
      ...GATE_ERROR_CODES.map((code) => ({ v: 1 as const, request_id: 'r1', kind: 'gate-error' as const, code, mode })),
      { v: 1 as const, request_id: 'r1', kind: 'ack' as const, mode },
    ];
    for (const r of results) {
      const line = serializeGateResult(r);
      assert.ok(!line.includes('\n'));
      assert.deepEqual({ ...parseGateResult(enc(line), 'r1') }, r);
    }
  }
});

test('result rejects mismatched request_id, extra status, unknown values', () => {
  assert.throws(() => parseGateResult(req(okResult), 'other'));
  assert.throws(() => parseGateResult(req({ ...okResult, verdict: 'REVOKED', status: 'VERIFIED' }), 'r1'));
  assert.throws(() => parseGateResult(req({ ...okResult, status: 'VERIFIED' }), 'r1'));
  assert.throws(() => parseGateResult(req({ v: 1, request_id: 'r1', status: 'VERIFIED', mode: 'enforce' }), 'r1'));
  assert.throws(() => parseGateResult(req({ ...okResult, verdict: 'verified' }), 'r1'));
  assert.throws(() => parseGateResult(req({ ...okResult, mode: 'audit' }), 'r1'));
  assert.throws(() => parseGateResult(req({ ...okResult, kind: 'gate-error' }), 'r1'));
  assert.throws(() => parseGateResult(req({ v: 1, request_id: 'r1', kind: 'gate-error', code: 'nope', mode: 'enforce' }), 'r1'));
  assert.throws(() => parseGateResult(req({ v: 1, request_id: 'r1', kind: 'gate-error', verdict: 'VERIFIED', code: 'internal', mode: 'enforce' }), 'r1'));
  assert.throws(() => parseGateResult(enc('[]'), 'r1'));
  assert.throws(() => parseGateResult(enc(`${JSON.stringify(okResult)}${JSON.stringify(okResult)}`), 'r1'));
});

test('decideAction: enforce allows only VERIFIED; shadow never denies', () => {
  for (const verdict of VERDICTS) {
    const e = decideAction({ v: 1, request_id: 'r', kind: 'verdict', verdict, mode: 'enforce' }, 'enforce');
    const s = decideAction({ v: 1, request_id: 'r', kind: 'verdict', verdict, mode: 'shadow' }, 'shadow');
    assert.equal(e, verdict === 'VERIFIED' ? 'allow' : 'deny', verdict);
    assert.equal(s, verdict === 'VERIFIED' ? 'allow' : 'observe', verdict);
  }
  for (const code of GATE_ERROR_CODES) {
    assert.equal(decideAction({ v: 1, request_id: 'r', kind: 'gate-error', code, mode: 'enforce' }, 'enforce'), 'deny');
    assert.equal(decideAction({ v: 1, request_id: 'r', kind: 'gate-error', code, mode: 'shadow' }, 'shadow'), 'observe');
  }
});

test('decideAction: parse failure follows configured mode; result cannot downgrade enforce', () => {
  assert.equal(decideAction({ kind: 'parse-failure' }, 'enforce'), 'deny');
  assert.equal(decideAction({ kind: 'parse-failure' }, 'shadow'), 'observe');
  const shadowFail: GateResult = { v: 1, request_id: 'r', kind: 'verdict', verdict: 'REVOKED', mode: 'shadow' };
  assert.equal(decideAction(shadowFail, 'enforce'), 'deny');
  const enforceFail: GateResult = { ...shadowFail, mode: 'enforce' };
  assert.equal(decideAction(enforceFail, 'shadow'), 'deny');
});

test('a configured mode other than exactly shadow fails closed to enforce', () => {
  for (const mode of ['Enforce', undefined, '', 'shadow ']) {
    assert.equal(decideAction({ kind: 'parse-failure' }, mode as never), 'deny', String(mode));
  }
});

test('ack: strict shape, and never permission', () => {
  const ack = { v: 1, request_id: 'r1', kind: 'ack', mode: 'enforce' };
  assert.deepEqual({ ...parseGateResult(req(ack), 'r1') }, ack);
  assert.throws(() => parseGateResult(req({ ...ack, verdict: 'VERIFIED' }), 'r1'));
  assert.throws(() => parseGateResult(req({ ...ack, code: 'internal' }), 'r1'));
  assert.equal(decideAction(ack as GateResult, 'enforce'), 'deny');
  assert.equal(decideAction({ ...ack, mode: 'shadow' } as GateResult, 'shadow'), 'observe');
  assert.equal(decideAction({ ...ack, mode: 'enforce' } as GateResult, 'shadow'), 'deny');
});
