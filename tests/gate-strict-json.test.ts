import assert from 'node:assert/strict';
import test from 'node:test';
import { DEFAULT_STRICT_JSON_LIMITS, parseStrictJson, StrictJsonError } from '../src/gate/strict-json.ts';

const enc = (s: string): Uint8Array => new TextEncoder().encode(s);
const bad = (input: string | Uint8Array, limits = DEFAULT_STRICT_JSON_LIMITS): void =>
  assert.throws(() => parseStrictJson(typeof input === 'string' ? enc(input) : input, limits), StrictJsonError);

test('parses ordinary non-canonical JSON', () => {
  const value = parseStrictJson(enc(' { "b" : [1, -2.5e3, true, null, "x\\u00e9\\n"], "a": {} } \n')) as Record<string, unknown>;
  assert.deepEqual(Object.keys(value), ['b', 'a']);
  assert.deepEqual(value['b'], [1, -2500, true, null, 'xé\n']);
  assert.equal(Object.getPrototypeOf(value), null);
  assert.equal(parseStrictJson(enc('"\\ud83d\\ude00"')), '\u{1F600}');
});

test('rejects duplicate members, including escaped-equivalent and nested', () => {
  bad('{"a":1,"a":2}');
  bad('{"a":1,"\\u0061":2}');
  bad('{"x":{"a":1,"a":2}}');
  bad('[{"k":1,"k":1}]');
});

test('rejects forbidden member names', () => {
  bad('{"__proto__":{}}');
  bad('{"constructor":1}');
  bad('{"prototype":1}');
  bad('{"\\u005f_proto__":1}');
});

test('rejects trailing data and multiple values', () => {
  bad('{} x');
  bad('{}{}');
  bad('1 2');
  bad('');
  bad('   ');
});

test('rejects bad UTF-8 and BOM', () => {
  bad(new Uint8Array([0x22, 0xff, 0x22]));
  bad(new Uint8Array([0xef, 0xbb, 0xbf, 0x7b, 0x7d]));
  bad(new Uint8Array([0x22, 0xed, 0xa0, 0x80, 0x22])); // encoded surrogate
});

test('enforces limits', () => {
  const limits = { maxBytes: 20, maxDepth: 3, maxMembers: 2, maxStringLength: 4 };
  assert.doesNotThrow(() => parseStrictJson(enc('[[[1]]]'), limits));
  bad('[[[[1]]]]', limits);
  bad('x'.repeat(21), limits);
  bad('[1,2,3]', limits);
  bad('{"a":1,"b":2,"c":3}', limits);
  assert.doesNotThrow(() => parseStrictJson(enc('"abcd"'), limits));
  bad('"abcde"', limits);
  bad('"\\u0061bcde"', limits);
});

test('rejects lone surrogates and control characters', () => {
  bad('"\\ud800"');
  bad('"\\ud800x"');
  bad('"\\ud800\\u0041"');
  bad('"\\udc00"');
  bad('"a\u0001b"');
  bad('"a\nb"');
  bad('"a\tb"');
});

test('rejects non-RFC 8259 syntax', () => {
  for (const s of ['01', '-01', 'NaN', 'Infinity', '-Infinity', '+1', '.5', '1.', '1e', '0x10',
    '{"a":1,}', '[1,]', "{'a':1}", '/* c */ {}', '{} // c', '{"a" 1}', '[1 2]', '"\\x41"', '"\\u12"',
    'tru', 'undefined', '{"a":}', '{1:2}']) bad(s);
});

test('errors name an offset and never echo content', () => {
  try {
    parseStrictJson(enc('{"secret-value":1,"secret-value":2}'));
    assert.fail('should throw');
  } catch (error) {
    assert.ok(error instanceof StrictJsonError);
    assert.match(error.message, /offset \d+/u);
    assert.doesNotMatch(error.message, /secret/u);
  }
});

test('numbers that overflow to Infinity are rejected', () => {
  for (const input of ['1e999', '-1e999', '[1e400]']) {
    assert.throws(() => parseStrictJson(new TextEncoder().encode(input)), StrictJsonError, input);
  }
});
