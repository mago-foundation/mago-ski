import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { plainNameLine } from '../src/gate/adapters/codex-names.ts';

interface Entry { id: string; doc: string; plain: string | null; codexName: string | null; note: string }
const corpus = JSON.parse(readFileSync(new URL('./fixtures/codex-names/corpus.json', import.meta.url), 'utf8')) as Entry[];

test('plainNameLine: every corpus document gets the recorded answer', () => {
  for (const e of corpus) assert.equal(plainNameLine(Buffer.from(e.doc, 'utf8')), e.plain, e.id);
});

test('plainNameLine: whatever it accepts, Codex names the Skill the same (oracle corpus)', () => {
  for (const e of corpus) {
    const got = plainNameLine(Buffer.from(e.doc, 'utf8'));
    if (got !== null) assert.equal(e.codexName, got, `${e.id}: Codex name differs`);
  }
  assert.ok(corpus.some((e) => e.plain !== null) && corpus.length > 50);
});

test('plainNameLine: invalid UTF-8 and size are refused; refusing is always allowed', () => {
  assert.equal(plainNameLine(Buffer.from([0x2d, 0x2d, 0x2d, 0x0a, 0xff, 0x0a])), null);
  assert.equal(plainNameLine(Buffer.alloc(0)), null);
  assert.equal(plainNameLine(Buffer.from('---\nname: ok\ndescription: d\n---\né body ☃\n')), 'ok');
});
