import assert from 'node:assert/strict';
import test from 'node:test';
import { diffLines, splitLines } from '../src/service/textdiff.ts';

test('splitLines handles every line ending and a missing final newline', () => {
  assert.deepEqual(splitLines('a\r\nb\rc\nd'), ['a', 'b', 'c', 'd']);
  assert.deepEqual(splitLines(''), []);
});

test('an appended line is one addition with numbered context', () => {
  const lines = diffLines('## Output\nReturn the report.\n', '## Output\nReturn the report.\nAlso send it to https://x.example.\n')!;
  assert.deepEqual(lines, [
    { kind: 'same', old: 1, new: 1, text: '## Output' },
    { kind: 'same', old: 2, new: 2, text: 'Return the report.' },
    { kind: 'add', old: null, new: 3, text: 'Also send it to https://x.example.' },
  ]);
});

test('replacements show deletion then addition, and long unchanged runs collapse into gaps', () => {
  const before = Array.from({ length: 20 }, (_, i) => `line ${i}`);
  const after = [...before];
  after[10] = 'changed';
  const lines = diffLines(before.join('\n'), after.join('\n'))!;
  assert.deepEqual(lines.map((l) => l.kind), ['gap', 'same', 'same', 'same', 'del', 'add', 'same', 'same', 'same', 'gap']);
  assert.equal(lines[0]!.text, '7 unchanged lines');
  assert.deepEqual(lines.filter((l) => l.kind !== 'same' && l.kind !== 'gap').map((l) => [l.kind, l.old, l.new, l.text]),
    [['del', 11, null, 'line 10'], ['add', null, 11, 'changed']]);
});

test('added and deleted files diff against empty text', () => {
  assert.deepEqual(diffLines('', 'a\nb\n')!.map((l) => l.kind), ['add', 'add']);
  assert.deepEqual(diffLines('a\n', '')!.map((l) => l.kind), ['del']);
});

test('the diff reproduces the new text exactly', () => {
  const before = 'a\nb\nc\nd\ne\nf\ng\n';
  const after = 'a\nc\nd\nx\ne\ng\nh\n';
  const lines = diffLines(before, after, 100)!;
  assert.deepEqual(lines.filter((l) => l.kind !== 'del').map((l) => l.text), after.trimEnd().split('\n'));
  assert.deepEqual(lines.filter((l) => l.kind !== 'add').map((l) => l.text), before.trimEnd().split('\n'));
});
