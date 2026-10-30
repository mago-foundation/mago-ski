// Line diff for the "original text" view. Display only: change detection and approval use engine digests.
import type { DiffLine } from './types.ts';

export const MAX_DIFF_LINES = 20_000;
/** Myers edit-distance budget; beyond it the file is shown as replaced, not diffed. */
const MAX_EDIT_DISTANCE = 4_000;

type Op = { kind: 'same' | 'add' | 'del'; oldIndex: number; newIndex: number };

export function splitLines(text: string): string[] {
  if (text === '') return [];
  const lines = text.split(/\r\n|\r|\n/u);
  if (lines[lines.length - 1] === '') lines.pop();
  return lines;
}

/** Myers O(ND) diff. Returns null when the files differ by more than the budget. */
function myers(a: string[], b: string[]): Op[] | null {
  const n = a.length;
  const m = b.length;
  const max = Math.min(n + m, MAX_EDIT_DISTANCE);
  const offset = max + 1;
  const v = new Int32Array(2 * max + 3);
  const trace: Int32Array[] = [];

  for (let d = 0; d <= max; d += 1) {
    trace.push(v.slice());
    for (let k = -d; k <= d; k += 2) {
      let x = k === -d || (k !== d && v[offset + k - 1]! < v[offset + k + 1]!)
        ? v[offset + k + 1]!
        : v[offset + k - 1]! + 1;
      let y = x - k;
      while (x < n && y < m && a[x] === b[y]) { x += 1; y += 1; }
      v[offset + k] = x;
      if (x >= n && y >= m) return backtrack(trace, a, b, offset, d);
    }
  }
  return null;
}

function backtrack(trace: Int32Array[], a: string[], b: string[], offset: number, distance: number): Op[] {
  const ops: Op[] = [];
  let x = a.length;
  let y = b.length;
  for (let d = distance; d > 0; d -= 1) {
    const v = trace[d]!;
    const k = x - y;
    const prevK = k === -d || (k !== d && v[offset + k - 1]! < v[offset + k + 1]!) ? k + 1 : k - 1;
    const prevX = v[offset + prevK]!;
    const prevY = prevX - prevK;
    while (x > prevX && y > prevY) { x -= 1; y -= 1; ops.push({ kind: 'same', oldIndex: x, newIndex: y }); }
    if (x === prevX) { y -= 1; ops.push({ kind: 'add', oldIndex: x, newIndex: y }); }
    else { x -= 1; ops.push({ kind: 'del', oldIndex: x, newIndex: y }); }
  }
  while (x > 0 && y > 0) { x -= 1; y -= 1; ops.push({ kind: 'same', oldIndex: x, newIndex: y }); }
  return ops.reverse();
}

/**
 * Diff with `context` unchanged lines around each change; longer unchanged runs become one "gap" line.
 * Returns null when the inputs are too large or too different to diff usefully.
 */
export function diffLines(before: string, after: string, context = 3): DiffLine[] | null {
  const a = splitLines(before);
  const b = splitLines(after);
  if (a.length + b.length > MAX_DIFF_LINES) return null;
  const ops = myers(a, b);
  if (!ops) return null;

  const keep = new Array<boolean>(ops.length).fill(false);
  ops.forEach((op, index) => {
    if (op.kind === 'same') return;
    for (let i = Math.max(0, index - context); i <= Math.min(ops.length - 1, index + context); i += 1) keep[i] = true;
  });

  const out: DiffLine[] = [];
  let skipped = 0;
  ops.forEach((op, index) => {
    if (!keep[index]) { skipped += 1; return; }
    if (skipped > 0) { out.push({ kind: 'gap', old: null, new: null, text: `${skipped} unchanged line${skipped === 1 ? '' : 's'}` }); skipped = 0; }
    out.push({
      kind: op.kind,
      old:  op.kind === 'add' ? null : op.oldIndex + 1,
      new:  op.kind === 'del' ? null : op.newIndex + 1,
      text: op.kind === 'add' ? b[op.newIndex]! : a[op.oldIndex]!,
    });
  });
  if (skipped > 0 && out.length > 0) out.push({ kind: 'gap', old: null, new: null, text: `${skipped} unchanged line${skipped === 1 ? '' : 's'}` });
  return out;
}
