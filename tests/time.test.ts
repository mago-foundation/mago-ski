import assert from 'node:assert/strict';
import test from 'node:test';
import {
  addDuration, formatTimestamp, parseDuration, parseTimestamp, truncateToSecond,
} from '../src/time.ts';

const LATEST_DATE_MS = 8.64e15;
const DAY_MS         = 86_400_000;

/** "2026" in Arabic-Indic digits, which a Unicode-aware \d would accept. */
const ARABIC_INDIC_YEAR = String.fromCharCode(0x0662, 0x0660, 0x0662, 0x0666);

test('timestamps round-trip with whole seconds', () => {
  const date = new Date('2026-10-09T12:34:56.789Z');
  assert.equal(formatTimestamp(date), '2026-10-09T12:34:56Z');

  const parsed = parseTimestamp('2026-10-09T12:34:56Z', 'at');
  assert.equal(parsed.getTime(), Date.parse('2026-10-09T12:34:56Z'));

  for (const edge of ['0000-01-01T00:00:00Z', '9999-12-31T23:59:59Z'])
    assert.equal(formatTimestamp(parseTimestamp(edge, 'at')), edge);
});

test('parseTimestamp rejects any other format', () => {
  const malformed = [
    123,
    null,
    undefined,
    '',
    '2026-10-09',
    '2026-10-09T12:00:00',
    '2026-10-09T12:00:00.000Z',
    '2026-10-09t12:00:00z',
    '2026-10-09T12:00:00+00:00',
    ' 2026-10-09T12:00:00Z',
    '2026-10-09T12:00:00Z\n',
    '+02026-10-09T12:00:00Z',
    `${ARABIC_INDIC_YEAR}-10-09T12:00:00Z`,
  ];

  for (const value of malformed)
    assert.throws(() => parseTimestamp(value, 'at'), /at must be a UTC timestamp/u, String(value));
});

test('parseTimestamp rejects dates that do not exist', () => {
  // Date would roll the first four over to another day; it rejects the last two itself.
  const impossible = [
    '2026-02-29T00:00:00Z',
    '2026-02-30T00:00:00Z',
    '2026-04-31T00:00:00Z',
    '2026-01-01T24:00:00Z',
    '2026-13-01T00:00:00Z',
    '2026-01-01T23:59:60Z',
  ];

  for (const value of impossible)
    assert.throws(() => parseTimestamp(value, 'at'), /at is not a valid timestamp/u, value);
});

test('formatTimestamp refuses invalid dates and years parseTimestamp cannot read', () => {
  const invalid = new Date(Number.NaN);
  assert.throws(() => formatTimestamp(invalid), /must be a valid date/u);

  const year10000 = new Date(Date.UTC(10_000, 0, 1));
  assert.throws(() => formatTimestamp(year10000), /between the years 0000 and 9999/u);

  const yearMinus1 = new Date(Date.UTC(-1, 0, 1));
  assert.throws(() => formatTimestamp(yearMinus1), /between the years 0000 and 9999/u);
});

test('parseDuration accepts 1 to 99999 days, hours or minutes', () => {
  assert.equal(parseDuration('90d'), 90 * DAY_MS);
  assert.equal(parseDuration('12h'), 12 * 3_600_000);
  assert.equal(parseDuration('30m'), 30 * 60_000);

  const longest = parseDuration('99999d');
  assert.equal(longest, 99_999 * DAY_MS);
  assert.ok(Number.isSafeInteger(longest));
});

test('parseDuration rejects anything else', () => {
  const malformed = ['', '1', 'd', '1w', '1.5d', '-1d', ' 1d', '1d\n', '100000d', 'Infinityd'];

  for (const value of malformed)
    assert.throws(() => parseDuration(value, 'expiry'), /expiry must look like 90d/u, value);

  assert.throws(() => parseDuration('0d', 'expiry'), /expiry must be positive/u);

  const notAString = 90 as unknown as string;
  assert.throws(() => parseDuration(notAString), /duration must look like 90d/u);
});

test('addDuration rounds down to a whole second', () => {
  const start = new Date('2026-10-09T12:00:00.999Z');
  assert.equal(addDuration(start, '1d').toISOString(), '2026-10-10T12:00:00.000Z');
});

test('addDuration refuses an invalid start and an end past the largest Date', () => {
  const invalid = new Date(Number.NaN);
  assert.throws(() => addDuration(invalid, '1d', 'expiry'), /expiry start must be a valid date/u);

  const latest = new Date(LATEST_DATE_MS);
  assert.throws(() => addDuration(latest, '1m', 'expiry'), /expiry end must be a valid date/u);
});

test('truncateToSecond drops milliseconds, also before 1970', () => {
  const after1970 = truncateToSecond(new Date('2026-10-09T12:00:00.999Z'));
  assert.equal(after1970.toISOString(), '2026-10-09T12:00:00.000Z');

  const before1970 = truncateToSecond(new Date(-1_500));
  assert.equal(before1970.toISOString(), '1969-12-31T23:59:58.000Z');

  assert.throws(() => truncateToSecond(new Date(Number.NaN)), /must be a valid date/u);
});
