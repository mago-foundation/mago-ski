/** The only timestamp format accepted: UTC with whole seconds, e.g. 2026-10-09T12:00:00Z. */
const TIMESTAMP_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/u;

/** A duration is 1 to 5 digits plus a unit; 99999d (about 273 years) is the largest. */
const DURATION_PATTERN  = /^(\d{1,5})([dhm])$/u;

type DurationUnit = 'd' | 'h' | 'm';

const UNIT_MS: Record<DurationUnit, number> = {
  d: 24 * 60 * 60 * 1000,
  h: 60 * 60 * 1000,
  m: 60 * 1000,
};

/** Allowed clock skew when checking that a signed object was not issued in the future. */
export const CLOCK_SKEW_MS = 5 * 60 * 1000;

/**
 * Throws unless `date` is a Date that holds a real time.
 * An invalid Date holds NaN, and every comparison with NaN is false,
 * so an expiry check against it would silently pass.
 * Every function that compares documents against the current time calls this on `now` first.
 */
export function requireValidDate(date: Date, label: string): void {
  if (!(date instanceof Date) || Number.isNaN(date.getTime()))
    throw new Error(`${label} must be a valid date`);
}

/**
 * Writes a date as a UTC timestamp with whole seconds, e.g. 2026-10-09T12:00:00Z.
 * Milliseconds are dropped.
 */
export function formatTimestamp(date: Date): string {
  requireValidDate(date, 'Date to format');

  const text = date.toISOString().replace(/\.\d{3}Z$/u, 'Z');

  // toISOString writes years outside 0000-9999 as "+010000-..." or "-000001-...".
  // parseTimestamp rejects those, so a document signed with one could never be read back.
  if (!TIMESTAMP_PATTERN.test(text))
    throw new Error('Timestamp must fall between the years 0000 and 9999');

  return text;
}

/**
 * Reads a timestamp in the exact format formatTimestamp writes.
 * Dates that do not exist (2026-02-30, 24:00:00) are rejected.
 */
export function parseTimestamp(value: unknown, label: string): Date {
  if (typeof value !== 'string' || !TIMESTAMP_PATTERN.test(value))
    throw new Error(`${label} must be a UTC timestamp like 2026-10-09T12:00:00Z`);

  // Date quietly rolls impossible values over (2026-02-30 becomes March 2),
  // so the parsed date must format back to exactly the same text.
  const date = new Date(value);
  if (Number.isNaN(date.getTime()) || formatTimestamp(date) !== value)
    throw new Error(`${label} is not a valid timestamp`);

  return date;
}

/** Reads a duration such as 90d, 12h or 30m and returns it in milliseconds. */
export function parseDuration(value: string, label = 'duration'): number {
  // The type says string, but this is a public export: plain JavaScript callers can pass anything.
  const match = typeof value === 'string' ? DURATION_PATTERN.exec(value) : null;
  if (!match)
    throw new Error(`${label} must look like 90d, 12h or 30m`);

  const amount = Number(match[1]);
  if (amount < 1)
    throw new Error(`${label} must be positive`);

  // Five digits at most keeps the result (at most 8.64e12) well inside the safe integer range.
  const unit = match[2] as DurationUnit;
  return amount * UNIT_MS[unit];
}

/** Returns `start` plus a duration such as 90d, rounded down to a whole second. */
export function addDuration(start: Date, duration: string, label = 'duration'): Date {
  requireValidDate(start, `${label} start`);

  // Past the largest date JavaScript can hold (year 275760) the sum becomes an invalid Date.
  const end = new Date(start.getTime() + parseDuration(duration, label));
  requireValidDate(end, `${label} end`);

  return truncateToSecond(end);
}

/** Drops the milliseconds, so the date survives formatTimestamp and parseTimestamp unchanged. */
export function truncateToSecond(date: Date): Date {
  requireValidDate(date, 'Date to truncate');

  return new Date(Math.floor(date.getTime() / 1000) * 1000);
}
