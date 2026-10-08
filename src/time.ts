const TIMESTAMP_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/u;

/** Allowed clock skew when checking that a signed object was not issued in the future. */
export const CLOCK_SKEW_MS = 5 * 60 * 1000;

/** UTC timestamp with second precision, e.g. 2026-10-09T12:00:00Z. */
export function formatTimestamp(date: Date): string {
  return date.toISOString().replace(/\.\d{3}Z$/u, 'Z');
}

export function parseTimestamp(value: unknown, label: string): Date {
  if (typeof value !== 'string' || !TIMESTAMP_PATTERN.test(value)) throw new Error(`${label} must be a UTC timestamp like 2026-10-09T12:00:00Z`);
  const date = new Date(value);
  if (Number.isNaN(date.getTime()) || formatTimestamp(date) !== value) throw new Error(`${label} is not a valid timestamp`);
  return date;
}

/** Parses durations like 90d, 12h, 30m. */
export function parseDuration(value: string, label = 'duration'): number {
  const match = /^(\d{1,5})([dhm])$/u.exec(value);
  if (!match) throw new Error(`${label} must look like 90d, 12h or 30m`);
  const amount = Number(match[1]);
  if (amount < 1) throw new Error(`${label} must be positive`);
  const unit = match[2] === 'd' ? 86_400_000 : match[2] === 'h' ? 3_600_000 : 60_000;
  return amount * unit;
}

export function addDuration(now: Date, duration: string, label?: string): Date {
  return new Date(Math.floor((now.getTime() + parseDuration(duration, label)) / 1000) * 1000);
}

export function truncateToSecond(date: Date): Date {
  return new Date(Math.floor(date.getTime() / 1000) * 1000);
}
