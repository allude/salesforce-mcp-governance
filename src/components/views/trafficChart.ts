import { realTraffic } from './simulatedTraffic';

export type TrafficRange = '1h' | '24h' | '7d';

const MINUTE_MS = 60_000;
const HOUR_MS = 60 * MINUTE_MS;
const DAY_MS = 24 * HOUR_MS;

/** A browser clock slightly behind the server must not lose the newest calls. */
const CLOCK_SKEW_TOLERANCE_MS = MINUTE_MS;

const RANGES: Record<
  TrafficRange,
  { count: number; step: number; unitMs: number; suffix: string; unit: string; per: string }
> = {
  '1h': { count: 12, step: 5, unitMs: MINUTE_MS, suffix: 'm', unit: 'min', per: '5 minutes' },
  '24h': { count: 24, step: 1, unitMs: HOUR_MS, suffix: 'h', unit: 'h', per: 'hour' },
  '7d': { count: 7, step: 1, unitMs: DAY_MS, suffix: 'd', unit: 'd', per: 'day' },
};

export interface TrafficBucket {
  /** Axis label, relative to now: the newest bucket is 'now', then -5m, -3h, -2d. */
  lbl: string;
  /** The span the bucket covers, for its tooltip. */
  span: string;
  ok: number;
  warn: number;
  err: number;
}

interface TrafficRow {
  timestamp: string;
  status: string;
  simulated?: boolean;
}

/**
 * Buckets, oldest first, each holding the real calls made that long before `now`. A bucket covers
 * [k, k + 1) bucket sizes ago, and calls at or beyond the window's edge or with an unreadable
 * timestamp are left out.
 */
export function trafficBuckets(rows: TrafficRow[], range: TrafficRange, now: number): TrafficBucket[] {
  const { count, step, unitMs, suffix, unit } = RANGES[range];
  const sizeMs = step * unitMs;

  const buckets = Array.from({ length: count }, (_, idx): TrafficBucket => {
    const ago = count - 1 - idx;
    const from = ago * step;
    return {
      lbl: ago === 0 ? 'now' : `-${from}${suffix}`,
      span: `${from}–${from + step} ${unit} ago`,
      ok: 0,
      warn: 0,
      err: 0,
    };
  });

  for (const row of realTraffic(rows)) {
    const time = Date.parse(row.timestamp);
    if (Number.isNaN(time)) continue;
    const age = now - time;
    if (age < -CLOCK_SKEW_TOLERANCE_MS) continue;
    const ago = Math.floor(Math.max(age, 0) / sizeMs);
    if (ago >= count) continue;
    const bucket = buckets[count - 1 - ago];
    if (row.status === 'ALLOWED') bucket.ok += 1;
    else if (row.status === 'DENIED') bucket.warn += 1;
    else bucket.err += 1;
  }

  return buckets;
}

/** The chart reads the capped log list, not all history, so the subtitle has to say so. */
export function trafficChartSubtitle(range: TrafficRange, realCallCount: number): string {
  const base = `Requests per ${RANGES[range].per} by policy outcome`;
  if (realCallCount === 0) return `${base}, no real calls to show`;
  const latest = realCallCount === 1 ? 'latest real call' : `latest ${realCallCount} real calls`;
  return `${base}, based on the ${latest}`;
}
