import type { McpTrafficRange, McpTrafficSlice } from '@/types/governance';

export type TrafficRange = McpTrafficRange;

const MINUTE_MS = 60_000;
const HOUR_MS = 60 * MINUTE_MS;
const DAY_MS = 24 * HOUR_MS;

const RANGES: Record<
  TrafficRange,
  { count: number; step: number; unitMs: number; suffix: string; unit: string; per: string; window: string }
> = {
  '1h': { count: 12, step: 5, unitMs: MINUTE_MS, suffix: 'm', unit: 'min', per: '5 minutes', window: 'hour' },
  '24h': { count: 24, step: 1, unitMs: HOUR_MS, suffix: 'h', unit: 'h', per: 'hour', window: '24 hours' },
  '7d': { count: 7, step: 1, unitMs: DAY_MS, suffix: 'd', unit: 'd', per: 'day', window: '7 days' },
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

/** One range's counts as /overview sends them: fixed slices of `sliceMs`, oldest first. */
export interface TrafficSeries {
  sliceMs: number;
  slices: McpTrafficSlice[];
}

/**
 * How far the server's clock is ahead of the browser's, to add to a browser time. Log timestamps come
 * from the server. The server's reading is taken as the request's midpoint, which is off by at most
 * half the round trip. An unreadable reading gives 0, leaving the browser's clock in charge.
 */
export function estimateClockOffsetMs(serverTime: unknown, sentAt: number, receivedAt: number): number {
  const time = typeof serverTime === 'string' ? Date.parse(serverTime) : NaN;
  if (Number.isNaN(time)) return 0;
  return time - (sentAt + receivedAt) / 2;
}

/**
 * Buckets, oldest first, each holding the calls made that long before `now`, which should be on the
 * server's clock. A bucket covers [k, k + 1) bucket sizes ago. The server counts calls in slices
 * smaller than a bucket; a slice is placed by its newest instant, so a call can show up to one slice
 * newer than it is, never older. A slice ahead of `now` counts in the newest bucket, as the header pill
 * clamps it, because leftover skew must not hide the newest calls. Slices at or beyond the window's
 * edge are left out. Placing them here rather than on the server keeps the bars ageing between polls.
 */
export function trafficBuckets(series: TrafficSeries | null | undefined, range: TrafficRange, now: number): TrafficBucket[] {
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

  if (!series) return buckets;
  for (const slice of series.slices) {
    const newest = slice.start + series.sliceMs - 1;
    if (!Number.isFinite(newest)) continue;
    const ago = Math.floor(Math.max(now - newest, 0) / sizeMs);
    if (ago >= count) continue;
    const bucket = buckets[count - 1 - ago];
    bucket.ok += slice.ok;
    bucket.warn += slice.warn;
    bucket.err += slice.err;
  }

  return buckets;
}

/** Says how many calls the bars hold, so an empty chart reads as a quiet window, not missing data. */
export function trafficChartSubtitle(range: TrafficRange, callsInWindow: number): string {
  const { per, window } = RANGES[range];
  const base = `Requests per ${per} by policy outcome`;
  if (callsInWindow === 0) return `${base}, none in the last ${window}`;
  return `${base}, ${callsInWindow} in the last ${window}`;
}
