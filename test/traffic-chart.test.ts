import './helpers/env.js';
// The dashboard chart must place each call by how long ago it happened and honour the selected range.
// `now` is a parameter so the boundaries can be pinned exactly. The server sends counts per slice of
// time; a 1 ms slice is a single instant, so most cases here place calls exactly.
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import {
  estimateClockOffsetMs,
  trafficBuckets,
  trafficChartSubtitle,
  type TrafficRange,
  type TrafficSeries,
} from '../src/components/views/trafficChart.js';
import type { McpTrafficSlice } from '../src/types/governance.js';

const NOW = Date.parse('2026-11-01T12:00:00.000Z');
const MIN = 60_000;
const HOUR = 60 * MIN;
const DAY = 24 * HOUR;

/** One call `ms` before NOW, as a 1 ms slice. */
const ago = (ms: number, status = 'ALLOWED'): McpTrafficSlice => ({
  start: NOW - ms,
  ok: status === 'ALLOWED' ? 1 : 0,
  warn: status === 'DENIED' ? 1 : 0,
  err: status === 'ERROR' ? 1 : 0,
});
const series = (slices: McpTrafficSlice[], sliceMs = 1): TrafficSeries => ({ sliceMs, slices });

/** Index, counted from the newest bucket, of each bucket holding calls. */
function filled(slices: McpTrafficSlice[], range: TrafficRange, sliceMs = 1): number[] {
  const buckets = trafficBuckets(series(slices, sliceMs), range, NOW);
  return buckets
    .map((b, i) => (b.ok + b.warn + b.err > 0 ? buckets.length - 1 - i : -1))
    .filter((i) => i >= 0)
    .reverse();
}

describe('bucket shape and labels', () => {
  test('1h is twelve 5-minute buckets, oldest first', () => {
    const buckets = trafficBuckets(series([]), '1h', NOW);
    assert.equal(buckets.length, 12);
    assert.equal(buckets[0].lbl, '-55m');
    assert.equal(buckets[10].lbl, '-5m');
    assert.equal(buckets[11].lbl, 'now');
    assert.equal(buckets[0].span, '55–60 min ago');
    assert.equal(buckets[11].span, '0–5 min ago');
  });

  test('24h labels are hours ago rather than clock hours', () => {
    const buckets = trafficBuckets(series([]), '24h', NOW);
    assert.equal(buckets.length, 24);
    assert.equal(buckets[0].lbl, '-23h');
    assert.equal(buckets[22].lbl, '-1h');
    assert.equal(buckets[23].lbl, 'now');
    assert.ok(buckets.every((b) => !b.lbl.includes(':')));
  });

  test('7d is seven daily buckets', () => {
    const buckets = trafficBuckets(series([]), '7d', NOW);
    assert.deepEqual(buckets.map((b) => b.lbl), ['-6d', '-5d', '-4d', '-3d', '-2d', '-1d', 'now']);
  });

  test('labels do not depend on the time of day', () => {
    const later = trafficBuckets(series([]), '24h', NOW + 7 * HOUR + 13 * MIN);
    assert.deepEqual(later, trafficBuckets(series([]), '24h', NOW));
  });

  test('no series yet draws the empty chart', () => {
    for (const missing of [null, undefined]) {
      assert.deepEqual(trafficBuckets(missing, '24h', NOW), trafficBuckets(series([]), '24h', NOW));
    }
  });
});

describe('bucket boundaries', () => {
  const cases: Array<[TrafficRange, number, number]> = [
    ['1h', 5 * MIN, 12],
    ['24h', HOUR, 24],
    ['7d', DAY, 7],
  ];

  for (const [range, size, count] of cases) {
    test(`${range}: a call right now is in the newest bucket`, () => {
      assert.deepEqual(filled([ago(0)], range), [0]);
    });

    test(`${range}: one ms before a bucket's edge stays newer, the edge itself is older`, () => {
      assert.deepEqual(filled([ago(size - 1)], range), [0]);
      assert.deepEqual(filled([ago(size)], range), [1]);
    });

    test(`${range}: the last ms of the window is in the oldest bucket`, () => {
      assert.deepEqual(filled([ago(size * count - 1)], range), [count - 1]);
    });

    test(`${range}: a call exactly at the window's edge or beyond is dropped`, () => {
      assert.deepEqual(filled([ago(size * count), ago(size * count + 1), ago(size * 500)], range), []);
    });
  }

  test('the range selector filters: a 3-hour-old call shows in 24h and 7d but not 1h', () => {
    const slices = [ago(3 * HOUR)];
    assert.deepEqual(filled(slices, '1h'), []);
    assert.deepEqual(filled(slices, '24h'), [3]);
    assert.deepEqual(filled(slices, '7d'), [0]);
  });

  test('a call eight days old shows nowhere', () => {
    for (const range of ['1h', '24h', '7d'] as const) {
      assert.deepEqual(filled([ago(8 * DAY)], range), []);
    }
  });

  test('counts in one slice add up in its bucket', () => {
    const buckets = trafficBuckets(series([{ start: NOW - 10 * MIN, ok: 3, warn: 2, err: 1 }]), '1h', NOW);
    assert.deepEqual([buckets.at(-3)?.ok, buckets.at(-3)?.warn, buckets.at(-3)?.err], [3, 2, 1]);
  });
});

describe('slices the size the server sends', () => {
  test('a slice is placed by its newest instant: calls show at most one slice newer, never older', () => {
    // A 5-minute slice from 65 to 60 minutes ago: its last instant falls in the 24h chart's 1–2 h bucket.
    const slice = { start: NOW - 65 * MIN, ok: 4, warn: 0, err: 0 };
    assert.deepEqual(filled([slice], '24h', 5 * MIN), [1]);
    // Its last instant is 60 min + 1 ms ago, so the 1h chart leaves it out as just past the window.
    assert.deepEqual(filled([slice], '1h', 5 * MIN), []);
  });

  test('a slice ending just inside the window shows in the oldest bucket', () => {
    const slice = { start: NOW - HOUR - 30_000, ok: 1, warn: 0, err: 0 };
    assert.deepEqual(filled([slice], '1h', MIN), [11]);
  });

  test('a whole day of hourly slices fills the 24h chart the 150-row list could not', () => {
    const slices = Array.from({ length: 24 }, (_, h) => ({ start: NOW - (h + 1) * HOUR, ok: 100, warn: 10, err: 1 }));
    const buckets = trafficBuckets(series(slices, HOUR), '24h', NOW);
    assert.ok(buckets.every((b) => b.ok === 100 && b.warn === 10 && b.err === 1));
  });

  test('a slice the clock has not reached yet counts as now', () => {
    assert.deepEqual(filled([{ start: NOW + 2 * MIN, ok: 1, warn: 0, err: 0 }], '1h', MIN), [0]);
  });

  test('bars age as the clock moves, with no new data', () => {
    const slices = series([{ start: NOW - MIN, ok: 1, warn: 0, err: 0 }], MIN);
    const index = (now: number) => {
      const buckets = trafficBuckets(slices, '24h', now);
      return buckets.length - 1 - buckets.findIndex((b) => b.ok === 1);
    };
    assert.equal(index(NOW), 0);
    assert.equal(index(NOW + 3 * HOUR), 3);
  });

  test('a slice with an unreadable start is dropped, not scattered', () => {
    assert.deepEqual(filled([{ start: Number.NaN, ok: 1, warn: 0, err: 0 }], '7d'), []);
  });
});

describe('what is counted', () => {
  test('statuses map to their segments', () => {
    const newest = trafficBuckets(series([ago(1), ago(2), ago(3, 'DENIED'), ago(4, 'ERROR')]), '1h', NOW).at(-1);
    assert.deepEqual([newest?.ok, newest?.warn, newest?.err], [2, 1, 1]);
  });
});

describe('estimateClockOffsetMs', () => {
  const at = (ms: number) => new Date(ms).toISOString();

  test('is zero when both clocks agree, measured at the middle of the request', () => {
    assert.equal(estimateClockOffsetMs(at(NOW), NOW - 200, NOW + 200), 0);
  });

  test('is positive for a slow browser and negative for a fast one', () => {
    assert.equal(estimateClockOffsetMs(at(NOW), NOW - 2 * MIN - 100, NOW - 2 * MIN + 100), 2 * MIN);
    assert.equal(estimateClockOffsetMs(at(NOW), NOW + 2 * HOUR - 100, NOW + 2 * HOUR + 100), -2 * HOUR);
  });

  test('an absent or unreadable server time leaves the browser clock alone', () => {
    for (const value of [undefined, null, '', 'not a date', 1_700_000_000_000]) {
      assert.equal(estimateClockOffsetMs(value, NOW, NOW + 100), 0);
    }
  });

  for (const [name, skew] of [['slow', -2 * MIN], ['fast', 2 * HOUR]] as const) {
    test(`a browser clock this ${name} still places a 5-second-old call in the newest bucket`, () => {
      const browserNow = NOW + skew;
      const offset = estimateClockOffsetMs(at(NOW), browserNow, browserNow);
      const newest = trafficBuckets(series([ago(5000)]), '1h', browserNow + offset).at(-1);
      assert.equal(newest?.ok, 1);
    });
  }
});

describe('trafficChartSubtitle', () => {
  test('says how many calls the window holds', () => {
    assert.equal(trafficChartSubtitle('24h', 2410), 'Requests per hour by policy outcome, 2410 in the last 24 hours');
  });

  test('names the bucket size and window of each range', () => {
    assert.equal(trafficChartSubtitle('1h', 2), 'Requests per 5 minutes by policy outcome, 2 in the last hour');
    assert.equal(trafficChartSubtitle('7d', 2), 'Requests per day by policy outcome, 2 in the last 7 days');
  });

  test('an empty window reads as quiet, not as missing data', () => {
    assert.equal(trafficChartSubtitle('24h', 0), 'Requests per hour by policy outcome, none in the last 24 hours');
  });
});
