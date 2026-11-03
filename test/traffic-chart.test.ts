import './helpers/env.js';
// The dashboard chart must place each call by how long ago it happened, honour the selected range
// and leave simulator rows out. `now` is a parameter so the boundaries can be pinned exactly.
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { estimateClockOffsetMs, trafficBuckets, trafficChartSubtitle, type TrafficRange } from '../src/components/views/trafficChart.js';

const NOW = Date.parse('2026-11-01T12:00:00.000Z');
const MIN = 60_000;
const HOUR = 60 * MIN;
const DAY = 24 * HOUR;

const ago = (ms: number, status = 'ALLOWED', simulated?: boolean) => ({
  timestamp: new Date(NOW - ms).toISOString(),
  status,
  ...(simulated ? { simulated } : {}),
});

/** Index, counted from the newest bucket, of each bucket holding calls. */
function filled(rows: Parameters<typeof trafficBuckets>[0], range: TrafficRange): number[] {
  const buckets = trafficBuckets(rows, range, NOW);
  return buckets
    .map((b, i) => (b.ok + b.warn + b.err > 0 ? buckets.length - 1 - i : -1))
    .filter((i) => i >= 0)
    .reverse();
}

describe('bucket shape and labels', () => {
  test('1h is twelve 5-minute buckets, oldest first', () => {
    const buckets = trafficBuckets([], '1h', NOW);
    assert.equal(buckets.length, 12);
    assert.equal(buckets[0].lbl, '-55m');
    assert.equal(buckets[10].lbl, '-5m');
    assert.equal(buckets[11].lbl, 'now');
    assert.equal(buckets[0].span, '55–60 min ago');
    assert.equal(buckets[11].span, '0–5 min ago');
  });

  test('24h labels are hours ago rather than clock hours', () => {
    const buckets = trafficBuckets([], '24h', NOW);
    assert.equal(buckets.length, 24);
    assert.equal(buckets[0].lbl, '-23h');
    assert.equal(buckets[22].lbl, '-1h');
    assert.equal(buckets[23].lbl, 'now');
    assert.ok(buckets.every((b) => !b.lbl.includes(':')));
  });

  test('7d is seven daily buckets', () => {
    const buckets = trafficBuckets([], '7d', NOW);
    assert.deepEqual(buckets.map((b) => b.lbl), ['-6d', '-5d', '-4d', '-3d', '-2d', '-1d', 'now']);
  });

  test('labels do not depend on the time of day', () => {
    const later = trafficBuckets([], '24h', NOW + 7 * HOUR + 13 * MIN);
    assert.deepEqual(later, trafficBuckets([], '24h', NOW));
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
    const rows = [ago(3 * HOUR)];
    assert.deepEqual(filled(rows, '1h'), []);
    assert.deepEqual(filled(rows, '24h'), [3]);
    assert.deepEqual(filled(rows, '7d'), [0]);
  });

  test('a call eight days old shows nowhere', () => {
    for (const range of ['1h', '24h', '7d'] as const) {
      assert.deepEqual(filled([ago(8 * DAY)], range), []);
    }
  });

  test('a row keeps its bucket wherever it sits in the list', () => {
    const rows = [ago(10 * MIN), ago(10 * MIN), ago(10 * MIN)];
    const buckets = trafficBuckets(rows, '1h', NOW);
    assert.equal(buckets[buckets.length - 3].ok, 3);
  });
});

describe('rows that cannot be placed', () => {
  test('invalid timestamps are dropped, not scattered', () => {
    for (const timestamp of ['', 'not a date', '2026-13-45T99:00:00Z']) {
      assert.deepEqual(filled([{ timestamp, status: 'ALLOWED' }], '7d'), []);
    }
  });

  test('a timestamp just ahead of the browser clock counts as now', () => {
    assert.deepEqual(filled([ago(-MIN)], '1h'), [0]);
  });

  test('a timestamp further in the future is clamped into the newest bucket, not dropped', () => {
    assert.deepEqual(filled([ago(-MIN - 1)], '1h'), [0]);
    assert.deepEqual(filled([ago(-DAY)], '7d'), [0]);
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
      const newest = trafficBuckets([ago(5000)], '1h', browserNow + offset).at(-1);
      assert.equal(newest?.ok, 1);
    });
  }
});

describe('what is counted', () => {
  test('simulated rows are left out', () => {
    assert.deepEqual(filled([ago(MIN, 'ALLOWED', true), ago(MIN, 'DENIED', true)], '1h'), []);
  });

  test('a real row beside a simulated one is still counted', () => {
    const newest = trafficBuckets([ago(MIN, 'ALLOWED', true), ago(MIN, 'DENIED')], '1h', NOW).at(-1);
    assert.deepEqual([newest?.ok, newest?.warn, newest?.err], [0, 1, 0]);
  });

  test('statuses map to their segments', () => {
    const newest = trafficBuckets([ago(1), ago(2), ago(3, 'DENIED'), ago(4, 'ERROR')], '1h', NOW).at(-1);
    assert.deepEqual([newest?.ok, newest?.warn, newest?.err], [2, 1, 1]);
  });
});

describe('trafficChartSubtitle', () => {
  test('discloses that the chart reads a capped list', () => {
    assert.equal(
      trafficChartSubtitle('24h', 150),
      'Requests per hour by policy outcome, based on the latest 150 real calls'
    );
  });

  test('names the bucket size of each range', () => {
    assert.match(trafficChartSubtitle('1h', 2), /^Requests per 5 minutes /);
    assert.match(trafficChartSubtitle('7d', 2), /^Requests per day /);
  });

  test('handles one call and none', () => {
    assert.match(trafficChartSubtitle('24h', 1), /based on the latest real call$/);
    assert.match(trafficChartSubtitle('24h', 0), /no real calls to show$/);
  });
});
