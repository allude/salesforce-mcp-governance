import './helpers/env.js';
// The shell's refresh loop (poller.ts) and its freshness chip (freshness.ts), with fake timers.
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { createPoller } from '../src/components/shell/poller.js';
import { freshness, sessionTimeLeft, updatedAgo } from '../src/components/shell/freshness.js';

function fakeTimers() {
  let seq = 0;
  const timers = new Map<number, { fn: () => void; ms: number }>();
  return {
    setTimer: (fn: () => void, ms: number) => {
      const id = ++seq;
      timers.set(id, { fn, ms });
      return id;
    },
    clearTimer: (h: unknown) => void timers.delete(h as number),
    fire() {
      const [id, t] = [...timers.entries()][0] ?? [];
      if (id === undefined) return false;
      timers.delete(id);
      t!.fn();
      return true;
    },
    get pending() {
      return timers.size;
    },
  };
}

const flush = () => new Promise((r) => setImmediate(r));

describe('createPoller', () => {
  test('runs at start, then on each tick; reports successes and failures', async () => {
    const t = fakeTimers();
    const results: boolean[] = [];
    let fail = false;
    const p = createPoller({
      intervalMs: 5000,
      run: async () => {
        if (fail) throw new Error('down');
      },
      onResult: (r) => results.push(r.ok),
      isHidden: () => false,
      ...t,
    });
    p.start();
    await flush();
    assert.deepEqual(results, [true]);
    assert.equal(t.pending, 1);
    fail = true;
    t.fire();
    await flush();
    assert.deepEqual(results, [true, false]);
    p.stop();
    assert.equal(t.pending, 0);
  });

  test('single flight: a refresh while one runs joins it instead of stacking', async () => {
    const t = fakeTimers();
    let runs = 0;
    let release!: () => void;
    const p = createPoller({
      intervalMs: 5000,
      run: () => {
        runs++;
        return new Promise<void>((r) => (release = r));
      },
      onResult: () => undefined,
      isHidden: () => false,
      ...t,
    });
    p.start();
    void p.refresh();
    void p.refresh();
    assert.equal(runs, 1);
    release();
    await flush();
    p.stop();
  });

  test('a hidden tab stops polling and aborts the run; visible again refreshes at once', async () => {
    const t = fakeTimers();
    let hidden = false;
    let runs = 0;
    const signals: AbortSignal[] = [];
    const reported: boolean[] = [];
    let release!: () => void;
    const p = createPoller({
      intervalMs: 5000,
      run: (signal) => {
        runs++;
        signals.push(signal);
        return new Promise<void>((r) => (release = r));
      },
      onResult: (r) => reported.push(r.ok),
      isHidden: () => hidden,
      ...t,
    });
    p.start();
    hidden = true;
    p.visibilityChanged();
    assert.equal(signals[0].aborted, true);
    release();
    await flush();
    assert.deepEqual(reported, [], 'an aborted run cannot report');
    assert.equal(t.pending, 0, 'no timer while hidden');
    hidden = false;
    p.visibilityChanged();
    assert.equal(runs, 2);
    release();
    await flush();
    assert.deepEqual(reported, [true]);
    p.stop();
  });
});

describe('freshness', () => {
  const now = 1_000_000;
  test('live, paused, connecting, and degraded after a failure (amber, the error tone)', () => {
    assert.equal(freshness({ live: true, lastOkAt: now - 4000, failures: 0, now }).label, 'Live');
    assert.equal(freshness({ live: true, lastOkAt: now - 4000, failures: 0, now }).tone, 'allowed');
    assert.equal(freshness({ live: false, lastOkAt: now, failures: 0, now }).state, 'paused');
    assert.equal(freshness({ live: false, lastOkAt: now, failures: 0, now }).tone, 'neutral');
    assert.equal(freshness({ live: true, lastOkAt: null, failures: 0, now }).state, 'connecting');
    const degraded = freshness({ live: true, lastOkAt: now - 9000, failures: 1, now });
    assert.equal(degraded.state, 'degraded');
    assert.equal(degraded.tone, 'error');
  });

  test('"Updated" and the session chip', () => {
    assert.equal(updatedAgo(now - 4200, now), 'Updated 4s ago');
    assert.equal(updatedAgo(now - 125_000, now), 'Updated 2 min ago');
    assert.equal(updatedAgo(null, now), 'Not updated yet');
    const iso = new Date(Date.UTC(2026, 0, 1, 8, 0)).toISOString();
    assert.equal(sessionTimeLeft(iso, Date.UTC(2026, 0, 1, 1, 18)), 'Session 6:42 left');
    assert.equal(sessionTimeLeft(iso, Date.UTC(2026, 0, 1, 9, 0)), 'Session ending');
    assert.equal(sessionTimeLeft(null, now), null);
  });
});
