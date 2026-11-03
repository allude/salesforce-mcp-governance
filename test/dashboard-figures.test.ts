import './helpers/env.js';
// The dashboard KPIs must say what their labels say. The success rate is measured against errors
// only: a policy denial is the access matrix working, and has its own KPI.
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { SUCCESS_RATE_TARGET, activityWindowLabel, successRate } from '../src/components/views/dashboardFigures.js';
import { formatShortTime } from '../src/components/ui/primitives.js';
import type { McpActivityFigures } from '../src/types/governance.js';
import { TrafficDashboardView, type McpRequestStats } from '../src/components/views/DashboardAndLogsViews.js';

describe('successRate', () => {
  test('denials do not lower it: 10% denied and 1% errors is 99.0%', () => {
    assert.deepEqual(successRate(1000, 10), { label: '99.0', meetsTarget: true });
  });

  test('errors below the target fail it', () => {
    assert.deepEqual(successRate(100, 3), { label: '97.0', meetsTarget: false });
  });

  test('exactly the target meets it', () => {
    assert.equal(SUCCESS_RATE_TARGET, 98);
    assert.equal(successRate(100, 2).meetsTarget, true);
  });

  test('a rate just short of the target never reads as meeting it: 97.96% shows as 97.9', () => {
    assert.deepEqual(successRate(4901, 100), { label: '97.9', meetsTarget: false });
    assert.deepEqual(successRate(49, 1), { label: '97.9', meetsTarget: false });
  });

  test('the target is judged on the counts, and the label rounds down', () => {
    for (const [total, errors] of [[100, 2], [50, 1], [1000, 20], [7, 0], [3, 1]] as const) {
      const exact = ((total - errors) * 100) / total;
      assert.equal(successRate(total, errors).meetsTarget, exact >= 98, `${total}/${errors}`);
    }
    assert.equal(successRate(50, 1).label, '98.0');
    assert.equal(successRate(3, 1).label, '66.6');
  });

  test('no calls is 100% and meets the target', () => {
    assert.deepEqual(successRate(0, 0), { label: '100.0', meetsTarget: true });
  });
});

describe('Success rate KPI', () => {
  const render = (stats: McpRequestStats) =>
    renderToStaticMarkup(
      createElement(TrafficDashboardView, {
        clockNow: Date.parse('2026-11-01T12:00:00.000Z'),
        clockOffsetMs: 0,
        mcpStats: stats,
        copilotLogs: [],
        portalLogs: [],
        profiles: [],
        objects: [],
        groups: [],
        onNavigateTab: () => {},
        onOpenFlyout: () => {},
      })
    );
  const kpi = (html: string) => html.slice(html.indexOf('Success rate'), html.indexOf('Policy denials'));

  test('a 9.4% denial rate with 1.1% errors reads 98.9% and passes', () => {
    const html = kpi(
      render({ totalMcpRequests: 9857, allowedMcpRequests: 8824, deniedMcpRequests: 928, erroredMcpRequests: 105, lastMcpCallAt: null })
    );
    assert.match(html, />98\.9%</);
    assert.match(html, /class="dot ok"/);
    assert.match(html, /105 errors/);
    assert.doesNotMatch(html, /transport errors/);
  });

  test('an error rate over 2% turns the dot red', () => {
    const html = kpi(
      render({ totalMcpRequests: 100, allowedMcpRequests: 95, deniedMcpRequests: 0, erroredMcpRequests: 5, lastMcpCallAt: null })
    );
    assert.match(html, />95\.0%</);
    assert.match(html, /class="dot err"/);
  });
});

describe('activityWindowLabel', () => {
  // Local noon, so the same-day cases hold in any time zone.
  const at = new Date(2026, 10, 1, 12, 0, 0).getTime();
  const asOf = new Date(at).toISOString();
  const figures = { windowHours: 24, asOf } as McpActivityFigures;

  test('fresh figures cover the last 24 h', () => {
    assert.equal(activityWindowLabel(figures, at), 'last 24 h');
    assert.equal(activityWindowLabel(figures, at + 2 * 60_000 - 1), 'last 24 h');
  });

  test('figures two minutes old or more say when their window ended', () => {
    assert.equal(activityWindowLabel(figures, at + 2 * 60_000), `24 h to ${formatShortTime(asOf)}`);
    assert.equal(activityWindowLabel(figures, at + 11 * 3_600_000), `24 h to ${formatShortTime(asOf)}`);
  });

  test('figures from an earlier day say which day', () => {
    const day = new Date(at).toLocaleDateString([], { month: 'short', day: 'numeric' });
    assert.equal(activityWindowLabel(figures, at + 13 * 3_600_000), `24 h to ${day} ${formatShortTime(asOf)}`);
    assert.equal(activityWindowLabel(figures, at + 3 * 86_400_000), `24 h to ${day} ${formatShortTime(asOf)}`);
  });

  test('with no figures, or an unreadable time, it falls back to the window alone', () => {
    assert.equal(activityWindowLabel(null, at), 'last 24 h');
    assert.equal(activityWindowLabel({ ...figures, asOf: 'nope' }, at + 86_400_000), 'last 24 h');
  });
});
