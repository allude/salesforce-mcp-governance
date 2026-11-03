import './helpers/env.js';
// The dashboard KPIs must say what their labels say. The success rate is measured against errors
// only: a policy denial is the access matrix working, and has its own KPI.
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { SUCCESS_RATE_TARGET, successRate } from '../src/components/views/dashboardFigures.js';
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

  test('the target is judged before rounding: 97.96% shows as 98.0 but misses', () => {
    assert.deepEqual(successRate(10_000, 204), { label: '98.0', meetsTarget: false });
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
