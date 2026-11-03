import './helpers/env.js';
// The chart must take its 'now' from the clock it is given, so bars keep ageing while the live
// refresh is paused and agree with the header pill. Rendered to markup to exercise the real view.
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { TrafficDashboardView } from '../src/components/views/DashboardAndLogsViews.js';
import type { CopilotMcpLogEntry, McpTrafficSeries } from '../src/types/governance.js';

const NOW = Date.parse('2026-11-01T12:00:00.000Z');
const HOUR = 3_600_000;
const FIVE_MIN = 300_000;

const call: CopilotMcpLogEntry = {
  id: 'mcp_1',
  timestamp: new Date(NOW - 1000).toISOString(),
  sfUsername: 'real.user@acme.com',
  profileId: '00e000000000001',
  profileName: 'P',
  matchedGroups: [],
  toolName: 'soql_query',
  targetObject: 'Account',
  status: 'ALLOWED',
  latencyMs: 1,
  sanitizedRequestPayload: '{}',
  sanitizedResponseSummary: '{}',
};

// That call as the server counts it: one ALLOWED in the 5-minute slice ending at NOW.
const oneCall = { ok: 1, warn: 0, err: 0 };
const traffic: McpTrafficSeries = {
  '1h': { sliceMs: 60_000, slices: [{ start: NOW - 60_000, ...oneCall }] },
  '24h': { sliceMs: FIVE_MIN, slices: [{ start: NOW - FIVE_MIN, ...oneCall }] },
  '7d': { sliceMs: HOUR, slices: [{ start: NOW - HOUR, ...oneCall }] },
};

const render = (clockNow: number, clockOffsetMs = 0, mcpTraffic: McpTrafficSeries | null = traffic) =>
  renderToStaticMarkup(
    createElement(TrafficDashboardView, {
      clockNow,
      clockOffsetMs,
      mcpTraffic,
      copilotLogs: [call],
      portalLogs: [],
      profiles: [],
      objects: [],
      groups: [],
      onNavigateTab: () => {},
      onOpenFlyout: () => {},
    })
  );

describe('TrafficDashboardView clock', () => {
  test('places a call relative to the clockNow prop', () => {
    assert.ok(render(NOW).includes('0–1 h ago — 1 allowed'));
    assert.ok(render(NOW + 3 * HOUR).includes('3–4 h ago — 1 allowed'));
  });

  test('reads the clock on the server: a browser 3 hours fast still shows a new call as new', () => {
    assert.ok(render(NOW + 3 * HOUR, -3 * HOUR).includes('0–1 h ago — 1 allowed'));
  });

  test('a call that has aged out of the window leaves the chart', () => {
    assert.ok(!render(NOW + 25 * HOUR).includes('— 1 allowed'));
  });
});

describe('TrafficDashboardView chart data', () => {
  test('the bars and subtitle come from the server counts, not the capped list', () => {
    const html = render(NOW);
    assert.ok(html.includes('Requests per hour by policy outcome, 1 in the last 24 hours'));
  });

  test('before the server answers, the chart is empty even with rows in the list', () => {
    const html = render(NOW, 0, null);
    assert.ok(!html.includes('— 1 allowed'));
    assert.ok(html.includes('none in the last 24 hours'));
  });
});
