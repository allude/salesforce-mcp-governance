import './helpers/env.js';
// The dashboard's activity figures (top tools, top users, active users, latency) must describe the
// verified calls of the last 24 hours. They used to be read from the /overview list, which holds the
// newest 150 verified calls beside the newest 50 rejected tokens, so a quiet hour of rejected tokens
// outranked a busy hour of real users, and anything older than the newest 150 calls vanished.
import { after, afterEach, before, describe, mock, test } from 'node:test';
import assert from 'node:assert/strict';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { store, UNVERIFIED_CALLER_USERNAME } from '../src/db/store.js';
import { TrafficDashboardView } from '../src/components/views/DashboardAndLogsViews.js';
import type { CopilotMcpLogEntry, McpActivityFigures } from '../src/types/governance.js';
import { startTestServer, loginAsAdmin, adminFetch, type AdminSession, type TestServer } from './helpers/server.js';

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;
// Each test writes at its own time, 10 days after the last, so no test sees another's rows.
const BASE = Date.parse('2026-01-01T00:00:00.000Z');
let slot = 0;
/** Moves the clock to a fresh slot and returns it. Rows written now are stamped with it. */
function freshSlot(): number {
  const now = BASE + 10 * DAY * slot++;
  mock.timers.enable({ apis: ['Date'], now });
  return now;
}
const setClock = (now: number) => mock.timers.setTime(now);

afterEach(() => mock.timers.reset());

function logCall(
  sfUsername: string,
  opts: { toolName?: string; status?: 'ALLOWED' | 'DENIED' | 'ERROR'; latencyMs?: number; profileName?: string; simulated?: boolean } = {}
) {
  return store.recordCopilotMcpLog({
    sfUsername,
    profileId: `00e${(opts.profileName ?? 'Sales').padEnd(12, '0').slice(0, 12)}`,
    profileName: opts.profileName ?? 'Sales',
    matchedGroups: [],
    toolName: opts.toolName ?? 'soql_query',
    targetObject: 'Account',
    status: opts.status ?? 'ALLOWED',
    latencyMs: opts.latencyMs ?? 100,
    rawRequestPayload: {},
    rawResponseSummary: {},
    simulated: opts.simulated,
  });
}

// The same fields /mcp writes when a bearer token fails verification.
const logRejectedToken = () =>
  store.recordCopilotMcpLog({
    sfUsername: UNVERIFIED_CALLER_USERNAME,
    profileId: 'unverified',
    profileName: 'Unverified Token',
    matchedGroups: [],
    toolName: 'mcp_authenticate',
    targetObject: '*',
    status: 'DENIED',
    latencyMs: 1,
    rawRequestPayload: { method: 'tools/call' },
    rawResponseSummary: { error: 'Salesforce token verification failed (HTTP 401)' },
  });

describe('getCopilotMcpActivityFigures', () => {
  test('rejected tokens never rank as a user or a tool, nor count as activity', () => {
    const now = freshSlot();
    logCall('maya@acme.com');
    logCall('maya@acme.com', { toolName: 'get_record' });
    logCall('omar@acme.com');
    for (let i = 0; i < 60; i++) logRejectedToken();

    const figures = store.getCopilotMcpActivityFigures(now);
    assert.equal(figures.verifiedCalls, 3);
    assert.equal(figures.activeUsers, 2);
    assert.deepEqual(figures.topUsers.map((u) => u.username), ['maya@acme.com', 'omar@acme.com']);
    assert.deepEqual(figures.topTools, [
      { toolName: 'soql_query', calls: 2 },
      { toolName: 'get_record', calls: 1 },
    ]);
  });

  test('rankings count the whole window, not the newest 150 calls', () => {
    const now = freshSlot();
    for (let i = 0; i < 200; i++) logCall('busy.morning@acme.com', { toolName: 'soql_query' });
    setClock(now + HOUR);
    for (let i = 0; i < 160; i++) logCall('busy.afternoon@acme.com', { toolName: 'get_record' });

    const figures = store.getCopilotMcpActivityFigures(now + HOUR);
    assert.equal(figures.verifiedCalls, 360);
    assert.deepEqual(figures.topUsers, [
      { username: 'busy.morning@acme.com', profileName: 'Sales', calls: 200 },
      { username: 'busy.afternoon@acme.com', profileName: 'Sales', calls: 160 },
    ]);
    assert.deepEqual(figures.topTools.map((t) => [t.toolName, t.calls]), [
      ['soql_query', 200],
      ['get_record', 160],
    ]);
  });

  test('the window is the 24 hours before now', () => {
    const now = freshSlot();
    logCall('early@acme.com');
    assert.equal(store.getCopilotMcpActivityFigures(now + DAY).verifiedCalls, 1, 'exactly 24 h old is in');
    assert.equal(store.getCopilotMcpActivityFigures(now + DAY + 1).verifiedCalls, 0, 'older is out');
    assert.equal(store.getCopilotMcpActivityFigures(now + DAY + 1).topUsers.length, 0);
  });

  test('simulator rows are left out', () => {
    const now = freshSlot();
    logCall('real@acme.com');
    for (let i = 0; i < 5; i++) logCall('simulated:test-user', { simulated: true });

    const figures = store.getCopilotMcpActivityFigures(now);
    assert.equal(figures.verifiedCalls, 1);
    assert.deepEqual(figures.topUsers.map((u) => u.username), ['real@acme.com']);
  });

  test('p95 and average latency are over verified calls only', () => {
    const now = freshSlot();
    for (let ms = 1; ms <= 100; ms++) logCall('latency@acme.com', { latencyMs: ms });
    // 1 ms rejections would pull a mixed p95 down.
    for (let i = 0; i < 50; i++) logRejectedToken();

    const figures = store.getCopilotMcpActivityFigures(now);
    assert.equal(figures.p95LatencyMs, 96, 'nearest rank: the value at floor(100 * 0.95)');
    assert.equal(figures.avgLatencyMs, 51, '50.5 rounds up');
  });

  test('a user ranks under the Profile of their latest call', () => {
    const now = freshSlot();
    logCall('mover@acme.com', { profileName: 'Support' });
    logCall('mover@acme.com', { profileName: 'Support' });
    setClock(now + 1000);
    logCall('mover@acme.com', { profileName: 'Sales' });

    const [user] = store.getCopilotMcpActivityFigures(now + 1000).topUsers;
    assert.deepEqual(user, { username: 'mover@acme.com', profileName: 'Sales', calls: 3 });
    assert.equal(store.getCopilotMcpActivityFigures(now + 1000).activeProfiles, 2);
  });

  test('ties rank by name, and the lists stop at 6 tools and 5 users', () => {
    const now = freshSlot();
    for (const u of ['f', 'e', 'd', 'c', 'b', 'a']) logCall(`${u}@acme.com`);
    for (const t of ['t7', 't6', 't5', 't4', 't3', 't2', 't1']) logCall('a@acme.com', { toolName: t });

    const figures = store.getCopilotMcpActivityFigures(now);
    assert.deepEqual(figures.topUsers.map((u) => u.username), ['a@acme.com', 'b@acme.com', 'c@acme.com', 'd@acme.com', 'e@acme.com']);
    assert.equal(figures.topTools.length, 6);
    assert.deepEqual(figures.topTools.slice(0, 2), [
      { toolName: 'soql_query', calls: 6 },
      { toolName: 't1', calls: 1 },
    ]);
  });

  test('no calls gives zeros and empty lists', () => {
    const now = freshSlot();
    assert.deepEqual(store.getCopilotMcpActivityFigures(now), {
      windowHours: 24,
      verifiedCalls: 0,
      activeUsers: 0,
      activeProfiles: 0,
      p95LatencyMs: 0,
      avgLatencyMs: 0,
      topTools: [],
      topUsers: [],
    });
  });
});

describe('getCopilotMcpTrafficSeries', () => {
  const total = (s: { slices: Array<{ ok: number; warn: number; err: number }> }) =>
    s.slices.reduce((acc, x) => acc + x.ok + x.warn + x.err, 0);

  test('a full day of traffic reaches the 24h and 7d series, beyond the newest 150 rows', () => {
    const start = freshSlot();
    for (let h = 0; h < 24; h++) {
      setClock(start + h * HOUR);
      for (let i = 0; i < 10; i++) logCall('steady@acme.com');
    }
    const series = store.getCopilotMcpTrafficSeries(start + 23 * HOUR + 30 * MINUTE);
    assert.equal(total(series['24h']), 240);
    assert.equal(total(series['7d']), 240);
    assert.equal(total(series['1h']), 10, 'only the last hour in the 1h series');
  });

  test('slices are aligned to their size, with each status in its segment', () => {
    const at = freshSlot() + 2 * HOUR + 7 * MINUTE + 13_000;
    setClock(at);
    logCall('a@acme.com');
    logCall('a@acme.com', { status: 'DENIED' });
    logCall('a@acme.com', { status: 'ERROR' });

    const series = store.getCopilotMcpTrafficSeries(at);
    assert.deepEqual(series['1h'], { sliceMs: MINUTE, slices: [{ start: at - 13_000, ok: 1, warn: 1, err: 1 }] });
    assert.deepEqual(series['24h'], { sliceMs: 5 * MINUTE, slices: [{ start: at - 2 * MINUTE - 13_000, ok: 1, warn: 1, err: 1 }] });
    assert.deepEqual(series['7d'], { sliceMs: HOUR, slices: [{ start: at - 7 * MINUTE - 13_000, ok: 1, warn: 1, err: 1 }] });
  });

  test('rejected tokens count, as in the totals; simulator runs do not', () => {
    const now = freshSlot();
    logCall('real@acme.com');
    logRejectedToken();
    for (let i = 0; i < 5; i++) logCall('simulated:test-user', { simulated: true });

    const [slice] = store.getCopilotMcpTrafficSeries(now)['24h'].slices;
    assert.deepEqual([slice.ok, slice.warn, slice.err], [1, 1, 0]);
  });

  test('the window reaches back one slice past its edge, so the edge slice is whole', () => {
    const now = freshSlot();
    logCall('edge@acme.com');
    // An hour and 30 s later the call's 1-minute slice still straddles the 1h window's edge.
    assert.equal(total(store.getCopilotMcpTrafficSeries(now + HOUR + 30_000)['1h']), 1);
    // Once a whole slice lies between it and the edge, it is no longer sent.
    assert.equal(total(store.getCopilotMcpTrafficSeries(now + HOUR + 2 * MINUTE)['1h']), 0);
  });

  test('a row ahead of the server clock is still sent', () => {
    const now = freshSlot();
    setClock(now + 10 * MINUTE);
    logCall('ahead@acme.com');
    assert.equal(total(store.getCopilotMcpTrafficSeries(now)['1h']), 1);
  });

  test('no calls sends empty series', () => {
    const now = freshSlot();
    const series = store.getCopilotMcpTrafficSeries(now);
    assert.deepEqual(Object.keys(series), ['1h', '24h', '7d']);
    for (const range of Object.values(series)) assert.deepEqual(range.slices, []);
  });
});

describe('the dashboard shows the server figures', () => {
  const rejected: CopilotMcpLogEntry = {
    id: 'mcp_x',
    timestamp: new Date(Date.parse('2026-11-01T11:59:00.000Z')).toISOString(),
    sfUsername: UNVERIFIED_CALLER_USERNAME,
    profileId: 'unverified',
    profileName: 'Unverified Token',
    matchedGroups: [],
    toolName: 'mcp_authenticate',
    targetObject: '*',
    status: 'DENIED',
    latencyMs: 1,
    sanitizedRequestPayload: '{}',
    sanitizedResponseSummary: '{}',
  };
  // Recent denials rightly lists rejected tokens; the two ranking cards come before it.
  const rankings = (html: string) => html.slice(html.indexOf('Most used tools'), html.indexOf('Recent denials'));
  const render = (mcpActivity: McpActivityFigures | null) =>
    renderToStaticMarkup(
      createElement(TrafficDashboardView, {
        clockNow: Date.parse('2026-11-01T12:00:00.000Z'),
        clockOffsetMs: 0,
        mcpActivity,
        copilotLogs: Array.from({ length: 50 }, (_, i) => ({ ...rejected, id: `mcp_${i}` })),
        portalLogs: [],
        profiles: [],
        objects: [],
        groups: [],
        onNavigateTab: () => {},
        onOpenFlyout: () => {},
      })
    );

  test('rankings and KPIs come from the figures, not from rejected rows in the list', () => {
    const html = render({
      windowHours: 24,
      verifiedCalls: 420,
      activeUsers: 31,
      activeProfiles: 12,
      p95LatencyMs: 510,
      avgLatencyMs: 190,
      topTools: [{ toolName: 'soql_query', calls: 230 }],
      topUsers: [{ username: 'priya@acme.com', profileName: 'Enterprise Sales AE', calls: 41 }],
    });
    assert.doesNotMatch(rankings(html), /mcp_authenticate|unverified_caller/);
    assert.match(rankings(html), /priya@acme\.com/);
    assert.match(html, /Enterprise Sales AE/);
    assert.match(html, /avg 190 ms · 420 verified calls, last 24 h/);
    assert.match(html, />31</);
    assert.match(html, /across 12 profiles, last 24 h/);
  });

  test('before the server answers, the figures are empty rather than read from the list', () => {
    const html = render(null);
    assert.match(html, /No verified MCP calls in the last 24 h/);
    assert.match(html, /No verified callers in the last 24 h/);
    assert.doesNotMatch(rankings(html), /mcp_authenticate|unverified_caller/);
  });
});

describe('/overview', () => {
  let server: TestServer;
  let session: AdminSession;
  before(async () => {
    server = await startTestServer();
    session = await loginAsAdmin(server.baseUrl);
  });
  after(async () => {
    await server.close();
  });

  test('sends the activity figures and chart counts, measured on the clock it reports', async () => {
    logCall('live@acme.com', { toolName: 'describe_object' });
    logRejectedToken();

    const { body } = await adminFetch(server.baseUrl, session, '/api/admin/overview');
    assert.equal(body.mcpActivity.windowHours, 24);
    assert.equal(body.mcpActivity.verifiedCalls, 1);
    assert.deepEqual(body.mcpActivity.topUsers, [{ username: 'live@acme.com', profileName: 'Sales', calls: 1 }]);
    assert.deepEqual(body.mcpActivity.topTools, [{ toolName: 'describe_object', calls: 1 }]);
    const sent = (range: string) =>
      body.mcpTraffic[range].slices.reduce((acc: number, s: { ok: number; warn: number }) => acc + s.ok + s.warn, 0);
    assert.deepEqual([sent('1h'), sent('24h'), sent('7d')], [2, 2, 2]);
    assert.ok(Math.abs(Date.parse(body.serverTime) - Date.now()) < 60_000);
  });
});
