import './helpers/env.js';
// The header reports when the last real MCP call happened. It must not be moved by the simulator or
// by a rejected token, and must not be hidden when simulator rows fill the capped log list.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { store } from '../src/db/store.js';
import { startTestServer, loginAsAdmin, adminFetch, mcpRequest, type AdminSession, type TestServer } from './helpers/server.js';
import { mcpActivityStatus } from '../src/components/views/mcpActivity.js';

const NOW = Date.parse('2026-11-01T12:00:00.000Z');
const MIN = 60_000;
const HOUR = 60 * MIN;
const DAY = 24 * HOUR;
const ago = (ms: number) => new Date(NOW - ms).toISOString();

describe('mcpActivityStatus', () => {
  test('no calls is said plainly, with a neutral dot', () => {
    assert.deepEqual(mcpActivityStatus(null, NOW), { label: 'No MCP calls yet', tone: 'off' });
  });

  test('before the server has answered, or with an unreadable time, it claims nothing', () => {
    assert.deepEqual(mcpActivityStatus(undefined, NOW), { label: 'Last MCP call unknown', tone: 'off' });
    assert.deepEqual(mcpActivityStatus('not a date', NOW), { label: 'Last MCP call unknown', tone: 'off' });
  });

  const labels: Array<[number, string]> = [
    [0, 'just now'],
    [MIN - 1, 'just now'],
    [MIN, '1 min ago'],
    [3 * MIN, '3 min ago'],
    [HOUR - 1, '59 min ago'],
    [HOUR, '1 h ago'],
    [DAY - 1, '23 h ago'],
    [DAY, '1 day ago'],
    [2 * DAY, '2 days ago'],
  ];
  for (const [age, text] of labels) {
    test(`a call ${age} ms ago reads "${text}"`, () => {
      assert.equal(mcpActivityStatus(ago(age), NOW).label, `Last MCP call ${text}`);
    });
  }

  test('the dot is active only within the last day', () => {
    assert.equal(mcpActivityStatus(ago(DAY - 1), NOW).tone, 'ok');
    assert.equal(mcpActivityStatus(ago(DAY), NOW).tone, 'off');
  });

  test('a time ahead of the browser clock reads as just now', () => {
    assert.deepEqual(mcpActivityStatus(ago(-5 * MIN), NOW), { label: 'Last MCP call just now', tone: 'ok' });
  });
});

describe('overview lastMcpCallAt', () => {
  let server: TestServer;
  let session: AdminSession;

  before(async () => {
    server = await startTestServer();
    session = await loginAsAdmin(server.baseUrl);
  });

  after(async () => {
    await server.close();
  });

  const lastCallAt = async () =>
    (await adminFetch(server.baseUrl, session, '/api/admin/overview')).body.stats.lastMcpCallAt;

  const logRow = (simulated: boolean) =>
    store.recordCopilotMcpLog({
      sfUsername: 'real@acme.com',
      profileId: '00e000000000001',
      profileName: 'P',
      matchedGroups: [],
      toolName: 'soql_query',
      targetObject: 'Account',
      status: 'ALLOWED',
      latencyMs: 1,
      rawRequestPayload: {},
      rawResponseSummary: {},
      simulated,
    });

  // These run in order: the first needs the empty log this file's fresh database starts with.
  test('is null with no real calls, even after simulated ones and rejected tokens', async () => {
    assert.equal(await lastCallAt(), null);

    logRow(true);
    const rejected = await mcpRequest(server.baseUrl, 'not-a-valid-token', 'tools/list');
    assert.equal(rejected.status, 401);
    assert.ok(store.getCopilotMcpLogs(10).some((r) => r.sfUsername === 'unverified_caller'));

    assert.equal(await lastCallAt(), null);
  });

  test('is the time of the newest real call', async () => {
    const row = logRow(false);
    assert.equal(await lastCallAt(), row.timestamp);
  });

  test('a real call followed by a full list of simulator rows is still listed and reported', async () => {
    const row = logRow(false);
    for (let i = 0; i < 151; i += 1) logRow(true);

    const overview = (await adminFetch(server.baseUrl, session, '/api/admin/overview')).body;
    assert.ok(overview.copilotLogs.some((r: any) => r.id === row.id), 'simulator rows must not displace it');
    assert.equal(overview.stats.lastMcpCallAt, row.timestamp);
  });

  test('a later rejected token does not move it', async () => {
    const before = await lastCallAt();
    await mcpRequest(server.baseUrl, 'not-a-valid-token', 'tools/list');
    assert.equal(await lastCallAt(), before);
  });
});
