import './helpers/env.js';
// A run of simulated rows must not hide real MCP calls or other audit entries from anything the
// portal shows, while every row stays stored. This file's fresh database makes the counts exact.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { store, UNVERIFIED_CALLER_USERNAME } from '../src/db/store.js';
import { startTestServer, loginAsAdmin, adminFetch, type AdminSession, type TestServer } from './helpers/server.js';
import { realTraffic } from '../src/components/views/simulatedTraffic.js';
import { trafficChartSubtitle } from '../src/components/views/trafficChart.js';
import { trafficLogCsv } from '../src/components/views/csvExport.js';
import { auditLogKinds, describeHeldLogs, trafficLogKinds } from '../src/components/views/logHistory.js';

let server: TestServer;
let session: AdminSession;

before(async () => {
  server = await startTestServer();
  session = await loginAsAdmin(server.baseUrl);
});

after(async () => {
  await server.close();
});

const overview = async () => (await adminFetch(server.baseUrl, session, '/api/admin/overview')).body;

const logCall = (sfUsername: string, status: 'ALLOWED' | 'DENIED', simulated: boolean) =>
  store.recordCopilotMcpLog({
    sfUsername,
    profileId: '00e000000000001',
    profileName: 'P',
    matchedGroups: [],
    toolName: 'delete_record',
    targetObject: 'Account',
    status,
    latencyMs: 7,
    rawRequestPayload: {},
    rawResponseSummary: {},
    simulated,
  });

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
    rawRequestPayload: { method: 'tools/list' },
    rawResponseSummary: { error: 'Token validation failed' },
  });

const logAudit = (action: string) =>
  store.recordPortalAdminLog({
    adminUsername: 'admin',
    authMethod: 'password',
    action,
    target: 'T',
    details: 'D',
  });

describe('MCP rows in /overview', () => {
  test('a real denial survives a burst of simulator rows in the list, dashboard figures and CSV', async () => {
    const denial = logCall('real.user@acme.com', 'DENIED', false);
    for (let i = 0; i < 151; i += 1) logCall('simulated:test-user', 'ALLOWED', true);

    const { copilotLogs, stats } = await overview();
    const real: Array<{ id: string }> = realTraffic(copilotLogs as Array<{ id: string; simulated?: boolean }>);

    assert.deepEqual(real.map((r) => r.id), [denial.id]);
    assert.equal(stats.totalMcpRequests, 1);
    assert.equal(stats.deniedMcpRequests, 1);
    assert.doesNotMatch(trafficChartSubtitle('24h', real.length), /no real calls/);
    assert.ok(trafficLogCsv(copilotLogs).includes('real.user@acme.com'));
  });

  test('simulated rows have their own smaller cap, keep their newest rows and are not lost', async () => {
    const { copilotLogs } = await overview();
    const simulated = copilotLogs.filter((r: any) => r.simulated);
    assert.equal(simulated.length, 50);

    const stored = store.getCopilotMcpLogs(1_000_000);
    const storedSimulated = stored.filter((r) => r.simulated);
    assert.equal(storedSimulated.length, 151, 'capping the list must not remove rows');
    assert.deepEqual(simulated.map((r: any) => r.id), storedSimulated.slice(0, 50).map((r) => r.id));
  });

  test('real rows keep the existing cap of 150 however few simulated rows there are', async () => {
    for (let i = 0; i < 160; i += 1) logCall('real.user@acme.com', 'ALLOWED', false);
    const { copilotLogs } = await overview();
    assert.equal(realTraffic(copilotLogs as Array<{ simulated?: boolean }>).length, 150);
    assert.equal(copilotLogs.length, 200);
  });

  test('the merged list runs newest first across both kinds, with ALLOWED and DENIED rows of each', async () => {
    const rows = [
      logCall('simulated:a', 'ALLOWED', true),
      logCall('real.user@acme.com', 'DENIED', false),
      logCall('simulated:b', 'DENIED', true),
      logCall('real.user@acme.com', 'ALLOWED', false),
    ];
    const { copilotLogs } = await overview();
    assert.deepEqual(copilotLogs.slice(0, 4).map((r: any) => r.id), rows.map((r) => r.id).reverse());
    assert.deepEqual(
      copilotLogs.slice(0, 4).map((r: any) => [r.status, r.simulated === true]),
      [
        ['ALLOWED', false],
        ['DENIED', true],
        ['DENIED', false],
        ['ALLOWED', true],
      ]
    );
  });

  test('a verified call survives a flood of rejected-token rows, which have their own smaller cap', async () => {
    const verified = logCall('real.user@acme.com', 'DENIED', false);
    const rejected = Array.from({ length: 151 }, () => logRejectedToken());

    const { copilotLogs } = await overview();
    assert.ok(copilotLogs.some((r: any) => r.id === verified.id), 'expected the verified call to stay visible');
    assert.ok(trafficLogCsv(copilotLogs).includes(verified.id));

    const shownRejected = copilotLogs.filter((r: any) => r.sfUsername === UNVERIFIED_CALLER_USERNAME);
    assert.deepEqual(
      shownRejected.map((r: any) => r.id),
      rejected.slice(-50).reverse().map((r) => r.id),
      'the newest 50 rejected-token rows are kept, newest first'
    );
    assert.equal(copilotLogs.filter((r: any) => !r.simulated && r.sfUsername !== UNVERIFIED_CALLER_USERNAME).length, 150);
    assert.equal(
      store.getCopilotMcpLogs(1_000_000).filter((r) => r.sfUsername === UNVERIFIED_CALLER_USERNAME).length,
      151,
      'capping the list must not remove rows'
    );
  });

  test('sends its caps, so the Logs view can say which rows it holds', async () => {
    const { copilotLogs, logCaps } = await overview();
    assert.deepEqual(logCaps.copilotLogs, { calls: 150, simulated: 50, rejected: 50 });
    assert.equal(
      describeHeldLogs({ overview: copilotLogs, older: [], cursor: undefined, kinds: trafficLogKinds(logCaps.copilotLogs) }),
      'latest 150 calls + latest 50 simulated + latest 50 rejected'
    );
  });
});

describe('Portal rows in /overview', () => {
  test('policy simulations do not displace other audit entries, and none is deleted', async () => {
    const entry = logAudit('UPDATE_GROUP');
    for (let i = 0; i < 151; i += 1) logAudit('SIMULATE_MCP_CALL');

    const { portalLogs } = await overview();
    assert.ok(portalLogs.some((l: any) => l.id === entry.id), 'expected UPDATE_GROUP to stay visible');
    assert.ok(portalLogs.some((l: any) => l.action === 'LOGIN_SUCCESS'), 'expected the login to stay visible');
    assert.equal(portalLogs.filter((l: any) => l.action === 'SIMULATE_MCP_CALL').length, 50);
    assert.equal(
      store.getPortalAdminLogs(1_000_000).filter((l) => l.action === 'SIMULATE_MCP_CALL').length,
      151
    );
  });

  test('other actions keep the existing cap of 150, newest first', async () => {
    for (let i = 0; i < 160; i += 1) logAudit('UPDATE_GROUP');
    const newest = logAudit('SIMULATE_MCP_CALL');

    const { portalLogs } = await overview();
    assert.equal(portalLogs[0].id, newest.id);
    assert.equal(portalLogs.filter((l: any) => l.action !== 'SIMULATE_MCP_CALL').length, 150);
  });

  test('sends its caps, so the Logs view can say which rows it holds', async () => {
    const { portalLogs, logCaps } = await overview();
    assert.deepEqual(logCaps.portalLogs, { events: 150, simulations: 50 });
    assert.equal(
      describeHeldLogs({ overview: portalLogs, older: [], cursor: undefined, kinds: auditLogKinds(logCaps.portalLogs) }),
      'latest 150 events + latest 50 simulations'
    );
  });
});

describe('serverTime in /overview', () => {
  test("is the server's current clock", async () => {
    const before = Date.now();
    const { serverTime } = await overview();
    const time = Date.parse(serverTime);
    assert.equal(new Date(time).toISOString(), serverTime);
    assert.ok(time >= before && time <= Date.now(), serverTime);
  });
});
