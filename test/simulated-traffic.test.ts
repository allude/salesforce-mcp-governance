import './helpers/env.js';
// Simulated traffic must stay identifiable in the audit log and must not be able to pose as a real
// user: the marker comes from the signed token or the route, and the name is always namespaced.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { config } from '../src/config.js';
import { store } from '../src/db/store.js';
import { createSimulatorToken, resolveSalesforceUserFromToken } from '../src/salesforce/client.js';
import { startTestServer, loginAsAdmin, adminFetch, mcpRequest, type AdminSession, type TestServer } from './helpers/server.js';
import { installSalesforceMock } from './helpers/salesforceMock.js';
import { TEST_ADMIN } from './helpers/env.js';
import { DEFAULT_SIMULATED_USERNAME, realTraffic, trafficBurstCalls } from '../src/components/views/simulatedTraffic.js';

const tag = () => crypto.randomBytes(4).toString('hex');
const newProfileId = () => `00e${crypto.randomBytes(6).toString('hex')}`.slice(0, 15);

let server: TestServer;
let session: AdminSession;

before(async () => {
  server = await startTestServer();
  session = await loginAsAdmin(server.baseUrl);
});

after(async () => {
  await server.close();
});

function seedProfile() {
  const profileId = newProfileId();
  const profileName = `Sim Traffic ${tag()}`;
  const objectName = `SimTraffic_${tag()}__c`;
  store.upsertProfile(profileId, profileName);
  store.upsertObjectWithFields({ objectName, fields: [{ fieldName: 'Id' }, { fieldName: 'Name' }] });
  const group = store.upsertGroup({
    name: `Sim Traffic Readers ${tag()}`,
    allowedActions: ['list_enabled_objects', 'soql_query'],
    objectPermissions: [
      { objectName, canRead: true, canCreate: false, canUpdate: false, canDelete: false, allowedFields: ['Id', 'Name'] },
    ],
  });
  store.setProfileGroups(profileId, [group.id]);
  return { profileId, profileName, objectName };
}

const rowsFor = (profileId: string) => store.getCopilotMcpLogs(1_000_000).filter((row) => row.profileId === profileId);

const simulate = (body: Record<string, unknown>) =>
  adminFetch(server.baseUrl, session, '/api/admin/test-mcp-access', { method: 'POST', body });

/** The identity a token resolves to when /mcp verifies it. */
async function usernameFromToken(username: string): Promise<string> {
  const token = createSimulatorToken({ profileId: newProfileId(), profileName: 'X', username });
  return (await resolveSalesforceUserFromToken(token)).username;
}

describe('simulated identity', () => {
  test('a real-looking name is namespaced so it cannot be read as that user', async () => {
    assert.equal(await usernameFromToken('ceo@acme.com'), 'simulated:ceo@acme.com');
  });

  test('control, line-separator and bidi characters are removed', async () => {
    assert.equal(await usernameFromToken('a\r\nb\u0000c‮d e'), 'simulated:abcde');
  });

  test('the name is capped at 64 characters', async () => {
    assert.equal(await usernameFromToken('x'.repeat(500)), `simulated:${'x'.repeat(64)}`);
  });

  test('an empty name or one that only repeats the prefix falls back to a synthetic default', async () => {
    assert.equal(await usernameFromToken(''), 'simulated:test-user');
    assert.equal(await usernameFromToken(' \r\n '), 'simulated:test-user');
    assert.equal(await usernameFromToken('simulated:'), 'simulated:test-user');
  });

  test('the prefix is not stacked', async () => {
    assert.equal(await usernameFromToken('Simulated: simulated:bob'), 'simulated:bob');
  });

  test('the default token identity is synthetic', async () => {
    const user = await resolveSalesforceUserFromToken(createSimulatorToken({ profileId: newProfileId(), profileName: 'X' }));
    assert.equal(user.username, 'simulated:test-user');
    assert.match(user.email, /\.invalid$/);
    assert.equal(user.simulated, true);
  });
});

describe('POST /test-mcp-access', () => {
  test('rows are marked and namespaced, and ALLOWED and DENIED rows both still appear', async () => {
    const { profileId, objectName } = seedProfile();

    await simulate({ profileId, toolName: 'soql_query', targetObject: objectName, username: 'ceo@acme.com' });
    await simulate({ profileId, toolName: 'delete_record', targetObject: objectName, username: 'ceo@acme.com' });

    assert.deepEqual(
      rowsFor(profileId).reverse().map((r) => [r.status, r.simulated, r.sfUsername]),
      [
        ['ALLOWED', true, 'simulated:ceo@acme.com'],
        ['DENIED', true, 'simulated:ceo@acme.com'],
      ]
    );
  });

  test('overview returns the marker on rows', async () => {
    const { profileId, objectName } = seedProfile();
    await simulate({ profileId, toolName: 'soql_query', targetObject: objectName });

    const res = await adminFetch(server.baseUrl, session, '/api/admin/overview');
    const row = res.body.copilotLogs.find((r: any) => r.profileId === profileId);
    assert.equal(row.simulated, true);
    assert.equal(row.sfUsername, 'simulated:test-user');
  });

  test('writes a portal admin log row naming the admin, Profile, tool and object', async () => {
    const { profileId, profileName, objectName } = seedProfile();

    await simulate({ profileId, toolName: 'delete_record', targetObject: objectName, username: 'ceo@acme.com' });

    const entry = store.getPortalAdminLogs(50).find((l) => l.action === 'SIMULATE_MCP_CALL' && l.target.includes(profileId));
    assert.ok(entry, 'expected a SIMULATE_MCP_CALL row');
    assert.equal(entry.adminUsername, TEST_ADMIN.username);
    assert.ok(entry.target.includes(profileName), entry.target);
    assert.ok(entry.details.includes('delete_record'), entry.details);
    assert.ok(entry.details.includes(objectName), entry.details);
    assert.ok(entry.details.includes('simulated:ceo@acme.com'), entry.details);
    assert.ok(entry.details.includes('DENIED'), entry.details);
  });

  test('in production it still evaluates the call but hands out no simulator token', async () => {
    const { profileId, objectName } = seedProfile();
    const mutable = config as { isProd: boolean };
    mutable.isProd = true;
    let res;
    try {
      res = await simulate({ profileId, toolName: 'soql_query', targetObject: objectName });
    } finally {
      mutable.isProd = false;
    }

    assert.equal(res.status, 200, JSON.stringify(res.body));
    assert.equal(res.body.evaluation.permitted, true);
    assert.equal('simulatorBearerToken' in res.body, false);
    const entry = store.getPortalAdminLogs(50).find((l) => l.action === 'SIMULATE_MCP_CALL' && l.target.includes(profileId));
    assert.ok(entry, 'expected a SIMULATE_MCP_CALL row');
    assert.ok(!entry.details.includes('token'), entry.details);
  });
});

describe('/mcp', () => {
  test('tools/call with a simulator token logs marked rows for allowed, denied and failed calls', async (t) => {
    const sf = installSalesforceMock();
    t.after(() => sf.restore());
    const { profileId, profileName, objectName } = seedProfile();
    const token = createSimulatorToken({ profileId, profileName, username: 'rep@acme.com' });

    await mcpRequest(server.baseUrl, token, 'tools/call', { name: 'soql_query', arguments: { objectName, fields: ['Id'] } });
    await mcpRequest(server.baseUrl, token, 'tools/call', { name: 'delete_record', arguments: { objectName, recordId: '001000000000001AAA' } });
    // A field outside the grant passes the tool check and is refused during execution, the third log site.
    await mcpRequest(server.baseUrl, token, 'tools/call', { name: 'soql_query', arguments: { objectName, fields: ['Secret__c'] } });

    const rows = rowsFor(profileId);
    assert.deepEqual(rows.reverse().map((r) => r.status), ['ALLOWED', 'DENIED', 'DENIED']);
    for (const row of rows) {
      assert.equal(row.simulated, true);
      assert.equal(row.sfUsername, 'simulated:rep@acme.com');
    }
  });

  test('a real token is never marked, whatever the caller puts in the request', async (t) => {
    const sf = installSalesforceMock();
    t.after(() => sf.restore());
    const { profileId, profileName, objectName } = seedProfile();
    const token = `real-token-${tag()}`;
    sf.addUser(token, {
      userId: `005${tag()}`,
      organizationId: '00D000000000001AAA',
      username: `real.${tag()}@acme.com`,
      profileId,
      profileName,
    });

    const res = await mcpRequest(server.baseUrl, token, 'tools/call', {
      name: 'soql_query',
      simulated: true,
      arguments: { objectName, fields: ['Id'], simulated: true },
    });
    assert.equal(res.status, 200);

    const [row] = rowsFor(profileId);
    assert.ok(row, 'expected a log row');
    assert.equal(row.simulated, undefined);
    assert.ok(!row.sfUsername.startsWith('simulated:'), row.sfUsername);
  });

  test('an unsigned simulator token is rejected and earns no marker', async () => {
    const before = new Set(store.getCopilotMcpLogs(1_000_000).map((r) => r.id));
    const forged = `sf_sim_${Buffer.from(JSON.stringify({ username: 'x', simulated: true })).toString('base64url')}.bad`;

    const res = await mcpRequest(server.baseUrl, forged, 'tools/list');

    assert.equal(res.status, 401);
    const added = store.getCopilotMcpLogs(1_000_000).filter((r) => !before.has(r.id));
    assert.deepEqual(added.map((r) => [r.sfUsername, r.simulated]), [['unverified_caller', undefined]]);
  });
});

describe('recordCopilotMcpLog', () => {
  test('defaults to not simulated and persists the marker', () => {
    const profileId = newProfileId();
    const base = {
      sfUsername: 'a',
      profileId,
      profileName: 'P',
      matchedGroups: [],
      toolName: 'soql_query',
      targetObject: 'Account',
      status: 'ALLOWED' as const,
      latencyMs: 1,
      rawRequestPayload: {},
      rawResponseSummary: {},
    };
    const real = store.recordCopilotMcpLog(base);
    const simulated = store.recordCopilotMcpLog({ ...base, simulated: true });

    assert.equal(real.simulated, undefined);
    assert.equal(simulated.simulated, true);
    const byId = new Map(rowsFor(profileId).map((r) => [r.id, r]));
    assert.equal(byId.get(real.id)?.simulated, undefined);
    assert.equal(byId.get(simulated.id)?.simulated, true);
  });
});

describe('dashboard figures', () => {
  test('simulator calls leave the overview KPIs unchanged while their rows still list', async () => {
    const { profileId, objectName } = seedProfile();
    const stats = async () => (await adminFetch(server.baseUrl, session, '/api/admin/overview')).body;
    const before = (await stats()).stats;

    await simulate({ profileId, toolName: 'soql_query', targetObject: objectName });
    await simulate({ profileId, toolName: 'delete_record', targetObject: objectName });
    const token = createSimulatorToken({ profileId, profileName: 'X' });
    await mcpRequest(server.baseUrl, token, 'tools/call', { name: 'soql_query', arguments: { objectName, fields: ['Id'] } });

    const overview = await stats();
    assert.equal(overview.stats.totalMcpRequests, before.totalMcpRequests);
    assert.equal(overview.stats.allowedMcpRequests, before.allowedMcpRequests);
    assert.equal(overview.stats.deniedMcpRequests, before.deniedMcpRequests);
    assert.equal(overview.stats.erroredMcpRequests, before.erroredMcpRequests);
    assert.equal(overview.copilotLogs.filter((r: any) => r.profileId === profileId).length, 3);
  });

  test('real calls still count', () => {
    const before = store.getCopilotMcpLogStats();
    const row = {
      sfUsername: 'real@acme.com',
      profileId: newProfileId(),
      profileName: 'P',
      matchedGroups: [],
      toolName: 'soql_query',
      targetObject: 'Account',
      latencyMs: 1,
      rawRequestPayload: {},
      rawResponseSummary: {},
    };
    store.recordCopilotMcpLog({ ...row, status: 'ALLOWED' });
    store.recordCopilotMcpLog({ ...row, status: 'ERROR' });
    store.recordCopilotMcpLog({ ...row, status: 'DENIED', simulated: true });

    assert.deepEqual(store.getCopilotMcpLogStats(), {
      total: before.total + 2,
      allowed: before.allowed + 1,
      denied: before.denied,
      errors: before.errors + 1,
    });
  });

  test('realTraffic drops simulated rows and keeps the order of the rest', () => {
    const logs = [{ id: 'a' }, { id: 'b', simulated: true }, { id: 'c' }];
    assert.deepEqual(realTraffic(logs).map((l) => l.id), ['a', 'c']);
  });
});

describe('traffic burst', () => {
  test('uses only obviously synthetic names', () => {
    const calls = trafficBurstCalls(['00e000000000001', '00e000000000002']);
    assert.equal(calls.length, 6);
    for (const call of calls) assert.match(call.username, /^test-user-\d+$/);
    assert.equal(new Set(calls.map((c) => c.username)).size, 6);
  });

  test('uses the given Profiles, and reuses the first when there are too few', () => {
    const calls = trafficBurstCalls(['00eA', '00eB']);
    assert.deepEqual(calls.map((c) => c.profileId), ['00eA', '00eB', '00eA', '00eB', '00eA', '00eB']);
  });

  test("the form's default name matches the server's", async () => {
    const profileId = newProfileId();
    const res = await simulate({ profileId, toolName: 'list_enabled_objects' });
    assert.equal(res.status, 200);
    assert.equal(rowsFor(profileId)[0].sfUsername, `simulated:${DEFAULT_SIMULATED_USERNAME}`);
  });
});

describe('devToolsEnabled', () => {
  test('overview reports it from the server config outside production', async () => {
    const res = await adminFetch(server.baseUrl, session, '/api/admin/overview');
    assert.equal(res.body.devToolsEnabled, true);
  });

  test('overview reports it off in production', async () => {
    const mutable = config as { isProd: boolean };
    mutable.isProd = true;
    try {
      const res = await adminFetch(server.baseUrl, session, '/api/admin/overview');
      assert.equal(res.status, 200);
      assert.equal(res.body.devToolsEnabled, false);
    } finally {
      mutable.isProd = false;
    }
  });
});
