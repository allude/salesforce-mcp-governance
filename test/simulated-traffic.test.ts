import './helpers/env.js';
// Simulated traffic must stay identifiable in the audit log and must not be able to pose as a real
// user: the marker comes from the signed token or the route, and the name is always namespaced.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { store } from '../src/db/store.js';
import { createSimulatorToken, resolveSalesforceUserFromToken } from '../src/salesforce/client.js';
import { startTestServer, loginAsAdmin, adminFetch, mcpRequest, type AdminSession, type TestServer } from './helpers/server.js';
import { installSalesforceMock } from './helpers/salesforceMock.js';
import { TEST_ADMIN } from './helpers/env.js';

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
