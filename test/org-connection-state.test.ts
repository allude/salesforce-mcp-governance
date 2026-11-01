import './helpers/env.js';
// Covers what the Salesforce org connection routes persist: which host MCP sends bearer tokens to,
// what a failed connect leaves behind, when a connection stops counting as verified, and the audit trail.
import { after, afterEach, before, beforeEach, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { repairConnectInstanceUrls, store } from '../src/db/store.js';
import { generateSelfSignedCertificateBundle } from '../src/salesforce/jwtConnection.js';
import { SIMULATED_ORG_INSTANCE_URL } from '../src/salesforce/simulatedOrg.js';
import { installSalesforceMock, type SalesforceMock } from './helpers/salesforceMock.js';
import {
  adminFetch,
  loginAsAdmin,
  mcpRequest,
  startTestServer,
  type AdminSession,
  type TestServer,
} from './helpers/server.js';

const MCP_HOST = 'https://mcp-host.my.salesforce.com';
const SYNC_HOST = 'https://sync-host.my.salesforce.com';
const ORG_ID = '00D000000000001AAA';
const uid = () => crypto.randomBytes(4).toString('hex');

let server: TestServer;
let session: AdminSession;
let sf: SalesforceMock;
let sfFetch: typeof fetch;
const bundle = generateSelfSignedCertificateBundle('Connection State Test');

before(async () => {
  sf = installSalesforceMock();
  sfFetch = globalThis.fetch;
  server = await startTestServer();
  session = await loginAsAdmin(server.baseUrl);
});

after(async () => {
  sf.restore();
  await server.close();
});

const route = (path: string, method: string, body: Record<string, unknown> = {}) =>
  adminFetch(server.baseUrl, session, `/api/admin/sf-settings${path}`, { method, body });
const connect = (body: Record<string, unknown> = {}) => route('/connect', 'POST', body);

/** Answers the JWT token exchange, which the shared Salesforce mock does not route. */
function answerTokenExchange(respond: () => Response) {
  globalThis.fetch = (async (input: any, init?: RequestInit) => {
    const url = new URL(typeof input === 'string' ? input : input.url ?? input.href);
    return url.pathname === '/services/oauth2/token' ? respond() : sfFetch(input, init);
  }) as typeof fetch;
}

const tokenGranted = (instanceUrl = SYNC_HOST, orgId = ORG_ID) => () =>
  Response.json({
    access_token: `sync_tok_${uid()}`,
    instance_url: instanceUrl,
    id: `https://login.salesforce.com/id/${orgId}/005000000000001AAA`,
  });

const tokenRefused = () => () => Response.json({ error: 'invalid_grant', error_description: 'user hasn\'t approved this consumer' }, { status: 400 });

function setRawInstanceUrl(value: string) {
  const db = new DatabaseSync(process.env.DB_PATH as string);
  try {
    db.prepare('UPDATE sf_connection_settings SET instance_url = ? WHERE id = 1').run(value);
  } finally {
    db.close();
  }
}

function rawInstanceUrl(): string {
  const db = new DatabaseSync(process.env.DB_PATH as string);
  try {
    return (db.prepare('SELECT instance_url FROM sf_connection_settings WHERE id = 1').get() as { instance_url: string }).instance_url;
  } finally {
    db.close();
  }
}

beforeEach(() => {
  sf.reset();
  store.updateSalesforceSettings({
    enabled: false,
    authMode: 'jwt_bearer',
    loginUrl: 'https://login.salesforce.com',
    clientId: '3MVG9_ORIGINAL',
    username: 'integration@example.com',
    privateKeyPem: bundle.privateKeyPem,
    certificatePem: bundle.certificatePem,
    expectedOrgId: '',
    enforceOrgIdLock: false,
    instanceUrl: MCP_HOST,
    syncInstanceUrl: '',
    connectionStatus: 'disconnected',
    lastConnectedAt: null,
    lastError: '',
    connectedOrgId: '',
    connectedUser: '',
  });
});

afterEach(() => {
  globalThis.fetch = sfFetch;
});

describe('the instance URL MCP uses to verify tokens', () => {
  test('a real connect records its host for sync and leaves the MCP host alone', async () => {
    answerTokenExchange(tokenGranted());
    const res = await connect();

    assert.equal(res.status, 200, JSON.stringify(res.body));
    assert.equal(res.body.sfSettings.syncInstanceUrl, SYNC_HOST);
    assert.equal(res.body.sfSettings.instanceUrl, MCP_HOST);
    assert.equal(rawInstanceUrl(), MCP_HOST);
  });

  test('after a connect, bearer tokens are still verified at the MCP host and it is still advertised', async () => {
    answerTokenExchange(tokenGranted());
    assert.equal((await connect()).status, 200);
    sf.reset();

    const token = `tok_${uid()}${uid()}`;
    sf.addUser(token, {
      userId: '005000000000001AAA',
      organizationId: ORG_ID,
      username: `u${uid()}@acme.example`,
      profileId: '00e000000000001AAA',
      profileName: 'P',
    });
    await mcpRequest(server.baseUrl, token, 'tools/list', {});

    const userinfo = sf.calls.filter((c) => c.url.pathname === '/services/oauth2/userinfo');
    assert.ok(userinfo.length > 0);
    assert.ok(userinfo.every((c) => c.url.origin === MCP_HOST));
    assert.ok(!sf.calls.some((c) => c.url.origin === SYNC_HOST));

    const doc = await (await fetch(`${server.baseUrl}/.well-known/oauth-protected-resource`)).json();
    assert.deepEqual(doc.authorization_servers, [MCP_HOST]);
  });

  test('an instance URL in the connect request is validated but does not change the MCP host', async () => {
    answerTokenExchange(tokenGranted());
    const res = await connect({ instanceUrl: 'https://other.my.salesforce.com' });
    assert.equal(res.status, 200, JSON.stringify(res.body));
    assert.equal(rawInstanceUrl(), MCP_HOST);

    const refused = await connect({ instanceUrl: 'https://evil.example.com' });
    assert.equal(refused.status, 400);
    assert.equal(rawInstanceUrl(), MCP_HOST);
  });

  test('a real connect initialises an empty MCP host', async () => {
    setRawInstanceUrl('');
    answerTokenExchange(tokenGranted());
    const res = await connect();

    assert.equal(res.status, 200, JSON.stringify(res.body));
    assert.equal(res.body.sfSettings.instanceUrl, SYNC_HOST);
    assert.equal(rawInstanceUrl(), SYNC_HOST);
  });

  test('a simulated connect never writes its host to the MCP host, even when empty', async () => {
    const overExisting = await connect({ authMode: 'simulated' });
    assert.equal(overExisting.status, 200, JSON.stringify(overExisting.body));
    assert.equal(overExisting.body.sfSettings.syncInstanceUrl, SIMULATED_ORG_INSTANCE_URL);
    assert.equal(rawInstanceUrl(), MCP_HOST);

    setRawInstanceUrl('');
    const overEmpty = await connect({ authMode: 'simulated' });
    assert.equal(overEmpty.status, 200, JSON.stringify(overEmpty.body));
    assert.notEqual(rawInstanceUrl(), SIMULATED_ORG_INSTANCE_URL);
    assert.notEqual(overEmpty.body.sfSettings.instanceUrl, SIMULATED_ORG_INSTANCE_URL);
  });

  test('upgrading keeps a connected row showing its host and removes the simulated host from the MCP host', () => {
    store.updateSalesforceSettings({ authMode: 'simulated', connectionStatus: 'connected', syncInstanceUrl: '' });
    setRawInstanceUrl(SIMULATED_ORG_INSTANCE_URL);

    repairConnectInstanceUrls();

    const settings = store.getSalesforceSettings();
    assert.equal(settings.syncInstanceUrl, SIMULATED_ORG_INSTANCE_URL);
    assert.equal(settings.instanceUrl, settings.loginUrl);
  });

  test('upgrading leaves a real org on the same host alone', () => {
    store.updateSalesforceSettings({ authMode: 'jwt_bearer' });
    setRawInstanceUrl(SIMULATED_ORG_INSTANCE_URL);

    repairConnectInstanceUrls();

    assert.equal(rawInstanceUrl(), SIMULATED_ORG_INSTANCE_URL);
  });
});
