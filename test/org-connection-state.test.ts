import './helpers/env.js';
// Covers what the Salesforce org connection routes persist: which host MCP sends bearer tokens to,
// what a failed connect leaves behind, when a connection stops counting as verified, and the audit trail.
import { after, afterEach, before, beforeEach, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { config } from '../src/config.js';
import { repairConnectInstanceUrls, store } from '../src/db/store.js';
import { generateSelfSignedCertificateBundle } from '../src/salesforce/jwtConnection.js';
import {
  isSimulatedOrgHost,
  isUninitialisedMcpTokenHost,
  SIMULATED_ORG_ID,
  SIMULATED_ORG_INSTANCE_URL,
} from '../src/salesforce/simulatedOrg.js';
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
/** The simulated host written so that an exact string match misses it. */
const SIMULATED_HOST_VARIANTS = [
  'https://enterprise-org.my.salesforce.com:8443',
  'https://ENTERPRISE-ORG.My.Salesforce.com',
  'https://enterprise-org.my.salesforce.com.',
];

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

  for (const written of [SIMULATED_ORG_INSTANCE_URL, 'https://ENTERPRISE-ORG.my.salesforce.com/path']) {
    test(`a save or connect naming ${written} as the MCP host is refused`, async () => {
      const saved = await route('', 'PUT', { instanceUrl: written });
      assert.equal(saved.status, 400);
      assert.match(saved.body.error, /simulated org host/);
      assert.equal(rawInstanceUrl(), MCP_HOST);

      const connected = await connect({ instanceUrl: written });
      assert.equal(connected.status, 400);
      assert.equal(rawInstanceUrl(), MCP_HOST);
    });
  }

  test('a real connect initialises an empty MCP host', async () => {
    setRawInstanceUrl('');
    answerTokenExchange(tokenGranted());
    const res = await connect();

    assert.equal(res.status, 200, JSON.stringify(res.body));
    assert.equal(res.body.sfSettings.instanceUrl, SYNC_HOST);
    assert.equal(rawInstanceUrl(), SYNC_HOST);
  });

  for (const seeded of ['https://login.salesforce.com', 'https://test.salesforce.com', SIMULATED_ORG_INSTANCE_URL]) {
    test(`a real connect moves an uninitialised MCP host off ${seeded}, and logs it`, async () => {
      setRawInstanceUrl(seeded);
      answerTokenExchange(tokenGranted());
      const res = await connect();

      assert.equal(res.status, 200, JSON.stringify(res.body));
      assert.equal(res.body.sfSettings.instanceUrl, SYNC_HOST);
      assert.equal(rawInstanceUrl(), SYNC_HOST);
      const entry = store.getPortalAdminLogs(50).find((row) => row.action === 'CONNECT_SALESFORCE_ORG');
      assert.ok(entry?.details.includes(`"instanceUrl":{"before":"${seeded}","after":"${SYNC_HOST}"}`), entry?.details);
    });
  }

  test('a sandbox connect on a fresh install verifies MCP tokens at the sandbox', async () => {
    const sandbox = 'https://acme--uat.sandbox.my.salesforce.com';
    setRawInstanceUrl('https://login.salesforce.com');
    answerTokenExchange(tokenGranted(sandbox));
    assert.equal((await connect({ loginUrl: 'https://test.salesforce.com' })).status, 200);

    const doc = await (await fetch(`${server.baseUrl}/.well-known/oauth-protected-resource`)).json();
    assert.deepEqual(doc.authorization_servers, [sandbox]);
  });

  test('a later connect to another host does not move a host the first one set', async () => {
    setRawInstanceUrl('https://login.salesforce.com');
    answerTokenExchange(tokenGranted());
    assert.equal((await connect()).status, 200);

    answerTokenExchange(tokenGranted('https://second-org.my.salesforce.com'));
    assert.equal((await connect()).status, 200);
    assert.equal(rawInstanceUrl(), SYNC_HOST);
  });

  test('a failed connect does not initialise the MCP host', async () => {
    setRawInstanceUrl('https://login.salesforce.com');
    answerTokenExchange(tokenRefused());
    assert.equal((await connect()).status, 400);
    assert.equal(rawInstanceUrl(), 'https://login.salesforce.com');
  });

  for (const reported of [SIMULATED_ORG_INSTANCE_URL, ...SIMULATED_HOST_VARIANTS]) {
    test(`a real connect that reports ${reported} is refused and adopts it nowhere`, async () => {
      setRawInstanceUrl('https://login.salesforce.com');
      answerTokenExchange(tokenGranted(reported));
      const res = await connect();

      assert.equal(res.status, 400, JSON.stringify(res.body));
      assert.equal(rawInstanceUrl(), 'https://login.salesforce.com');
      const settings = store.getSalesforceSettings();
      assert.equal(settings.syncInstanceUrl, '');
      assert.notEqual(settings.connectionStatus, 'connected');
      assert.ok(!sf.calls.some((call) => isSimulatedOrgHost(call.url.href)), 'the access token was not sent there');
    });
  }

  test('a simulated connect does not initialise a generic login host', async () => {
    setRawInstanceUrl('https://login.salesforce.com');
    assert.equal((await connect({ authMode: 'simulated' })).status, 200);
    assert.equal(rawInstanceUrl(), 'https://login.salesforce.com');
  });

  test('a simulated connect needs no credentials from the form, and keeps none it made up', async () => {
    const res = await connect({ authMode: 'simulated', clientId: '', username: '' });

    assert.equal(res.status, 200, JSON.stringify(res.body));
    assert.equal(res.body.connected, true);
    assert.equal(res.body.sfSettings.connectionStatus, 'connected');
    assert.equal(res.body.sfSettings.connectedUser, 'mcp-metadata-sync@enterprise.my.salesforce.com');
    // The placeholders stay server-side, so switching back to a live org starts from blank fields.
    assert.equal(res.body.sfSettings.clientId, '');
    assert.equal(res.body.sfSettings.username, '');

    // Later org calls rebuild the session from these stored blank values.
    const pulled = await adminFetch(server.baseUrl, session, '/api/admin/profiles/pull-preview', { method: 'POST', body: {} });
    assert.equal(pulled.status, 200, JSON.stringify(pulled.body));
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
    store.updateSalesforceSettings({ authMode: 'jwt_bearer', connectionStatus: 'connected', connectedOrgId: ORG_ID });
    setRawInstanceUrl(SIMULATED_ORG_INSTANCE_URL);

    repairConnectInstanceUrls();

    assert.equal(rawInstanceUrl(), SIMULATED_ORG_INSTANCE_URL);
  });

  test('upgrading removes the simulated host from a jwt_bearer row whose live connect failed', () => {
    store.updateSalesforceSettings({
      authMode: 'jwt_bearer',
      connectionStatus: 'error',
      lastError: 'invalid_grant',
      connectedOrgId: '',
      loginUrl: 'https://test.salesforce.com',
    });
    setRawInstanceUrl(SIMULATED_ORG_INSTANCE_URL);

    repairConnectInstanceUrls();

    assert.equal(rawInstanceUrl(), 'https://test.salesforce.com');
    assert.equal(store.getSalesforceSettings().connectionStatus, 'error');
  });

  test('upgrading treats the simulated Org ID as no evidence of a real org, whatever the mode', () => {
    store.updateSalesforceSettings({ authMode: 'jwt_bearer', connectionStatus: 'connected', connectedOrgId: SIMULATED_ORG_ID });
    setRawInstanceUrl(SIMULATED_ORG_INSTANCE_URL);

    repairConnectInstanceUrls();

    assert.equal(rawInstanceUrl(), 'https://login.salesforce.com');
  });

  test('upgrading still repairs a simulated row that reported an expected Org ID as its own', () => {
    store.updateSalesforceSettings({ authMode: 'simulated', connectionStatus: 'connected', connectedOrgId: ORG_ID });
    setRawInstanceUrl(SIMULATED_ORG_INSTANCE_URL);

    repairConnectInstanceUrls();

    assert.equal(rawInstanceUrl(), 'https://login.salesforce.com');
  });

  test('upgrading does not put the simulated host back when the login URL is that host too', () => {
    store.updateSalesforceSettings({ authMode: 'jwt_bearer', loginUrl: SIMULATED_ORG_INSTANCE_URL });
    setRawInstanceUrl(SIMULATED_ORG_INSTANCE_URL);

    repairConnectInstanceUrls();

    assert.equal(rawInstanceUrl(), 'https://login.salesforce.com');
  });

  test('upgrading leaves any other MCP host alone on a row with no connection evidence', () => {
    repairConnectInstanceUrls();
    assert.equal(rawInstanceUrl(), MCP_HOST);
  });
});

describe('the simulated host however it is written', () => {
  for (const written of SIMULATED_HOST_VARIANTS) {
    test(`${written} is refused as the MCP host and as the login URL`, async () => {
      const asInstance = await route('', 'PUT', { instanceUrl: written });
      assert.equal(asInstance.status, 400, JSON.stringify(asInstance.body));
      assert.equal(rawInstanceUrl(), MCP_HOST);

      const asLogin = await route('', 'PUT', { loginUrl: written });
      assert.equal(asLogin.status, 400, JSON.stringify(asLogin.body));
      assert.equal(store.getSalesforceSettings().loginUrl, 'https://login.salesforce.com');

      const connected = await connect({ loginUrl: written });
      assert.equal(connected.status, 400, JSON.stringify(connected.body));
      assert.equal(store.getSalesforceSettings().loginUrl, 'https://login.salesforce.com');
    });

    test(`a real connect never posts the JWT assertion to a stored login URL of ${written}`, async () => {
      store.updateSalesforceSettings({ loginUrl: written });
      let exchanges = 0;
      answerTokenExchange(() => {
        exchanges += 1;
        return tokenGranted()();
      });

      const res = await connect();
      assert.equal(res.status, 400, JSON.stringify(res.body));
      assert.equal(exchanges, 0);
      assert.equal(rawInstanceUrl(), MCP_HOST);
    });

    test(`upgrading removes ${written} from the MCP host and from the value it falls back to`, () => {
      store.updateSalesforceSettings({ authMode: 'jwt_bearer', loginUrl: written, connectedOrgId: '' });
      setRawInstanceUrl(written);

      repairConnectInstanceUrls();

      assert.equal(rawInstanceUrl(), 'https://login.salesforce.com');
    });
  }

  test('a simulated connect still works in development', async () => {
    const res = await connect({ authMode: 'simulated' });
    assert.equal(res.status, 200, JSON.stringify(res.body));
    assert.equal(res.body.sfSettings.connectionStatus, 'connected');
    assert.equal(res.body.sfSettings.syncInstanceUrl, SIMULATED_ORG_INSTANCE_URL);
    assert.equal(rawInstanceUrl(), MCP_HOST);
  });
});

describe('isSimulatedOrgHost', () => {
  test('matches the simulated hostname with any port, case, path or trailing dot', () => {
    for (const url of [SIMULATED_ORG_INSTANCE_URL, ...SIMULATED_HOST_VARIANTS, ' https://enterprise-org.my.salesforce.com:443/x ', 'https://enterprise-org.my.salesforce.com../']) {
      assert.equal(isSimulatedOrgHost(url), true, url);
    }
  });

  test('does not match other hosts or values that are not URLs', () => {
    for (const url of [MCP_HOST, 'https://enterprise-org.my.salesforce.com.evil.example', 'https://x.enterprise-org.my.salesforce.com', 'enterprise-org.my.salesforce.com', '', 'not a url']) {
      assert.equal(isSimulatedOrgHost(url), false, url);
    }
  });
});

describe('isUninitialisedMcpTokenHost', () => {
  test('blank, generic login hosts and the simulated host are uninitialised, however they are written', () => {
    for (const host of ['', '  ', 'https://login.salesforce.com', 'https://LOGIN.salesforce.com/', 'https://test.salesforce.com', SIMULATED_ORG_INSTANCE_URL]) {
      assert.equal(isUninitialisedMcpTokenHost(host), true, JSON.stringify(host));
    }
  });

  test('any other value counts as the admin\'s', () => {
    for (const host of [MCP_HOST, 'https://login.salesforce.com.my.salesforce.com', 'https://acme--uat.sandbox.my.salesforce.com', 'not a url']) {
      assert.equal(isUninitialisedMcpTokenHost(host), false, host);
    }
  });
});

describe('a connect that does not succeed', () => {
  const newKey = () => generateSelfSignedCertificateBundle('Replacement').privateKeyPem;
  const changes = () => ({
    clientId: '3MVG9_CANDIDATE',
    username: 'candidate@example.com',
    loginUrl: 'https://test.salesforce.com',
    expectedOrgId: '00D000000000002AAA',
    enforceOrgIdLock: true,
    apiVersion: 'v61.0',
    privateKeyPem: newKey(),
    certificatePem: generateSelfSignedCertificateBundle('Replacement').certificatePem,
  });
  const stored = () => {
    const { connectionStatus, lastError, updatedAt, ...rest } = store.getSalesforceSettingsWithSecrets();
    return rest;
  };

  test('tries the submitted settings and key, not the stored ones', async () => {
    let assertion = '';
    globalThis.fetch = (async (input: any, init?: RequestInit) => {
      const url = new URL(typeof input === 'string' ? input : input.url ?? input.href);
      if (url.pathname !== '/services/oauth2/token') return sfFetch(input, init);
      assertion = new URLSearchParams(String(init?.body)).get('assertion') || '';
      return tokenRefused()();
    }) as typeof fetch;
    const candidate = changes();

    await connect(candidate);

    const [header, payload, signature] = assertion.split('.');
    const claims = JSON.parse(Buffer.from(payload, 'base64url').toString());
    assert.equal(claims.iss, candidate.clientId);
    assert.equal(claims.sub, candidate.username);
    assert.equal(claims.aud, candidate.loginUrl);
    const verifier = crypto.createVerify('RSA-SHA256').update(`${header}.${payload}`);
    assert.ok(verifier.verify(crypto.createPublicKey(candidate.privateKeyPem), signature, 'base64url'));
  });

  test('keeps the old key and settings, and records only the error', async () => {
    answerTokenExchange(tokenGranted());
    assert.equal((await connect()).status, 200);
    const connected = stored();

    answerTokenExchange(tokenRefused());
    const res = await connect(changes());

    assert.equal(res.status, 400);
    assert.match(res.body.error, /invalid_grant/);
    assert.deepEqual(stored(), connected);
    const after = store.getSalesforceSettings();
    assert.equal(after.connectionStatus, 'error');
    assert.match(after.lastError, /invalid_grant/);
  });

  test('an Org ID lock the org does not match saves nothing', async () => {
    const before = stored();
    answerTokenExchange(tokenGranted(SYNC_HOST, '00D000000000009AAA'));

    const res = await connect({ expectedOrgId: '00D000000000002AAA', enforceOrgIdLock: true });

    assert.equal(res.status, 400);
    assert.match(res.body.error, /Org ID Lock Mismatch/);
    assert.deepEqual(stored(), before);
  });

  test('a success saves the submitted settings and key', async () => {
    const candidate = { ...changes(), expectedOrgId: ORG_ID };
    answerTokenExchange(tokenGranted());

    const res = await connect(candidate);

    assert.equal(res.status, 200, JSON.stringify(res.body));
    const after = store.getSalesforceSettingsWithSecrets();
    assert.equal(after.connectionStatus, 'connected');
    assert.equal(after.clientId, candidate.clientId);
    assert.equal(after.username, candidate.username);
    assert.equal(after.loginUrl, candidate.loginUrl);
    assert.equal(after.enforceOrgIdLock, true);
    assert.equal(after.apiVersion, 'v61.0');
    assert.equal(after.privateKeyPem.trim(), candidate.privateKeyPem.trim());
  });

  for (const [name, body] of Object.entries({
    'a malformed Org ID': { expectedOrgId: 'nope', clientId: '3MVG9_CANDIDATE' },
    'a disallowed login URL': { loginUrl: 'https://evil.example.com', clientId: '3MVG9_CANDIDATE' },
    'an unparseable private key': { privateKeyPem: 'not a key', clientId: '3MVG9_CANDIDATE' },
    'a lock with no Org ID': { enforceOrgIdLock: true, clientId: '3MVG9_CANDIDATE' },
  })) {
    test(`${name} is a 400 that leaves the connection status and settings alone`, async () => {
      answerTokenExchange(tokenGranted());
      assert.equal((await connect()).status, 200);
      const before = store.getSalesforceSettingsWithSecrets();
      sf.reset();

      const res = await connect(body);

      assert.equal(res.status, 400);
      assert.equal(res.body.sfSettings.connectionStatus, 'connected');
      assert.deepEqual(store.getSalesforceSettingsWithSecrets(), before);
      assert.deepEqual(sf.calls, []);
    });
  }

  test('production still refuses simulated mode, without touching the connection', async () => {
    answerTokenExchange(tokenGranted());
    assert.equal((await connect()).status, 200);
    const mutable = config as { isProd: boolean };
    mutable.isProd = true;
    try {
      const res = await connect({ authMode: 'simulated' });
      assert.equal(res.status, 400);
      assert.match(res.body.error, /not available in production/);
    } finally {
      mutable.isProd = false;
    }
    const after = store.getSalesforceSettings();
    assert.equal(after.authMode, 'jwt_bearer');
    assert.equal(after.connectionStatus, 'connected');
  });

  test('settings saved during the token exchange are not reported as verified', async () => {
    answerTokenExchange(() => {
      store.updateSalesforceSettings({ username: 'changed-meanwhile@example.com' });
      return tokenGranted()();
    });

    const res = await connect();

    assert.equal(res.status, 400);
    assert.match(res.body.error, /changed while connecting/);
    assert.equal(store.getSalesforceSettings().connectionStatus, 'error');
    assert.equal(store.getSalesforceSettings().connectedOrgId, '');
  });
});

describe('a connection whose settings changed', () => {
  const connected = async () => {
    answerTokenExchange(tokenGranted());
    const res = await connect();
    assert.equal(res.status, 200, JSON.stringify(res.body));
    assert.equal(res.body.sfSettings.connectionStatus, 'connected');
    assert.equal(res.body.sfSettings.connectedOrgId, ORG_ID);
  };
  const assertNotVerified = (settings: any) => {
    assert.equal(settings.connectionStatus, 'not_verified');
    assert.equal(settings.connectedOrgId, '');
    assert.equal(settings.connectedUser, '');
    assert.equal(settings.syncInstanceUrl, '');
    assert.equal(settings.lastConnectedAt, null);
    assert.equal(settings.lastError, '');
    assert.equal(settings.enabled, false);
  };

  for (const [name, change] of Object.entries<() => Record<string, unknown>>({
    'the private key': () => ({ privateKeyPem: generateSelfSignedCertificateBundle('Other').privateKeyPem }),
    'the certificate': () => ({ certificatePem: generateSelfSignedCertificateBundle('Other').certificatePem }),
    'the client ID': () => ({ clientId: '3MVG9_OTHER' }),
    'the username': () => ({ username: 'other@example.com' }),
    'the login URL': () => ({ loginUrl: 'https://test.salesforce.com' }),
    'the auth mode': () => ({ authMode: 'simulated' }),
    'the expected Org ID': () => ({ expectedOrgId: '00D000000000002AAA' }),
    'the Org ID lock': () => ({ expectedOrgId: ORG_ID, enforceOrgIdLock: true }),
  })) {
    test(`saving a new value for ${name} ends the verified state`, async () => {
      await connected();
      const res = await route('', 'PUT', change());
      assert.equal(res.status, 200, JSON.stringify(res.body));
      assertNotVerified(res.body.sfSettings);
      assertNotVerified(store.getSalesforceSettings());
    });
  }

  test('turning the Org ID lock off ends the verified state', async () => {
    store.updateSalesforceSettings({ expectedOrgId: ORG_ID, enforceOrgIdLock: true });
    await connected();
    assertNotVerified((await route('', 'PUT', { enforceOrgIdLock: false })).body.sfSettings);
  });

  test('generating a new key and certificate ends the verified state', async () => {
    await connected();
    const res = await route('/generate-cert', 'POST');
    assert.equal(res.status, 200, JSON.stringify(res.body));
    assertNotVerified(res.body.sfSettings);
  });

  test('saving an earlier connection error ends it too: it was about the old settings', async () => {
    answerTokenExchange(tokenRefused());
    assert.equal((await connect()).status, 400);
    assertNotVerified((await route('', 'PUT', { clientId: '3MVG9_OTHER' })).body.sfSettings);
  });

  test('resending the same values, or changing what a connect does not prove, keeps the connection', async () => {
    await connected();
    const s = store.getSalesforceSettings();
    const same = await route('', 'PUT', {
      authMode: s.authMode,
      loginUrl: s.loginUrl,
      clientId: ` ${s.clientId} `,
      username: s.username,
      expectedOrgId: s.expectedOrgId,
      enforceOrgIdLock: s.enforceOrgIdLock,
      certificatePem: s.certificatePem,
      privateKeyPem: '',
    });
    assert.equal(same.body.sfSettings.connectionStatus, 'connected');
    assert.equal(same.body.sfSettings.connectedOrgId, ORG_ID);

    const reSent = await route('', 'PUT', { privateKeyPem: bundle.privateKeyPem });
    assert.equal(reSent.body.sfSettings.connectionStatus, 'connected');

    const other = await route('', 'PUT', { apiVersion: 'v60.0', sfdxObjectsFolderPath: '/tmp/x', instanceUrl: MCP_HOST });
    assert.equal(other.body.sfSettings.connectionStatus, 'connected');
    assert.equal(other.body.sfSettings.syncInstanceUrl, SYNC_HOST);
  });

  test('saving only the MCP token host keeps the connection and logs the change', async () => {
    await connected();
    const host = 'https://chosen-host.my.salesforce.com';

    const res = await route('', 'PUT', { instanceUrl: host });

    assert.equal(res.status, 200, JSON.stringify(res.body));
    assert.equal(res.body.sfSettings.instanceUrl, host);
    assert.equal(res.body.sfSettings.connectionStatus, 'connected');
    const entry = store.getPortalAdminLogs(50).find((row) => row.action === 'UPDATE_SF_SETTINGS');
    assert.ok(entry?.details.includes(`"instanceUrl":{"before":"${MCP_HOST}","after":"${host}"}`), entry?.details);
  });

  test('an org that was never connected stays disconnected', async () => {
    const res = await route('', 'PUT', { clientId: '3MVG9_OTHER' });
    assert.equal(res.body.sfSettings.connectionStatus, 'disconnected');
  });

  test('a save the store refuses changes nothing', async () => {
    await connected();
    assert.equal((await route('', 'PUT', { privateKeyPem: 'not a key', clientId: '3MVG9_OTHER' })).status, 400);
    const after = store.getSalesforceSettings();
    assert.equal(after.connectionStatus, 'connected');
    assert.equal(after.clientId, '3MVG9_ORIGINAL');
  });

  test('org sync refuses until the changed settings are verified, without trying them', async () => {
    await connected();
    await route('', 'PUT', { clientId: '3MVG9_OTHER' });
    let exchanged = false;
    answerTokenExchange(() => {
      exchanged = true;
      return tokenGranted()();
    });

    const res = await adminFetch(server.baseUrl, session, '/api/admin/profiles/pull-preview', { method: 'POST', body: {} });

    assert.match(res.body.error, /not active/);
    assert.equal(exchanged, false);
  });

  test('a stray enabled flag does not make a not-verified connection usable', async () => {
    await connected();
    await route('', 'PUT', { clientId: '3MVG9_OTHER' });
    store.updateSalesforceSettings({ enabled: true });

    const res = await adminFetch(server.baseUrl, session, '/api/admin/profiles/pull-preview', { method: 'POST', body: {} });

    assert.match(res.body.error, /not active/);
  });

  test('connecting again verifies the new settings', async () => {
    await connected();
    await route('', 'PUT', { clientId: '3MVG9_OTHER' });
    await connected();
    assert.equal(store.getSalesforceSettings().syncInstanceUrl, SYNC_HOST);
  });

  test('disconnect clears the connected fields and leaves the settings and MCP host', async () => {
    await connected();
    const res = await route('/disconnect', 'POST');

    assert.equal(res.status, 200);
    const after = res.body.sfSettings;
    assert.equal(after.connectionStatus, 'disconnected');
    assert.equal(after.connectedOrgId, '');
    assert.equal(after.connectedUser, '');
    assert.equal(after.syncInstanceUrl, '');
    assert.equal(after.lastConnectedAt, null);
    assert.equal(after.enabled, false);
    assert.equal(after.instanceUrl, MCP_HOST);
    assert.equal(after.clientId, '3MVG9_ORIGINAL');
    assert.equal(after.hasPrivateKey, true);
  });
});

describe('the Portal Admin log of connection changes', () => {
  const latest = (action: string) => {
    const entry = store.getPortalAdminLogs(200).find((row) => row.action === action);
    assert.ok(entry, `no ${action} entry`);
    return entry.details;
  };
  const changesIn = (details: string): Record<string, { before: unknown; after: unknown }> =>
    JSON.parse(details.match(/Changes: (\{.*?\})\. privateKeyReplaced: /)?.[1] ?? 'null');
  const notSavedIn = (details: string): Record<string, { before: unknown; after: unknown }> =>
    JSON.parse(details.match(/Not saved: (\{.*\})\. privateKeySubmitted: /)?.[1] ?? 'null');

  /** The PEM body lines as well as its markers, so a re-encoded or partial copy is caught too. */
  function assertNoSecrets(secrets: string[]) {
    const logged = JSON.stringify(store.getPortalAdminLogs(500));
    assert.ok(!logged.includes('PRIVATE KEY'));
    assert.ok(!logged.includes('BEGIN CERTIFICATE'));
    for (const secret of secrets) {
      for (const line of secret.split('\n').filter((l) => l && !l.startsWith('-----'))) {
        assert.ok(!logged.includes(line), 'a line of a PEM reached the log');
      }
    }
  }

  test('turning off the Org ID lock is identifiable', async () => {
    store.updateSalesforceSettings({ expectedOrgId: ORG_ID, enforceOrgIdLock: true });

    assert.equal((await route('', 'PUT', { enforceOrgIdLock: false })).status, 200);

    const details = latest('UPDATE_SF_SETTINGS');
    assert.deepEqual(changesIn(details).enforceOrgIdLock, { before: true, after: false });
    assert.match(details, /privateKeyReplaced: false\./);
  });

  test('a save logs the before and after of each non-secret field it changes, and no others', async () => {
    const other = generateSelfSignedCertificateBundle('Other');
    const before = store.getSalesforceSettings();

    const res = await route('', 'PUT', {
      clientId: '3MVG9_NEW',
      username: 'new@example.com',
      loginUrl: 'https://test.salesforce.com',
      instanceUrl: 'https://new-host.my.salesforce.com',
      expectedOrgId: ORG_ID,
      enforceOrgIdLock: true,
      authMode: 'simulated',
      certificatePem: other.certificatePem,
      privateKeyPem: other.privateKeyPem,
    });
    assert.equal(res.status, 200, JSON.stringify(res.body));

    const details = latest('UPDATE_SF_SETTINGS');
    assert.deepEqual(changesIn(details), {
      authMode: { before: 'jwt_bearer', after: 'simulated' },
      loginUrl: { before: before.loginUrl, after: 'https://test.salesforce.com' },
      clientId: { before: '3MVG9_ORIGINAL', after: '3MVG9_NEW' },
      username: { before: 'integration@example.com', after: 'new@example.com' },
      expectedOrgId: { before: '', after: ORG_ID },
      enforceOrgIdLock: { before: false, after: true },
      instanceUrl: { before: MCP_HOST, after: 'https://new-host.my.salesforce.com' },
      certFingerprint: { before: bundle.fingerprintSha256, after: other.fingerprintSha256 },
    });
    assert.match(details, /privateKeyReplaced: true\./);
    assertNoSecrets([bundle.privateKeyPem, other.privateKeyPem, other.certificatePem]);
  });

  test('a save that ends a verified connection logs that too', async () => {
    answerTokenExchange(tokenGranted());
    await connect();
    await route('', 'PUT', { clientId: '3MVG9_NEW' });

    const changes = changesIn(latest('UPDATE_SF_SETTINGS'));
    assert.deepEqual(changes.connectionStatus, { before: 'connected', after: 'not_verified' });
    assert.deepEqual(changes.connectedOrgId, { before: ORG_ID, after: '' });
    assert.deepEqual(changes.syncInstanceUrl, { before: SYNC_HOST, after: '' });
  });

  test('generate-cert logs the new fingerprint and the replaced key', async () => {
    const res = await route('/generate-cert', 'POST');
    assert.equal(res.status, 200, JSON.stringify(res.body));

    const details = latest('GENERATE_SF_JWT_CERT');
    assert.deepEqual(changesIn(details).certFingerprint, {
      before: bundle.fingerprintSha256,
      after: res.body.fingerprintSha256,
    });
    assert.match(details, /privateKeyReplaced: true\./);
    assertNoSecrets([store.getSalesforceSettingsWithSecrets().privateKeyPem, res.body.certificatePem]);
  });

  test('a successful connect logs what it saved, and no token', async () => {
    const other = generateSelfSignedCertificateBundle('Other');
    const token = `sync_tok_${uid()}`;
    answerTokenExchange(() =>
      Response.json({ access_token: token, instance_url: SYNC_HOST, id: `https://login.salesforce.com/id/${ORG_ID}/005000000000001AAA` })
    );

    const res = await connect({ clientId: '3MVG9_NEW', privateKeyPem: other.privateKeyPem, certificatePem: other.certificatePem });
    assert.equal(res.status, 200, JSON.stringify(res.body));

    const details = latest('CONNECT_SALESFORCE_ORG');
    const changes = changesIn(details);
    assert.deepEqual(changes.clientId, { before: '3MVG9_ORIGINAL', after: '3MVG9_NEW' });
    assert.deepEqual(changes.syncInstanceUrl, { before: '', after: SYNC_HOST });
    assert.deepEqual(changes.certFingerprint, { before: bundle.fingerprintSha256, after: other.fingerprintSha256 });
    assert.equal(changes.instanceUrl, undefined);
    assert.match(details, /privateKeyReplaced: true\./);
    assert.ok(!details.includes(token));
    assertNoSecrets([other.privateKeyPem, other.certificatePem]);
  });

  test('a failed connect logs what changed and, apart, what was tried and not saved', async () => {
    store.updateSalesforceSettings({ expectedOrgId: ORG_ID, enforceOrgIdLock: true });
    const other = generateSelfSignedCertificateBundle('Other');
    answerTokenExchange(tokenRefused());

    const res = await connect({ enforceOrgIdLock: false, privateKeyPem: other.privateKeyPem, certificatePem: other.certificatePem });
    assert.equal(res.status, 400);

    const details = latest('CONNECT_SALESFORCE_ORG_FAILED');
    assert.match(details, /invalid_grant/);
    assert.deepEqual(changesIn(details), { connectionStatus: { before: 'disconnected', after: 'error' } });
    assert.match(details, /privateKeyReplaced: false\./);
    assert.deepEqual(notSavedIn(details), {
      enforceOrgIdLock: { before: true, after: false },
      certFingerprint: { before: bundle.fingerprintSha256, after: other.fingerprintSha256 },
    });
    assert.match(details, /privateKeySubmitted: true\./);
    assertNoSecrets([other.privateKeyPem, other.certificatePem]);
  });

  test('a connect request that fails validation is logged with no changes', async () => {
    const leaked = 'not-a-real-key-but-still-secret';
    assert.equal((await connect({ privateKeyPem: leaked })).status, 400);

    const details = latest('CONNECT_SALESFORCE_ORG_FAILED');
    assert.deepEqual(changesIn(details), {});
    assert.ok(!details.includes(leaked));
  });
});
