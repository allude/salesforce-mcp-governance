import './helpers/env.js';
// Covers the Salesforce org connection added with the redesigned portal: what the settings routes
// accept, what stays out of production, and how fields removed from the org behave on tool calls.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { config } from '../src/config.js';
import { store } from '../src/db/store.js';
import { installSalesforceMock, type SalesforceMock } from './helpers/salesforceMock.js';
import {
  adminFetch,
  loginAsAdmin,
  mcpRequest,
  startTestServer,
  toolResultPayload,
  type AdminSession,
  type TestServer,
} from './helpers/server.js';

const uid = () => crypto.randomBytes(4).toString('hex');

let server: TestServer;
let session: AdminSession;
let sf: SalesforceMock;

before(async () => {
  sf = installSalesforceMock();
  server = await startTestServer();
  session = await loginAsAdmin(server.baseUrl);
});

after(async () => {
  sf.restore();
  await server.close();
});

const putSettings = (body: Record<string, unknown>) =>
  adminFetch(server.baseUrl, session, '/api/admin/sf-settings', { method: 'PUT', body });

/** Runs `fn` with the app treating this as production, for the runtime checks that read config.isProd. */
async function asProduction<T>(fn: () => Promise<T>): Promise<T> {
  const mutable = config as { isProd: boolean };
  mutable.isProd = true;
  try {
    return await fn();
  } finally {
    mutable.isProd = false;
  }
}

describe('portal sign-in', () => {
  test('there is no route that issues an admin session for a claimed Okta email', async () => {
    const res = await fetch(`${server.baseUrl}/api/admin/login-okta`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'attacker@evil.example', displayName: 'Attacker' }),
    });

    assert.equal(res.status, 401);
    assert.deepEqual(res.headers.getSetCookie(), []);
    assert.ok(!store.getPortalAdminLogs(50).some((row) => row.adminUsername === 'attacker@evil.example'));
  });
});

describe('Salesforce settings routes', () => {
  test('connection state cannot be set from a request', async () => {
    const res = await putSettings({
      enabled: true,
      connectionStatus: 'connected',
      connectedOrgId: '00D000000000001AAA',
      connectedUser: 'attacker@evil.example',
      lastError: 'x',
      certFingerprint: 'forged',
    });

    assert.equal(res.status, 200, JSON.stringify(res.body));
    assert.equal(res.body.sfSettings.enabled, false);
    assert.equal(res.body.sfSettings.connectionStatus, 'disconnected');
    assert.equal(res.body.sfSettings.connectedOrgId, '');
    assert.equal(res.body.sfSettings.connectedUser, '');
    assert.equal(res.body.sfSettings.lastError, '');
    assert.notEqual(res.body.sfSettings.certFingerprint, 'forged');
  });

  for (const loginUrl of ['https://evil.example.com', 'http://login.salesforce.com', 'https://evil%22x.my.salesforce.com']) {
    test(`a login URL of ${loginUrl} is refused by both routes, so the signed assertion is never sent there`, async () => {
      assert.equal((await putSettings({ loginUrl })).status, 400);

      sf.reset();
      const res = await adminFetch(server.baseUrl, session, '/api/admin/sf-settings/connect', {
        method: 'POST',
        body: { loginUrl },
      });
      assert.equal(res.status, 400);
      assert.deepEqual(sf.calls, []);
      assert.deepEqual(sf.nonSalesforceCalls, []);
      assert.equal(store.getSalesforceSettings().loginUrl, 'https://login.salesforce.com');
    });
  }

  test('the connect route applies the same Org ID and API version checks as the save route', async () => {
    for (const body of [{ expectedOrgId: 'not-an-org-id' }, { apiVersion: '62' }, { authMode: 'other' }]) {
      const res = await adminFetch(server.baseUrl, session, '/api/admin/sf-settings/connect', { method: 'POST', body });
      assert.equal(res.status, 400, JSON.stringify(body));
    }
  });

  test('a generated private key is stored encrypted and is never returned by the API', async () => {
    const res = await adminFetch(server.baseUrl, session, '/api/admin/sf-settings/generate-cert', { method: 'POST', body: {} });
    assert.equal(res.status, 200, JSON.stringify(res.body));
    assert.equal(res.body.sfSettings.hasPrivateKey, true);
    assert.ok(!JSON.stringify(res.body).includes('PRIVATE KEY'));

    const overview = await adminFetch(server.baseUrl, session, '/api/admin/overview');
    assert.ok(!JSON.stringify(overview.body).includes('PRIVATE KEY'));
    assert.ok(store.getSalesforceSettingsWithSecrets().privateKeyPem.includes('PRIVATE KEY'));
  });
});

describe('outside production only', () => {
  test('sample data cannot be loaded in production', async () => {
    const res = await asProduction(() =>
      adminFetch(server.baseUrl, session, '/api/admin/workspace/seed-sample', { method: 'POST', body: {} })
    );
    assert.equal(res.status, 403);
    assert.ok(!store.getGroups().some((group) => group.id === 'grp-admin'));
  });

  test('simulated mode can be neither saved nor connected in production', async () => {
    const saved = await asProduction(() => putSettings({ authMode: 'simulated' }));
    assert.equal(saved.status, 400);

    const previous = store.getSalesforceSettings().authMode;
    store.updateSalesforceSettings({ authMode: 'simulated' });
    try {
      // A value already stored, e.g. by a database first used in development
      const connected = await asProduction(() =>
        adminFetch(server.baseUrl, session, '/api/admin/sf-settings/connect', { method: 'POST', body: {} })
      );
      assert.equal(connected.status, 400);
      assert.match(connected.body.error, /not available in production/);
    } finally {
      store.updateSalesforceSettings({ authMode: previous, connectionStatus: 'disconnected', lastError: '' });
    }
  });
});

describe('Okta settings URLs', () => {
  const HTTPS_ISSUER = 'https://acme.okta.com/oauth2/default';
  const HTTPS_REDIRECT = 'https://portal.example.com/auth/okta/callback';

  const putOkta = (body: Record<string, unknown>) =>
    adminFetch(server.baseUrl, session, '/api/admin/okta', { method: 'PUT', body });

  function seedHttps(t: { after: (fn: () => void) => void }) {
    store.updateOktaConfig({ oktaDomain: 'acme.okta.com', issuer: HTTPS_ISSUER, redirectUri: HTTPS_REDIRECT });
    t.after(() => {
      store.updateOktaConfig({ oktaDomain: '', issuer: '', redirectUri: '' });
    });
  }

  for (const [name, body] of Object.entries({
    'an http issuer': { issuer: 'http://acme.okta.com/oauth2/default' },
    'an http issuer in capitals': { issuer: 'HTTP://acme.okta.com/oauth2/default' },
    'an issuer with no scheme': { issuer: 'acme.okta.com/oauth2/default' },
    'an issuer with an https prefix only': { issuer: 'https://' },
    'an issuer that is not a string': { issuer: ['https://acme.okta.com'] },
    'an http redirect URI': { redirectUri: 'http://portal.example.com/auth/okta/callback' },
    'an https issuer with an http redirect URI': {
      issuer: HTTPS_ISSUER,
      redirectUri: 'http://portal.example.com/auth/okta/callback',
    },
  })) {
    test(`production refuses ${name} and saves nothing`, async (t) => {
      seedHttps(t);
      const before = store.getOktaConfig();

      const res = await asProduction(() => putOkta({ ...body, adminGroup: 'Changed-Group' }));

      assert.equal(res.status, 400);
      assert.match(res.body.error, /must be an https:\/\/ URL in production/);
      assert.deepEqual(store.getOktaConfig(), before);
    });
  }

  test('production accepts https URLs in any letter case', async (t) => {
    seedHttps(t);
    const res = await asProduction(() =>
      putOkta({ issuer: 'HTTPS://other.okta.com/oauth2/default', redirectUri: HTTPS_REDIRECT })
    );

    assert.equal(res.status, 200);
    assert.equal(res.body.oktaSettings.issuer, 'HTTPS://other.okta.com/oauth2/default');
    assert.equal(res.body.oktaSettings.redirectUri, HTTPS_REDIRECT);
  });

  test('production accepts a save that sets no URL, or leaves the issuer to be derived', async (t) => {
    seedHttps(t);
    const unrelated = await asProduction(() => putOkta({ adminGroup: 'Other-Group' }));
    assert.equal(unrelated.status, 200);
    assert.equal(unrelated.body.oktaSettings.issuer, HTTPS_ISSUER);

    const derived = await asProduction(() => putOkta({ oktaDomain: 'http://derived.okta.com', issuer: '', redirectUri: '' }));
    assert.equal(derived.status, 200);
    assert.equal(derived.body.oktaSettings.issuer, 'https://derived.okta.com/oauth2/default');
    assert.equal(derived.body.oktaSettings.redirectUri, '');
  });

  test('outside production a local http issuer and redirect URI still work', async (t) => {
    seedHttps(t);
    const res = await putOkta({
      issuer: 'http://127.0.0.1:9999',
      redirectUri: 'http://localhost:3000/auth/okta/callback',
    });

    assert.equal(res.status, 200);
    assert.equal(res.body.oktaSettings.issuer, 'http://127.0.0.1:9999');
    assert.equal(res.body.oktaSettings.redirectUri, 'http://localhost:3000/auth/okta/callback');
  });
});

describe('fields removed from the org', () => {
  /** A Profile allowed on an object whose Legacy__c field was kept after being removed from the org. */
  function seed(t: { after: (fn: () => void) => void }) {
    const objectName = `Sync_${uid()}__c`;
    const profileId = `00e${crypto.randomBytes(6).toString('hex')}`.slice(0, 15);
    const profileName = `Sync Profile ${uid()}`;
    store.upsertObjectWithFields({
      objectName,
      fields: [
        { fieldName: 'Id' },
        { fieldName: 'Name' },
        { fieldName: 'Gone__c' },
        { fieldName: 'Legacy__c', missingInOrg: true },
      ],
    });
    const group = store.upsertGroup({
      name: `Sync Group ${uid()}`,
      allowedActions: ['describe_object', 'soql_query', 'get_record', 'create_record', 'update_record'],
      objectPermissions: [
        { objectName, canRead: true, canCreate: true, canUpdate: true, canDelete: false, allowedFields: ['Id', 'Name', 'Gone__c', 'Legacy__c'] },
      ],
    });
    store.upsertProfile(profileId, profileName);
    store.setProfileGroups(profileId, [group.id]);
    t.after(() => {
      store.deleteGroup(group.id);
      store.deleteObject(objectName);
      store.deleteProfile(profileId);
    });
    const token = `tok_${uid()}${uid()}`;
    sf.addUser(token, { userId: '005000000000001AAA', organizationId: '00D000000000001AAA', username: `u${uid()}@acme.example`, profileId, profileName });
    sf.reset();
    const call = async (name: string, args: Record<string, unknown>) =>
      toolResultPayload((await mcpRequest(server.baseUrl, token, 'tools/call', { name, arguments: { objectName, ...args } })).body);
    const sent = (method: string) => sf.calls.filter((c) => c.method === method && c.url.pathname.includes('/services/data/'));
    return { objectName, call, sent };
  }

  test('soql_query leaves a kept field out of the SELECT and reports it', async (t) => {
    const { call, sent } = seed(t);
    const payload = await call('soql_query', { fields: ['Id', 'Legacy__c'] });
    assert.deepEqual(payload.ignoredMissingFields, ['Legacy__c']);
    assert.deepEqual(payload.fieldsQueried, ['Id']);
    const soql = sent('GET').map((c) => c.url.searchParams.get('q') || '').find((q) => q.includes('FROM Sync_')) || '';
    assert.match(soql, /^SELECT Id FROM /);
  });

  test('a kept field does not widen access: fields outside the allowlist are still denied', async (t) => {
    const { call, sent } = seed(t);
    const payload = await call('soql_query', { fields: ['Id', 'Secret__c'] });
    assert.equal(payload.error, 'ACCESS_DENIED');
    assert.ok(!sent('GET').some((c) => (c.url.searchParams.get('q') || '').includes('Secret__c')));
  });

  test('soql_query retries once without a field the org reports as deleted, and only a selected field qualifies', async (t) => {
    const { call, sent } = seed(t);
    const mocked = globalThis.fetch;
    t.after(() => {
      globalThis.fetch = mocked;
    });
    globalThis.fetch = (async (input: any, init?: RequestInit) => {
      const url = new URL(typeof input === 'string' ? input : input.url ?? input.href);
      const soql = url.searchParams.get('q') || '';
      if (/Gone__c/.test(soql)) {
        // Recorded by the inner mock first, so the attempt is visible in sf.calls
        await mocked(input, init);
        return new Response(
          JSON.stringify([{ errorCode: 'INVALID_FIELD', message: "No such column 'Gone__c' on entity" }]),
          { status: 400, headers: { 'Content-Type': 'application/json' } }
        );
      }
      return mocked(input, init);
    }) as typeof fetch;

    const retried = await call('soql_query', { fields: ['Id', 'Gone__c'] });
    assert.deepEqual(retried.ignoredMissingFields, ['Gone__c']);
    assert.deepEqual(retried.fieldsQueried, ['Id']);

    sf.reset();
    const inWhere = await call('soql_query', { fields: ['Id'], whereClause: "Gone__c = 'x'" });
    assert.ok(inWhere.error, JSON.stringify(inWhere));
    assert.equal(sent('GET').filter((c) => (c.url.searchParams.get('q') || '').includes('FROM Sync_')).length, 1, 'no retry');
  });

  test('create_record and update_record write to Salesforce without the kept field', async (t) => {
    const { call, sent } = seed(t);

    const created = await call('create_record', { fields: { Name: 'A', Legacy__c: 'x' } });
    assert.equal(created.status, 'SUCCESS', JSON.stringify(created));
    assert.deepEqual(created.ignoredMissingFields, ['Legacy__c']);
    assert.deepEqual(sent('POST').at(-1)?.body, { Name: 'A' });
    assert.ok(created.recordId, 'the id Salesforce returned, not an invented one');

    const updated = await call('update_record', { recordId: '001000000000001AAA', fields: { Name: 'B', Legacy__c: 'x' } });
    assert.equal(updated.status, 'SUCCESS', JSON.stringify(updated));
    assert.deepEqual(sent('PATCH').at(-1)?.body, { Name: 'B' });
  });

  test('a write whose every field was removed from the org fails instead of sending an empty body', async (t) => {
    const { call, sent } = seed(t);
    const payload = await call('create_record', { fields: { Legacy__c: 'x' } });
    assert.ok(payload.error, JSON.stringify(payload));
    assert.deepEqual(sent('POST'), []);
  });

  test('describe_object separates allowed fields from those still in the org', async (t) => {
    const { call } = seed(t);
    const payload = await call('describe_object', {});
    assert.ok(payload.allowedFields.includes('Legacy__c'));
    assert.ok(!payload.activeOrgFields.includes('Legacy__c'));
  });
});
