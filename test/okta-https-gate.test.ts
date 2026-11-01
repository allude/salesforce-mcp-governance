import './helpers/env.js';
// In production the Okta issuer and redirect URI must be https whatever put them there: the settings
// route judges the merged result of a save, and sign-in refuses an http issuer already stored, because
// a row can predate the route check or be seeded from OKTA_ISSUER.
import { after, afterEach, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { config } from '../src/config.js';
import { store } from '../src/db/store.js';
import { adminFetch, loginAsAdmin, startTestServer, type AdminSession, type TestServer } from './helpers/server.js';

const HTTP_ISSUER = 'http://okta.internal/oauth2/default';
const HTTPS_ISSUER = 'https://acme.okta.com/oauth2/default';
const HTTP_REDIRECT = 'http://portal.example.com/auth/okta/callback';
const HTTPS_REDIRECT = 'https://portal.example.com/auth/okta/callback';

let server: TestServer;
let session: AdminSession;
/** A plain-http issuer that counts what reaches it, since a refused sign-in must send it nothing. */
let fakeIssuer: http.Server;
let fakeIssuerUrl = '';
let fakeIssuerRequests = 0;

before(async () => {
  fakeIssuer = http.createServer((req, res) => {
    fakeIssuerRequests += 1;
    req.resume();
    res.writeHead(404);
    res.end();
  });
  await new Promise<void>((resolve) => fakeIssuer.listen(0, '127.0.0.1', resolve));
  fakeIssuerUrl = `http://127.0.0.1:${(fakeIssuer.address() as AddressInfo).port}`;
  server = await startTestServer();
  session = await loginAsAdmin(server.baseUrl);
});

after(async () => {
  await server.close();
  await new Promise<void>((resolve) => fakeIssuer.close(() => resolve()));
});

afterEach(() => {
  store.updateOktaConfig({ enabled: false, oktaDomain: '', issuer: '', clientId: '', redirectUri: '' });
});

async function asProduction<T>(fn: () => Promise<T>): Promise<T> {
  const mutable = config as { isProd: boolean };
  mutable.isProd = true;
  try {
    return await fn();
  } finally {
    mutable.isProd = false;
  }
}

const putOkta = (body: Record<string, unknown>) =>
  adminFetch(server.baseUrl, session, '/api/admin/okta', { method: 'PUT', body });

describe('saving Okta settings in production', () => {
  for (const [name, stored] of Object.entries({
    'an http issuer': { issuer: HTTP_ISSUER, redirectUri: HTTPS_REDIRECT },
    'an http redirect URI': { issuer: HTTPS_ISSUER, redirectUri: HTTP_REDIRECT },
  })) {
    test(`enabling over a stored ${name} is refused and saves nothing`, async () => {
      store.updateOktaConfig({ enabled: false, clientId: 'client', ...stored });
      const before = store.getOktaConfig();

      const res = await asProduction(() => putOkta({ enabled: true }));

      assert.equal(res.status, 400);
      assert.match(res.body.error, /must be an https:\/\/ URL in production/);
      assert.deepEqual(store.getOktaConfig(), before);
    });

    test(`an unrelated save that stays enabled over a stored ${name} is refused`, async () => {
      store.updateOktaConfig({ enabled: true, clientId: 'client', ...stored });
      const before = store.getOktaConfig();

      const res = await asProduction(() => putOkta({ adminGroup: 'Changed-Group' }));

      assert.equal(res.status, 400);
      assert.deepEqual(store.getOktaConfig(), before);
    });
  }

  test('an admin can turn Okta off with bad stored values, as the portal sends that save', async () => {
    store.updateOktaConfig({ enabled: true, clientId: 'client', oktaDomain: 'acme.okta.com', issuer: HTTP_ISSUER, redirectUri: HTTP_REDIRECT });

    const res = await asProduction(() =>
      putOkta({ enabled: false, oktaDomain: 'acme.okta.com', clientId: 'client', redirectUri: HTTP_REDIRECT })
    );

    assert.equal(res.status, 200, JSON.stringify(res.body));
    assert.equal(res.body.oktaSettings.enabled, false);
    assert.equal(store.getOktaConfig().issuer, HTTP_ISSUER);
  });

  test('turning Okta off does not let a new http value in with it', async () => {
    store.updateOktaConfig({ enabled: true, clientId: 'client', issuer: HTTPS_ISSUER });

    const res = await asProduction(() => putOkta({ enabled: false, issuer: HTTP_ISSUER }));

    assert.equal(res.status, 400);
    assert.equal(store.getOktaConfig().enabled, true);
  });

  test('blank values that derive https from the domain are accepted when enabling', async () => {
    store.updateOktaConfig({ clientId: 'client', issuer: HTTP_ISSUER, redirectUri: HTTP_REDIRECT });

    const res = await asProduction(() =>
      putOkta({ enabled: true, oktaDomain: 'acme.okta.com', issuer: '', redirectUri: '' })
    );

    assert.equal(res.status, 200, JSON.stringify(res.body));
    assert.equal(res.body.oktaSettings.issuer, HTTPS_ISSUER);
    assert.equal(res.body.oktaSettings.redirectUri, '');
  });

  test('changing the domain replaces a stored http issuer, so the result is judged, not the old value', async () => {
    store.updateOktaConfig({ clientId: 'client', oktaDomain: 'old.okta.com', issuer: HTTP_ISSUER });

    const res = await asProduction(() => putOkta({ enabled: true, oktaDomain: 'acme.okta.com' }));

    assert.equal(res.status, 200, JSON.stringify(res.body));
    assert.equal(res.body.oktaSettings.issuer, HTTPS_ISSUER);
  });

  test('control: outside production an http issuer can be enabled', async () => {
    store.updateOktaConfig({ clientId: 'client', issuer: HTTP_ISSUER, redirectUri: HTTP_REDIRECT });

    const res = await putOkta({ enabled: true });

    assert.equal(res.status, 200);
    assert.equal(res.body.oktaSettings.enabled, true);
  });
});

describe('signing in with Okta in production', () => {
  /** Portal Admin log rows written while `fn` ran. */
  async function newLogRows(fn: () => Promise<unknown>) {
    const seen = new Set(store.getPortalAdminLogs(500).map((row) => row.id));
    await fn();
    return store.getPortalAdminLogs(500).filter((row) => !seen.has(row.id));
  }

  function assertRefused(res: Response, rows: Awaited<ReturnType<typeof newLogRows>>) {
    assert.equal(res.status, 302);
    assert.equal(res.headers.get('location'), '/?auth_error=sso_failed');
    assert.equal(rows.length, 1);
    assert.equal(rows[0].action, 'OKTA_LOGIN_FAILED');
    assert.match(rows[0].details, /not an https:\/\/ URL/);
  }

  const login = () => fetch(`${server.baseUrl}/auth/okta/login`, { redirect: 'manual' });

  /** A login started outside production, so the callback gets past its state checks to the gate. */
  async function startedLogin(): Promise<{ cookie: string; state: string }> {
    const res = await login();
    assert.equal(res.status, 302);
    const state = new URL(res.headers.get('location') || '').searchParams.get('state') || '';
    const cookie = res.headers.getSetCookie().find((c) => c.startsWith('sf_mcp_oidc_flow='));
    assert.ok(cookie && state, 'login state');
    return { cookie: cookie.split(';')[0], state };
  }

  test('login with an http issuer is refused with an audit row, before reaching the issuer', async () => {
    store.updateOktaConfig({ enabled: true, clientId: 'client', issuer: fakeIssuerUrl });
    const reached = fakeIssuerRequests;
    let res!: Response;

    const rows = await newLogRows(async () => {
      res = await asProduction(login);
    });

    assertRefused(res, rows);
    assert.equal(fakeIssuerRequests, reached);
    assert.ok(!res.headers.getSetCookie().some((c) => c.startsWith('sf_mcp_oidc_flow=')), 'no login is started');
  });

  test('callback with an http issuer is refused with an audit row, before any code exchange', async () => {
    store.updateOktaConfig({ enabled: true, clientId: 'client', clientSecret: 'okta-test-secret', issuer: fakeIssuerUrl });
    const { cookie, state } = await startedLogin();
    const reached = fakeIssuerRequests;
    let res!: Response;

    const rows = await newLogRows(async () => {
      res = await asProduction(() =>
        fetch(`${server.baseUrl}/auth/okta/callback?${new URLSearchParams({ code: 'code-1', state })}`, {
          redirect: 'manual',
          headers: { Cookie: cookie },
        })
      );
    });

    assertRefused(res, rows);
    assert.equal(fakeIssuerRequests, reached, 'neither discovery nor the token endpoint is called');
  });

  test('control: login with an https issuer still redirects to Okta', async () => {
    store.updateOktaConfig({ enabled: true, clientId: 'client', issuer: HTTPS_ISSUER });
    const realFetch = globalThis.fetch;
    // Discovery is best-effort, so answering it with a failure keeps this test off the network.
    globalThis.fetch = (async (input: any, init?: RequestInit) =>
      String(input).startsWith(HTTPS_ISSUER) ? new Response('', { status: 503 }) : realFetch(input, init)) as typeof fetch;
    try {
      const res = await asProduction(login);
      assert.equal(res.status, 302);
      assert.match(res.headers.get('location') || '', /^https:\/\/acme\.okta\.com\/oauth2\/default\/v1\/authorize\?/);
    } finally {
      globalThis.fetch = realFetch;
    }
  });
});
