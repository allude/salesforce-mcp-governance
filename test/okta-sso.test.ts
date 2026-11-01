import './helpers/env.js';
// Covers the Okta OIDC callback in src/security/adminAuth.ts against a fake Okta issuer on a local
// port: the ID token nonce check, and what an error callback writes to the Portal Admin log.
import { after, before, beforeEach, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import * as jose from 'jose';
import { store } from '../src/db/store.js';
import { startTestServer, type TestServer } from './helpers/server.js';

const CLIENT_ID = 'okta-test-client';
const ADMIN_GROUP = 'MCP-Admins';

let server: TestServer;
let okta: http.Server;
let issuer = '';
let signingKey: jose.KeyLike;
let publicJwk: jose.JWK;
/** The id_token the fake token endpoint returns next. */
let nextIdToken = '';

before(async () => {
  const keys = await jose.generateKeyPair('RS256');
  signingKey = keys.privateKey;
  publicJwk = { ...(await jose.exportJWK(keys.publicKey)), kid: 'test-key', alg: 'RS256', use: 'sig' };

  okta = http.createServer((req, res) => {
    const send = (status: number, body: unknown) => {
      res.writeHead(status, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(body));
    };
    if (req.url === '/.well-known/openid-configuration') {
      return send(200, {
        issuer,
        authorization_endpoint: `${issuer}/v1/authorize`,
        token_endpoint: `${issuer}/v1/token`,
        jwks_uri: `${issuer}/v1/keys`,
      });
    }
    if (req.url === '/v1/token' && req.method === 'POST') {
      req.resume();
      return req.on('end', () => send(200, { token_type: 'Bearer', id_token: nextIdToken, access_token: 'unused' }));
    }
    if (req.url === '/v1/keys') return send(200, { keys: [publicJwk] });
    send(404, { error: 'not_found' });
  });
  await new Promise<void>((resolve) => okta.listen(0, '127.0.0.1', resolve));
  issuer = `http://127.0.0.1:${(okta.address() as AddressInfo).port}`;

  store.updateOktaConfig({ enabled: true, issuer, clientId: CLIENT_ID, clientSecret: 'okta-test-secret', adminGroup: ADMIN_GROUP });
  server = await startTestServer();
});

after(async () => {
  store.updateOktaConfig({ enabled: false });
  await server.close();
  await new Promise<void>((resolve) => okta.close(() => resolve()));
});

beforeEach(() => {
  nextIdToken = '';
});

/** Starts a sign-in like a browser would: returns the login state cookie and the state and nonce sent to Okta. */
async function startLogin(): Promise<{ cookie: string; state: string; nonce: string }> {
  const res = await fetch(`${server.baseUrl}/auth/okta/login`, { redirect: 'manual' });
  assert.equal(res.status, 302);
  const authorize = new URL(res.headers.get('location') || '');
  assert.equal(`${authorize.origin}${authorize.pathname}`, `${issuer}/v1/authorize`);
  const cookie = res.headers.getSetCookie().find((c) => c.startsWith('sf_mcp_oidc_flow='));
  assert.ok(cookie, 'login state cookie');
  return {
    cookie: cookie.split(';')[0],
    state: authorize.searchParams.get('state') || '',
    nonce: authorize.searchParams.get('nonce') || '',
  };
}

function callback(query: Record<string, string>, cookie?: string) {
  return fetch(`${server.baseUrl}/auth/okta/callback?${new URLSearchParams(query)}`, {
    redirect: 'manual',
    headers: cookie ? { Cookie: cookie } : {},
  });
}

function signIdToken(claims: Record<string, unknown>): Promise<string> {
  return new jose.SignJWT({ email: 'okta.admin@acme.example', groups: [ADMIN_GROUP], ...claims })
    .setProtectedHeader({ alg: 'RS256', kid: 'test-key' })
    .setIssuer(issuer)
    .setAudience(CLIENT_ID)
    .setSubject('00u000000000001')
    .setIssuedAt()
    .setExpirationTime('5m')
    .sign(signingKey);
}

const sessionCookieOf = (res: Response) =>
  res.headers.getSetCookie().find((c) => c.startsWith('sf_mcp_admin_session=') && !/Expires=Thu, 01 Jan 1970/i.test(c));

/** Portal Admin log rows written while `fn` ran. */
async function newLogRows(fn: () => Promise<unknown>) {
  const before = new Set(store.getPortalAdminLogs(500).map((row) => row.id));
  await fn();
  return store.getPortalAdminLogs(500).filter((row) => !before.has(row.id));
}

describe('ID token nonce', () => {
  test('control: an ID token carrying this login\'s nonce signs the admin in', async () => {
    const login = await startLogin();
    nextIdToken = await signIdToken({ nonce: login.nonce });

    const res = await callback({ code: 'code-1', state: login.state }, login.cookie);

    assert.equal(res.status, 302);
    assert.equal(res.headers.get('location'), '/');
    assert.ok(sessionCookieOf(res), 'a session cookie is issued');
  });

  const rejected: Record<string, (nonce: string, otherNonce: string) => Record<string, unknown>> = {
    'without a nonce': () => ({}),
    'with a made-up nonce': () => ({ nonce: crypto.randomBytes(16).toString('base64url') }),
    'with the nonce of another login (replayed token)': (_nonce, otherNonce) => ({ nonce: otherNonce }),
    'with a non-string nonce': (nonce) => ({ nonce: [nonce] }),
  };

  for (const [label, claims] of Object.entries(rejected)) {
    test(`an otherwise valid ID token ${label} is refused with sso_failed and no session`, async () => {
      const other = await startLogin();
      const login = await startLogin();
      nextIdToken = await signIdToken(claims(login.nonce, other.nonce));

      let res!: Response;
      const rows = await newLogRows(async () => {
        res = await callback({ code: 'code-2', state: login.state }, login.cookie);
      });

      assert.equal(res.status, 302);
      assert.equal(res.headers.get('location'), '/?auth_error=sso_failed');
      assert.equal(sessionCookieOf(res), undefined);
      assert.deepEqual(rows.map((row) => row.action), ['OKTA_LOGIN_FAILED']);
      assert.match(rows[0].details, /nonce/i);
    });
  }
});

describe('Okta error callbacks', () => {
  const lure = 'Sign in at https://evil.example/okta instead';

  test('an error for a login this browser started is logged with Okta\'s text (printable, at most 300 characters)', async () => {
    const login = await startLogin();
    const description = `${lure}\r\n${'x'.repeat(1000)}`;

    let res!: Response;
    const rows = await newLogRows(async () => {
      res = await callback({ error: 'access_denied', error_description: description, state: login.state }, login.cookie);
    });

    assert.equal(res.status, 302);
    assert.equal(res.headers.get('location'), '/?auth_error=okta_error');
    assert.deepEqual(rows.map((row) => row.action), ['OKTA_LOGIN_FAILED']);
    assert.ok(rows[0].details.includes(lure), rows[0].details);
    assert.match(rows[0].details, /^[\x20-\x7e]+$/);
    assert.ok(rows[0].details.length < 400, `details length ${rows[0].details.length}`);
  });

  const unverified: Record<string, () => Promise<{ query: Record<string, string>; cookie?: string }>> = {
    'without a login state cookie': async () => ({ query: { error: 'access_denied', error_description: lure } }),
    'with a state that does not match the cookie': async () => {
      const login = await startLogin();
      return { query: { error: 'access_denied', error_description: lure, state: 'not-the-state' }, cookie: login.cookie };
    },
    'with a forged login state cookie': async () => ({
      query: { error: 'access_denied', error_description: lure, state: 'abc' },
      cookie: 'sf_mcp_oidc_flow=eyJhbGciOiJub25lIn0.eyJzdGF0ZSI6ImFiYyJ9.',
    }),
  };

  for (const [label, build] of Object.entries(unverified)) {
    test(`an error callback ${label} redirects with invalid_callback and does not log the error text`, async () => {
      const { query, cookie } = await build();

      let res!: Response;
      const rows = await newLogRows(async () => {
        res = await callback(query, cookie);
      });

      assert.equal(res.status, 302);
      assert.equal(res.headers.get('location'), '/?auth_error=invalid_callback');
      assert.deepEqual(rows.map((row) => row.action), ['OKTA_LOGIN_FAILED']);
      assert.ok(!rows[0].details.includes('evil.example'), rows[0].details);
    });
  }
});
