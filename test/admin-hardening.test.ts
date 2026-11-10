import './helpers/env.js';
// The portal sign-in hardening: authenticator codes (RFC 6238) on password accounts, production's
// break-glass rules, server-side sessions that logout, idle time and account removal end, step-up
// confirmation before security changes, and the backend's loopback-only binding.
import { after, before, describe, test, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { config } from '../src/config.js';
import { store } from '../src/db/store.js';
import { isLoopbackHost } from '../src/index.js';
import { base32Encode, generateTotpSecret, totpCode, totpStep, verifyTotp } from '../src/security/totp.js';
import { adminFetch, loginAsAdmin, startTestServer, type AdminSession, type TestServer } from './helpers/server.js';

let server: TestServer;

before(async () => {
  server = await startTestServer();
});

after(async () => {
  await server.close();
});

const uid = () => crypto.randomBytes(5).toString('hex');

// Every sign-in names its own client, so this file's attempts never share a rate-limit bucket.
let clientCounter = 0;
const nextClientIp = () => {
  clientCounter += 1;
  return `203.0.113.${1 + (clientCounter % 250)}`;
};

/** A throwaway password account, optionally with an authenticator; removed after the test. */
function createAccount(t: TestContext, options: { totp?: boolean } = {}) {
  const username = `hardening.${uid()}`;
  const password = crypto.randomBytes(18).toString('base64url');
  store.upsertPortalUser({ username, displayName: 'Hardening Test', password, role: 'Admin' });
  const secret = options.totp ? generateTotpSecret() : '';
  if (secret) store.setPortalUserTotp(username, secret);
  t.after(() => {
    try {
      store.deletePortalUser(username);
    } catch {
      // already removed by the test
    }
  });
  return { username, password, secret };
}

async function signIn(username: string, password: string, totp?: string) {
  const res = await fetch(`${server.baseUrl}/api/admin/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Forwarded-For': nextClientIp() },
    body: JSON.stringify({ username, password, ...(totp !== undefined ? { totp } : {}) }),
  });
  const text = await res.text();
  let body: any = text;
  try {
    body = JSON.parse(text);
  } catch {
    // leave as text
  }
  const cookie = (res.headers.get('set-cookie') || '').split(';')[0];
  return { status: res.status, body, headers: res.headers, session: { cookie, csrfToken: body?.csrfToken ?? '' } as AdminSession };
}

/** The current code, then the code of the step after it (a code is single-use, so a second sign-in needs another step). */
const codeNow = (secret: string) => totpCode(secret, totpStep());
const codeNext = (secret: string) => totpCode(secret, totpStep() + 1);

/** Runs `fn` with Date.now() shifted by `offsetMs`; the server shares this process and its clock. */
async function withClockOffset<T>(offsetMs: number, fn: () => Promise<T>): Promise<T> {
  const realNow = Date.now;
  Date.now = () => realNow() + offsetMs;
  try {
    return await fn();
  } finally {
    Date.now = realNow;
  }
}

/** Runs the rest of the test as production (or with other config flags); restored afterwards. */
function withConfig(t: TestContext, overrides: Partial<{ isProd: boolean; breakGlassEnabled: boolean }>): void {
  const mutable = config as unknown as Record<string, unknown>;
  const previous = Object.fromEntries(Object.keys(overrides).map((key) => [key, mutable[key]]));
  Object.assign(mutable, overrides);
  t.after(() => Object.assign(mutable, previous));
}

async function sessionIsValid(session: AdminSession): Promise<boolean> {
  const res = await adminFetch(server.baseUrl, session, '/api/admin/overview');
  return res.status === 200;
}

// ---------------------------------------------------------------------------------------------
// TOTP (RFC 6238)
// ---------------------------------------------------------------------------------------------

describe('TOTP codes', () => {
  // RFC 6238 appendix B, SHA-1, with the last six of its eight digits.
  const RFC_SECRET = base32Encode(Buffer.from('12345678901234567890', 'ascii'));
  const vectors: Array<[number, string]> = [
    [59, '287082'],
    [1111111109, '081804'],
    [1111111111, '050471'],
    [1234567890, '005924'],
    [2000000000, '279037'],
    [20000000000, '353130'],
  ];

  test('match the RFC 6238 SHA-1 test vectors', () => {
    for (const [seconds, expected] of vectors) {
      assert.equal(totpCode(RFC_SECRET, totpStep(seconds * 1000)), expected, `T=${seconds}`);
    }
  });

  test('verifyTotp accepts one step of clock drift either way, refuses two, and never the same step twice', () => {
    const now = 1_700_000_000_000;
    const step = totpStep(now);
    assert.equal(verifyTotp(RFC_SECRET, totpCode(RFC_SECRET, step), 0, now), step);
    assert.equal(verifyTotp(RFC_SECRET, totpCode(RFC_SECRET, step - 1), 0, now), step - 1);
    assert.equal(verifyTotp(RFC_SECRET, totpCode(RFC_SECRET, step + 1), 0, now), step + 1);
    assert.equal(verifyTotp(RFC_SECRET, totpCode(RFC_SECRET, step - 2), 0, now), null);
    assert.equal(verifyTotp(RFC_SECRET, totpCode(RFC_SECRET, step + 2), 0, now), null);
    assert.equal(verifyTotp(RFC_SECRET, totpCode(RFC_SECRET, step), step, now), null, 'replay of the last used step');
    assert.equal(verifyTotp(RFC_SECRET, totpCode(RFC_SECRET, step - 1), step, now), null, 'an older step after a newer one');
    for (const junk of ['', '12345', '1234567', 'abcdef', ' 123456', null, undefined, 123456]) {
      assert.equal(verifyTotp(RFC_SECRET, junk as any, 0, now), null, String(junk));
    }
  });
});

describe('password sign-in with an authenticator', () => {
  test('an enrolled account needs its current code; a wrong or reused code is refused with the same answer', async (t) => {
    const account = createAccount(t, { totp: true });

    const passwordOnly = await signIn(account.username, account.password);
    assert.equal(passwordOnly.status, 401, JSON.stringify(passwordOnly.body));
    const wrongCode = await signIn(account.username, account.password, codeNow(account.secret) === '000000' ? '111111' : '000000');
    assert.equal(wrongCode.status, 401);
    assert.deepEqual(wrongCode.body, passwordOnly.body, 'a guesser cannot tell a right password from a wrong code');

    const code = codeNow(account.secret);
    const accepted = await signIn(account.username, account.password, code);
    assert.equal(accepted.status, 200, JSON.stringify(accepted.body));
    assert.equal(accepted.body.user.authMethod, 'local_bootstrap');
    assert.equal(accepted.body.user.totpEnrolled, true);

    const replayed = await signIn(account.username, account.password, code);
    assert.equal(replayed.status, 401, 'a code works once');
  });

  test('an account without an authenticator signs in with its password outside production only', async (t) => {
    const account = createAccount(t);
    assert.equal((await signIn(account.username, account.password)).status, 200);

    withConfig(t, { isProd: true });
    const production = await signIn(account.username, account.password);
    assert.equal(production.status, 401, 'production asks every password sign-in for a code');
  });

  test('a throttled account still signs in with its password and a valid code, but not with a password alone', async (t) => {
    const account = createAccount(t, { totp: true });
    for (let i = 0; i < 6; i++) await signIn(account.username, 'wrong-password', '000000');

    const throttled = await signIn(account.username, account.password);
    assert.equal(throttled.status, 429, JSON.stringify(throttled.body));
    assert.ok(Number(throttled.headers.get('retry-after')) >= 1);

    const withCode = await signIn(account.username, account.password, codeNow(account.secret));
    assert.equal(withCode.status, 200, JSON.stringify(withCode.body));
  });

  test('production with Okta on refuses password sign-in unless BREAK_GLASS_ENABLED, and logs a break-glass sign-in', async (t) => {
    const account = createAccount(t, { totp: true });
    const okta = store.getOktaConfig();
    store.updateOktaConfig({ enabled: true, adminGroup: okta.adminGroup || 'MCP-Admins' });
    t.after(() => store.updateOktaConfig({ enabled: okta.enabled, adminGroup: okta.adminGroup }));
    withConfig(t, { isProd: true, breakGlassEnabled: false });

    const closed = await signIn(account.username, account.password, codeNow(account.secret));
    assert.equal(closed.status, 403, JSON.stringify(closed.body));
    assert.match(String(closed.body.error), /BREAK_GLASS_ENABLED/);
    const sessionInfo = await (await fetch(`${server.baseUrl}/api/admin/session`)).json();
    assert.equal(sessionInfo.passwordLogin.enabled, false);
    assert.equal(sessionInfo.passwordLogin.totpRequired, true);

    withConfig(t, { breakGlassEnabled: true });
    const breakGlass = await signIn(account.username, account.password, codeNext(account.secret));
    assert.equal(breakGlass.status, 200, JSON.stringify(breakGlass.body));
    const row = store
      .getPortalAdminLogs(20)
      .find((r) => r.action === 'LOGIN_SUCCESS' && r.adminUsername === account.username);
    assert.ok(row && /break-glass/.test(row.details), row?.details);
  });
});

describe('authenticator enrollment', () => {
  test('setup issues a pending secret that takes effect only once confirmed with one of its codes', async (t) => {
    const account = createAccount(t);
    const { session } = await signIn(account.username, account.password);

    const confirmFirst = await adminFetch(server.baseUrl, session, '/api/admin/account/totp/confirm', {
      method: 'POST',
      body: { code: '123456' },
    });
    assert.equal(confirmFirst.status, 400, 'nothing to confirm yet');

    const setup = await adminFetch(server.baseUrl, session, '/api/admin/account/totp/setup', { method: 'POST' });
    assert.equal(setup.status, 200, JSON.stringify(setup.body));
    assert.match(setup.body.secret, /^[A-Z2-7]{32}$/);
    assert.match(setup.body.otpauthUri, /^otpauth:\/\/totp\//);
    assert.equal(store.getPortalUserTotp(account.username), null, 'not active until confirmed');

    const wrong = await adminFetch(server.baseUrl, session, '/api/admin/account/totp/confirm', {
      method: 'POST',
      body: { code: totpCode(setup.body.secret, totpStep()) === '000000' ? '111111' : '000000' },
    });
    assert.equal(wrong.status, 400);

    const confirmed = await adminFetch(server.baseUrl, session, '/api/admin/account/totp/confirm', {
      method: 'POST',
      body: { code: totpCode(setup.body.secret, totpStep()) },
    });
    assert.equal(confirmed.status, 200, JSON.stringify(confirmed.body));
    const me = await adminFetch(server.baseUrl, session, '/api/admin/session');
    assert.equal(me.body.user.totpEnrolled, true);

    // The password alone no longer signs in; a later code does.
    assert.equal((await signIn(account.username, account.password)).status, 401);
    assert.equal((await signIn(account.username, account.password, codeNext(setup.body.secret))).status, 200);
  });
});

// ---------------------------------------------------------------------------------------------
// Server-side sessions
// ---------------------------------------------------------------------------------------------

describe('admin sessions', () => {
  test('logout revokes the session: a copy of the cookie stops working', async (t) => {
    const account = createAccount(t);
    const { session } = await signIn(account.username, account.password);
    assert.ok(await sessionIsValid(session));

    const logout = await adminFetch(server.baseUrl, session, '/api/admin/logout', { method: 'POST' });
    assert.equal(logout.status, 200);
    assert.equal(await sessionIsValid(session), false);
  });

  test('a session idle for more than an hour ends; one used within the hour continues', async (t) => {
    const account = createAccount(t);
    const { session } = await signIn(account.username, account.password);

    assert.ok(await withClockOffset(50 * 60 * 1000, () => sessionIsValid(session)), 'used after 50 minutes');
    assert.ok(await withClockOffset(100 * 60 * 1000, () => sessionIsValid(session)), '50 minutes after its last use');
    assert.equal(await withClockOffset(170 * 60 * 1000, () => sessionIsValid(session)), false, '70 minutes idle');
  });

  test('a session ends 8 hours after sign-in however active it is', async (t) => {
    const account = createAccount(t);
    const { session } = await signIn(account.username, account.password);
    for (let minutes = 50; minutes < 8 * 60; minutes += 50) {
      assert.ok(await withClockOffset(minutes * 60 * 1000, () => sessionIsValid(session)), `${minutes} minutes in`);
    }
    assert.equal(await withClockOffset((8 * 60 + 5) * 60 * 1000, () => sessionIsValid(session)), false);
  });

  test('a new password ends the account\'s other sessions, but not the session that set it', async (t) => {
    const account = createAccount(t);
    const elsewhere = (await signIn(account.username, account.password)).session;
    const here = (await signIn(account.username, account.password)).session;

    const res = await adminFetch(server.baseUrl, here, '/api/admin/portal-users', {
      method: 'POST',
      body: { username: account.username, password: crypto.randomBytes(18).toString('base64url') },
    });
    assert.equal(res.status, 200, JSON.stringify(res.body));
    assert.equal(await sessionIsValid(elsewhere), false, 'the other session ended');
    assert.ok(await sessionIsValid(here), 'the session that made the change continues');
  });

  test('removing a portal user ends that user\'s sessions at once', async (t) => {
    const removed = createAccount(t);
    const admin = createAccount(t);
    const removedSession = (await signIn(removed.username, removed.password)).session;
    const adminSession = (await signIn(admin.username, admin.password)).session;
    assert.ok(await sessionIsValid(removedSession));

    const res = await adminFetch(server.baseUrl, adminSession, `/api/admin/portal-users/${encodeURIComponent(removed.username)}`, {
      method: 'DELETE',
    });
    assert.equal(res.status, 200, JSON.stringify(res.body));
    assert.equal(await sessionIsValid(removedSession), false);
  });
});

// ---------------------------------------------------------------------------------------------
// Step-up before security changes
// ---------------------------------------------------------------------------------------------

describe('step-up confirmation', () => {
  test('a security change more than 10 minutes after sign-in needs POST /reauth first; ordinary reads do not', async (t) => {
    const account = createAccount(t);
    const { session } = await signIn(account.username, account.password);
    const current = store.getSalesforceSettings();
    const change = { apiVersion: current.apiVersion };

    const fresh = await adminFetch(server.baseUrl, session, '/api/admin/sf-settings', { method: 'PUT', body: change });
    assert.equal(fresh.status, 200, JSON.stringify(fresh.body));

    await withClockOffset(11 * 60 * 1000, async () => {
      assert.ok(await sessionIsValid(session), 'the session itself is still valid');
      const stale = await adminFetch(server.baseUrl, session, '/api/admin/sf-settings', { method: 'PUT', body: change });
      assert.equal(stale.status, 403);
      assert.equal(stale.body.code, 'REAUTH_REQUIRED');
      assert.equal(stale.body.authMethod, 'local_bootstrap');

      const wrong = await adminFetch(server.baseUrl, session, '/api/admin/reauth', {
        method: 'POST',
        body: { password: 'not-the-password' },
      });
      assert.equal(wrong.status, 403, 'a failed confirmation does not read as a lost session');
      assert.equal(wrong.body.code, 'REAUTH_FAILED');
      assert.ok(await sessionIsValid(session));

      const reauth = await adminFetch(server.baseUrl, session, '/api/admin/reauth', {
        method: 'POST',
        body: { password: account.password },
      });
      assert.equal(reauth.status, 200, JSON.stringify(reauth.body));

      const retried = await adminFetch(server.baseUrl, session, '/api/admin/sf-settings', { method: 'PUT', body: change });
      assert.equal(retried.status, 200, JSON.stringify(retried.body));
    });
  });

  test('enrolled accounts confirm with their authenticator code too', async (t) => {
    const account = createAccount(t, { totp: true });
    const { session } = await signIn(account.username, account.password, codeNow(account.secret));

    await withClockOffset(11 * 60 * 1000, async () => {
      const passwordOnly = await adminFetch(server.baseUrl, session, '/api/admin/reauth', {
        method: 'POST',
        body: { password: account.password },
      });
      assert.equal(passwordOnly.status, 403);
      const withCode = await adminFetch(server.baseUrl, session, '/api/admin/reauth', {
        method: 'POST',
        body: { password: account.password, totp: totpCode(account.secret, totpStep()) },
      });
      assert.equal(withCode.status, 200, JSON.stringify(withCode.body));
    });
  });

  test('PUT /okta refuses to enable SSO without a required admin group', async (t) => {
    const okta = store.getOktaConfig();
    t.after(() => store.updateOktaConfig({ enabled: okta.enabled, adminGroup: okta.adminGroup }));
    store.updateOktaConfig({ enabled: false, adminGroup: '' });
    const session = await loginAsAdmin(server.baseUrl);

    const res = await adminFetch(server.baseUrl, session, '/api/admin/okta', {
      method: 'PUT',
      body: { enabled: true, adminGroup: '   ' },
    });
    assert.equal(res.status, 400, JSON.stringify(res.body));
    assert.match(String(res.body.error), /group/i);
    assert.equal(store.getOktaConfig().enabled, false);
  });
});

// ---------------------------------------------------------------------------------------------
// Network binding
// ---------------------------------------------------------------------------------------------

test('isLoopbackHost: only loopback names and addresses count as private to this machine', () => {
  for (const host of ['127.0.0.1', '127.1.2.3', 'localhost', 'LOCALHOST', '::1', '[::1]', ' 127.0.0.1 ']) {
    assert.equal(isLoopbackHost(host), true, host);
  }
  for (const host of ['0.0.0.0', '::', '', '10.0.0.5', '192.168.1.10', 'example.com', '127.0.0.1.evil.example', '128.0.0.1']) {
    assert.equal(isLoopbackHost(host), false, host);
  }
});

test('the backend listens on 127.0.0.1 unless MCP_BACKEND_HOST says otherwise', () => {
  assert.equal(config.host, process.env.MCP_BACKEND_HOST?.trim() || '127.0.0.1');
});
