import { TEST_ADMIN } from './helpers/env.js';
import { after, before, describe, it, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { DatabaseSync, type SQLInputValue } from 'node:sqlite';
import { installSalesforceMock, type SalesforceMock } from './helpers/salesforceMock.js';
import { mcpRequest, startTestServer, type AdminSession, type TestServer } from './helpers/server.js';
import { SIMULATE_MCP_CALL_ACTION, store } from '../src/db/store.js';
import { adminRouter } from '../src/routes/adminRoutes.js';
import { config, DEV_FALLBACK_SECRET_KEY, KNOWN_DEFAULT_PASSWORDS } from '../src/config.js';
import { PORTAL_PASSWORD_MIN_LENGTH } from '../src/security/passwordPolicy.js';
import type { AccessGroup, PortalAdminLogRecord } from '../src/types/governance.js';

// Admin REST API over HTTP: session auth, CSRF, every route of src/routes/adminRoutes.ts, the
// portal admin audit trail, and the login / Admin API rate limits from src/index.ts.

// ------------------------------------------------------------------------------------------------
// Isolation: all test files may share one process, one app instance and one throwaway database.
// ------------------------------------------------------------------------------------------------

// Every record created here carries RUN and is removed again when its test ends.
const RUN = crypto.randomBytes(3).toString('hex');
let sequence = 0;
const nextNumber = () => ++sequence;
const newProfileId = () => `00e${RUN}${String(nextNumber()).padStart(6, '0')}`; // 15 characters
const newObjectName = (base: string) => `${base}_${RUN}_${nextNumber()}__c`;
const newGroupName = (base: string) => `${base} ${RUN}-${nextNumber()}`;
const newUsername = (base: string) => `${base}.${RUN}.${nextNumber()}`;

// Rate-limit counters live in the shared app and are keyed by client IP. The test env sets
// TRUST_PROXY=loopback (the app defaults to false), so every test sends its own X-Forwarded-For
// address: no test here can be throttled by, or throttle, another test or test file.
const IP_PREFIX = `10.${crypto.randomInt(1, 255)}.${crypto.randomInt(1, 255)}`;
let ipSuffix = 0;
function newClientIp(): string {
  ipSuffix += 1;
  assert.ok(ipSuffix < 255, 'this file ran out of client IP addresses');
  return `${IP_PREFIX}.${ipSuffix}`;
}

const BOOTSTRAP_ADMIN = { ...TEST_ADMIN };
const SESSION_COOKIE = 'sf_mcp_admin_session';
const SIMULATOR_TOKEN = /^sf_sim_[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;

let server: TestServer;
let sf: SalesforceMock;
let tmpRoot: string;

// ------------------------------------------------------------------------------------------------
// HTTP helpers (adminFetch / loginAsAdmin plus the test's own client IP)
// ------------------------------------------------------------------------------------------------

interface Client {
  ip: string;
  cookie?: string;
  csrfToken?: string;
}

interface Session extends AdminSession {
  ip: string;
  username: string;
}

interface ApiResponse {
  status: number;
  headers: Headers;
  body: any;
}

async function call(client: Client, method: string, urlPath: string, body?: unknown): Promise<ApiResponse> {
  const headers: Record<string, string> = { 'X-Forwarded-For': client.ip };
  if (client.cookie) headers.Cookie = client.cookie;
  if (client.csrfToken) headers['X-CSRF-Token'] = client.csrfToken;
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const res = await fetch(`${server.baseUrl}${urlPath}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  let parsed: any = text;
  try {
    parsed = text ? JSON.parse(text) : null;
  } catch {
    // leave as text
  }
  return { status: res.status, headers: res.headers, body: parsed };
}

function postLogin(ip: string, credentials: Record<string, unknown>): Promise<ApiResponse> {
  return call({ ip }, 'POST', '/api/admin/login', credentials);
}

function sessionSetCookie(res: ApiResponse): string | undefined {
  return res.headers.getSetCookie().find((c) => c.startsWith(`${SESSION_COOKIE}=`));
}

async function signIn(
  ip = newClientIp(),
  username = BOOTSTRAP_ADMIN.username,
  password = BOOTSTRAP_ADMIN.password
): Promise<Session> {
  const res = await postLogin(ip, { username, password });
  assert.equal(res.status, 200, `sign-in as ${username} failed: ${JSON.stringify(res.body)}`);
  return {
    ip,
    username: res.body.user.username,
    cookie: (sessionSetCookie(res) || '').split(';')[0],
    csrfToken: res.body.csrfToken,
  };
}

// ------------------------------------------------------------------------------------------------
// Portal admin audit trail
// ------------------------------------------------------------------------------------------------

/** Action codes whose audit row was verified by a mutation in this file (checked by section 11). */
const auditedActions = new Set<string>();

/** Id of the newest portal admin log row; rows written after it belong to the next request. */
function auditMark(): string | undefined {
  return store.getPortalAdminLogs(1)[0]?.id;
}

/** Portal admin log rows written after `mark` for requests from `ip`, oldest first. */
function auditRowsSince(mark: string | undefined, ip: string): PortalAdminLogRecord[] {
  const newestFirst = store.getPortalAdminLogs(1000);
  const end = mark === undefined ? -1 : newestFirst.findIndex((row) => row.id === mark);
  return newestFirst
    .slice(0, end === -1 ? newestFirst.length : end)
    .filter((row) => row.ipAddress === ip)
    .reverse();
}

const describeAuditRow = (row: PortalAdminLogRecord) => `${row.action} by ${row.adminUsername} (${row.authMethod})`;

/** Exactly one row since `mark`: `action`, by the session's user, from the session's client IP. */
function assertAudited(mark: string | undefined, session: Session, action: string, target?: string): PortalAdminLogRecord {
  const rows = auditRowsSince(mark, session.ip);
  assert.deepEqual(rows.map(describeAuditRow), [`${action} by ${session.username} (password)`]);
  if (target !== undefined) {
    assert.ok(rows[0].target.includes(target), `audit target "${rows[0].target}" should mention "${target}"`);
  }
  auditedActions.add(action);
  return rows[0];
}

function assertNotAudited(mark: string | undefined, ip: string): void {
  assert.deepEqual(auditRowsSince(mark, ip).map(describeAuditRow), []);
}

/** A mutation that must succeed (200) and write its portal admin log row (returned as `audit`). */
async function mutate(
  session: Session,
  method: string,
  urlPath: string,
  body: unknown,
  action: string,
  target?: string
): Promise<ApiResponse & { audit: PortalAdminLogRecord }> {
  const mark = auditMark();
  const res = await call(session, method, urlPath, body);
  assert.equal(res.status, 200, `${method} ${urlPath} failed: ${JSON.stringify(res.body)}`);
  return { ...res, audit: assertAudited(mark, session, action, target) };
}

// ------------------------------------------------------------------------------------------------
// Fixtures (written straight to the store) and cleanup
// ------------------------------------------------------------------------------------------------

function addProfile(t: TestContext, name = `Fixture Profile ${RUN}`): string {
  const id = newProfileId();
  store.upsertProfile(id, name);
  t.after(() => {
    store.deleteProfile(id);
  });
  return id;
}

function addObject(t: TestContext, base: string, fieldNames = ['Id', 'Name']): string {
  const objectName = newObjectName(base);
  store.upsertObjectWithFields({ objectName, fields: fieldNames.map((fieldName) => ({ fieldName })) });
  t.after(() => {
    store.deleteObject(objectName);
  });
  return objectName;
}

function addGroup(t: TestContext, base: string): AccessGroup {
  const group = store.upsertGroup({
    name: newGroupName(base),
    allowedActions: ['list_enabled_objects'],
    objectPermissions: [],
  });
  t.after(() => {
    store.deleteGroup(group.id);
  });
  return group;
}

function removePortalUser(username: string): void {
  if (store.getPortalUsers().some((u) => u.username === username)) store.deletePortalUser(username);
}

function addPortalUser(t: TestContext): { username: string; password: string } {
  const username = newUsername('fixture');
  const password = `Pw-${RUN}-${crypto.randomBytes(6).toString('hex')}`;
  store.upsertPortalUser({ username, displayName: 'Fixture Admin', password, role: 'Admin' });
  t.after(() => removePortalUser(username));
  return { username, password };
}

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

const mappedGroupIds = (profileId: string) =>
  store.getProfileGroupMappings().find((m) => m.profileId === profileId)?.groupIds;
const objectInStore = (objectName: string) => store.getObjects().find((o) => o.objectName === objectName);
const copilotRowsFor = (profileId: string) => store.getCopilotMcpLogs(1000).filter((row) => row.profileId === profileId);

/**
 * Snapshot of a settings row; the returned function puts it back exactly. It uses its own
 * connection to the throwaway test database because the API cannot undo every change (it can
 * never clear a stored Okta client secret, for instance).
 */
function snapshotSettingsRow(table: 'okta_config' | 'sf_connection_settings'): () => void {
  const db = new DatabaseSync(config.dbPath);
  const row = db.prepare(`SELECT * FROM ${table} WHERE id = 1`).get() as Record<string, SQLInputValue>;
  return () => {
    const columns = Object.keys(row).filter((column) => column !== 'id');
    db.prepare(`UPDATE ${table} SET ${columns.map((c) => `${c} = ?`).join(', ')} WHERE id = 1`).run(
      ...columns.map((c) => row[c])
    );
    db.close();
  };
}

/** Removes every portal user except `keep` for one test, then restores them with their password hashes. */
function parkPortalUsersExcept(t: TestContext, keep: string): void {
  const db = new DatabaseSync(config.dbPath);
  const parked = db.prepare('SELECT * FROM portal_users WHERE username <> ?').all(keep) as Array<
    Record<string, SQLInputValue>
  >;
  db.prepare('DELETE FROM portal_users WHERE username <> ?').run(keep);
  t.after(() => {
    const insert = db.prepare(
      `INSERT OR REPLACE INTO portal_users
         (username, display_name, password_hash, password_salt, role, created_at, last_login_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    );
    for (const u of parked) {
      insert.run(u.username, u.display_name, u.password_hash, u.password_salt, u.role, u.created_at, u.last_login_at);
    }
    db.close();
  });
}

// ------------------------------------------------------------------------------------------------
// SFDX source-format metadata
// ------------------------------------------------------------------------------------------------

function objectMetaXml(label: string): string {
  return `<?xml version="1.0" encoding="UTF-8"?>
<CustomObject xmlns="http://soap.sforce.com/2006/04/metadata">
    <deploymentStatus>Deployed</deploymentStatus>
    <label>${label}</label>
    <nameField>
        <label>${label} Name</label>
        <type>Text</type>
    </nameField>
    <pluralLabel>${label}s</pluralLabel>
    <sharingModel>ReadWrite</sharingModel>
</CustomObject>
`;
}

function fieldMetaXml(fullName: string, label: string, type: string, required = false): string {
  return `<?xml version="1.0" encoding="UTF-8"?>
<CustomField xmlns="http://soap.sforce.com/2006/04/metadata">
    <fullName>${fullName}</fullName>
    <label>${label}</label>
    <required>${required}</required>
    <type>${type}</type>
</CustomField>
`;
}

function picklistFieldMetaXml(fullName: string, label: string, values: string[]): string {
  const valueXml = values
    .map((v) => `            <value>\n                <fullName>${v}</fullName>\n                <default>false</default>\n                <label>${v}</label>\n            </value>`)
    .join('\n');
  return `<?xml version="1.0" encoding="UTF-8"?>
<CustomField xmlns="http://soap.sforce.com/2006/04/metadata">
    <fullName>${fullName}</fullName>
    <label>${label}</label>
    <required>false</required>
    <type>Picklist</type>
    <valueSet>
        <valueSetDefinition>
${valueXml}
        </valueSetDefinition>
    </valueSet>
</CustomField>
`;
}

function writeFile(filePath: string, content: string): void {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, content);
}

/** fieldName -> "Label: Type", with " (required)" / " (disabled)" when they apply. */
function describeFields(object: { fields: Array<Record<string, any>> }): Record<string, string> {
  return Object.fromEntries(
    object.fields.map((f) => [
      f.fieldName,
      `${f.label}: ${f.fieldType}${f.required ? ' (required)' : ''}${f.enabled ? '' : ' (disabled)'}`,
    ])
  );
}

// ------------------------------------------------------------------------------------------------
// Session JWTs crafted by the test (HS256, keyed like src/security/adminAuth.ts)
// ------------------------------------------------------------------------------------------------

const base64UrlJson = (value: object) => Buffer.from(JSON.stringify(value)).toString('base64url');

function hs256SessionCookie(claims: object, key: string): string {
  const unsigned = `${base64UrlJson({ alg: 'HS256', typ: 'JWT' })}.${base64UrlJson(claims)}`;
  const signature = crypto.createHmac('sha256', key).update(unsigned).digest('base64url');
  return `${SESSION_COOKIE}=${unsigned}.${signature}`;
}

function unsignedSessionCookie(claims: object): string {
  return `${SESSION_COOKIE}=${base64UrlJson({ alg: 'none', typ: 'JWT' })}.${base64UrlJson(claims)}.`;
}

// ================================================================================================

describe('Admin REST API', () => {
  before(async () => {
    sf = installSalesforceMock();
    server = await startTestServer();
    tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'admin-api-test-'));
  });

  after(async () => {
    await server?.close();
    sf?.restore();
    if (tmpRoot) fs.rmSync(tmpRoot, { recursive: true, force: true });
  });

  // ----------------------------------------------------------------------------------------------
  describe('1. Unauthenticated access', () => {
    it('GET /session without a cookie reports signed out with no CSRF token', async () => {
      const res = await call({ ip: newClientIp() }, 'GET', '/api/admin/session');

      assert.equal(res.status, 200);
      assert.equal(res.body.authenticated, false);
      assert.equal(res.body.user, null);
      assert.equal(res.body.csrfToken, null);
      assert.equal(typeof res.body.oktaSso.enabled, 'boolean');
    });

    it('protected routes answer 401 without a session cookie and change nothing', async (t) => {
      t.after(snapshotSettingsRow('okta_config'));
      const client = { ip: newClientIp() };
      const profileId = newProfileId();
      const simulatedProfileId = newProfileId();
      t.after(() => {
        store.deleteProfile(profileId);
      });
      const oktaBefore = store.getOktaConfig();

      const attempts: Array<[string, string, unknown?]> = [
        ['GET', '/api/admin/overview'],
        ['POST', '/api/admin/profiles', { id: profileId, name: 'Unauthenticated' }],
        ['PUT', '/api/admin/okta', { enabled: true, clientSecret: `unauthenticated-${RUN}` }],
        ['POST', '/api/admin/test-mcp-access', { profileId: simulatedProfileId, toolName: 'list_enabled_objects' }],
      ];
      for (const [method, urlPath, body] of attempts) {
        const res = await call(client, method, urlPath, body);
        assert.equal(res.status, 401, `${method} ${urlPath}`);
        assert.deepEqual(Object.keys(res.body), ['error'], `${method} ${urlPath} should return only an error`);
        assert.match(res.body.error, /Unauthorized/);
      }

      assert.equal(store.getProfileById(profileId), null);
      assert.deepEqual(store.getOktaConfig(), oktaBefore);
      assert.deepEqual(copilotRowsFor(simulatedProfileId), [], 'no simulation may run');
    });

    it('a garbage or tampered session cookie gets 401, and /session reports signed out', async (t) => {
      t.after(snapshotSettingsRow('sf_connection_settings'));
      const admin = await signIn();
      const [header, payload, signature] = admin.cookie.slice(`${SESSION_COOKIE}=`.length).split('.');
      const claims = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
      const escalated = base64UrlJson({ ...claims, email: `attacker.${RUN}`, csrfToken: 'attacker-csrf' });
      // Change the first character: every bit of it is signature data (unlike the padding bits of the last one).
      const alteredSignature = (signature[0] === 'A' ? 'B' : 'A') + signature.slice(1);
      const cookies: Record<string, string> = {
        garbage: `${SESSION_COOKIE}=garbage`,
        randomBytes: `${SESSION_COOKIE}=${crypto.randomBytes(48).toString('base64url')}`,
        editedPayload: `${SESSION_COOKIE}=${header}.${escalated}.${signature}`,
        alteredSignature: `${SESSION_COOKIE}=${header}.${payload}.${alteredSignature}`,
      };

      const outcomes: Record<string, unknown> = {};
      for (const [name, cookie] of Object.entries(cookies)) {
        const overview = await call({ ip: admin.ip, cookie }, 'GET', '/api/admin/overview');
        const session = await call({ ip: admin.ip, cookie }, 'GET', '/api/admin/session');
        outcomes[name] = { overview: overview.status, authenticated: session.body.authenticated, csrfToken: session.body.csrfToken };
      }
      const signedOut = { overview: 401, authenticated: false, csrfToken: null };
      assert.deepEqual(outcomes, { garbage: signedOut, randomBytes: signedOut, editedPayload: signedOut, alteredSignature: signedOut });

      // The edited token's own CSRF claim does not help either: the signature is checked first.
      const write = await call(
        { ip: admin.ip, cookie: cookies.editedPayload, csrfToken: 'attacker-csrf' },
        'PUT',
        '/api/admin/sf-settings',
        { apiVersion: 'v1.0' }
      );
      assert.equal(write.status, 401);
    });

    it('forged session JWTs are rejected: public dev key, alg "none", expired, wrong audience or issuer', async () => {
      assert.notEqual(config.appSecretKey, DEV_FALLBACK_SECRET_KEY, 'tests must run with a private APP_SECRET_KEY');
      const now = Math.floor(Date.now() / 1000);
      // Every session cookie names a server-side record; this one is real, so only the cookie is forged.
      const jti = `forged-test-${crypto.randomBytes(6).toString('hex')}`;
      store.createAdminSession({ jti, subject: 'admin', authMethod: 'local_bootstrap', nowMs: Date.now(), expiresAtMs: Date.now() + 3_600_000 });
      const claims = {
        jti,
        sub: 'portal_admin',
        email: 'admin',
        name: 'Portal Administrator',
        authMethod: 'local_bootstrap',
        groups: ['Super Admin'],
        csrfToken: 'forged-csrf-token',
        iss: 'salesforce-mcp-admin',
        aud: 'salesforce-mcp-admin-portal',
        iat: now,
        exp: now + 3600,
      };
      const cookies: Record<string, string> = {
        // Control: the same claims signed with the server's key are accepted, so each rejection
        // below is caused by its key, algorithm or claim alone.
        control: hs256SessionCookie(claims, config.appSecretKey),
        publicDevKey: hs256SessionCookie(claims, DEV_FALLBACK_SECRET_KEY),
        algNone: unsignedSessionCookie(claims),
        expired: hs256SessionCookie({ ...claims, iat: now - 7200, exp: now - 60 }, config.appSecretKey),
        wrongAudience: hs256SessionCookie({ ...claims, aud: 'another-app' }, config.appSecretKey),
        wrongIssuer: hs256SessionCookie({ ...claims, iss: 'another-issuer' }, config.appSecretKey),
        // Signed with the server's own key, but naming no session the server started: a stolen
        // APP_SECRET_KEY alone no longer mints sessions.
        unknownSession: hs256SessionCookie({ ...claims, jti: 'no-such-session' }, config.appSecretKey),
        noSessionId: hs256SessionCookie({ ...claims, jti: undefined }, config.appSecretKey),
      };
      const ip = newClientIp();
      const statuses: Record<string, number> = {};
      for (const [name, cookie] of Object.entries(cookies)) {
        statuses[name] = (await call({ ip, cookie }, 'GET', '/api/admin/overview')).status;
      }

      assert.deepEqual(statuses, {
        control: 200,
        publicDevKey: 401,
        algNone: 401,
        expired: 401,
        wrongAudience: 401,
        wrongIssuer: 401,
        unknownSession: 401,
        noSessionId: 401,
      });
    });
  });

  // ----------------------------------------------------------------------------------------------
  describe('2. Password login', () => {
    it('the configured bootstrap credentials (ADMIN_BOOTSTRAP_*) sign in with a CSRF token and an HttpOnly, SameSite=Lax cookie', async () => {
      const res = await postLogin(newClientIp(), BOOTSTRAP_ADMIN);

      assert.equal(res.status, 200, JSON.stringify(res.body));
      assert.equal(res.body.success, true);
      assert.equal(res.body.user.username, 'admin');
      assert.equal(typeof res.body.csrfToken, 'string');
      assert.ok(res.body.csrfToken.length >= 32, 'the CSRF token should be long and random');

      const cookie = sessionSetCookie(res);
      assert.ok(cookie, `expected a ${SESSION_COOKIE} cookie, got ${JSON.stringify(res.headers.getSetCookie())}`);
      assert.match(cookie, new RegExp(`^${SESSION_COOKIE}=[^;]+;`));
      assert.match(cookie, /;\s*HttpOnly/i);
      assert.match(cookie, /;\s*SameSite=Lax/i);
      assert.match(cookie, /;\s*Path=\/(;|$)/);
      assert.match(cookie, /;\s*Max-Age=28800\b/, 'sessions last 8 hours');
    });

    it('GET /session with the new cookie reports the signed-in admin and the same CSRF token', async () => {
      const admin = await signIn();

      const res = await call(admin, 'GET', '/api/admin/session');

      assert.equal(res.status, 200);
      assert.equal(res.body.authenticated, true);
      assert.equal(res.body.csrfToken, admin.csrfToken);
      assert.equal(res.body.user.username, 'admin');
      assert.equal(res.body.user.authMethod, 'local_bootstrap');
    });

    it('a wrong password or an unknown username gets the same 401 and no session cookie', async () => {
      const ip = newClientIp();

      const wrongPassword = await postLogin(ip, { username: 'admin', password: 'not-the-password' });
      const unknownUser = await postLogin(ip, { username: `nobody.${RUN}`, password: 'admin123' });

      for (const res of [wrongPassword, unknownUser]) {
        assert.equal(res.status, 401);
        assert.deepEqual(res.headers.getSetCookie(), []);
      }
      // The same answer either way, so the response does not reveal which usernames exist.
      assert.deepEqual(wrongPassword.body, unknownUser.body);
    });

    it('a login without a username or password gets 400 and no session cookie', async () => {
      const ip = newClientIp();
      const bodies = [{ username: 'admin' }, { password: 'admin123' }, { username: '   ', password: 'admin123' }, {}];

      for (const body of bodies) {
        const res = await postLogin(ip, body);
        assert.equal(res.status, 400, JSON.stringify(body));
        assert.match(res.body.error, /required/i);
        assert.deepEqual(res.headers.getSetCookie(), []);
      }
    });

    it('failed logins are written to the portal admin log as LOGIN_FAILED, never with the attempted password', async () => {
      const ip = newClientIp();
      const intruder = `intruder.${RUN}`;
      const attempts = [
        { username: intruder, password: `guess-${RUN}-one` },
        { username: 'admin', password: `guess-${RUN}-two` },
      ];
      const mark = auditMark();

      for (const attempt of attempts) assert.equal((await postLogin(ip, attempt)).status, 401);

      const rows = auditRowsSince(mark, ip);
      assert.deepEqual(
        rows.map((r) => [r.action, r.adminUsername, r.authMethod, r.target]),
        [
          ['LOGIN_FAILED', intruder, 'password', 'Portal Auth'],
          ['LOGIN_FAILED', 'admin', 'password', 'Portal Auth'],
        ]
      );
      for (const { password } of attempts) {
        assert.ok(!JSON.stringify(rows).includes(password), 'an attempted password reached the audit log');
      }
    });
  });

  // ----------------------------------------------------------------------------------------------
  describe('3. CSRF protection', () => {
    interface CsrfFixture {
      profileId: string;
      objectName: string;
      groupId: string;
      username: string;
    }
    let fx: CsrfFixture;
    let restoreSettings: Array<() => void> = [];

    before(() => {
      restoreSettings = [snapshotSettingsRow('okta_config'), snapshotSettingsRow('sf_connection_settings')];
      const profileId = newProfileId();
      store.upsertProfile(profileId, `CSRF Target ${RUN}`);
      const objectName = newObjectName('CsrfTarget');
      store.upsertObjectWithFields({ objectName });
      const group = store.upsertGroup({
        name: newGroupName('CSRF Target'),
        allowedActions: ['list_enabled_objects'],
        objectPermissions: [],
      });
      store.setProfileGroups(profileId, [group.id]);
      const username = newUsername('csrf.target');
      store.upsertPortalUser({ username, displayName: 'CSRF Target', password: `Pw-${RUN}-csrf`, role: 'Admin' });

      fx = { profileId, objectName, groupId: group.id, username };
    });

    after(() => {
      for (const restore of restoreSettings) restore();
      if (!fx) return;
      store.deleteProfile(fx.profileId);
      store.deleteObject(fx.objectName);
      store.deleteGroup(fx.groupId);
      removePortalUser(fx.username);
    });

    // The walk finds 28 today; finding fewer means it has stopped seeing routes. Lower it only when removing one.
    const MIN_MUTATING_ROUTES = 28;

    /** Fills path params with this suite's fixture records, so a handler that ran would visibly change one. */
    function samplePath(pattern: string): string {
      const samples: Record<string, string> = {
        id: pattern.startsWith('/groups/') ? fx.groupId : fx.profileId,
        profileId: fx.profileId,
        objectName: fx.objectName,
        fieldName: 'Name',
        username: fx.username,
      };
      return pattern.replace(/:(\w+)/g, (_param, name: string) => {
        assert.ok(Object.hasOwn(samples, name), `no sample value for :${name} in ${pattern}`);
        return encodeURIComponent(samples[name]);
      });
    }

    /**
     * Every state-changing Admin API route as [method, path pattern, URL], read from adminRouter's own
     * stack so a new route is covered without being listed here. /login and /logout come before the
     * session check and are left out.
     */
    function mutatingRoutes(): Array<[string, string, string]> {
      const routes: Array<[string, string, string]> = [];
      for (const layer of adminRouter.stack) {
        if (!layer.route) {
          assert.ok(!('stack' in layer.handle), 'adminRouter mounts a nested router, whose routes this walk cannot see');
          continue;
        }
        // Express 4 keeps a route's methods as { post: true }, which its typings do not declare.
        const { path: pattern, methods } = layer.route as unknown as { path: string; methods: Record<string, boolean> };
        if (pattern === '/login' || pattern === '/logout') continue;
        for (const method of Object.keys(methods).filter((m) => m !== 'get')) {
          routes.push([method.toUpperCase(), `/api/admin${pattern}`, `/api/admin${samplePath(pattern)}`]);
        }
      }
      assert.ok(
        routes.length >= MIN_MUTATING_ROUTES,
        `the adminRouter walk found ${routes.length} mutating routes, expected at least ${MIN_MUTATING_ROUTES}`
      );
      return routes;
    }

    function governanceState() {
      return {
        profile: store.getProfileById(fx.profileId),
        object: objectInStore(fx.objectName),
        group: store.getGroups().find((g) => g.id === fx.groupId),
        mapping: mappedGroupIds(fx.profileId),
        okta: store.getOktaConfig(),
        sfSettings: store.getSalesforceSettings(),
        portalUser: store.getPortalUsers().find((u) => u.username === fx.username),
      };
    }

    async function assertEveryMutationForbidden(t: TestContext, client: Client): Promise<void> {
      const before = governanceState();
      const mark = auditMark();
      const routes = mutatingRoutes();

      const outcomes: string[] = [];
      for (const [method, pattern, urlPath] of routes) {
        const res = await call(client, method, urlPath);
        const csrfRejection = res.status === 403 && /X-CSRF-Token/.test(String(res.body?.error));
        outcomes.push(`${method} ${pattern} -> ${csrfRejection ? '403 CSRF error' : `${res.status} ${JSON.stringify(res.body)}`}`);
      }

      assert.deepEqual(outcomes, routes.map(([method, pattern]) => `${method} ${pattern} -> 403 CSRF error`));
      assert.deepEqual(governanceState(), before, 'a request rejected for CSRF must not change any state');
      assertNotAudited(mark, client.ip);
      t.diagnostic(`covered ${routes.length} routes: ${routes.map(([method, pattern]) => `${method} ${pattern}`).join(', ')}`);
    }

    it('every mutating route rejects a valid cookie without X-CSRF-Token (403) and changes nothing', async (t) => {
      const admin = await signIn();
      await assertEveryMutationForbidden(t, { ...admin, csrfToken: undefined });
    });

    it("every mutating route rejects a valid cookie with another session's X-CSRF-Token (403) and changes nothing", async (t) => {
      const admin = await signIn();
      const other = await signIn();
      assert.notEqual(other.csrfToken, admin.csrfToken);
      await assertEveryMutationForbidden(t, { ...admin, csrfToken: other.csrfToken });
    });
  });

  // ----------------------------------------------------------------------------------------------
  describe('4. Logout', () => {
    it('POST /logout clears the session cookie and is audited as LOGOUT', async () => {
      const admin = await signIn();
      const mark = auditMark();

      const res = await call(admin, 'POST', '/api/admin/logout');

      assert.equal(res.status, 200);
      assert.deepEqual(res.body, { success: true });
      const cleared = sessionSetCookie(res) || '';
      assert.match(cleared, new RegExp(`^${SESSION_COOKIE}=;`));
      assert.match(cleared, /Expires=Thu, 01 Jan 1970 00:00:00 GMT/);
      assertAudited(mark, admin, 'LOGOUT', 'Portal Auth');

      // The browser now holds the cleared cookie, which is signed out.
      const session = await call({ ip: admin.ip, cookie: cleared.split(';')[0] }, 'GET', '/api/admin/session');
      assert.equal(session.body.authenticated, false);
    });
  });

  // ----------------------------------------------------------------------------------------------
  describe('5. Profiles', () => {
    it('POST /profiles creates a profile, and posting the same id again renames it', async (t) => {
      const admin = await signIn();
      const id = newProfileId();
      t.after(() => {
        store.deleteProfile(id);
      });

      const created = await mutate(admin, 'POST', '/api/admin/profiles', { id, name: 'Custom: Support' }, 'CREATE_PROFILE', id);
      assert.deepEqual({ id: created.body.profile.id, name: created.body.profile.name }, { id, name: 'Custom: Support' });
      assert.ok(created.body.profiles.some((p: any) => p.id === id));

      const renamed = await mutate(admin, 'POST', '/api/admin/profiles', { id, name: 'Custom: Support Tier 2' }, 'UPDATE_PROFILE', id);
      assert.equal(renamed.body.profile.name, 'Custom: Support Tier 2');
      assert.deepEqual(
        renamed.body.profiles.filter((p: any) => p.id === id).map((p: any) => p.name),
        ['Custom: Support Tier 2']
      );
    });

    it('POST /profiles without an id or a name is rejected (400)', async (t) => {
      const admin = await signIn();
      const id = newProfileId();
      t.after(() => {
        store.deleteProfile(id);
      });
      const mark = auditMark();

      for (const body of [{ name: 'No id' }, { id }, {}]) {
        assert.equal((await call(admin, 'POST', '/api/admin/profiles', body)).status, 400, JSON.stringify(body));
      }
      assert.equal(store.getProfileById(id), null);
      assertNotAudited(mark, admin.ip);
    });

    it('CSV import via csvText handles a header row, CRLF line endings, quoted values and blank lines', async (t) => {
      const admin = await signIn();
      const sysAdminId = newProfileId();
      const readOnlyId = newProfileId();
      t.after(() => {
        store.deleteProfile(sysAdminId);
        store.deleteProfile(readOnlyId);
      });
      const csvText = ['', 'id,name', `"${sysAdminId}","System Administrator"`, '', `${readOnlyId},Read Only ${RUN}`, '   ', ''].join('\r\n');

      const res = await mutate(admin, 'POST', '/api/admin/profiles/import-csv', { csvText }, 'IMPORT_PROFILES_CSV', 'Profiles');

      assert.deepEqual({ inserted: res.body.summary.inserted, updated: res.body.summary.updated }, { inserted: 2, updated: 0 });
      assert.equal(store.getProfileById(sysAdminId)?.name, 'System Administrator');
      assert.equal(store.getProfileById(readOnlyId)?.name, `Read Only ${RUN}`);
      assert.equal(store.getProfileById('id'), null, 'the header row must not be imported');
    });

    it('CSV import keeps commas and escaped double quotes inside quoted values (RFC 4180)', async (t) => {
      const admin = await signIn();
      const withComma = newProfileId();
      const withQuotes = newProfileId();
      t.after(() => {
        store.deleteProfile(withComma);
        store.deleteProfile(withQuotes);
      });
      const csvText = `Id,Name\r\n"${withComma}","Sales, EMEA"\r\n"${withQuotes}","The ""Best"" Profile"\r\n`;

      const res = await call(admin, 'POST', '/api/admin/profiles/import-csv', { csvText });

      assert.equal(res.status, 200, JSON.stringify(res.body));
      assert.deepEqual(
        [store.getProfileById(withComma)?.name, store.getProfileById(withQuotes)?.name],
        ['Sales, EMEA', 'The "Best" Profile']
      );
    });

    it('CSV import via rows[] upserts the complete rows and skips incomplete ones', async (t) => {
      const admin = await signIn();
      const existingId = addProfile(t, 'Before Rename');
      const newId = newProfileId();
      const nameless = newProfileId();
      t.after(() => {
        store.deleteProfile(newId);
        store.deleteProfile(nameless);
      });
      const rows = [
        { id: newId, name: 'Partner Community User' },
        { id: existingId, name: 'After Rename' },
        { id: '', name: 'No id' },
        { name: 'Also no id' },
        { id: nameless },
        null,
      ];

      const res = await mutate(admin, 'POST', '/api/admin/profiles/import-csv', { rows }, 'IMPORT_PROFILES_CSV');

      assert.deepEqual({ inserted: res.body.summary.inserted, updated: res.body.summary.updated }, { inserted: 1, updated: 1 });
      assert.equal(store.getProfileById(newId)?.name, 'Partner Community User');
      assert.equal(store.getProfileById(existingId)?.name, 'After Rename');
      assert.equal(store.getProfileById(nameless), null);
    });

    it('an import with no valid rows is rejected (400) and writes nothing', async () => {
      const admin = await signIn();
      const mark = auditMark();
      const bodies = [
        { csvText: 'id,name\r\n\r\n' },
        { csvText: 'only-one-column\r\n' },
        { rows: [] },
        { rows: [{ name: 'No id' }] },
        {},
      ];

      for (const body of bodies) {
        const res = await call(admin, 'POST', '/api/admin/profiles/import-csv', body);
        assert.equal(res.status, 400, JSON.stringify(body));
        assert.match(res.body.error, /No valid/);
      }
      assertNotAudited(mark, admin.ip);
    });

    it('DELETE /profiles/:id deletes the profile', async (t) => {
      const admin = await signIn();
      const id = addProfile(t);

      const res = await mutate(admin, 'DELETE', `/api/admin/profiles/${id}`, undefined, 'DELETE_PROFILE', id);

      assert.ok(!res.body.profiles.some((p: any) => p.id === id));
      assert.equal(store.getProfileById(id), null);
    });

    it('DELETE /profiles/:id answers 404 for a profile that does not exist', async () => {
      const admin = await signIn();
      const mark = auditMark();

      const res = await call(admin, 'DELETE', `/api/admin/profiles/${newProfileId()}`);

      assert.equal(res.status, 404);
      assert.match(res.body.error, /not found/i);
      assertNotAudited(mark, admin.ip);
    });
  });

  // ----------------------------------------------------------------------------------------------
  describe('6. Objects', () => {
    it('POST /objects creates an object with its fields', async (t) => {
      const admin = await signIn();
      const objectName = newObjectName('Widget');
      t.after(() => {
        store.deleteObject(objectName);
      });

      const res = await mutate(
        admin,
        'POST',
        '/api/admin/objects',
        {
          objectName,
          label: 'Widget',
          fields: [
            { fieldName: 'Id', label: 'Record ID', fieldType: 'Id', required: true },
            { fieldName: 'Name', label: 'Widget Name', fieldType: 'Text' },
            { fieldName: 'Color__c', label: 'Color', fieldType: 'Picklist' },
          ],
        },
        'UPSERT_OBJECT',
        objectName
      );

      const { object } = res.body;
      assert.deepEqual(
        { objectName: object.objectName, label: object.label, isCustom: object.isCustom, enabled: object.enabled },
        { objectName, label: 'Widget', isCustom: true, enabled: true }
      );
      assert.deepEqual(describeFields(object), {
        Color__c: 'Color: Picklist',
        Id: 'Record ID: Id (required)',
        Name: 'Widget Name: Text',
      });
      assert.ok(res.body.objects.some((o: any) => o.objectName === objectName));
    });

    it('POST /objects without an objectName is rejected (400)', async () => {
      const admin = await signIn();
      const mark = auditMark();

      const res = await call(admin, 'POST', '/api/admin/objects', { label: 'No API name' });

      assert.equal(res.status, 400);
      assertNotAudited(mark, admin.ip);
    });

    it('PUT /objects/:objectName/toggle disables and re-enables an object', async (t) => {
      const admin = await signIn();
      const objectName = addObject(t, 'Toggle');
      const toggleUrl = `/api/admin/objects/${objectName}/toggle`;

      const off = await mutate(admin, 'PUT', toggleUrl, { enabled: false }, 'TOGGLE_OBJECT', objectName);
      assert.equal(off.body.object.enabled, false);
      assert.equal(objectInStore(objectName)?.enabled, false);

      const on = await mutate(admin, 'PUT', toggleUrl, { enabled: true }, 'TOGGLE_OBJECT', objectName);
      assert.equal(on.body.object.enabled, true);
      assert.equal(objectInStore(objectName)?.enabled, true);
    });

    it('PUT /objects/:objectName/fields/:fieldName/toggle disables a single field', async (t) => {
      const admin = await signIn();
      const objectName = addObject(t, 'FieldToggle', ['Id', 'Name', 'Email__c']);

      const res = await mutate(
        admin,
        'PUT',
        `/api/admin/objects/${objectName}/fields/Email__c/toggle`,
        { enabled: false },
        'TOGGLE_FIELD',
        `${objectName}.Email__c`
      );

      const enabledByField = Object.fromEntries(res.body.object.fields.map((f: any) => [f.fieldName, f.enabled]));
      assert.deepEqual(enabledByField, { Email__c: false, Id: true, Name: true });
      assert.equal(res.body.object.enabledFieldCount, 2);
    });

    it('PUT /objects/:objectName/fields/bulk disables and re-enables every field of an object', async (t) => {
      const admin = await signIn();
      const objectName = addObject(t, 'BulkToggle', ['Id', 'Name', 'Email__c']);
      const bulkUrl = `/api/admin/objects/${objectName}/fields/bulk`;
      const enabledByField = (objects: any[]) =>
        Object.fromEntries(objects.find((o) => o.objectName === objectName).fields.map((f: any) => [f.fieldName, f.enabled]));

      const off = await mutate(admin, 'PUT', bulkUrl, { enabled: false }, 'BULK_TOGGLE_FIELDS', objectName);
      assert.deepEqual(enabledByField(off.body.objects), { Email__c: false, Id: false, Name: false });

      const on = await mutate(admin, 'PUT', bulkUrl, { enabled: true }, 'BULK_TOGGLE_FIELDS', objectName);
      assert.deepEqual(enabledByField(on.body.objects), { Email__c: true, Id: true, Name: true });
    });

    it('both toggle routes answer 404 for an object that does not exist', async () => {
      const admin = await signIn();
      const missing = newObjectName('Missing');
      const mark = auditMark();

      const objectToggle = await call(admin, 'PUT', `/api/admin/objects/${missing}/toggle`, { enabled: false });
      const fieldToggle = await call(admin, 'PUT', `/api/admin/objects/${missing}/fields/Name/toggle`, { enabled: false });

      assert.deepEqual([objectToggle.status, fieldToggle.status], [404, 404]);
      assertNotAudited(mark, admin.ip);
    });

    it('toggling a field the object does not have answers 404 and writes no audit row', async (t) => {
      const admin = await signIn();
      const objectName = addObject(t, 'NoSuchField');
      const mark = auditMark();

      const res = await call(admin, 'PUT', `/api/admin/objects/${objectName}/fields/NoSuchField__c/toggle`, { enabled: false });

      assert.deepEqual(
        { status: res.status, auditRows: auditRowsSince(mark, admin.ip).map((r) => `${r.action}: ${r.details}`) },
        { status: 404, auditRows: [] }
      );
    });

    it('POST /objects/import-sfdx-files parses SFDX source-format files into objects and fields', async (t) => {
      const admin = await signIn();
      const shipment = newObjectName('Shipment');
      const depot = newObjectName('Depot');
      t.after(() => {
        store.deleteObject(shipment);
        store.deleteObject(depot);
      });
      const root = 'force-app/main/default/objects';
      const files = [
        { relativePath: `${root}/${shipment}/${shipment}.object-meta.xml`, content: objectMetaXml('Shipment') },
        { relativePath: `${root}/${shipment}/fields/Carrier__c.field-meta.xml`, content: fieldMetaXml('Carrier__c', 'Carrier', 'Text', true) },
        { relativePath: `${root}/${shipment}/fields/Weight__c.field-meta.xml`, content: fieldMetaXml('Weight__c', 'Weight', 'Number') },
        { relativePath: `${root}/${shipment}/listViews/All.listView-meta.xml`, content: '<ListView><fullName>All</fullName><label>All</label></ListView>' },
        // An object folder with only field files (no .object-meta.xml), as for standard objects
        { relativePath: `${root}/${depot}/fields/Region__c.field-meta.xml`, content: picklistFieldMetaXml('Region__c', 'Region', ['EMEA', 'APAC']) },
      ];

      const res = await mutate(admin, 'POST', '/api/admin/objects/import-sfdx-files', { files }, 'IMPORT_SFDX_OBJECTS_FOLDER', 'Objects');

      assert.deepEqual(res.body.summary, { objectsImported: 2, fieldsImported: 7 });
      const imported = Object.fromEntries(
        res.body.objects
          .filter((o: any) => o.objectName === shipment || o.objectName === depot)
          .map((o: any) => [o.objectName, { isCustom: o.isCustom, enabled: o.enabled, fields: describeFields(o) }])
      );
      assert.deepEqual(imported, {
        [shipment]: {
          isCustom: true,
          enabled: true,
          fields: {
            Carrier__c: 'Carrier: Text (required)',
            Id: 'Record ID: Id (required)',
            Name: 'Name: Text',
            Weight__c: 'Weight: Number',
          },
        },
        [depot]: {
          isCustom: true,
          enabled: true,
          fields: { Id: 'Record ID: Id (required)', Name: 'Name: Text', Region__c: 'Region: Picklist' },
        },
      });
      assert.equal(objectInStore(shipment)?.label, 'Shipment');
    });

    it('re-importing SFDX files keeps manual object and field toggles', async (t) => {
      const admin = await signIn();
      const objectName = newObjectName('Reimport');
      t.after(() => {
        store.deleteObject(objectName);
      });
      const files = [
        { relativePath: `objects/${objectName}/${objectName}.object-meta.xml`, content: objectMetaXml('Reimport') },
        { relativePath: `objects/${objectName}/fields/Salary__c.field-meta.xml`, content: fieldMetaXml('Salary__c', 'Salary', 'Currency') },
      ];
      await mutate(admin, 'POST', '/api/admin/objects/import-sfdx-files', { files }, 'IMPORT_SFDX_OBJECTS_FOLDER');
      await mutate(admin, 'PUT', `/api/admin/objects/${objectName}/toggle`, { enabled: false }, 'TOGGLE_OBJECT');
      await mutate(admin, 'PUT', `/api/admin/objects/${objectName}/fields/Salary__c/toggle`, { enabled: false }, 'TOGGLE_FIELD');

      const again = await mutate(admin, 'POST', '/api/admin/objects/import-sfdx-files', { files }, 'IMPORT_SFDX_OBJECTS_FOLDER');

      const object = again.body.objects.find((o: any) => o.objectName === objectName);
      assert.equal(object.enabled, false);
      assert.deepEqual(describeFields(object), {
        Id: 'Record ID: Id (required)',
        Name: 'Name: Text',
        Salary__c: 'Salary: Currency (disabled)',
      });
    });

    it('POST /objects/import-sfdx-files rejects an empty files array, or files with no object metadata (400)', async () => {
      const admin = await signIn();
      const mark = auditMark();
      const bodies = [{ files: [] }, {}, { files: [{ relativePath: 'objects/README.md', content: '# notes' }] }];

      for (const body of bodies) {
        assert.equal((await call(admin, 'POST', '/api/admin/objects/import-sfdx-files', body)).status, 400, JSON.stringify(body));
      }
      assertNotAudited(mark, admin.ip);
    });

    it('POST /objects/import-local-folder imports an SFDX objects directory tree and remembers its path', async (t) => {
      t.after(snapshotSettingsRow('sf_connection_settings'));
      const admin = await signIn();
      const widget = newObjectName('LocalWidget');
      const gadget = newObjectName('LocalGadget');
      t.after(() => {
        store.deleteObject(widget);
        store.deleteObject(gadget);
      });
      const folderPath = path.join(tmpRoot, `objects-${nextNumber()}`);
      writeFile(path.join(folderPath, widget, `${widget}.object-meta.xml`), objectMetaXml('Local Widget'));
      writeFile(path.join(folderPath, widget, 'fields', 'Color__c.field-meta.xml'), fieldMetaXml('Color__c', 'Color', 'Text'));
      // A folder without an .object-meta.xml file still becomes an object
      writeFile(path.join(folderPath, gadget, 'fields', 'Size__c.field-meta.xml'), fieldMetaXml('Size__c', 'Size', 'Number', true));
      writeFile(path.join(folderPath, 'README.md'), '# not metadata');

      const res = await mutate(
        admin,
        'POST',
        '/api/admin/objects/import-local-folder',
        { folderPath },
        'SYNC_LOCAL_SFDX_FOLDER',
        folderPath
      );

      assert.deepEqual(res.body.summary, { objectsImported: 2, fieldsImported: 6, resolvedPath: folderPath });
      const imported = Object.fromEntries(
        res.body.objects
          .filter((o: any) => o.objectName === widget || o.objectName === gadget)
          .map((o: any) => [o.objectName, describeFields(o)])
      );
      assert.deepEqual(imported, {
        [widget]: { Color__c: 'Color: Text', Id: 'Record ID: Id (required)', Name: 'Name: Text' },
        [gadget]: { Id: 'Record ID: Id (required)', Name: 'Name: Text', Size__c: 'Size: Number (required)' },
      });
      assert.equal(objectInStore(widget)?.label, 'Local Widget');
      assert.equal(store.getSalesforceSettings().sfdxObjectsFolderPath, folderPath);
    });

    it('POST /objects/import-local-folder rejects a path that does not exist (400)', async () => {
      const admin = await signIn();
      const settingsBefore = store.getSalesforceSettings();
      const mark = auditMark();

      for (const body of [{ folderPath: path.join(tmpRoot, `missing-${RUN}`) }, {}]) {
        const res = await call(admin, 'POST', '/api/admin/objects/import-local-folder', body);
        assert.equal(res.status, 400, JSON.stringify(body));
        assert.equal(typeof res.body.error, 'string');
      }
      assert.deepEqual(store.getSalesforceSettings(), settingsBefore);
      assertNotAudited(mark, admin.ip);
    });

    it('in production, POST /objects/import-local-folder is refused (403) and reads nothing', async (t) => {
      const admin = await signIn();
      const widget = newObjectName('ProdWidget');
      t.after(() => {
        store.deleteObject(widget);
      });
      const folderPath = path.join(tmpRoot, `objects-${nextNumber()}`);
      writeFile(path.join(folderPath, widget, `${widget}.object-meta.xml`), objectMetaXml('Prod Widget'));
      const settingsBefore = store.getSalesforceSettings();
      const mark = auditMark();

      const res = await asProduction(() => call(admin, 'POST', '/api/admin/objects/import-local-folder', { folderPath }));

      assert.equal(res.status, 403);
      assert.match(res.body.error, /outside production/);
      assert.equal(objectInStore(widget), undefined);
      assert.deepEqual(store.getSalesforceSettings(), settingsBefore);
      assertNotAudited(mark, admin.ip);
    });

    it('DELETE /objects/:objectName/fields/:fieldName deletes one field and keeps the rest', async (t) => {
      const admin = await signIn();
      const objectName = addObject(t, 'FieldDelete', ['Id', 'Name', 'Notes__c']);

      const res = await mutate(
        admin,
        'DELETE',
        `/api/admin/objects/${objectName}/fields/Notes__c`,
        undefined,
        'DELETE_FIELD',
        `${objectName}.Notes__c`
      );

      assert.deepEqual(res.body.object.fields.map((f: any) => f.fieldName).sort(), ['Id', 'Name']);
      assert.deepEqual(objectInStore(objectName)?.fields.map((f) => f.fieldName).sort(), ['Id', 'Name']);
    });

    it('DELETE /objects/:objectName deletes the object and its fields', async (t) => {
      const admin = await signIn();
      const objectName = addObject(t, 'Doomed', ['Id', 'Name', 'Notes__c']);

      const res = await mutate(admin, 'DELETE', `/api/admin/objects/${objectName}`, undefined, 'DELETE_OBJECT', objectName);

      assert.ok(!res.body.objects.some((o: any) => o.objectName === objectName));
      assert.equal(objectInStore(objectName), undefined);
    });

    it('DELETE /objects/:objectName answers 404 for an object that does not exist', async () => {
      const admin = await signIn();
      const mark = auditMark();

      const res = await call(admin, 'DELETE', `/api/admin/objects/${newObjectName('Missing')}`);

      assert.equal(res.status, 404);
      assertNotAudited(mark, admin.ip);
    });
  });

  // ----------------------------------------------------------------------------------------------
  describe('7. Groups and the profile-group matrix', () => {
    /** A Read grant on an object this test adds to Salesforce > Objects, as POST /groups stores it. */
    const readGrant = (objectName: string) => ({
      objectName,
      canRead: true,
      canCreate: false,
      canUpdate: false,
      canDelete: false,
      allowedFields: ['Id', 'Name'],
    });

    it('POST /groups creates a group, and posting its id again updates it', async (t) => {
      const admin = await signIn();
      const objectName = addObject(t, 'GroupReaders');
      const name = newGroupName('Account Readers');
      // Not echoed as sent on purpose: the grant is stored as the catalog spells it, with every flag
      // set and the unknown key dropped, and the group starts at version 1.
      const input = {
        name: `  ${name}  `,
        description: ' Read Accounts ',
        allowedActions: ['list_enabled_objects', 'soql_query'],
        objectPermissions: [{ objectName: objectName.toUpperCase(), canRead: true, allowedFields: ['id', 'NAME'], note: 'dropped' }],
      };

      const created = await mutate(admin, 'POST', '/api/admin/groups', input, 'CREATE_GROUP', name);
      const { id } = created.body.group;
      t.after(() => {
        store.deleteGroup(id);
      });
      assert.match(id, /^grp_/);
      const { id: _id, updatedAt: _updatedAt, ...stored } = created.body.group;
      assert.deepEqual(stored, {
        name,
        description: 'Read Accounts',
        allowedActions: input.allowedActions,
        objectPermissions: [readGrant(objectName)],
        version: 1,
      });

      const renamed = newGroupName('Account Editors');
      const update = {
        id,
        expectedVersion: 1,
        name: renamed,
        description: 'Read and update Accounts',
        allowedActions: ['list_enabled_objects', 'soql_query', 'update_record'],
        objectPermissions: [{ ...readGrant(objectName), canUpdate: true }],
      };
      const updated = await mutate(admin, 'POST', '/api/admin/groups', update, 'UPDATE_GROUP', renamed);
      const { updatedAt: _changedAt, ...storedUpdate } = updated.body.group;
      const { expectedVersion: _expected, ...updatedFields } = update;
      assert.deepEqual(storedUpdate, { ...updatedFields, version: 2 });
      assert.equal(store.getGroups().filter((g) => g.id === id).length, 1);
    });

    it('POST /groups refuses an update built from an older version (409) and changes nothing', async (t) => {
      const admin = await signIn();
      const group = addGroup(t, 'Versioned');
      const current = store.upsertGroup({ ...group, description: 'Changed in another tab' });
      assert.equal(current.version, 2);

      const mark = auditMark();
      const stale = await call(admin, 'POST', '/api/admin/groups', {
        ...group,
        expectedVersion: group.version,
        description: 'From the stale tab',
      });

      assert.equal(stale.status, 409);
      assert.match(stale.body.error, /changed since it was loaded, so nothing was saved/);
      assert.deepEqual(stale.body.group, current);
      assert.deepEqual(store.getGroups().find((g) => g.id === group.id), current);
      assertNotAudited(mark, admin.ip);

      // Without expectedVersion (a client from before versions) the update is accepted.
      const unversioned = await mutate(admin, 'POST', '/api/admin/groups', { ...group, description: 'Last write' }, 'UPDATE_GROUP');
      assert.deepEqual([unversioned.body.group.description, unversioned.body.group.version], ['Last write', 3]);
    });

    it('POST /groups saving a group unchanged keeps its version, answers 200 and is audited with an empty diff', async (t) => {
      const admin = await signIn();
      const objectName = addObject(t, 'Unchanged');
      const created = await mutate(
        admin,
        'POST',
        '/api/admin/groups',
        { name: newGroupName('Unchanged'), description: 'Kept', allowedActions: ['soql_query'], objectPermissions: [readGrant(objectName)] },
        'CREATE_GROUP'
      );
      const group = created.body.group as AccessGroup;
      t.after(() => {
        store.deleteGroup(group.id);
      });
      const revision = store.getPolicyRevision();

      // Sent in another spelling, with spaces and without the false flags: parsed, it is what is stored.
      const resave = await mutate(
        admin,
        'POST',
        '/api/admin/groups',
        {
          id: group.id,
          expectedVersion: group.version,
          name: ` ${group.name} `,
          description: group.description,
          allowedActions: group.allowedActions,
          objectPermissions: [{ objectName: objectName.toLowerCase(), canRead: true, allowedFields: ['id', 'NAME'] }],
        },
        'UPDATE_GROUP',
        group.name
      );

      assert.deepEqual(resave.body.group, group, 'same version and updatedAt');
      assert.deepEqual(resave.body.groups.find((g: AccessGroup) => g.id === group.id), group);
      assert.deepEqual(resave.audit.diff, { before: {}, after: {} });
      assert.equal(resave.audit.details, `Saved Access Group "${group.name}" (1 MCP actions, 1 objects configured) without changes.`);
      assert.equal(store.getPolicyRevision(), revision);

      // So an editor that loaded the group before the no-op save can still save its change.
      const otherTab = await signIn();
      const changed = await mutate(
        otherTab,
        'POST',
        '/api/admin/groups',
        { ...group, expectedVersion: group.version, description: 'Changed in the other tab' },
        'UPDATE_GROUP'
      );
      assert.equal(changed.body.group.version, group.version + 1);
      assert.match(changed.audit.details, /^Updated Access Group /);
    });

    it('POST /groups answers a draft still holding an Object or field deleted since with the reload 409, not a 400', async (t) => {
      const admin = await signIn();
      const objectName = addObject(t, 'StaleEditor', ['Id', 'Name', 'Phone']);
      const created = await mutate(admin, 'POST', '/api/admin/groups', {
        name: newGroupName('Stale Editor'),
        allowedActions: ['soql_query'],
        objectPermissions: [{ ...readGrant(objectName), allowedFields: ['Id', 'Name', 'Phone'] }],
      }, 'CREATE_GROUP');
      const loaded = created.body.group as AccessGroup;
      t.after(() => {
        store.deleteGroup(loaded.id);
      });
      // The editor's draft, built from the group as loaded, still names the field and the Object.
      const saveLoaded = () =>
        call(admin, 'POST', '/api/admin/groups', { ...loaded, expectedVersion: loaded.version, description: 'From the stale tab' });
      const assertReloadConflict = async () => {
        const mark = auditMark();
        const current = store.getGroups().find((g) => g.id === loaded.id);
        const res = await saveLoaded();
        assert.equal(res.status, 409, JSON.stringify(res.body));
        assert.match(res.body.error, /changed since it was loaded, so nothing was saved/);
        assert.deepEqual(res.body.group, current);
        assert.deepEqual(store.getGroups().find((g) => g.id === loaded.id), current);
        assertNotAudited(mark, admin.ip);
      };

      // Deleting the field revokes it from the group, a change the editor never saw.
      await mutate(admin, 'DELETE', `/api/admin/objects/${objectName}/fields/Phone`, undefined, 'DELETE_FIELD');
      await assertReloadConflict();
      await mutate(admin, 'DELETE', `/api/admin/objects/${objectName}`, undefined, 'DELETE_OBJECT');
      await assertReloadConflict();

      // Saved without a version, the same draft lists the held Object live, which would restore it
      // unseen: a restore needs the version the client loaded, so it is the reload 409 too.
      const mark = auditMark();
      const current = store.getGroups().find((g) => g.id === loaded.id);
      const unversioned = await call(admin, 'POST', '/api/admin/groups', loaded);
      assert.equal(unversioned.status, 409, JSON.stringify(unversioned.body));
      assert.match(unversioned.body.error, /restoring one needs the version of the group that was loaded/);
      assert.deepEqual(store.getGroups().find((g) => g.id === loaded.id), current);
      assertNotAudited(mark, admin.ip);
    });

    it('POST /groups answers a draft loaded before an older release changed the group with the reload 409', async (t) => {
      const admin = await signIn();
      const objectName = addObject(t, 'OlderRelease', ['Id', 'Name']);
      const created = await mutate(admin, 'POST', '/api/admin/groups', {
        name: newGroupName('Older Release'),
        allowedActions: ['list_enabled_objects'],
        objectPermissions: [],
      }, 'CREATE_GROUP');
      const loaded = created.body.group as AccessGroup;
      t.after(() => {
        store.deleteGroup(loaded.id);
      });
      // An older release run on the database after a rollback saves the group as its upsert does,
      // on a connection of its own, leaving the version column alone.
      const olderRelease = new DatabaseSync(config.dbPath);
      try {
        olderRelease
          .prepare(
            `INSERT INTO access_groups (id, name, description, allowed_actions_json, object_permissions_json, updated_at)
             VALUES (?, ?, 'ROLLBACK EDIT', '["list_enabled_objects","soql_query"]', ?, ?)
             ON CONFLICT(id) DO UPDATE SET
               name = excluded.name, description = excluded.description, allowed_actions_json = excluded.allowed_actions_json,
               object_permissions_json = excluded.object_permissions_json, updated_at = excluded.updated_at`
          )
          .run(loaded.id, loaded.name, JSON.stringify([{ objectName, canRead: true, allowedFields: ['Name'] }]), new Date().toISOString());
      } finally {
        olderRelease.close();
      }
      const current = store.getGroups().find((g) => g.id === loaded.id)!;
      assert.equal(current.version, loaded.version + 1);

      const mark = auditMark();
      const res = await call(admin, 'POST', '/api/admin/groups', { ...loaded, expectedVersion: loaded.version, description: 'From the stale tab' });
      assert.equal(res.status, 409, JSON.stringify(res.body));
      assert.match(res.body.error, /changed since it was loaded, so nothing was saved/);
      assert.deepEqual(store.getGroups().find((g) => g.id === loaded.id), current);
      assertNotAudited(mark, admin.ip);
    });

    it('POST /groups with an id no group has answers 404 and creates nothing', async () => {
      const admin = await signIn();
      const id = `grp_missing_${RUN}`;
      const mark = auditMark();
      const res = await call(admin, 'POST', '/api/admin/groups', { id, name: newGroupName('Never Created') });
      assert.deepEqual([res.status, res.body], [404, { error: 'Group not found.' }]);
      assert.ok(!store.getGroups().some((g) => g.id === id));
      assertNotAudited(mark, admin.ip);
    });

    it('POST /groups with the name of another group is refused with 400 or 409, not a 500', async (t) => {
      const admin = await signIn();
      const existing = addGroup(t, 'Taken Name');
      t.after(() => {
        for (const duplicate of store.getGroups().filter((g) => g.name === existing.name && g.id !== existing.id)) {
          store.deleteGroup(duplicate.id);
        }
      });

      const res = await call(admin, 'POST', '/api/admin/groups', { name: existing.name, allowedActions: ['soql_query'] });

      assert.ok([400, 409].includes(res.status), `expected 400 or 409, got ${res.status} ${JSON.stringify(res.body)}`);
      assert.equal(store.getGroups().filter((g) => g.name === existing.name).length, 1);
    });

    it('PUT /profile-groups/:profileId adds and removes single groups of a profile', async (t) => {
      const admin = await signIn();
      const profileId = addProfile(t);
      const first = addGroup(t, 'Matrix A');
      const second = addGroup(t, 'Matrix B');
      const url = `/api/admin/profile-groups/${profileId}`;

      const both = await mutate(admin, 'PUT', url, { add: [first.id, second.id] }, 'UPDATE_PROFILE_GROUPS', profileId);
      assert.deepEqual(both.body.mapping.profileId, profileId);
      assert.deepEqual([...both.body.mapping.groupIds].sort(), [first.id, second.id].sort());
      assert.deepEqual(mappedGroupIds(profileId)?.sort(), [first.id, second.id].sort());
      assert.ok(both.audit.details.includes(first.name) && both.audit.details.includes(second.name), both.audit.details);
      assert.match(both.audit.details, /Added: /);

      const removal = await mutate(admin, 'PUT', url, { remove: [first.id] }, 'UPDATE_PROFILE_GROUPS', profileId);
      assert.deepEqual(mappedGroupIds(profileId), [second.id]);
      assert.ok(removal.audit.details.includes(`Removed: ${first.name}.`), removal.audit.details);

      // Nothing to change: still 200 with the current mapping, and one audit row saying so.
      const noChange = await mutate(admin, 'PUT', url, { add: [second.id], remove: [first.id] }, 'UPDATE_PROFILE_GROUPS');
      assert.deepEqual(noChange.body.mapping, { profileId, groupIds: [second.id] });
      assert.match(noChange.audit.details, /Nothing changed\./);

      await mutate(admin, 'PUT', url, { groupIds: [first.id], expectedGroupIds: [second.id] }, 'UPDATE_PROFILE_GROUPS');
      assert.deepEqual(mappedGroupIds(profileId), [first.id]);

      await mutate(admin, 'PUT', url, { groupIds: [], expectedGroupIds: [first.id] }, 'UPDATE_PROFILE_GROUPS');
      assert.deepEqual(mappedGroupIds(profileId), []);
    });

    it('PUT /profile-groups refuses a full replacement whose expectedGroupIds are stale (409) and changes nothing', async (t) => {
      const admin = await signIn();
      const profileId = addProfile(t);
      const stored = addGroup(t, 'Matrix Stored');
      const revoked = addGroup(t, 'Matrix Revoked');
      store.setProfileGroups(profileId, [stored.id]);
      const mark = auditMark();

      // Built from a screen that still showed the revoked group.
      const res = await call(admin, 'PUT', `/api/admin/profile-groups/${profileId}`, {
        groupIds: [stored.id, revoked.id],
        expectedGroupIds: [revoked.id],
      });

      assert.equal(res.status, 409, JSON.stringify(res.body));
      assert.deepEqual(res.body.mapping, { profileId, groupIds: [stored.id] });
      assert.deepEqual(mappedGroupIds(profileId), [stored.id]);
      assertNotAudited(mark, admin.ip);
    });

    it('PUT /profile-groups answers 404 for an unknown profile and 400 for a malformed body', async (t) => {
      const admin = await signIn();
      const profileId = addProfile(t);
      const group = addGroup(t, 'Matrix Validation');
      store.setProfileGroups(profileId, [group.id]);
      const url = `/api/admin/profile-groups/${profileId}`;
      const mark = auditMark();

      const unknownProfile = await call(admin, 'PUT', `/api/admin/profile-groups/${newProfileId()}`, { add: [group.id] });
      const statuses = [unknownProfile.status];
      for (const body of [
        {},
        { add: group.id },
        { remove: [7] },
        { groupIds: group.id, expectedGroupIds: [group.id] },
        // A full replacement without the groups it was built from could re-grant a revoked group.
        { groupIds: [] },
        { groupIds: [], expectedGroupIds: [group.id], remove: [group.id] },
        { add: [group.id], remove: [group.id] },
      ]) {
        statuses.push((await call(admin, 'PUT', url, body)).status);
      }

      assert.deepEqual(statuses, [404, 400, 400, 400, 400, 400, 400, 400]);
      assert.deepEqual(mappedGroupIds(profileId), [group.id]);
      assertNotAudited(mark, admin.ip);
    });

    it('PUT /profile-groups with an unknown group id is rejected (400/404) and leaves the mapping untouched', async (t) => {
      const admin = await signIn();
      const profileId = addProfile(t);
      const kept = addGroup(t, 'Matrix Kept');
      const other = addGroup(t, 'Matrix Other');
      store.setProfileGroups(profileId, [kept.id]);
      const mark = auditMark();

      // A valid group first, then an id that does not exist: all or nothing.
      for (const body of [
        { add: [other.id, `grp_missing_${RUN}`], remove: [kept.id] },
        { groupIds: [other.id, `grp_missing_${RUN}`], expectedGroupIds: [kept.id] },
      ]) {
        const res = await call(admin, 'PUT', `/api/admin/profile-groups/${profileId}`, body);

        const mapping = mappedGroupIds(profileId);
        const auditRows = auditRowsSince(mark, admin.ip).map(describeAuditRow);
        assert.deepEqual(
          { clientError: [400, 404].includes(res.status), mapping, auditRows },
          { clientError: true, mapping: [kept.id], auditRows: [] },
          `PUT ${JSON.stringify(body)} answered ${res.status} ${JSON.stringify(res.body)}`
        );
      }
    });

    it('POST /groups/:id/profiles adds and removes many profiles of one group', async (t) => {
      const admin = await signIn();
      const [first, second, third] = [addProfile(t, `Bulk One ${RUN}`), addProfile(t), addProfile(t)];
      const group = addGroup(t, 'Bulk Target');
      const other = addGroup(t, 'Bulk Other');
      store.setProfileGroups(first, [group.id, other.id]);
      const url = `/api/admin/groups/${group.id}/profiles`;

      const res = await mutate(admin, 'POST', url, { add: [second, third], remove: [first] }, 'UPDATE_PROFILE_GROUPS', group.name);

      assert.equal(res.body.membership.groupId, group.id);
      assert.deepEqual([...res.body.membership.profileIds].sort(), [second, third].sort());
      assert.deepEqual(mappedGroupIds(first), [other.id], "the profile's other group stays");
      assert.deepEqual(mappedGroupIds(second), [group.id]);
      assert.deepEqual(mappedGroupIds(third), [group.id]);
      assert.deepEqual(res.body.profileGroupMappings.find((m: any) => m.profileId === second)?.groupIds, [group.id]);
      assert.ok(res.audit.details.includes(`Removed: Bulk One ${RUN} (${first}).`), res.audit.details);
      assert.ok(res.audit.details.includes(second) && res.audit.details.includes(third), res.audit.details);

      const noChange = await mutate(admin, 'POST', url, { add: [second] }, 'UPDATE_PROFILE_GROUPS', group.name);
      assert.deepEqual([...noChange.body.membership.profileIds].sort(), [second, third].sort());
      assert.match(noChange.audit.details, /Nothing changed\./);
    });

    it('POST /groups/:id/profiles answers 404 for an unknown group and 400 for an unknown profile or a malformed body', async (t) => {
      const admin = await signIn();
      const profileId = addProfile(t);
      const other = addProfile(t);
      const group = addGroup(t, 'Bulk Validation');
      store.setProfileGroups(profileId, [group.id]);
      const url = `/api/admin/groups/${group.id}/profiles`;
      const mark = auditMark();

      const statuses = [(await call(admin, 'POST', `/api/admin/groups/grp_missing_${RUN}/profiles`, { add: [profileId] })).status];
      for (const body of [
        {},
        { add: profileId },
        { add: [other, newProfileId()], remove: [profileId] },
        { add: [other], remove: [other] },
      ]) {
        statuses.push((await call(admin, 'POST', url, body)).status);
      }

      assert.deepEqual(statuses, [404, 400, 400, 400, 400]);
      assert.deepEqual(mappedGroupIds(profileId), [group.id]);
      assert.deepEqual(mappedGroupIds(other), []);
      assertNotAudited(mark, admin.ip);
    });

    it('DELETE /groups/:id deletes the group and removes it from every profile mapping', async (t) => {
      const admin = await signIn();
      const profileId = addProfile(t);
      const doomed = addGroup(t, 'Matrix Doomed');
      const kept = addGroup(t, 'Matrix Kept');
      store.setProfileGroups(profileId, [doomed.id, kept.id]);

      const res = await mutate(admin, 'DELETE', `/api/admin/groups/${doomed.id}`, undefined, 'DELETE_GROUP', doomed.name);

      assert.ok(!res.body.groups.some((g: any) => g.id === doomed.id));
      assert.deepEqual(res.body.profileGroupMappings.find((m: any) => m.profileId === profileId)?.groupIds, [kept.id]);
      assert.deepEqual(mappedGroupIds(profileId), [kept.id]);
    });

    it('DELETE /groups/:id answers 404 for a group that does not exist', async () => {
      const admin = await signIn();
      const mark = auditMark();

      const res = await call(admin, 'DELETE', `/api/admin/groups/grp_missing_${RUN}`);

      assert.equal(res.status, 404);
      assertNotAudited(mark, admin.ip);
    });

    /**
     * Makes the next Portal Admin log write throw, as a full disk or a locked database would. The
     * returned function puts the real writer back, for the retry.
     */
    function failNextAuditWrite(t: TestContext): () => void {
      const realRecord = store.recordPortalAdminLog;
      let failed = false;
      const mocked = t.mock.method(store, 'recordPortalAdminLog', function (this: typeof store, input: Parameters<typeof realRecord>[0]) {
        if (!failed) {
          failed = true;
          throw new Error('audit write failed');
        }
        return realRecord.call(this, input);
      });
      return () => mocked.mock.restore();
    }

    /** The request answered 500 through the shared error handler, and wrote no audit row. */
    function assertRolledBack(res: ApiResponse, mark: string | undefined, session: Session): void {
      assert.deepEqual([res.status, res.body], [500, { error: 'Internal server error' }]);
      assertNotAudited(mark, session.ip);
    }

    it('POST /groups whose audit entry cannot be written creates or changes nothing (500)', async (t) => {
      const admin = await signIn();
      const name = newGroupName('Unlogged Create');
      const objectName = addObject(t, 'UnloggedCreate');
      const input = { name, description: 'Never saved', allowedActions: ['soql_query'], objectPermissions: [readGrant(objectName)] };
      t.after(() => {
        for (const group of store.getGroups().filter((g) => g.name === name)) store.deleteGroup(group.id);
      });

      let mark = auditMark();
      let restore = failNextAuditWrite(t);
      assertRolledBack(await call(admin, 'POST', '/api/admin/groups', input), mark, admin);
      restore();
      assert.ok(!store.getGroups().some((g) => g.name === name), 'the group must not have been created');

      // Nothing half-saved is left in the way: the retry creates it, and its row holds the whole group.
      const created = await mutate(admin, 'POST', '/api/admin/groups', input, 'CREATE_GROUP', name);
      const { id: _id, updatedAt: _updatedAt, version: _version, ...stored } = created.body.group;
      assert.deepEqual(created.audit.diff, { after: stored });

      const existing = created.body.group as AccessGroup;
      const update = { ...input, id: existing.id, name: newGroupName('Unlogged Update'), allowedActions: ['delete_record'] };
      mark = auditMark();
      restore = failNextAuditWrite(t);
      assertRolledBack(await call(admin, 'POST', '/api/admin/groups', update), mark, admin);
      restore();
      assert.deepEqual(store.getGroups().find((g) => g.id === existing.id), existing, 'the group must be unchanged');
    });

    it('DELETE /groups/:id whose audit entry cannot be written keeps the group and its mappings (500)', async (t) => {
      const admin = await signIn();
      const profileId = addProfile(t);
      const group = addGroup(t, 'Unlogged Delete');
      store.setProfileGroups(profileId, [group.id]);

      const mark = auditMark();
      const restore = failNextAuditWrite(t);
      assertRolledBack(await call(admin, 'DELETE', `/api/admin/groups/${group.id}`), mark, admin);
      restore();
      assert.deepEqual(store.getGroups().find((g) => g.id === group.id), group);
      assert.deepEqual(mappedGroupIds(profileId), [group.id]);

      const deleted = await mutate(admin, 'DELETE', `/api/admin/groups/${group.id}`, undefined, 'DELETE_GROUP', group.name);
      const { id: _id, updatedAt: _updatedAt, version: _version, ...fields } = group;
      assert.deepEqual(deleted.audit.diff, { before: { ...fields, profileIds: [profileId] } });
    });

    it('PUT /profile-groups/:profileId whose audit entry cannot be written leaves the mapping as it was (500)', async (t) => {
      const admin = await signIn();
      const profileId = addProfile(t);
      const kept = addGroup(t, 'Unlogged Kept');
      const added = addGroup(t, 'Unlogged Added');
      store.setProfileGroups(profileId, [kept.id]);
      const url = `/api/admin/profile-groups/${profileId}`;
      const change = { add: [added.id], remove: [kept.id] };

      const mark = auditMark();
      const restore = failNextAuditWrite(t);
      assertRolledBack(await call(admin, 'PUT', url, change), mark, admin);
      restore();
      assert.deepEqual(mappedGroupIds(profileId), [kept.id]);

      // Had any of it been applied, the retry would report less than the whole change.
      const retried = await mutate(admin, 'PUT', url, change, 'UPDATE_PROFILE_GROUPS', profileId);
      assert.deepEqual(retried.audit.diff, { added: [added.id], removed: [kept.id] });
    });

    it('POST /groups/:id/profiles whose audit entry cannot be written leaves every membership as it was (500)', async (t) => {
      const admin = await signIn();
      const [member, joining] = [addProfile(t), addProfile(t)];
      const group = addGroup(t, 'Unlogged Bulk');
      store.setProfileGroups(member, [group.id]);
      const url = `/api/admin/groups/${group.id}/profiles`;
      const change = { add: [joining], remove: [member] };

      const mark = auditMark();
      const restore = failNextAuditWrite(t);
      assertRolledBack(await call(admin, 'POST', url, change), mark, admin);
      restore();
      assert.deepEqual([mappedGroupIds(member), mappedGroupIds(joining)], [[group.id], []]);

      const retried = await mutate(admin, 'POST', url, change, 'UPDATE_PROFILE_GROUPS', group.name);
      assert.deepEqual(retried.audit.diff, { added: [joining], removed: [member] });
    });

    it('POST /workspace/seed-sample loads the sample groups and maps the sample profiles to them', async (t) => {
      const admin = await signIn();
      const profilesBefore = new Set(store.getProfiles().map((p) => p.id));
      const groupsBefore = new Set(store.getGroups().map((g) => g.id));
      // Deleting what the seed added also drops its mappings (ON DELETE CASCADE).
      t.after(() => {
        for (const group of store.getGroups().filter((g) => !groupsBefore.has(g.id))) store.deleteGroup(group.id);
        for (const profile of store.getProfiles().filter((p) => !profilesBefore.has(p.id))) store.deleteProfile(profile.id);
      });

      const res = await mutate(admin, 'POST', '/api/admin/workspace/seed-sample', {}, 'SEED_ENTERPRISE_MATRIX', 'Access Matrix');

      const seeded = res.body.groups.filter((g: any) => !groupsBefore.has(g.id)).map((g: any) => g.id);
      assert.deepEqual(seeded.sort(), ['grp-admin', 'grp-revops', 'grp-sales-ro', 'grp-sales-rw', 'grp-svc-cases']);
      assert.deepEqual(mappedGroupIds('00e5g000001B2k9AAC')?.sort(), ['grp-sales-ro', 'grp-sales-rw']);
    });

    it('POST /workspace/seed-sample answers 409 and loads nothing while another group has a sample name, in any case', async (t) => {
      const admin = await signIn();
      const sampleIds = ['grp-admin', 'grp-revops', 'grp-sales-ro', 'grp-sales-rw', 'grp-svc-cases'];
      assert.ok(!store.getGroups().some((g) => sampleIds.includes(g.id)), 'precondition: no sample group is loaded');
      const profilesBefore = new Set(store.getProfiles().map((p) => p.id));
      t.after(() => {
        for (const id of sampleIds) store.deleteGroup(id);
        for (const profile of store.getProfiles().filter((p) => !profilesBefore.has(p.id))) store.deleteProfile(profile.id);
      });
      const state = () =>
        JSON.stringify({ profiles: store.getProfiles(), groups: store.getGroups(), mappings: store.getProfileGroupMappings() });

      for (const name of ['Platform Admin', 'SALES · READ-ONLY']) {
        const holder = store.createGroup({ name, allowedActions: [], objectPermissions: [] });
        const before = state();
        const revision = store.getPolicyRevision();
        const mark = auditMark();

        const res = await call(admin, 'POST', '/api/admin/workspace/seed-sample', {});

        assert.equal(res.status, 409, JSON.stringify(res.body));
        assert.ok(
          res.body.error.startsWith(`Access Group "${name}" already uses the name of the sample group "`),
          res.body.error
        );
        assert.equal(state(), before);
        assert.equal(store.getPolicyRevision(), revision);
        assertNotAudited(mark, admin.ip);
        store.deleteGroup(holder.id);
      }

      // With the names free it loads, and loading it again still answers 200.
      await mutate(admin, 'POST', '/api/admin/workspace/seed-sample', {}, 'SEED_ENTERPRISE_MATRIX');
      await mutate(admin, 'POST', '/api/admin/workspace/seed-sample', {}, 'SEED_ENTERPRISE_MATRIX');

      // A sample group renamed to another one's exact name holds it while that one is saved: 409 too.
      const readOnly = store.getGroups().find((g) => g.id === 'grp-sales-ro')!;
      const admins = store.getGroups().find((g) => g.id === 'grp-admin')!;
      store.upsertGroup({ ...readOnly, name: `Renamed ${RUN}` });
      store.upsertGroup({ ...admins, name: readOnly.name });
      const before = state();
      const mark = auditMark();
      const res = await call(admin, 'POST', '/api/admin/workspace/seed-sample', {});
      assert.equal(res.status, 409, JSON.stringify(res.body));
      assert.match(res.body.error, /because another Access Group has it, so no sample data was loaded/);
      assert.equal(state(), before);
      assertNotAudited(mark, admin.ip);

      // The other way round, where the group holding the name is saved before the one it belongs to: 409 as well.
      store.upsertGroup({ ...store.getGroups().find((g) => g.id === 'grp-admin')!, name: `Renamed admin ${RUN}` });
      store.upsertGroup({ ...store.getGroups().find((g) => g.id === 'grp-sales-ro')!, name: admins.name });
      const reversed = state();
      const reversedMark = auditMark();
      const refused = await call(admin, 'POST', '/api/admin/workspace/seed-sample', {});
      assert.equal(refused.status, 409, JSON.stringify(refused.body));
      assert.match(refused.body.error, /because another Access Group has it, so no sample data was loaded/);
      assert.equal(state(), reversed);
      assertNotAudited(reversedMark, admin.ip);
    });
  });

  // ----------------------------------------------------------------------------------------------
  describe('8. Settings', () => {
    it('PUT /okta stores the client secret but neither it nor GET /overview ever returns it (only hasClientSecret)', async (t) => {
      t.after(snapshotSettingsRow('okta_config'));
      const admin = await signIn();
      const clientSecret = `okta-secret-${RUN}-${crypto.randomBytes(12).toString('hex')}`;

      const res = await mutate(
        admin,
        'PUT',
        '/api/admin/okta',
        { enabled: true, oktaDomain: `dev-${RUN}.okta.com`, clientId: `client-${RUN}`, clientSecret, adminGroup: 'MCP-Admins' },
        'UPDATE_OKTA_SSO',
        `dev-${RUN}.okta.com`
      );

      assert.equal(store.getOktaConfig().clientSecret, clientSecret, 'control: the secret was stored');
      assert.equal(res.body.oktaSettings.hasClientSecret, true);
      assert.equal(res.body.oktaSettings.clientId, `client-${RUN}`);
      assert.equal('clientSecret' in res.body.oktaSettings, false);
      assert.ok(!JSON.stringify(res.body).includes(clientSecret), 'PUT /okta echoed the client secret');

      const overview = await call(admin, 'GET', '/api/admin/overview');
      assert.equal(overview.status, 200);
      assert.equal(overview.body.oktaSettings.hasClientSecret, true);
      assert.equal('clientSecret' in overview.body.oktaSettings, false);
      // The whole payload, so the portal admin logs it includes are covered too
      assert.ok(!JSON.stringify(overview.body).includes(clientSecret), 'GET /overview leaked the client secret');

      const session = await call(admin, 'GET', '/api/admin/session');
      assert.ok(!JSON.stringify(session.body).includes(clientSecret), 'GET /session leaked the client secret');
    });

    it('PUT /sf-settings applies a partial update and leaves every other setting unchanged', async (t) => {
      t.after(snapshotSettingsRow('sf_connection_settings'));
      const admin = await signIn();
      const { updatedAt: _before, ...before } = store.getSalesforceSettings();
      const orgId = `00D${RUN}000000001`;

      const first = await mutate(admin, 'PUT', '/api/admin/sf-settings', { apiVersion: 'v59.0' }, 'UPDATE_SF_SETTINGS');
      const { updatedAt: _first, ...afterFirst } = first.body.sfSettings;
      assert.deepEqual(afterFirst, { ...before, apiVersion: 'v59.0' });

      const second = await mutate(admin, 'PUT', '/api/admin/sf-settings', { expectedOrgId: orgId }, 'UPDATE_SF_SETTINGS');
      const { updatedAt: _second, ...afterSecond } = second.body.sfSettings;
      assert.deepEqual(afterSecond, { ...before, apiVersion: 'v59.0', expectedOrgId: orgId });
    });
  });

  // ----------------------------------------------------------------------------------------------
  describe('9. Portal users', () => {
    it('POST /portal-users creates an admin who can sign in and whose changes are audited under their own name', async (t) => {
      const admin = await signIn();
      const username = newUsername('ops');
      const password = `Pw-${RUN}-${crypto.randomBytes(6).toString('hex')}`;
      t.after(() => removePortalUser(username));

      const created = await mutate(
        admin,
        'POST',
        '/api/admin/portal-users',
        { username, displayName: 'Ops Admin', password, role: 'Admin' },
        'UPSERT_PORTAL_USER',
        username
      );
      const entry = created.body.portalUsers.find((u: any) => u.username === username);
      assert.deepEqual({ displayName: entry?.displayName, role: entry?.role }, { displayName: 'Ops Admin', role: 'Admin' });
      for (const user of created.body.portalUsers) {
        assert.deepEqual(Object.keys(user).sort(), ['createdAt', 'displayName', 'lastLoginAt', 'role', 'totpEnrolled', 'username']);
      }
      assert.ok(!JSON.stringify(created.body).includes(password));

      const second = await signIn(newClientIp(), username, password);
      assert.equal((await call(second, 'GET', '/api/admin/session')).body.user.username, username);

      const profileId = newProfileId();
      t.after(() => {
        store.deleteProfile(profileId);
      });
      await mutate(second, 'POST', '/api/admin/profiles', { id: profileId, name: `Created by ${username}` }, 'CREATE_PROFILE', profileId);
    });

    it(`POST /portal-users refuses a password shorter than ${PORTAL_PASSWORD_MIN_LENGTH} characters (400) and saves nothing`, async (t) => {
      const admin = await signIn();
      const { username, password } = addPortalUser(t);
      const newcomer = newUsername('short');
      t.after(() => removePortalUser(newcomer));
      const tooShort = 'x'.repeat(PORTAL_PASSWORD_MIN_LENGTH - 1);
      const mark = auditMark();

      for (const target of [newcomer, username]) {
        const res = await call(admin, 'POST', '/api/admin/portal-users', { username: target, password: tooShort });
        assert.equal(res.status, 400, target);
        assert.match(res.body.error, new RegExp(`at least ${PORTAL_PASSWORD_MIN_LENGTH} characters`));
      }

      assert.ok(!store.getPortalUsers().some((u) => u.username === newcomer));
      assert.ok(store.verifyPortalUserCredentials(username, password), 'the existing password is kept');
      assertNotAudited(mark, admin.ip);

      // Exactly the minimum is enough, as the portal form says.
      const justLongEnough = 'y'.repeat(PORTAL_PASSWORD_MIN_LENGTH);
      await mutate(admin, 'POST', '/api/admin/portal-users', { username: newcomer, password: justLongEnough }, 'UPSERT_PORTAL_USER', newcomer);
      assert.ok(store.verifyPortalUserCredentials(newcomer, justLongEnough));
    });

    it('in production, POST /portal-users refuses every publicly known default password (400)', async (t) => {
      const admin = await signIn();
      const { username, password } = addPortalUser(t);
      const newcomer = newUsername('known');
      t.after(() => removePortalUser(newcomer));
      // Shorter ones are already refused by the length rule; at least one must reach the known-password check.
      assert.ok(KNOWN_DEFAULT_PASSWORDS.some((known) => known.length >= PORTAL_PASSWORD_MIN_LENGTH));
      const mark = auditMark();

      await asProduction(async () => {
        for (const target of [newcomer, username]) {
          for (const known of KNOWN_DEFAULT_PASSWORDS) {
            const res = await call(admin, 'POST', '/api/admin/portal-users', { username: target, password: known });
            assert.equal(res.status, 400, `${target}: ${known}`);
            assert.match(res.body.error, known.length < PORTAL_PASSWORD_MIN_LENGTH ? /at least/ : /publicly known/);
          }
        }
      });

      assert.ok(!store.getPortalUsers().some((u) => u.username === newcomer));
      assert.ok(store.verifyPortalUserCredentials(username, password), 'the existing password is kept');
      assertNotAudited(mark, admin.ip);
    });

    it('DELETE /portal-users/:username removes the admin, who then can no longer sign in', async (t) => {
      const admin = await signIn();
      const { username, password } = addPortalUser(t);
      await signIn(newClientIp(), username, password);

      const res = await mutate(
        admin,
        'DELETE',
        `/api/admin/portal-users/${encodeURIComponent(username)}`,
        undefined,
        'DELETE_PORTAL_USER',
        username
      );

      assert.ok(!res.body.portalUsers.some((u: any) => u.username === username));
      assert.equal((await postLogin(newClientIp(), { username, password })).status, 401);
    });

    it("a deleted portal admin's existing session stops working", async (t) => {
      const admin = await signIn();
      const { username, password } = addPortalUser(t);
      const removed = await signIn(newClientIp(), username, password);
      await mutate(admin, 'DELETE', `/api/admin/portal-users/${encodeURIComponent(username)}`, undefined, 'DELETE_PORTAL_USER');

      const overview = await call(removed, 'GET', '/api/admin/overview');
      const recreateOwnAccount = await call(removed, 'POST', '/api/admin/portal-users', { username, password });

      assert.deepEqual(
        { overview: overview.status, recreateOwnAccount: recreateOwnAccount.status },
        { overview: 401, recreateOwnAccount: 401 }
      );
    });

    it('deleting the last remaining portal admin is refused (400)', async (t) => {
      const admin = await signIn();
      parkPortalUsersExcept(t, BOOTSTRAP_ADMIN.username);
      assert.deepEqual(store.getPortalUsers().map((u) => u.username), [BOOTSTRAP_ADMIN.username]);
      const mark = auditMark();

      const res = await call(admin, 'DELETE', `/api/admin/portal-users/${BOOTSTRAP_ADMIN.username}`);

      assert.equal(res.status, 400);
      assert.match(res.body.error, /last remaining/i);
      assert.deepEqual(store.getPortalUsers().map((u) => u.username), [BOOTSTRAP_ADMIN.username]);
      assertNotAudited(mark, admin.ip);
    });

    it('deleting a portal user that does not exist answers 404 and writes no audit row', async (t) => {
      const admin = await signIn();
      addPortalUser(t); // a second user, so the last-admin guard does not answer first
      const mark = auditMark();

      const res = await call(admin, 'DELETE', `/api/admin/portal-users/${encodeURIComponent(newUsername('ghost'))}`);

      assert.deepEqual(
        { status: res.status, auditRows: auditRowsSince(mark, admin.ip).map((r) => `${r.action}: ${r.details}`) },
        { status: 404, auditRows: [] }
      );
    });
  });

  // ----------------------------------------------------------------------------------------------
  describe('10. Policy simulator (POST /test-mcp-access)', () => {
    const fx = { profileId: '', profileName: '', objectName: '', groupId: '', groupName: '' };

    before(() => {
      fx.profileId = newProfileId();
      fx.profileName = `Simulated Support ${RUN}`;
      fx.objectName = newObjectName('SimCase');
      fx.groupName = newGroupName('Simulated Readers');
      store.upsertProfile(fx.profileId, fx.profileName);
      store.upsertObjectWithFields({
        objectName: fx.objectName,
        fields: [{ fieldName: 'Id' }, { fieldName: 'Name' }, { fieldName: 'Subject__c' }, { fieldName: 'SSN__c' }],
      });
      const group = store.upsertGroup({
        name: fx.groupName,
        allowedActions: ['list_enabled_objects', 'describe_object', 'soql_query'],
        objectPermissions: [
          {
            objectName: fx.objectName,
            canRead: true,
            canCreate: false,
            canUpdate: false,
            canDelete: false,
            allowedFields: ['Id', 'Name', 'Subject__c'],
          },
        ],
      });
      fx.groupId = group.id;
      store.setProfileGroups(fx.profileId, [group.id]);
    });

    after(() => {
      store.deleteProfile(fx.profileId);
      store.deleteObject(fx.objectName);
      store.deleteGroup(fx.groupId);
    });

    it('a mapped profile with a granted tool and object is permitted and gets a simulator token that works on /mcp', async () => {
      const admin = await signIn();
      sf.reset();

      const res = await call(admin, 'POST', '/api/admin/test-mcp-access', {
        profileId: fx.profileId,
        toolName: 'soql_query',
        targetObject: fx.objectName,
      });

      assert.equal(res.status, 200, JSON.stringify(res.body));
      const { evaluation, effectivePermissions, simulatorBearerToken } = res.body;
      assert.equal(evaluation.permitted, true, evaluation.reason);
      assert.deepEqual(evaluation.matchedGroups, [fx.groupName]);
      assert.deepEqual([...evaluation.allowedFields].sort(), ['Id', 'Name', 'Subject__c']);
      assert.deepEqual(effectivePermissions, {
        profileId: fx.profileId,
        profileName: fx.profileName,
        assignedGroups: [{ id: fx.groupId, name: fx.groupName }],
        allowedActions: ['list_enabled_objects', 'describe_object', 'soql_query'],
      });
      assert.match(simulatorBearerToken, SIMULATOR_TOKEN);

      const tools = await mcpRequest(server.baseUrl, simulatorBearerToken, 'tools/list', {}, { 'X-Forwarded-For': admin.ip });
      assert.equal(tools.status, 200, JSON.stringify(tools.body));
      assert.deepEqual(
        tools.body.result.tools.map((tool: any) => tool.name),
        ['list_enabled_objects', 'describe_object', 'soql_query']
      );
      // Simulator tokens are verified locally and never reach Salesforce (or anywhere else).
      assert.deepEqual(sf.calls, []);
      assert.deepEqual(sf.nonSalesforceCalls, []);
    });

    it('denied combinations report permitted: false with a reason', async () => {
      const admin = await signIn();
      const cases = [
        { body: { profileId: fx.profileId, toolName: 'delete_record', targetObject: fx.objectName }, reason: /not granted/ },
        { body: { profileId: newProfileId(), toolName: 'list_enabled_objects' }, reason: /not registered/ },
      ];

      for (const { body, reason } of cases) {
        const res = await call(admin, 'POST', '/api/admin/test-mcp-access', body);
        assert.equal(res.status, 200, JSON.stringify(res.body));
        assert.equal(res.body.evaluation.permitted, false, JSON.stringify(body));
        assert.match(res.body.evaluation.reason, reason);
      }
    });

    it('returns the structured decision next to the evaluation, which keeps its shape', async () => {
      const admin = await signIn();
      const res = await call(admin, 'POST', '/api/admin/test-mcp-access', {
        profileId: fx.profileId,
        toolName: 'soql_query',
        targetObject: fx.objectName.toLowerCase(),
      });

      assert.equal(res.status, 200, JSON.stringify(res.body));
      const { evaluation, decision } = res.body;
      assert.deepEqual(Object.keys(evaluation).sort(), ['allowedFields', 'matchedGroups', 'objectName', 'permitted', 'reason']);
      assert.equal(decision.outcome, 'allowed');
      assert.equal(decision.code, 'ALLOWED');
      assert.equal(decision.objectName, fx.objectName);
      assert.deepEqual(decision.assignedGroups, [{ id: fx.groupId, name: fx.groupName }]);
      assert.deepEqual(decision.decidingGroupIds, [fx.groupId]);
      assert.deepEqual(decision.identity, { callerProfileId: fx.profileId, matchedProfileId: fx.profileId, matchMethod: 'id' });
      assert.equal(decision.policyRevision, store.getPolicyRevision());
      // Without a sample payload only the tool and the Object are checked, as before.
      assert.deepEqual(
        decision.steps.map((s: any) => s.stage),
        ['tool', 'identity', 'groups', 'tool_grant', 'object', 'crud']
      );
    });

    it('evaluates a sample payload as the call\'s arguments, so a field outside the allowlist is denied', async () => {
      const admin = await signIn();
      const seen = new Set(copilotRowsFor(fx.profileId).map((row) => row.id));
      const simulate = (samplePayload: unknown, toolName = 'soql_query') =>
        call(admin, 'POST', '/api/admin/test-mcp-access', {
          profileId: fx.profileId,
          toolName,
          targetObject: fx.objectName,
          samplePayload,
        });

      // SSN__c is a field of the Object, enabled globally, but the group does not grant it.
      const denied = await simulate({ fields: ['Id', 'SSN__c'] });
      assert.equal(denied.status, 200, JSON.stringify(denied.body));
      assert.equal(denied.body.evaluation.permitted, false);
      assert.equal(
        denied.body.evaluation.reason,
        `Fields [SSN__c] on ${fx.objectName} are not permitted for Profile '${fx.profileName}'.`
      );
      assert.deepEqual(denied.body.evaluation.allowedFields, []);
      assert.equal(denied.body.decision.outcome, 'denied');
      assert.equal(denied.body.decision.code, 'FIELD_NOT_PERMITTED');
      assert.deepEqual(denied.body.decision.steps.at(-1), {
        stage: 'fields',
        result: 'fail',
        grantingGroupIds: [],
        objectName: fx.objectName,
        fieldNames: ['SSN__c'],
        ruleId: null,
      });

      const whereDenied = await simulate({ objectName: fx.objectName, whereClause: "SSN__c = '123-45-6789'" });
      assert.equal(whereDenied.body.decision.code, 'WHERE_FIELD_NOT_PERMITTED');
      const malformed = await simulate({ objectName: fx.objectName, whereClause: "(Name = 'x'" });
      assert.equal(malformed.body.decision.outcome, 'invalid');
      assert.equal(malformed.body.decision.code, 'INPUT_INVALID');
      assert.equal(malformed.body.evaluation.reason, 'whereClause has unbalanced parentheses.');

      const allowed = await simulate({ fields: ['Id', 'Subject__c'], whereClause: "Name != null" });
      assert.equal(allowed.body.evaluation.permitted, true, allowed.body.evaluation.reason);
      // The last step, an 'input' pass, says the sample payload's arguments were checked.
      assert.deepEqual(
        allowed.body.decision.steps.map((s: any) => s.stage),
        ['tool', 'identity', 'groups', 'tool_grant', 'object', 'crud', 'fields', 'where', 'input']
      );

      const rows = copilotRowsFor(fx.profileId)
        .filter((row) => !seen.has(row.id))
        .reverse();
      assert.deepEqual(rows.map((r) => r.status), ['DENIED', 'DENIED', 'DENIED', 'ALLOWED']);
      assert.ok(!JSON.stringify(rows).includes('123-45-6789'), 'the sample filter value was stored');
    });

    it('decides on the Object its log rows name: targetObject over a sample payload objectName, which only fills in a missing one', async () => {
      const admin = await signIn();
      // Enabled globally, but the group grants no access to it.
      const ungranted = newObjectName('SimUngranted');
      store.upsertObjectWithFields({ objectName: ungranted, fields: [{ fieldName: 'Id' }] });
      try {
        const cases: Array<{
          label: string;
          targetObject?: string;
          samplePayload: Record<string, unknown>;
          decidedOn: string;
          code: string;
          status: string;
        }> = [
          {
            label: 'a sample payload naming a granted Object does not override an ungranted targetObject',
            targetObject: ungranted,
            samplePayload: { objectName: fx.objectName, fields: ['Id'] },
            decidedOn: ungranted,
            code: 'OBJECT_NOT_GRANTED',
            status: 'DENIED',
          },
          {
            label: 'a sample payload naming an ungranted Object does not override a granted targetObject',
            targetObject: fx.objectName,
            samplePayload: { objectName: ungranted, fields: ['Id'] },
            decidedOn: fx.objectName,
            code: 'ALLOWED',
            status: 'ALLOWED',
          },
          {
            label: 'a null objectName in the sample payload does not remove targetObject',
            targetObject: fx.objectName,
            samplePayload: { objectName: null, fields: ['Id'] },
            decidedOn: fx.objectName,
            code: 'ALLOWED',
            status: 'ALLOWED',
          },
          {
            label: 'without targetObject, the sample payload names the Object',
            samplePayload: { objectName: fx.objectName, fields: ['Id'] },
            decidedOn: fx.objectName,
            code: 'ALLOWED',
            status: 'ALLOWED',
          },
        ];

        for (const c of cases) {
          const seen = new Set(copilotRowsFor(fx.profileId).map((row) => row.id));
          const mark = auditMark();
          const res = await call(admin, 'POST', '/api/admin/test-mcp-access', {
            profileId: fx.profileId,
            toolName: 'soql_query',
            ...(c.targetObject === undefined ? {} : { targetObject: c.targetObject }),
            samplePayload: c.samplePayload,
          });

          assert.equal(res.status, 200, `${c.label}: ${JSON.stringify(res.body)}`);
          const { decision } = res.body;
          assert.equal(decision.code, c.code, `${c.label}: ${decision.reason}`);
          const objectStep = decision.steps.find((s: any) => s.stage === 'object');
          assert.equal(objectStep?.objectName, c.decidedOn, `${c.label}: the Object decided on`);

          const rows = copilotRowsFor(fx.profileId).filter((row) => !seen.has(row.id));
          assert.deepEqual(
            rows.map((r) => ({ target: r.targetObject, status: r.status })),
            [{ target: c.decidedOn, status: c.status }],
            `${c.label}: the Copilot MCP row names the Object decided on`
          );
          const [audit] = auditRowsSince(mark, admin.ip).filter((row) => row.action === SIMULATE_MCP_CALL_ACTION);
          assert.ok(
            audit?.details.startsWith(`Simulated soql_query on ${c.decidedOn} as `),
            `${c.label}: the admin log row names the Object decided on: ${audit?.details}`
          );
          assert.ok(audit.details.includes(`: ${c.status}.`), `${c.label}: ${audit.details}`);
        }
      } finally {
        store.deleteObject(ungranted);
      }
    });

    it('every simulation writes a Copilot MCP log row, with the sample payload values redacted', async () => {
      const admin = await signIn();
      const seen = new Set(copilotRowsFor(fx.profileId).map((row) => row.id));
      const sensitive = [`123-45-${RUN}`, `VIP escalation ${RUN}`, `Jane Doe ${RUN}`];
      const samplePayload = {
        objectName: fx.objectName,
        fields: { SSN__c: sensitive[0], Subject__c: sensitive[1] },
        soql: `SELECT Id FROM ${fx.objectName} WHERE Name = '${sensitive[2]}'`,
      };

      const allowed = await call(admin, 'POST', '/api/admin/test-mcp-access', {
        profileId: fx.profileId,
        toolName: 'soql_query',
        targetObject: fx.objectName,
        samplePayload,
      });
      const denied = await call(admin, 'POST', '/api/admin/test-mcp-access', {
        profileId: fx.profileId,
        toolName: 'delete_record',
        targetObject: fx.objectName,
      });
      assert.deepEqual([allowed.status, denied.status], [200, 200]);

      const rows = copilotRowsFor(fx.profileId)
        .filter((row) => !seen.has(row.id))
        .reverse();
      assert.deepEqual(
        rows.map((r) => ({ tool: r.toolName, target: r.targetObject, status: r.status, profile: r.profileName, groups: r.matchedGroups })),
        [
          { tool: 'soql_query', target: fx.objectName, status: 'ALLOWED', profile: fx.profileName, groups: [fx.groupName] },
          { tool: 'delete_record', target: fx.objectName, status: 'DENIED', profile: fx.profileName, groups: [fx.groupName] },
        ]
      );
      const stored = JSON.stringify(rows);
      for (const value of sensitive) assert.ok(!stored.includes(value), `"${value}" was stored in the Copilot MCP log`);
    });
  });

  // ----------------------------------------------------------------------------------------------
  describe('11. Audit trail', () => {
    it('every mutation route was audited above with its action code and the acting admin username', () => {
      const required = [
        'CREATE_PROFILE',
        'IMPORT_PROFILES_CSV',
        'UPSERT_OBJECT',
        'TOGGLE_OBJECT',
        'TOGGLE_FIELD',
        'BULK_TOGGLE_FIELDS',
        'DELETE_FIELD',
        'IMPORT_SFDX_OBJECTS_FOLDER',
        'SYNC_LOCAL_SFDX_FOLDER',
        'CREATE_GROUP',
        'UPDATE_GROUP',
        'UPDATE_PROFILE_GROUPS',
        'DELETE_GROUP',
        'SEED_ENTERPRISE_MATRIX',
        'UPDATE_OKTA_SSO',
        'UPDATE_SF_SETTINGS',
        'UPSERT_PORTAL_USER',
        'DELETE_PORTAL_USER',
        'DELETE_PROFILE',
        'DELETE_OBJECT',
      ];
      // mutate() checks each successful mutation's row (action, admin username, auth method, client IP).
      assert.deepEqual(
        required.filter((action) => !auditedActions.has(action)),
        [],
        'action codes not verified by a passing mutation test in this file'
      );
    });
  });

  // ----------------------------------------------------------------------------------------------
  describe('12. Rate limiting', () => {
    it('80 consecutive authenticated GET /overview calls all succeed (no 429)', async () => {
      const admin = await signIn();
      const statuses: number[] = [];

      for (let i = 0; i < 80; i++) statuses.push((await call(admin, 'GET', '/api/admin/overview')).status);

      assert.deepEqual(statuses, new Array(80).fill(200));
    });

    it('the Admin API limit (300 per minute) is per session: one exhausted session does not throttle another from the same client', async () => {
      const ip = newClientIp();
      const busy = await signIn(ip);
      const other = await signIn(ip);
      assert.notEqual(busy.cookie, other.cookie);

      const statuses: number[] = [];
      for (let i = 0; i < 300; i++) statuses.push((await call(busy, 'GET', '/api/admin/session')).status);
      assert.deepEqual(statuses, new Array(300).fill(200));

      assert.equal((await call(busy, 'GET', '/api/admin/session')).status, 429, 'the 301st request in the window');
      assert.equal((await call(other, 'GET', '/api/admin/session')).status, 200, 'same client IP, different session');
      assert.equal((await call({ ip }, 'GET', '/api/admin/session')).status, 200, 'same client IP, no session');
    });

    it('failed logins are limited to 60 per client: successful logins do not count, the 61st failure gets 429', async () => {
      const ip = newClientIp();
      const outcomes: string[] = [];
      const expected: string[] = [];

      for (let failure = 1; failure <= 60; failure++) {
        if (failure % 15 === 1) {
          // A correct sign-in from the same client every 15 failures: it must succeed and not count.
          outcomes.push(`sign-in before failure ${failure}: ${(await postLogin(ip, BOOTSTRAP_ADMIN)).status}`);
          expected.push(`sign-in before failure ${failure}: 200`);
        }
        // A different username each time isolates the per-client limit from the per-username one (20).
        const res = await postLogin(ip, { username: `nobody.${RUN}.${failure}`, password: `wrong-${failure}` });
        outcomes.push(`failure ${failure}: ${res.status}`);
        expected.push(`failure ${failure}: 401`);
      }
      // Had the four sign-ins counted, failures 57 to 60 would already have been answered with 429.
      assert.deepEqual(outcomes, expected);

      const blocked = await postLogin(ip, { username: `nobody.${RUN}.61`, password: 'wrong-61' });
      assert.equal(blocked.status, 429);
      assert.match(blocked.body.error, /Too many authentication attempts/);
      assert.ok(Number(blocked.headers.get('retry-after')) > 0, 'a 429 should say when to retry');
    });

    it('a locked-out client is refused even with the right password; its open session and other clients keep working', async () => {
      const ip = newClientIp();
      const signedInEarlier = await signIn(ip);

      for (let failure = 1; failure <= 60; failure++) {
        const res = await postLogin(ip, { username: `ghost.${RUN}.${failure}`, password: `wrong-${failure}` });
        assert.equal(res.status, 401, `failure ${failure}`);
      }

      assert.equal((await postLogin(ip, BOOTSTRAP_ADMIN)).status, 429, 'the right password must not bypass the lockout');
      assert.equal((await postLogin(newClientIp(), BOOTSTRAP_ADMIN)).status, 200, 'another client can still sign in');
      assert.equal((await call(signedInEarlier, 'GET', '/api/admin/overview')).status, 200, 'an open session keeps working');
    });
  });
});
