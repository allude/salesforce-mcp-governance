import { TEST_ADMIN, testTmpDir } from './helpers/env.js';
// The structured Portal Admin log record: its result, target, diff and correlation id. Covers the
// result rule the store and the portal share, the store's writer and readers, the upgrade of a
// database whose rows predate those columns, and the id the Admin API gives each request.
import { after, before, describe, test, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';
import { store } from '../src/db/store.js';
import { config } from '../src/config.js';
import { auditResultFromAction } from '../src/security/auditResult.js';
import { portalAuditResult } from '../src/components/views/portalAudit.js';
import { adminFetch, loginAsAdmin, startTestServer, type AdminSession, type TestServer } from './helpers/server.js';
import type { PortalAdminLogRecord } from '../src/types/governance.js';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const tag = () => crypto.randomBytes(4).toString('hex');

const logEntry = (overrides: Partial<Parameters<typeof store.recordPortalAdminLog>[0]> = {}) => ({
  adminUsername: `audit-${tag()}`,
  authMethod: 'password' as const,
  action: 'AUDIT_TEST',
  target: 'Audit tests',
  details: 'A row written by the audit tests.',
  ...overrides,
});

function rawRow(id: string): Record<string, unknown> {
  const db = new DatabaseSync(config.dbPath);
  try {
    return db.prepare('SELECT * FROM portal_admin_logs WHERE id = ?').get(id) as Record<string, unknown>;
  } finally {
    db.close();
  }
}

describe('the result rule for a row written without one', () => {
  for (const action of ['LOGIN_FAILED', 'OKTA_LOGIN_FAILED', 'CONNECT_SALESFORCE_ORG_FAILED']) {
    test(`${action} is FAILED`, () => {
      assert.equal(auditResultFromAction(action), 'FAILED');
    });
  }

  test('OKTA_LOGIN_DENIED and GENERATE_SF_JWT_CERT_DENIED are DENIED', () => {
    assert.equal(auditResultFromAction('OKTA_LOGIN_DENIED'), 'DENIED');
    assert.equal(auditResultFromAction('GENERATE_SF_JWT_CERT_DENIED'), 'DENIED');
  });

  // Only the exact suffix counts: the action names are upper case, and a word inside one is not an outcome.
  for (const action of ['LOGIN_SUCCESS', 'DELETE_FIELD', 'UPDATE_OKTA_SSO', 'login_failed', 'FAILED_SYNC_RETRY', 'DENIED']) {
    test(`${action} is SUCCESS`, () => {
      assert.equal(auditResultFromAction(action), 'SUCCESS');
    });
  }
});

describe('portalAuditResult (the Result badge in the audit drawer)', () => {
  test('shows the stored result, whatever the action is called', () => {
    assert.deepEqual(portalAuditResult({ action: 'GENERATE_SF_JWT_CERT', result: 'DENIED' }), { label: 'DENIED', tone: 'err' });
    assert.deepEqual(portalAuditResult({ action: 'UPDATE_GROUP', result: 'FAILED' }), { label: 'FAILED', tone: 'err' });
    assert.deepEqual(portalAuditResult({ action: 'LOGIN_FAILED', result: 'SUCCESS' }), { label: 'SUCCESS', tone: 'ok' });
  });

  test('falls back to the action name for a row without a result', () => {
    assert.deepEqual(portalAuditResult({ action: 'LOGIN_FAILED' }), { label: 'FAILED', tone: 'err' });
    assert.deepEqual(portalAuditResult({ action: 'OKTA_LOGIN_DENIED' }), { label: 'DENIED', tone: 'err' });
    assert.deepEqual(portalAuditResult({ action: 'CONNECT_SALESFORCE_ORG' }), { label: 'SUCCESS', tone: 'ok' });
  });
});

describe('store.recordPortalAdminLog', () => {
  test('a row without a result gets the action-name rule, and a given result is stored as given', () => {
    const failed = store.recordPortalAdminLog(logEntry({ action: 'AUDIT_TEST_FAILED' }));
    const denied = store.recordPortalAdminLog(logEntry({ action: 'AUDIT_TEST_DENIED' }));
    const plain = store.recordPortalAdminLog(logEntry());
    const explicit = store.recordPortalAdminLog(logEntry({ action: 'AUDIT_TEST', result: 'DENIED' }));

    assert.deepEqual(
      [failed, denied, plain, explicit].map((row) => [row.result, rawRow(row.id).result]),
      [
        ['FAILED', 'FAILED'],
        ['DENIED', 'DENIED'],
        ['SUCCESS', 'SUCCESS'],
        ['DENIED', 'DENIED'],
      ]
    );
  });

  test('target, diff and correlation id are stored and come back from every reader', () => {
    const correlationId = crypto.randomUUID();
    const diff = { added: ['grp_a'], removed: [], flags: { enabled: true } };
    const written = store.recordPortalAdminLog(
      logEntry({ targetType: 'group', targetId: `grp_${tag()}`, diff, correlationId, result: 'SUCCESS' })
    );

    const stored = rawRow(written.id);
    assert.equal(stored.target_type, 'group');
    assert.equal(stored.target_id, written.targetId);
    assert.equal(stored.diff_json, JSON.stringify(diff));
    assert.equal(stored.correlation_id, correlationId);

    const expected = { ...written, diff };
    assert.deepEqual(written.diff, diff);
    assert.deepEqual(store.getPortalAdminLogs(1)[0], expected);
    const { seq: _pageSeq, ...fromPage } = store.getPortalAdminLogPage({ limit: 1 }).rows[0];
    assert.deepEqual(fromPage, expected);
    const { seq: _cappedSeq, ...fromCapped } = store.getPortalAdminLogsCappedByKind(1, 1)[0];
    assert.deepEqual(fromCapped, expected);
  });

  test('a row written without them has no target or diff and a correlation id of its own', () => {
    const first = store.recordPortalAdminLog(logEntry());
    const second = store.recordPortalAdminLog(logEntry());

    assert.deepEqual([first.targetType, first.targetId, first.diff], ['', '', null]);
    assert.deepEqual([rawRow(first.id).target_type, rawRow(first.id).target_id, rawRow(first.id).diff_json], ['', '', '']);
    assert.match(String(first.correlationId), UUID);
    assert.match(String(second.correlationId), UUID);
    assert.notEqual(first.correlationId, second.correlationId);
  });

  test('a diff over 64 KB is not kept: the row notes its length instead', () => {
    const limit = 64 * 1024;
    // {"s":"..."} is 8 characters around the text.
    const atLimit = { s: 'x'.repeat(limit - 8) };
    assert.equal(JSON.stringify(atLimit).length, limit);
    assert.deepEqual(store.recordPortalAdminLog(logEntry({ diff: atLimit })).diff, atLimit);

    const tooLarge = { s: 'x'.repeat(limit - 7) };
    const written = store.recordPortalAdminLog(logEntry({ diff: tooLarge }));
    const note = { truncated: true, length: limit + 1 };
    assert.deepEqual(written.diff, note);
    assert.equal(rawRow(written.id).diff_json, JSON.stringify(note));
    assert.deepEqual(store.getPortalAdminLogs(1)[0].diff, note);
  });

  test('a result outside SUCCESS, FAILED and DENIED is refused and writes nothing', () => {
    const before = store.getPortalAdminLogs(1)[0]?.id;
    assert.throws(() => store.recordPortalAdminLog(logEntry({ result: 'PARTIAL' as never })), /Unknown audit result/);
    assert.equal(store.getPortalAdminLogs(1)[0]?.id, before);
  });
});

// ------------------------------------------------------------------------------------------------
// Upgrade. The migration runs when the store loads, so each boot here is a real child process.
// ------------------------------------------------------------------------------------------------

function bootStore(dbPath: string) {
  execFileSync(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', "await import('./src/db/store.ts');"], {
    cwd: REPO_ROOT,
    env: { ...process.env, DB_PATH: dbPath },
    stdio: 'pipe',
    timeout: 60_000,
  });
}

function withDb<T>(dbPath: string, fn: (db: DatabaseSync) => T): T {
  const db = new DatabaseSync(dbPath);
  try {
    return fn(db);
  } finally {
    db.close();
  }
}

function insertLegacyRow(db: DatabaseSync, id: string, action: string) {
  db.prepare(
    `INSERT INTO portal_admin_logs (id, timestamp, admin_username, auth_method, action, target, details, ip_address)
     VALUES (?, '2026-10-01T00:00:00.000Z', 'admin', 'password', ?, 'Portal Auth', 'An old row.', '127.0.0.1')`
  ).run(id, action);
}

/** A database as it stood before the structured columns: the table with free text only, and old rows. */
function legacyDatabase(name: string): string {
  const dbPath = path.join(testTmpDir, name);
  withDb(dbPath, (db) => {
    db.exec(`
      CREATE TABLE portal_admin_logs (
        id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL,
        admin_username TEXT NOT NULL,
        auth_method TEXT NOT NULL,
        action TEXT NOT NULL,
        target TEXT NOT NULL,
        details TEXT NOT NULL,
        ip_address TEXT NOT NULL
      );
    `);
    insertLegacyRow(db, 'login-failed', 'LOGIN_FAILED');
    insertLegacyRow(db, 'connect-failed-1', 'CONNECT_SALESFORCE_ORG_FAILED');
    insertLegacyRow(db, 'connect-failed-2', 'CONNECT_SALESFORCE_ORG_FAILED');
    insertLegacyRow(db, 'okta-denied', 'OKTA_LOGIN_DENIED');
    insertLegacyRow(db, 'update-group', 'UPDATE_GROUP');
    insertLegacyRow(db, 'lower-case', 'login_failed');
  });
  return dbPath;
}

const auditColumns = (dbPath: string) =>
  withDb(dbPath, (db) =>
    (db.prepare('PRAGMA table_info(portal_admin_logs)').all() as Array<Record<string, unknown>>).map(
      ({ cid, name, type, notnull, dflt_value, pk }) => ({ cid, name, type, notnull, dflt_value, pk })
    )
  );

const storedResults = (dbPath: string) =>
  withDb(dbPath, (db) =>
    Object.fromEntries(
      (db.prepare('SELECT id, result FROM portal_admin_logs').all() as Array<{ id: string; result: string }>).map(
        (r) => [r.id, r.result]
      )
    )
  );

describe('upgrading a database from before the structured audit columns', () => {
  test('old rows get the result their action name implies, and the other columns stay empty', () => {
    const dbPath = legacyDatabase('legacy-audit.sqlite');

    bootStore(dbPath);
    assert.deepEqual(storedResults(dbPath), {
      'login-failed': 'FAILED',
      'connect-failed-1': 'FAILED',
      'connect-failed-2': 'FAILED',
      'okta-denied': 'DENIED',
      'update-group': 'SUCCESS',
      'lower-case': 'SUCCESS',
    });
    const others = withDb(dbPath, (db) =>
      db.prepare('SELECT DISTINCT target_type, target_id, diff_json, correlation_id FROM portal_admin_logs').all()
    );
    assert.deepEqual(others.map((r) => ({ ...r })), [{ target_type: '', target_id: '', diff_json: '', correlation_id: '' }]);

    // A row written after the upgrade keeps the result it was given: this version always gives a row a
    // correlation id, so the backfill must never touch it.
    withDb(dbPath, (db) =>
      db
        .prepare(
          `INSERT INTO portal_admin_logs (id, timestamp, admin_username, auth_method, action, target, details, ip_address, result, correlation_id)
           VALUES ('later', '2026-10-02T00:00:00.000Z', 'admin', 'password', 'LOGIN_FAILED', 'Portal Auth', 'A new row.', '127.0.0.1', 'SUCCESS', ?)`
        )
        .run(crypto.randomUUID())
    );
    bootStore(dbPath);
    assert.equal(storedResults(dbPath).later, 'SUCCESS');
  });

  test('rows an older release writes after a rollback get their result on the next boot', () => {
    const dbPath = legacyDatabase('rolled-back-audit.sqlite');
    bootStore(dbPath);

    // The older release lists only its own columns, so its rows get the column defaults: SUCCESS, no id.
    withDb(dbPath, (db) => {
      insertLegacyRow(db, 'rolled-back-failed', 'LOGIN_FAILED');
      insertLegacyRow(db, 'rolled-back-denied', 'OKTA_LOGIN_DENIED');
      insertLegacyRow(db, 'rolled-back-success', 'LOGIN_SUCCESS');
    });
    assert.equal(storedResults(dbPath)['rolled-back-failed'], 'SUCCESS');

    bootStore(dbPath);
    const results = storedResults(dbPath);
    assert.deepEqual(
      [results['rolled-back-failed'], results['rolled-back-denied'], results['rolled-back-success'], results['login-failed']],
      ['FAILED', 'DENIED', 'SUCCESS', 'FAILED']
    );
  });

  test('a row an older release writes while this one runs reads as the result its action implies, before any boot', () => {
    // This process's database, written on a connection of its own as a release sharing the file during
    // a rolling deploy writes it: the column defaults, SUCCESS and no correlation id.
    withDb(config.dbPath, (db) => {
      insertLegacyRow(db, `shared-failed-${tag()}`, 'LOGIN_FAILED');
      insertLegacyRow(db, `shared-denied-${tag()}`, 'OKTA_LOGIN_DENIED');
      insertLegacyRow(db, `shared-success-${tag()}`, 'LOGIN_SUCCESS');
    });
    const written = withDb(config.dbPath, (db) =>
      db.prepare(`SELECT id, result FROM portal_admin_logs WHERE id LIKE 'shared-%' ORDER BY seq`).all()
    ) as Array<{ id: string; result: string }>;
    assert.deepEqual(written.map((r) => r.result), ['SUCCESS', 'SUCCESS', 'SUCCESS']);

    const ids = written.map((r) => r.id);
    const read = (rows: PortalAdminLogRecord[]) => ids.map((id) => rows.find((r) => r.id === id)?.result);
    const expected = ['FAILED', 'DENIED', 'SUCCESS'];
    assert.deepEqual(read(store.getPortalAdminLogs(1000)), expected);
    assert.deepEqual(read(store.getPortalAdminLogPage({ limit: 1000 }).rows), expected);
    assert.deepEqual(ids.map((id) => portalAuditResult(store.getPortalAdminLogs(1000).find((r) => r.id === id)!).tone), ['err', 'err', 'ok']);
  });

  test('an upgraded database ends with the same table as a new one', () => {
    const upgraded = legacyDatabase('legacy-audit-schema.sqlite');
    const fresh = path.join(testTmpDir, 'fresh-audit-schema.sqlite');
    bootStore(upgraded);
    bootStore(fresh);

    const columns = auditColumns(fresh);
    assert.deepEqual(
      columns.slice(-5).map(({ name, type, notnull, dflt_value }) => [name, type, notnull, dflt_value]),
      [
        ['result', 'TEXT', 1, "'SUCCESS'"],
        ['target_type', 'TEXT', 1, "''"],
        ['target_id', 'TEXT', 1, "''"],
        ['diff_json', 'TEXT', 1, "''"],
        ['correlation_id', 'TEXT', 1, "''"],
      ]
    );
    assert.deepEqual(auditColumns(upgraded), columns);
  });
});

// ------------------------------------------------------------------------------------------------
// Over the Admin API
// ------------------------------------------------------------------------------------------------

describe('the Admin API audit record', () => {
  let server: TestServer;
  let session: AdminSession;

  // POST /groups accepts grants only for Objects and fields in Salesforce > Objects.
  const CATALOG: Record<string, string[]> = {
    Account: ['Id', 'Name', 'Phone'],
    Contact: ['Id', 'Email'],
    Opportunity: ['Id', 'Amount'],
    Case: ['Id'],
  };

  before(async () => {
    server = await startTestServer();
    session = await loginAsAdmin(server.baseUrl);
    for (const [objectName, fields] of Object.entries(CATALOG)) {
      store.upsertObjectWithFields({ objectName, fields: fields.map((fieldName) => ({ fieldName })) });
    }
  });

  after(async () => {
    for (const objectName of Object.keys(CATALOG)) store.deleteObject(objectName);
    await server.close();
  });

  const api = (urlPath: string, init: Parameters<typeof adminFetch>[3] = {}) =>
    adminFetch(server.baseUrl, session, urlPath, init);
  const rowsFor = (correlationId: string | null) =>
    store.getPortalAdminLogs(1_000_000).filter((row) => row.correlationId === correlationId);
  const newGroup = async (t: TestContext, extra: Record<string, unknown> = {}) => {
    const res = await api('/api/admin/groups', {
      method: 'POST',
      body: { name: `Audit ${tag()}`, allowedActions: ['soql_query'], ...extra },
    });
    assert.equal(res.status, 200, JSON.stringify(res.body));
    t.after(() => {
      store.deleteGroup(res.body.group.id);
    });
    return res;
  };

  test('every row one request writes carries its X-Correlation-Id, and the next request gets another', async (t) => {
    // The sync's own row is attempted first, fails, and the route then logs the failure: two writes.
    const realRecord = store.recordPortalAdminLog;
    const attempted: Array<Parameters<typeof realRecord>[0]> = [];
    const mocked = t.mock.method(store, 'recordPortalAdminLog', function (this: typeof store, input: Parameters<typeof realRecord>[0]) {
      attempted.push(input);
      if (attempted.length === 1) throw new Error('audit write failed');
      return realRecord.call(this, input);
    });

    const sync = await api('/api/admin/profiles/pull-apply', { method: 'POST', body: { upserts: [] } });
    mocked.mock.restore();

    assert.equal(sync.status, 500);
    const syncId = sync.headers.get('x-correlation-id');
    assert.match(String(syncId), UUID);
    assert.deepEqual(
      attempted.map((input) => [input.action, input.correlationId]),
      [
        ['SYNC_PROFILES_FROM_ORG', syncId],
        ['SYNC_PROFILES_FROM_ORG_FAILED', syncId],
      ]
    );
    assert.deepEqual(rowsFor(syncId).map((row) => [row.action, row.result]), [['SYNC_PROFILES_FROM_ORG_FAILED', 'FAILED']]);

    const create = await newGroup(t);
    const createId = create.headers.get('x-correlation-id');
    assert.match(String(createId), UUID);
    assert.notEqual(createId, syncId);
    assert.deepEqual(rowsFor(createId).map((row) => row.action), ['CREATE_GROUP']);
  });

  test('a correlation id sent by the client is never used', async (t) => {
    const clientId = crypto.randomUUID();
    const res = await api('/api/admin/groups', {
      method: 'POST',
      body: { name: `Audit ${tag()}`, allowedActions: [] },
      headers: { 'X-Correlation-Id': clientId },
    });
    assert.equal(res.status, 200, JSON.stringify(res.body));
    t.after(() => {
      store.deleteGroup(res.body.group.id);
    });

    const serverId = res.headers.get('x-correlation-id');
    assert.match(String(serverId), UUID);
    assert.notEqual(serverId, clientId);
    assert.deepEqual(rowsFor(clientId), []);
    assert.deepEqual(rowsFor(serverId).map((row) => row.action), ['CREATE_GROUP']);
  });

  test('sign-in and a sync body the JSON parser refused are filed under their request too', async () => {
    const login = await fetch(`${server.baseUrl}/api/admin/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(TEST_ADMIN),
    });
    assert.equal(login.status, 200);
    assert.deepEqual(rowsFor(login.headers.get('x-correlation-id')).map((row) => row.action), ['LOGIN_SUCCESS']);

    // Refused before the Admin API router runs, by the body parser in front of it.
    const refused = await fetch(`${server.baseUrl}/api/admin/objects/pull-apply`, {
      method: 'POST',
      headers: { Cookie: session.cookie, 'X-CSRF-Token': session.csrfToken, 'Content-Type': 'application/json' },
      body: '{"pulledMetadata": [',
    });
    assert.equal(refused.status, 400);
    const refusedId = refused.headers.get('x-correlation-id');
    assert.match(String(refusedId), UUID);
    assert.deepEqual(rowsFor(refusedId).map((row) => [row.action, row.result]), [['SYNC_OBJECTS_FROM_ORG_FAILED', 'FAILED']]);
  });

  test('group rows name the group and hold what changed, and the log API returns them', async (t) => {
    const permissions = [
      { objectName: 'Account', canRead: true, canCreate: false, canUpdate: false, canDelete: false, allowedFields: ['Id', 'Name'] },
    ];
    const created = await newGroup(t, { description: 'Reads Accounts', objectPermissions: permissions });
    const group = created.body.group;
    const after = {
      name: group.name,
      description: 'Reads Accounts',
      allowedActions: ['soql_query'],
      objectPermissions: permissions,
    };

    const renamed = `${group.name} renamed`;
    const update = await api('/api/admin/groups', {
      method: 'POST',
      body: { ...group, name: renamed, allowedActions: ['soql_query', 'get_record'] },
    });
    assert.equal(update.status, 200, JSON.stringify(update.body));

    const profileId = `00e${crypto.randomBytes(6).toString('hex')}`;
    store.upsertProfile(profileId, `Audit Profile ${tag()}`);
    t.after(() => {
      store.deleteProfile(profileId);
    });
    const mapped = await api(`/api/admin/groups/${group.id}/profiles`, { method: 'POST', body: { add: [profileId] } });
    assert.equal(mapped.status, 200, JSON.stringify(mapped.body));
    const unmapped = await api(`/api/admin/profile-groups/${profileId}`, { method: 'PUT', body: { remove: [group.id] } });
    assert.equal(unmapped.status, 200, JSON.stringify(unmapped.body));
    await api(`/api/admin/groups/${group.id}/profiles`, { method: 'POST', body: { add: [profileId] } });
    const deleted = await api(`/api/admin/groups/${group.id}`, { method: 'DELETE' });
    assert.equal(deleted.status, 200, JSON.stringify(deleted.body));

    const structured = (row: PortalAdminLogRecord) => ({
      action: row.action,
      result: row.result,
      targetType: row.targetType,
      targetId: row.targetId,
      diff: row.diff,
    });
    const onlyRow = (res: { headers: Headers }) => {
      const rows = rowsFor(res.headers.get('x-correlation-id'));
      assert.equal(rows.length, 1);
      return structured(rows[0]);
    };
    const renamedAfter = { ...after, name: renamed, allowedActions: ['soql_query', 'get_record'] };
    assert.deepEqual(onlyRow(created), {
      action: 'CREATE_GROUP', result: 'SUCCESS', targetType: 'group', targetId: group.id, diff: { after },
    });
    // An update keeps only what changed: here the name and the actions, not the unchanged grant.
    assert.deepEqual(onlyRow(update), {
      action: 'UPDATE_GROUP', result: 'SUCCESS', targetType: 'group', targetId: group.id,
      diff: {
        before: { name: group.name, allowedActions: ['soql_query'] },
        after: { name: renamed, allowedActions: ['soql_query', 'get_record'] },
      },
    });
    assert.deepEqual(onlyRow(mapped), {
      action: 'UPDATE_PROFILE_GROUPS', result: 'SUCCESS', targetType: 'group', targetId: group.id, diff: { added: [profileId], removed: [] },
    });
    assert.deepEqual(onlyRow(unmapped), {
      action: 'UPDATE_PROFILE_GROUPS', result: 'SUCCESS', targetType: 'profile', targetId: profileId, diff: { added: [], removed: [group.id] },
    });
    assert.deepEqual(onlyRow(deleted), {
      action: 'DELETE_GROUP', result: 'SUCCESS', targetType: 'group', targetId: group.id,
      diff: { before: { ...renamedAfter, profileIds: [profileId] } },
    });

    // The log API and the overview send the same record, structured fields included.
    const deleteRow = rowsFor(deleted.headers.get('x-correlation-id'))[0];
    const page = await api('/api/admin/portal-logs?action=DELETE_GROUP&limit=1000');
    assert.equal(page.status, 200);
    const { seq: _seq, ...fromPage } = page.body.rows.find((row: PortalAdminLogRecord) => row.id === deleteRow.id);
    assert.deepEqual(fromPage, deleteRow);
    const overview = await api('/api/admin/overview');
    const { seq: _overviewSeq, ...fromOverview } = overview.body.portalLogs.find((row: PortalAdminLogRecord) => row.id === deleteRow.id);
    assert.deepEqual(fromOverview, deleteRow);
  });

  const grant = (objectName: string, allowedFields: string[]) => ({
    objectName, canRead: true, canCreate: false, canUpdate: false, canDelete: false, allowedFields,
  });

  test('an update row holds only the grants that changed, on the side they were on', async (t) => {
    const account = grant('Account', ['Id', 'Name']);
    const contact = grant('Contact', ['Id', 'Email']);
    const opportunity = grant('Opportunity', ['Id', 'Amount']);
    const created = await newGroup(t, { description: 'Unchanged', objectPermissions: [account, contact, opportunity] });
    const group = created.body.group;

    const accountWithPhone = grant('Account', ['Id', 'Name', 'Phone']);
    const caseGrant = grant('Case', ['Id']);
    const update = await api('/api/admin/groups', {
      method: 'POST',
      body: { ...group, objectPermissions: [opportunity, caseGrant, accountWithPhone] },
    });
    assert.equal(update.status, 200, JSON.stringify(update.body));
    // Removed or changed in before, added or changed in after; the untouched Opportunity grant in neither.
    assert.deepEqual(rowsFor(update.headers.get('x-correlation-id'))[0].diff, {
      before: { objectPermissions: [account, contact] },
      after: { objectPermissions: [caseGrant, accountWithPhone] },
    });

    const unchanged = await api('/api/admin/groups', { method: 'POST', body: update.body.group });
    assert.equal(unchanged.status, 200, JSON.stringify(unchanged.body));
    assert.deepEqual(rowsFor(unchanged.headers.get('x-correlation-id'))[0].diff, { before: {}, after: {} });
  });

  test('a refused grant writes nothing, and its error names the entry but no value but the name typed', async () => {
    const secret = `TOPSECRET-${tag()}`;
    const email = `jane.${tag()}@example.com`;
    const name = `Refused ${tag()}`;
    const auditsBefore = store.getPortalAdminLogs(1_000_000).length;
    const refusals: Array<[unknown, RegExp]> = [
      [{ ...grant('Account', ['Name']), clientSecret: secret, canDelete: secret }, /^objectPermissions\[0\]\.canDelete must be true or false\.$/],
      [`free text ${secret}`, /^objectPermissions\[0\] must be an object\.$/],
      [{ objectName: { value: secret }, canRead: true }, /^objectPermissions\[0\]\.objectName must be the API name of an Object\.$/],
      [{ ...grant('Account', ['Name']), allowedFields: ['Name', 7], sample: secret }, /^objectPermissions\[0\]\.allowedFields\[1\] must be a field API name\.$/],
      [grant('Account', ['Name', email]), /^objectPermissions\[0\]\.allowedFields\[1\]: Object "Account" has no field named "jane\./],
    ];
    for (const [entry, error] of refusals) {
      const res = await api('/api/admin/groups', { method: 'POST', body: { name, objectPermissions: [entry] } });
      assert.equal(res.status, 400, JSON.stringify(res.body));
      assert.match(res.body.error, error);
      assert.ok(!res.body.error.includes(secret), res.body.error);
    }
    assert.ok(!store.getGroups().some((group) => group.name === name));
    assert.equal(store.getPortalAdminLogs(1_000_000).length, auditsBefore);
  });

  test('a group diff keeps each stored grant as the policy engine reads it, as names and flags only', async (t) => {
    // A group an older version saved, which stored its grants as they were sent.
    const secret = `TOPSECRET-${tag()}`;
    const email = `jane.${tag()}@example.com`;
    const badName = `Bad Name ${secret}`;
    const legacy = store.upsertGroup({
      name: `Legacy ${tag()}`,
      allowedActions: ['soql_query'],
      objectPermissions: [
        { ...grant('Account', ['Name', email]), clientSecret: secret, sample: { Email: email } },
        { ...grant('Contact', ['Id']), canDelete: 'yes' },
        `free text ${secret}`,
        { objectName: { value: secret }, canRead: true },
        { objectName: badName, canRead: true, allowedFields: [7, { secret }] },
        { objectName: badName, canRead: true },
      ] as never,
    });
    t.after(() => {
      store.deleteGroup(legacy.id);
    });
    const cleared = await api('/api/admin/groups', { method: 'POST', body: { ...legacy, objectPermissions: [] } });
    assert.equal(cleared.status, 200, JSON.stringify(cleared.body));
    const deleted = await api(`/api/admin/groups/${legacy.id}`, { method: 'DELETE' });
    assert.equal(deleted.status, 200, JSON.stringify(deleted.body));

    // The entries the engine skips (a flag that is not true or false, a non-object, a name or field
    // list that is not text) grant nothing and are left out. A name that is not a Salesforce API name
    // matches nothing in the catalog: it is kept by its length only.
    const audited = [
      grant('Account', ['Name', `<invalid:len=${email.length}>`]),
      grant(`<invalid:len=${badName.length}>`, []),
    ];
    const [clearRow] = rowsFor(cleared.headers.get('x-correlation-id'));
    const [deleteRow] = rowsFor(deleted.headers.get('x-correlation-id'));
    assert.deepEqual(clearRow.diff, { before: { objectPermissions: audited }, after: { objectPermissions: [] } });
    for (const row of [clearRow, deleteRow]) {
      const stored = JSON.stringify(rawRow(row.id));
      assert.ok(!stored.includes(secret) && !stored.includes(email), stored);
    }
  });

  test('a description over 500 characters is refused, and a stored one over 1,000 is cut in the diff', async (t) => {
    const tooLong = await api('/api/admin/groups', {
      method: 'POST',
      body: { name: `Audit ${tag()}`, description: 'x'.repeat(501) },
    });
    assert.equal(tooLong.status, 400);
    assert.match(tooLong.body.error, /at most 500 characters/);

    const atLimit = await newGroup(t, { description: ` ${'x'.repeat(500)} ` });
    assert.equal(atLimit.body.group.description, 'x'.repeat(500));
    assert.equal(rowsFor(atLimit.headers.get('x-correlation-id'))[0].diff?.truncated, undefined);

    // An older version stored any length.
    const description = `${'x'.repeat(1_000)}${'y'.repeat(4_000)}`;
    const legacy = store.upsertGroup({ name: `Legacy ${tag()}`, description, allowedActions: ['soql_query'], objectPermissions: [] });
    t.after(() => {
      store.deleteGroup(legacy.id);
    });
    const update = await api('/api/admin/groups', { method: 'POST', body: { ...legacy, description: 'Short again' } });
    assert.equal(update.status, 200, JSON.stringify(update.body));
    assert.deepEqual(rowsFor(update.headers.get('x-correlation-id'))[0].diff, {
      before: { description: 'x'.repeat(1_000), truncated: ['description'] },
      after: { description: 'Short again' },
    });
  });

  test('deleting a portal user by another spelling of the name files the row under the stored username', async () => {
    const username = `audit.case.${tag()}`;
    const user = await api('/api/admin/portal-users', {
      method: 'POST',
      body: { username, password: `Audit-Password-${tag()}${tag()}` },
    });
    assert.equal(user.status, 200, JSON.stringify(user.body));

    const removed = await api(`/api/admin/portal-users/${encodeURIComponent(` ${username.toUpperCase()}`)}`, {
      method: 'DELETE',
    });
    assert.equal(removed.status, 200, JSON.stringify(removed.body));
    assert.equal(store.portalUserExists(username), false);
    const [row] = rowsFor(removed.headers.get('x-correlation-id'));
    assert.deepEqual([row.action, row.targetType, row.targetId], ['DELETE_PORTAL_USER', 'portal_user', username]);
  });

  test('settings and portal user rows name their target but keep no diff, so no secret can reach one', async () => {
    const clientSecret = `okta-secret-${tag()}${tag()}`;
    const okta = await api('/api/admin/okta', { method: 'PUT', body: { clientSecret } });
    assert.equal(okta.status, 200, JSON.stringify(okta.body));
    const password = `Audit-Password-${tag()}${tag()}`;
    const username = `audit.user.${tag()}`;
    const user = await api('/api/admin/portal-users', { method: 'POST', body: { username, password } });
    assert.equal(user.status, 200, JSON.stringify(user.body));
    const removed = await api(`/api/admin/portal-users/${username}`, { method: 'DELETE' });
    assert.equal(removed.status, 200, JSON.stringify(removed.body));

    const rows = [okta, user, removed].map((res) => rowsFor(res.headers.get('x-correlation-id')));
    assert.deepEqual(
      rows.map(([row]) => [row.action, row.targetType, row.targetId, row.diff]),
      [
        ['UPDATE_OKTA_SSO', 'settings', 'okta', null],
        ['UPSERT_PORTAL_USER', 'portal_user', username, null],
        ['DELETE_PORTAL_USER', 'portal_user', username, null],
      ]
    );
    for (const [row] of rows) {
      const stored = JSON.stringify(rawRow(row.id));
      assert.ok(!stored.includes(clientSecret) && !stored.includes(password), stored);
    }
  });
});
