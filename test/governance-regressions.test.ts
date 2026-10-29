import './helpers/env.js';
// Regression tests for control-plane defects found in the audit: group id collisions, non-atomic
// profile mappings, revoked objects coming back on re-import, Okta secret/issuer handling,
// portal-user updates, dashboard totals, Salesforce settings validation and audit-log redaction.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { store, stripSensitivePayloadData } from '../src/db/store.js';
import { startTestServer, loginAsAdmin, adminFetch, mcpRequest, toolResultPayload, type AdminSession, type TestServer } from './helpers/server.js';
import { installSalesforceMock } from './helpers/salesforceMock.js';
import { createSimulatorToken } from '../src/salesforce/client.js';

const tag = () => crypto.randomBytes(4).toString('hex');
const rawDb = () => new DatabaseSync(process.env.DB_PATH as string);

let server: TestServer;
let session: AdminSession;

before(async () => {
  server = await startTestServer();
  session = await loginAsAdmin(server.baseUrl);
});

after(async () => {
  await server.close();
});

describe('Access Groups', () => {
  test('creating a group whose id would collide with an existing one fails instead of overwriting it', (t) => {
    const t1 = tag();
    // Force the random id suffix to repeat, so both names below map to the same generated id.
    t.mock.method(crypto, 'randomBytes', () => Buffer.alloc(6));
    const first = store.upsertGroup({
      name: `Finance Read ${t1}`,
      allowedActions: ['soql_query'],
      objectPermissions: [{ objectName: 'Invoice__c', canRead: true, canCreate: false, canUpdate: false, canDelete: false, allowedFields: ['Id'] }],
    });
    assert.equal(first.id, `grp_finance_read_${t1}_000000000000`);
    assert.throws(
      () => store.upsertGroup({ name: `Finance-Read ${t1}`, allowedActions: ['delete_record'], objectPermissions: [] }),
      /UNIQUE constraint failed: access_groups\.id/
    );
    t.mock.restoreAll();

    const reloaded = store.getGroups().find((g) => g.id === first.id)!;
    assert.equal(reloaded.name, `Finance Read ${t1}`);
    assert.deepEqual(reloaded.allowedActions, ['soql_query']);
    assert.equal(reloaded.objectPermissions.length, 1);
  });

  test('without a forced collision, groups whose names share a slug get distinct ids', () => {
    const t1 = tag();
    const a = store.upsertGroup({ name: `Ops Read ${t1}`, allowedActions: [], objectPermissions: [] });
    const b = store.upsertGroup({ name: `Ops-Read ${t1}`, allowedActions: [], objectPermissions: [] });
    assert.notEqual(a.id, b.id);
    assert.match(a.id, /^grp_ops_read_[0-9a-f]+_[0-9a-f]{12}$/);
  });

  test('POST /groups with a duplicate name returns 409 JSON instead of a 500', async () => {
    const name = `Dup ${tag()}`;
    const created = await adminFetch(server.baseUrl, session, '/api/admin/groups', { method: 'POST', body: { name } });
    assert.equal(created.status, 200);
    const dup = await adminFetch(server.baseUrl, session, '/api/admin/groups', { method: 'POST', body: { name } });
    assert.equal(dup.status, 409);
    assert.match(dup.body.error, /already exists/);
  });

  test('PUT /profile-groups with an unknown group id is rejected and leaves the existing mapping intact', async () => {
    const profileId = `00e${crypto.randomBytes(6).toString('hex')}`.slice(0, 15);
    store.upsertProfile(profileId, `Profile ${tag()}`);
    const group = store.upsertGroup({ name: `Keep ${tag()}`, allowedActions: ['soql_query'], objectPermissions: [] });
    store.setProfileGroups(profileId, [group.id]);

    const res = await adminFetch(server.baseUrl, session, `/api/admin/profile-groups/${profileId}`, {
      method: 'PUT',
      body: { groupIds: [group.id, 'grp_deleted_in_another_tab'] },
    });
    assert.equal(res.status, 400);
    assert.match(res.body.error, /grp_deleted_in_another_tab/);
    const mapping = store.getProfileGroupMappings().find((m) => m.profileId === profileId);
    assert.deepEqual(mapping?.groupIds, [group.id]);
  });
});

describe('Objects', () => {
  test('deleting an object revokes it from every group, so a later re-import does not restore access', async () => {
    const objectName = `Salary_${tag()}__c`;
    store.upsertObjectWithFields({ objectName, fields: [{ fieldName: 'Id' }, { fieldName: 'Amount__c' }] });
    const group = store.upsertGroup({
      name: `Payroll ${tag()}`,
      allowedActions: ['soql_query'],
      objectPermissions: [
        { objectName, canRead: true, canCreate: false, canUpdate: false, canDelete: false, allowedFields: ['Id', 'Amount__c'] },
        { objectName: 'Account', canRead: true, canCreate: false, canUpdate: false, canDelete: false, allowedFields: ['Id'] },
      ],
    });

    const del = await adminFetch(server.baseUrl, session, `/api/admin/objects/${objectName}`, { method: 'DELETE' });
    assert.equal(del.status, 200);
    const afterDelete = store.getGroups().find((g) => g.id === group.id)!;
    assert.deepEqual(afterDelete.objectPermissions.map((p) => p.objectName), ['Account']);
    const log = store.getPortalAdminLogs(5).find((l) => l.action === 'DELETE_OBJECT');
    assert.match(log?.details || '', /revoked it from 1 Access Group/);

    // Re-import the same object from SFDX files: it comes back, but no group grants it.
    const reimport = await adminFetch(server.baseUrl, session, '/api/admin/objects/import-sfdx-files', {
      method: 'POST',
      body: { files: [{ relativePath: `objects/${objectName}/${objectName}.object-meta.xml`, content: '<CustomObject><label>Salary</label></CustomObject>' }] },
    });
    assert.equal(reimport.status, 200);
    assert.ok(store.getObjects().some((o) => o.objectName === objectName));
    assert.ok(!store.getGroups().find((g) => g.id === group.id)!.objectPermissions.some((p) => p.objectName === objectName));
  });

  test('SFDX import through the API uses the object label, not a compact layout label', async () => {
    const objectName = `Invoice_${tag()}__c`;
    const res = await adminFetch(server.baseUrl, session, '/api/admin/objects/import-sfdx-files', {
      method: 'POST',
      body: {
        files: [
          {
            relativePath: `objects/${objectName}.object`,
            content: `<CustomObject><compactLayouts><label>Compact</label></compactLayouts><fields><fullName>Amount__c</fullName><label>Amount</label></fields><label>Invoice</label></CustomObject>`,
          },
        ],
      },
    });
    assert.equal(res.status, 200);
    const imported = store.getObjects().find((o) => o.objectName === objectName);
    assert.equal(imported?.label, 'Invoice');
  });
});

describe('Profiles CSV import', () => {
  test('quoted names containing commas are imported intact', async () => {
    const id = `00e${crypto.randomBytes(6).toString('hex')}`.slice(0, 15);
    const res = await adminFetch(server.baseUrl, session, '/api/admin/profiles/import-csv', {
      method: 'POST',
      body: { csvText: `Id,Name\r\n${id},"Custom: Sales, EMEA"\r\n` },
    });
    assert.equal(res.status, 200);
    assert.equal(store.getProfileById(id)?.name, 'Custom: Sales, EMEA');
  });
});

describe('Okta settings', () => {
  test('a blank secret on save keeps the stored ciphertext, even when it cannot be decrypted', () => {
    const foreignKey = crypto.randomBytes(32);
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', foreignKey, iv);
    const enc = Buffer.concat([cipher.update('secret-from-old-key', 'utf8'), cipher.final()]);
    const undecryptable = `${iv.toString('hex')}:${cipher.getAuthTag().toString('hex')}:${enc.toString('hex')}`;
    const db = rawDb();
    db.prepare('UPDATE okta_config SET client_secret_enc = ? WHERE id = 1').run(undecryptable);

    assert.equal(store.getOktaConfig().hasClientSecret, false);
    store.updateOktaConfig({ enabled: false, adminGroup: 'MCP-Admins' });
    const stored = (db.prepare('SELECT client_secret_enc FROM okta_config WHERE id = 1').get() as any).client_secret_enc;
    assert.equal(stored, undecryptable, 'the ciphertext must not be wiped');

    store.updateOktaConfig({ clientSecret: 'new-secret' });
    assert.equal(store.getOktaConfig().clientSecret, 'new-secret');
    db.close();
  });

  test('a custom issuer survives saves that keep the domain; an empty issuer derives it from the domain', () => {
    store.updateOktaConfig({ oktaDomain: 'acme.okta.com', issuer: 'https://acme.okta.com' });
    assert.equal(store.getOktaConfig().issuer, 'https://acme.okta.com');
    store.updateOktaConfig({ oktaDomain: 'acme.okta.com', adminGroup: 'Admins' });
    assert.equal(store.getOktaConfig().issuer, 'https://acme.okta.com');
    store.updateOktaConfig({ oktaDomain: 'acme.okta.com', issuer: '' });
    assert.equal(store.getOktaConfig().issuer, 'https://acme.okta.com/oauth2/default');
    store.updateOktaConfig({ oktaDomain: 'other.okta.com' });
    assert.equal(store.getOktaConfig().issuer, 'https://other.okta.com/oauth2/default');
  });

  test('the redirect URI can be cleared so it follows BASE_URL at request time', () => {
    store.updateOktaConfig({ redirectUri: '' });
    assert.equal(store.getOktaConfig().redirectUri, '');
    store.updateOktaConfig({ redirectUri: 'https://portal.example.com/auth/okta/callback' });
    assert.equal(store.getOktaConfig().redirectUri, 'https://portal.example.com/auth/okta/callback');
    store.updateOktaConfig({ redirectUri: '' });
  });
});

describe('Portal users', () => {
  test('changing a password keeps the existing role and display name', async () => {
    const username = `ops_${tag()}`;
    store.upsertPortalUser({ username, displayName: 'Ops Lead', password: 'first-pass-1', role: 'Super Admin' });
    const res = await adminFetch(server.baseUrl, session, '/api/admin/portal-users', {
      method: 'POST',
      body: { username, password: 'second-pass-2' },
    });
    assert.equal(res.status, 200);
    const user = store.getPortalUsers().find((u) => u.username === username)!;
    assert.equal(user.role, 'Super Admin');
    assert.equal(user.displayName, 'Ops Lead');
    assert.ok(store.verifyPortalUserCredentials(username, 'second-pass-2'));
    store.deletePortalUser(username);
  });
});

describe('Dashboard totals', () => {
  test('overview stats count every Copilot log row, not just the latest 150', async () => {
    for (let i = 0; i < 160; i++) {
      store.recordCopilotMcpLog({
        sfUsername: 'load@acme.com',
        profileId: '00e000000000001',
        profileName: 'Load',
        matchedGroups: [],
        toolName: 'soql_query',
        targetObject: 'Account',
        status: i % 4 === 0 ? 'DENIED' : 'ALLOWED',
        latencyMs: 1,
        rawRequestPayload: {},
        rawResponseSummary: {},
      });
    }
    const res = await adminFetch(server.baseUrl, session, '/api/admin/overview');
    assert.equal(res.status, 200);
    const stats = store.getCopilotMcpLogStats();
    assert.ok(stats.total >= 160);
    assert.equal(res.body.stats.totalMcpRequests, stats.total);
    assert.equal(
      res.body.stats.allowedMcpRequests + res.body.stats.deniedMcpRequests + res.body.stats.erroredMcpRequests,
      stats.total
    );
    assert.equal(res.body.stats.deniedMcpRequests, stats.denied, 'ERROR rows are not counted as policy denials');
    assert.equal(res.body.copilotLogs.length, 150);
  });
});

describe('Salesforce settings validation', () => {
  const put = (body: Record<string, unknown>) =>
    adminFetch(server.baseUrl, session, '/api/admin/sf-settings', { method: 'PUT', body });

  test('rejects instance URLs outside SALESFORCE_ALLOWED_DOMAINS, malformed Org IDs and API versions', async () => {
    assert.equal((await put({ instanceUrl: 'https://evil.example.com' })).status, 400);
    assert.equal((await put({ instanceUrl: 'http://169.254.169.254' })).status, 400);
    assert.equal((await put({ expectedOrgId: 'not-an-org-id' })).status, 400);
    assert.equal((await put({ apiVersion: '62' })).status, 400);
  });

  test('refuses to enforce the Org ID lock without an expected Org ID', async () => {
    const res = await put({ expectedOrgId: '', enforceOrgIdLock: true });
    assert.equal(res.status, 400);
    assert.equal(store.getSalesforceSettings().enforceOrgIdLock, false);
  });

  test('saves a valid configuration and normalises the instance URL to its origin', async () => {
    const res = await put({
      instanceUrl: 'https://acme.my.salesforce.com/some/path',
      apiVersion: 'v61.0',
      expectedOrgId: '00D000000000001AAA',
      enforceOrgIdLock: true,
    });
    assert.equal(res.status, 200, JSON.stringify(res.body));
    assert.equal(res.body.sfSettings.instanceUrl, 'https://acme.my.salesforce.com');
    assert.equal(res.body.sfSettings.enforceOrgIdLock, true);
    // restore defaults for the rest of the file
    await put({ instanceUrl: 'https://login.salesforce.com', apiVersion: 'v62.0', expectedOrgId: '', enforceOrgIdLock: false });
  });
});

describe('Audit-log redaction', () => {
  test('record values sent where field names belong are redacted; field names and ids are kept', () => {
    const stripped = stripSensitivePayloadData({
      objectName: 'Account',
      fields: [{ Name: 'Jane Array-Wrapped Doe', Industry: 'Banking' }],
      fieldNames: ['Id', 'Name'],
      id: '001000000000001AAA',
      toolName: 'Jane Doe 123-45-6789',
    }) as Record<string, unknown>;
    const text = JSON.stringify(stripped);
    assert.ok(!text.includes('Jane'), text);
    assert.ok(!text.includes('Banking'), text);
    assert.deepEqual(stripped.fieldNames, ['Id', 'Name']);
    assert.equal(stripped.id, '001000000000001AAA');
    assert.equal(stripped.objectName, 'Account');
    assert.equal(stripped.toolName, '<REDACTED:string>');
  });
});

describe('Okta callback errors', () => {
  const callback = (query: string) =>
    fetch(`${server.baseUrl}/auth/okta/callback?${query}`, { redirect: 'manual' });

  test('an IdP error redirects with a fixed code only; the attacker-controlled text goes to the audit log', async () => {
    const lure = 'Sign in at https://evil.example/okta instead';
    const res = await callback(`error=access_denied&error_description=${encodeURIComponent(lure)}`);
    assert.equal(res.status, 302);
    assert.equal(res.headers.get('location'), '/?auth_error=okta_error');
    const log = store.getPortalAdminLogs(5).find((l) => l.action === 'OKTA_LOGIN_FAILED');
    assert.match(log?.details || '', /evil\.example/);
  });

  test('a callback without the login state cookie redirects with invalid_callback', async () => {
    const res = await callback('code=abc&state=xyz');
    assert.equal(res.status, 302);
    assert.equal(res.headers.get('location'), '/?auth_error=invalid_callback');
  });
});

/** Seeds an enabled object, a group granting read+create on it, and a profile mapped to that group. */
function seedReadablePolicy(objectName: string) {
  const profileId = `00e${crypto.randomBytes(6).toString('hex')}`.slice(0, 15);
  const profileName = `Policy ${tag()}`;
  store.upsertObjectWithFields({ objectName, fields: [{ fieldName: 'Id' }, { fieldName: 'Name' }] });
  const group = store.upsertGroup({
    name: `Readers ${tag()}`,
    allowedActions: ['soql_query', 'create_record'],
    objectPermissions: [{ objectName, canRead: true, canCreate: true, canUpdate: false, canDelete: false, allowedFields: ['Id', 'Name'] }],
  });
  store.upsertProfile(profileId, profileName);
  store.setProfileGroups(profileId, [group.id]);
  return { profileId, profileName };
}

describe('Simulator tokens on tools/call', () => {
  test('soql_query and create_record with a simulator token return simulated data and never reach Salesforce', async (t) => {
    const sf = installSalesforceMock();
    t.after(() => sf.restore());
    const objectName = `Sim_${tag()}__c`;
    const { profileId, profileName } = seedReadablePolicy(objectName);
    const token = createSimulatorToken({ profileId, profileName });

    const query = await mcpRequest(server.baseUrl, token, 'tools/call', { name: 'soql_query', arguments: { objectName, fields: ['Id', 'Name'] } });
    assert.equal(query.status, 200);
    assert.notEqual(query.body.result.isError, true, JSON.stringify(query.body));
    assert.equal(toolResultPayload(query.body).totalSize, 2);

    const create = await mcpRequest(server.baseUrl, token, 'tools/call', { name: 'create_record', arguments: { objectName, fields: { Name: 'Simulated' } } });
    assert.notEqual(create.body.result.isError, true, JSON.stringify(create.body));
    assert.equal(toolResultPayload(create.body).recordId, '006SIM000009999AAA');

    assert.deepEqual(sf.calls, [], 'a simulator token must never be sent to Salesforce');
    assert.deepEqual(sf.nonSalesforceCalls, []);
  });
});

describe('Profile resolution fails closed', () => {
  test('when the User/Profile lookup fails, the caller gets no tools even if a registered Profile is named "Standard User"', async (t) => {
    const sf = installSalesforceMock();
    t.after(() => sf.restore());
    const objectName = `Std_${tag()}__c`;
    const { profileId } = seedReadablePolicy(objectName);
    store.upsertProfile(profileId, 'Standard User');

    const token = `tok_${tag()}`;
    sf.addUser(token, {
      userId: '005000000000099AAA',
      organizationId: '00D000000000001AAA',
      username: 'noscope@acme.com',
      profileId,
      profileName: 'Standard User',
      userQueryStatus: 403,
    });
    const list = await mcpRequest(server.baseUrl, token, 'tools/list');
    assert.equal(list.status, 200);
    assert.deepEqual(list.body.result.tools, []);

    const call = await mcpRequest(server.baseUrl, token, 'tools/call', { name: 'soql_query', arguments: { objectName } });
    assert.equal(call.body.result.isError, true);
    assert.match(toolResultPayload(call.body).reason, /could not be determined/);
  });
});

describe('Salesforce API names', () => {
  test('SFDX import skips fields and objects whose names are not API names (no SOQL injection through metadata)', async () => {
    const objectName = `Meta_${tag()}__c`;
    const res = await adminFetch(server.baseUrl, session, '/api/admin/objects/import-sfdx-files', {
      method: 'POST',
      body: {
        files: [
          { relativePath: `objects/${objectName}/fields/Ok__c.field-meta.xml`, content: '<CustomField><fullName>Ok__c</fullName></CustomField>' },
          {
            relativePath: `objects/${objectName}/fields/Evil.field-meta.xml`,
            content: '<CustomField><fullName>(SELECT Email FROM Contacts)</fullName></CustomField>',
          },
          { relativePath: `objects/${objectName}/fields/Owner.Email.field-meta.xml`, content: '<CustomField><label>x</label></CustomField>' },
          { relativePath: 'objects/Bad Name/Bad Name.object-meta.xml', content: '<CustomObject><label>Bad</label></CustomObject>' },
        ],
      },
    });
    assert.equal(res.status, 200, JSON.stringify(res.body));
    const imported = store.getObjects().find((o) => o.objectName === objectName)!;
    assert.deepEqual(imported.fields.map((f) => f.fieldName).sort(), ['Id', 'Name', 'Ok__c']);
    assert.ok(!store.getObjects().some((o) => o.objectName === 'Bad Name'));
  });

  test('POST /objects rejects invalid object or field API names with 400', async () => {
    const badField = await adminFetch(server.baseUrl, session, '/api/admin/objects', {
      method: 'POST',
      body: { objectName: `Manual_${tag()}__c`, fields: [{ fieldName: 'Owner.Email' }] },
    });
    assert.equal(badField.status, 400);
    assert.match(badField.body.error, /not a valid Salesforce field API name/);
    const badObject = await adminFetch(server.baseUrl, session, '/api/admin/objects', {
      method: 'POST',
      body: { objectName: 'Account WHERE Id != null' },
    });
    assert.equal(badObject.status, 400);
  });
});

describe('Login throttling per username', () => {
  test('failed logins for one account are limited even when each attempt claims a different client IP', async () => {
    const username = `target_${tag()}`;
    const statuses: number[] = [];
    for (let i = 0; i < 22; i++) {
      const res = await fetch(`${server.baseUrl}/api/admin/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Forwarded-For': `198.51.100.${i + 1}` },
        body: JSON.stringify({ username, password: `guess-${i}` }),
      });
      statuses.push(res.status);
      await res.text();
    }
    assert.deepEqual(statuses.slice(0, 20), Array(20).fill(401));
    assert.equal(statuses[20], 429);
    assert.equal(statuses[21], 429);
  });
});

describe('Login input hardening', () => {
  test('non-string credentials get a 400 and the server keeps answering (no unhandled rejection)', async () => {
    for (const body of [
      { username: { toString: 1 }, password: 'x' },
      { username: 'admin', password: { toString: 1 } },
      { username: ['admin'], password: 'x' },
    ]) {
      const res = await fetch(`${server.baseUrl}/api/admin/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Forwarded-For': '203.0.113.77' },
        body: JSON.stringify(body),
      });
      assert.equal(res.status, 400, JSON.stringify(body));
      await res.text();
    }
    const health = await fetch(`${server.baseUrl}/healthz`);
    assert.equal(health.status, 200);
  });
});

describe('Manual object updates', () => {
  test('POST /objects applies an explicit field `enabled` to an existing field, and omitting it keeps the toggle', async () => {
    const objectName = `Toggle_${tag()}__c`;
    const create = await adminFetch(server.baseUrl, session, '/api/admin/objects', {
      method: 'POST',
      body: { objectName, fields: [{ fieldName: 'Id' }, { fieldName: 'Secret__c' }] },
    });
    assert.equal(create.status, 200);
    const fieldEnabled = () =>
      store.getObjects().find((o) => o.objectName === objectName)!.fields.find((f) => f.fieldName === 'Secret__c')!.enabled;
    assert.equal(fieldEnabled(), true);

    await adminFetch(server.baseUrl, session, '/api/admin/objects', {
      method: 'POST',
      body: { objectName, fields: [{ fieldName: 'Secret__c', enabled: false }] },
    });
    assert.equal(fieldEnabled(), false);

    await adminFetch(server.baseUrl, session, '/api/admin/objects', {
      method: 'POST',
      body: { objectName, fields: [{ fieldName: 'Secret__c', label: 'Secret (renamed)' }] },
    });
    assert.equal(fieldEnabled(), false, 'omitting enabled keeps the admin toggle');
  });
});

describe('Case variants left by older versions', () => {
  test('deleting one case variant of a username never deletes the other or bypasses the last-admin guard', () => {
    const name = `Case_${tag()}`;
    const db = rawDb();
    const insert = db.prepare(
      "INSERT INTO portal_users (username, display_name, password_hash, password_salt, role, created_at) VALUES (?, ?, 'x', 'y', 'Admin', ?)"
    );
    insert.run(name, name, new Date().toISOString());
    insert.run(name.toLowerCase(), name, new Date().toISOString());
    db.close();

    assert.equal(store.deletePortalUser(name.toLowerCase()), true);
    const remaining = store.getPortalUsers().map((u) => u.username);
    assert.ok(remaining.includes(name), 'the other case variant must survive');
    assert.ok(!remaining.includes(name.toLowerCase()));
    store.deletePortalUser(name);
  });

  test('deleting a mis-cased duplicate object keeps the grants of the remaining object', () => {
    const real = `Dup_${tag()}__c`;
    store.upsertObjectWithFields({ objectName: real });
    store.upsertObjectWithFields({ objectName: real.toLowerCase() });
    const group = store.upsertGroup({
      name: `Dup grants ${tag()}`,
      allowedActions: ['soql_query'],
      objectPermissions: [{ objectName: real, canRead: true, canCreate: false, canUpdate: false, canDelete: false, allowedFields: ['Id'] }],
    });
    assert.equal(store.deleteObject(real.toLowerCase()), true);
    assert.deepEqual(store.getGroups().find((g) => g.id === group.id)!.objectPermissions.map((p) => p.objectName), [real]);
  });
});

describe('MCP rate limit is per caller', () => {
  test('anonymous /mcp traffic cannot use up the allowance of a caller with a bearer token', async (t) => {
    const sf = installSalesforceMock();
    t.after(() => sf.restore());
    // Exhaust the anonymous bucket (120 per minute) from one client address
    let lastAnonymous = 0;
    for (let i = 0; i < 125; i++) {
      const res = await fetch(`${server.baseUrl}/mcp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream' },
        body: JSON.stringify({ jsonrpc: '2.0', id: i, method: 'tools/list' }),
      });
      lastAnonymous = res.status;
      await res.text();
    }
    assert.equal(lastAnonymous, 429);

    const token = `tok_${tag()}`;
    sf.addUser(token, {
      userId: '005000000000123AAA',
      organizationId: '00D000000000001AAA',
      username: 'busy@acme.com',
      profileId: '00e000000000123AAA',
      profileName: 'Nobody',
    });
    const authed = await mcpRequest(server.baseUrl, token, 'tools/list');
    assert.equal(authed.status, 200, 'a token holder keeps its own allowance');
  });
});

