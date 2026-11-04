import { testTmpDir } from './helpers/env.js';
// Every Admin API change shares one transaction with its Portal Admin log row: a row that cannot be
// written rolls the change back, and the request ends in a 500 from the shared error handler. The
// routes that were transactional before (POST /groups, DELETE /groups/:id, the membership routes and
// both pull-apply routes) are covered in admin-api.test.ts and org-sync-apply.test.ts.
import { after, before, describe, test, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync, type SQLInputValue } from 'node:sqlite';
import { SIMULATE_MCP_CALL_ACTION, store } from '../src/db/store.js';
import { generateSelfSignedCertificateBundle } from '../src/salesforce/jwtConnection.js';
import { PORTAL_PASSWORD_MIN_LENGTH } from '../src/security/passwordPolicy.js';
import { adminFetch, loginAsAdmin, startTestServer, type AdminSession, type TestServer } from './helpers/server.js';
import { installSalesforceMock, type SalesforceMock } from './helpers/salesforceMock.js';

const uid = () => crypto.randomBytes(4).toString('hex');
const newProfileId = () => `00e${crypto.randomBytes(6).toString('hex')}`.slice(0, 15);
const newObjectName = () => `Rollback_${uid()}__c`;
const ORG_ID = '00D000000000001AAA';
const bundle = generateSelfSignedCertificateBundle('Audit Rollback Test');

let server: TestServer;
let session: AdminSession;
let sf: SalesforceMock;
let raw: DatabaseSync;

before(async () => {
  sf = installSalesforceMock();
  server = await startTestServer();
  session = await loginAsAdmin(server.baseUrl);
  raw = new DatabaseSync(process.env.DB_PATH as string);
});

after(async () => {
  raw.close();
  sf.restore();
  await server.close();
});

// ------------------------------------------------------------------------------------------------
// Fixtures, each removed again when its test ends
// ------------------------------------------------------------------------------------------------

function addProfile(t: TestContext): string {
  const id = newProfileId();
  store.upsertProfile(id, `Rollback Profile ${uid()}`);
  t.after(() => store.deleteProfile(id));
  return id;
}

function addObject(t: TestContext, fieldNames = ['Id', 'Name', 'Secret__c']): string {
  const objectName = newObjectName();
  store.upsertObjectWithFields({ objectName, fields: fieldNames.map((fieldName) => ({ fieldName })) });
  t.after(() => store.deleteObject(objectName));
  return objectName;
}

/** A group granting Read on `objectName` with all of its fields. */
function addGrantingGroup(t: TestContext, objectName: string): string {
  const group = store.createGroup({
    name: `Rollback Group ${uid()}`,
    allowedActions: ['soql_query'],
    objectPermissions: [
      { objectName, canRead: true, canCreate: false, canUpdate: false, canDelete: false, allowedFields: ['Id', 'Name', 'Secret__c'] },
    ],
  });
  t.after(() => store.deleteGroup(group.id));
  return group.id;
}

function addPortalUser(t: TestContext): string {
  const username = `rollback.${uid()}`;
  store.upsertPortalUser({ username, password: `Pw-${crypto.randomBytes(12).toString('hex')}` });
  t.after(() => {
    if (store.findPortalUsername(username) !== undefined) store.deletePortalUser(username);
  });
  return username;
}

/** Puts both settings rows back exactly as they were, which the API alone cannot (a stored secret stays). */
function restoreSettingsAfter(t: TestContext): void {
  for (const table of ['okta_config', 'sf_connection_settings']) {
    const row = raw.prepare(`SELECT * FROM ${table} WHERE id = 1`).get() as Record<string, SQLInputValue>;
    t.after(() => {
      const columns = Object.keys(row).filter((column) => column !== 'id');
      raw
        .prepare(`UPDATE ${table} SET ${columns.map((c) => `${c} = ?`).join(', ')} WHERE id = 1`)
        .run(...columns.map((c) => row[c]));
    });
  }
}

const objectMetaXml = (label: string) =>
  `<?xml version="1.0" encoding="UTF-8"?>
<CustomObject xmlns="http://soap.sforce.com/2006/04/metadata"><label>${label}</label></CustomObject>`;
const fieldMetaXml = (fullName: string) =>
  `<?xml version="1.0" encoding="UTF-8"?>
<CustomField xmlns="http://soap.sforce.com/2006/04/metadata"><fullName>${fullName}</fullName><label>${fullName}</label><type>Text</type></CustomField>`;

/** Removes, when the test ends, the Object a request adds. */
function removeImportedObjectsAfter(t: TestContext, objectName: string): void {
  t.after(() => store.deleteObject(objectName));
}

// ------------------------------------------------------------------------------------------------
// What a rolled-back request must leave as it was
// ------------------------------------------------------------------------------------------------

/** Every table an Admin API change can write, read back as plain JSON. */
function storeState() {
  return JSON.parse(
    JSON.stringify({
      profiles: store.getProfiles(),
      objects: store.getObjects(),
      groups: store.getGroups(),
      mappings: store.getProfileGroupMappings(),
      okta: raw.prepare('SELECT * FROM okta_config').all(),
      salesforce: raw.prepare('SELECT * FROM sf_connection_settings').all(),
      portalUsers: raw.prepare('SELECT * FROM portal_users ORDER BY username').all(),
      copilotLogIds: store.getCopilotMcpLogs(1000).map((row) => row.id),
    })
  );
}

const latestAudit = () => store.getPortalAdminLogs(1)[0];

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

interface Request {
  method: string;
  path: string;
  body?: unknown;
}

interface Row {
  name: string;
  /** The action of the row the retry writes. */
  action: string;
  arrange: (t: TestContext) => Request;
  /** What the retry answers: 200 unless the change is a failure the route records. */
  retryStatus?: number;
}

const rows: Row[] = [
  {
    name: 'POST /profiles creating a Profile',
    action: 'CREATE_PROFILE',
    arrange: (t) => {
      const id = newProfileId();
      t.after(() => store.deleteProfile(id));
      return { method: 'POST', path: '/api/admin/profiles', body: { id, name: `Created ${uid()}` } };
    },
  },
  {
    name: 'POST /profiles renaming a Profile',
    action: 'UPDATE_PROFILE',
    arrange: (t) => ({ method: 'POST', path: '/api/admin/profiles', body: { id: addProfile(t), name: `Renamed ${uid()}` } }),
  },
  {
    name: 'POST /profiles/import-csv',
    action: 'IMPORT_PROFILES_CSV',
    arrange: (t) => {
      const ids = [newProfileId(), newProfileId()];
      t.after(() => ids.forEach((id) => store.deleteProfile(id)));
      return {
        method: 'POST',
        path: '/api/admin/profiles/import-csv',
        body: { csvText: `id,name\n${ids.map((id) => `${id},Imported ${id}`).join('\n')}` },
      };
    },
  },
  {
    name: 'DELETE /profiles/:id of a Profile in an Access Group',
    action: 'DELETE_PROFILE',
    arrange: (t) => {
      const id = addProfile(t);
      store.setProfileGroups(id, [addGrantingGroup(t, addObject(t))]);
      return { method: 'DELETE', path: `/api/admin/profiles/${id}` };
    },
  },
  {
    name: 'POST /objects/import-sfdx-files',
    action: 'IMPORT_SFDX_OBJECTS_FOLDER',
    arrange: (t) => {
      const objectName = newObjectName();
      removeImportedObjectsAfter(t, objectName);
      const root = `force-app/main/default/objects/${objectName}`;
      return {
        method: 'POST',
        path: '/api/admin/objects/import-sfdx-files',
        body: {
          files: [
            { relativePath: `${root}/${objectName}.object-meta.xml`, content: objectMetaXml('Uploaded') },
            { relativePath: `${root}/fields/Color__c.field-meta.xml`, content: fieldMetaXml('Color__c') },
          ],
        },
      };
    },
  },
  {
    name: 'POST /objects/import-local-folder, which also stores the folder path',
    action: 'SYNC_LOCAL_SFDX_FOLDER',
    arrange: (t) => {
      const objectName = newObjectName();
      removeImportedObjectsAfter(t, objectName);
      const folderPath = path.join(testTmpDir, `objects-${uid()}`);
      fs.mkdirSync(path.join(folderPath, objectName, 'fields'), { recursive: true });
      fs.writeFileSync(path.join(folderPath, objectName, `${objectName}.object-meta.xml`), objectMetaXml('Local'));
      fs.writeFileSync(path.join(folderPath, objectName, 'fields', 'Color__c.field-meta.xml'), fieldMetaXml('Color__c'));
      return { method: 'POST', path: '/api/admin/objects/import-local-folder', body: { folderPath } };
    },
  },
  {
    name: 'POST /objects',
    action: 'UPSERT_OBJECT',
    arrange: (t) => {
      const objectName = newObjectName();
      removeImportedObjectsAfter(t, objectName);
      return { method: 'POST', path: '/api/admin/objects', body: { objectName, fields: [{ fieldName: 'Id' }] } };
    },
  },
  {
    name: 'PUT /objects/:objectName/toggle',
    action: 'TOGGLE_OBJECT',
    arrange: (t) => ({ method: 'PUT', path: `/api/admin/objects/${addObject(t)}/toggle`, body: { enabled: false } }),
  },
  {
    name: 'PUT /objects/:objectName/fields/:fieldName/toggle',
    action: 'TOGGLE_FIELD',
    arrange: (t) => ({ method: 'PUT', path: `/api/admin/objects/${addObject(t)}/fields/Name/toggle`, body: { enabled: false } }),
  },
  {
    name: 'PUT /objects/:objectName/fields/bulk',
    action: 'BULK_TOGGLE_FIELDS',
    arrange: (t) => ({ method: 'PUT', path: `/api/admin/objects/${addObject(t)}/fields/bulk`, body: { enabled: false } }),
  },
  {
    name: 'DELETE /objects/:objectName/fields/:fieldName of a granted field, whose revocation is undone too',
    action: 'DELETE_FIELD',
    arrange: (t) => {
      const objectName = addObject(t);
      addGrantingGroup(t, objectName);
      return { method: 'DELETE', path: `/api/admin/objects/${objectName}/fields/Secret__c` };
    },
  },
  {
    name: 'DELETE /objects/:objectName of a granted Object, whose revocation is undone too',
    action: 'DELETE_OBJECT',
    arrange: (t) => {
      const objectName = addObject(t);
      addGrantingGroup(t, objectName);
      return { method: 'DELETE', path: `/api/admin/objects/${objectName}` };
    },
  },
  {
    name: 'PUT /okta',
    action: 'UPDATE_OKTA_SSO',
    arrange: () => ({
      method: 'PUT',
      path: '/api/admin/okta',
      body: { enabled: false, oktaDomain: `dev-${uid()}.okta.com`, clientId: `client-${uid()}`, clientSecret: `secret-${uid()}` },
    }),
  },
  {
    name: 'PUT /sf-settings turning the Org ID lock on',
    action: 'UPDATE_SF_SETTINGS',
    arrange: () => ({ method: 'PUT', path: '/api/admin/sf-settings', body: { expectedOrgId: ORG_ID, enforceOrgIdLock: true } }),
  },
  {
    name: 'POST /sf-settings/generate-cert',
    action: 'GENERATE_SF_JWT_CERT',
    arrange: () => ({ method: 'POST', path: '/api/admin/sf-settings/generate-cert', body: {} }),
  },
  {
    name: 'POST /sf-settings/connect that verifies the settings',
    action: 'CONNECT_SALESFORCE_ORG',
    arrange: () => {
      store.updateSalesforceSettings({
        privateKeyPem: bundle.privateKeyPem,
        certificatePem: bundle.certificatePem,
        connectionStatus: 'disconnected',
      });
      return { method: 'POST', path: '/api/admin/sf-settings/connect', body: { authMode: 'simulated' } };
    },
  },
  {
    name: 'POST /sf-settings/connect that fails, whose error status is undone too',
    action: 'CONNECT_SALESFORCE_ORG_FAILED',
    arrange: () => {
      store.updateSalesforceSettings({ connectionStatus: 'disconnected', lastError: '' });
      // No key at all, which the API cannot set: the simulated connect has nothing to sign with.
      raw.prepare("UPDATE sf_connection_settings SET private_key_enc = '' WHERE id = 1").run();
      return { method: 'POST', path: '/api/admin/sf-settings/connect', body: { authMode: 'simulated' } };
    },
    retryStatus: 400,
  },
  {
    name: 'POST /sf-settings/disconnect',
    action: 'DISCONNECT_SALESFORCE_ORG',
    arrange: () => {
      store.updateSalesforceSettings({ enabled: true, connectionStatus: 'connected', connectedOrgId: ORG_ID });
      return { method: 'POST', path: '/api/admin/sf-settings/disconnect', body: {} };
    },
  },
  {
    name: 'POST /portal-users',
    action: 'UPSERT_PORTAL_USER',
    arrange: (t) => {
      const username = `rollback.new.${uid()}`;
      t.after(() => {
        if (store.findPortalUsername(username) !== undefined) store.deletePortalUser(username);
      });
      const password = `Pw-${crypto.randomBytes(PORTAL_PASSWORD_MIN_LENGTH).toString('hex')}`;
      return { method: 'POST', path: '/api/admin/portal-users', body: { username, password } };
    },
  },
  {
    name: 'DELETE /portal-users/:username',
    action: 'DELETE_PORTAL_USER',
    arrange: (t) => ({ method: 'DELETE', path: `/api/admin/portal-users/${addPortalUser(t)}` }),
  },
  {
    name: 'POST /test-mcp-access, whose Copilot MCP log row is undone too',
    action: SIMULATE_MCP_CALL_ACTION,
    arrange: (t) => {
      const objectName = addObject(t);
      const profileId = addProfile(t);
      store.setProfileGroups(profileId, [addGrantingGroup(t, objectName)]);
      return {
        method: 'POST',
        path: '/api/admin/test-mcp-access',
        body: { profileId, toolName: 'soql_query', targetObject: objectName },
      };
    },
  },
  {
    name: 'POST /workspace/seed-sample',
    action: 'SEED_ENTERPRISE_MATRIX',
    arrange: (t) => {
      const profilesBefore = new Set(store.getProfiles().map((p) => p.id));
      const groupsBefore = new Set(store.getGroups().map((g) => g.id));
      // Deleting what the seed added also drops its mappings (ON DELETE CASCADE).
      t.after(() => {
        for (const group of store.getGroups().filter((g) => !groupsBefore.has(g.id))) store.deleteGroup(group.id);
        for (const profile of store.getProfiles().filter((p) => !profilesBefore.has(p.id))) store.deleteProfile(profile.id);
      });
      // The sample keeps only grants for Objects in the catalog, so give it one to grant.
      if (!store.getObjects().some((o) => o.objectName === 'Account')) {
        store.upsertObjectWithFields({ objectName: 'Account', fields: [{ fieldName: 'Id' }, { fieldName: 'Name' }] });
        t.after(() => store.deleteObject('Account'));
      }
      return { method: 'POST', path: '/api/admin/workspace/seed-sample', body: {} };
    },
  },
];

describe('an Admin API change whose audit row cannot be written is rolled back (500)', () => {
  for (const row of rows) {
    test(row.name, async (t) => {
      restoreSettingsAfter(t);
      const request = row.arrange(t);
      const send = () => adminFetch(server.baseUrl, session, request.path, { method: request.method, body: request.body });
      const before = storeState();
      const revision = store.getPolicyRevision();
      const lastAudit = latestAudit()?.id;

      const restore = failNextAuditWrite(t);
      const res = await send();
      restore();

      assert.deepEqual([res.status, res.body], [500, { error: 'Internal server error' }]);
      assert.deepEqual(storeState(), before, 'the change must be rolled back');
      assert.equal(store.getPolicyRevision(), revision);
      assert.equal(latestAudit()?.id, lastAudit, 'no audit row may be written');

      // Control: nothing half-done is in the way, and the same request goes through with its row.
      const retry = await send();
      assert.equal(retry.status, row.retryStatus ?? 200, JSON.stringify(retry.body));
      assert.equal(latestAudit().action, row.action);
      assert.notDeepEqual(storeState(), before);
    });
  }
});
