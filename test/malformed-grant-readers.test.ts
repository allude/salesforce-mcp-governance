import './helpers/env.js';
// The readers of stored Access Group grants outside policy evaluation: the field and Object deletes
// (Admin API and org sync), which revoke grants, and the org sync preview, which names the groups a
// removal affects. A database from an older version can hold entries malformedGrantReason refuses and
// columns that do not parse. None of these readers may fail on them, and none may rewrite them.
import { after, before, describe, test, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { store } from '../src/db/store.js';
import { adminFetch, loginAsAdmin, startTestServer, type AdminSession, type TestServer } from './helpers/server.js';

const uid = () => crypto.randomBytes(4).toString('hex');

let server: TestServer;
let session: AdminSession;
let raw: DatabaseSync;

before(async () => {
  server = await startTestServer();
  session = await loginAsAdmin(server.baseUrl);
  raw = new DatabaseSync(process.env.DB_PATH as string);
});

after(async () => {
  raw.close();
  await server.close();
});

/** Every shape malformedGrantReason refuses, each naming the Object or its Secret__c where it can. */
const malformedEntries = (objectName: string): unknown[] => [
  null,
  'text',
  [],
  { objectName: 7, canRead: true },
  { objectName, canRead: 'true', allowedFields: ['Secret__c'] },
  { objectName, canRead: true, allowedFields: 'Secret__c' },
  { objectName, canRead: true, allowedFields: [1, 'Secret__c'] },
];

const validEntry = (objectName: string) => ({
  objectName,
  canRead: true,
  canCreate: false,
  canUpdate: false,
  canDelete: false,
  allowedFields: ['Id', 'Secret__c'],
});

const storedColumn = (groupId: string) =>
  raw.prepare('SELECT object_permissions_json AS json, version FROM access_groups WHERE id = ?').get(groupId) as {
    json: string;
    version: number;
  };

/** Writes a column as an older version could have left it, past every check a save makes. */
function plantColumn(groupId: string, json: string) {
  raw.prepare('UPDATE access_groups SET object_permissions_json = ? WHERE id = ?').run(json, groupId);
}

/**
 * An Object with Id, Name and Secret__c, and four groups:
 * - mixed: every malformed entry, then one valid grant of Id and Secret__c;
 * - valid: only that valid grant;
 * - malformedOnly: only the malformed entries, which grant nothing;
 * - unparseable and notAList: columns that are not JSON, and JSON that is not a list.
 */
function arrange(t: TestContext) {
  // getGroups warns once per unreadable column; that warning has its own tests.
  t.mock.method(console, 'warn', () => {});
  const objectName = `Legacy_${uid()}__c`;
  store.upsertObjectWithFields({
    objectName,
    fields: [{ fieldName: 'Id' }, { fieldName: 'Name' }, { fieldName: 'Secret__c' }],
  });
  const newGroup = (label: string) =>
    store.createGroup({ name: `${label} ${uid()}`, allowedActions: ['soql_query'], objectPermissions: [] });
  const mixed = newGroup('Mixed');
  const valid = newGroup('Valid');
  const malformedOnly = newGroup('Malformed only');
  const unparseable = newGroup('Unparseable');
  const notAList = newGroup('Not a list');
  plantColumn(mixed.id, JSON.stringify([...malformedEntries(objectName), validEntry(objectName)]));
  plantColumn(valid.id, JSON.stringify([validEntry(objectName)]));
  plantColumn(malformedOnly.id, JSON.stringify(malformedEntries(objectName)));
  plantColumn(unparseable.id, '{not json');
  plantColumn(notAList.id, '{"objectName":"' + objectName + '","canRead":true}');
  t.after(() => {
    for (const group of [mixed, valid, malformedOnly, unparseable, notAList]) store.deleteGroup(group.id);
    store.deleteObject(objectName);
  });

  const untouched = [malformedOnly, unparseable, notAList].map((g) => ({ id: g.id, ...storedColumn(g.id) }));
  return {
    objectName,
    mixed,
    valid,
    malformedOnly,
    mixedVersion: storedColumn(mixed.id).version,
    validVersion: storedColumn(valid.id).version,
    /** The groups no revocation may write: their column and version are exactly as planted. */
    assertUntouched() {
      for (const before of untouched) {
        assert.deepEqual({ id: before.id, ...storedColumn(before.id) }, before);
      }
    },
  };
}

const latestAudit = () => store.getPortalAdminLogs(1)[0];

describe('deleting a field revokes it from readable grants only', () => {
  test('DELETE /objects/:objectName/fields/:fieldName skips malformed entries and unreadable columns', async (t) => {
    const fx = arrange(t);

    const res = await adminFetch(server.baseUrl, session, `/api/admin/objects/${fx.objectName}/fields/Secret__c`, {
      method: 'DELETE',
    });

    assert.equal(res.status, 200, JSON.stringify(res.body));
    assert.deepEqual(JSON.parse(storedColumn(fx.mixed.id).json), [
      ...malformedEntries(fx.objectName),
      { ...validEntry(fx.objectName), allowedFields: ['Id'] },
    ]);
    assert.deepEqual(JSON.parse(storedColumn(fx.valid.id).json), [{ ...validEntry(fx.objectName), allowedFields: ['Id'] }]);
    assert.deepEqual(
      [storedColumn(fx.mixed.id).version, storedColumn(fx.valid.id).version],
      [fx.mixedVersion + 1, fx.validVersion + 1]
    );
    fx.assertUntouched();
    assert.equal(latestAudit().action, 'DELETE_FIELD');
  });

  test('POST /objects/pull-apply removing a field skips them too, and names only the groups that lost it', async (t) => {
    const fx = arrange(t);

    const res = await adminFetch(server.baseUrl, session, '/api/admin/objects/pull-apply', {
      method: 'POST',
      body: {
        pulledMetadata: [
          {
            objectName: fx.objectName,
            label: fx.objectName,
            isCustom: true,
            existsInOrg: true,
            fields: ['Id', 'Name'].map((fieldName) => ({ fieldName, label: fieldName, fieldType: 'Text', isCustom: false, required: false })),
          },
        ],
        removeObjectNames: [],
        removeFields: [{ objectName: fx.objectName, fieldName: 'Secret__c' }],
      },
    });

    assert.equal(res.status, 200, JSON.stringify(res.body));
    assert.deepEqual(JSON.parse(storedColumn(fx.mixed.id).json), [
      ...malformedEntries(fx.objectName),
      { ...validEntry(fx.objectName), allowedFields: ['Id'] },
    ]);
    fx.assertUntouched();
    const audit = latestAudit();
    assert.equal(audit.action, 'SYNC_OBJECTS_FROM_ORG');
    assert.match(audit.details, new RegExp(`Access Groups that lost grants: .*${fx.mixed.name}`));
    assert.match(audit.details, new RegExp(`Access Groups that lost grants: .*${fx.valid.name}`));
    assert.doesNotMatch(audit.details, new RegExp(fx.malformedOnly.name));
  });
});

describe('deleting an Object revokes it from readable grants only', () => {
  test('DELETE /objects/:objectName keeps malformed entries, and its audit entry names the groups that lost a grant', async (t) => {
    const fx = arrange(t);

    const res = await adminFetch(server.baseUrl, session, `/api/admin/objects/${fx.objectName}`, { method: 'DELETE' });

    assert.equal(res.status, 200, JSON.stringify(res.body));
    assert.deepEqual(JSON.parse(storedColumn(fx.mixed.id).json), malformedEntries(fx.objectName));
    assert.deepEqual(JSON.parse(storedColumn(fx.valid.id).json), []);
    assert.deepEqual(
      [storedColumn(fx.mixed.id).version, storedColumn(fx.valid.id).version],
      [fx.mixedVersion + 1, fx.validVersion + 1]
    );
    fx.assertUntouched();
    const audit = latestAudit();
    assert.equal(audit.action, 'DELETE_OBJECT');
    assert.match(audit.details, /revoked it from 2 Access Group\(s\): /);
    assert.ok(audit.details.includes(fx.mixed.name) && audit.details.includes(fx.valid.name), audit.details);
    assert.ok(!audit.details.includes(fx.malformedOnly.name), audit.details);
  });

  test('POST /objects/pull-apply removing the Object keeps them too', async (t) => {
    const fx = arrange(t);

    const res = await adminFetch(server.baseUrl, session, '/api/admin/objects/pull-apply', {
      method: 'POST',
      body: {
        pulledMetadata: [{ objectName: fx.objectName, label: fx.objectName, isCustom: true, existsInOrg: false, fields: [] }],
        removeObjectNames: [fx.objectName],
        removeFields: [],
      },
    });

    assert.equal(res.status, 200, JSON.stringify(res.body));
    assert.deepEqual(JSON.parse(storedColumn(fx.mixed.id).json), malformedEntries(fx.objectName));
    assert.deepEqual(JSON.parse(storedColumn(fx.valid.id).json), []);
    fx.assertUntouched();
    assert.doesNotMatch(latestAudit().details, new RegExp(fx.malformedOnly.name));
  });

  test('a case variant that remains keeps every grant, and the audit entry names no group', async (t) => {
    const fx = arrange(t);
    const variant = fx.objectName.toLowerCase();
    // As an older version could leave it: a second row for the same Object in another case.
    raw
      .prepare('INSERT INTO sf_objects (object_name, label, updated_at) VALUES (?, ?, ?)')
      .run(variant, variant, new Date().toISOString());
    t.after(() => store.deleteObject(variant));
    const mixedBefore = storedColumn(fx.mixed.id);

    const res = await adminFetch(server.baseUrl, session, `/api/admin/objects/${variant}`, { method: 'DELETE' });

    assert.equal(res.status, 200, JSON.stringify(res.body));
    assert.deepEqual(storedColumn(fx.mixed.id), mixedBefore);
    fx.assertUntouched();
    assert.equal(latestAudit().details, `Deleted Salesforce Object "${variant}" and its fields from the MCP Server.`);
  });
});

describe('the org sync preview reads grants as the policy engine does', () => {
  test('previewObjectsSyncFromOrg names only groups with a readable grant for a removed Object or field', (t) => {
    const fx = arrange(t);
    const orgInfo = { orgId: '00D000000000001AAA', instanceUrl: 'https://example.my.salesforce.com' };

    const fieldGone = store.previewObjectsSyncFromOrg(
      [
        {
          objectName: fx.objectName,
          label: fx.objectName,
          isCustom: true,
          existsInOrg: true,
          fields: ['Id', 'Name'].map((fieldName) => ({ fieldName, label: fieldName, fieldType: 'Text', isCustom: false, required: false })),
        },
      ],
      orgInfo
    );
    const removedField = fieldGone.upsertedObjects[0].removedFieldsFromOrg.find((f) => f.fieldName === 'Secret__c');
    assert.deepEqual([...(removedField?.referencedInGroups ?? [])].sort(), [fx.mixed.name, fx.valid.name].sort());

    const objectGone = store.previewObjectsSyncFromOrg(
      [{ objectName: fx.objectName, label: fx.objectName, isCustom: true, existsInOrg: false, fields: [] }],
      orgInfo
    );
    assert.deepEqual(
      [...objectGone.removedObjectsFromOrg[0].referencedInGroups].sort(),
      [fx.mixed.name, fx.valid.name].sort()
    );
    fx.assertUntouched();
  });
});
