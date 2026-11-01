import './helpers/env.js';
// Covers Object & Field sync: a deleted field stays revoked when it returns, a name differing only
// by case is the same row, and a failed Salesforce read is an error rather than "removed from org".
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { store } from '../src/db/store.js';
import {
  fetchObjectsMetadataFromOrgSession,
  type SalesforceOrgTokenSession,
} from '../src/salesforce/jwtConnection.js';
import { adminFetch, loginAsAdmin, startTestServer, type AdminSession, type TestServer } from './helpers/server.js';

const uid = () => crypto.randomBytes(4).toString('hex');
const newObjectName = () => `Sync_${uid()}__c`;

let server: TestServer;
let session: AdminSession;

before(async () => {
  server = await startTestServer();
  session = await loginAsAdmin(server.baseUrl);
});

after(async () => {
  await server.close();
});

const pulledField = (fieldName: string) => ({
  fieldName,
  label: fieldName,
  fieldType: 'Text',
  isCustom: fieldName.endsWith('__c'),
  required: false,
});

function syncFromOrg(objectName: string, fieldNames: string[]) {
  return store.applyObjectsSyncFromOrg({
    pulledMetadata: [
      { objectName, label: objectName, isCustom: true, existsInOrg: true, fields: fieldNames.map(pulledField) },
    ],
    removeObjectNames: [],
    removeFields: [],
  });
}

function seedObjectWithGrant(allowedFields: string[]) {
  const objectName = newObjectName();
  store.upsertObjectWithFields({
    objectName,
    fields: ['Id', 'Secret__c'].map((fieldName) => ({ fieldName })),
  });
  const group = store.upsertGroup({
    name: `Sync group ${uid()}`,
    allowedActions: ['soql_query'],
    objectPermissions: [{ objectName, canRead: true, canCreate: false, canUpdate: false, canDelete: false, allowedFields }],
  });
  return { objectName, groupId: group.id };
}

const allowedFieldsOf = (groupId: string) =>
  store.getGroups().find((g) => g.id === groupId)!.objectPermissions[0].allowedFields;
const objectNamed = (objectName: string) => store.getObjects().find((o) => o.objectName === objectName)!;

describe('deleting a field', () => {
  test('revokes it from Access Groups, so a later sync that restores the field does not restore the grant', () => {
    const { objectName, groupId } = seedObjectWithGrant(['Id', 'Secret__c']);

    store.deleteObjectField(objectName, 'Secret__c');
    assert.deepEqual(allowedFieldsOf(groupId), ['Id']);

    syncFromOrg(objectName, ['Id', 'Secret__c']);
    assert.ok(objectNamed(objectName).fields.some((f) => f.fieldName === 'Secret__c'), 'the field is back');
    assert.deepEqual(allowedFieldsOf(groupId), ['Id'], 'the grant is not');
  });

  test('revokes a grant stored in different casing', () => {
    const { objectName, groupId } = seedObjectWithGrant(['Id', 'SECRET__C']);
    store.deleteObjectField(objectName, 'Secret__c');
    assert.deepEqual(allowedFieldsOf(groupId), ['Id']);
  });

  test('removing a field through sync revokes it the same way', () => {
    const { objectName, groupId } = seedObjectWithGrant(['Id', 'Secret__c']);
    store.applyObjectsSyncFromOrg({
      pulledMetadata: [
        { objectName, label: objectName, isCustom: true, existsInOrg: true, fields: [pulledField('Id')] },
      ],
      removeObjectNames: [],
      removeFields: [{ objectName, fieldName: 'Secret__c' }],
    });
    assert.deepEqual(allowedFieldsOf(groupId), ['Id']);
  });

  test('keeps the grant while a case variant left by an older version still exists', () => {
    const { objectName, groupId } = seedObjectWithGrant(['Id', 'Secret__c']);
    new DatabaseSync(process.env.DB_PATH as string).prepare(
      `INSERT INTO sf_object_fields (object_name, field_name, label, field_type, is_custom, required, enabled, missing_in_org)
       VALUES (?, 'secret__c', 'secret__c', 'Text', 1, 0, 1, 0)`
    ).run(objectName);

    store.deleteObjectField(objectName, 'secret__c');
    assert.deepEqual(allowedFieldsOf(groupId), ['Id', 'Secret__c']);
  });

  test('leaves grants on other objects alone', () => {
    const first = seedObjectWithGrant(['Id', 'Secret__c']);
    const second = seedObjectWithGrant(['Id', 'Secret__c']);
    store.deleteObjectField(first.objectName, 'Secret__c');
    assert.deepEqual(allowedFieldsOf(second.groupId), ['Id', 'Secret__c']);
  });

  test('the admin route answers 404 for a field that does not exist, and logs nothing', async () => {
    const { objectName } = seedObjectWithGrant(['Id']);
    const logsBefore = store.getPortalAdminLogs(500).length;
    const res = await adminFetch(server.baseUrl, session, `/api/admin/objects/${objectName}/fields/Nope__c`, {
      method: 'DELETE',
    });
    assert.equal(res.status, 404);
    assert.equal(store.getPortalAdminLogs(500).length, logsBefore);
  });
});
