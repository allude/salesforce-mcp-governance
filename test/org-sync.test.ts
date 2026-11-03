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
const fieldNamed = (objectName: string, fieldName: string) =>
  objectNamed(objectName).fields.find((f) => f.fieldName === fieldName)!;

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

describe('a sync whose names differ from the local row only by case', () => {
  test('does not re-enable a disabled object', () => {
    const objectName = newObjectName();
    store.upsertObjectWithFields({ objectName, fields: [{ fieldName: 'Id' }] });
    store.toggleObject(objectName, false);

    syncFromOrg(objectName.toUpperCase(), ['Id']);

    const rows = store.getObjects().filter((o) => o.objectName.toLowerCase() === objectName.toLowerCase());
    assert.deepEqual(rows.map((o) => [o.objectName, o.enabled]), [[objectName, false]]);
  });

  test('does not re-enable a disabled field or flag it as missing', () => {
    const objectName = newObjectName();
    store.upsertObjectWithFields({ objectName, fields: [{ fieldName: 'Id' }, { fieldName: 'Secret__c' }] });
    store.toggleObjectField(objectName, 'Secret__c', false);

    syncFromOrg(objectName, ['Id', 'SECRET__C']);

    const rows = objectNamed(objectName).fields.filter((f) => f.fieldName.toLowerCase() === 'secret__c');
    assert.deepEqual(rows.map((f) => [f.fieldName, f.enabled, f.missingInOrg]), [['Secret__c', false, false]]);
  });

  test('an SFDX re-import in different casing also updates the existing row', () => {
    const objectName = newObjectName();
    store.upsertObjectWithFields({ objectName, fields: [{ fieldName: 'Id' }] });
    store.toggleObject(objectName, false);

    store.importObjectsFromParsedSfdx([
      { objectName: objectName.toLowerCase(), label: 'x', isCustom: true, sourcePath: 'p', fields: [] },
    ] as any);

    const rows = store.getObjects().filter((o) => o.objectName.toLowerCase() === objectName.toLowerCase());
    assert.deepEqual(rows.map((o) => [o.objectName, o.enabled]), [[objectName, false]]);
  });

  test('adding the object by hand in different casing also updates the existing row', async () => {
    const objectName = newObjectName();
    store.upsertObjectWithFields({ objectName, fields: [{ fieldName: 'Id' }] });
    store.toggleObject(objectName, false);

    const res = await adminFetch(server.baseUrl, session, '/api/admin/objects', {
      method: 'POST',
      body: { objectName: objectName.toLowerCase(), fields: [{ fieldName: 'Id' }] },
    });

    assert.equal(res.status, 200);
    const rows = store.getObjects().filter((o) => o.objectName.toLowerCase() === objectName.toLowerCase());
    assert.deepEqual(rows.map((o) => [o.objectName, o.enabled]), [[objectName, false]]);
  });
});

describe('the missing-in-org flag outside org sync', () => {
  /** An object present in the org, with a local Legacy__c field the sync flagged and kept. */
  function seedFlaggedField() {
    const objectName = newObjectName();
    store.upsertObjectWithFields({ objectName, fields: [{ fieldName: 'Id' }, { fieldName: 'Legacy__c' }] });
    syncFromOrg(objectName, ['Id']);
    assert.equal(fieldNamed(objectName, 'Legacy__c').missingInOrg, true);
    return objectName;
  }

  /** An object the sync flagged as gone from the org and kept. */
  function seedFlaggedObject() {
    const objectName = newObjectName();
    store.upsertObjectWithFields({ objectName, fields: [{ fieldName: 'Id' }] });
    store.applyObjectsSyncFromOrg({
      pulledMetadata: [{ objectName, label: objectName, isCustom: true, existsInOrg: false, fields: [] }],
      removeObjectNames: [],
      removeFields: [],
    });
    assert.equal(objectNamed(objectName).missingInOrg, true);
    return objectName;
  }

  const sfdxImportOf = (objectName: string, fieldNames: string[]) => [
    {
      objectName,
      label: objectName,
      isCustom: true,
      sourcePath: 'force-app/main/default/objects',
      fields: fieldNames.map(pulledField),
    },
  ];

  const postObject = (body: Record<string, unknown>) =>
    adminFetch(server.baseUrl, session, '/api/admin/objects', { method: 'POST', body });

  test('an SFDX re-import keeps the flags while updating the rest of the row', () => {
    const fieldObject = seedFlaggedField();
    store.importObjectsFromParsedSfdx(sfdxImportOf(fieldObject, ['Id', 'Legacy__c']));
    assert.equal(fieldNamed(fieldObject, 'Legacy__c').missingInOrg, true);
    assert.equal(fieldNamed(fieldObject, 'Id').missingInOrg, false);
    assert.equal(objectNamed(fieldObject).sourcePath, 'force-app/main/default/objects');

    const flaggedObject = seedFlaggedObject();
    store.importObjectsFromParsedSfdx(sfdxImportOf(flaggedObject, ['Id']));
    assert.equal(objectNamed(flaggedObject).missingInOrg, true);
  });

  test('a manual object save keeps the flags', async () => {
    const fieldObject = seedFlaggedField();
    const saved = await postObject({ objectName: fieldObject, label: 'Renamed', fields: [{ fieldName: 'Legacy__c' }] });
    assert.equal(saved.status, 200);
    assert.equal(objectNamed(fieldObject).label, 'Renamed');
    assert.equal(fieldNamed(fieldObject, 'Legacy__c').missingInOrg, true);

    const flaggedObject = seedFlaggedObject();
    assert.equal((await postObject({ objectName: flaggedObject, label: 'Renamed' })).status, 200);
    assert.equal(objectNamed(flaggedObject).missingInOrg, true);
  });

  test('a manual object save cannot set or clear the flag from the request', async () => {
    const objectName = seedFlaggedField();
    const res = await postObject({
      objectName,
      fields: [
        { fieldName: 'Legacy__c', missingInOrg: false },
        { fieldName: 'Id', missingInOrg: true },
      ],
    });

    assert.equal(res.status, 200);
    assert.equal(fieldNamed(objectName, 'Legacy__c').missingInOrg, true);
    assert.equal(fieldNamed(objectName, 'Id').missingInOrg, false);
  });

  test('a save in different casing keeps the flag of the existing row', () => {
    const objectName = seedFlaggedField();
    store.upsertObjectWithFields({ objectName, fields: [{ fieldName: 'LEGACY__C' }] });
    assert.equal(fieldNamed(objectName, 'Legacy__c').missingInOrg, true);
  });

  test('new rows start unflagged', () => {
    const objectName = newObjectName();
    store.importObjectsFromParsedSfdx(sfdxImportOf(objectName, ['Id', 'Fresh__c']));
    assert.equal(objectNamed(objectName).missingInOrg, false);
    assert.ok(objectNamed(objectName).fields.every((f) => !f.missingInOrg));
  });

  test('keeping the flag leaves a manual enabled toggle alone, and an explicit one still applies', () => {
    const objectName = seedFlaggedField();
    store.toggleObjectField(objectName, 'Legacy__c', false);
    store.importObjectsFromParsedSfdx(sfdxImportOf(objectName, ['Legacy__c']));
    assert.equal(fieldNamed(objectName, 'Legacy__c').enabled, false);

    store.upsertObjectWithFields({ objectName, fields: [{ fieldName: 'Legacy__c', enabled: true }] });
    assert.equal(fieldNamed(objectName, 'Legacy__c').enabled, true);
    assert.equal(fieldNamed(objectName, 'Legacy__c').missingInOrg, true);
  });

  test('org sync clears the flags when the field or object reappears', () => {
    const fieldObject = seedFlaggedField();
    store.importObjectsFromParsedSfdx(sfdxImportOf(fieldObject, ['Legacy__c']));
    syncFromOrg(fieldObject, ['Id', 'Legacy__c']);
    assert.equal(fieldNamed(fieldObject, 'Legacy__c').missingInOrg, false);

    const flaggedObject = seedFlaggedObject();
    syncFromOrg(flaggedObject, ['Id']);
    assert.equal(objectNamed(flaggedObject).missingInOrg, false);
  });

  test('org sync flags a field again after it goes missing a second time', () => {
    const objectName = seedFlaggedField();
    syncFromOrg(objectName, ['Id', 'Legacy__c']);
    syncFromOrg(objectName, ['Id']);
    assert.equal(fieldNamed(objectName, 'Legacy__c').missingInOrg, true);
  });
});

describe('reading object metadata from Salesforce', () => {
  const orgSession: SalesforceOrgTokenSession = {
    authMode: 'jwt_bearer',
    instanceUrl: 'https://acme.my.salesforce.com',
    accessToken: 'test-token',
    apiVersion: 'v62.0',
    orgId: '00D000000000001',
  } as SalesforceOrgTokenSession;
  const OBJECT = 'Thing__c';

  type Reply = { status: number; body?: unknown };
  const json = (body: unknown): Reply => ({ status: 200, body });
  const denied: Reply = { status: 403, body: [{ errorCode: 'REQUEST_LIMIT_EXCEEDED' }] };
  const notFound: Reply = { status: 404, body: [{ errorCode: 'NOT_FOUND' }] };
  const definition = json({ done: true, records: [{ QualifiedApiName: OBJECT, Label: 'Thing' }] });
  const none = json({ done: true, records: [] });
  const fieldRow = (name: string) => ({ QualifiedApiName: name, Label: name, DataType: 'Text' });

  /** Stubs fetch with one reply per endpoint, chosen by what the URL asks for. */
  function stubSalesforce(
    t: { mock: { method: Function } },
    replies: { describe: Reply; entity?: Reply; fields?: Reply | Reply[] }
  ) {
    const fieldReplies = Array.isArray(replies.fields) ? [...replies.fields] : null;
    t.mock.method(globalThis, 'fetch', async (input: unknown) => {
      const url = decodeURIComponent(String(input));
      let reply: Reply | undefined;
      if (url.includes('/describe')) reply = replies.describe;
      else if (url.includes('FROM EntityDefinition')) reply = replies.entity;
      else if (url.includes('FROM FieldDefinition') || url.includes('/query/next')) {
        reply = fieldReplies ? fieldReplies.shift() : (replies.fields as Reply | undefined);
      }
      assert.ok(reply, `unexpected Salesforce call: ${url}`);
      return new Response(JSON.stringify(reply.body ?? {}), { status: reply.status });
    });
  }
  const read = () => fetchObjectsMetadataFromOrgSession(orgSession, [OBJECT]);

  for (const status of [400, 401, 429, 500, 503]) {
    test(`a ${status} from describe is an error, not a removed object`, async (t) => {
      stubSalesforce(t, { describe: { status, body: [{ errorCode: 'X' }] } });
      await assert.rejects(read(), new RegExp(`${OBJECT}.*${status}`));
    });
  }

  test('a failed EntityDefinition query is an error, not a removed object', async (t) => {
    stubSalesforce(t, { describe: notFound, entity: { status: 500 } });
    await assert.rejects(read(), /EntityDefinition.*500/);
  });

  test('a failed FieldDefinition query is an error, not an object with no fields', async (t) => {
    stubSalesforce(t, { describe: denied, entity: definition, fields: { status: 500 } });
    await assert.rejects(read(), /FieldDefinition.*500/);
  });

  test('an object that comes back with no fields is an error', async (t) => {
    stubSalesforce(t, { describe: json({ name: OBJECT, fields: [] }) });
    await assert.rejects(read(), /no fields/);
  });

  test('a FieldDefinition query with no rows is an error', async (t) => {
    stubSalesforce(t, { describe: notFound, entity: definition, fields: none });
    await assert.rejects(read(), /no fields/);
  });

  test('a 403 with no visible definition is an error: rate limits are 403s too', async (t) => {
    stubSalesforce(t, { describe: denied, entity: none });
    await assert.rejects(read(), /describe returned 403/);
  });

  test('a 404 confirmed by an empty EntityDefinition query is a removed object', async (t) => {
    stubSalesforce(t, { describe: notFound, entity: none });
    const [result] = await read();
    assert.equal(result.existsInOrg, false);
  });

  test('a user with no access to the object still gets its fields through the Tooling API', async (t) => {
    stubSalesforce(t, {
      describe: denied,
      entity: definition,
      fields: json({ done: true, records: [fieldRow('Id'), fieldRow('Secret__c')] }),
    });
    const [result] = await read();
    assert.equal(result.existsInOrg, true);
    assert.deepEqual(result.fields.map((f) => f.fieldName), ['Id', 'Secret__c']);
  });

  test('follows FieldDefinition result pages, so later fields are not reported as removed', async (t) => {
    stubSalesforce(t, {
      describe: notFound,
      entity: definition,
      fields: [
        json({ done: false, nextRecordsUrl: '/services/data/v62.0/tooling/query/next-1', records: [fieldRow('Id')] }),
        json({ done: true, records: [fieldRow('Secret__c')] }),
      ],
    });
    const [result] = await read();
    assert.deepEqual(result.fields.map((f) => f.fieldName), ['Id', 'Secret__c']);
  });

  test('a result page that cannot be followed is an error', async (t) => {
    stubSalesforce(t, {
      describe: notFound,
      entity: definition,
      fields: json({ done: false, nextRecordsUrl: 'https://evil.example/next', records: [fieldRow('Id')] }),
    });
    await assert.rejects(read(), /did not return all/);
  });

  test('a successful describe is returned as before', async (t) => {
    stubSalesforce(t, {
      describe: json({ name: OBJECT, label: 'Thing', custom: true, fields: [{ name: 'Id', label: 'Id', type: 'id' }] }),
    });
    const [result] = await read();
    assert.equal(result.existsInOrg, true);
    assert.deepEqual(result.fields.map((f) => f.fieldName), ['Id']);
  });
});
