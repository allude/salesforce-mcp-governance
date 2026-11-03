import './helpers/env.js';
// Covers applying an org sync: all-or-nothing writes, what a payload may and may not change, and
// that both outcomes reach the Portal Admin Log.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { runInTransaction, store } from '../src/db/store.js';
import { adminFetch, loginAsAdmin, startTestServer, type AdminSession, type TestServer } from './helpers/server.js';

const uid = () => crypto.randomBytes(4).toString('hex');
const newObjectName = () => `Apply_${uid()}__c`;
const newProfileId = () => `00e${uid()}`;

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
const presentObject = (objectName: string, fieldNames: string[]) => ({
  objectName,
  label: objectName,
  isCustom: true,
  existsInOrg: true,
  fields: fieldNames.map(pulledField),
});
const goneObject = (objectName: string) => ({
  objectName,
  label: objectName,
  isCustom: true,
  existsInOrg: false,
  fields: [],
});

/** Everything an apply may write, timestamps included, so "unchanged" means unchanged. */
const snapshot = () =>
  JSON.stringify({
    objects: store.getObjects(),
    groups: store.getGroups(),
    profiles: store.getProfiles(),
    mappings: store.getProfileGroupMappings(),
  });

/** An object with a field, granted to a group. */
function seedGrantedObject() {
  const objectName = newObjectName();
  store.upsertObjectWithFields({
    objectName,
    fields: [{ fieldName: 'Id' }, { fieldName: 'Secret__c' }],
  });
  const group = store.upsertGroup({
    name: `Apply group ${uid()}`,
    allowedActions: ['soql_query'],
    objectPermissions: [
      { objectName, canRead: true, canCreate: false, canUpdate: false, canDelete: false, allowedFields: ['Id', 'Secret__c'] },
    ],
  });
  return { objectName, group };
}

/** Makes SQLite refuse one insert, a real failure part-way through an apply that passed validation. */
async function withInsertRefused(table: string, column: string, value: string, run: () => unknown | Promise<unknown>) {
  const raw = new DatabaseSync(process.env.DB_PATH as string);
  raw.exec(`
    CREATE TRIGGER refuse_insert BEFORE INSERT ON ${table} WHEN NEW.${column} = '${value}'
    BEGIN SELECT RAISE(ABORT, 'forced failure'); END
  `);
  try {
    await run();
  } finally {
    raw.exec('DROP TRIGGER refuse_insert');
    raw.close();
  }
}

describe('runInTransaction', () => {
  test('a nested call commits with the outer one', () => {
    const id = newProfileId();
    runInTransaction(() => {
      runInTransaction(() => store.upsertProfile(id, 'Nested'));
    });
    assert.equal(store.getProfileById(id)?.name, 'Nested');
  });

  test('an outer failure undoes a finished nested call', () => {
    const id = newProfileId();
    assert.throws(
      () =>
        runInTransaction(() => {
          runInTransaction(() => store.upsertProfile(id, 'Nested'));
          throw new Error('outer failed');
        }),
      /outer failed/
    );
    assert.equal(store.getProfileById(id), null);
  });

  test('a nested failure rolls back everything even when the outer step catches it', () => {
    const outerId = newProfileId();
    const innerId = newProfileId();
    assert.throws(
      () =>
        runInTransaction(() => {
          store.upsertProfile(outerId, 'Outer');
          try {
            runInTransaction(() => {
              store.upsertProfile(innerId, 'Inner');
              throw new Error('inner failed');
            });
          } catch {
            // Swallowed on purpose: the transaction must not commit half of the inner step.
          }
        }),
      /nested step failed/
    );
    assert.equal(store.getProfileById(outerId), null);
    assert.equal(store.getProfileById(innerId), null);
  });

  test('a later transaction works normally after a rollback', () => {
    const id = newProfileId();
    assert.throws(() => runInTransaction(() => { throw new Error('first failed'); }));
    runInTransaction(() => store.upsertProfile(id, 'After'));
    assert.equal(store.getProfileById(id)?.name, 'After');
  });
});

describe('applying an object sync in the store', () => {
  test('a failing entry undoes earlier upserts, deletions and revoked grants', () => {
    const gone = seedGrantedObject();
    const shrunk = seedGrantedObject();
    const brandNew = newObjectName();
    const before = snapshot();

    assert.throws(
      () =>
        store.applyObjectsSyncFromOrg({
          pulledMetadata: [
            goneObject(gone.objectName),
            presentObject(shrunk.objectName, ['Id']),
            presentObject(brandNew, ['Id']),
            presentObject('Not A Valid Name', ['Id']),
          ],
          removeObjectNames: [gone.objectName],
          removeFields: [{ objectName: shrunk.objectName, fieldName: 'Secret__c' }],
        }),
      /not a valid Salesforce object API name/
    );

    assert.equal(snapshot(), before);
    assert.ok(store.getObjects().some((o) => o.objectName === gone.objectName));
    assert.ok(!store.getObjects().some((o) => o.objectName === brandNew));
  });

  test('a database error part-way through also leaves everything as it was', async () => {
    const gone = seedGrantedObject();
    const blocked = newObjectName();
    const before = snapshot();

    await withInsertRefused('sf_objects', 'object_name', blocked, () => {
      assert.throws(
        () =>
          store.applyObjectsSyncFromOrg({
            pulledMetadata: [goneObject(gone.objectName), presentObject(blocked, ['Id'])],
            removeObjectNames: [gone.objectName],
            removeFields: [],
          }),
        /forced failure/
      );
    });

    assert.equal(snapshot(), before);
  });

  test('reports the affected names and the groups that lost grants', () => {
    const gone = seedGrantedObject();
    const shrunk = seedGrantedObject();
    const kept = seedGrantedObject();

    const summary = store.applyObjectsSyncFromOrg({
      pulledMetadata: [
        goneObject(gone.objectName),
        presentObject(shrunk.objectName, ['Id']),
        goneObject(kept.objectName),
      ],
      removeObjectNames: [gone.objectName],
      removeFields: [{ objectName: shrunk.objectName, fieldName: 'Secret__c' }],
    });

    assert.deepEqual(summary.affected.objectsRemoved, [gone.objectName]);
    assert.deepEqual(summary.affected.fieldsRemoved, [`${shrunk.objectName}.Secret__c`]);
    assert.deepEqual(summary.affected.objectsKeptMissing, [kept.objectName]);
    assert.deepEqual(summary.affected.objectsSynced, [shrunk.objectName]);
    assert.deepEqual(summary.affected.groupsLosingGrants.sort(), [gone.group.name, shrunk.group.name].sort());
    assert.equal(summary.objectsRemoved, 1);
    assert.equal(summary.fieldsRemoved, 1);
  });

  test('a field reported by either of two entries for one object is not removed', () => {
    const { objectName, group } = seedGrantedObject();

    store.applyObjectsSyncFromOrg({
      pulledMetadata: [presentObject(objectName, ['Id']), presentObject(objectName.toUpperCase(), ['Id', 'Secret__c'])],
      removeObjectNames: [],
      removeFields: [{ objectName, fieldName: 'Secret__c' }],
    });

    const secret = store.getObjects().find((o) => o.objectName === objectName)!.fields.find((f) => f.fieldName === 'Secret__c');
    assert.equal(secret?.missingInOrg, false);
    assert.deepEqual(store.getGroups().find((g) => g.id === group.id)!.objectPermissions[0].allowedFields, ['Id', 'Secret__c']);
  });
});

describe('applying a profile sync in the store', () => {
  test('a failing entry undoes earlier upserts and deletions', async () => {
    const removed = newProfileId();
    store.upsertProfile(removed, 'Removed');
    const group = store.upsertGroup({ name: `Apply group ${uid()}`, allowedActions: [], objectPermissions: [] });
    store.setProfileGroups(removed, [group.id]);
    const added = newProfileId();
    const blocked = newProfileId();
    const before = snapshot();

    await withInsertRefused('sf_profiles', 'id', blocked, () => {
      assert.throws(
        () =>
          store.applyProfilesSyncFromOrg({
            upserts: [{ id: added, name: 'Added' }, { id: blocked, name: 'Blocked' }],
            removeProfileIds: [removed],
          }),
        /forced failure/
      );
    });

    assert.equal(snapshot(), before);
  });

  test('a remove or keep entry for a profile the payload upserts is ignored', () => {
    const present = newProfileId();
    const flagged = newProfileId();
    store.upsertProfile(present, 'Present');
    store.upsertProfile(flagged, 'Flagged');

    const summary = store.applyProfilesSyncFromOrg({
      upserts: [{ id: present, name: 'Present' }, { id: flagged, name: 'Flagged' }],
      removeProfileIds: [present],
      keptMissingProfileIds: [flagged],
    });

    assert.equal(summary.removed, 0);
    assert.equal(summary.keptMissing, 0);
    assert.ok(store.getProfileById(present));
    assert.equal(store.getProfileById(flagged)?.missingInOrg, false);
  });

  test('reports the affected names and the groups that lost a member', () => {
    const removed = newProfileId();
    const kept = newProfileId();
    store.upsertProfile(removed, `Removed ${removed}`);
    store.upsertProfile(kept, `Kept ${kept}`);
    const group = store.upsertGroup({ name: `Apply group ${uid()}`, allowedActions: [], objectPermissions: [] });
    store.setProfileGroups(removed, [group.id]);

    const summary = store.applyProfilesSyncFromOrg({
      upserts: [],
      removeProfileIds: [removed],
      keptMissingProfileIds: [kept],
    });

    assert.deepEqual(summary.affected.removed, [`Removed ${removed}`]);
    assert.deepEqual(summary.affected.keptMissing, [`Kept ${kept}`]);
    assert.deepEqual(summary.affected.groupsLosingMembers, [group.name]);
  });
});

const applyObjects = (body: unknown) =>
  adminFetch(server.baseUrl, session, '/api/admin/objects/pull-apply', { method: 'POST', body });
const applyProfiles = (body: unknown) =>
  adminFetch(server.baseUrl, session, '/api/admin/profiles/pull-apply', { method: 'POST', body });
const latestLog = () => store.getPortalAdminLogs(1)[0];

describe('POST /objects/pull-apply validation', () => {
  const valid = presentObject('Valid_Object__c', ['Id']);
  const invalidPayloads: Array<[string, unknown, RegExp]> = [
    ['no pulledMetadata', {}, /pulledMetadata array is required/],
    ['pulledMetadata that is not an array', { pulledMetadata: 'x' }, /pulledMetadata array is required/],
    ['an entry that is not an object', { pulledMetadata: [valid, 'x'] }, /pulledMetadata\[1\] must be an object/],
    ['a non-string objectName', { pulledMetadata: [{ ...valid, objectName: 42 }] }, /objectName must be a non-empty string/],
    ['an objectName with SOQL in it', { pulledMetadata: [{ ...valid, objectName: 'Account WHERE 1=1' }] }, /not a valid Salesforce API name/],
    ['a missing existsInOrg', { pulledMetadata: [{ objectName: 'Valid_Object__c', fields: [] }] }, /existsInOrg must be true or false/],
    ['a non-boolean existsInOrg', { pulledMetadata: [{ ...valid, existsInOrg: 'false' }] }, /existsInOrg must be true or false/],
    ['missing fields', { pulledMetadata: [{ objectName: 'Valid_Object__c', existsInOrg: false }] }, /fields must be an array/],
    ['fields that are not an array', { pulledMetadata: [{ ...valid, fields: {} }] }, /fields must be an array/],
    ['a field that is not an object', { pulledMetadata: [{ ...valid, fields: [null] }] }, /fields\[0\] must be an object/],
    ['a non-string fieldName', { pulledMetadata: [{ ...valid, fields: [{ fieldName: 7 }] }] }, /fieldName must be a non-empty string/],
    ['a relationship path as fieldName', { pulledMetadata: [{ ...valid, fields: [{ fieldName: 'Owner.Email' }] }] }, /not a valid Salesforce API name/],
    ['a non-boolean field attribute', { pulledMetadata: [{ ...valid, fields: [{ fieldName: 'Id', required: 'yes' }] }] }, /required must be true or false/],
    ['a present object with no fields', { pulledMetadata: [{ ...valid, fields: [] }] }, /reported as present/],
    [
      'two entries that disagree about one object',
      { pulledMetadata: [valid, { ...goneObject('VALID_OBJECT__C') }] },
      /contradicts an earlier entry/,
    ],
    ['removeObjectNames that is not an array', { pulledMetadata: [valid], removeObjectNames: 'Account' }, /removeObjectNames must be an array/],
    ['a non-string remove name', { pulledMetadata: [valid], removeObjectNames: [{ toString: 1 }] }, /removeObjectNames\[0\] must be a non-empty string/],
    ['removeFields that is not an array', { pulledMetadata: [valid], removeFields: {} }, /removeFields must be an array/],
    ['a remove field without a fieldName', { pulledMetadata: [valid], removeFields: [{ objectName: 'A' }] }, /removeFields\[0\]\.fieldName/],
  ];

  for (const [name, payload, message] of invalidPayloads) {
    test(`rejects ${name}, changes nothing, and logs the failure`, async () => {
      const before = snapshot();
      const res = await applyObjects(payload);
      assert.equal(res.status, 400);
      assert.match(res.body.error, message);
      assert.equal(snapshot(), before);
      assert.equal(latestLog().action, 'SYNC_OBJECTS_FROM_ORG_FAILED');
      assert.match(latestLog().details, message);
    });
  }

  test('an invalid late entry stops the valid entries before it', async () => {
    const earlier = newObjectName();
    const res = await applyObjects({
      pulledMetadata: [presentObject(earlier, ['Id']), { objectName: 'Late__c', fields: [] }],
    });
    assert.equal(res.status, 400);
    assert.ok(!store.getObjects().some((o) => o.objectName === earlier));
  });

  test('a missing existsInOrg does not delete an object listed for removal', async () => {
    const { objectName } = seedGrantedObject();
    const res = await applyObjects({
      pulledMetadata: [{ objectName, fields: [] }],
      removeObjectNames: [objectName],
    });
    assert.equal(res.status, 400);
    assert.ok(store.getObjects().some((o) => o.objectName === objectName));
  });
});

describe('POST /objects/pull-apply effects', () => {
  test('a client-sent enabled or missingInOrg on a field is not applied', async () => {
    const { objectName } = seedGrantedObject();
    store.toggleObjectField(objectName, 'Secret__c', false);
    const fresh = `Fresh_${uid()}__c`;

    const res = await applyObjects({
      pulledMetadata: [
        {
          ...presentObject(objectName, []),
          fields: [
            { ...pulledField('Id'), missingInOrg: true },
            { ...pulledField('Secret__c'), enabled: true },
            { ...pulledField(fresh), enabled: false, objectName: 'Other__c' },
          ],
          enabled: false,
        },
      ],
    });

    assert.equal(res.status, 200, JSON.stringify(res.body));
    const stored = store.getObjects().find((o) => o.objectName === objectName)!;
    const field = (name: string) => stored.fields.find((f) => f.fieldName === name)!;
    assert.equal(stored.enabled, true);
    assert.equal(field('Secret__c').enabled, false);
    assert.equal(field('Id').missingInOrg, false);
    assert.equal(field(fresh).enabled, true);
    assert.ok(!store.getObjects().some((o) => o.objectName === 'Other__c'));
  });

  test('a remove entry never touches an item the payload says exists', async () => {
    const { objectName, group } = seedGrantedObject();
    const res = await applyObjects({
      pulledMetadata: [presentObject(objectName, ['Id', 'Secret__c'])],
      removeObjectNames: [objectName],
      removeFields: [{ objectName, fieldName: 'Secret__c' }],
    });

    assert.equal(res.status, 200, JSON.stringify(res.body));
    assert.equal(res.body.summary.objectsRemoved, 0);
    assert.equal(res.body.summary.fieldsRemoved, 0);
    const stored = store.getObjects().find((o) => o.objectName === objectName)!;
    assert.ok(stored.fields.some((f) => f.fieldName === 'Secret__c'));
    assert.deepEqual(store.getGroups().find((g) => g.id === group.id)!.objectPermissions[0].allowedFields, ['Id', 'Secret__c']);
  });

  test('a remove entry for a name the payload does not report does nothing', async () => {
    const { objectName } = seedGrantedObject();
    const res = await applyObjects({ pulledMetadata: [], removeObjectNames: [objectName] });
    assert.equal(res.status, 200);
    assert.ok(store.getObjects().some((o) => o.objectName === objectName));
  });

  test('a success logs the affected names, counts and groups', async () => {
    const gone = seedGrantedObject();
    const shrunk = seedGrantedObject();

    const res = await applyObjects({
      pulledMetadata: [goneObject(gone.objectName), presentObject(shrunk.objectName, ['Id'])],
      removeObjectNames: [gone.objectName],
      removeFields: [{ objectName: shrunk.objectName, fieldName: 'Secret__c' }],
    });

    assert.equal(res.status, 200, JSON.stringify(res.body));
    const log = latestLog();
    assert.equal(log.action, 'SYNC_OBJECTS_FROM_ORG');
    assert.match(log.details, /1 objects\/1 fields synced; 1 objects & 1 fields removed/);
    assert.ok(log.details.includes(`Removed objects: ${gone.objectName}.`), log.details);
    assert.ok(log.details.includes(`Removed fields: ${shrunk.objectName}.Secret__c.`), log.details);
    assert.ok(log.details.includes(gone.group.name), log.details);
    assert.ok(log.details.includes(shrunk.group.name), log.details);
  });

  test('a long list of synced names is capped in the log, not the count', async () => {
    const names = Array.from({ length: 60 }, newObjectName);
    const res = await applyObjects({ pulledMetadata: names.map((n) => presentObject(n, ['Id'])) });
    assert.equal(res.status, 200);
    assert.match(latestLog().details, /60 objects\/60 fields synced/);
    assert.match(latestLog().details, /and 10 more\./);
  });

  test('a failure part-way returns 500, changes nothing, and logs only the failure', async () => {
    const gone = seedGrantedObject();
    const blocked = newObjectName();
    const before = snapshot();
    const logsBefore = store.getPortalAdminLogs(1000).length;

    await withInsertRefused('sf_objects', 'object_name', blocked, async () => {
      const res = await applyObjects({
        pulledMetadata: [goneObject(gone.objectName), presentObject(blocked, ['Id'])],
        removeObjectNames: [gone.objectName],
      });
      assert.equal(res.status, 500);
      assert.match(res.body.error, /nothing was changed/);
      assert.doesNotMatch(res.body.error, /forced failure/);
    });

    assert.equal(snapshot(), before);
    assert.equal(store.getPortalAdminLogs(1000).length, logsBefore + 1);
    assert.equal(latestLog().action, 'SYNC_OBJECTS_FROM_ORG_FAILED');
    assert.match(latestLog().details, /forced failure/);
  });

  test('a success whose audit entry cannot be written is rolled back', async (t) => {
    const { objectName } = seedGrantedObject();
    const before = snapshot();
    const realRecord = store.recordPortalAdminLog;
    let calls = 0;
    t.mock.method(store, 'recordPortalAdminLog', function (this: typeof store, input: Parameters<typeof realRecord>[0]) {
      calls++;
      if (calls === 1) throw new Error('audit write failed');
      return realRecord.call(this, input);
    });

    const res = await applyObjects({
      pulledMetadata: [goneObject(objectName)],
      removeObjectNames: [objectName],
    });

    assert.equal(res.status, 500);
    assert.equal(snapshot(), before);
    assert.equal(latestLog().action, 'SYNC_OBJECTS_FROM_ORG_FAILED');
  });
});

describe('POST /profiles/pull-apply', () => {
  const invalidPayloads: Array<[string, unknown, RegExp]> = [
    ['no upserts', {}, /upserts array is required/],
    ['an upsert that is not an object', { upserts: ['x'] }, /upserts\[0\] must be an object/],
    ['a non-string id', { upserts: [{ id: 5, name: 'x' }] }, /upserts\[0\]\.id/],
    ['an empty name', { upserts: [{ id: '00e1', name: ' ' }] }, /upserts\[0\]\.name/],
    ['removeProfileIds that is not an array', { upserts: [], removeProfileIds: 'x' }, /removeProfileIds must be an array/],
    ['a non-string remove id', { upserts: [], removeProfileIds: [1] }, /removeProfileIds\[0\]/],
    ['a non-string keep id', { upserts: [], keptMissingProfileIds: [null] }, /keptMissingProfileIds\[0\]/],
  ];

  for (const [name, payload, message] of invalidPayloads) {
    test(`rejects ${name}, changes nothing, and logs the failure`, async () => {
      const before = snapshot();
      const res = await applyProfiles(payload);
      assert.equal(res.status, 400);
      assert.match(res.body.error, message);
      assert.equal(snapshot(), before);
      assert.equal(latestLog().action, 'SYNC_PROFILES_FROM_ORG_FAILED');
    });
  }

  test('an invalid late entry stops the valid entries before it', async () => {
    const earlier = newProfileId();
    const res = await applyProfiles({ upserts: [{ id: earlier, name: 'Earlier' }, { id: '', name: 'x' }] });
    assert.equal(res.status, 400);
    assert.equal(store.getProfileById(earlier), null);
  });

  test('only id and name are taken from an upsert', async () => {
    const id = newProfileId();
    store.upsertProfile(id, 'Before');
    const res = await applyProfiles({ upserts: [{ id, name: 'After', missingInOrg: true, userType: 'Standard' }] });
    assert.equal(res.status, 200);
    assert.equal(store.getProfileById(id)?.name, 'After');
    assert.equal(store.getProfileById(id)?.missingInOrg, false);
  });

  test('a remove entry for a profile the payload upserts does nothing', async () => {
    const id = newProfileId();
    store.upsertProfile(id, 'Present');
    const res = await applyProfiles({ upserts: [{ id, name: 'Present' }], removeProfileIds: [id] });
    assert.equal(res.status, 200);
    assert.equal(res.body.summary.removed, 0);
    assert.ok(store.getProfileById(id));
  });

  test('a success logs the affected names, counts and groups', async () => {
    const removed = newProfileId();
    store.upsertProfile(removed, `Removed ${removed}`);
    const group = store.upsertGroup({ name: `Apply group ${uid()}`, allowedActions: [], objectPermissions: [] });
    store.setProfileGroups(removed, [group.id]);

    const res = await applyProfiles({ upserts: [], removeProfileIds: [removed] });

    assert.equal(res.status, 200);
    const log = latestLog();
    assert.equal(log.action, 'SYNC_PROFILES_FROM_ORG');
    assert.match(log.details, /0 added, 0 updated, 1 removed/);
    assert.ok(log.details.includes(`Removed: Removed ${removed}.`), log.details);
    assert.ok(log.details.includes(group.name), log.details);
  });

  test('a failure part-way returns 500, changes nothing, and logs the failure', async () => {
    const removed = newProfileId();
    store.upsertProfile(removed, 'Removed');
    const blocked = newProfileId();
    const before = snapshot();

    await withInsertRefused('sf_profiles', 'id', blocked, async () => {
      const res = await applyProfiles({
        upserts: [{ id: blocked, name: 'Blocked' }],
        removeProfileIds: [removed],
      });
      assert.equal(res.status, 500);
      assert.match(res.body.error, /nothing was changed/);
    });

    assert.equal(snapshot(), before);
    assert.equal(latestLog().action, 'SYNC_PROFILES_FROM_ORG_FAILED');
    assert.match(latestLog().details, /forced failure/);
  });
});

describe('the body limit on POST /objects/pull-apply', () => {
  const url = () => `${server.baseUrl}/api/admin/objects/pull-apply`;

  /** Well over the general 1 MB limit, spread over many valid fields as a large org would be. */
  function largePayload(objectName: string) {
    const fields = Array.from({ length: 12000 }, (_, i) => ({
      ...pulledField(`Field_${i}__c`),
      label: `Label of a custom field number ${i} with a long name`,
    }));
    return JSON.stringify({ pulledMetadata: [{ ...presentObject(objectName, []), fields }] });
  }

  test('accepts a payload over 1 MB from an authenticated admin', async () => {
    const objectName = newObjectName();
    const body = largePayload(objectName);
    assert.ok(Buffer.byteLength(body) > 1024 * 1024);

    const res = await fetch(url(), {
      method: 'POST',
      headers: { Cookie: session.cookie, 'X-CSRF-Token': session.csrfToken, 'Content-Type': 'application/json' },
      body,
    });

    assert.equal(res.status, 200);
    assert.equal(store.getObjects().find((o) => o.objectName === objectName)?.fieldCount, 12000);
  });

  test('rejects a large payload without a session', async () => {
    const objectName = newObjectName();
    const res = await fetch(url(), {
      method: 'POST',
      headers: { 'X-CSRF-Token': session.csrfToken, 'Content-Type': 'application/json' },
      body: largePayload(objectName),
    });
    assert.equal(res.status, 401);
    assert.ok(!store.getObjects().some((o) => o.objectName === objectName));
  });

  test('rejects a large payload without the CSRF header', async () => {
    const objectName = newObjectName();
    const res = await fetch(url(), {
      method: 'POST',
      headers: { Cookie: session.cookie, 'Content-Type': 'application/json' },
      body: largePayload(objectName),
    });
    assert.equal(res.status, 403);
    assert.ok(!store.getObjects().some((o) => o.objectName === objectName));
  });

  test('the larger limit is bounded, and a body over it is audited as a failed apply', async () => {
    const before = snapshot();
    const res = await fetch(url(), {
      method: 'POST',
      headers: { Cookie: session.cookie, 'X-CSRF-Token': session.csrfToken, 'Content-Type': 'application/json' },
      body: JSON.stringify({ pulledMetadata: [], padding: 'x'.repeat(26 * 1024 * 1024) }),
    });
    assert.equal(res.status, 413);
    assert.equal(snapshot(), before);
    assert.equal(latestLog().action, 'SYNC_OBJECTS_FROM_ORG_FAILED');
    assert.match(latestLog().details, /larger than the 25mb limit/);
  });

  test('a body that is not JSON answers 400 and is audited as a failed apply', async () => {
    const res = await fetch(url(), {
      method: 'POST',
      headers: { Cookie: session.cookie, 'X-CSRF-Token': session.csrfToken, 'Content-Type': 'application/json' },
      body: '{not json',
    });
    assert.equal(res.status, 400);
    assert.equal(latestLog().action, 'SYNC_OBJECTS_FROM_ORG_FAILED');
    assert.match(latestLog().details, /could not be read as JSON/);
  });

  test('a large body elsewhere still meets the general limit', async () => {
    const res = await fetch(`${server.baseUrl}/api/admin/profiles/pull-apply`, {
      method: 'POST',
      headers: { Cookie: session.cookie, 'X-CSRF-Token': session.csrfToken, 'Content-Type': 'application/json' },
      body: largePayload(newObjectName()),
    });
    assert.equal(res.status, 413);
  });
});
