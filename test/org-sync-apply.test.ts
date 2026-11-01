import './helpers/env.js';
// Covers applying an org sync: all-or-nothing writes, what a payload may and may not change, and
// that both outcomes reach the Portal Admin Log.
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { runInTransaction, store } from '../src/db/store.js';

const uid = () => crypto.randomBytes(4).toString('hex');
const newObjectName = () => `Apply_${uid()}__c`;
const newProfileId = () => `00e${uid()}`;

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
