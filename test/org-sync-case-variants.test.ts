import './helpers/env.js';
// Covers org sync on a database from an older version, whose sf_objects can hold 'Account' and
// 'account' as separate rows: every decision reaches every variant, and none of them is merged.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { store } from '../src/db/store.js';
import {
  objectSyncNeedsReview,
  objectSyncRemovals,
  otherFieldVariants,
  otherObjectVariants,
  fieldResolutionKey,
  objectResolutionKey,
} from '../src/components/views/objectSyncReview.js';
import { adminFetch, loginAsAdmin, startTestServer, type AdminSession, type TestServer } from './helpers/server.js';

const uid = () => crypto.randomBytes(4).toString('hex');
const ORG = { orgId: '00D000000000001AAA', instanceUrl: 'https://acme.my.salesforce.com' };

let server: TestServer;
let session: AdminSession;

before(async () => {
  server = await startTestServer();
  session = await loginAsAdmin(server.baseUrl);
});

after(async () => {
  await server.close();
});

const present = (objectName: string, fieldNames: string[]) => ({
  objectName,
  label: objectName,
  isCustom: true,
  existsInOrg: true,
  fields: fieldNames.map((fieldName) => ({
    fieldName,
    label: fieldName,
    fieldType: 'Text',
    isCustom: fieldName.endsWith('__c'),
    required: false,
  })),
});
const gone = (objectName: string) => ({ objectName, label: objectName, isCustom: true, existsInOrg: false, fields: [] });

/** `upper` {Id, ...upperFields} and `lower` {Id, ...lowerFields}, as an older version could store them. */
function seedVariants(upperFields: string[], lowerFields: string[], allowedFields: string[]) {
  const upper = `Var_${uid()}__c`;
  const lower = upper.toLowerCase();
  store.upsertObjectWithFields({ objectName: upper, fields: ['Id', ...upperFields].map((fieldName) => ({ fieldName })) });
  store.upsertObjectWithFields({ objectName: lower, fields: ['Id', ...lowerFields].map((fieldName) => ({ fieldName })) });
  const group = store.upsertGroup({
    name: `Variant group ${uid()}`,
    allowedActions: ['soql_query'],
    objectPermissions: [
      { objectName: upper, canRead: true, canCreate: false, canUpdate: false, canDelete: false, allowedFields },
    ],
  });
  return { upper, lower, group };
}

const objectNamed = (objectName: string) => store.getObjects().find((o) => o.objectName === objectName);
const fieldNames = (objectName: string) => objectNamed(objectName)!.fields.map((f) => f.fieldName);
const fieldNamed = (objectName: string, fieldName: string) =>
  objectNamed(objectName)!.fields.find((f) => f.fieldName === fieldName)!;
const permissionsOf = (groupId: string) => store.getGroups().find((g) => g.id === groupId)!.objectPermissions;
const apply = (
  pulledMetadata: Array<ReturnType<typeof present> | ReturnType<typeof gone>>,
  removeObjectNames: string[] = [],
  removeFields: Array<{ objectName: string; fieldName: string }> = []
) => store.applyObjectsSyncFromOrg({ pulledMetadata, removeObjectNames, removeFields });

describe('a field the org removed', () => {
  test('held only by the first variant is previewed and removed, and its grant revoked', () => {
    const { upper, group } = seedVariants(['Gone__c'], [], ['Id', 'Gone__c']);

    const preview = store.previewObjectsSyncFromOrg([present(upper, ['Id'])], ORG);
    assert.deepEqual(
      preview.upsertedObjects[0].removedFieldsFromOrg.map((f) => [f.objectName, f.fieldName, f.referencedInGroups]),
      [[upper, 'Gone__c', [group.name]]]
    );

    const summary = apply([present(upper, ['Id'])], [], [{ objectName: upper, fieldName: 'Gone__c' }]);

    assert.deepEqual(fieldNames(upper), ['Id']);
    assert.deepEqual(permissionsOf(group.id)[0].allowedFields, ['Id']);
    assert.deepEqual(summary.affected.fieldsRemoved, [`${upper}.Gone__c`]);
    assert.deepEqual(summary.affected.groupsLosingGrants, [group.name]);
    assert.deepEqual(summary.affected.fieldsKeptMissing, []);
  });

  test('held only by the last variant is previewed and removed, whichever spelling the pull used', () => {
    const { upper, lower, group } = seedVariants([], ['Gone__c'], ['Id', 'Gone__c']);

    const preview = store.previewObjectsSyncFromOrg([present(upper, ['Id'])], ORG);
    assert.deepEqual(
      preview.upsertedObjects[0].removedFieldsFromOrg.map((f) => [f.objectName, f.fieldName]),
      [[lower, 'Gone__c']]
    );

    const summary = apply([present(upper, ['Id'])], [], [{ objectName: lower, fieldName: 'Gone__c' }]);

    assert.deepEqual(fieldNames(lower), ['Id']);
    assert.deepEqual(permissionsOf(group.id)[0].allowedFields, ['Id']);
    assert.deepEqual(summary.affected.fieldsRemoved, [`${lower}.Gone__c`]);
  });

  test('held by both variants is removed from both, and the grant goes with the last', () => {
    const { upper, lower, group } = seedVariants(['Gone__c'], ['Gone__c'], ['Id', 'Gone__c']);

    const summary = apply([present(upper, ['Id'])], [], [{ objectName: upper, fieldName: 'Gone__c' }]);

    assert.deepEqual(fieldNames(upper), ['Id']);
    assert.deepEqual(fieldNames(lower), ['Id']);
    assert.deepEqual(permissionsOf(group.id)[0].allowedFields, ['Id']);
    assert.deepEqual(summary.affected.fieldsRemoved.sort(), [`${upper}.Gone__c`, `${lower}.Gone__c`].sort());
    assert.deepEqual(summary.affected.groupsLosingGrants, [group.name]);
  });

  test('kept is flagged on every variant holding it, and only there', () => {
    const { upper, lower, group } = seedVariants(['Gone__c'], ['Other__c'], ['Id', 'Gone__c']);

    const summary = apply([present(upper, ['Id'])]);

    assert.equal(fieldNamed(upper, 'Gone__c').missingInOrg, true);
    assert.equal(fieldNamed(lower, 'Other__c').missingInOrg, true);
    assert.equal(fieldNamed(upper, 'Id').missingInOrg, false);
    assert.equal(fieldNamed(lower, 'Id').missingInOrg, false);
    assert.deepEqual(summary.affected.fieldsKeptMissing.sort(), [`${upper}.Gone__c`, `${lower}.Other__c`].sort());
    assert.deepEqual(permissionsOf(group.id)[0].allowedFields, ['Id', 'Gone__c']);
  });
});

describe('an object the org no longer has', () => {
  test('KEEP flags every variant and leaves its enabled state alone', () => {
    const { upper, lower, group } = seedVariants([], [], ['Id']);
    store.toggleObject(lower, false);

    const preview = store.previewObjectsSyncFromOrg([gone(upper)], ORG);
    assert.deepEqual(preview.removedObjectsFromOrg.map((o) => o.objectName).sort(), [upper, lower].sort());
    assert.ok(preview.removedObjectsFromOrg.every((o) => o.referencedInGroups.includes(group.name)));

    const summary = apply([gone(upper)]);

    assert.deepEqual(summary.affected.objectsKeptMissing.sort(), [upper, lower].sort());
    assert.deepEqual(summary.affected.objectsRemoved, []);
    assert.deepEqual(
      [upper, lower].map((n) => [objectNamed(n)!.missingInOrg, objectNamed(n)!.enabled]),
      [[true, true], [true, false]]
    );
    assert.equal(permissionsOf(group.id).length, 1);
  });

  test('remove deletes every variant, revokes the grant and reports both', () => {
    const { upper, lower, group } = seedVariants([], [], ['Id']);

    const summary = apply([gone(upper)], [upper]);

    assert.equal(objectNamed(upper), undefined);
    assert.equal(objectNamed(lower), undefined);
    // Revoked, but kept on the group as not available for an admin to review.
    assert.deepEqual(permissionsOf(group.id).map((p) => [p.objectName, Boolean(p.removed)]), [[upper, true]]);
    assert.deepEqual(summary.affected.objectsRemoved.sort(), [upper, lower].sort());
    assert.deepEqual(summary.affected.objectsKeptMissing, []);
    assert.deepEqual(summary.affected.groupsLosingGrants, [group.name]);
    assert.equal(summary.objectsRemoved, 2);
  });

  test('the audit row of an apply names every variant it changed', async () => {
    const removed = seedVariants([], [], ['Id']);
    const shrunk = seedVariants(['Gone__c'], ['Kept__c'], ['Id', 'Gone__c']);

    const res = await adminFetch(server.baseUrl, session, '/api/admin/objects/pull-apply', {
      method: 'POST',
      body: {
        pulledMetadata: [gone(removed.upper), present(shrunk.upper, ['Id'])],
        removeObjectNames: [removed.upper],
        removeFields: [{ objectName: shrunk.upper, fieldName: 'Gone__c' }],
      },
    });

    assert.equal(res.status, 200, JSON.stringify(res.body));
    const details = store.getPortalAdminLogs(1)[0].details;
    for (const name of [
      removed.upper,
      removed.lower,
      shrunk.upper,
      shrunk.lower,
      `${shrunk.upper}.Gone__c`,
      `${shrunk.lower}.Kept__c`,
      removed.group.name,
      shrunk.group.name,
    ]) {
      assert.ok(details.includes(name), `${name} is missing from: ${details}`);
    }
  });
});

describe('a present object with case variants', () => {
  test('clears the flags on every variant without merging or enabling anything', () => {
    const { upper, lower } = seedVariants(['Secret__c'], ['Secret__c'], ['Id']);
    apply([gone(upper)]);
    apply([present(upper, ['Id'])]);
    store.toggleObject(lower, false);
    store.toggleObjectField(upper, 'Secret__c', false);
    store.toggleObjectField(lower, 'Id', false);

    const summary = apply([present(upper, ['Id', 'Secret__c'])]);

    assert.deepEqual(summary.affected.objectsSynced.sort(), [upper, lower].sort());
    assert.equal(summary.fieldsUpserted, 4);
    assert.deepEqual(
      [upper, lower].map((n) => [objectNamed(n)!.enabled, objectNamed(n)!.missingInOrg]),
      [[true, false], [false, false]]
    );
    assert.deepEqual(
      [fieldNamed(upper, 'Secret__c'), fieldNamed(lower, 'Id')].map((f) => [f.enabled, f.missingInOrg]),
      [[false, false], [false, false]]
    );
    assert.equal(fieldNamed(lower, 'Secret__c').missingInOrg, false);
  });

  test('does not re-add a field a variant holds disabled onto the other variant as enabled', () => {
    const { upper, lower } = seedVariants([], ['Secret__c'], ['Id']);
    store.toggleObjectField(lower, 'Secret__c', false);

    const preview = store.previewObjectsSyncFromOrg([present(upper, ['Id', 'Secret__c'])], ORG);
    assert.deepEqual(preview.upsertedObjects[0].addedFields, []);

    apply([present(upper, ['Id', 'Secret__c'])]);

    assert.deepEqual(fieldNames(upper), ['Id']);
    assert.equal(fieldNamed(lower, 'Secret__c').enabled, false);
  });

  test('adds a field no variant has to one row only', () => {
    const { upper, lower } = seedVariants([], [], ['Id']);

    const preview = store.previewObjectsSyncFromOrg([present(lower, ['Id', 'Fresh__c'])], ORG);
    assert.deepEqual(preview.upsertedObjects[0].addedFields.map((f) => f.fieldName), ['Fresh__c']);

    apply([present(lower, ['Id', 'Fresh__c'])]);

    assert.deepEqual(fieldNames(lower), ['Fresh__c', 'Id']);
    assert.deepEqual(fieldNames(upper), ['Id']);
  });

  test('the preview names the variants it will update, with nothing to resolve', () => {
    const { upper, lower } = seedVariants([], [], ['Id']);

    const preview = store.previewObjectsSyncFromOrg([present(upper, ['Id'])], ORG);

    assert.deepEqual(preview.upsertedObjects[0].caseVariants.sort(), [upper, lower].sort());
    assert.equal(preview.upsertedObjects[0].isNewObject, false);
    assert.equal(objectSyncNeedsReview(preview), true);
  });
});

// The pull route asks about every tracked name, so a variant database reports the object twice.
describe('a pull that reports both spellings', () => {
  test('previews each removal once', () => {
    const { upper, lower } = seedVariants(['Gone__c'], [], ['Id', 'Gone__c']);
    const preview = store.previewObjectsSyncFromOrg([present(upper, ['Id']), present(lower, ['Id'])], ORG);

    assert.equal(preview.upsertedObjects.length, 1);
    assert.deepEqual(preview.upsertedObjects[0].removedFieldsFromOrg.map((f) => f.fieldName), ['Gone__c']);

    const goneObject = seedVariants([], [], ['Id']);
    const gonePreview = store.previewObjectsSyncFromOrg([gone(goneObject.upper), gone(goneObject.lower)], ORG);
    assert.equal(gonePreview.removedObjectsFromOrg.length, 2);
  });

  test('a field either entry reports stays, in the preview as in the apply', () => {
    const { upper, lower } = seedVariants(['Secret__c'], [], ['Id', 'Secret__c']);
    const pull = [present(upper, ['Id']), present(lower, ['Id', 'Secret__c'])];

    assert.deepEqual(store.previewObjectsSyncFromOrg(pull, ORG).upsertedObjects[0].removedFieldsFromOrg, []);
    apply(pull, [], [{ objectName: upper, fieldName: 'Secret__c' }]);
    assert.equal(fieldNamed(upper, 'Secret__c').missingInOrg, false);
  });

  test('reports each changed row once', () => {
    const { upper, lower } = seedVariants(['Gone__c'], [], ['Id', 'Gone__c']);

    const summary = apply([present(upper, ['Id']), present(lower, ['Id'])]);

    assert.deepEqual(summary.affected.objectsSynced.sort(), [upper, lower].sort());
    assert.deepEqual(summary.affected.fieldsKeptMissing, [`${upper}.Gone__c`]);

    const removed = seedVariants([], [], ['Id']);
    const removal = apply([gone(removed.upper), gone(removed.lower)], [removed.lower]);
    assert.deepEqual(removal.affected.objectsRemoved.sort(), [removed.upper, removed.lower].sort());
  });
});

describe('objects without a case variant', () => {
  test('report no variants and sync as one row', () => {
    const objectName = `Solo_${uid()}__c`;
    store.upsertObjectWithFields({ objectName, fields: [{ fieldName: 'Id' }] });

    const preview = store.previewObjectsSyncFromOrg([present(objectName, ['Id']), present('Brand_New__c', ['Id'])], ORG);

    assert.deepEqual(preview.upsertedObjects.map((o) => o.caseVariants), [[], []]);
    assert.equal(objectSyncNeedsReview(preview), false);
  });
});

describe('the portal review of variants', () => {
  const removedField = (objectName: string, fieldName: string) => ({
    objectName,
    fieldName,
    label: fieldName,
    fieldType: 'Text',
    enabled: true,
    referencedInGroups: [],
  });
  const preview = {
    ...ORG,
    upsertedObjects: [
      {
        objectName: 'Acct__c',
        label: 'Acct',
        isCustom: true,
        isNewObject: false,
        totalOrgFields: 1,
        addedFields: [],
        updatedFieldsCount: 1,
        removedFieldsFromOrg: [removedField('Acct__c', 'Gone__c'), removedField('acct__c', 'Gone__c'), removedField('acct__c', 'Solo__c')],
        caseVariants: ['Acct__c', 'acct__c'],
      },
    ],
    removedObjectsFromOrg: [
      { objectName: 'Old__c', label: 'Old', fieldCount: 1, referencedInGroups: [] },
      { objectName: 'old__c', label: 'Old', fieldCount: 1, referencedInGroups: [] },
      { objectName: 'Other__c', label: 'Other', fieldCount: 1, referencedInGroups: [] },
    ],
  };

  test('one decision covers every variant, so no row can show a Keep the apply would not honour', () => {
    const removals = objectSyncRemovals(
      preview,
      { [objectResolutionKey('old__c')]: 'DELETE', [objectResolutionKey('Other__c')]: 'KEEP_FLAGGED' },
      { [fieldResolutionKey('Acct__c', 'Gone__c')]: 'DELETE' }
    );

    assert.deepEqual(removals.removeObjectNames, ['Old__c', 'old__c']);
    assert.deepEqual(removals.removeFields, [
      { objectName: 'Acct__c', fieldName: 'Gone__c' },
      { objectName: 'acct__c', fieldName: 'Gone__c' },
    ]);
  });

  test('an unresolved removal is kept', () => {
    assert.deepEqual(objectSyncRemovals(preview, {}, {}), { removeObjectNames: [], removeFields: [] });
  });

  test('names the other rows a decision reaches', () => {
    assert.deepEqual(otherObjectVariants(preview, 'Old__c'), ['old__c']);
    assert.deepEqual(otherObjectVariants(preview, 'Other__c'), []);
    assert.deepEqual(otherFieldVariants(preview, { objectName: 'acct__c', fieldName: 'Gone__c' }), ['Acct__c.Gone__c']);
    assert.deepEqual(otherFieldVariants(preview, { objectName: 'acct__c', fieldName: 'Solo__c' }), []);
  });
});
