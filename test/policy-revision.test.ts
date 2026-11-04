import { testTmpDir } from './helpers/env.js';
// The policy revision: one counter for everything an /mcp decision is made from. Each committed change
// to Profiles, Objects, fields, Access Groups or their memberships raises it by exactly one, whichever
// store function or route makes it and however many rows it touches. A write that changes nothing, a
// write to anything else, and a change that is rolled back leave it alone. It is kept in the database:
// 1 on a new database and on one upgraded to it, and the same after a restart, unless an older release
// changed the policy in between, which the restart counts as one revision. Boots are real child
// processes, as the revision is set up when the store loads.
import { after, before, describe, test, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';
import { MembershipChangeError, runInTransaction, store } from '../src/db/store.js';
import type { AccessGroup } from '../src/types/governance.js';
import {
  adminFetch,
  loginAsAdmin,
  mcpRequest,
  startTestServer,
  toolResultPayload,
  type AdminSession,
  type TestServer,
} from './helpers/server.js';
import { installSalesforceMock } from './helpers/salesforceMock.js';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const tag = () => crypto.randomBytes(4).toString('hex');
/** A new 15-character Profile ID. */
const newProfileId = () => `00eRv${crypto.randomBytes(5).toString('hex')}`;
const to18 = (id15: string) => `${id15}AAK`;

let server: TestServer;
let session: AdminSession;

before(async () => {
  server = await startTestServer();
  session = await loginAsAdmin(server.baseUrl);
});

after(async () => {
  await server.close();
});

const api = (urlPath: string, init: Parameters<typeof adminFetch>[3] = {}) =>
  adminFetch(server.baseUrl, session, urlPath, init);

/** How much `change` raised the policy revision. */
async function bumps(change: () => unknown): Promise<number> {
  const before = store.getPolicyRevision();
  await change();
  return store.getPolicyRevision() - before;
}

// ---------------------------------------------------------------------------------------------
// Fixtures. Each is removed after its test; creating them raises the revision, which no test counts.
// ---------------------------------------------------------------------------------------------
function newObject(t: TestContext, fields = ['Id', 'Name', 'Phone']): string {
  const objectName = `Rev_${tag()}__c`;
  store.upsertObjectWithFields({ objectName, fields: fields.map((fieldName) => ({ fieldName })) });
  t.after(() => store.deleteObject(objectName));
  return objectName;
}

const readGrant = (objectName: string, allowedFields = ['Id', 'Name']) => ({
  objectName,
  canRead: true,
  canCreate: false,
  canUpdate: false,
  canDelete: false,
  allowedFields,
});

function newGroup(t: TestContext, objectPermissions: ReturnType<typeof readGrant>[] = []): AccessGroup {
  const group = store.createGroup({ name: `Revision ${tag()}`, allowedActions: ['soql_query'], objectPermissions });
  t.after(() => store.deleteGroup(group.id));
  return group;
}

function newProfile(t: TestContext, groupIds: string[] = []): string {
  const id = newProfileId();
  store.upsertProfile(id, `Revision Profile ${tag()}`);
  if (groupIds.length > 0) store.setProfileGroups(id, groupIds);
  // Also the 18-character form, for a test that upgrades the stored ID.
  t.after(() => {
    store.deleteProfile(id);
    store.deleteProfile(to18(id));
  });
  return id;
}

/** A new Profile ID for a test that creates the Profile itself. */
function profileIdToCreate(t: TestContext): string {
  const id = newProfileId();
  t.after(() => store.deleteProfile(id));
  return id;
}

/** A new Object name for a test that creates the Object itself. */
function objectNameToCreate(t: TestContext): string {
  const objectName = `Rev_${tag()}__c`;
  t.after(() => store.deleteObject(objectName));
  return objectName;
}

const parsedObject = (objectName: string, label = 'Imported') => ({
  objectName,
  label,
  isCustom: true,
  sourcePath: `objects/${objectName}`,
  fields: [
    { fieldName: 'Id', label: 'Record ID', fieldType: 'Id', isCustom: false, required: true },
    { fieldName: 'Amount__c', label: 'Amount', fieldType: 'Currency', isCustom: true, required: false },
  ],
});

/** An SFDX objects folder on disk holding `objectNames`, each with one custom field. */
function sfdxFolder(t: TestContext, objectNames: string[]): string {
  const root = fs.mkdtempSync(path.join(testTmpDir, 'revision-sfdx-'));
  for (const objectName of objectNames) {
    const dir = path.join(root, objectName);
    fs.mkdirSync(path.join(dir, 'fields'), { recursive: true });
    fs.writeFileSync(path.join(dir, `${objectName}.object-meta.xml`), '<CustomObject><label>Disk</label></CustomObject>');
    fs.writeFileSync(
      path.join(dir, 'fields', 'Amount__c.field-meta.xml'),
      '<CustomField><fullName>Amount__c</fullName><label>Amount</label><type>Currency</type></CustomField>'
    );
  }
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return root;
}

const pulled = (objectName: string, fieldNames: string[]) => ({
  objectName,
  label: 'Pulled',
  isCustom: true,
  existsInOrg: true,
  fields: fieldNames.map((fieldName) => ({ fieldName, label: fieldName, fieldType: 'Text' })),
});

// =============================================================================================
// The store
// =============================================================================================
describe('every policy change raises the revision by exactly one', () => {
  const changes: Array<[string, (t: TestContext) => () => unknown]> = [
    [
      'createGroup',
      (t) => () => {
        const group = store.createGroup({ name: `Revision ${tag()}`, allowedActions: [], objectPermissions: [] });
        t.after(() => store.deleteGroup(group.id));
      },
    ],
    [
      'upsertGroup changing what the group grants',
      (t) => {
        const group = newGroup(t);
        return () => store.upsertGroup({ ...group, allowedActions: ['soql_query', 'get_record'] });
      },
    ],
    [
      'upsertGroup changing only the description, which is stored policy too',
      (t) => {
        const group = newGroup(t);
        return () => store.upsertGroup({ ...group, description: 'Now described' });
      },
    ],
    [
      'deleteGroup, with the memberships it cascades to',
      (t) => {
        const group = newGroup(t);
        newProfile(t, [group.id]);
        newProfile(t, [group.id]);
        return () => assert.equal(store.deleteGroup(group.id), true);
      },
    ],
    [
      'deleteObject, revoking it from the groups that grant it',
      (t) => {
        const objectName = newObject(t);
        newGroup(t, [readGrant(objectName)]);
        newGroup(t, [readGrant(objectName)]);
        return () => assert.equal(store.deleteObject(objectName), true);
      },
    ],
    [
      'deleteObjectField, revoking it from the groups that grant it',
      (t) => {
        const objectName = newObject(t);
        newGroup(t, [readGrant(objectName, ['Id', 'Phone'])]);
        newGroup(t, [readGrant(objectName, ['Phone'])]);
        return () => assert.ok(store.deleteObjectField(objectName, 'Phone'));
      },
    ],
    [
      'applyMembershipDelta',
      (t) => {
        const [kept, removed, added] = [newGroup(t), newGroup(t), newGroup(t)];
        const profileId = newProfile(t, [kept.id, removed.id]);
        return () => store.applyMembershipDelta(profileId, { add: [added.id], remove: [removed.id] });
      },
    ],
    [
      'applyGroupMembershipDelta',
      (t) => {
        const group = newGroup(t);
        const [first, second] = [newProfile(t), newProfile(t)];
        return () => store.applyGroupMembershipDelta(group.id, { add: [first, second], remove: [] });
      },
    ],
    [
      'setProfileGroups',
      (t) => {
        const [before, after] = [newGroup(t), newGroup(t)];
        const profileId = newProfile(t, [before.id]);
        return () => store.setProfileGroups(profileId, [after.id]);
      },
    ],
    [
      'upsertProfile adding a Profile',
      (t) => {
        const id = profileIdToCreate(t);
        return () => store.upsertProfile(id, 'Added Profile');
      },
    ],
    [
      'upsertProfile renaming a Profile',
      (t) => {
        const id = newProfile(t);
        return () => store.upsertProfile(id, `Renamed ${tag()}`);
      },
    ],
    [
      'upsertProfile upgrading a stored 15-character ID to 18, moving its memberships',
      (t) => {
        const group = newGroup(t);
        const id = newProfile(t, [group.id]);
        const { name } = store.getProfileById(id)!;
        return () => assert.equal(store.upsertProfile(to18(id), name).previousId, id);
      },
    ],
    [
      'deleteProfile, with the memberships it cascades to',
      (t) => {
        const id = newProfile(t, [newGroup(t).id, newGroup(t).id]);
        return () => assert.equal(store.deleteProfile(id), true);
      },
    ],
    [
      'importProfilesFromCsvRows of several rows',
      (t) => {
        const renamed = newProfile(t);
        const [first, second] = [profileIdToCreate(t), profileIdToCreate(t)];
        return () =>
          store.importProfilesFromCsvRows([
            { id: first, name: 'CSV One' },
            { id: second, name: 'CSV Two' },
            { id: renamed, name: `CSV Renamed ${tag()}` },
          ]);
      },
    ],
    [
      'applyProfilesSyncFromOrg adding, renaming, removing and keeping Profiles',
      (t) => {
        const group = newGroup(t);
        const [renamed, removed, kept] = [newProfile(t, [group.id]), newProfile(t, [group.id]), newProfile(t)];
        const added = profileIdToCreate(t);
        return () =>
          store.applyProfilesSyncFromOrg({
            upserts: [
              { id: renamed, name: `Synced ${tag()}` },
              { id: added, name: 'Synced New' },
            ],
            removeProfileIds: [removed],
            keptMissingProfileIds: [kept],
          });
      },
    ],
    [
      'upsertObjectWithFields adding an Object and its fields',
      (t) => {
        const objectName = objectNameToCreate(t);
        return () => store.upsertObjectWithFields({ objectName, fields: [{ fieldName: 'Id' }, { fieldName: 'Name' }] });
      },
    ],
    [
      'upsertObjectWithFields disabling a field and adding one',
      (t) => {
        const objectName = newObject(t);
        return () =>
          store.upsertObjectWithFields({
            objectName,
            fields: [{ fieldName: 'Phone', enabled: false }, { fieldName: 'Email' }],
          });
      },
    ],
    [
      'toggleObject',
      (t) => {
        const objectName = newObject(t);
        return () => store.toggleObject(objectName, false);
      },
    ],
    [
      'toggleObjectField',
      (t) => {
        const objectName = newObject(t);
        return () => store.toggleObjectField(objectName, 'Phone', false);
      },
    ],
    [
      'importObjectsFromParsedSfdx of several Objects',
      (t) => {
        const [first, second] = [objectNameToCreate(t), objectNameToCreate(t)];
        return () => store.importObjectsFromParsedSfdx([parsedObject(first), parsedObject(second)]);
      },
    ],
    [
      'importObjectsFromLocalDiskFolder of several Objects',
      (t) => {
        const [first, second] = [objectNameToCreate(t), objectNameToCreate(t)];
        const folder = sfdxFolder(t, [first, second]);
        return () => assert.equal(store.importObjectsFromLocalDiskFolder(folder).objectsImported, 2);
      },
    ],
    [
      'applyObjectsSyncFromOrg adding a field, removing a field and an Object, and keeping one missing',
      (t) => {
        const synced = newObject(t);
        const removed = newObject(t);
        const kept = newObject(t);
        newGroup(t, [readGrant(synced, ['Id', 'Phone']), readGrant(removed)]);
        return () =>
          store.applyObjectsSyncFromOrg({
            pulledMetadata: [
              pulled(synced, ['Id', 'Name', 'Website']),
              { ...pulled(removed, []), existsInOrg: false },
              { ...pulled(kept, []), existsInOrg: false },
            ],
            removeObjectNames: [removed],
            removeFields: [{ objectName: synced, fieldName: 'Phone' }],
          });
      },
    ],
    [
      'several store changes in one runInTransaction',
      (t) => {
        const objectName = newObject(t);
        const profileId = profileIdToCreate(t);
        return () =>
          runInTransaction(() => {
            const group = store.createGroup({ name: `Revision ${tag()}`, allowedActions: [], objectPermissions: [] });
            t.after(() => store.deleteGroup(group.id));
            store.upsertProfile(profileId, 'One revision');
            store.applyMembershipDelta(profileId, { add: [group.id], remove: [] });
            store.toggleObject(objectName, false);
          });
      },
    ],
  ];

  for (const [name, arrange] of changes) {
    test(name, async (t) => {
      const change = arrange(t);
      assert.equal(await bumps(change), 1);
    });
  }

  test('getPolicyRevision inside the transaction already counts its change', (t) => {
    const before = store.getPolicyRevision();
    const objectName = newObject(t);
    const seen = runInTransaction(() => {
      store.toggleObject(objectName, false);
      return store.getPolicyRevision();
    });
    assert.equal(seen, store.getPolicyRevision());
    assert.ok(seen > before);
  });
});

describe('a write that changes nothing leaves the revision alone', () => {
  const noOps: Array<[string, (t: TestContext) => () => unknown]> = [
    [
      'applyMembershipDelta with an empty delta',
      (t) => {
        const profileId = newProfile(t, [newGroup(t).id]);
        return () => store.applyMembershipDelta(profileId, { add: [], remove: [] });
      },
    ],
    [
      'applyMembershipDelta adding a group the Profile has and removing one it does not',
      (t) => {
        const [member, other] = [newGroup(t), newGroup(t)];
        const profileId = newProfile(t, [member.id]);
        return () => {
          const change = store.applyMembershipDelta(profileId, { add: [member.id], remove: [other.id] });
          assert.deepEqual([change.added, change.removed], [[], []]);
        };
      },
    ],
    [
      'applyGroupMembershipDelta removing a Profile that is not a member',
      (t) => {
        const group = newGroup(t);
        const profileId = newProfile(t);
        return () => store.applyGroupMembershipDelta(group.id, { add: [], remove: [profileId] });
      },
    ],
    [
      'setProfileGroups with the groups the Profile has',
      (t) => {
        const groups = [newGroup(t), newGroup(t)];
        const profileId = newProfile(t, groups.map((g) => g.id));
        return () => store.setProfileGroups(profileId, [groups[1].id, groups[0].id]);
      },
    ],
    [
      'toggleObject to the value it has',
      (t) => {
        const objectName = newObject(t);
        return () => assert.ok(store.toggleObject(objectName, true));
      },
    ],
    [
      'toggleObjectField to the value it has',
      (t) => {
        const objectName = newObject(t);
        store.toggleObjectField(objectName, 'Phone', false);
        return () => assert.ok(store.toggleObjectField(objectName, 'Phone', false));
      },
    ],
    [
      'upsertGroup saving the group as it is, which still gives it a new version',
      (t) => {
        const group = newGroup(t, [readGrant(newObject(t))]);
        return () => assert.equal(store.upsertGroup(group).version, group.version + 1);
      },
    ],
    [
      'upsertProfile with the name it has',
      (t) => {
        const id = newProfile(t);
        const { name } = store.getProfileById(id)!;
        return () => assert.equal(store.upsertProfile(id, name).action, 'updated');
      },
    ],
    [
      'importProfilesFromCsvRows of rows stored as they are',
      (t) => {
        const ids = [newProfile(t), newProfile(t)];
        const rows = ids.map((id) => ({ id, name: store.getProfileById(id)!.name }));
        return () => store.importProfilesFromCsvRows(rows);
      },
    ],
    [
      'applyProfilesSyncFromOrg with nothing to apply',
      () => () => store.applyProfilesSyncFromOrg({ upserts: [], removeProfileIds: [], keptMissingProfileIds: [] }),
    ],
    [
      'upsertObjectWithFields saving an Object as it is',
      (t) => {
        const objectName = objectNameToCreate(t);
        const input = { objectName, label: 'Same', fields: [{ fieldName: 'Id' }, { fieldName: 'Name', enabled: false }] };
        store.upsertObjectWithFields(input);
        return () => store.upsertObjectWithFields(input);
      },
    ],
    [
      'importObjectsFromParsedSfdx of Objects stored as they are',
      (t) => {
        const parsed = [parsedObject(objectNameToCreate(t)), parsedObject(objectNameToCreate(t))];
        store.importObjectsFromParsedSfdx(parsed);
        return () => store.importObjectsFromParsedSfdx(parsed);
      },
    ],
    [
      'applyObjectsSyncFromOrg of an Object stored as the org has it',
      (t) => {
        const objectName = newObject(t);
        const input = { pulledMetadata: [pulled(objectName, ['Id', 'Name', 'Phone'])], removeObjectNames: [], removeFields: [] };
        store.applyObjectsSyncFromOrg(input);
        return () => store.applyObjectsSyncFromOrg(input);
      },
    ],
    [
      'deleting a Profile, group, Object or field that does not exist',
      (t) => {
        const objectName = newObject(t);
        return () => {
          assert.equal(store.deleteProfile(newProfileId()), false);
          assert.equal(store.deleteGroup(`grp_missing_${tag()}`), false);
          assert.equal(store.deleteObject(`Missing_${tag()}__c`), false);
          assert.equal(store.deleteObjectField(objectName, 'Missing__c'), null);
          assert.equal(store.toggleObject(`Missing_${tag()}__c`, false), null);
        };
      },
    ],
  ];

  for (const [name, arrange] of noOps) {
    test(name, async (t) => {
      const change = arrange(t);
      assert.equal(await bumps(change), 0);
    });
  }
});

describe('a change that is rolled back leaves the revision alone', () => {
  test('a transaction that fails after changing a group', async () => {
    const name = `Rolled back ${tag()}`;
    const delta = await bumps(() =>
      assert.throws(
        () =>
          runInTransaction(() => {
            store.createGroup({ name, allowedActions: ['soql_query'], objectPermissions: [] });
            throw new Error('boom');
          }),
        /boom/
      )
    );
    assert.equal(delta, 0);
    assert.ok(!store.getGroups().some((g) => g.name === name));
  });

  test('a nested step that fails, even when the outer step catches it', async (t) => {
    const objectName = newObject(t);
    const profileId = newProfile(t);
    const delta = await bumps(() =>
      assert.throws(
        () =>
          runInTransaction(() => {
            store.toggleObject(objectName, false);
            try {
              store.applyMembershipDelta(profileId, { add: [`grp_missing_${tag()}`], remove: [] });
            } catch (err) {
              assert.ok(err instanceof MembershipChangeError);
            }
          }),
        /a nested step failed/
      )
    );
    assert.equal(delta, 0);
    assert.equal(store.getObjects().find((o) => o.objectName === objectName)?.enabled, true);
  });

  test('an import with one invalid Object saves none of them', async (t) => {
    const valid = objectNameToCreate(t);
    const delta = await bumps(() =>
      assert.throws(() => store.importObjectsFromParsedSfdx([parsedObject(valid), parsedObject('1nvalid')]), /not a valid/)
    );
    assert.equal(delta, 0);
    assert.ok(!store.getObjects().some((o) => o.objectName === valid));
  });
});

describe('writes outside the policy leave the revision alone', () => {
  const writes: Array<[string, () => unknown]> = [
    [
      'the Copilot MCP and Portal Admin logs',
      () => {
        store.recordCopilotMcpLog({
          sfUsername: 'revision@acme.example.com',
          profileId: newProfileId(),
          profileName: 'Revision',
          matchedGroups: [],
          toolName: 'soql_query',
          targetObject: 'Account',
          status: 'DENIED',
          latencyMs: 1,
          rawRequestPayload: {},
          rawResponseSummary: {},
        });
        store.recordPortalAdminLog({
          adminUsername: 'revision',
          authMethod: 'password',
          action: 'REVISION_TEST',
          target: 'Revision tests',
          details: 'A row written by the revision tests.',
        });
      },
    ],
    ['Okta settings', () => store.updateOktaConfig({ adminGroup: `Revision-${tag()}` })],
    [
      'portal users and their sign-in',
      () => {
        const username = `revision.${tag()}`;
        const password = `revision-${tag()}-${tag()}`;
        store.upsertPortalUser({ username, password });
        assert.ok(store.verifyPortalUserCredentials(username, password));
        assert.equal(store.deletePortalUser(username), true);
      },
    ],
    [
      'Salesforce connection settings, including the Org ID lock',
      () => {
        store.updateSalesforceSettings({ expectedOrgId: '00D000000000001AAA', enforceOrgIdLock: true });
        store.updateSalesforceSettings({ expectedOrgId: '', enforceOrgIdLock: false });
      },
    ],
  ];

  for (const [name, write] of writes) {
    test(name, async () => {
      assert.equal(await bumps(write), 0);
    });
  }
});

// =============================================================================================
// The Admin API
// =============================================================================================
describe('GET /api/admin/overview', () => {
  test('returns the policy revision, which a change raises', async (t) => {
    const first = await api('/api/admin/overview');
    assert.equal(first.status, 200);
    assert.equal(first.body.policyRevision, store.getPolicyRevision());

    const created = await api('/api/admin/groups', {
      method: 'POST',
      body: { name: `Overview ${tag()}`, allowedActions: ['soql_query'] },
    });
    assert.equal(created.status, 200, JSON.stringify(created.body));
    t.after(() => store.deleteGroup(created.body.group.id));

    const second = await api('/api/admin/overview');
    assert.equal(second.body.policyRevision, first.body.policyRevision + 1);
  });
});

describe('every Admin API change to the policy is one revision', () => {
  type Call = { method: string; path: string; body?: unknown };
  const routes: Array<[string, (t: TestContext) => Call]> = [
    ['POST /groups creating a group', (t) => {
      const name = `Route ${tag()}`;
      t.after(() => {
        for (const g of store.getGroups().filter((group) => group.name === name)) store.deleteGroup(g.id);
      });
      return { method: 'POST', path: '/api/admin/groups', body: { name, allowedActions: ['soql_query'] } };
    }],
    ['POST /groups updating a group', (t) => {
      const objectName = newObject(t);
      const group = newGroup(t);
      return {
        method: 'POST',
        path: '/api/admin/groups',
        body: { ...group, expectedVersion: group.version, objectPermissions: [readGrant(objectName)] },
      };
    }],
    ['DELETE /groups/:id, with its memberships', (t) => {
      const group = newGroup(t);
      newProfile(t, [group.id]);
      return { method: 'DELETE', path: `/api/admin/groups/${group.id}` };
    }],
    ['PUT /profile-groups/:profileId with a delta', (t) => {
      const [removed, added] = [newGroup(t), newGroup(t)];
      const profileId = newProfile(t, [removed.id]);
      return { method: 'PUT', path: `/api/admin/profile-groups/${profileId}`, body: { add: [added.id], remove: [removed.id] } };
    }],
    ['PUT /profile-groups/:profileId with a full replacement', (t) => {
      const [removed, added] = [newGroup(t), newGroup(t)];
      const profileId = newProfile(t, [removed.id]);
      return {
        method: 'PUT',
        path: `/api/admin/profile-groups/${profileId}`,
        body: { groupIds: [added.id], expectedGroupIds: [removed.id] },
      };
    }],
    ['POST /groups/:id/profiles', (t) => {
      const group = newGroup(t);
      const [first, second] = [newProfile(t), newProfile(t)];
      return { method: 'POST', path: `/api/admin/groups/${group.id}/profiles`, body: { add: [first, second] } };
    }],
    ['POST /profiles creating a Profile', (t) => ({
      method: 'POST',
      path: '/api/admin/profiles',
      body: { id: profileIdToCreate(t), name: 'Route Profile', creating: true },
    })],
    ['POST /profiles renaming a Profile', (t) => ({
      method: 'POST',
      path: '/api/admin/profiles',
      body: { id: newProfile(t), name: `Route Renamed ${tag()}` },
    })],
    ['POST /profiles/import-csv', (t) => ({
      method: 'POST',
      path: '/api/admin/profiles/import-csv',
      body: { rows: [{ id: profileIdToCreate(t), name: 'CSV A' }, { id: profileIdToCreate(t), name: 'CSV B' }] },
    })],
    ['DELETE /profiles/:id, with its memberships', (t) => {
      const profileId = newProfile(t, [newGroup(t).id, newGroup(t).id]);
      return { method: 'DELETE', path: `/api/admin/profiles/${profileId}` };
    }],
    ['POST /profiles/pull-apply', (t) => {
      const removed = newProfile(t, [newGroup(t).id]);
      return {
        method: 'POST',
        path: '/api/admin/profiles/pull-apply',
        body: { upserts: [{ id: profileIdToCreate(t), name: 'Pulled' }], removeProfileIds: [removed] },
      };
    }],
    ['POST /objects', (t) => ({
      method: 'POST',
      path: '/api/admin/objects',
      body: { objectName: objectNameToCreate(t), fields: [{ fieldName: 'Id' }, { fieldName: 'Name' }] },
    })],
    ['POST /objects/import-sfdx-files', (t) => {
      const [first, second] = [objectNameToCreate(t), objectNameToCreate(t)];
      return {
        method: 'POST',
        path: '/api/admin/objects/import-sfdx-files',
        body: {
          files: [first, second].flatMap((objectName) => [
            { relativePath: `objects/${objectName}/${objectName}.object-meta.xml`, content: '<CustomObject><label>Up</label></CustomObject>' },
            {
              relativePath: `objects/${objectName}/fields/Amount__c.field-meta.xml`,
              content: '<CustomField><fullName>Amount__c</fullName><label>Amount</label><type>Currency</type></CustomField>',
            },
          ]),
        },
      };
    }],
    ['POST /objects/import-local-folder', (t) => ({
      method: 'POST',
      path: '/api/admin/objects/import-local-folder',
      body: { folderPath: sfdxFolder(t, [objectNameToCreate(t), objectNameToCreate(t)]) },
    })],
    ['PUT /objects/:objectName/toggle', (t) => ({
      method: 'PUT',
      path: `/api/admin/objects/${newObject(t)}/toggle`,
      body: { enabled: false },
    })],
    ['PUT /objects/:objectName/fields/:fieldName/toggle', (t) => ({
      method: 'PUT',
      path: `/api/admin/objects/${newObject(t)}/fields/Phone/toggle`,
      body: { enabled: false },
    })],
    ['PUT /objects/:objectName/fields/bulk, toggling every field', (t) => ({
      method: 'PUT',
      path: `/api/admin/objects/${newObject(t)}/fields/bulk`,
      body: { enabled: false },
    })],
    ['DELETE /objects/:objectName/fields/:fieldName, revoking it', (t) => {
      const objectName = newObject(t);
      newGroup(t, [readGrant(objectName, ['Phone'])]);
      return { method: 'DELETE', path: `/api/admin/objects/${objectName}/fields/Phone` };
    }],
    ['DELETE /objects/:objectName, revoking it', (t) => {
      const objectName = newObject(t);
      newGroup(t, [readGrant(objectName)]);
      return { method: 'DELETE', path: `/api/admin/objects/${objectName}` };
    }],
    ['POST /objects/pull-apply', (t) => {
      const synced = newObject(t);
      const removed = newObject(t);
      return {
        method: 'POST',
        path: '/api/admin/objects/pull-apply',
        body: {
          pulledMetadata: [pulled(synced, ['Id', 'Website']), { ...pulled(removed, []), existsInOrg: false }],
          removeObjectNames: [removed],
          removeFields: [{ objectName: synced, fieldName: 'Phone' }],
        },
      };
    }],
  ];

  for (const [name, arrange] of routes) {
    test(name, async (t) => {
      const call = arrange(t);
      let status = 0;
      const delta = await bumps(async () => {
        const res = await api(call.path, { method: call.method, body: call.body });
        status = res.status;
        assert.equal(res.status, 200, JSON.stringify(res.body));
      });
      assert.equal(status, 200);
      assert.equal(delta, 1);
    });
  }

  test('POST /workspace/seed-sample is one revision, and loading it again none', async (t) => {
    // The sample keeps only grants for Objects in the catalog.
    const objects = ['Account', 'Contact', 'Opportunity', 'Case', 'Lead'];
    for (const objectName of objects.filter((name) => !store.getObjects().some((o) => o.objectName === name))) {
      store.upsertObjectWithFields({ objectName, fields: [{ fieldName: 'Id' }, { fieldName: 'Name' }] });
      t.after(() => store.deleteObject(objectName));
    }
    const seed = () => api('/api/admin/workspace/seed-sample', { method: 'POST', body: {} });
    assert.equal(await bumps(async () => assert.equal((await seed()).status, 200)), 1);
    assert.equal(await bumps(async () => assert.equal((await seed()).status, 200)), 0);
  });
});

describe('an Admin API request that changes nothing is no revision', () => {
  const routes: Array<[string, (t: TestContext) => { method: string; path: string; body?: unknown }]> = [
    ['PUT /profile-groups/:profileId with an empty delta', (t) => ({
      method: 'PUT',
      path: `/api/admin/profile-groups/${newProfile(t, [newGroup(t).id])}`,
      body: { add: [] },
    })],
    ['POST /groups/:id/profiles removing a Profile that is not a member', (t) => ({
      method: 'POST',
      path: `/api/admin/groups/${newGroup(t).id}/profiles`,
      body: { remove: [newProfile(t)] },
    })],
    ['PUT /objects/:objectName/toggle to the value it has', (t) => ({
      method: 'PUT',
      path: `/api/admin/objects/${newObject(t)}/toggle`,
      body: { enabled: true },
    })],
    ['PUT /objects/:objectName/fields/bulk to the values they have', (t) => ({
      method: 'PUT',
      path: `/api/admin/objects/${newObject(t)}/fields/bulk`,
      body: { enabled: true },
    })],
  ];

  for (const [name, arrange] of routes) {
    test(name, async (t) => {
      const call = arrange(t);
      const delta = await bumps(async () => {
        const res = await api(call.path, { method: call.method, body: call.body });
        assert.equal(res.status, 200, JSON.stringify(res.body));
      });
      assert.equal(delta, 0);
    });
  }
});

describe('an Admin API change whose audit row cannot be written is no revision', () => {
  /** Makes the next Portal Admin log write throw, as a full disk or a locked database would. */
  function failNextAuditWrite(t: TestContext): void {
    const realRecord = store.recordPortalAdminLog;
    let failed = false;
    t.mock.method(store, 'recordPortalAdminLog', function (this: typeof store, input: Parameters<typeof realRecord>[0]) {
      if (!failed) {
        failed = true;
        throw new Error('audit write failed');
      }
      return realRecord.call(this, input);
    });
  }

  const routes: Array<[string, (t: TestContext) => { method: string; path: string; body?: unknown; unchanged: () => void }]> = [
    ['POST /groups creating a group', () => {
      const name = `Unlogged ${tag()}`;
      return {
        method: 'POST',
        path: '/api/admin/groups',
        body: { name, allowedActions: ['soql_query'] },
        unchanged: () => assert.ok(!store.getGroups().some((g) => g.name === name)),
      };
    }],
    ['POST /groups updating a group', (t) => {
      const group = newGroup(t);
      return {
        method: 'POST',
        path: '/api/admin/groups',
        body: { ...group, expectedVersion: group.version, allowedActions: ['delete_record'] },
        unchanged: () => assert.deepEqual(store.getGroups().find((g) => g.id === group.id), group),
      };
    }],
    ['DELETE /groups/:id', (t) => {
      const group = newGroup(t);
      const profileId = newProfile(t, [group.id]);
      return {
        method: 'DELETE',
        path: `/api/admin/groups/${group.id}`,
        unchanged: () => assert.deepEqual(store.getProfileGroupIds(profileId), [group.id]),
      };
    }],
    ['PUT /profile-groups/:profileId', (t) => {
      const [removed, added] = [newGroup(t), newGroup(t)];
      const profileId = newProfile(t, [removed.id]);
      return {
        method: 'PUT',
        path: `/api/admin/profile-groups/${profileId}`,
        body: { add: [added.id], remove: [removed.id] },
        unchanged: () => assert.deepEqual(store.getProfileGroupIds(profileId), [removed.id]),
      };
    }],
    ['POST /groups/:id/profiles', (t) => {
      const group = newGroup(t);
      const profileId = newProfile(t);
      return {
        method: 'POST',
        path: `/api/admin/groups/${group.id}/profiles`,
        body: { add: [profileId] },
        unchanged: () => assert.deepEqual(store.getProfileGroupIds(profileId), []),
      };
    }],
  ];

  for (const [name, arrange] of routes) {
    test(name, async (t) => {
      const call = arrange(t);
      failNextAuditWrite(t);
      const delta = await bumps(async () => {
        const res = await api(call.path, { method: call.method, body: call.body });
        assert.equal(res.status, 500, JSON.stringify(res.body));
      });
      assert.equal(delta, 0);
      call.unchanged();
    });
  }
});

describe('Admin API and /mcp traffic outside the policy is no revision', () => {
  test('sign-in, Okta, Salesforce settings, certificates, portal users and the policy simulator', async (t) => {
    const profileId = newProfile(t, [newGroup(t).id]);
    const username = `revision.${tag()}`;
    const delta = await bumps(async () => {
      const other = await loginAsAdmin(server.baseUrl);
      const calls: Array<[string, string, unknown?]> = [
        ['PUT', '/api/admin/okta', { enabled: false, adminGroup: 'MCP-Admins' }],
        ['PUT', '/api/admin/sf-settings', { expectedOrgId: '00D000000000001AAA', enforceOrgIdLock: true }],
        ['PUT', '/api/admin/sf-settings', { enforceOrgIdLock: false }],
        ['POST', '/api/admin/sf-settings/generate-cert', {}],
        ['POST', '/api/admin/sf-settings/disconnect', {}],
        ['POST', '/api/admin/portal-users', { username, password: `revision-${tag()}-${tag()}` }],
        ['DELETE', `/api/admin/portal-users/${username}`],
        ['POST', '/api/admin/test-mcp-access', { profileId, toolName: 'soql_query', targetObject: 'Account' }],
      ];
      for (const [method, urlPath, body] of calls) {
        const res = await api(urlPath, { method, body });
        assert.equal(res.status, 200, `${method} ${urlPath}: ${JSON.stringify(res.body)}`);
      }
      const logout = await adminFetch(server.baseUrl, other, '/api/admin/logout', { method: 'POST' });
      assert.equal(logout.status, 200);
    });
    assert.equal(delta, 0);
  });

  test('/mcp tool calls and rejected tokens, which are logged', async (t) => {
    const mock = installSalesforceMock();
    t.after(() => mock.restore());
    const objectName = newObject(t);
    const group = store.createGroup({
      name: `Revision MCP ${tag()}`,
      allowedActions: ['soql_query'],
      objectPermissions: [readGrant(objectName)],
    });
    t.after(() => store.deleteGroup(group.id));
    const profileId = newProfile(t, [group.id]);
    const token = `tok_revision_${tag()}${tag()}`;
    mock.addUser(token, {
      userId: `005${crypto.randomBytes(6).toString('hex')}`,
      organizationId: `00D${crypto.randomBytes(6).toString('hex')}`,
      username: `revision.${tag()}@acme.example.com`,
      profileId,
      profileName: store.getProfileById(profileId)!.name,
      instanceUrl: `https://revision-${tag()}.my.salesforce.com`,
    });
    const logged = () => store.getCopilotMcpLogs(1_000_000).length;
    const rowsBefore = logged();

    const delta = await bumps(async () => {
      const allowed = await mcpRequest(server.baseUrl, token, 'tools/call', {
        name: 'soql_query',
        arguments: { objectName, fields: ['Name'] },
      });
      assert.equal(allowed.body.result.isError, undefined, JSON.stringify(allowed.body));
      assert.ok(toolResultPayload(allowed.body));
      const denied = await mcpRequest(server.baseUrl, token, 'tools/call', {
        name: 'delete_record',
        arguments: { objectName, recordId: `001${crypto.randomBytes(6).toString('hex')}` },
      });
      assert.equal(denied.body.result.isError, true);
      await mcpRequest(server.baseUrl, `tok_unknown_${tag()}`, 'tools/list');
    });
    assert.equal(delta, 0);
    assert.ok(logged() >= rowsBefore + 3, 'the calls were logged');
  });
});

// =============================================================================================
// The database: a new one, an upgraded one, and a restart
// =============================================================================================
function withDb<T>(dbPath: string, fn: (db: DatabaseSync) => T): T {
  const db = new DatabaseSync(dbPath);
  try {
    return fn(db);
  } finally {
    db.close();
  }
}

/** Loads the store on `dbPath` (running its migrations), runs `action` there, and returns the revision then. */
function bootAndReadRevision(dbPath: string, action = ''): number {
  const script = `
    const { store } = await import('./src/db/store.ts');
    ${action}
    process.stdout.write('\\nPROBE ' + JSON.stringify(store.getPolicyRevision()) + '\\n');
  `;
  const out = execFileSync(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', script], {
    cwd: REPO_ROOT,
    env: { ...process.env, DB_PATH: dbPath },
    stdio: 'pipe',
    timeout: 60_000,
  }).toString();
  const line = out.split('\n').find((l) => l.startsWith('PROBE '));
  assert.ok(line, `no probe output in: ${out}`);
  return JSON.parse(line.slice('PROBE '.length));
}

const storedRevision = (dbPath: string) =>
  withDb(dbPath, (db) => Number((db.prepare('SELECT revision FROM policy_state WHERE id = 1').get() as { revision: number }).revision));

/** A database as the release before the revision left it: the store's schema without policy_state or a trigger. */
function databaseFromBeforeTheRevision(name: string, prepare: (db: DatabaseSync) => void): string {
  const dbPath = path.join(testTmpDir, name);
  bootAndReadRevision(dbPath);
  withDb(dbPath, (db) => {
    for (const { name: trigger } of db.prepare(`SELECT name FROM sqlite_master WHERE type = 'trigger'`).all() as Array<{ name: string }>) {
      db.exec(`DROP TRIGGER "${trigger}"`);
    }
    db.exec('DROP TABLE policy_state');
    prepare(db);
  });
  return dbPath;
}

/**
 * Writes to the database as an older release run on it after a rollback does: on a connection of its
 * own, which has none of the triggers this release adds to its connection when the store loads.
 */
function asAnOlderRelease(dbPath: string, write: (db: DatabaseSync) => void) {
  withDb(dbPath, (db) => {
    db.exec('PRAGMA foreign_keys = ON');
    write(db);
  });
}

describe('the revision in the database', () => {
  test('a new database starts at 1, and a change made before a restart is still counted after it', () => {
    const dbPath = path.join(testTmpDir, 'revision-new.sqlite');
    assert.equal(bootAndReadRevision(dbPath), 1);
    assert.equal(storedRevision(dbPath), 1);

    const created = "store.createGroup({ name: 'Before the restart', allowedActions: [], objectPermissions: [] });";
    assert.equal(bootAndReadRevision(dbPath, created), 2);
    assert.equal(bootAndReadRevision(dbPath), 2);
    assert.equal(storedRevision(dbPath), 2);
  });

  test('a database from before the revision starts at 1, its policy as it was', () => {
    const dbPath = databaseFromBeforeTheRevision('revision-upgraded.sqlite', (db) => {
      db.prepare(
        `INSERT INTO sf_profiles (id, name, updated_at) VALUES ('00e000000UPGRAD', 'Upgraded', '2026-10-01T00:00:00.000Z')`
      ).run();
      db.prepare(
        `INSERT INTO access_groups (id, name, allowed_actions_json, updated_at) VALUES ('grp_upgraded', 'Upgraded', '["soql_query"]', '2026-10-01T00:00:00.000Z')`
      ).run();
      db.prepare(`INSERT INTO profile_group_memberships (profile_id, group_id) VALUES ('00e000000UPGRAD', 'grp_upgraded')`).run();
    });
    const policyRows = () =>
      withDb(dbPath, (db) => ({
        groups: db.prepare('SELECT * FROM access_groups').all(),
        memberships: db.prepare('SELECT * FROM profile_group_memberships').all(),
      }));
    const before = policyRows();

    assert.equal(bootAndReadRevision(dbPath), 1);
    assert.equal(bootAndReadRevision(dbPath), 1);
    assert.deepEqual(policyRows(), before);
  });

  test('an upgrade whose one-time grant canonicalization changes a group counts it as one revision', () => {
    // From before the group version column too, so the canonicalization runs on this boot.
    const dbPath = databaseFromBeforeTheRevision('revision-canonicalized.sqlite', (db) => {
      db.exec('ALTER TABLE access_groups DROP COLUMN version');
      db.prepare(`INSERT INTO sf_objects (object_name, label, updated_at) VALUES ('Account', 'Account', '2026-10-01T00:00:00.000Z')`).run();
      db.prepare(`INSERT INTO sf_object_fields (object_name, field_name, label) VALUES ('Account', 'Id', 'Id')`).run();
      const group = db.prepare(
        `INSERT INTO access_groups (id, name, object_permissions_json, updated_at) VALUES (?, ?, ?, '2026-10-01T00:00:00.000Z')`
      );
      for (const id of ['grp_lower', 'grp_upper']) {
        group.run(id, id, JSON.stringify([{ objectName: id === 'grp_lower' ? 'account' : 'ACCOUNT', canRead: true, allowedFields: ['id'] }]));
      }
    });

    assert.equal(bootAndReadRevision(dbPath), 2);
    assert.deepEqual(
      withDb(dbPath, (db) => db.prepare('SELECT id, version FROM access_groups ORDER BY id').all().map((r) => ({ ...r }))),
      [
        { id: 'grp_lower', version: 2 },
        { id: 'grp_upper', version: 2 },
      ]
    );
    // It runs once, so a later boot leaves the revision where it is.
    assert.equal(bootAndReadRevision(dbPath), 2);
  });

  test('the changes an older release made after a rollback are one revision when this release starts again', () => {
    const dbPath = path.join(testTmpDir, 'revision-rollback.sqlite');
    const created = `store.createGroup({ id: 'grp_rollback', name: 'Before the rollback', allowedActions: ['soql_query'], objectPermissions: [] });
      store.upsertProfile('00e000000ROLLBK', 'Rollback');
      store.setProfileGroups('00e000000ROLLBK', ['grp_rollback']);`;
    assert.equal(bootAndReadRevision(dbPath, created), 4);

    asAnOlderRelease(dbPath, (db) => {
      db.prepare(`UPDATE access_groups SET allowed_actions_json = '["soql_query","delete_record"]' WHERE id = 'grp_rollback'`).run();
      db.prepare(`INSERT INTO sf_profiles (id, name, updated_at) VALUES ('00e000000OLDREL', 'Older release', '2026-10-01T00:00:00.000Z')`).run();
      // The membership goes with the Profile, by ON DELETE CASCADE.
      db.prepare(`DELETE FROM sf_profiles WHERE id = '00e000000ROLLBK'`).run();
    });
    assert.equal(bootAndReadRevision(dbPath), 5);
    // Counted once: a later boot leaves the revision where it is.
    assert.equal(bootAndReadRevision(dbPath), 5);

    // This release's own change on the boot that counts them is a revision of its own.
    asAnOlderRelease(dbPath, (db) => {
      db.prepare(`UPDATE sf_profiles SET name = 'Renamed by the older release' WHERE id = '00e000000OLDREL'`).run();
    });
    assert.equal(bootAndReadRevision(dbPath, "store.deleteProfile('00e000000OLDREL');"), 7);
    assert.equal(storedRevision(dbPath), 7);
  });

  test('an older release that only saved what was stored, or wrote outside the policy, leaves the revision alone', () => {
    const dbPath = path.join(testTmpDir, 'revision-rollback-noop.sqlite');
    const created = `store.createGroup({ id: 'grp_noop', name: 'Unchanged', allowedActions: ['soql_query'], objectPermissions: [] });
      store.upsertProfile('00e000000NOOPRB', 'Unchanged');`;
    assert.equal(bootAndReadRevision(dbPath, created), 3);

    asAnOlderRelease(dbPath, (db) => {
      db.prepare(`UPDATE sf_profiles SET name = 'Unchanged', updated_at = '2026-11-01T00:00:00.000Z' WHERE id = '00e000000NOOPRB'`).run();
      db.prepare(`UPDATE access_groups SET version = version + 1, updated_at = '2026-11-01T00:00:00.000Z' WHERE id = 'grp_noop'`).run();
      db.prepare(
        `INSERT INTO mcp_copilot_logs (id, timestamp, sf_username, profile_id, profile_name, tool_name, status)
         VALUES ('log_older_release', '2026-11-01T00:00:00.000Z', 'older@example.com', '00e000000NOOPRB', 'Unchanged', 'soql_query', 'ALLOWED')`
      ).run();
    });
    assert.equal(bootAndReadRevision(dbPath), 3);
  });
});
