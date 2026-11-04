import './helpers/env.js';
// A group's action IDs are matched exactly at /mcp, so an ID that names no tool silently denies it.
// These tests keep the catalog, the MCP server, the portal defaults and POST /groups in agreement.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { store } from '../src/db/store.js';
import { TOOL_INPUT_SCHEMAS } from '../src/mcp/server.js';
import { AVAILABLE_MCP_ACTIONS, unknownMcpActionIds } from '../src/types/governance.js';
import {
  DEFAULT_NEW_GROUP_ACTIONS,
  groupDraftGrants,
  newAccessGroupDraft,
  reloadedGroup,
  savedAccessGroup,
  splitMcpActions,
  staleGroupFromError,
} from '../src/components/views/accessGroupDraft.js';
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

const tag = () => crypto.randomBytes(4).toString('hex');
const CATALOG_IDS = AVAILABLE_MCP_ACTIONS.map((action) => action.id);

let server: TestServer;
let session: AdminSession;

before(async () => {
  server = await startTestServer();
  session = await loginAsAdmin(server.baseUrl);
});

after(async () => {
  await server.close();
});

const postGroup = (body: Record<string, unknown>) =>
  adminFetch(server.baseUrl, session, '/api/admin/groups', { method: 'POST', body });

describe('the catalog and the MCP server agree', () => {
  test('every catalog tool has an input schema, and every schema is a catalog tool', () => {
    assert.deepEqual(Object.keys(TOOL_INPUT_SCHEMAS).sort(), [...CATALOG_IDS].sort());
  });

  test('a Profile granted the whole catalog is offered and can run exactly those tools', async () => {
    const mock = installSalesforceMock();
    try {
      const suffix = tag();
      const profileId = `00e${crypto.randomBytes(6).toString('hex')}`;
      const profileName = `Catalog Profile ${suffix}`;
      const objectName = `Catalog_${suffix}__c`;
      store.upsertProfile(profileId, profileName);
      store.upsertObjectWithFields({ objectName, fields: [{ fieldName: 'Id' }, { fieldName: 'Name' }] });
      const group = store.upsertGroup({
        name: `Catalog Group ${suffix}`,
        allowedActions: [...CATALOG_IDS],
        objectPermissions: [
          { objectName, canRead: true, canCreate: true, canUpdate: true, canDelete: true, allowedFields: ['Id', 'Name'] },
        ],
      });
      store.setProfileGroups(profileId, [group.id]);
      const token = `tok_catalog_${suffix}${tag()}`;
      mock.addUser(token, {
        userId: `005${crypto.randomBytes(6).toString('hex')}`,
        organizationId: `00D${crypto.randomBytes(6).toString('hex')}`,
        username: `catalog.${suffix}@acme.example.com`,
        profileId,
        profileName,
        instanceUrl: `https://catalog-${suffix}.my.salesforce.com`,
      });

      const listed = await mcpRequest(server.baseUrl, token, 'tools/list');
      assert.deepEqual(
        listed.body.result.tools.map((tool: { name: string }) => tool.name).sort(),
        [...CATALOG_IDS].sort()
      );

      const recordId = `001${crypto.randomBytes(6).toString('hex')}`;
      for (const name of CATALOG_IDS) {
        const res = await mcpRequest(server.baseUrl, token, 'tools/call', {
          name,
          arguments: { objectName, recordId, fields: name.endsWith('_record') && name !== 'get_record' ? { Name: 'X' } : ['Name'] },
        });
        assert.equal(res.body.result.isError, undefined, `${name}: ${JSON.stringify(res.body)}`);
        // The dispatch in server.ts has no final else, so a tool it does not handle answers with {}.
        assert.notDeepEqual(toolResultPayload(res.body), {}, `${name} has a handler`);
      }
    } finally {
      mock.restore();
    }
  });
});

describe('new group defaults', () => {
  test('every default names a real tool, including describe and SOQL', () => {
    assert.deepEqual(unknownMcpActionIds(DEFAULT_NEW_GROUP_ACTIONS), []);
    assert.ok(DEFAULT_NEW_GROUP_ACTIONS.includes('describe_object'));
    assert.ok(DEFAULT_NEW_GROUP_ACTIONS.includes('soql_query'));
  });

  test('defaults grant no write or delete tool', () => {
    for (const id of ['create_record', 'update_record', 'delete_record'] as const) {
      assert.ok(!DEFAULT_NEW_GROUP_ACTIONS.includes(id));
    }
  });

  test('a draft cannot change the shared default', () => {
    newAccessGroupDraft().allowedActions.push('delete_record');
    assert.ok(!newAccessGroupDraft().allowedActions.includes('delete_record'));
  });

  test('a new group saved with the defaults keeps them', async () => {
    const draft = newAccessGroupDraft();
    const res = await postGroup({ ...draft, name: `Default ${tag()}` });
    assert.equal(res.status, 200, JSON.stringify(res.body));
    assert.deepEqual(res.body.group.allowedActions, [...DEFAULT_NEW_GROUP_ACTIONS]);
  });
});

describe('stored groups naming IDs that are not tools', () => {
  test('the drawer keeps real tools and reports the rest', () => {
    assert.deepEqual(splitMcpActions(['get_record', 'query_records', 'describe_object_schema']), {
      known: ['get_record'],
      unknown: ['query_records', 'describe_object_schema'],
    });
  });

  test('what the drawer keeps can be saved over a group created with the old defaults', async () => {
    const stale = store.upsertGroup({
      name: `Stale ${tag()}`,
      allowedActions: ['list_enabled_objects', 'describe_object_schema', 'query_records', 'get_record'],
      objectPermissions: [],
    });
    const res = await postGroup({ ...stale, allowedActions: splitMcpActions(stale.allowedActions).known });
    assert.equal(res.status, 200, JSON.stringify(res.body));
    assert.deepEqual(res.body.group.allowedActions, ['list_enabled_objects', 'get_record']);
  });
});

describe('controls that need a saved group', () => {
  const saved = { id: 'grp-1', name: 'Saved', description: '', allowedActions: [], objectPermissions: [], version: 1, updatedAt: '' };

  test('a new group draft has no saved group, whatever its name', () => {
    assert.equal(savedAccessGroup([saved], undefined), null);
    assert.equal(savedAccessGroup([{ ...saved, name: 'New Access Group' }], undefined), null);
  });

  test('a group deleted while its drawer is open no longer counts as saved', () => {
    assert.equal(savedAccessGroup([], saved.id), null);
  });

  test('a group in the saved list is found, from the list and not the stale drawer data', () => {
    assert.equal(savedAccessGroup([saved], saved.id), saved);
  });
});

describe('the group drawer and the stricter POST /groups', () => {
  const catalogObject = (objectName: string, fieldNames: string[]) => ({
    objectName,
    label: objectName,
    isCustom: false,
    enabled: true,
    sourcePath: '',
    fieldCount: fieldNames.length,
    enabledFieldCount: fieldNames.length,
    fields: fieldNames.map((fieldName) => ({
      objectName,
      fieldName,
      label: fieldName,
      fieldType: 'Text',
      isCustom: false,
      required: false,
      enabled: true,
    })),
    updatedAt: '',
  });

  test('starts from the grants as the server stores them and names what it leaves out', () => {
    const objects = [catalogObject('Account', ['Id', 'Name']), catalogObject('Contact', ['Id'])];
    const { grants, dropped } = groupDraftGrants(
      [
        { objectName: 'account', canRead: true, allowedFields: ['ID', 'Gone__c'] },
        { objectName: 'Ghost__c', canRead: true, allowedFields: ['Id'] },
        { objectName: 'ACCOUNT', canUpdate: true, allowedFields: ['Name'] },
        { objectName: 'Contact', canRead: 'false' },
        null,
      ],
      objects
    );
    // Every grant the drawer shows, and nothing POST /groups would refuse, so the group can be saved.
    assert.deepEqual(grants, [
      { objectName: 'Account', canRead: true, canCreate: false, canUpdate: true, canDelete: false, allowedFields: ['Id', 'Name'] },
    ]);
    assert.deepEqual(dropped, ['Account.Gone__c', 'Ghost__c', 'entry 4', 'entry 5']);
  });

  test('a save refused because the group changed elsewhere hands the drawer the current group', () => {
    const current = { id: 'grp-1', name: 'Saved', description: '', allowedActions: [], objectPermissions: [], version: 3, updatedAt: '' };
    assert.deepEqual(staleGroupFromError(Object.assign(new Error('changed'), { status: 409, body: { group: current } })), current);
    // A duplicate name is also a 409, but carries no group: there is nothing to reload.
    assert.equal(staleGroupFromError(Object.assign(new Error('taken'), { status: 409, body: { error: 'taken' } })), null);
    assert.equal(staleGroupFromError(Object.assign(new Error('bad'), { status: 400, body: { group: current } })), null);
    assert.equal(staleGroupFromError(undefined), null);
  });

  test('"Reload group" rebuilds the draft from one fresh read of the workspace, so it keeps a grant on an Object added since', () => {
    const conflict = {
      id: 'grp-1',
      name: 'Saved',
      description: '',
      allowedActions: [],
      objectPermissions: [
        { objectName: 'Added__c', canRead: true, canCreate: false, canUpdate: false, canDelete: false, allowedFields: ['Id'] },
      ],
      version: 2,
      updatedAt: '',
    };
    const current = { ...conflict, version: 3 };
    // The page's own Objects, read before another admin added Added__c and granted it: a draft built
    // from them drops the grant, and saving it with the current version would revoke it.
    const pageObjects = [catalogObject('Account', ['Id'])];
    assert.deepEqual(groupDraftGrants(conflict.objectPermissions, pageObjects).dropped, ['Added__c']);

    const workspace = { groups: [current], objects: [...pageObjects, catalogObject('Added__c', ['Id'])] };
    const reloaded = reloadedGroup(conflict, workspace);
    assert.ok(!('error' in reloaded), JSON.stringify(reloaded));
    assert.equal(reloaded.group, current);
    assert.deepEqual(groupDraftGrants(reloaded.group.objectPermissions, reloaded.objects), {
      grants: conflict.objectPermissions,
      dropped: [],
    });

    // Without a fresh read there is nothing safe to rebuild from.
    assert.deepEqual(reloadedGroup(conflict, null), { error: 'Access Group "Saved" could not be reloaded. Try again.' });
    assert.deepEqual(reloadedGroup(conflict, { ...workspace, groups: [] }), {
      error: 'Access Group "Saved" was deleted elsewhere, so there is nothing to reload.',
    });
  });

  test('a stored group the drawer loaded can be saved back without edits, with its version, which stores its grants normalized', async () => {
    const objectName = `Drawer_${tag()}__c`;
    store.upsertObjectWithFields({ objectName, fields: [{ fieldName: 'Id' }] });
    const stored = store.upsertGroup({
      name: `Drawer ${tag()}`,
      allowedActions: ['soql_query'],
      objectPermissions: [
        { objectName: objectName.toLowerCase(), canRead: true, canCreate: false, canUpdate: false, canDelete: false, allowedFields: ['id', 'Gone__c'] },
      ],
    });
    const { grants } = groupDraftGrants(stored.objectPermissions, store.getObjects());
    const res = await postGroup({ ...stored, objectPermissions: grants, expectedVersion: stored.version });
    assert.equal(res.status, 200, JSON.stringify(res.body));
    assert.deepEqual(res.body.group.objectPermissions, [
      { objectName, canRead: true, canCreate: false, canUpdate: false, canDelete: false, allowedFields: ['Id'] },
    ]);
    assert.equal(res.body.group.version, stored.version + 1);
  });
});

describe('POST /api/admin/groups', () => {
  test('rejects unknown action IDs, naming them, and stores and audits nothing', async () => {
    const name = `Rejected ${tag()}`;
    const auditsBefore = store.getPortalAdminLogs(1_000_000).length;
    const res = await postGroup({ name, allowedActions: ['soql_query', 'query_records', 'export_all_data'] });
    assert.equal(res.status, 400);
    assert.match(res.body.error, /query_records, export_all_data/);
    assert.doesNotMatch(res.body.error, /Unknown MCP action IDs: soql_query/);
    assert.ok(!store.getGroups().some((group) => group.name === name));
    assert.equal(store.getPortalAdminLogs(1_000_000).length, auditsBefore);
  });

  test('a rejected group request writes no row, though its response still names the request', async () => {
    const taken = store.upsertGroup({ name: `Taken ${tag()}`, allowedActions: [], objectPermissions: [] });
    const send = (path: string, method: string, body?: unknown) =>
      adminFetch(server.baseUrl, session, `/api/admin${path}`, { method, body });
    const auditsBefore = store.getPortalAdminLogs(1_000_000).length;

    const rejected = [
      await postGroup({ allowedActions: ['soql_query'] }),
      await postGroup({ name: `Unknown ${tag()}`, allowedActions: ['query_records'] }),
      await postGroup({ name: taken.name, allowedActions: ['soql_query'] }),
      await send(`/groups/grp_missing_${tag()}`, 'DELETE'),
      await send(`/groups/grp_missing_${tag()}/profiles`, 'POST', { add: [] }),
      await send(`/groups/${taken.id}/profiles`, 'POST', {}),
    ];

    assert.deepEqual(rejected.map((res) => res.status), [400, 400, 409, 404, 404, 400]);
    const ids = rejected.map((res) => res.headers.get('x-correlation-id'));
    assert.ok(ids.every((id) => typeof id === 'string' && id.length > 0), `every response names its request: ${ids}`);
    assert.equal(new Set(ids).size, ids.length);
    const logs = store.getPortalAdminLogs(1_000_000);
    assert.equal(logs.length, auditsBefore);
    assert.deepEqual(logs.filter((row) => ids.includes(row.correlationId ?? null)), []);
    assert.deepEqual(store.getGroups().filter((group) => group.name === taken.name).map((group) => group.id), [taken.id]);
  });

  test('an update cannot add an unknown ID to an existing group', async () => {
    const existing = store.upsertGroup({ name: `Existing ${tag()}`, allowedActions: ['soql_query'], objectPermissions: [] });
    const res = await postGroup({ ...existing, allowedActions: ['soql_query', 'query_records'] });
    assert.equal(res.status, 400);
    const reloaded = store.getGroups().find((group) => group.id === existing.id);
    assert.deepEqual(reloaded?.allowedActions, ['soql_query']);
  });

  test('a non-string entry is rejected rather than stored', async () => {
    const res = await postGroup({ name: `Null ${tag()}`, allowedActions: [null] });
    assert.equal(res.status, 400);
    assert.match(res.body.error, /null/);
  });

  test('every catalog ID, and no IDs at all, are accepted', async () => {
    const all = await postGroup({ name: `All ${tag()}`, allowedActions: [...CATALOG_IDS] });
    assert.equal(all.status, 200, JSON.stringify(all.body));
    const none = await postGroup({ name: `None ${tag()}` });
    assert.equal(none.status, 200, JSON.stringify(none.body));
    assert.deepEqual(none.body.group.allowedActions, []);
  });
});

describe('sample data', () => {
  test('every group from seed-sample names only real tools', async () => {
    const res = await adminFetch(server.baseUrl, session, '/api/admin/workspace/seed-sample', { method: 'POST', body: {} });
    assert.equal(res.status, 200, JSON.stringify(res.body));
    const seeded = res.body.groups.filter((group: { id: string }) => group.id.startsWith('grp-'));
    assert.ok(seeded.length >= 5);
    for (const group of seeded) {
      assert.deepEqual(unknownMcpActionIds(group.allowedActions), [], group.name);
    }
  });
});
