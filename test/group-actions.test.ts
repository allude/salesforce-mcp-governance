import './helpers/env.js';
// A group's action IDs are matched exactly at /mcp, so an ID that names no tool grants nothing. Such
// an ID is kept on the group and reported as not available (it may come from an XML file of another
// server). These tests keep the catalog, the MCP server, the portal defaults and POST /groups in agreement.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { store } from '../src/db/store.js';
import { TOOL_INPUT_SCHEMAS } from '../src/mcp/server.js';
import { AVAILABLE_MCP_ACTIONS, unknownMcpActionIds } from '../src/types/governance.js';
import {
  DEFAULT_NEW_GROUP_ACTIONS,
  newAccessGroupDraft,
  savedAccessGroup,
  splitMcpActions,
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
  const saved = { id: 'grp-1', name: 'Saved', description: '', allowedActions: [], objectPermissions: [], updatedAt: '' };

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

describe('POST /api/admin/groups', () => {
  test('keeps action IDs this server has no tool for and reports them as not available', async () => {
    const name = `Kept ${tag()}`;
    const res = await postGroup({ name, allowedActions: ['soql_query', 'query_records', 'export_all_data'] });
    assert.equal(res.status, 200, JSON.stringify(res.body));
    assert.deepEqual(res.body.group.allowedActions, ['soql_query', 'query_records', 'export_all_data']);
    assert.deepEqual(
      res.body.issues.map((issue: { name: string; reason: string }) => [issue.name, issue.reason]),
      [
        ['query_records', 'unknown_action'],
        ['export_all_data', 'unknown_action'],
      ]
    );
    assert.match(store.getPortalAdminLogs(1)[0].details, /2 not available/);
  });

  test('an unknown ID kept on a group is never offered or run at /mcp', async () => {
    const mock = installSalesforceMock();
    try {
      const suffix = tag();
      const profileId = `00e${crypto.randomBytes(6).toString('hex')}`;
      const profileName = `Unknown Tool Profile ${suffix}`;
      store.upsertProfile(profileId, profileName);
      const existing = store.upsertGroup({ name: `Existing ${suffix}`, allowedActions: ['soql_query'], objectPermissions: [] });
      const res = await postGroup({ ...existing, allowedActions: ['soql_query', 'query_records'] });
      assert.equal(res.status, 200, JSON.stringify(res.body));
      assert.deepEqual(store.getGroup(existing.id)?.allowedActions, ['soql_query', 'query_records']);
      store.setProfileGroups(profileId, [existing.id]);
      const token = `tok_unknown_${suffix}${tag()}`;
      mock.addUser(token, {
        userId: `005${crypto.randomBytes(6).toString('hex')}`,
        organizationId: `00D${crypto.randomBytes(6).toString('hex')}`,
        username: `unknown.${suffix}@acme.example.com`,
        profileId,
        profileName,
        instanceUrl: `https://unknown-${suffix}.my.salesforce.com`,
      });
      const listed = await mcpRequest(server.baseUrl, token, 'tools/list');
      assert.deepEqual(listed.body.result.tools.map((tool: { name: string }) => tool.name), ['soql_query']);
      const called = await mcpRequest(server.baseUrl, token, 'tools/call', { name: 'query_records', arguments: {} });
      assert.ok(called.body.error || called.body.result?.isError, JSON.stringify(called.body));
    } finally {
      mock.restore();
    }
  });

  test('an ID that cannot be a tool name is rejected rather than stored', async () => {
    const name = `Bad ${tag()}`;
    const res = await postGroup({ name, allowedActions: ['soql_query', "drop table'; --"] });
    assert.equal(res.status, 400);
    assert.match(res.body.error, /not a valid MCP action ID/);
    assert.ok(!store.getGroups().some((group) => group.name === name));
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
