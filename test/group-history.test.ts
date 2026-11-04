import { TEST_ADMIN } from './helpers/env.js';
// A group's history through the Admin API: who changed it, from where, and what changed, including
// changes made in Salesforce > Objects and by org sync to what it grants. Also covers that a deleted
// object or field stays on the group, held and granting nothing, until an admin restores it.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { store } from '../src/db/store.js';
import { resolveEffectiveProfilePermissions } from '../src/rbac/policyEngine.js';
import { accessGroupToXml, parseAccessGroupXml } from '../src/groups/groupXml.js';
import type { AccessGroupHistoryEntry, GroupObjectPermission } from '../src/types/governance.js';
import { adminFetch, loginAsAdmin, startTestServer, type AdminSession, type TestServer } from './helpers/server.js';

const tag = () => crypto.randomBytes(4).toString('hex');

let server: TestServer;
let session: AdminSession;

before(async () => {
  server = await startTestServer();
  session = await loginAsAdmin(server.baseUrl);
});

after(async () => {
  await server.close();
});

const api = (path: string, method = 'GET', body?: unknown) =>
  adminFetch(server.baseUrl, session, `/api/admin${path}`, { method, ...(body === undefined ? {} : { body }) });

const postGroup = (body: Record<string, unknown>) => api('/groups', 'POST', body);

const historyOf = async (groupId: string): Promise<AccessGroupHistoryEntry[]> => {
  const res = await api(`/groups/${groupId}/history`);
  assert.equal(res.status, 200, JSON.stringify(res.body));
  return res.body.history;
};

const read = (objectName: string, allowedFields: string[], extra: Partial<GroupObjectPermission> = {}): GroupObjectPermission => ({
  objectName,
  canRead: true,
  canCreate: false,
  canUpdate: false,
  canDelete: false,
  allowedFields,
  ...extra,
});

/** An object in the catalog, a group granting it, and a Profile mapped to the group. */
function seed(fields = ['Id', 'Amount__c']) {
  const objectName = `Hist_${tag()}__c`;
  store.upsertObjectWithFields({ objectName, fields: fields.map((fieldName) => ({ fieldName })) });
  const group = store.upsertGroup({
    name: `History ${tag()}`,
    allowedActions: ['soql_query'],
    objectPermissions: [read(objectName, fields)],
  });
  const profileId = `00e${crypto.randomBytes(6).toString('hex')}`.slice(0, 15);
  store.upsertProfile(profileId, `History profile ${tag()}`);
  store.setProfileGroups(profileId, [group.id]);
  const granted = () => resolveEffectiveProfilePermissions(profileId).objectPermissions.get(objectName);
  return { objectName, group, granted };
}

describe('edits are recorded', () => {
  test('a creation, then an edit, each with who, where from and what changed', async () => {
    const created = await postGroup({ name: `Edited ${tag()}`, allowedActions: ['soql_query'], objectPermissions: [read('Account', ['Id'])] });
    assert.equal(created.status, 200, JSON.stringify(created.body));
    const id = created.body.group.id;

    const updated = await postGroup({
      ...created.body.group,
      allowedActions: ['soql_query', 'get_record'],
      objectPermissions: [read('Account', ['Id', 'Name'])],
      source: 'xml_editor',
    });
    assert.equal(updated.status, 200);

    const [edit, creation] = await historyOf(id);
    assert.equal(creation.kind, 'created');
    assert.equal(creation.source, 'editor');
    assert.equal(creation.adminUsername, TEST_ADMIN.username);
    assert.deepEqual(creation.changes, ['MCP actions: soql_query.', 'Account (R) with fields Id.']);
    assert.equal(edit.kind, 'updated');
    assert.equal(edit.source, 'xml_editor');
    assert.deepEqual(edit.changes, ['Added MCP actions: get_record.', 'Account fields added: Name.']);
    assert.deepEqual(edit.snapshot.allowedActions, ['soql_query', 'get_record']);
    assert.equal(store.getPortalAdminLogs(1)[0].details.includes('in the XML editor'), true);
  });

  test('saving from an editor without changing anything adds no entry', async () => {
    const created = await postGroup({ name: `Same ${tag()}`, allowedActions: ['soql_query'] });
    await postGroup({ ...created.body.group, source: 'editor' });
    assert.equal((await historyOf(created.body.group.id)).length, 1);
  });

  test('an import is recorded with its file, even when it changes nothing, and audited as an import', async () => {
    const created = await postGroup({ name: `Imported ${tag()}`, allowedActions: ['soql_query'] });
    const res = await postGroup({ ...created.body.group, source: 'xml_import', sourceDetail: 'sales-read.xml' });
    assert.equal(res.status, 200);
    const [entry] = await historyOf(created.body.group.id);
    assert.equal(entry.source, 'xml_import');
    assert.equal(entry.sourceDetail, 'sales-read.xml');
    assert.deepEqual(entry.changes, ['Nothing the group grants changed.']);
    const log = store.getPortalAdminLogs(1)[0];
    assert.equal(log.action, 'IMPORT_GROUP_XML');
    assert.match(log.details, /from XML \(sales-read\.xml\)/);
  });

  test('a source the editor does not send is recorded as the editor', async () => {
    const created = await postGroup({ name: `Spoofed ${tag()}`, source: 'org_sync' });
    assert.equal((await historyOf(created.body.group.id))[0].source, 'editor');
  });

  test('a deleted group keeps its history, ending with what it held', async () => {
    const created = await postGroup({ name: `Gone ${tag()}`, allowedActions: ['get_record'] });
    const id = created.body.group.id;
    assert.equal((await api(`/groups/${id}`, 'DELETE')).status, 200);
    const [deletion] = await historyOf(id);
    assert.equal(deletion.kind, 'deleted');
    assert.deepEqual(deletion.snapshot.allowedActions, ['get_record']);
    assert.equal((await api('/groups/grp_never_existed/history')).status, 404);
  });

  test('a group exported as XML and imported under a new name grants the same', async () => {
    const { group } = seed();
    const parsed = parseAccessGroupXml(accessGroupToXml({ ...store.getGroup(group.id)!, id: group.id }, { objects: store.getObjects() }));
    assert.ok(parsed.ok);
    const { id: _id, ...content } = parsed.group;
    const copy = await postGroup({ ...content, name: `${group.name} copy`, source: 'xml_import', sourceDetail: 'copy.xml' });
    assert.equal(copy.status, 200, JSON.stringify(copy.body));
    assert.deepEqual(copy.body.group.objectPermissions, store.getGroup(group.id)!.objectPermissions);
    assert.deepEqual(copy.body.group.allowedActions, store.getGroup(group.id)!.allowedActions);
  });
});

describe('what a save must look like', () => {
  test('object entries with names that are not API names, or listed twice, are rejected', async () => {
    const bad = await postGroup({ name: `Bad ${tag()}`, objectPermissions: [read("Account' OR 1=1", ['Id'])] });
    assert.equal(bad.status, 400);
    assert.match(bad.body.error, /not a valid Salesforce object API name/);
    const twice = await postGroup({ name: `Twice ${tag()}`, objectPermissions: [read('Account', ['Id']), read('ACCOUNT', ['Id'])] });
    assert.equal(twice.status, 400);
    assert.match(twice.body.error, /listed more than once/);
  });

  test('an object this server does not have is kept and reported, not dropped', async () => {
    const res = await postGroup({ name: `Pending ${tag()}`, objectPermissions: [read('Never_Imported__c', ['Id'])] });
    assert.equal(res.status, 200);
    assert.deepEqual(res.body.group.objectPermissions.map((p: GroupObjectPermission) => p.objectName), ['Never_Imported__c']);
    assert.deepEqual(res.body.issues.map((i: { reason: string }) => i.reason), ['object_not_in_catalog']);
  });

  test('a held entry saved through the API stays held and grants nothing', async () => {
    const { group, objectName, granted } = seed();
    const held = read(objectName, ['Id'], { removed: { at: '2026-11-01T00:00:00.000Z', by: 'someone' } });
    const res = await postGroup({ ...store.getGroup(group.id)!, objectPermissions: [held] });
    assert.equal(res.status, 200);
    assert.deepEqual(store.getGroup(group.id)!.objectPermissions[0].removed, held.removed);
    assert.equal(granted(), undefined);
  });
});

describe('deleting from Salesforce > Objects keeps the grant on the group, not available', () => {
  test('a deleted field is held with who deleted it, stays revoked when it returns, and is granted again once restored', async () => {
    const { group, objectName, granted } = seed();
    assert.ok(granted()?.allowedFields.has('Amount__c'));

    const del = await api(`/objects/${objectName}/fields/Amount__c`, 'DELETE');
    assert.equal(del.status, 200);
    const perm = store.getGroup(group.id)!.objectPermissions[0];
    assert.deepEqual(perm.allowedFields, ['Id']);
    assert.deepEqual(perm.removedFields?.map((f) => [f.fieldName, f.by]), [['Amount__c', TEST_ADMIN.username]]);
    assert.match(store.getPortalAdminLogs(1)[0].details, /revoked it from 1 Access Group\(s\), which keep it as not available/);
    const [entry] = await historyOf(group.id);
    assert.equal(entry.kind, 'catalog');
    assert.equal(entry.source, 'objects');
    assert.match(entry.changes[0], new RegExp(`${objectName}\\.Amount__c was deleted from Salesforce > Objects`));

    store.upsertObjectWithFields({ objectName, fields: [{ fieldName: 'Id' }, { fieldName: 'Amount__c' }] });
    assert.ok(!granted()?.allowedFields.has('Amount__c'), 'the field is back but the grant is not');

    const restored = await postGroup({
      ...store.getGroup(group.id)!,
      objectPermissions: [read(objectName, ['Id', 'Amount__c'])],
    });
    assert.equal(restored.status, 200);
    assert.ok(granted()?.allowedFields.has('Amount__c'));
    assert.deepEqual((await historyOf(group.id))[0].changes, [`${objectName} fields restored: Amount__c.`]);
  });

  test('org sync removing an object holds it the same way, naming the admin who applied the sync', async () => {
    const { group, objectName } = seed();
    const res = await api('/objects/pull-apply', 'POST', {
      pulledMetadata: [{ objectName, label: objectName, isCustom: true, existsInOrg: false, fields: [] }],
      removeObjectNames: [objectName],
      removeFields: [],
    });
    assert.equal(res.status, 200, JSON.stringify(res.body));
    assert.equal(store.getGroup(group.id)!.objectPermissions[0].removed?.by, TEST_ADMIN.username);
    const [entry] = await historyOf(group.id);
    assert.equal(entry.source, 'org_sync');
  });
});

describe('changes in Salesforce > Objects to what a group grants are noted in its history', () => {
  test('disabling and enabling an object, once each, and nothing for a toggle that changes nothing', async () => {
    const { group, objectName } = seed();
    const before = (await historyOf(group.id)).length;
    await api(`/objects/${objectName}/toggle`, 'PUT', { enabled: false });
    await api(`/objects/${objectName}/toggle`, 'PUT', { enabled: false });
    await api(`/objects/${objectName}/toggle`, 'PUT', { enabled: true });
    const entries = await historyOf(group.id);
    assert.equal(entries.length, before + 2);
    assert.match(entries[1].changes[0], /was disabled in Salesforce > Objects/);
    assert.match(entries[0].changes[0], /was enabled in Salesforce > Objects/);
    assert.equal(entries[0].kind, 'catalog');
  });

  test('disabling a field is noted only on groups granting it', async () => {
    const { group, objectName } = seed();
    const other = store.upsertGroup({ name: `Other ${tag()}`, allowedActions: [], objectPermissions: [read(objectName, ['Id'])] });
    await api(`/objects/${objectName}/fields/Amount__c/toggle`, 'PUT', { enabled: false });
    assert.match((await historyOf(group.id))[0].changes[0], /Amount__c was disabled/);
    assert.deepEqual(await historyOf(other.id), [], 'the group that does not grant the field is not told');
  });

  test('org sync flagging an object missing from the org is noted once', async () => {
    const { group, objectName } = seed();
    const missing = { pulledMetadata: [{ objectName, label: objectName, isCustom: true, existsInOrg: false, fields: [] }], removeObjectNames: [], removeFields: [] };
    await api('/objects/pull-apply', 'POST', missing);
    await api('/objects/pull-apply', 'POST', missing);
    const notes = (await historyOf(group.id)).filter((e) => e.source === 'org_sync');
    assert.equal(notes.length, 1);
    assert.match(notes[0].changes[0], /missing from the Salesforce org/);
  });
});
