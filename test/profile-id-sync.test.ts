import './helpers/env.js';
// Covers Profile sync when one Salesforce ID exists in its 15- and 18-character forms: no duplicate
// row, no flagged removal, no lost membership, and no access gained without it being reported.
import { after, before, describe, test, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { store } from '../src/db/store.js';
import { resolveEffectiveProfilePermissions } from '../src/rbac/policyEngine.js';
import { salesforceIdKey } from '../src/salesforce/ids.js';
import { salesforceIdsMatch } from '../src/salesforce/client.js';
import {
  describeProfileDuplicate,
  profileSyncNeedsReview,
  profileSyncResultMessage,
} from '../src/components/views/profileSyncReview.js';
import { adminFetch, loginAsAdmin, startTestServer, type AdminSession, type TestServer } from './helpers/server.js';

const uid = () => crypto.randomBytes(4).toString('hex');
/** A 15-character ID holding upper- and lower-case letters, so a case-flipped copy is a different ID. */
const newId15 = () => `00eAb${crypto.randomBytes(5).toString('hex')}`;
const to18 = (id15: string) => `${id15}AAK`;
const flipCase = (id: string) => id.replace('Ab', 'aB');

let server: TestServer;
let session: AdminSession;

before(async () => {
  server = await startTestServer();
  session = await loginAsAdmin(server.baseUrl);
});

after(async () => {
  await server.close();
});

function newGroup(t: TestContext) {
  const group = store.upsertGroup({ name: `Sync group ${uid()}`, allowedActions: [], objectPermissions: [] });
  t.after(() => store.deleteGroup(group.id));
  return group;
}

function localProfile(t: TestContext, id: string, name: string, groupIds: string[] = []) {
  store.upsertProfile(id, name);
  store.setProfileGroups(id, groupIds);
  t.after(() => store.deleteProfile(id));
}

const groupIdsOf = (profileId: string) =>
  [...(store.getProfileGroupMappings().find((m) => m.profileId === profileId)?.groupIds || [])].sort();
const inForce = (profileId: string) =>
  resolveEffectiveProfilePermissions(profileId).assignedGroups.map((g) => g.id).sort();
const previewOf = (id: string, name: string) =>
  store.previewProfilesSyncFromOrg([{ id, name }], { orgId: 'org', instanceUrl: 'https://x.my.salesforce.com' });
const applyOf = (id: string, name: string) =>
  store.applyProfilesSyncFromOrg({ upserts: [{ id, name }], removeProfileIds: [] });
const rowsMatching = (id: string) => store.getProfiles().filter((p) => salesforceIdsMatch(p.id, id));
const sorted = (ids: string[]) => [...ids].sort();

describe('salesforceIdKey', () => {
  test('two values share a key exactly when salesforceIdsMatch says they match', () => {
    const id = newId15();
    const values = [id, to18(id), `${id}aak`, flipCase(id), to18(flipCase(id)), `${id}A`, `${id}!!!`, '00eLEGACY_DELETED', ` ${id} `];
    for (const a of values) {
      for (const b of values) {
        assert.equal(salesforceIdKey(a) === salesforceIdKey(b), salesforceIdsMatch(a, b), `${a} vs ${b}`);
      }
    }
  });

  test('an empty value has an empty key and still matches nothing', () => {
    assert.equal(salesforceIdKey('  '), '');
    assert.equal(salesforceIdsMatch('', '  '), false);
  });
});

describe('previewing a Profile sync', () => {
  test('a local 15-character row is an update, not a removal and an addition', (t) => {
    const id = newId15();
    localProfile(t, id, 'Local name');

    const preview = previewOf(to18(id), 'Org name');

    assert.deepEqual(preview.updated.filter((u) => u.id === to18(id)), [
      { id: to18(id), name: 'Org name', previousName: 'Local name', previousId: id, unchanged: false },
    ]);
    assert.equal(preview.added.length, 0);
    assert.equal(preview.removedFromOrg.some((r) => r.id === id), false);
    assert.equal(preview.duplicates.length, 0);
  });

  test('an upgrade is not reported as unchanged even when the name is the same', (t) => {
    const id = newId15();
    localProfile(t, id, 'Same');
    assert.equal(previewOf(to18(id), 'Same').updated[0].unchanged, false);
  });

  test('a stored 18-character row and an org 15-character form need no upgrade', (t) => {
    const id = newId15();
    localProfile(t, to18(id), 'Same');
    assert.deepEqual(previewOf(id, 'Same').updated, [
      { id, name: 'Same', previousName: 'Same', unchanged: true },
    ]);
  });

  test('an ID differing only by case on the first 15 characters is a different Profile', (t) => {
    const id = newId15();
    localProfile(t, id, 'Local');

    const preview = previewOf(to18(flipCase(id)), 'Other');

    assert.deepEqual(preview.added.map((a) => a.id), [to18(flipCase(id))]);
    assert.equal(preview.removedFromOrg.some((r) => r.id === id), true);
    assert.equal(preview.updated.length, 0);
  });

  test('a preview writes nothing', (t) => {
    const id = newId15();
    localProfile(t, id, 'Local');
    localProfile(t, to18(id), 'Local');
    const before = JSON.stringify([store.getProfiles(), store.getProfileGroupMappings()]);
    previewOf(to18(id), 'Org name');
    assert.equal(JSON.stringify([store.getProfiles(), store.getProfileGroupMappings()]), before);
  });

  test('duplicates with one set of groups are a reported merge', (t) => {
    const group = newGroup(t);
    const id = newId15();
    localProfile(t, id, 'Row', [group.id]);
    localProfile(t, to18(id), 'Row', [group.id]);

    const preview = previewOf(to18(id), 'Org name');

    assert.equal(preview.duplicates.length, 1);
    assert.equal(preview.duplicates[0].outcome, 'merge');
    assert.deepEqual(preview.duplicates[0].resultGroupNames, [group.name]);
    assert.deepEqual(preview.duplicates[0].grantedGroupNames, []);
    assert.deepEqual(preview.updated.map((u) => u.id), [to18(id)]);
    assert.equal(preview.removedFromOrg.some((r) => salesforceIdsMatch(r.id, id)), false);
    assert.equal(preview.added.length, 0);
  });

  test('duplicates whose union would add access are a conflict, and are not offered as an upsert', (t) => {
    const [a, b] = [newGroup(t), newGroup(t)];
    const id = newId15();
    localProfile(t, id, 'Row', [a.id]);
    localProfile(t, to18(id), 'Row', [b.id]);

    const preview = previewOf(to18(id), 'Org name');

    assert.equal(preview.duplicates[0].outcome, 'conflict');
    assert.deepEqual(preview.duplicates[0].rows.map((r) => r.groupNames), [[a.name], [b.name]]);
    assert.equal(preview.updated.length, 0);
    assert.equal(preview.added.length, 0);
    assert.equal(preview.removedFromOrg.some((r) => salesforceIdsMatch(r.id, id)), false);
  });

  test('duplicates where the row in force has no groups name what a merge would grant', (t) => {
    const group = newGroup(t);
    const id = newId15();
    localProfile(t, id, 'Row');
    localProfile(t, to18(id), 'Row', [group.id]);

    const [duplicate] = previewOf(to18(id), 'Org name').duplicates;

    assert.equal(duplicate.outcome, 'merge');
    assert.deepEqual(duplicate.grantedGroupNames, [group.name]);
  });
});

describe('applying a Profile sync', () => {
  test('upgrades a 15-character row in place, and its memberships still resolve', (t) => {
    const group = newGroup(t);
    const id = newId15();
    localProfile(t, id, 'Local name', [group.id]);
    t.after(() => store.deleteProfile(to18(id)));
    store.applyProfilesSyncFromOrg({ upserts: [], removeProfileIds: [], keptMissingProfileIds: [id] });
    assert.equal(store.getProfileById(id)?.missingInOrg, true);

    const summary = applyOf(to18(id), 'Org name');

    assert.equal(summary.inserted, 0);
    assert.equal(summary.updated, 1);
    assert.deepEqual(summary.affected.idsUpgraded, ['Org name']);
    assert.equal(store.getProfileById(id), null);
    assert.deepEqual(rowsMatching(id).map((p) => [p.id, p.name, p.missingInOrg]), [[to18(id), 'Org name', false]]);
    assert.deepEqual(groupIdsOf(to18(id)), [group.id]);
    assert.deepEqual(groupIdsOf(id), []);
    assert.deepEqual(inForce(to18(id)), [group.id]);
    assert.deepEqual(inForce(id), [group.id]);
  });

  test('a second sync changes nothing further', (t) => {
    const group = newGroup(t);
    const id = newId15();
    localProfile(t, id, 'Name', [group.id]);
    t.after(() => store.deleteProfile(to18(id)));
    applyOf(to18(id), 'Name');

    const summary = applyOf(to18(id), 'Name');

    assert.deepEqual(summary.affected.idsUpgraded, []);
    assert.deepEqual(rowsMatching(id).map((p) => p.id), [to18(id)]);
    assert.deepEqual(groupIdsOf(to18(id)), [group.id]);
  });

  test('a stored 18-character form is not given up for a 15-character upsert', (t) => {
    const group = newGroup(t);
    const id = newId15();
    localProfile(t, to18(id), 'Name', [group.id]);

    applyOf(id, 'Org name');

    assert.deepEqual(rowsMatching(id).map((p) => [p.id, p.name]), [[to18(id), 'Org name']]);
    assert.deepEqual(groupIdsOf(to18(id)), [group.id]);
  });

  test('a remove or keep entry for another form of an upserted Profile is ignored', (t) => {
    const group = newGroup(t);
    const id = newId15();
    localProfile(t, id, 'Name', [group.id]);
    t.after(() => store.deleteProfile(to18(id)));

    const summary = store.applyProfilesSyncFromOrg({
      upserts: [{ id: to18(id), name: 'Name' }],
      removeProfileIds: [id],
      keptMissingProfileIds: [id],
    });

    assert.equal(summary.removed, 0);
    assert.equal(summary.keptMissing, 0);
    assert.deepEqual(summary.affected.groupsLosingMembers, []);
    assert.equal(store.getProfileById(to18(id))?.missingInOrg, false);
    assert.deepEqual(inForce(id), [group.id]);
  });

  test('IDs differing only by case stay separate rows with their own memberships', (t) => {
    const [a, b] = [newGroup(t), newGroup(t)];
    const id = newId15();
    localProfile(t, id, 'Lower', [a.id]);
    localProfile(t, flipCase(id), 'Flipped', [b.id]);
    t.after(() => store.deleteProfile(to18(id)));

    const summary = applyOf(to18(id), 'Lower');

    assert.deepEqual(summary.affected.duplicatesMerged, []);
    assert.deepEqual(groupIdsOf(to18(id)), [a.id]);
    assert.deepEqual(groupIdsOf(flipCase(id)), [b.id]);
    assert.deepEqual(inForce(flipCase(id)), [b.id]);
    assert.deepEqual(inForce(to18(id)), [a.id]);
  });

  test('merges duplicates with the same groups without changing access', (t) => {
    const [a, b] = [newGroup(t), newGroup(t)];
    const id = newId15();
    localProfile(t, id, 'Row', [a.id, b.id]);
    localProfile(t, to18(id), 'Row', [b.id, a.id]);

    const summary = applyOf(to18(id), 'Org name');

    assert.deepEqual(summary.affected.duplicatesMerged, ['Org name']);
    assert.deepEqual(summary.affected.accessGranted, []);
    assert.deepEqual(rowsMatching(id).map((p) => p.id), [to18(id)]);
    assert.deepEqual(groupIdsOf(to18(id)), sorted([a.id, b.id]));
    assert.deepEqual(inForce(id), sorted([a.id, b.id]));
  });

  test('merges three forms into the org form when the org suffix matches none of them', (t) => {
    const group = newGroup(t);
    const id = newId15();
    localProfile(t, id, 'Row', [group.id]);
    localProfile(t, `${id}aak`, 'Row', [group.id]);
    localProfile(t, to18(id), 'Row');

    const orgForm = `${id}BBB`;
    t.after(() => store.deleteProfile(orgForm));
    const summary = applyOf(orgForm, 'Org name');

    assert.equal(summary.inserted, 0);
    assert.deepEqual(rowsMatching(id).map((p) => p.id), [orgForm]);
    assert.deepEqual(groupIdsOf(orgForm), [group.id]);
  });

  test('merges when the row in force already holds every group of the other', (t) => {
    const [a, b] = [newGroup(t), newGroup(t)];
    const id = newId15();
    localProfile(t, id, 'A in force', [a.id, b.id]);
    localProfile(t, to18(id), 'B not in force', [a.id]);
    const before = inForce(id);

    const summary = applyOf(to18(id), 'Org name');

    assert.deepEqual(summary.affected.duplicatesUnresolved, []);
    assert.deepEqual(summary.affected.accessGranted, []);
    assert.deepEqual(rowsMatching(id).map((p) => p.id), [to18(id)]);
    assert.deepEqual(inForce(id), before);
  });

  test('keeps the row with memberships over an empty row in force, and reports what that grants', (t) => {
    const group = newGroup(t);
    const id = newId15();
    localProfile(t, id, 'A empty in force');
    localProfile(t, to18(id), 'B has groups', [group.id]);
    assert.deepEqual(inForce(id), []);

    const summary = applyOf(to18(id), 'Org name');

    assert.deepEqual(summary.affected.accessGranted, [`Org name now grants ${group.name}`]);
    assert.deepEqual(rowsMatching(id).map((p) => p.id), [to18(id)]);
    assert.deepEqual(inForce(id), [group.id]);
  });

  test('keeps memberships held only by the 15-character row when it is merged away', (t) => {
    const group = newGroup(t);
    const id = newId15();
    localProfile(t, id, 'A has groups', [group.id]);
    localProfile(t, to18(id), 'B empty');

    const summary = applyOf(to18(id), 'Org name');

    assert.deepEqual(summary.affected.accessGranted, []);
    assert.deepEqual(groupIdsOf(to18(id)), [group.id]);
    assert.deepEqual(inForce(to18(id)), [group.id]);
  });

  const conflicts: Array<[string, (a: string, b: string) => [string[], string[]]]> = [
    ['disjoint groups', (a, b) => [[a], [b]]],
    ['a row in force holding fewer groups than the other', (a, b) => [[a], [a, b]]],
  ];
  for (const [name, sets] of conflicts) {
    test(`leaves duplicates untouched and reports them when they have ${name}`, (t) => {
      const [a, b] = [newGroup(t), newGroup(t)];
      const id = newId15();
      const [inForceGroups, otherGroups] = sets(a.id, b.id);
      localProfile(t, id, 'A in force', inForceGroups);
      localProfile(t, to18(id), 'B not in force', otherGroups);
      const rowsBefore = JSON.stringify(rowsMatching(id));
      const accessBefore = inForce(id);

      const summary = store.applyProfilesSyncFromOrg({
        upserts: [{ id: to18(id), name: 'Org name' }],
        removeProfileIds: [id],
        keptMissingProfileIds: [to18(id)],
      });

      assert.deepEqual(summary.affected.duplicatesUnresolved, ['Org name']);
      assert.deepEqual(summary.affected.upserted, []);
      assert.equal(summary.updated, 0);
      assert.equal(summary.removed, 0);
      assert.equal(JSON.stringify(rowsMatching(id)), rowsBefore);
      assert.deepEqual(groupIdsOf(id), sorted(inForceGroups));
      assert.deepEqual(groupIdsOf(to18(id)), sorted(otherGroups));
      assert.deepEqual(inForce(id), accessBefore);
      assert.deepEqual(inForce(to18(id)), accessBefore);
    });
  }

  test('a conflict settles on the next sync once an admin gives the rows the same groups', (t) => {
    const [a, b] = [newGroup(t), newGroup(t)];
    const id = newId15();
    localProfile(t, id, 'Row', [a.id]);
    localProfile(t, to18(id), 'Row', [b.id]);
    applyOf(to18(id), 'Row');

    store.setProfileGroups(to18(id), [a.id]);
    const summary = applyOf(to18(id), 'Row');

    assert.deepEqual(summary.affected.duplicatesMerged, ['Row']);
    assert.deepEqual(rowsMatching(id).map((p) => p.id), [to18(id)]);
    assert.deepEqual(inForce(id), [a.id]);
  });

  test('a failure part-way undoes the ID upgrade and the membership move', async (t) => {
    const group = newGroup(t);
    const id = newId15();
    localProfile(t, id, 'Local', [group.id]);
    const blocked = newId15();
    const before = JSON.stringify([store.getProfiles(), store.getProfileGroupMappings()]);

    const raw = new DatabaseSync(process.env.DB_PATH as string);
    raw.exec(`
      CREATE TRIGGER refuse_insert BEFORE INSERT ON sf_profiles WHEN NEW.id = '${blocked}'
      BEGIN SELECT RAISE(ABORT, 'forced failure'); END
    `);
    try {
      assert.throws(
        () =>
          store.applyProfilesSyncFromOrg({
            upserts: [{ id: to18(id), name: 'Org name' }, { id: blocked, name: 'Blocked' }],
            removeProfileIds: [],
          }),
        /forced failure/
      );
    } finally {
      raw.exec('DROP TRIGGER refuse_insert');
      raw.close();
    }

    assert.equal(JSON.stringify([store.getProfiles(), store.getProfileGroupMappings()]), before);
    assert.deepEqual(inForce(id), [group.id]);
  });
});

describe('POST /profiles/pull-apply with forms of one ID', () => {
  const apply = (body: unknown) =>
    adminFetch(server.baseUrl, session, '/api/admin/profiles/pull-apply', { method: 'POST', body });

  test('the audit entry names the upgrade, the granted access and the unresolved conflict', async (t) => {
    const [a, b, c] = [newGroup(t), newGroup(t), newGroup(t)];
    const upgrade = newId15();
    const granted = newId15();
    const conflict = newId15();
    localProfile(t, upgrade, 'Upgrade row', [a.id]);
    localProfile(t, granted, 'A empty');
    localProfile(t, to18(granted), 'B groups', [b.id]);
    localProfile(t, conflict, 'A conflict', [a.id]);
    localProfile(t, to18(conflict), 'B conflict', [c.id]);
    t.after(() => store.deleteProfile(to18(upgrade)));

    const res = await apply({
      upserts: [
        { id: to18(upgrade), name: `Upgraded ${upgrade}` },
        { id: to18(granted), name: `Granted ${granted}` },
        { id: to18(conflict), name: `Conflict ${conflict}` },
      ],
    });

    assert.equal(res.status, 200);
    assert.deepEqual(res.body.summary.affected.duplicatesUnresolved, [`Conflict ${conflict}`]);
    assert.deepEqual(res.body.profileGroupMappings.find((m: any) => m.profileId === to18(upgrade)).groupIds, [a.id]);
    const log = store.getPortalAdminLogs(1)[0];
    assert.equal(log.action, 'SYNC_PROFILES_FROM_ORG');
    assert.match(log.details, new RegExp(`18-character form: Upgraded ${upgrade}`));
    assert.match(log.details, new RegExp(`Duplicate rows merged: Granted ${granted}`));
    assert.ok(log.details.includes(`Granted ${granted} now grants ${b.name}`));
    assert.match(log.details, new RegExp(`groups differ: Conflict ${conflict}`));
  });
});

describe('portal review of a Profile sync', () => {
  const preview = (over: object) => ({
    orgId: 'o',
    instanceUrl: 'i',
    added: [],
    updated: [],
    removedFromOrg: [],
    duplicates: [],
    ...over,
  });
  const duplicate = (over: object) => ({
    id: 'x',
    name: 'X',
    rows: [],
    outcome: 'merge' as const,
    resultGroupNames: [],
    grantedGroupNames: [],
    ...over,
  });

  test('a sync with duplicates stops for review, as one with removals does', () => {
    assert.equal(profileSyncNeedsReview(preview({})), false);
    assert.equal(profileSyncNeedsReview(preview({ duplicates: [duplicate({})] })), true);
    assert.equal(profileSyncNeedsReview(preview({ removedFromOrg: [{ id: 'a', name: 'A', mappedGroupNames: [] }] })), true);
  });

  test('the review says what each duplicate does to access', () => {
    assert.match(describeProfileDuplicate(duplicate({})), /Access does not change/);
    assert.match(describeProfileDuplicate(duplicate({ grantedGroupNames: ['Sales', 'Ops'] })), /adds access.*Sales, Ops/);
    assert.match(describeProfileDuplicate(duplicate({ outcome: 'conflict' })), /Left unchanged/);
  });

  test('the result message does not read as clean when a Profile was left unsynced', () => {
    assert.equal(
      profileSyncResultMessage({ inserted: 1, updated: 2, affected: { duplicatesUnresolved: [] } }),
      'Synced Profiles from Salesforce Org (3 upserted)'
    );
    assert.match(profileSyncResultMessage({ affected: { duplicatesUnresolved: ['Sales'] } }), /Not synced.*Sales/);
    assert.equal(profileSyncResultMessage(null), 'Synced Profiles from Salesforce Org (0 upserted)');
  });
});
