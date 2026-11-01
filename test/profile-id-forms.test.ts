import './helpers/env.js';
// Covers Profile writes outside org sync: every entry point reaches the row that already holds a
// Salesforce ID in either form, memberships survive, and the org sync's missing flag is kept.
import { after, before, describe, test, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { store } from '../src/db/store.js';
import { resolveEffectiveProfilePermissions } from '../src/rbac/policyEngine.js';
import { salesforceIdsMatch } from '../src/salesforce/ids.js';
import { adminFetch, loginAsAdmin, startTestServer, type AdminSession, type TestServer } from './helpers/server.js';

const newId15 = () => `00eAb${crypto.randomBytes(5).toString('hex')}`;

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

function cleanUp(t: TestContext, ...ids: string[]) {
  t.after(() => {
    for (const id of ids) store.deleteProfile(id);
  });
}

describe('Profile missing_in_org outside org sync', () => {
  function flaggedProfile(t: TestContext) {
    const id = newId15();
    cleanUp(t, id);
    store.upsertProfile(id, 'Flagged');
    store.applyProfilesSyncFromOrg({ upserts: [], removeProfileIds: [], keptMissingProfileIds: [id] });
    assert.equal(store.getProfileById(id)?.missingInOrg, true);
    return id;
  }

  test('a manual save keeps the flag and reports it', (t) => {
    const id = flaggedProfile(t);
    const res = store.upsertProfile(id, 'Renamed');
    assert.equal(res.profile.missingInOrg, true);
    assert.equal(store.getProfileById(id)?.missingInOrg, true);
    assert.equal(store.getProfileById(id)?.name, 'Renamed');
  });

  test('a CSV re-import keeps the flag', (t) => {
    const id = flaggedProfile(t);
    store.importProfilesFromCsvRows([{ id, name: 'Reimported' }]);
    assert.equal(store.getProfileById(id)?.missingInOrg, true);
  });

  test('org sync still clears the flag when the Profile is back in the org', (t) => {
    const id = flaggedProfile(t);
    store.applyProfilesSyncFromOrg({ upserts: [{ id, name: 'Back' }], removeProfileIds: [] });
    assert.equal(store.getProfileById(id)?.missingInOrg, false);
  });

  test('a new row starts without the flag', (t) => {
    const id = newId15();
    cleanUp(t, id);
    assert.equal(store.upsertProfile(id, 'New').profile.missingInOrg, false);
    assert.equal(store.getProfileById(id)?.missingInOrg, false);
  });
});

describe('Profile ID forms outside org sync', () => {
  function newGroup(t: TestContext) {
    const group = store.upsertGroup({ name: `Forms group ${newId15()}`, allowedActions: [], objectPermissions: [] });
    t.after(() => store.deleteGroup(group.id));
    return group;
  }

  /** A stored row with one Access Group, its ID cleaned up under either form. */
  function mapped(t: TestContext, id: string, name: string) {
    const group = newGroup(t);
    store.upsertProfile(id, name);
    store.setProfileGroups(id, [group.id]);
    cleanUp(t, id.slice(0, 15), to18(id.slice(0, 15)));
    return group;
  }

  /** Two forms as an older version could leave them; upsertProfile can no longer create this. */
  function storedTwice(t: TestContext, rows: Array<{ id: string; name: string }>) {
    const raw = new DatabaseSync(process.env.DB_PATH as string);
    for (const { id, name } of rows) {
      raw.prepare('INSERT INTO sf_profiles (id, name, updated_at) VALUES (?, ?, ?)').run(id, name, new Date().toISOString());
    }
    raw.close();
    cleanUp(t, ...rows.map((r) => r.id));
  }

  const rowsOf = (id: string) => store.getProfiles().filter((p) => salesforceIdsMatch(p.id, id));
  const inForce = (id: string) => resolveEffectiveProfilePermissions(id).assignedGroups.map((g) => g.id);
  const groupsOf = (id: string) => store.getProfileGroupMappings().find((m) => m.profileId === id)?.groupIds || [];

  test('a 15-character form updates a stored 18-character row and adds none', (t) => {
    const id = newId15();
    const group = mapped(t, to18(id), 'Sales');

    const res = store.upsertProfile(id, 'Sales renamed');

    assert.equal(res.action, 'updated');
    assert.equal(res.profile.id, to18(id));
    assert.equal(res.previousId, undefined);
    assert.deepEqual(rowsOf(id).map((p) => [p.id, p.name]), [[to18(id), 'Sales renamed']]);
    assert.deepEqual(inForce(to18(id)), [group.id]);
  });

  test('an 18-character form upgrades a stored 15-character row and moves its memberships', (t) => {
    const id = newId15();
    const group = mapped(t, id, 'Sales');
    store.applyProfilesSyncFromOrg({ upserts: [], removeProfileIds: [], keptMissingProfileIds: [id] });

    const res = store.upsertProfile(to18(id), 'Sales');

    assert.equal(res.action, 'updated');
    assert.equal(res.previousId, id);
    assert.deepEqual(rowsOf(id).map((p) => p.id), [to18(id)]);
    assert.equal(store.getProfileById(id), null);
    assert.deepEqual(groupsOf(to18(id)), [group.id]);
    assert.deepEqual(inForce(id), [group.id]);
    assert.equal(store.getProfileById(to18(id))?.missingInOrg, true, 'an upgrade is not a sighting in the org');
  });

  test('an upgrade that fails partway leaves the row and its memberships untouched', (t) => {
    const id = newId15();
    const group = mapped(t, id, 'Sales');
    const raw = new DatabaseSync(process.env.DB_PATH as string);
    raw.exec(`CREATE TRIGGER refuse_delete BEFORE DELETE ON sf_profiles BEGIN SELECT RAISE(ABORT, 'forced failure'); END`);
    try {
      assert.throws(() => store.upsertProfile(to18(id), 'Sales'), /forced failure/);
    } finally {
      raw.exec('DROP TRIGGER refuse_delete');
      raw.close();
    }
    assert.deepEqual(rowsOf(id).map((p) => p.id), [id]);
    assert.deepEqual(groupsOf(id), [group.id]);
  });

  test('a stored 18-character ID is not replaced by another suffix', (t) => {
    const id = newId15();
    mapped(t, to18(id), 'Sales');
    cleanUp(t, `${id}aak`);
    const res = store.upsertProfile(`${id}aak`, 'Sales');
    assert.equal(res.profile.id, to18(id));
    assert.deepEqual(rowsOf(id).map((p) => p.id), [to18(id)]);
  });

  test('IDs that differ only by case stay separate Profiles', (t) => {
    const id = newId15();
    const other = id.replace('Ab', 'aB');
    cleanUp(t, id, other);
    store.upsertProfile(id, 'One');
    assert.equal(store.upsertProfile(other, 'Two').action, 'inserted');
    assert.equal(store.getProfileById(id)?.name, 'One');
  });

  test('CSV import counts other forms as updates and keeps access', (t) => {
    const stored18 = newId15();
    const stored15 = newId15();
    const fresh = newId15();
    cleanUp(t, fresh);
    const a = mapped(t, to18(stored18), 'CSV long');
    const b = mapped(t, stored15, 'CSV short');
    const before = store.getProfiles().length;

    const summary = store.importProfilesFromCsvRows([
      { id: stored18, name: 'CSV long' },
      { id: to18(stored15), name: 'CSV short' },
      { id: fresh, name: 'CSV new' },
    ]);

    assert.deepEqual(
      { inserted: summary.inserted, updated: summary.updated, idsUpgraded: summary.idsUpgraded, total: summary.total },
      { inserted: 1, updated: 2, idsUpgraded: 1, total: before + 1 }
    );
    assert.deepEqual(inForce(to18(stored18)), [a.id]);
    assert.deepEqual(inForce(stored15), [b.id]);
    assert.equal(store.getProfileById(stored15), null);
  });

  test('both forms in one CSV end as one row under the 18-character ID', (t) => {
    const id = newId15();
    cleanUp(t, id, to18(id));
    const summary = store.importProfilesFromCsvRows([
      { id, name: 'Twice' },
      { id: to18(id), name: 'Twice' },
    ]);
    assert.deepEqual([summary.inserted, summary.updated], [1, 1]);
    assert.deepEqual(rowsOf(id).map((p) => p.id), [to18(id)]);
  });

  describe('when both forms are already stored', () => {
    function twoForms(t: TestContext, firstName: string, secondName: string) {
      const id = newId15();
      storedTwice(t, [{ id, name: firstName }, { id: to18(id), name: secondName }]);
      const group = newGroup(t);
      return { id, group };
    }

    test('an update through either form goes to the row in force and adds none', (t) => {
      const { id, group } = twoForms(t, 'A in force', 'B other');
      store.setProfileGroups(id, [group.id]);

      const res = store.upsertProfile(to18(id), 'A renamed');

      assert.equal(res.profile.id, id);
      assert.equal(res.previousId, undefined);
      assert.deepEqual(rowsOf(id).map((p) => [p.id, p.name]), [[id, 'A renamed'], [to18(id), 'B other']]);
      assert.deepEqual(inForce(to18(id)), [group.id]);
    });

    test('a rename that would sort the row in force later keeps it in force', (t) => {
      const { id, group } = twoForms(t, 'Same', 'Same');
      store.setProfileGroups(id, [group.id]);

      const res = store.upsertProfile(id, 'Zed renamed');

      assert.equal(res.nameKept, undefined);
      assert.deepEqual(rowsOf(id).map((p) => p.id), [id, to18(id)], 'the lower ID still wins the tie');
      assert.deepEqual(inForce(to18(id)), [group.id]);
    });

    test('a rename that no row order can honour is refused and reported', (t) => {
      const id = newId15();
      storedTwice(t, [{ id: to18(id), name: 'A long in force' }, { id, name: 'B short' }]);
      const group = newGroup(t);
      store.setProfileGroups(to18(id), [group.id]);

      const res = store.upsertProfile(id, 'Zed renamed');

      assert.equal(res.nameKept, true);
      assert.equal(res.profile.name, 'A long in force');
      assert.deepEqual(rowsOf(id).map((p) => p.name), ['A long in force', 'B short']);
      assert.deepEqual(inForce(id), [group.id]);
      assert.equal(store.importProfilesFromCsvRows([{ id, name: 'Zed renamed' }]).namesKept, 1);
    });

    test('POST /profiles refuses that rename and audits no change', async (t) => {
      const id = newId15();
      storedTwice(t, [{ id: to18(id), name: 'A long in force' }, { id, name: 'B short' }]);
      const res = await adminFetch(server.baseUrl, session, '/api/admin/profiles', {
        method: 'POST',
        body: { id, name: 'Zed renamed' },
      });
      assert.equal(res.status, 409);
      assert.match(res.body.error, new RegExp(to18(id)));
      assert.equal(store.getProfileById(to18(id))?.name, 'A long in force');
      assert.equal(store.getPortalAdminLogs().some((l) => l.target.includes(id)), false);
    });
  });

  describe('POST /profiles', () => {
    const post = (body: object) => adminFetch(server.baseUrl, session, '/api/admin/profiles', { method: 'POST', body });

    test('a save under another form reaches the stored row and keeps access', async (t) => {
      const id = newId15();
      const group = mapped(t, to18(id), 'Sales');
      const res = await post({ id, name: 'Sales' });
      assert.equal(res.status, 200, JSON.stringify(res.body));
      assert.equal(res.body.profile.id, to18(id));
      assert.deepEqual(rowsOf(id).map((p) => p.id), [to18(id)]);
      assert.deepEqual(inForce(to18(id)), [group.id]);
    });

    test('a save under the 18-character form upgrades the row and audits the old ID', async (t) => {
      const id = newId15();
      const group = mapped(t, id, 'Sales');
      const res = await post({ id: to18(id), name: 'Sales' });
      assert.equal(res.status, 200, JSON.stringify(res.body));
      assert.deepEqual(rowsOf(id).map((p) => p.id), [to18(id)]);
      assert.deepEqual(groupsOf(to18(id)), [group.id]);
      const log = store.getPortalAdminLogs().find((l) => l.target.includes(to18(id)));
      assert.equal(log?.action, 'UPDATE_PROFILE');
      assert.match(log?.details || '', new RegExp(`upgraded from "${id}"`));
    });

    test('CSV import over HTTP reports another form as an update', async (t) => {
      const id = newId15();
      mapped(t, to18(id), 'Sales');
      const res = await adminFetch(server.baseUrl, session, '/api/admin/profiles/import-csv', {
        method: 'POST',
        body: { csvText: `id,name\r\n${id},Sales` },
      });
      assert.equal(res.status, 200, JSON.stringify(res.body));
      assert.deepEqual([res.body.summary.inserted, res.body.summary.updated], [0, 1]);
      assert.deepEqual(rowsOf(id).map((p) => p.id), [to18(id)]);
    });
  });
});
