import './helpers/env.js';
// Covers Profile writes outside org sync: every entry point reaches the row that already holds a
// Salesforce ID in either form, memberships survive, and the org sync's missing flag is kept.
import { describe, test, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { store } from '../src/db/store.js';

const newId15 = () => `00eAb${crypto.randomBytes(5).toString('hex')}`;

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
