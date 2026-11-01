import './helpers/env.js';
// The New Profile form used to submit a made-up ID that matched no real Profile. The portal and
// POST /profiles now share one format check, so a mistyped or empty-looking ID is caught on create.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { store } from '../src/db/store.js';
import { isSalesforceId, salesforceIdKey, salesforceIdsMatch } from '../src/salesforce/ids.js';
import { adminFetch, loginAsAdmin, startTestServer, type AdminSession, type TestServer } from './helpers/server.js';

const newId = (length: 15 | 18) => `00e${crypto.randomBytes(9).toString('hex')}`.slice(0, length);

let server: TestServer;
let session: AdminSession;

before(async () => {
  server = await startTestServer();
  session = await loginAsAdmin(server.baseUrl);
});

after(async () => {
  await server.close();
});

const post = (body: Record<string, unknown>) =>
  adminFetch(server.baseUrl, session, '/api/admin/profiles', { method: 'POST', body });

describe('isSalesforceId', () => {
  test('accepts 15 and 18 letters and digits, ignoring surrounding space', () => {
    for (const id of [newId(15), newId(18), ` ${newId(18)} `, '00e5g000001X9zAAAS']) {
      assert.equal(isSalesforceId(id), true, id);
    }
  });

  test('rejects other lengths and characters', () => {
    for (const id of ['', '00e', '00e5g000001X9z', '00e5g000001X9zAAA', '00e5g000001X9zAAASS', '00e5g000001-9zA', '00e5g 00001X9zA']) {
      assert.equal(isSalesforceId(id), false, id);
    }
  });

  test('ID matching across the 15 and 18 character forms is unchanged', () => {
    assert.equal(salesforceIdKey('00e5g000001X9zAAAS'), '00e5g000001X9zA');
    assert.equal(salesforceIdKey('not an id'), 'not an id');
    assert.ok(salesforceIdsMatch('00e5g000001X9zA', '00e5g000001X9zAAAS'));
  });
});

describe('POST /api/admin/profiles', () => {
  test('rejects a new ID of the wrong shape, stores nothing and audits nothing', async () => {
    const auditsBefore = store.getPortalAdminLogs(1_000_000).length;
    for (const id of ['00e123', 'not-a-salesforce-id', `${newId(15)}A`]) {
      const res = await post({ id, name: 'Bad ID' });
      assert.equal(res.status, 400, id);
      assert.match(res.body.error, /15 or 18/);
      assert.equal(store.getProfileById(id), null);
    }
    assert.equal(store.getPortalAdminLogs(1_000_000).length, auditsBefore);
  });

  test('accepts both lengths and trims', async () => {
    const short = newId(15);
    const long = newId(18);
    assert.equal((await post({ id: short, name: 'Short' })).status, 200);
    assert.equal((await post({ id: ` ${long} `, name: 'Long' })).status, 200);
    assert.equal(store.getProfileById(long)?.name, 'Long');
  });

  test('a row stored before this rule can still be renamed', async () => {
    const legacy = `legacy-${crypto.randomBytes(4).toString('hex')}`;
    store.upsertProfile(legacy, 'Legacy');
    const res = await post({ id: legacy, name: 'Legacy Renamed' });
    assert.equal(res.status, 200, JSON.stringify(res.body));
    assert.equal(store.getProfileById(legacy)?.name, 'Legacy Renamed');
  });
});
