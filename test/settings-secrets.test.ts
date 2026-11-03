import './helpers/env.js';
// Covers the stored JWT private key when it cannot be decrypted (usually a changed APP_SECRET_KEY):
// no settings write or failed connect may destroy the ciphertext, so restoring the key recovers it.
import { after, before, beforeEach, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { store } from '../src/db/store.js';
import { generateCertRequestBody } from '../src/components/views/orgConnectionState.js';
import { installSalesforceMock, type SalesforceMock } from './helpers/salesforceMock.js';
import { adminFetch, loginAsAdmin, startTestServer, type AdminSession, type TestServer } from './helpers/server.js';

let server: TestServer;
let session: AdminSession;
let sf: SalesforceMock;

before(async () => {
  sf = installSalesforceMock();
  server = await startTestServer();
  session = await loginAsAdmin(server.baseUrl);
});

after(async () => {
  sf.restore();
  await server.close();
});

const newPrivateKeyPem = () =>
  crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  }).privateKey;

/** What encryptSecret would have written under a different APP_SECRET_KEY. */
function encryptUnderAnotherKey(plaintext: string): string {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', crypto.randomBytes(32), iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return `${iv.toString('hex')}:${cipher.getAuthTag().toString('hex')}:${encrypted.toString('hex')}`;
}

function withRawDb<T>(fn: (db: DatabaseSync) => T): T {
  const db = new DatabaseSync(process.env.DB_PATH as string);
  try {
    return fn(db);
  } finally {
    db.close();
  }
}

const rawPrivateKeyEnc = () =>
  withRawDb(
    (db) =>
      (db.prepare('SELECT private_key_enc FROM sf_connection_settings WHERE id = 1').get() as { private_key_enc: string })
        .private_key_enc
  );

const setRawPrivateKeyEnc = (value: string) =>
  withRawDb((db) => db.prepare('UPDATE sf_connection_settings SET private_key_enc = ? WHERE id = 1').run(value));

const settingsRoute = (path: string, method: string, body: Record<string, unknown>) =>
  adminFetch(server.baseUrl, session, `/api/admin/sf-settings${path}`, { method, body });

describe('a stored private key that cannot be decrypted', () => {
  let planted: string;

  beforeEach(() => {
    sf.reset();
    store.updateSalesforceSettings({
      enabled: true,
      authMode: 'jwt_bearer',
      clientId: '3MVG9_TEST_CONNECTED_APP',
      username: 'integration@example.com',
      connectionStatus: 'disconnected',
      lastError: '',
    });
    planted = encryptUnderAnotherKey(newPrivateKeyPem());
    setRawPrivateKeyEnc(planted);
  });

  // First on purpose: the warning is once per process.
  test('warns the operator once, without the ciphertext', (t) => {
    const warn = t.mock.method(console, 'warn', () => {});

    store.getSalesforceSettings();
    store.getSalesforceSettingsWithSecrets();
    store.updateSalesforceSettings({ username: 'integration@example.com' });

    const warnings = warn.mock.calls.map((call) => String(call.arguments[0]));
    assert.equal(warnings.length, 1);
    assert.match(warnings[0], /private key cannot be decrypted/);
    assert.ok(!warnings[0].includes(planted));
  });

  test('reads as no usable key, while the store reports why', () => {
    assert.equal(store.getSalesforceSettings().hasPrivateKey, false);
    const secrets = store.getSalesforceSettingsWithSecrets();
    assert.equal(secrets.privateKeyPem, '');
    assert.equal(secrets.privateKeyUndecryptable, true);
  });

  test('survives a settings save, byte for byte, with or without a blank key', async () => {
    const saved = await settingsRoute('', 'PUT', { username: 'renamed@example.com' });
    assert.equal(saved.status, 200);
    assert.equal(saved.body.sfSettings.username, 'renamed@example.com');
    assert.equal(rawPrivateKeyEnc(), planted);

    const blank = await settingsRoute('', 'PUT', { privateKeyPem: '   ' });
    assert.equal(blank.status, 200);
    assert.equal(rawPrivateKeyEnc(), planted);
  });

  test('survives a rejected replacement key', async () => {
    const res = await settingsRoute('', 'PUT', { privateKeyPem: 'not a key' });
    assert.equal(res.status, 400);
    assert.equal(rawPrivateKeyEnc(), planted);
  });

  test('a failed connect says what is wrong, never reaches Salesforce, and keeps the key', async () => {
    const res = await settingsRoute('/connect', 'POST', {});

    assert.equal(res.status, 400);
    assert.match(res.body.error, /cannot be decrypted with the current APP_SECRET_KEY/);
    assert.equal(res.body.sfSettings.connectionStatus, 'error');
    assert.match(res.body.sfSettings.lastError, /cannot be decrypted/);
    assert.equal(sf.calls.length, 0);
    assert.equal(rawPrivateKeyEnc(), planted);
  });

  test('a failed connect that also saves settings keeps the key', async () => {
    const res = await settingsRoute('/connect', 'POST', { username: 'other@example.com', privateKeyPem: '' });

    assert.equal(res.status, 400);
    assert.match(res.body.error, /cannot be decrypted/);
    assert.equal(store.getSalesforceSettings().username, 'other@example.com');
    assert.equal(rawPrivateKeyEnc(), planted);
  });

  test('simulated mode reports the same error rather than asking for a key', async () => {
    store.updateSalesforceSettings({ authMode: 'simulated' });
    const res = await settingsRoute('/connect', 'POST', {});

    assert.equal(res.status, 400);
    assert.match(res.body.error, /cannot be decrypted/);
    assert.equal(rawPrivateKeyEnc(), planted);
  });

  test('org sync through the stored key reports the same error', async () => {
    const res = await adminFetch(server.baseUrl, session, '/api/admin/profiles/pull-preview', {
      method: 'POST',
      body: {},
    });

    assert.match(res.body.error, /cannot be decrypted/);
    assert.equal(sf.calls.length, 0);
    assert.equal(rawPrivateKeyEnc(), planted);
  });

  test('survives a disconnect', async () => {
    const res = await settingsRoute('/disconnect', 'POST', {});

    assert.equal(res.status, 200);
    assert.equal(res.body.sfSettings.connectionStatus, 'disconnected');
    assert.equal(rawPrivateKeyEnc(), planted);
  });

  test('corrupted ciphertext is kept too', async () => {
    const corrupted = 'not-valid-ciphertext';
    setRawPrivateKeyEnc(corrupted);

    assert.equal((await settingsRoute('', 'PUT', { username: 'x@example.com' })).status, 200);
    assert.equal((await settingsRoute('/connect', 'POST', {})).status, 400);
    assert.equal((await settingsRoute('/disconnect', 'POST', {})).status, 200);
    assert.equal(rawPrivateKeyEnc(), corrupted);
  });

  test('the settings response flags it as a boolean and carries no key material', async () => {
    const res = await adminFetch(server.baseUrl, session, '/api/admin/overview');
    assert.equal(res.status, 200);
    assert.equal(res.body.sfSettings.privateKeyUndecryptable, true);
    assert.equal(res.body.sfSettings.hasPrivateKey, false);
    const text = JSON.stringify(res.body);
    assert.ok(!text.includes(planted));
    assert.ok(!('privateKeyPem' in res.body.sfSettings));
  });

  for (const [why, body] of [
    ['no confirmation', {}],
    ['a confirmation that is not exactly true', { confirmReplaceUndecryptableKey: 'true' }],
  ] as const) {
    test(`generate-cert refuses to overwrite it with ${why}, and logs the refusal`, async () => {
      const res = await settingsRoute('/generate-cert', 'POST', body);

      assert.equal(res.status, 409);
      assert.match(res.body.error, /APP_SECRET_KEY/);
      assert.equal(res.body.sfSettings.privateKeyUndecryptable, true);
      assert.ok(!('certificatePem' in res.body), 'a refusal generates nothing');
      assert.equal(rawPrivateKeyEnc(), planted, 'the ciphertext must survive');

      const refused = store.getPortalAdminLogs(200).find((row) => row.action === 'GENERATE_SF_JWT_CERT_DENIED');
      assert.ok(refused);
      assert.ok(!refused.details.includes(planted));
    });
  }

  test('generate-cert overwrites it once confirmed, and the audit log says the key was destroyed', async () => {
    const res = await settingsRoute('/generate-cert', 'POST', generateCertRequestBody('CN', 'destroy-undecryptable'));

    assert.equal(res.status, 200, JSON.stringify(res.body));
    assert.equal(res.body.sfSettings.hasPrivateKey, true);
    assert.equal(res.body.sfSettings.privateKeyUndecryptable, false);
    assert.notEqual(rawPrivateKeyEnc(), planted);

    const entry = store.getPortalAdminLogs(200).find((row) => row.action === 'GENERATE_SF_JWT_CERT');
    assert.ok(entry);
    assert.match(entry.details, /privateKeyReplaced: true\./);
    assert.match(entry.details, /undecryptableKeyDestroyed: true\./);
    assert.ok(!entry.details.includes(planted));
  });

  test('a key that decrypts needs no confirmation and logs no destruction', async () => {
    store.updateSalesforceSettings({ privateKeyPem: newPrivateKeyPem() });
    const res = await settingsRoute('/generate-cert', 'POST', {});
    assert.equal(res.status, 200, JSON.stringify(res.body));

    const entry = store.getPortalAdminLogs(200).find((row) => row.action === 'GENERATE_SF_JWT_CERT');
    assert.ok(entry);
    assert.match(entry.details, /undecryptableKeyDestroyed: false\./);
  });

  test('entering a new key replaces it and makes it usable again', async () => {
    const pem = newPrivateKeyPem();
    const res = await settingsRoute('', 'PUT', { privateKeyPem: pem });

    assert.equal(res.status, 200);
    assert.equal(res.body.sfSettings.hasPrivateKey, true);
    assert.notEqual(rawPrivateKeyEnc(), planted);
    const secrets = store.getSalesforceSettingsWithSecrets();
    assert.equal(secrets.privateKeyPem.trim(), pem.trim());
    assert.equal(secrets.privateKeyUndecryptable, false);
  });
});

describe('a stored private key that decrypts', () => {
  test('stays usable and byte-identical across other settings writes and a connect', async () => {
    const pem = newPrivateKeyPem();
    store.updateSalesforceSettings({ authMode: 'simulated', privateKeyPem: pem });
    const stored = rawPrivateKeyEnc();

    assert.equal((await settingsRoute('', 'PUT', { username: 'kept@example.com' })).status, 200);
    assert.equal((await settingsRoute('/connect', 'POST', {})).status, 200);
    assert.equal((await settingsRoute('/disconnect', 'POST', {})).status, 200);

    assert.equal(rawPrivateKeyEnc(), stored);
    assert.equal(store.getSalesforceSettingsWithSecrets().privateKeyPem.trim(), pem.trim());
    assert.equal(store.getSalesforceSettingsWithSecrets().privateKeyUndecryptable, false);
    assert.equal(store.getSalesforceSettings().hasPrivateKey, true);
  });
});
