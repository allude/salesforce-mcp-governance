import { TEST_ADMIN } from './helpers/env.js';
// Unit tests for src/db/store.ts against the throwaway SQLite database configured by
// test/helpers/env.ts: schema initialisation, the bootstrap admin and portal users, profiles,
// objects/fields, groups and the profile-group matrix, the sanitized audit logs, the Okta and
// Salesforce settings singletons, and the SFDX parser + local-folder import.
//
// A second node:sqlite connection on the same database file reads raw rows, so the tests check what
// is really stored at rest (password hashes, ciphertext, sanitized payloads, cascades).
//
// All test files of a run may share this database, so every test uses unique ids/names and removes
// what it creates. Tests that change a singleton row (Okta config, Salesforce settings) or hide the
// other portal users are fully synchronous and put the original rows back in `finally`, so no other
// test can run (or observe the temporary state) in between.
import { after, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync, type SQLInputValue, type SQLOutputValue } from 'node:sqlite';
import { testTmpDir } from './helpers/env.js';
import { store, parseSfdxFilesToObjects } from '../src/db/store.js';
import type { SalesforceConnectionSettings } from '../src/types/governance.js';

const BOOTSTRAP_USERNAME = 'admin';
const BOOTSTRAP_PASSWORD = TEST_ADMIN.password;

/** Short random suffix for unique ids and names (the database may be shared with other test files). */
const uid = () => crypto.randomBytes(4).toString('hex');

// ---------------------------------------------------------------------------------------------
// Raw access to the store's database file through a separate connection
// ---------------------------------------------------------------------------------------------
const raw = new DatabaseSync(process.env.DB_PATH!, { timeout: 5_000 });
after(() => raw.close());

function rawGet<T>(sql: string, ...params: SQLInputValue[]): T | undefined {
  return raw.prepare(sql).get(...params) as unknown as T | undefined;
}

function rawAll<T>(sql: string, ...params: SQLInputValue[]): T[] {
  return raw.prepare(sql).all(...params) as unknown as T[];
}

function rawCount(sql: string, ...params: SQLInputValue[]): number {
  return Number(rawGet<{ n: number | bigint }>(sql, ...params)?.n);
}

interface PortalUserRow {
  username: string;
  display_name: string;
  password_hash: string;
  password_salt: string;
  role: string;
  created_at: string;
  last_login_at: string | null;
}

const pbkdf2Sha512Hex = (password: string, salt: string) =>
  crypto.pbkdf2Sync(password, salt, 100_000, 64, 'sha512').toString('hex');

/** Runs `fn` (synchronously), then writes the singleton row (id = 1) of `table` back exactly as it was. */
function restoringSingleton<T>(table: 'okta_config' | 'sf_connection_settings', fn: () => T): T {
  const saved = raw.prepare(`SELECT * FROM ${table} WHERE id = 1`).get();
  assert.ok(saved, `${table} has no singleton row`);
  try {
    return fn();
  } finally {
    const columns = Object.keys(saved).filter((c) => c !== 'id');
    raw
      .prepare(`UPDATE ${table} SET ${columns.map((c) => `${c} = ?`).join(', ')} WHERE id = 1`)
      .run(...columns.map((c) => saved[c]));
  }
}

/**
 * Synchronously removes every portal user except the bootstrap admin, runs `fn`, then puts every
 * removed row back with its original rowid. Lets a test reach the "last remaining administrator"
 * state even when other test files have created portal users in the shared database.
 */
function withOnlyTheBootstrapAdmin(fn: () => void): void {
  const saved = rawAll<Record<string, SQLOutputValue>>('SELECT rowid AS row_id, * FROM portal_users');
  raw.prepare('DELETE FROM portal_users WHERE username <> ?').run(BOOTSTRAP_USERNAME);
  try {
    fn();
  } finally {
    const reinsert = raw.prepare(
      `INSERT OR IGNORE INTO portal_users
         (rowid, username, display_name, password_hash, password_salt, role, created_at, last_login_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    );
    for (const r of saved) {
      reinsert.run(
        r.row_id,
        r.username,
        r.display_name,
        r.password_hash,
        r.password_salt,
        r.role,
        r.created_at,
        r.last_login_at
      );
    }
  }
}

// Captured when this module loads, before any test of the run has started (node:test imports every
// test file before it runs a single test, also with --test-isolation=none).
const portalUsersAtLoad = store.getPortalUsers();
const bootstrapRowAtLoad = rawGet<PortalUserRow>(
  'SELECT * FROM portal_users WHERE username = ?',
  BOOTSTRAP_USERNAME
);
const sfSettingsAtLoad = store.getSalesforceSettings();

// ---------------------------------------------------------------------------------------------
// Lookup helpers
// ---------------------------------------------------------------------------------------------
type ParsedObject = ReturnType<typeof parseSfdxFilesToObjects>[number];

function parsedObject(parsed: ParsedObject[], objectName: string): ParsedObject {
  const found = parsed.find((o) => o.objectName === objectName);
  assert.ok(found, `object ${objectName} was not parsed (got: ${parsed.map((o) => o.objectName).join(', ')})`);
  return found;
}

function parsedField(obj: ParsedObject, fieldName: string) {
  const found = obj.fields.find((f) => f.fieldName === fieldName);
  assert.ok(
    found,
    `field ${obj.objectName}.${fieldName} was not parsed (got: ${obj.fields.map((f) => f.fieldName).join(', ')})`
  );
  return found;
}

function assertHasStandardIdAndName(obj: ParsedObject): void {
  const id = parsedField(obj, 'Id');
  assert.equal(id.fieldType, 'Id');
  assert.equal(id.required, true);
  assert.equal(id.isCustom, false);
  assert.equal(parsedField(obj, 'Name').isCustom, false);
}

function storedObject(objectName: string) {
  const found = store.getObjects().find((o) => o.objectName === objectName);
  assert.ok(found, `object ${objectName} is not stored`);
  return found;
}

function storedField(objectName: string, fieldName: string) {
  const found = storedObject(objectName).fields.find((f) => f.fieldName === fieldName);
  assert.ok(found, `field ${objectName}.${fieldName} is not stored`);
  return found;
}

/** Sorted group ids the matrix maps to a profile ([] when the profile has none). */
function groupIdsOf(profileId: string): string[] {
  const mapping = store.getProfileGroupMappings().find((m) => m.profileId === profileId);
  return [...(mapping?.groupIds ?? [])].sort();
}

const newGroup = (prefix: string) =>
  store.upsertGroup({ name: `${prefix} ${uid()}`, allowedActions: [], objectPermissions: [] });

// ---------------------------------------------------------------------------------------------
// SFDX / Metadata API fixtures
// ---------------------------------------------------------------------------------------------
const INVOICE_OBJECT_META_XML = `<?xml version="1.0" encoding="UTF-8"?>
<CustomObject xmlns="http://soap.sforce.com/2006/04/metadata">
    <deploymentStatus>Deployed</deploymentStatus>
    <enableActivities>true</enableActivities>
    <label>Invoice</label>
    <nameField>
        <displayFormat>INV-{0000}</displayFormat>
        <label>Invoice Number</label>
        <type>AutoNumber</type>
    </nameField>
    <pluralLabel>Invoices</pluralLabel>
    <sharingModel>ReadWrite</sharingModel>
</CustomObject>
`;

const AMOUNT_FIELD_META_XML = `<?xml version="1.0" encoding="UTF-8"?>
<CustomField xmlns="http://soap.sforce.com/2006/04/metadata">
    <fullName>Amount__c</fullName>
    <externalId>false</externalId>
    <label>Invoice Amount</label>
    <precision>18</precision>
    <required>true</required>
    <scale>2</scale>
    <type>Currency</type>
</CustomField>
`;

const DUE_DATE_FIELD_META_XML = `<?xml version="1.0" encoding="UTF-8"?>
<CustomField xmlns="http://soap.sforce.com/2006/04/metadata">
    <fullName>Due_Date__c</fullName>
    <label>Due Date</label>
    <required>false</required>
    <type>Date</type>
</CustomField>
`;

const TIER_FIELD_META_XML = `<?xml version="1.0" encoding="UTF-8"?>
<CustomField xmlns="http://soap.sforce.com/2006/04/metadata">
    <fullName>Tier__c</fullName>
    <label>Customer Tier</label>
    <required>false</required>
    <type>Picklist</type>
    <valueSet>
        <valueSetDefinition>
            <sorted>false</sorted>
            <value>
                <fullName>Gold</fullName>
                <default>false</default>
                <label>Gold</label>
            </value>
        </valueSetDefinition>
    </valueSet>
</CustomField>
`;

// Classic Metadata API format: elements in the order Salesforce returns them, so the inline
// <fields> blocks come before any top-level <label>. A standard object such as Case has none.
const CASE_CLASSIC_OBJECT_XML = `<?xml version="1.0" encoding="UTF-8"?>
<CustomObject xmlns="http://soap.sforce.com/2006/04/metadata">
    <fields>
        <fullName>Resolution_Notes__c</fullName>
        <externalId>false</externalId>
        <label>Resolution Notes</label>
        <length>32768</length>
        <type>LongTextArea</type>
        <visibleLines>5</visibleLines>
    </fields>
    <fields>
        <fullName>Severity__c</fullName>
        <externalId>false</externalId>
        <label>Severity Level</label>
        <required>true</required>
        <type>Picklist</type>
    </fields>
    <fields>
        <fullName>Subject</fullName>
        <trackHistory>false</trackHistory>
    </fields>
    <listViews>
        <fullName>AllOpenCases</fullName>
        <filterScope>Everything</filterScope>
        <label>All Open Cases</label>
    </listViews>
    <sharingModel>ReadWrite</sharingModel>
</CustomObject>
`;

const SHIPMENT_CLASSIC_OBJECT_XML = `<?xml version="1.0" encoding="UTF-8"?>
<CustomObject xmlns="http://soap.sforce.com/2006/04/metadata">
    <deploymentStatus>Deployed</deploymentStatus>
    <fields>
        <fullName>Tracking_Number__c</fullName>
        <externalId>true</externalId>
        <label>Tracking Number</label>
        <length>40</length>
        <required>false</required>
        <type>Text</type>
        <unique>true</unique>
    </fields>
    <label>Shipment</label>
    <listViews>
        <fullName>All</fullName>
        <filterScope>Everything</filterScope>
        <label>All</label>
    </listViews>
    <nameField>
        <label>Shipment Name</label>
        <type>Text</type>
    </nameField>
    <pluralLabel>Shipments</pluralLabel>
    <sharingModel>ReadWrite</sharingModel>
</CustomObject>
`;

// =============================================================================================
// 1. SQLite initialisation
// =============================================================================================
describe('store: SQLite initialisation', () => {
  const SCHEMA_TABLES = [
    'portal_users',
    'sf_profiles',
    'sf_objects',
    'sf_object_fields',
    'access_groups',
    'profile_group_memberships',
    'mcp_copilot_logs',
    'portal_admin_logs',
    'okta_config',
    'sf_connection_settings',
  ];

  test('creates every table of the schema block', () => {
    const tables = rawAll<{ name: string }>("SELECT name FROM sqlite_master WHERE type = 'table'").map(
      (r) => r.name
    );
    for (const table of SCHEMA_TABLES) {
      assert.ok(tables.includes(table), `table ${table} is missing (found: ${tables.join(', ')})`);
    }
  });

  test('puts the database in WAL journal mode', () => {
    assert.equal(rawGet<{ journal_mode: string }>('PRAGMA journal_mode')?.journal_mode, 'wal');
  });

  test('seeds exactly one row (id 1) in each settings singleton table', () => {
    for (const table of ['okta_config', 'sf_connection_settings']) {
      assert.deepEqual(
        rawAll<{ id: number }>(`SELECT id FROM ${table}`).map((r) => Number(r.id)),
        [1],
        `${table} must hold exactly the singleton row`
      );
    }
  });

  test('enforces foreign keys: deleting a profile cascades its group memberships', (t) => {
    const profileId = `00eFKP${uid()}`;
    const group = newGroup('FK profile cascade');
    t.after(() => {
      store.deleteProfile(profileId);
      store.deleteGroup(group.id);
    });
    store.upsertProfile(profileId, 'FK cascade profile');
    store.setProfileGroups(profileId, [group.id]);
    const memberships = () =>
      rawCount('SELECT COUNT(*) AS n FROM profile_group_memberships WHERE profile_id = ?', profileId);
    assert.equal(memberships(), 1);

    assert.equal(store.deleteProfile(profileId), true);

    assert.equal(memberships(), 0, 'the membership row must be deleted with its profile');
    assert.equal(rawCount('SELECT COUNT(*) AS n FROM profile_group_memberships WHERE group_id = ?', group.id), 0);
  });

  test('enforces foreign keys: deleting a group cascades its profile memberships', (t) => {
    const profileId = `00eFKG${uid()}`;
    const deleted = newGroup('FK group cascade deleted');
    const kept = newGroup('FK group cascade kept');
    t.after(() => {
      store.deleteProfile(profileId);
      store.deleteGroup(deleted.id);
      store.deleteGroup(kept.id);
    });
    store.upsertProfile(profileId, 'FK cascade group');
    store.setProfileGroups(profileId, [deleted.id, kept.id]);
    assert.equal(rawCount('SELECT COUNT(*) AS n FROM profile_group_memberships WHERE group_id = ?', deleted.id), 1);

    assert.equal(store.deleteGroup(deleted.id), true);

    assert.equal(
      rawCount('SELECT COUNT(*) AS n FROM profile_group_memberships WHERE group_id = ?', deleted.id),
      0,
      'the membership row must be deleted with its group'
    );
    assert.deepEqual(groupIdsOf(profileId), [kept.id]);
  });
});

// =============================================================================================
// 2. Bootstrap admin and portal users
// =============================================================================================
describe('store: bootstrap admin and portal users', () => {
  test('seeds exactly one portal user, the bootstrap admin', () => {
    assert.deepEqual(
      portalUsersAtLoad.map((u) => ({ username: u.username, displayName: u.displayName, role: u.role })),
      [{ username: BOOTSTRAP_USERNAME, displayName: 'Portal Administrator', role: 'Super Admin' }]
    );
    assert.equal(
      rawCount('SELECT COUNT(*) AS n FROM portal_users WHERE lower(username) = ?', BOOTSTRAP_USERNAME),
      1
    );
  });

  test('verifyPortalUserCredentials accepts the bootstrap password with a case-insensitive username', () => {
    for (const username of ['admin', 'ADMIN', '  Admin  ']) {
      const user = store.verifyPortalUserCredentials(username, BOOTSTRAP_PASSWORD);
      assert.ok(user, `sign-in as "${username}" should succeed`);
      assert.equal(user.username, BOOTSTRAP_USERNAME);
      assert.equal(user.role, 'Super Admin');
      assert.ok(user.lastLoginAt && !Number.isNaN(Date.parse(user.lastLoginAt)), 'lastLoginAt is set');
    }
    const stored = store.getPortalUsers().find((u) => u.username === BOOTSTRAP_USERNAME);
    assert.ok(stored?.lastLoginAt, 'the last sign-in time is persisted');
  });

  test('verifyPortalUserCredentials returns null for a wrong password or an unknown user', () => {
    assert.equal(store.verifyPortalUserCredentials(BOOTSTRAP_USERNAME, 'wrong-password'), null);
    assert.equal(store.verifyPortalUserCredentials(BOOTSTRAP_USERNAME, BOOTSTRAP_PASSWORD.toUpperCase()), null);
    assert.equal(store.verifyPortalUserCredentials(BOOTSTRAP_USERNAME, ''), null);
    assert.equal(store.verifyPortalUserCredentials(`nobody-${uid()}`, BOOTSTRAP_PASSWORD), null);
  });

  test('stores the bootstrap password as a salted PBKDF2-SHA512 hash, never as plaintext', () => {
    const row = bootstrapRowAtLoad;
    assert.ok(row, 'the bootstrap admin row exists');
    assert.match(row.password_hash, /^[0-9a-f]{128}$/);
    assert.match(row.password_salt, /^[0-9a-f]{32}$/);
    for (const [column, value] of Object.entries(row)) {
      assert.ok(!String(value).includes(BOOTSTRAP_PASSWORD), `column ${column} contains the plaintext password`);
    }
    assert.equal(row.password_hash, pbkdf2Sha512Hex(BOOTSTRAP_PASSWORD, row.password_salt));
  });

  test('upsertPortalUser re-hashes the password with a fresh salt on every save', (t) => {
    const username = `store-rehash-${uid()}`;
    const readRow = () => rawGet<PortalUserRow>('SELECT * FROM portal_users WHERE username = ?', username);
    t.after(() => store.deletePortalUser(username));

    store.upsertPortalUser({ username, displayName: 'Rehash Test', password: 'First-Passw0rd!' });
    const first = readRow();
    store.upsertPortalUser({ username, displayName: 'Rehash Test', password: 'First-Passw0rd!' });
    const second = readRow();

    assert.ok(first && second);
    assert.match(second.password_salt, /^[0-9a-f]{32}$/);
    assert.notEqual(second.password_salt, first.password_salt, 'a new salt is generated');
    assert.notEqual(second.password_hash, first.password_hash, 'so the stored hash changes too');
    assert.equal(second.password_hash, pbkdf2Sha512Hex('First-Passw0rd!', second.password_salt));

    store.upsertPortalUser({ username, displayName: 'Rehash Test', password: 'Second-Passw0rd!' });
    assert.equal(store.verifyPortalUserCredentials(username, 'First-Passw0rd!'), null);
    assert.equal(store.verifyPortalUserCredentials(username, 'Second-Passw0rd!')?.username, username);
  });

  test('upsertPortalUser treats usernames case-insensitively, like sign-in does', (t) => {
    const username = `store-case-${uid()}`;
    const shouted = username.toUpperCase();
    t.after(() => {
      for (const name of [shouted, username]) {
        if (store.getPortalUsers().some((u) => u.username === name)) store.deletePortalUser(name);
      }
    });

    store.upsertPortalUser({ username: shouted, displayName: 'Case Test', password: 'Original-Passw0rd!' });
    // Rotating the password of the same account, with the username typed in lower case:
    store.upsertPortalUser({ username, displayName: 'Case Test', password: 'Rotated-Passw0rd!' });

    const accounts = store.getPortalUsers().filter((u) => u.username.toLowerCase() === username);
    assert.equal(
      accounts.length,
      1,
      `expected a single account, found ${accounts.length}: ${accounts.map((u) => u.username).join(', ')}`
    );
    assert.equal(store.verifyPortalUserCredentials(username, 'Original-Passw0rd!'), null, 'the old password stops working');
    assert.ok(store.verifyPortalUserCredentials(username, 'Rotated-Passw0rd!'), 'the rotated password works');
  });

  test('deletePortalUser deletes a user while another administrator remains', () => {
    const username = `store-delete-${uid()}`;
    store.upsertPortalUser({ username, displayName: 'Delete Test', password: 'Delete-Passw0rd!' });

    assert.equal(store.deletePortalUser(`missing-${uid()}`), false);
    assert.equal(store.deletePortalUser(username), true);

    assert.equal(store.getPortalUsers().some((u) => u.username === username), false);
    assert.equal(store.verifyPortalUserCredentials(username, 'Delete-Passw0rd!'), null);
  });

  test('deletePortalUser refuses to delete the last remaining portal administrator', () => {
    withOnlyTheBootstrapAdmin(() => {
      assert.deepEqual(
        store.getPortalUsers().map((u) => u.username),
        [BOOTSTRAP_USERNAME]
      );
      assert.throws(() => store.deletePortalUser(BOOTSTRAP_USERNAME), /last remaining portal administrator/);
      assert.ok(
        store.verifyPortalUserCredentials(BOOTSTRAP_USERNAME, BOOTSTRAP_PASSWORD),
        'the last administrator can still sign in'
      );
    });
  });
});

// =============================================================================================
// 3. Profiles
// =============================================================================================
describe('store: profiles', () => {
  test('upsertProfile reports inserted for a new id, then updated for the same id', (t) => {
    const id = `00eUPS${uid()}`;
    t.after(() => store.deleteProfile(id));

    const first = store.upsertProfile(`  ${id}  `, '  Sales Rep  ');
    assert.equal(first.action, 'inserted');
    assert.deepEqual({ id: first.profile.id, name: first.profile.name }, { id, name: 'Sales Rep' });

    const second = store.upsertProfile(id, 'Senior Sales Rep');
    assert.equal(second.action, 'updated');
    assert.equal(store.getProfileById(id)?.name, 'Senior Sales Rep');
    assert.equal(store.getProfiles().filter((p) => p.id === id).length, 1);
  });

  test('importProfilesFromCsvRows counts inserted and updated rows and skips rows without an id or name', (t) => {
    const existing = `00eCSV${uid()}`;
    const newA = `00eCSV${uid()}`;
    const newB = `00eCSV${uid()}`;
    const withoutName = `00eCSV${uid()}`;
    const orphanName = `CSV row without id ${uid()}`;
    t.after(() => {
      for (const id of [existing, newA, newB, withoutName]) store.deleteProfile(id);
    });
    store.upsertProfile(existing, 'Before CSV import');

    const summary = store.importProfilesFromCsvRows([
      { id: newA, name: 'CSV Profile A' },
      { id: existing, name: 'After CSV import' },
      { id: '', name: orphanName },
      { id: withoutName, name: '' },
      { id: newB, name: 'CSV Profile B' },
    ]);

    assert.equal(summary.inserted, 2);
    assert.equal(summary.updated, 1);
    assert.equal(summary.total, store.getProfiles().length);
    assert.equal(store.getProfileById(newA)?.name, 'CSV Profile A');
    assert.equal(store.getProfileById(newB)?.name, 'CSV Profile B');
    assert.equal(store.getProfileById(existing)?.name, 'After CSV import');
    assert.equal(store.getProfileById(withoutName), null, 'a row without a name is skipped');
    assert.equal(store.getProfiles().some((p) => p.name === orphanName), false, 'a row without an id is skipped');
  });

  test('deleteProfile removes the profile and reports whether anything was deleted', () => {
    const id = `00eDEL${uid()}`;
    store.upsertProfile(id, 'Delete me');

    assert.equal(store.deleteProfile(id), true);
    assert.equal(store.getProfileById(id), null);
    assert.equal(store.deleteProfile(id), false);
  });
});

// =============================================================================================
// 4. Objects and fields
// =============================================================================================
describe('store: objects and fields', () => {
  test('upsertObjectWithFields without fields creates the default Id and Name fields', (t) => {
    const objectName = `StoreDefaults_${uid()}__c`;
    t.after(() => store.deleteObject(objectName));

    const saved = store.upsertObjectWithFields({ objectName: `  ${objectName}  ` });

    assert.equal(saved.objectName, objectName);
    assert.equal(saved.label, objectName);
    assert.equal(saved.isCustom, true);
    assert.equal(saved.enabled, true);
    assert.equal(saved.sourcePath, 'manual');
    assert.deepEqual(saved.fields, [
      { objectName, fieldName: 'Id', label: 'Record ID', fieldType: 'Id', isCustom: false, required: true, enabled: true },
      { objectName, fieldName: 'Name', label: 'Name', fieldType: 'Text', isCustom: false, required: false, enabled: true },
    ]);
    assert.equal(saved.fieldCount, 2);
    assert.equal(saved.enabledFieldCount, 2);
  });

  test('toggleObject and toggleObjectField persist the enabled flags', (t) => {
    const objectName = `StoreToggle_${uid()}__c`;
    t.after(() => store.deleteObject(objectName));
    store.upsertObjectWithFields({ objectName });

    assert.equal(store.toggleObject(objectName, false)?.enabled, false);
    const afterFieldOff = store.toggleObjectField(objectName, 'Name', false);
    assert.equal(afterFieldOff?.enabledFieldCount, 1);

    // Read back through a fresh query and straight from the table
    assert.equal(storedObject(objectName).enabled, false);
    assert.equal(storedField(objectName, 'Name').enabled, false);
    assert.equal(storedField(objectName, 'Id').enabled, true);
    assert.equal(rawGet<{ enabled: number }>('SELECT enabled FROM sf_objects WHERE object_name = ?', objectName)?.enabled, 0);
    assert.equal(
      rawGet<{ enabled: number }>(
        'SELECT enabled FROM sf_object_fields WHERE object_name = ? AND field_name = ?',
        objectName,
        'Name'
      )?.enabled,
      0
    );

    assert.equal(store.toggleObject(objectName, true)?.enabled, true);
    assert.equal(store.toggleObjectField(objectName, 'Name', true)?.enabledFieldCount, 2);
    assert.equal(storedObject(objectName).enabled, true);
    assert.equal(store.toggleObject(`StoreMissing_${uid()}__c`, true), null, 'unknown objects return null');
  });

  test('re-importing an object from SFDX keeps a field the admin switched off disabled', (t) => {
    const objectName = `StoreReimport_${uid()}__c`;
    t.after(() => store.deleteObject(objectName));
    const sfdxFiles = (amountType: string, amountLabel: string) => [
      {
        relativePath: `objects/${objectName}/${objectName}.object-meta.xml`,
        content: '<CustomObject><label>Re-import</label></CustomObject>',
      },
      {
        relativePath: `objects/${objectName}/fields/Amount__c.field-meta.xml`,
        content: `<CustomField><fullName>Amount__c</fullName><label>${amountLabel}</label><type>${amountType}</type></CustomField>`,
      },
      {
        relativePath: `objects/${objectName}/fields/Notes__c.field-meta.xml`,
        content: '<CustomField><fullName>Notes__c</fullName><label>Notes</label><type>TextArea</type></CustomField>',
      },
    ];

    store.importObjectsFromParsedSfdx(parseSfdxFilesToObjects(sfdxFiles('Currency', 'Amount')));
    store.toggleObjectField(objectName, 'Amount__c', false);
    const summary = store.importObjectsFromParsedSfdx(parseSfdxFilesToObjects(sfdxFiles('Number', 'Gross Amount')));

    assert.deepEqual(summary, { objectsImported: 1, fieldsImported: 4 });
    const amount = storedField(objectName, 'Amount__c');
    assert.equal(amount.enabled, false, "the admin's manual toggle must survive the re-import");
    assert.equal(amount.fieldType, 'Number', 'the re-import still refreshes the field metadata');
    assert.equal(amount.label, 'Gross Amount');
    assert.equal(storedField(objectName, 'Notes__c').enabled, true);
  });

  test('re-importing an object from SFDX keeps an object the admin switched off disabled', (t) => {
    const objectName = `StoreReimportObj_${uid()}__c`;
    t.after(() => store.deleteObject(objectName));
    const metaFile = (label: string) => ({
      relativePath: `objects/${objectName}/${objectName}.object-meta.xml`,
      content: `<CustomObject><label>${label}</label></CustomObject>`,
    });

    store.importObjectsFromParsedSfdx(parseSfdxFilesToObjects([metaFile('Before')]));
    store.toggleObject(objectName, false);
    store.importObjectsFromParsedSfdx(parseSfdxFilesToObjects([metaFile('After')]));

    const obj = storedObject(objectName);
    assert.equal(obj.enabled, false);
    assert.equal(obj.label, 'After');
  });

  test('deleteObject removes the object and cascades its fields', () => {
    const objectName = `StoreDelete_${uid()}__c`;
    const fieldRows = () => rawCount('SELECT COUNT(*) AS n FROM sf_object_fields WHERE object_name = ?', objectName);
    store.upsertObjectWithFields({
      objectName,
      fields: [
        { fieldName: 'Id', fieldType: 'Id', required: true },
        { fieldName: 'Status__c', fieldType: 'Picklist' },
        { fieldName: 'Notes__c' },
      ],
    });
    assert.equal(fieldRows(), 3);

    assert.equal(store.deleteObject(objectName), true);

    assert.equal(fieldRows(), 0, 'field rows must be deleted with their object');
    assert.equal(store.getObjects().some((o) => o.objectName === objectName), false);
    assert.equal(store.deleteObject(objectName), false);
  });
});

// =============================================================================================
// 5. Groups and the profile-group matrix
// =============================================================================================
describe('store: groups and profile-group mappings', () => {
  test('upsertGroup creates a group with a generated id, then updates it in place by id', (t) => {
    const suffix = uid();
    const created = store.upsertGroup({
      name: `Store Group ${suffix}`,
      description: 'first version',
      allowedActions: ['list_enabled_objects'],
      objectPermissions: [],
    });
    t.after(() => store.deleteGroup(created.id));
    assert.match(created.id, new RegExp(`^grp_store_group_${suffix}_[a-z0-9]+$`));

    const updated = store.upsertGroup({
      id: created.id,
      name: `Store Group ${suffix} renamed`,
      description: 'second version',
      allowedActions: ['soql_query'],
      objectPermissions: [],
    });

    assert.equal(updated.id, created.id);
    assert.equal(updated.name, `Store Group ${suffix} renamed`);
    assert.equal(updated.description, 'second version');
    assert.deepEqual(updated.allowedActions, ['soql_query']);
    const groups = store.getGroups();
    assert.equal(groups.filter((g) => g.id === created.id).length, 1);
    assert.equal(groups.some((g) => g.name === `Store Group ${suffix}`), false, 'no copy under the old name');
  });

  test('upsertGroup round-trips allowedActions and objectPermissions through JSON', (t) => {
    const allowedActions = ['list_enabled_objects', 'soql_query', 'get_record', 'create_record'];
    const objectPermissions = [
      {
        objectName: 'Account',
        canRead: true,
        canCreate: false,
        canUpdate: true,
        canDelete: false,
        allowedFields: ['Id', 'Name', 'Industry'],
      },
      {
        objectName: 'Invoice__c',
        canRead: true,
        canCreate: true,
        canUpdate: true,
        canDelete: true,
        allowedFields: ['Id', 'Amount__c'],
      },
    ];
    const saved = store.upsertGroup({ name: `Store JSON ${uid()}`, allowedActions, objectPermissions });
    t.after(() => store.deleteGroup(saved.id));

    const reread = store.getGroups().find((g) => g.id === saved.id);
    assert.ok(reread);
    assert.deepEqual(reread.allowedActions, allowedActions);
    assert.deepEqual(reread.objectPermissions, objectPermissions);
    const row = rawGet<{ allowed_actions_json: string; object_permissions_json: string }>(
      'SELECT allowed_actions_json, object_permissions_json FROM access_groups WHERE id = ?',
      saved.id
    );
    assert.ok(row);
    assert.deepEqual(JSON.parse(row.allowed_actions_json), allowedActions);
    assert.deepEqual(JSON.parse(row.object_permissions_json), objectPermissions);
  });

  test('deleteGroup removes the group and reports whether anything was deleted', () => {
    const group = newGroup('Store delete group');

    assert.equal(store.deleteGroup(group.id), true);
    assert.equal(store.getGroups().some((g) => g.id === group.id), false);
    assert.equal(store.deleteGroup(group.id), false);
  });

  test('setProfileGroups replaces the previous mapping', (t) => {
    const profileId = `00eSET${uid()}`;
    const g1 = newGroup('Store mapping one');
    const g2 = newGroup('Store mapping two');
    t.after(() => {
      store.deleteProfile(profileId);
      store.deleteGroup(g1.id);
      store.deleteGroup(g2.id);
    });
    store.upsertProfile(profileId, 'Store mapping profile');

    assert.deepEqual(store.setProfileGroups(profileId, [g1.id, g2.id]), { profileId, groupIds: [g1.id, g2.id] });
    assert.deepEqual(groupIdsOf(profileId), [g1.id, g2.id].sort());

    store.setProfileGroups(profileId, [g2.id]);
    assert.deepEqual(groupIdsOf(profileId), [g2.id]);

    store.setProfileGroups(profileId, []);
    assert.deepEqual(groupIdsOf(profileId), []);
    assert.equal(rawCount('SELECT COUNT(*) AS n FROM profile_group_memberships WHERE profile_id = ?', profileId), 0);
  });

  test('getProfileGroupMappings lists every profile, including profiles with no groups', (t) => {
    const mapped = `00eMAP${uid()}`;
    const unmapped = `00eMAP${uid()}`;
    const group = newGroup('Store matrix');
    t.after(() => {
      store.deleteProfile(mapped);
      store.deleteProfile(unmapped);
      store.deleteGroup(group.id);
    });
    store.upsertProfile(mapped, 'Store mapped profile');
    store.upsertProfile(unmapped, 'Store unmapped profile');
    store.setProfileGroups(mapped, [group.id]);

    const mappings = store.getProfileGroupMappings();

    assert.deepEqual(mappings.find((m) => m.profileId === mapped), { profileId: mapped, groupIds: [group.id] });
    assert.deepEqual(mappings.find((m) => m.profileId === unmapped), { profileId: unmapped, groupIds: [] });
    assert.deepEqual(
      mappings.map((m) => m.profileId).sort(),
      store.getProfiles().map((p) => p.id).sort(),
      'exactly one mapping per profile'
    );
  });

  test('setProfileGroups keeps the previous mapping when one of the new group ids does not exist', (t) => {
    const profileId = `00eATM${uid()}`;
    const previous = newGroup('Store atomic previous');
    const next = newGroup('Store atomic next');
    t.after(() => {
      store.deleteProfile(profileId);
      store.deleteGroup(previous.id);
      store.deleteGroup(next.id);
    });
    store.upsertProfile(profileId, 'Store atomic mapping');
    store.setProfileGroups(profileId, [previous.id]);

    // e.g. a group another admin deleted while this admin's matrix screen was open
    assert.throws(
      () => store.setProfileGroups(profileId, [next.id, `grp_missing_${uid()}`]),
      /Unknown Access Group/
    );
    assert.deepEqual(groupIdsOf(profileId), [previous.id], 'a rejected update must leave the previous mapping intact');
  });
});

// =============================================================================================
// 6. Audit logs
// =============================================================================================
describe('store: audit logs', () => {
  type CopilotLogInput = Parameters<typeof store.recordCopilotMcpLog>[0];
  const copilotLog = (overrides: Partial<CopilotLogInput> = {}): CopilotLogInput => ({
    sfUsername: `rep.${uid()}@acme.example.com`,
    profileId: `00eLOG${uid()}`,
    profileName: 'Store Test Profile',
    matchedGroups: ['Store Test Readers'],
    toolName: 'soql_query',
    targetObject: 'Account',
    status: 'ALLOWED',
    latencyMs: 12,
    rawRequestPayload: {},
    rawResponseSummary: {},
    ...overrides,
  });

  /** Records a Copilot log and returns the sanitized payloads exactly as stored in the table. */
  function recordAndReadStored(rawRequestPayload: unknown, rawResponseSummary: unknown = {}) {
    const entry = store.recordCopilotMcpLog(copilotLog({ rawRequestPayload, rawResponseSummary }));
    const row = rawGet<{ sanitized_request_payload: string; sanitized_response_summary: string }>(
      'SELECT sanitized_request_payload, sanitized_response_summary FROM mcp_copilot_logs WHERE id = ?',
      entry.id
    );
    assert.ok(row, 'the log row is stored');
    return {
      request: JSON.parse(row.sanitized_request_payload),
      response: JSON.parse(row.sanitized_response_summary),
      storedText: `${row.sanitized_request_payload}\n${row.sanitized_response_summary}`,
    };
  }

  function assertNotStored(storedText: string, literals: string[]): void {
    for (const literal of literals) {
      assert.ok(!storedText.includes(literal), `the audit log stored the literal value "${literal}":\n${storedText}`);
    }
  }

  test('recordCopilotMcpLog persists every field and getCopilotMcpLogs returns the newest first', () => {
    const olderInput = copilotLog({
      toolName: 'delete_record',
      targetObject: 'Contact',
      status: 'DENIED',
      latencyMs: 3,
      matchedGroups: [],
    });
    const newerInput = copilotLog({
      matchedGroups: ['Store Test Readers', 'Store Test Writers'],
      latencyMs: 27,
      rawRequestPayload: { objectName: 'Account', limit: 10 },
      rawResponseSummary: { totalSize: 0, done: true },
    });
    const older = store.recordCopilotMcpLog(olderInput);
    const newer = store.recordCopilotMcpLog(newerInput);

    const [first, second] = store.getCopilotMcpLogs();

    assert.deepEqual(first, newer);
    assert.deepEqual(second, older);
    const { id, timestamp, sanitizedRequestPayload, sanitizedResponseSummary, ...fields } = first;
    assert.deepEqual(fields, {
      sfUsername: newerInput.sfUsername,
      profileId: newerInput.profileId,
      profileName: newerInput.profileName,
      matchedGroups: newerInput.matchedGroups,
      toolName: newerInput.toolName,
      targetObject: newerInput.targetObject,
      status: newerInput.status,
      latencyMs: newerInput.latencyMs,
    });
    assert.ok(id && id !== older.id, 'each entry gets its own id');
    assert.ok(!Number.isNaN(Date.parse(timestamp)) && timestamp >= older.timestamp);
    assert.deepEqual(JSON.parse(sanitizedRequestPayload), { objectName: 'Account', limit: 10 });
    assert.deepEqual(JSON.parse(sanitizedResponseSummary), { totalSize: 0, done: true });
  });

  test('sanitizing redacts every SOQL string literal but keeps the query shape', () => {
    const { request, storedText } = recordAndReadStored({
      soql: "SELECT Id, Name FROM Account WHERE Name = 'Acme Secret Corp' AND Owner.Email LIKE '%ceo@acme.example%' LIMIT 5",
    });

    assert.equal(
      request.soql,
      "SELECT Id, Name FROM Account WHERE Name = '[REDACTED]' AND Owner.Email LIKE '[REDACTED]' LIMIT 5"
    );
    assertNotStored(storedText, ['Acme Secret Corp', 'ceo@acme.example']);
  });

  test('sanitizing redacts SOQL string literals that contain escaped quotes', () => {
    // SOQL escapes a quote inside a string literal with a backslash (src/mcp/soqlGuard.ts accepts it).
    const { request, storedText } = recordAndReadStored({
      soql: "SELECT Id FROM Contact WHERE LastName = 'O\\'Malley-Secret' AND Email = 'jane.doe@acme.example'",
    });

    assertNotStored(storedText, ['Malley-Secret', 'jane.doe@acme.example']);
    assert.equal(request.soql, "SELECT Id FROM Contact WHERE LastName = '[REDACTED]' AND Email = '[REDACTED]'");
  });

  test('sanitizing replaces non-safe primitive values with their type', () => {
    const { request, storedText } = recordAndReadStored({
      customerEmail: 'jane.doe@acme.example',
      annualRevenue: 9_876_543,
      isVip: true,
    });

    assert.deepEqual(request, {
      customerEmail: '<REDACTED:string>',
      annualRevenue: '<REDACTED:number>',
      isVip: '<REDACTED:boolean>',
    });
    assertNotStored(storedText, ['jane.doe@acme.example', '9876543']);
  });

  test('sanitizing collapses records arrays to a redacted record count', () => {
    const { response, storedText } = recordAndReadStored(
      {},
      {
        totalSize: 2,
        done: true,
        records: [
          { attributes: { type: 'Account' }, Id: '001000000000001AAA', Name: 'Private Customer Record' },
          { attributes: { type: 'Account' }, Id: '001000000000002AAA', Name: 'Another Private Customer' },
        ],
      }
    );

    assert.deepEqual(response, { totalSize: 2, done: true, records: '[REDACTED 2 RECORDS]' });
    assertNotStored(storedText, ['Private Customer Record', 'Another Private Customer']);
  });

  test('sanitizing keeps the keys of nested create_record fields but redacts their values', () => {
    const { request, storedText } = recordAndReadStored({
      objectName: 'Contact',
      fields: {
        LastName: 'Doe-Secret',
        Email: 'jane.doe@acme.example',
        NumberOfEmployees__c: 42,
        MailingAddress: { street: '1 Secret Lane', city: 'Springfield' },
      },
    });

    assert.deepEqual(request, {
      objectName: 'Contact',
      fields: {
        LastName: '<REDACTED:string>',
        Email: '<REDACTED:string>',
        NumberOfEmployees__c: '<REDACTED:number>',
        MailingAddress: { street: '<REDACTED:string>', city: '<REDACTED:string>' },
      },
    });
    assertNotStored(storedText, ['Doe-Secret', 'jane.doe@acme.example', '1 Secret Lane', 'Springfield']);
  });

  test('sanitizing keeps safe keys verbatim: objectName, toolName, a fields array, limit and Id', () => {
    const payload = {
      toolName: 'get_record',
      objectName: 'Account',
      fields: ['Id', 'Name', 'Industry'],
      limit: 25,
      Id: '001000000000001AAA',
    };

    assert.deepEqual(recordAndReadStored(payload).request, payload);
  });

  test('recordPortalAdminLog persists the entry and defaults the IP address to 127.0.0.1', () => {
    const adminUsername = `store-admin-${uid()}`;
    const withoutIp = store.recordPortalAdminLog({
      adminUsername,
      authMethod: 'password',
      action: 'STORE_TEST_NO_IP',
      target: 'Store tests',
      details: 'IP address not given',
    });
    const withIp = store.recordPortalAdminLog({
      adminUsername,
      authMethod: 'okta_sso',
      action: 'STORE_TEST_WITH_IP',
      target: 'Store tests',
      details: 'IP address given',
      ipAddress: '203.0.113.7',
    });

    const [first, second] = store.getPortalAdminLogs();

    assert.deepEqual(first, withIp);
    assert.deepEqual(second, withoutIp);
    const { id, timestamp, ...fields } = second;
    assert.deepEqual(fields, {
      adminUsername,
      authMethod: 'password',
      action: 'STORE_TEST_NO_IP',
      target: 'Store tests',
      details: 'IP address not given',
      ipAddress: '127.0.0.1',
    });
    assert.ok(id && !Number.isNaN(Date.parse(timestamp)));
    assert.equal(first.ipAddress, '203.0.113.7');
    assert.equal(
      rawGet<{ ip_address: string }>('SELECT ip_address FROM portal_admin_logs WHERE id = ?', withoutIp.id)?.ip_address,
      '127.0.0.1'
    );
  });

  test('getCopilotMcpLogs honours its limit argument', () => {
    const ids = [1, 2, 3].map((latencyMs) => store.recordCopilotMcpLog(copilotLog({ latencyMs })).id);

    assert.deepEqual(store.getCopilotMcpLogs(2).map((l) => l.id), [ids[2], ids[1]]);
    assert.deepEqual(store.getCopilotMcpLogs(1).map((l) => l.id), [ids[2]]);
  });

  test('getPortalAdminLogs honours its limit argument', () => {
    const ids = [1, 2, 3].map(
      (n) =>
        store.recordPortalAdminLog({
          adminUsername: `store-admin-${uid()}`,
          authMethod: 'password',
          action: `STORE_TEST_LIMIT_${n}`,
          target: 'Store tests',
          details: `entry ${n}`,
        }).id
    );

    assert.deepEqual(store.getPortalAdminLogs(2).map((l) => l.id), [ids[2], ids[1]]);
    assert.deepEqual(store.getPortalAdminLogs(1).map((l) => l.id), [ids[2]]);
  });
});

// =============================================================================================
// 7. Okta SSO config
// =============================================================================================
describe('store: Okta SSO config', () => {
  const ENCRYPTED_SHAPE = /^[0-9a-f]{24}:[0-9a-f]{32}:[0-9a-f]+$/; // 12-byte IV : 16-byte GCM tag : ciphertext
  const storedSecretColumn = () =>
    rawGet<{ client_secret_enc: string }>('SELECT client_secret_enc FROM okta_config WHERE id = 1')?.client_secret_enc ??
    '';
  const newSecret = () => `okta-client-secret-${uid()}${uid()}`;

  test('updateOktaConfig stores the client secret encrypted (iv:tag:ciphertext), never in plaintext', () => {
    restoringSingleton('okta_config', () => {
      const secret = newSecret();
      const updated = store.updateOktaConfig({ clientSecret: secret });
      assert.equal(updated.hasClientSecret, true);
      assert.equal('clientSecret' in updated, false, 'the returned settings must not echo the secret');

      const stored = storedSecretColumn();
      assert.match(stored, ENCRYPTED_SHAPE);
      assert.ok(!stored.includes(secret), 'plaintext secret stored');
      assert.ok(!stored.includes(Buffer.from(secret).toString('hex')), 'hex-encoded plaintext is not encryption');

      // AES-256-GCM under the configured APP_SECRET_KEY
      const [ivHex, tagHex, dataHex] = stored.split(':');
      const decipher = crypto.createDecipheriv(
        'aes-256-gcm',
        Buffer.from(process.env.APP_SECRET_KEY!, 'hex'),
        Buffer.from(ivHex, 'hex')
      );
      decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
      const plaintext = Buffer.concat([decipher.update(Buffer.from(dataHex, 'hex')), decipher.final()]).toString('utf8');
      assert.equal(plaintext, secret);

      store.updateOktaConfig({ clientSecret: secret });
      assert.notEqual(storedSecretColumn(), stored, 'saving the same secret again uses a fresh IV');
    });
  });

  test('getOktaConfig decrypts the client secret and reports hasClientSecret', () => {
    restoringSingleton('okta_config', () => {
      const secret = newSecret();
      const clientId = `0oa${uid()}`;
      store.updateOktaConfig({ clientId, clientSecret: secret });

      const okta = store.getOktaConfig();

      assert.equal(okta.clientSecret, secret);
      assert.equal(okta.hasClientSecret, true);
      assert.equal(okta.clientId, clientId);
    });
  });

  test('updateOktaConfig without a clientSecret keeps the previous secret', () => {
    restoringSingleton('okta_config', () => {
      const secret = newSecret();
      store.updateOktaConfig({ clientSecret: secret });

      const clientId = `0oa${uid()}`;
      const afterOmitted = store.updateOktaConfig({ clientId });
      assert.equal(afterOmitted.clientId, clientId);
      assert.equal(afterOmitted.hasClientSecret, true);
      assert.equal(store.getOktaConfig().clientSecret, secret, 'an omitted clientSecret keeps the stored one');

      store.updateOktaConfig({ adminGroup: 'Store-Test-Admins', clientSecret: '' });
      assert.equal(store.getOktaConfig().clientSecret, secret, 'an empty clientSecret keeps the stored one');
      assert.equal(store.getOktaConfig().adminGroup, 'Store-Test-Admins');
    });
  });

  test('updateOktaConfig derives the issuer from oktaDomain when no issuer is given', () => {
    restoringSingleton('okta_config', () => {
      const domain = `dev-${uid()}.okta.com`;

      assert.equal(store.updateOktaConfig({ oktaDomain: domain }).issuer, `https://${domain}/oauth2/default`);
      assert.equal(
        store.updateOktaConfig({ oktaDomain: `https://${domain}` }).issuer,
        `https://${domain}/oauth2/default`,
        'a scheme on the domain is not doubled'
      );

      const customIssuer = `https://${domain}/oauth2/aus${uid()}`;
      assert.equal(store.updateOktaConfig({ oktaDomain: domain, issuer: customIssuer }).issuer, customIssuer);
      assert.equal(store.getOktaConfig().issuer, customIssuer);
    });
  });
});

// =============================================================================================
// 8. Salesforce connection settings
// =============================================================================================
describe('store: Salesforce connection settings', () => {
  const withoutTimestamp = ({ updatedAt, ...rest }: SalesforceConnectionSettings) => rest;

  test('seeds the defaults from SALESFORCE_LOGIN_URL and API version v62.0', () => {
    assert.deepEqual(withoutTimestamp(sfSettingsAtLoad), {
      expectedOrgId: '',
      instanceUrl: process.env.SALESFORCE_LOGIN_URL,
      apiVersion: process.env.SALESFORCE_API_VERSION || 'v62.0',
      enforceOrgIdLock: false,
      sfdxObjectsFolderPath: '',
    });
    assert.ok(!Number.isNaN(Date.parse(sfSettingsAtLoad.updatedAt)));
  });

  test('updateSalesforceSettings only changes the fields it is given', () => {
    restoringSingleton('sf_connection_settings', () => {
      const before = store.getSalesforceSettings();
      const orgId = `00D${uid()}${uid()}`.slice(0, 15);

      const step1 = store.updateSalesforceSettings({ expectedOrgId: orgId });
      assert.deepEqual(withoutTimestamp(step1), { ...withoutTimestamp(before), expectedOrgId: orgId });

      const step2 = store.updateSalesforceSettings({ apiVersion: 'v61.0', enforceOrgIdLock: true });
      assert.deepEqual(withoutTimestamp(step2), {
        ...withoutTimestamp(step1),
        apiVersion: 'v61.0',
        enforceOrgIdLock: true,
      });

      const step3 = store.updateSalesforceSettings({ instanceUrl: 'https://acme.my.salesforce.com' });
      assert.deepEqual(withoutTimestamp(step3), {
        ...withoutTimestamp(step2),
        instanceUrl: 'https://acme.my.salesforce.com',
      });

      const step4 = store.updateSalesforceSettings({ enforceOrgIdLock: false });
      assert.deepEqual(withoutTimestamp(step4), { ...withoutTimestamp(step3), enforceOrgIdLock: false });
      assert.deepEqual(withoutTimestamp(store.getSalesforceSettings()), withoutTimestamp(step4));
    });
  });
});

// =============================================================================================
// 9. parseSfdxFilesToObjects
// =============================================================================================
describe('store: parseSfdxFilesToObjects', () => {
  test('parses SFDX source format: <Object>.object-meta.xml plus fields/<Field>.field-meta.xml', () => {
    const parsed = parseSfdxFilesToObjects([
      {
        relativePath: 'force-app/main/default/objects/Invoice__c/Invoice__c.object-meta.xml',
        content: INVOICE_OBJECT_META_XML,
      },
      {
        relativePath: 'force-app/main/default/objects/Invoice__c/fields/Amount__c.field-meta.xml',
        content: AMOUNT_FIELD_META_XML,
      },
      {
        relativePath: 'force-app/main/default/objects/Invoice__c/fields/Due_Date__c.field-meta.xml',
        content: DUE_DATE_FIELD_META_XML,
      },
    ]);

    assert.deepEqual(parsed.map((o) => o.objectName), ['Invoice__c']);
    const invoice = parsed[0];
    assert.equal(invoice.label, 'Invoice');
    assert.equal(invoice.isCustom, true);
    assert.deepEqual(invoice.fields.map((f) => f.fieldName).sort(), ['Amount__c', 'Due_Date__c', 'Id', 'Name']);
    assert.deepEqual(parsedField(invoice, 'Amount__c'), {
      fieldName: 'Amount__c',
      label: 'Invoice Amount',
      fieldType: 'Currency',
      isCustom: true,
      required: true,
    });
    assert.deepEqual(parsedField(invoice, 'Due_Date__c'), {
      fieldName: 'Due_Date__c',
      label: 'Due Date',
      fieldType: 'Date',
      isCustom: true,
      required: false,
    });
    assertHasStandardIdAndName(invoice);
  });

  test('infers a standard object extended with only fields/ files from its folder name', () => {
    const parsed = parseSfdxFilesToObjects([
      {
        relativePath: 'force-app/main/default/objects/Account/fields/Tier__c.field-meta.xml',
        content: TIER_FIELD_META_XML,
      },
    ]);

    assert.deepEqual(parsed.map((o) => o.objectName), ['Account']);
    const account = parsed[0];
    assert.equal(account.label, 'Account');
    assert.equal(account.isCustom, false);
    assert.equal(account.sourcePath, 'force-app/main/default/objects/Account');
    assert.deepEqual(account.fields.map((f) => f.fieldName).sort(), ['Id', 'Name', 'Tier__c']);
    assert.deepEqual(parsedField(account, 'Tier__c'), {
      fieldName: 'Tier__c',
      label: 'Customer Tier',
      fieldType: 'Picklist',
      isCustom: true,
      required: false,
    });
    assertHasStandardIdAndName(account);
  });

  test('parses classic Metadata API .object files with inline <fields> blocks', () => {
    const parsed = parseSfdxFilesToObjects([{ relativePath: 'src/objects/Case.object', content: CASE_CLASSIC_OBJECT_XML }]);

    assert.deepEqual(parsed.map((o) => o.objectName), ['Case']);
    const kase = parsed[0];
    assert.equal(kase.isCustom, false);
    assert.deepEqual(kase.fields.map((f) => f.fieldName).sort(), [
      'Id',
      'Name',
      'Resolution_Notes__c',
      'Severity__c',
      'Subject',
    ]);
    assert.deepEqual(parsedField(kase, 'Severity__c'), {
      fieldName: 'Severity__c',
      label: 'Severity Level',
      fieldType: 'Picklist',
      isCustom: true,
      required: true,
    });
    assert.deepEqual(parsedField(kase, 'Resolution_Notes__c'), {
      fieldName: 'Resolution_Notes__c',
      label: 'Resolution Notes',
      fieldType: 'LongTextArea',
      isCustom: true,
      required: false,
    });
    assert.deepEqual(parsedField(kase, 'Subject'), {
      fieldName: 'Subject',
      label: 'Subject',
      fieldType: 'Text',
      isCustom: false,
      required: false,
    });
    assertHasStandardIdAndName(kase);
  });

  test('labels a classic .object only from its top-level <label>, never from a nested field or list view', () => {
    const parsed = parseSfdxFilesToObjects([
      { relativePath: 'src/objects/Case.object', content: CASE_CLASSIC_OBJECT_XML },
      { relativePath: 'src/objects/Shipment__c.object', content: SHIPMENT_CLASSIC_OBJECT_XML },
    ]);

    assert.equal(
      parsedObject(parsed, 'Case').label,
      'Case',
      'Case.object has no top-level <label>, so the label falls back to the object name'
    );
    assert.equal(parsedObject(parsed, 'Shipment__c').label, 'Shipment');
  });
});

// =============================================================================================
// 10. importObjectsFromLocalDiskFolder
// =============================================================================================
describe('store: importObjectsFromLocalDiskFolder', () => {
  function writeFile(filePath: string, content: string): void {
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, content);
  }

  test('imports an SFDX objects folder from disk, including a folder that has only fields/, and saves its path', (t) => {
    const root = fs.mkdtempSync(path.join(testTmpDir, 'sfdx-'));
    const objectsDir = path.join(root, 'force-app', 'main', 'default', 'objects');
    const customObject = `StoreDisk_${uid()}__c`;
    const fieldsOnlyObject = `StoreDiskStd${uid()}`;
    writeFile(
      path.join(objectsDir, customObject, `${customObject}.object-meta.xml`),
      '<?xml version="1.0" encoding="UTF-8"?><CustomObject><label>Disk Invoice</label></CustomObject>'
    );
    writeFile(path.join(objectsDir, customObject, 'fields', 'Amount__c.field-meta.xml'), AMOUNT_FIELD_META_XML);
    writeFile(
      path.join(objectsDir, customObject, 'listViews', 'All.listView-meta.xml'),
      '<ListView><fullName>All</fullName><label>All</label></ListView>'
    );
    writeFile(path.join(objectsDir, fieldsOnlyObject, 'fields', 'Tier__c.field-meta.xml'), TIER_FIELD_META_XML);
    t.after(() => {
      store.deleteObject(customObject);
      store.deleteObject(fieldsOnlyObject);
      fs.rmSync(root, { recursive: true, force: true });
    });

    restoringSingleton('sf_connection_settings', () => {
      const result = store.importObjectsFromLocalDiskFolder(path.join(objectsDir, '..', 'objects'));

      assert.deepEqual(result, { objectsImported: 2, fieldsImported: 6, resolvedPath: path.resolve(objectsDir) });
      assert.equal(store.getSalesforceSettings().sfdxObjectsFolderPath, path.resolve(objectsDir));
    });

    const custom = storedObject(customObject);
    assert.equal(custom.label, 'Disk Invoice');
    assert.equal(custom.isCustom, true);
    assert.equal(custom.enabled, true);
    assert.deepEqual(custom.fields.map((f) => f.fieldName), ['Amount__c', 'Id', 'Name']);
    const amount = storedField(customObject, 'Amount__c');
    assert.deepEqual(
      { fieldType: amount.fieldType, required: amount.required, isCustom: amount.isCustom, enabled: amount.enabled },
      { fieldType: 'Currency', required: true, isCustom: true, enabled: true }
    );

    const fieldsOnly = storedObject(fieldsOnlyObject);
    assert.equal(fieldsOnly.isCustom, false);
    assert.equal(fieldsOnly.label, fieldsOnlyObject);
    assert.deepEqual(fieldsOnly.fields.map((f) => f.fieldName), ['Id', 'Name', 'Tier__c']);
    assert.equal(storedField(fieldsOnlyObject, 'Tier__c').fieldType, 'Picklist');
  });

  test('throws for a missing directory (or a file) and leaves the saved folder path alone', () => {
    restoringSingleton('sf_connection_settings', () => {
      const savedPath = store.getSalesforceSettings().sfdxObjectsFolderPath;
      const missingDir = path.join(testTmpDir, `missing-${uid()}`, 'objects');
      const regularFile = path.join(testTmpDir, `not-a-folder-${uid()}.object-meta.xml`);
      fs.writeFileSync(regularFile, '<CustomObject><label>File</label></CustomObject>');

      assert.throws(() => store.importObjectsFromLocalDiskFolder(missingDir), /Directory not found/);
      assert.throws(() => store.importObjectsFromLocalDiskFolder(regularFile), /Directory not found/);
      assert.equal(store.getSalesforceSettings().sfdxObjectsFolderPath, savedPath);
    });
  });
});
