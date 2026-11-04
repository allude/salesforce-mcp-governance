import { testTmpDir } from './helpers/env.js';
// Upgrading a database from before the group version column rewrites each group's grants with the
// catalog's spelling of their Object and field names and merges entries that then name one Object,
// once. The migration runs when the store loads, so each boot here is a real child process.
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';
import { store } from '../src/db/store.js';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PROFILE_ID = '00e000000MIGRAT';

/** Loads the store on `dbPath` (running its migrations) and returns the Profile's effective access. */
function bootAndResolve(dbPath: string): unknown {
  const script = `
    const { resolveEffectiveProfilePermissions } = await import('./src/rbac/policyEngine.ts');
    const e = resolveEffectiveProfilePermissions(${JSON.stringify(PROFILE_ID)});
    const objects = [...e.objectPermissions.values()].map((o) => ({
      ...o,
      allowedFields: [...o.allowedFields].sort(),
      missingInOrgFields: [...o.missingInOrgFields].sort(),
    }));
    process.stdout.write('\\nPROBE ' + JSON.stringify({
      profileFound: e.profileFound,
      assignedGroups: e.assignedGroups,
      allowedActions: [...e.allowedActions].sort(),
      objects,
    }) + '\\n');
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

function withDb<T>(dbPath: string, fn: (db: DatabaseSync) => T): T {
  const db = new DatabaseSync(dbPath);
  try {
    return fn(db);
  } finally {
    db.close();
  }
}

const insertGroup = (db: DatabaseSync, id: string, objectPermissions: unknown[]) =>
  db
    .prepare(
      `INSERT INTO access_groups (id, name, description, allowed_actions_json, object_permissions_json, updated_at)
       VALUES (?, ?, '', '["soql_query","update_record"]', ?, '2026-10-01T00:00:00.000Z')`
    )
    .run(id, `Group ${id}`, JSON.stringify(objectPermissions));

// As POST /groups stored them before: names in any case, an entry per spelling, a field list for an
// entry that grants nothing, an entry whose fields the catalog does not have (which the engine reads
// as Id alone) next to one whose fields it has, and entries the policy engine cannot use at all.
const CASE_VARIANT_GRANTS = [
  { objectName: 'account', canRead: true, allowedFields: ['ID', 'name'] },
  { objectName: 'Ghost__c', canRead: true, allowedFields: ['Id'] },
  { objectName: 'ACCOUNT', canUpdate: true, allowedFields: ['Phone', 'NAME'] },
  { objectName: 'account', allowedFields: ['Secret__c'] },
  { objectName: 7, canRead: true },
  { objectName: 'contact', canRead: true, allowedFields: ['email', 'Unknown__c'] },
  { objectName: 'lead', canRead: true, allowedFields: ['Gone__c'] },
  { objectName: 'LEAD', canUpdate: true, allowedFields: ['company'] },
];
const CANONICAL_GRANTS = [{ objectName: 'Contact', canRead: true, canCreate: false, canUpdate: false, canDelete: false, allowedFields: ['Id'] }];

/** A database as it stood before the column: the tables as they were, with a catalog and two groups. */
function legacyDatabase(name: string): string {
  const dbPath = path.join(testTmpDir, name);
  withDb(dbPath, (db) => {
    db.exec(`
      CREATE TABLE sf_profiles (
        id TEXT PRIMARY KEY, name TEXT NOT NULL, missing_in_org INTEGER NOT NULL DEFAULT 0, updated_at TEXT NOT NULL
      );
      CREATE TABLE sf_objects (
        object_name TEXT PRIMARY KEY, label TEXT NOT NULL, is_custom INTEGER NOT NULL DEFAULT 0,
        enabled INTEGER NOT NULL DEFAULT 1, source_path TEXT NOT NULL DEFAULT '',
        missing_in_org INTEGER NOT NULL DEFAULT 0, updated_at TEXT NOT NULL
      );
      CREATE TABLE sf_object_fields (
        object_name TEXT NOT NULL, field_name TEXT NOT NULL, label TEXT NOT NULL,
        field_type TEXT NOT NULL DEFAULT 'Text', is_custom INTEGER NOT NULL DEFAULT 0,
        required INTEGER NOT NULL DEFAULT 0, enabled INTEGER NOT NULL DEFAULT 1,
        missing_in_org INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (object_name, field_name),
        FOREIGN KEY (object_name) REFERENCES sf_objects(object_name) ON DELETE CASCADE
      );
      CREATE TABLE access_groups (
        id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, description TEXT NOT NULL DEFAULT '',
        allowed_actions_json TEXT NOT NULL DEFAULT '[]', object_permissions_json TEXT NOT NULL DEFAULT '[]',
        updated_at TEXT NOT NULL
      );
      CREATE TABLE profile_group_memberships (
        profile_id TEXT NOT NULL, group_id TEXT NOT NULL, PRIMARY KEY (profile_id, group_id),
        FOREIGN KEY (profile_id) REFERENCES sf_profiles(id) ON DELETE CASCADE,
        FOREIGN KEY (group_id) REFERENCES access_groups(id) ON DELETE CASCADE
      );
    `);
    const object = db.prepare(`INSERT INTO sf_objects (object_name, label, updated_at) VALUES (?, ?, '2026-10-01T00:00:00.000Z')`);
    const field = db.prepare('INSERT INTO sf_object_fields (object_name, field_name, label) VALUES (?, ?, ?)');
    for (const [objectName, fields] of Object.entries({
      Account: ['Id', 'Name', 'Phone', 'Secret__c'],
      Contact: ['Id', 'Email'],
      Lead: ['Id', 'Company'],
    })) {
      object.run(objectName, objectName);
      for (const fieldName of fields) field.run(objectName, fieldName, fieldName);
    }
    insertGroup(db, 'grp_variants', CASE_VARIANT_GRANTS);
    insertGroup(db, 'grp_canonical', CANONICAL_GRANTS);
    db.prepare(`INSERT INTO sf_profiles (id, name, updated_at) VALUES (?, 'Migrated Profile', '2026-10-01T00:00:00.000Z')`).run(PROFILE_ID);
    const member = db.prepare('INSERT INTO profile_group_memberships (profile_id, group_id) VALUES (?, ?)');
    member.run(PROFILE_ID, 'grp_variants');
    member.run(PROFILE_ID, 'grp_canonical');
  });
  return dbPath;
}

const storedGroups = (dbPath: string) =>
  withDb(dbPath, (db) =>
    Object.fromEntries(
      (db.prepare('SELECT id, object_permissions_json, version FROM access_groups').all() as Array<{
        id: string;
        object_permissions_json: string;
        version: number;
      }>).map((r) => [r.id, { grants: JSON.parse(r.object_permissions_json), version: r.version }])
    )
  );

describe('canonicalization of group grants on upgrade', () => {
  test('grants take the catalog spelling and merge, and the effective access stays the same', () => {
    const upgraded = legacyDatabase('legacy-groups.sqlite');
    // The same data on a database that already has the column, so its boot leaves the grants as stored.
    const asStored = path.join(testTmpDir, 'legacy-groups-as-stored.sqlite');
    fs.copyFileSync(upgraded, asStored);
    withDb(asStored, (db) => db.exec('ALTER TABLE access_groups ADD COLUMN version INTEGER NOT NULL DEFAULT 1'));

    const before = bootAndResolve(asStored);
    const after = bootAndResolve(upgraded);
    assert.deepEqual(after, before);
    const objects = (before as { objects: Array<{ objectName: string; allowedFields: string[] }> }).objects;
    assert.deepEqual(objects.map((o) => o.objectName).sort(), ['Account', 'Contact', 'Lead']);
    assert.deepEqual(objects.find((o) => o.objectName === 'Lead')?.allowedFields, ['Company', 'Id']);

    assert.deepEqual(storedGroups(upgraded), {
      grp_variants: {
        grants: [
          // Flags OR-ed, fields of the granting entries unioned: Secret__c, listed only by an entry
          // that grants nothing, is not added.
          { objectName: 'Account', canRead: true, canCreate: false, canUpdate: true, canDelete: false, allowedFields: ['Id', 'Name', 'Phone'] },
          // Not in the catalog, or not a grant the engine can read: kept as stored.
          { objectName: 'Ghost__c', canRead: true, allowedFields: ['Id'] },
          { objectName: 7, canRead: true },
          { objectName: 'Contact', canRead: true, allowedFields: ['Email', 'Unknown__c'] },
          // The Read entry named no field of Lead, so on its own it gave Id: merged, it still does.
          { objectName: 'Lead', canRead: true, canCreate: false, canUpdate: true, canDelete: false, allowedFields: ['Gone__c', 'Company', 'Id'] },
        ],
        version: 2,
      },
      grp_canonical: { grants: CANONICAL_GRANTS, version: 1 },
    });
    assert.deepEqual(storedGroups(asStored).grp_variants, { grants: CASE_VARIANT_GRANTS, version: 1 });
  });

  test('an Object stored under two spellings keeps its entries as stored, so a merge cannot add Id', () => {
    // As an older version could leave it: the real Opportunity, and a stray disabled 'opportunity' row
    // with other fields. The engine reads only the enabled row; the Amount entry names a field of it,
    // which the stray row does not have, so taken from that row's fields a merge would add Id.
    const STRAY_VARIANT_GRANTS = [
      { objectName: 'opportunity', canRead: true, allowedFields: ['Amount'] },
      { objectName: 'Opportunity', canRead: true, allowedFields: ['Name'] },
    ];
    const upgraded = legacyDatabase('legacy-groups-stray-variant.sqlite');
    withDb(upgraded, (db) => {
      const object = db.prepare(
        `INSERT INTO sf_objects (object_name, label, enabled, updated_at) VALUES (?, ?, ?, '2026-10-01T00:00:00.000Z')`
      );
      const field = db.prepare('INSERT INTO sf_object_fields (object_name, field_name, label) VALUES (?, ?, ?)');
      object.run('Opportunity', 'Opportunity', 1);
      for (const fieldName of ['Id', 'Name', 'Amount']) field.run('Opportunity', fieldName, fieldName);
      object.run('opportunity', 'opportunity', 0);
      for (const fieldName of ['id', 'Probability']) field.run('opportunity', fieldName, fieldName);
      insertGroup(db, 'grp_pipeline', STRAY_VARIANT_GRANTS);
      db.prepare('INSERT INTO profile_group_memberships (profile_id, group_id) VALUES (?, ?)').run(PROFILE_ID, 'grp_pipeline');
    });
    const asStored = path.join(testTmpDir, 'legacy-groups-stray-variant-as-stored.sqlite');
    fs.copyFileSync(upgraded, asStored);
    withDb(asStored, (db) => db.exec('ALTER TABLE access_groups ADD COLUMN version INTEGER NOT NULL DEFAULT 1'));

    const before = bootAndResolve(asStored);
    const after = bootAndResolve(upgraded);
    assert.deepEqual(after, before);
    const objects = (after as { objects: Array<{ objectName: string; allowedFields: string[] }> }).objects;
    assert.deepEqual(objects.find((o) => o.objectName === 'Opportunity')?.allowedFields, ['Amount', 'Name']);
    assert.deepEqual(storedGroups(upgraded).grp_pipeline, { grants: STRAY_VARIANT_GRANTS, version: 1 });
  });

  test('runs once: a case variant written after the upgrade is left alone', () => {
    const dbPath = legacyDatabase('legacy-groups-once.sqlite');
    bootAndResolve(dbPath);
    const later = [{ objectName: 'account', canRead: true, allowedFields: ['id'] }];
    withDb(dbPath, (db) => insertGroup(db, 'grp_later', later));

    bootAndResolve(dbPath);
    assert.deepEqual(storedGroups(dbPath).grp_later, { grants: later, version: 1 });
  });

  test('an upgraded database ends with the same access_groups table as a new one', () => {
    const dbPath = legacyDatabase('legacy-groups-schema.sqlite');
    bootAndResolve(dbPath);
    const columns = (file: string) =>
      withDb(file, (db) =>
        (db.prepare('PRAGMA table_info(access_groups)').all() as Array<Record<string, unknown>>).map(
          ({ name, type, notnull, dflt_value, pk }) => ({ name, type, notnull, dflt_value, pk })
        )
      );
    // This process's store created its database new.
    assert.ok(store.getGroups());
    assert.deepEqual(columns(dbPath), columns(process.env.DB_PATH as string));
    assert.deepEqual(columns(dbPath).at(-1), { name: 'version', type: 'INTEGER', notnull: 1, dflt_value: '1', pk: 0 });
  });
});
