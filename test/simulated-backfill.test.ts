import { testTmpDir } from './helpers/env.js';
// Upgrading a database from before the simulated column must mark the old default simulator rows,
// once. The migration runs when the store loads, so each boot here is a real child process.
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function bootStore(dbPath: string) {
  execFileSync(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', "await import('./src/db/store.ts');"], {
    cwd: REPO_ROOT,
    env: { ...process.env, DB_PATH: dbPath },
    stdio: 'pipe',
    timeout: 60_000,
  });
}

function withDb<T>(dbPath: string, fn: (db: DatabaseSync) => T): T {
  const db = new DatabaseSync(dbPath);
  try {
    return fn(db);
  } finally {
    db.close();
  }
}

function insertRow(db: DatabaseSync, id: string, sfUsername: string) {
  db.prepare(
    `INSERT INTO mcp_copilot_logs (id, timestamp, sf_username, profile_id, profile_name, tool_name, status)
     VALUES (?, '2026-10-01T00:00:00.000Z', ?, '00e000000000001', 'P', 'soql_query', 'ALLOWED')`
  ).run(id, sfUsername);
}

const kinds = (dbPath: string) =>
  withDb(dbPath, (db) =>
    Object.fromEntries(
      (db.prepare('SELECT id, kind FROM mcp_copilot_logs').all() as Array<{ id: string; kind: string }>).map((r) => [r.id, r.kind])
    )
  );

const simulatedFlags = (dbPath: string) =>
  withDb(dbPath, (db) =>
    Object.fromEntries(
      (db.prepare('SELECT id, simulated FROM mcp_copilot_logs').all() as Array<{ id: string; simulated: number }>).map(
        (r) => [r.id, r.simulated]
      )
    )
  );

/** A database as it stood before the column: the table as d6edd70 created it, with old rows. */
function legacyDatabase(name: string): string {
  const dbPath = path.join(testTmpDir, name);
  withDb(dbPath, (db) => {
    db.exec(`
      CREATE TABLE mcp_copilot_logs (
        id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL,
        sf_username TEXT NOT NULL,
        profile_id TEXT NOT NULL,
        profile_name TEXT NOT NULL,
        matched_groups_json TEXT NOT NULL DEFAULT '[]',
        tool_name TEXT NOT NULL,
        target_object TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL,
        latency_ms INTEGER NOT NULL DEFAULT 0,
        sanitized_request_payload TEXT NOT NULL DEFAULT '{}',
        sanitized_response_summary TEXT NOT NULL DEFAULT '{}'
      );
    `);
    insertRow(db, 'route-default', 'copilot.user@enterprise.com');
    insertRow(db, 'token-default', 'alex.demo@company.my.salesforce.com');
    insertRow(db, 'real', 'real.user@acme.com');
    insertRow(db, 'rejected', 'unverified_caller');
    insertRow(db, 'similar', 'COPILOT.USER@enterprise.com.acme');
  });
  return dbPath;
}

describe('backfill of the simulated column', () => {
  test('marks only the known simulator identities, and later real rows under those names stay real', () => {
    const dbPath = legacyDatabase('legacy.sqlite');

    bootStore(dbPath);
    assert.deepEqual(simulatedFlags(dbPath), {
      'route-default': 1,
      'token-default': 1,
      real: 0,
      rejected: 0,
      similar: 0,
    });
    // The same boot gives the log table its seq and every row the kind its flags imply.
    assert.deepEqual(kinds(dbPath), {
      'route-default': 'simulated',
      'token-default': 'simulated',
      real: 'real',
      rejected: 'rejected',
      similar: 'real',
    });
    assert.deepEqual(
      withDb(dbPath, (db) => (db.prepare('SELECT id FROM mcp_copilot_logs ORDER BY seq').all() as Array<{ id: string }>).map((r) => r.id)),
      ['route-default', 'token-default', 'real', 'rejected', 'similar']
    );

    withDb(dbPath, (db) => insertRow(db, 'later-real', 'copilot.user@enterprise.com'));
    bootStore(dbPath);
    assert.equal(simulatedFlags(dbPath)['later-real'], 0, 'the backfill must not run a second time');
    assert.equal(kinds(dbPath)['later-real'], 'real');
  });

  test('does nothing to a database that already has the column', () => {
    const dbPath = path.join(testTmpDir, 'current.sqlite');
    bootStore(dbPath);
    withDb(dbPath, (db) => insertRow(db, 'real-under-old-name', 'alex.demo@company.my.salesforce.com'));

    bootStore(dbPath);
    assert.equal(simulatedFlags(dbPath)['real-under-old-name'], 0);
  });
});
