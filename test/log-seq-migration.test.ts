import { testTmpDir } from './helpers/env.js';
// Upgrading a database from before the seq column: both log tables are rebuilt once, with every row in
// its old order under its old id, and a paging cursor handed out before the upgrade still reads the
// same page after it. The migration runs when the store loads, so each boot here is a real child
// process; the store's own readers run in one too, against the upgraded file.
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const LOG_TABLES = ['mcp_copilot_logs', 'portal_admin_logs'] as const;
const RESULT_MARK = '__store_result__';

/** Loads the store on `dbPath` in a child process (which runs the migrations) and returns what `body` returns. */
function withStore<T = unknown>(dbPath: string, body = 'null'): T {
  const script = `const { store } = await import('./src/db/store.ts');
    const result = await (async () => (${body}))();
    console.log(${JSON.stringify(RESULT_MARK)} + JSON.stringify(result));`;
  const out = execFileSync(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', script], {
    cwd: REPO_ROOT,
    env: { ...process.env, DB_PATH: dbPath },
    stdio: 'pipe',
    timeout: 60_000,
    encoding: 'utf8',
  });
  const line = out.split('\n').find((l) => l.startsWith(RESULT_MARK));
  assert.ok(line, `the child printed no result: ${out}`);
  return JSON.parse(line.slice(RESULT_MARK.length)) as T;
}

function withDb<T>(dbPath: string, fn: (db: DatabaseSync) => T): T {
  const db = new DatabaseSync(dbPath);
  try {
    return fn(db);
  } finally {
    db.close();
  }
}

function insertMcpRow(db: DatabaseSync, id: string, sfUsername: string, simulated = 0) {
  db.prepare(
    `INSERT INTO mcp_copilot_logs (id, timestamp, sf_username, profile_id, profile_name, tool_name, target_object, status, latency_ms, simulated)
     VALUES (?, '2026-10-01T00:00:00.000Z', ?, '00e000000000001', 'P', 'soql_query', 'Account', 'ALLOWED', 12, ?)`
  ).run(id, sfUsername, simulated);
}

function insertPortalRow(db: DatabaseSync, id: string, action: string) {
  db.prepare(
    `INSERT INTO portal_admin_logs (id, timestamp, admin_username, auth_method, action, target, details, ip_address)
     VALUES (?, '2026-10-01T00:00:00.000Z', 'admin', 'password', ?, 'Portal Auth', 'An old row.', '127.0.0.1')`
  ).run(id, action);
}

/**
 * A database as the release before seq left it: both tables keyed by id, listed by rowid, the simulated
 * and audit columns added by ALTER TABLE, and old rows with a gap in their rowids where rows were removed.
 */
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
      ALTER TABLE mcp_copilot_logs ADD COLUMN simulated INTEGER NOT NULL DEFAULT 0;
      CREATE TABLE portal_admin_logs (
        id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL,
        admin_username TEXT NOT NULL,
        auth_method TEXT NOT NULL,
        action TEXT NOT NULL,
        target TEXT NOT NULL,
        details TEXT NOT NULL,
        ip_address TEXT NOT NULL
      );
      ALTER TABLE portal_admin_logs ADD COLUMN result TEXT NOT NULL DEFAULT 'SUCCESS';
      ALTER TABLE portal_admin_logs ADD COLUMN target_type TEXT NOT NULL DEFAULT '';
      ALTER TABLE portal_admin_logs ADD COLUMN target_id TEXT NOT NULL DEFAULT '';
      ALTER TABLE portal_admin_logs ADD COLUMN diff_json TEXT NOT NULL DEFAULT '';
      ALTER TABLE portal_admin_logs ADD COLUMN correlation_id TEXT NOT NULL DEFAULT '';
    `);
    // Ids that sort differently from the write order, so an order by id would be caught.
    insertMcpRow(db, 'm-zulu', 'real.user@acme.com');
    insertMcpRow(db, 'm-yankee', 'unverified_caller');
    insertMcpRow(db, 'm-removed', 'real.user@acme.com');
    insertMcpRow(db, 'm-xray', 'simulated:test-user', 1);
    insertMcpRow(db, 'm-whiskey', 'real.user@acme.com');
    insertMcpRow(db, 'm-victor', 'unverified_caller');
    insertMcpRow(db, 'm-uniform', 'real.user@acme.com');
    db.exec(`DELETE FROM mcp_copilot_logs WHERE id = 'm-removed'`);

    insertPortalRow(db, 'p-zulu', 'LOGIN_FAILED');
    insertPortalRow(db, 'p-removed', 'LOGIN_SUCCESS');
    insertPortalRow(db, 'p-yankee', 'UPDATE_GROUP');
    insertPortalRow(db, 'p-xray', 'OKTA_LOGIN_DENIED');
    insertPortalRow(db, 'p-whiskey', 'LOGIN_SUCCESS');
    db.exec(`DELETE FROM portal_admin_logs WHERE id = 'p-removed'`);
  });
  return dbPath;
}

type Row = Record<string, unknown>;
const plain = (rows: unknown[]) => rows.map((r) => ({ ...(r as Row) }));

/** Every row of `table` as the release before seq listed it: newest first by rowid. */
const rowsByRowid = (dbPath: string, table: string) =>
  withDb(dbPath, (db) => plain(db.prepare(`SELECT rowid AS old_rowid, * FROM ${table} ORDER BY rowid DESC`).all()));

/** The ids on the page the release before seq served for `before`, two rows a page. */
const legacyPage = (dbPath: string, table: string, before: number) =>
  withDb(dbPath, (db) =>
    (db.prepare(`SELECT id FROM ${table} WHERE rowid < ? ORDER BY rowid DESC LIMIT 2`).all(before) as Array<{ id: string }>).map(
      (r) => r.id
    )
  );

const tableInfo = (dbPath: string, table: string) =>
  withDb(dbPath, (db) =>
    plain(db.prepare(`PRAGMA table_info(${table})`).all()).map(({ cid, name, type, notnull, dflt_value, pk }) => ({
      cid,
      name,
      type,
      notnull,
      dflt_value,
      pk,
    }))
  );

const indexInfo = (dbPath: string, table: string) =>
  withDb(dbPath, (db) =>
    plain(db.prepare(`PRAGMA index_list(${table})`).all()).map(({ name, unique, origin }) => ({ name, unique, origin }))
  );

const tablePages = (dbPath: string) =>
  withDb(dbPath, (db) =>
    plain(db.prepare(`SELECT name, rootpage, sql FROM sqlite_master WHERE name IN ('mcp_copilot_logs', 'portal_admin_logs') ORDER BY name`).all())
  );

describe('upgrading the log tables to an explicit seq', () => {
  test('every row keeps its id, its values and its place, and seq is its old rowid', () => {
    const dbPath = legacyDatabase('legacy-seq.sqlite');
    const before = Object.fromEntries(LOG_TABLES.map((t) => [t, rowsByRowid(dbPath, t)]));

    withStore(dbPath);

    for (const table of LOG_TABLES) {
      const after = withDb(dbPath, (db) => plain(db.prepare(`SELECT * FROM ${table} ORDER BY seq DESC`).all()));
      assert.deepEqual(
        after.map((r) => [r.seq, r.id]),
        before[table].map((r) => [r.old_rowid, r.id]),
        `${table}: the same rows, in the same order, each with its rowid as its seq`
      );
      // Every column the old table had holds what it held, except portal results the audit backfill sets.
      for (const [i, old] of before[table].entries()) {
        const { old_rowid, result, ...values } = old;
        const { seq, ...current } = after[i];
        for (const [column, value] of Object.entries(values)) assert.equal(current[column], value, `${table} ${old.id} ${column}`);
        if (table === 'mcp_copilot_logs') assert.equal(current.result, undefined);
      }
    }
    // The rowid gap is still there: nothing was renumbered.
    assert.deepEqual(
      withDb(dbPath, (db) => plain(db.prepare('SELECT seq FROM mcp_copilot_logs ORDER BY seq').all())).map((r) => r.seq),
      [1, 2, 4, 5, 6, 7]
    );
  });

  test('a cursor handed out before the upgrade reads the same page after it, through the store', () => {
    const dbPath = legacyDatabase('legacy-seq-cursor.sqlite');
    const cursors = { mcp_copilot_logs: [8, 7, 4, 3, 2], portal_admin_logs: [6, 5, 3, 2] };
    const expected = Object.fromEntries(
      LOG_TABLES.map((t) => [t, cursors[t].map((before) => legacyPage(dbPath, t, before))])
    );

    const pages = withStore<Record<string, Array<{ ids: string[]; seqs: number[]; nextBefore: number | null }>>>(
      dbPath,
      `(() => {
        const read = (page) => ({ ids: page.rows.map((r) => r.id), seqs: page.rows.map((r) => r.seq), nextBefore: page.nextBefore });
        return {
          mcp_copilot_logs: ${JSON.stringify(cursors.mcp_copilot_logs)}.map((before) => read(store.getCopilotMcpLogPage({ before, limit: 2 }))),
          portal_admin_logs: ${JSON.stringify(cursors.portal_admin_logs)}.map((before) => read(store.getPortalAdminLogPage({ before, limit: 2 }))),
        };
      })()`
    );

    for (const table of LOG_TABLES) {
      assert.deepEqual(pages[table].map((p) => p.ids), expected[table], table);
      for (const page of pages[table]) {
        assert.equal(page.nextBefore, page.seqs.length === 2 && page.seqs[1] > 1 ? page.seqs[1] : null);
      }
    }

    // Reading from the newest page by nextBefore reaches every row once, and a new row goes first.
    const walk = withStore<{ mcp: string[]; portal: string[]; newSeq: number }>(
      dbPath,
      `(() => {
        const all = (read) => { const ids = []; let before; for (;;) { const page = read(before); ids.push(...page.rows.map((r) => r.id)); if (page.nextBefore === null) return ids; before = page.nextBefore; } };
        const created = store.recordCopilotMcpLog({ sfUsername: 'real.user@acme.com', profileId: '00e000000000001', profileName: 'P', matchedGroups: [], toolName: 'soql_query', targetObject: 'Account', status: 'ALLOWED', latencyMs: 1, rawRequestPayload: {}, rawResponseSummary: {} });
        return {
          mcp: all((before) => store.getCopilotMcpLogPage({ before, limit: 2 })),
          portal: all((before) => store.getPortalAdminLogPage({ before, limit: 2 })).filter((id) => id.startsWith('p-')),
          newSeq: created.seq,
        };
      })()`
    );
    assert.deepEqual(walk.mcp.slice(1), ['m-uniform', 'm-victor', 'm-whiskey', 'm-xray', 'm-yankee', 'm-zulu']);
    assert.equal(walk.newSeq, 8);
    assert.deepEqual(walk.portal, ['p-whiskey', 'p-xray', 'p-yankee', 'p-zulu']);
  });

  test('old rows get the kind their columns imply and nothing else, and the audit results backfill still runs', () => {
    const dbPath = legacyDatabase('legacy-seq-kinds.sqlite');
    withStore(dbPath);

    const rows = withDb(dbPath, (db) =>
      plain(
        db
          .prepare(
            `SELECT id, kind, decision_json, decision_stage, decision_code, assigned_group_ids_json, deciding_group_ids_json,
                    policy_revision, caller_profile_id, matched_profile_id, match_method, verification_ms, total_ms, latency_ms
             FROM mcp_copilot_logs ORDER BY seq`
          )
          .all()
      )
    );
    assert.deepEqual(
      Object.fromEntries(rows.map((r) => [r.id, r.kind])),
      { 'm-zulu': 'real', 'm-yankee': 'rejected', 'm-xray': 'simulated', 'm-whiskey': 'real', 'm-victor': 'rejected', 'm-uniform': 'real' }
    );
    for (const { id, kind, latency_ms, ...rest } of rows) {
      assert.equal(latency_ms, 12, `${id} keeps its latency`);
      assert.deepEqual(rest, {
        decision_json: '',
        decision_stage: '',
        decision_code: '',
        assigned_group_ids_json: '[]',
        deciding_group_ids_json: '[]',
        policy_revision: null,
        caller_profile_id: '',
        matched_profile_id: '',
        match_method: '',
        verification_ms: null,
        total_ms: null,
      });
    }

    // The store reads those rows as "not recorded".
    const record = withStore<Record<string, unknown>>(dbPath, `store.getCopilotMcpLogPage({ limit: 10 }).rows.find((r) => r.id === 'm-zulu')`);
    assert.deepEqual(
      [record.kind, record.decision, record.decisionStage, record.decisionCode, record.assignedGroupIds, record.decidingGroupIds,
        record.policyRevision, record.callerProfileId, record.matchedProfileId, record.matchMethod, record.verificationMs, record.totalMs, record.latencyMs],
      ['real', null, '', '', [], [], null, '', '', '', null, null, 12]
    );

    const results = withDb(dbPath, (db) =>
      Object.fromEntries((db.prepare('SELECT id, result FROM portal_admin_logs').all() as Array<{ id: string; result: string }>).map((r) => [r.id, r.result]))
    );
    assert.deepEqual(results, { 'p-zulu': 'FAILED', 'p-yankee': 'SUCCESS', 'p-xray': 'DENIED', 'p-whiskey': 'SUCCESS' });
  });

  test('runs once: a second boot leaves both tables as they are, and rows an older release writes get their kind', () => {
    const dbPath = legacyDatabase('legacy-seq-once.sqlite');
    withStore(dbPath);
    const tables = tablePages(dbPath);

    // An older release lists only its own columns: the row gets the next seq and no kind.
    withDb(dbPath, (db) => {
      insertMcpRow(db, 'm-rolled-back', 'unverified_caller');
      insertPortalRow(db, 'p-rolled-back', 'LOGIN_FAILED');
    });
    const added = withDb(dbPath, (db) => ({
      ...(db.prepare(`SELECT seq, kind FROM mcp_copilot_logs WHERE id = 'm-rolled-back'`).get() as Row),
      portalSeq: (db.prepare(`SELECT seq FROM portal_admin_logs WHERE id = 'p-rolled-back'`).get() as Row).seq,
    }));
    assert.deepEqual(added, { seq: 8, kind: '', portalSeq: 6 });

    withStore(dbPath);
    assert.deepEqual(tablePages(dbPath), tables, 'neither table was rebuilt again');
    assert.equal(
      withDb(dbPath, (db) => (db.prepare(`SELECT kind FROM mcp_copilot_logs WHERE id = 'm-rolled-back'`).get() as Row).kind),
      'rejected'
    );
    assert.deepEqual(
      withDb(dbPath, (db) => plain(db.prepare('SELECT seq, id FROM mcp_copilot_logs ORDER BY seq').all())).map((r) => r.id),
      ['m-zulu', 'm-yankee', 'm-xray', 'm-whiskey', 'm-victor', 'm-uniform', 'm-rolled-back']
    );
  });

  test('an upgraded database ends with the same log tables as a new one', () => {
    const upgraded = legacyDatabase('legacy-seq-schema.sqlite');
    const fresh = path.join(testTmpDir, 'fresh-seq-schema.sqlite');
    withStore(upgraded);
    withStore(fresh);

    for (const table of LOG_TABLES) {
      const columns = tableInfo(fresh, table);
      assert.deepEqual(columns.slice(0, 2).map(({ name, type, notnull, pk }) => [name, type, notnull, pk]), [
        ['seq', 'INTEGER', 0, 1],
        ['id', 'TEXT', 1, 0],
      ]);
      assert.deepEqual(tableInfo(upgraded, table), columns, table);
      assert.deepEqual(indexInfo(upgraded, table), indexInfo(fresh, table), `${table} indexes`);
    }
    assert.deepEqual(
      tableInfo(fresh, 'mcp_copilot_logs').slice(-12).map(({ name, type, notnull, dflt_value }) => [name, type, notnull, dflt_value]),
      [
        ['kind', 'TEXT', 1, "''"],
        ['decision_json', 'TEXT', 1, "''"],
        ['decision_stage', 'TEXT', 1, "''"],
        ['decision_code', 'TEXT', 1, "''"],
        ['assigned_group_ids_json', 'TEXT', 1, "'[]'"],
        ['deciding_group_ids_json', 'TEXT', 1, "'[]'"],
        ['policy_revision', 'INTEGER', 0, null],
        ['caller_profile_id', 'TEXT', 1, "''"],
        ['matched_profile_id', 'TEXT', 1, "''"],
        ['match_method', 'TEXT', 1, "''"],
        ['verification_ms', 'INTEGER', 0, null],
        ['total_ms', 'INTEGER', 0, null],
      ]
    );
    // No table is left over from the rebuild, and an id still cannot be written twice.
    assert.deepEqual(
      withDb(upgraded, (db) => plain(db.prepare(`SELECT name FROM sqlite_master WHERE name LIKE '%__with_seq%'`).all())),
      []
    );
    withDb(upgraded, (db) => {
      assert.throws(() => insertMcpRow(db, 'm-zulu', 'real.user@acme.com'), /UNIQUE/);
      assert.throws(() => insertPortalRow(db, 'p-zulu', 'LOGIN_SUCCESS'), /UNIQUE/);
    });
  });
});
