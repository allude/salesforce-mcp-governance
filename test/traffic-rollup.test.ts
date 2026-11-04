import { testTmpDir } from './helpers/env.js';
// The chart reads a per-minute rollup of the MCP log so a poll does not scan 7 days of rows. The
// rollup must match the log after the upgrade that creates it and after every kind of write, and
// the index the dashboard added must not slow the existing newest-rows queries.
import { before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import fs from 'node:fs';
import path from 'node:path';

const MINUTE = 60_000;
const T = Date.parse('2026-05-01T10:00:00.000Z');
const iso = (ms: number) => new Date(ms).toISOString();

// A database from before the rollup existed: the log table as it was, already holding calls.
assert.equal(process.env.DB_PATH, path.join(testTmpDir, 'governance.sqlite'));
assert.ok(!fs.existsSync(process.env.DB_PATH!));
{
  const old = new DatabaseSync(process.env.DB_PATH!);
  old.exec(`
    CREATE TABLE mcp_copilot_logs (
      id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, sf_username TEXT NOT NULL, profile_id TEXT NOT NULL,
      profile_name TEXT NOT NULL, matched_groups_json TEXT NOT NULL DEFAULT '[]', tool_name TEXT NOT NULL,
      target_object TEXT NOT NULL DEFAULT '', status TEXT NOT NULL, latency_ms INTEGER NOT NULL DEFAULT 0,
      sanitized_request_payload TEXT NOT NULL DEFAULT '{}', sanitized_response_summary TEXT NOT NULL DEFAULT '{}',
      simulated INTEGER NOT NULL DEFAULT 0
    );`);
  const add = old.prepare(
    `INSERT INTO mcp_copilot_logs (id, timestamp, sf_username, profile_id, profile_name, tool_name, status, simulated)
     VALUES (?, ?, 'u@acme.com', '00e', 'P', 'soql_query', ?, ?)`
  );
  add.run('old1', iso(T + 5_000), 'ALLOWED', 0);
  add.run('old2', iso(T + 10_000), 'DENIED', 0);
  add.run('old3', iso(T + 59_999), 'ERROR', 0);
  add.run('old4', iso(T + 20_000), 'ALLOWED', 1);
  add.run('old5', iso(T + MINUTE), 'ALLOWED', 0);
  add.run('old6', 'not a time', 'ALLOWED', 0);
  old.close();
}

const { store } = await import('../src/db/store.js');
const db = new DatabaseSync(process.env.DB_PATH!);

/**
 * The 1h series for T's first half hour as {minute offset from T: [ok, warn, err]}. The series has no
 * end, so the call logged with the real clock is sent too; it is left out here.
 */
function minutes(now = T + 30 * MINUTE): Record<number, number[]> {
  const out: Record<number, number[]> = {};
  for (const s of store.getCopilotMcpTrafficSeries(now)['1h'].slices) {
    if (s.start >= T + 30 * MINUTE) continue;
    out[(s.start - T) / MINUTE] = [s.ok, s.warn, s.err];
  }
  return out;
}

/** What the rollup should hold, counted straight from the log. */
function fromLog(): Record<number, number[]> {
  const out: Record<number, number[]> = {};
  const rows = db
    .prepare(`SELECT timestamp, status FROM mcp_copilot_logs WHERE simulated = 0`)
    .all() as Array<{ timestamp: string; status: string }>;
  for (const r of rows) {
    const t = Date.parse(r.timestamp);
    if (Number.isNaN(t) || t < T || t >= T + 30 * MINUTE) continue;
    const m = Math.floor((t - T) / MINUTE);
    out[m] ??= [0, 0, 0];
    out[m][r.status === 'ALLOWED' ? 0 : r.status === 'DENIED' ? 1 : 2] += 1;
  }
  return out;
}

const log = (timestamp: number, status: 'ALLOWED' | 'DENIED' | 'ERROR', simulated = false) => {
  const id = `new_${timestamp}_${status}_${simulated}_${Math.random()}`;
  db.prepare(
    `INSERT INTO mcp_copilot_logs (id, timestamp, sf_username, profile_id, profile_name, tool_name, status, simulated)
     VALUES (?, ?, 'u@acme.com', '00e', 'P', 'soql_query', ?, ?)`
  ).run(id, iso(timestamp), status, simulated ? 1 : 0);
  return id;
};

describe('the upgrade', () => {
  test('fills the rollup from the calls already logged, leaving out simulated and unreadable rows', () => {
    assert.deepEqual(minutes(), { 0: [1, 1, 1], 1: [1, 0, 0] });
  });
});

describe('writes keep the rollup in step', () => {
  test('a call logged through the store is counted', () => {
    store.recordCopilotMcpLog({
      sfUsername: 'live@acme.com',
      profileId: '00e',
      profileName: 'P',
      matchedGroups: [],
      toolName: 'get_record',
      targetObject: 'Account',
      status: 'ALLOWED',
      latencyMs: 5,
      rawRequestPayload: {},
      rawResponseSummary: {},
    });
    // Stamped with the real clock, so it shows in a series read now and not in T's hour.
    const live = store.getCopilotMcpTrafficSeries(Date.now())['1h'].slices;
    assert.equal(live.reduce((n, s) => n + s.ok, 0), 1);
    assert.deepEqual(minutes(), { 0: [1, 1, 1], 1: [1, 0, 0] });
  });

  test('inserts, deletes and updates from any connection', () => {
    const a = log(T + 5 * MINUTE, 'DENIED');
    log(T + 5 * MINUTE + 1, 'ERROR');
    log(T + 5 * MINUTE + 2, 'ALLOWED', true);
    assert.deepEqual(minutes()[5], [0, 1, 1]);

    db.prepare('DELETE FROM mcp_copilot_logs WHERE id = ?').run(a);
    assert.deepEqual(minutes()[5], [0, 0, 1]);

    db.prepare(`UPDATE mcp_copilot_logs SET simulated = 1 WHERE id = 'old5'`).run();
    assert.equal(minutes()[1], undefined, 'a row marked simulated leaves the chart');

    db.prepare(`UPDATE mcp_copilot_logs SET timestamp = ?, status = 'DENIED' WHERE id = 'old1'`).run(iso(T + 7 * MINUTE));
    assert.deepEqual(minutes()[0], [0, 1, 1]);
    assert.deepEqual(minutes()[7], [0, 1, 0]);

    db.prepare(`UPDATE mcp_copilot_logs SET timestamp = ? WHERE id = 'old6'`).run(iso(T + 9 * MINUTE));
    assert.deepEqual(minutes()[9], [1, 0, 0], 'a row whose time becomes readable is counted');
  });

  test('after a mix of writes the rollup matches the log', () => {
    for (let i = 0; i < 200; i++) {
      const status = (['ALLOWED', 'DENIED', 'ERROR'] as const)[i % 3];
      log(T + ((i * 7919) % (25 * MINUTE)), status, i % 11 === 0);
    }
    db.exec(`DELETE FROM mcp_copilot_logs WHERE rowid % 13 = 0`);
    db.exec(`UPDATE mcp_copilot_logs SET simulated = 1 - simulated WHERE rowid % 17 = 0`);
    assert.deepEqual(minutes(), fromLog());
  });

  test('a minute emptied by deletes is not sent', () => {
    const id = log(T + 20 * MINUTE + 30_000, 'ALLOWED');
    db.prepare('DELETE FROM mcp_copilot_logs WHERE timestamp >= ? AND timestamp < ?').run(iso(T + 20 * MINUTE), iso(T + 21 * MINUTE));
    assert.equal(minutes()[20], undefined, id);
  });
});

describe('query plans', () => {
  let plan: (sql: string) => string;
  before(() => {
    plan = (sql) =>
      (db.prepare(`EXPLAIN QUERY PLAN ${sql}`).all({}) as Array<{ detail: string }>).map((r) => r.detail).join(' | ');
  });

  test('the newest-rows queries keep their rowid scan, which stops after LIMIT', () => {
    for (const sql of [
      `SELECT * FROM mcp_copilot_logs WHERE simulated = 0 AND sf_username <> 'x' ORDER BY rowid DESC LIMIT 150`,
      `SELECT * FROM mcp_copilot_logs WHERE simulated <> 0 ORDER BY rowid DESC LIMIT 50`,
      `SELECT timestamp FROM mcp_copilot_logs WHERE simulated = 0 AND sf_username <> 'x' ORDER BY rowid DESC LIMIT 1`,
    ]) {
      const p = plan(sql);
      assert.doesNotMatch(p, /TEMP B-TREE FOR ORDER BY/, p);
      assert.match(p, /SCAN mcp_copilot_logs/, p);
    }
  });

  test('the 24-hour figures search by time', () => {
    const p = plan(
      `SELECT COUNT(*) FROM mcp_copilot_logs WHERE simulated = 0 AND timestamp >= '2026-05-01' AND sf_username <> 'x'`
    );
    assert.match(p, /USING INDEX idx_mcp_copilot_logs_timestamp \(timestamp>\?\)/, p);
  });

  test('the chart reads the rollup by its key, not the log', () => {
    const p = plan(`SELECT minute / 5, SUM(ok) FROM mcp_traffic_minutes WHERE minute >= 100 GROUP BY 1`);
    assert.match(p, /SEARCH mcp_traffic_minutes USING INTEGER PRIMARY KEY \(rowid>\?\)/, p);
  });
});
