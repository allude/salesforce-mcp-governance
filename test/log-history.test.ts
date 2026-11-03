import './helpers/env.js';
// The Logs views' paging and export logic, against an in-memory log that pages like the routes.
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import {
  auditRouteQuery,
  auditRowMatches,
  LOG_EXPORT_MAX_ROWS,
  LOG_EXPORT_MAX_SCANNED_ROWS,
  LOG_EXPORT_PAGE_ROWS,
  exportCutMessage,
  exportFileName,
  exportTruncatedMessage,
  logPageUrl,
  mergeNewestFirst,
  readAllRows,
  readOlderRows,
  trafficRouteQuery,
  trafficRowMatches,
  type ReadLogPage,
} from '../src/components/views/logHistory.js';
import type { CopilotMcpLogEntry, PortalAdminLogEntry } from '../src/types/governance.js';

interface Row {
  id: string;
  seq: number;
}

/** Rows seq 1..count, paged newest first exactly as the routes do, counting the requests. */
function pagedLog(count: number) {
  const rows: Row[] = Array.from({ length: count }, (_, i) => ({ id: `r${i + 1}`, seq: i + 1 })).reverse();
  const calls: Array<{ before: number | undefined; limit: number }> = [];
  const read: ReadLogPage<Row> = async (before, limit) => {
    calls.push({ before, limit });
    const older = rows.filter((r) => before === undefined || r.seq < before);
    const page = older.slice(0, limit);
    return { rows: page, nextBefore: older.length > limit ? page[page.length - 1].seq : null };
  };
  return { rows, read, calls };
}

describe('readOlderRows', () => {
  test('skips pages the view already holds, so a click always shows something older', async () => {
    const log = pagedLog(1000);
    // What /overview might hold: the newest 300 rows.
    const held = new Set(log.rows.slice(0, 300).map((r) => r.id));
    const page = await readOlderRows(log.read, undefined, held, 200);
    assert.deepEqual(log.calls.map((c) => c.before), [undefined, 801]);
    assert.ok(page.rows.some((r) => !held.has(r.id)));
    assert.equal(page.nextBefore, 601);
  });

  test('continues from its cursor and reports the start of the log', async () => {
    const log = pagedLog(250);
    const page = await readOlderRows(log.read, 51, new Set(), 200);
    assert.deepEqual(page.rows.map((r) => r.seq), Array.from({ length: 50 }, (_, i) => 50 - i));
    assert.equal(page.nextBefore, null);
  });

  test('stops when the log ends even if nothing new turned up', async () => {
    const log = pagedLog(10);
    const page = await readOlderRows(log.read, undefined, new Set(log.rows.map((r) => r.id)), 4);
    assert.equal(page.nextBefore, null);
    assert.equal(log.calls.length, 3);
  });

  test('treats a cursor that does not move back as the end instead of looping', async () => {
    const stuck: ReadLogPage<Row> = async () => ({ rows: [{ id: 'a', seq: 5 }], nextBefore: 5 });
    const page = await readOlderRows(stuck, 5, new Set(['a']));
    assert.equal(page.nextBefore, null);
  });
});

describe('readAllRows', () => {
  test('reads every row, newest first, when the log is under the limit', async () => {
    const log = pagedLog(2500);
    const { rows, truncated } = await readAllRows(log.read);
    assert.equal(truncated, false);
    assert.deepEqual(rows, log.rows);
    assert.ok(log.calls.every((c) => c.limit <= 1000));
  });

  test('stops at 10,000 rows by default and marks the export cut', async () => {
    const log = pagedLog(10_001);
    const { rows, truncated } = await readAllRows(log.read);
    assert.equal(rows.length, 10_000);
    assert.equal(truncated, true);
    assert.equal(rows[rows.length - 1].seq, 2, 'the newest rows are the ones kept');
  });

  test('is not cut when the log holds exactly the limit', async () => {
    const { rows, truncated } = await readAllRows(pagedLog(10_000).read);
    assert.equal(rows.length, 10_000);
    assert.equal(truncated, false);
  });

  test('asks only for the rows still needed on the last page', async () => {
    const log = pagedLog(100);
    await readAllRows(log.read, 25, 10);
    assert.deepEqual(log.calls.map((c) => c.limit), [10, 10, 5]);
  });
});

describe('export naming and notice', () => {
  test('a cut export says so in its file name', () => {
    assert.equal(exportFileName('portal-audit-log', '2026-11-02', false), 'portal-audit-log-2026-11-02.csv');
    assert.equal(
      exportFileName('portal-audit-log', '2026-11-02', true),
      'portal-audit-log-2026-11-02-newest-10000-rows.csv'
    );
    assert.match(exportTruncatedMessage(), /newest 10,000 matching rows/);
  });
});

describe('export with a search the route cannot apply', () => {
  test('counts the limit after the search, so rare matches past the newest 10,000 rows are kept', async () => {
    // 50,000 rows; 12 match, spread down to the oldest rows.
    const log = pagedLog(50_000);
    const matches = new Set(Array.from({ length: 12 }, (_, i) => i * 4000 + 7));
    const keep = (r: Row) => matches.has(r.seq);
    const read = await readAllRows(log.read, LOG_EXPORT_MAX_ROWS, LOG_EXPORT_PAGE_ROWS, { keep });
    assert.equal(read.rows.length, 12);
    assert.deepEqual(read.rows.map((r) => r.seq), [...matches].sort((a, b) => b - a));
    assert.equal(read.scanned, 50_000);
    assert.equal(read.cut, null);
    assert.equal(read.truncated, false);
    assert.equal(exportFileName('mcp-traffic-log', '2026-11-02', read.cut), 'mcp-traffic-log-2026-11-02.csv');
  });

  test('stops at the most kept rows, newest first, and says the match limit cut it', async () => {
    const log = pagedLog(1000);
    const read = await readAllRows(log.read, 30, 100, { keep: (r) => r.seq % 2 === 0 });
    assert.equal(read.rows.length, 30);
    assert.equal(read.rows[0].seq, 1000);
    assert.equal(read.rows[29].seq, 942);
    assert.deepEqual(read.cut, { by: 'matches', matched: 30, scanned: 60 });
    assert.equal(read.truncated, true);
    assert.equal(exportFileName('portal-audit-log', '2026-11-02', read.cut, 30), 'portal-audit-log-2026-11-02-newest-30-rows.csv');
    assert.equal(
      exportCutMessage({ by: 'matches', matched: 10_000, scanned: 61_234 }),
      'Export stopped at the newest 10,000 matching rows, the most one file holds; older rows were not checked.'
    );
  });

  test('a rare search stops at the scan bound and says how many rows matched in what it read', async () => {
    const log = pagedLog(1000);
    const read = await readAllRows(log.read, 30, 100, { keep: (r) => r.seq % 97 === 0, maxScanned: 450 });
    assert.deepEqual(read.rows.map((r) => r.seq), [970, 873, 776, 679, 582]);
    assert.deepEqual(read.cut, { by: 'scan', matched: 5, scanned: 450 });
    assert.ok(log.calls.every((c) => c.limit <= 100));
    assert.equal(log.calls.reduce((n, c) => n + c.limit, 0), 450, 'never asks for rows past the scan bound');
    assert.equal(
      exportFileName('mcp-traffic-log', '2026-11-02', read.cut),
      'mcp-traffic-log-2026-11-02-5-matching-in-newest-450-rows.csv'
    );
    assert.equal(
      exportCutMessage({ by: 'scan', matched: 12, scanned: 100_000 }),
      'Export stopped after checking the newest 100,000 rows, the most one export reads: 12 rows matched; older rows were not checked.'
    );
    assert.match(exportCutMessage({ by: 'scan', matched: 1, scanned: 100_000 }), /: 1 row matched;/);
  });

  test('a log that ends at the scan bound or the match limit is not called cut', async () => {
    const all = await readAllRows(pagedLog(450).read, 30, 100, { keep: (r) => r.seq % 97 === 0, maxScanned: 450 });
    assert.equal(all.cut, null);
    const exact = await readAllRows(pagedLog(60).read, 30, 100, { keep: (r) => r.seq % 2 === 0 });
    assert.equal(exact.rows.length, 30);
    assert.equal(exact.cut, null);
  });

  test('the scan bound defaults to 100,000 rows', async () => {
    assert.equal(LOG_EXPORT_MAX_SCANNED_ROWS, 100_000);
    const log = pagedLog(100_001);
    const read = await readAllRows(log.read, undefined, undefined, { keep: () => false });
    assert.deepEqual(read.cut, { by: 'scan', matched: 0, scanned: 100_000 });
  });
});

describe('mergeNewestFirst', () => {
  test('orders by seq across lists and keeps each id once', () => {
    const merged = mergeNewestFirst(
      [{ id: 'c', seq: 9 }, { id: 'a', seq: 3 }],
      [{ id: 'b', seq: 5 }, { id: 'a', seq: 3 }, { id: 'z', seq: 1 }]
    );
    assert.deepEqual(merged.map((r) => r.id), ['c', 'b', 'a', 'z']);
  });
});

describe('route queries', () => {
  test('logPageUrl leaves out unset parameters and encodes the rest', () => {
    assert.equal(logPageUrl('/api/admin/mcp-logs', {}), '/api/admin/mcp-logs');
    assert.equal(
      logPageUrl('/api/admin/portal-logs', { before: 12, limit: 200, action: 'A&B', authMethod: undefined }),
      '/api/admin/portal-logs?before=12&limit=200&action=A%26B'
    );
  });

  const call: CopilotMcpLogEntry = {
    id: 'mcp_1',
    timestamp: '2026-11-02T10:00:00.000Z',
    sfUsername: 'Jane@Acme.com',
    profileId: '00e000000000001',
    profileName: 'Sales',
    matchedGroups: [],
    toolName: 'soql_query',
    targetObject: 'Account',
    status: 'DENIED',
    latencyMs: 4,
    sanitizedRequestPayload: '{}',
    sanitizedResponseSummary: '{}',
  };

  test('the traffic filters the route applies match the view, and search stays client-side', () => {
    const filters = { status: 'DENIED' as const, tool: 'soql_query', object: 'all', search: 'jane' };
    assert.deepEqual(trafficRouteQuery(filters), { status: 'DENIED', tool: 'soql_query', object: undefined });
    assert.equal(trafficRowMatches(call, filters), true);
    assert.equal(trafficRowMatches(call, { ...filters, search: 'bob' }), false);
    assert.equal(trafficRowMatches(call, { ...filters, status: 'ALLOWED' }), false);
  });

  const audit: PortalAdminLogEntry = {
    id: 'adm_1',
    timestamp: '2026-11-02T10:00:00.000Z',
    adminUsername: 'admin',
    authMethod: 'okta_sso',
    action: 'SIMULATE_MCP_CALL',
    target: 'Profile 00e',
    details: 'Issued a 15-minute simulator token',
    ipAddress: '127.0.0.1',
  };

  test('the audit filters the route applies match the view', () => {
    const filters = { method: 'okta_sso' as const, action: 'SIMULATE_MCP_CALL', search: 'simulator' };
    assert.deepEqual(auditRouteQuery(filters), { authMethod: 'okta_sso', action: 'SIMULATE_MCP_CALL' });
    assert.equal(auditRowMatches(audit, filters), true);
    assert.equal(auditRowMatches(audit, { ...filters, method: 'password' }), false);
    assert.deepEqual(auditRouteQuery({ method: 'all', action: 'all', search: '' }), {
      authMethod: undefined,
      action: undefined,
    });
  });
});
