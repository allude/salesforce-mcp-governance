import './helpers/env.js';
// The paged log routes reach every stored row, past the /overview caps, without gaps or repeats.
// This file's fresh database makes the counts exact.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { store, UNVERIFIED_CALLER_USERNAME } from '../src/db/store.js';
import { startTestServer, loginAsAdmin, adminFetch, type AdminSession, type TestServer } from './helpers/server.js';
import { LOG_PAGE_DEFAULT_ROWS, LOG_PAGE_MAX_ROWS } from '../src/routes/logPageQuery.js';
import { logPageUrl, readAllRows, type ReadLogPage } from '../src/components/views/logHistory.js';
import { portalAuditCsv } from '../src/components/views/csvExport.js';

let server: TestServer;
let session: AdminSession;

before(async () => {
  server = await startTestServer();
  session = await loginAsAdmin(server.baseUrl);
});

after(async () => {
  await server.close();
});

const get = (path: string) => adminFetch(server.baseUrl, session, path);

const logCall = (opts: { status?: 'ALLOWED' | 'DENIED' | 'ERROR'; simulated?: boolean; tool?: string; object?: string } = {}) =>
  store.recordCopilotMcpLog({
    sfUsername: opts.simulated ? 'simulated:test-user' : 'real.user@acme.com',
    profileId: '00e000000000001',
    profileName: 'P',
    matchedGroups: [],
    toolName: opts.tool ?? 'soql_query',
    targetObject: opts.object ?? 'Account',
    status: opts.status ?? 'ALLOWED',
    latencyMs: 3,
    rawRequestPayload: {},
    rawResponseSummary: {},
    simulated: opts.simulated,
  });

const logAudit = (action: string, authMethod: 'password' | 'okta_sso' = 'password') =>
  store.recordPortalAdminLog({ adminUsername: 'admin', authMethod, action, target: 'T', details: 'D' });

/** Follows nextBefore from the newest page to the end, as the portal does. */
async function readEveryPage(path: string, query: Record<string, string | number> = {}) {
  const ids: string[] = [];
  let beforeCursor: number | undefined;
  for (;;) {
    const res = await get(logPageUrl(path, { ...query, before: beforeCursor }));
    assert.equal(res.status, 200, JSON.stringify(res.body));
    ids.push(...res.body.rows.map((r: any) => r.id));
    if (res.body.nextBefore === null) return ids;
    assert.ok(beforeCursor === undefined || res.body.nextBefore < beforeCursor, 'the cursor moves back');
    beforeCursor = res.body.nextBefore;
  }
}

describe('GET /api/admin/mcp-logs and /api/admin/portal-logs', () => {
  test('need an admin session', async () => {
    for (const path of ['/api/admin/mcp-logs', '/api/admin/portal-logs']) {
      const res = await fetch(`${server.baseUrl}${path}`);
      assert.equal(res.status, 401, path);
    }
  });

  test('page through every MCP row, newest first, with no gaps or repeats past the /overview caps', async () => {
    logCall({ status: 'DENIED' });
    for (let i = 0; i < 160; i += 1) logCall({ simulated: true });
    for (let i = 0; i < 60; i += 1) {
      store.recordCopilotMcpLog({
        sfUsername: UNVERIFIED_CALLER_USERNAME,
        profileId: 'unverified',
        profileName: 'Unverified Token',
        matchedGroups: [],
        toolName: 'mcp_authenticate',
        targetObject: '*',
        status: 'DENIED',
        latencyMs: 1,
        rawRequestPayload: {},
        rawResponseSummary: {},
      });
    }
    for (let i = 0; i < 160; i += 1) logCall();

    const stored = store.getCopilotMcpLogs(1_000_000).map((r) => r.id);
    const overview = (await get('/api/admin/overview')).body.copilotLogs;
    assert.ok(overview.length < stored.length, 'the /overview list is capped');

    assert.deepEqual(await readEveryPage('/api/admin/mcp-logs', { limit: 37 }), stored);
  });

  test('a page defaults to 200 rows, carries seq, and its nextBefore is the last row', async () => {
    const res = await get('/api/admin/mcp-logs');
    assert.equal(res.body.rows.length, LOG_PAGE_DEFAULT_ROWS);
    const seqs = res.body.rows.map((r: any) => r.seq);
    assert.ok(seqs.every((s: unknown, i: number) => typeof s === 'number' && (i === 0 || (s as number) < seqs[i - 1])));
    assert.equal(res.body.nextBefore, seqs[seqs.length - 1]);
  });

  test('the overview rows carry the same seq as the paged rows, so the portal can merge them', async () => {
    const overview = (await get('/api/admin/overview')).body.copilotLogs;
    const page = (await get(`/api/admin/mcp-logs?limit=${LOG_PAGE_MAX_ROWS}`)).body.rows;
    const seqById = new Map(page.map((r: any) => [r.id, r.seq]));
    for (const row of overview) assert.equal(row.seq, seqById.get(row.id), row.id);
  });

  test('filter MCP rows by status, simulated, tool and object', async () => {
    const error = logCall({ status: 'ERROR', tool: 'delete_record', object: 'Case' });
    const all = store.getCopilotMcpLogs(1_000_000);

    const errors = await readEveryPage('/api/admin/mcp-logs', { status: 'ERROR' });
    assert.deepEqual(errors, all.filter((r) => r.status === 'ERROR').map((r) => r.id));
    assert.equal(errors[0], error.id);

    const simulated = await readEveryPage('/api/admin/mcp-logs', { simulated: 'true', limit: LOG_PAGE_MAX_ROWS });
    assert.deepEqual(simulated, all.filter((r) => r.simulated).map((r) => r.id));
    const real = await readEveryPage('/api/admin/mcp-logs', { simulated: 'false', limit: LOG_PAGE_MAX_ROWS });
    assert.deepEqual(real, all.filter((r) => !r.simulated).map((r) => r.id));

    assert.deepEqual(await readEveryPage('/api/admin/mcp-logs', { tool: 'delete_record', object: 'Case' }), [error.id]);
    assert.deepEqual(await readEveryPage('/api/admin/mcp-logs', { tool: 'delete_record', object: 'Account' }), []);
  });

  test('every policy simulation stays reachable after more than 50 newer ones', async () => {
    const first = logAudit('SIMULATE_MCP_CALL');
    for (let i = 0; i < 60; i += 1) logAudit('SIMULATE_MCP_CALL');

    const overview = (await get('/api/admin/overview')).body.portalLogs;
    assert.equal(overview.some((l: any) => l.id === first.id), false, 'the /overview list is capped');

    const simulations = await readEveryPage('/api/admin/portal-logs', { action: 'SIMULATE_MCP_CALL' });
    assert.equal(simulations.length, 61);
    assert.equal(simulations[simulations.length - 1], first.id);
  });

  test('page through every portal row and filter by sign-in method', async () => {
    const sso = logAudit('LOGIN_SUCCESS', 'okta_sso');
    const stored = store.getPortalAdminLogs(1_000_000).map((r) => r.id);
    assert.deepEqual(await readEveryPage('/api/admin/portal-logs', { limit: 9 }), stored);
    assert.deepEqual(await readEveryPage('/api/admin/portal-logs', { authMethod: 'okta_sso' }), [sso.id]);
  });

  test('reading a page writes nothing, not even an audit row', async () => {
    const auditsBefore = store.getPortalAdminLogs(1_000_000).length;
    const callsBefore = store.getCopilotMcpLogs(1_000_000).length;
    await get('/api/admin/mcp-logs');
    await get('/api/admin/portal-logs');
    assert.equal(store.getPortalAdminLogs(1_000_000).length, auditsBefore);
    assert.equal(store.getCopilotMcpLogs(1_000_000).length, callsBefore);
  });

  test('refuse malformed paging and filters with 400', async () => {
    const bad = [
      '/api/admin/mcp-logs?limit=0',
      `/api/admin/mcp-logs?limit=${LOG_PAGE_MAX_ROWS + 1}`,
      '/api/admin/mcp-logs?limit=abc',
      '/api/admin/mcp-logs?limit=1.5',
      '/api/admin/mcp-logs?before=-1',
      '/api/admin/mcp-logs?before=99999999999999999999',
      '/api/admin/mcp-logs?before=1&before=2',
      '/api/admin/mcp-logs?status=allowed',
      '/api/admin/mcp-logs?simulated=1',
      '/api/admin/mcp-logs?tool=',
      `/api/admin/mcp-logs?object=${'x'.repeat(256)}`,
      '/api/admin/portal-logs?authMethod=saml',
      '/api/admin/portal-logs?action[x]=1',
    ];
    for (const path of bad) {
      const res = await get(path);
      assert.equal(res.status, 400, path);
      assert.equal(typeof res.body.error, 'string', path);
    }
  });
});

describe('CSV export through the paged route', () => {
  const readPortalPage =
    (query: Record<string, string>): ReadLogPage<any> =>
    async (beforeCursor, limit) =>
      (await get(logPageUrl('/api/admin/portal-logs', { ...query, before: beforeCursor, limit }))).body;

  test('includes simulations the /overview list leaves out', async () => {
    const { rows, truncated } = await readAllRows(readPortalPage({ action: 'SIMULATE_MCP_CALL' }));
    assert.equal(truncated, false);
    const stored = store.getPortalAdminLogs(1_000_000).filter((l) => l.action === 'SIMULATE_MCP_CALL');
    assert.deepEqual(rows.map((r) => r.id), stored.map((r) => r.id));
    const csv = portalAuditCsv(rows);
    assert.equal(csv.split('\n').length, stored.length + 1);
  });

  test('stops at the row limit and reports that it was cut', async () => {
    const { rows, truncated } = await readAllRows(readPortalPage({}), 25, 10);
    assert.equal(rows.length, 25);
    assert.equal(truncated, true);
    assert.deepEqual(rows.map((r) => r.id), store.getPortalAdminLogs(25).map((r) => r.id));
  });

  test('is not marked cut when the log holds exactly the row limit', async () => {
    const total = store.getPortalAdminLogs(1_000_000).length;
    const { rows, truncated } = await readAllRows(readPortalPage({}), total, 7);
    assert.equal(rows.length, total);
    assert.equal(truncated, false);
  });
});
