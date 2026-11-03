import './helpers/env.js';
// Covers the /mcp limit on rejected bearer tokens in src/index.ts (mcpRejectedTokenLimiter) and the
// recently-verified exemption it reads from src/salesforce/client.ts. Each test sends from its own
// forwarded client address (the test env trusts X-Forwarded-For from loopback), so buckets never mix.
import { after, before, beforeEach, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { store, UNVERIFIED_CALLER_USERNAME } from '../src/db/store.js';
import { createSimulatorToken } from '../src/salesforce/client.js';
import { installSalesforceMock, type SalesforceMock } from './helpers/salesforceMock.js';
import { mcpRequest, startTestServer, type TestServer } from './helpers/server.js';

const FAILED_TOKEN_LIMIT = 30;

let server: TestServer;
let sf: SalesforceMock;
let ipCounter = 0;

before(async () => {
  sf = installSalesforceMock();
  server = await startTestServer();
});

after(async () => {
  await server.close();
  sf.restore();
});

beforeEach(() => sf.reset());

/** A forwarded client address no other test in this file uses. */
function freshClient(): Record<string, string> {
  ipCounter += 1;
  return { 'X-Forwarded-For': `203.0.113.${ipCounter}` };
}

const junkToken = () => `junk_${crypto.randomBytes(12).toString('hex')}`;

function addValidUser(): string {
  const token = `valid_${crypto.randomBytes(12).toString('hex')}`;
  sf.addUser(token, {
    userId: '005000000000777AAA',
    organizationId: '00D000000000001AAA',
    username: `limit.${ipCounter}@acme.example`,
    profileId: '00e000000000777AAA',
    profileName: 'Limit Test',
  });
  return token;
}

const rejectedRows = () =>
  store.getCopilotMcpLogs(5000).filter((row) => row.sfUsername === UNVERIFIED_CALLER_USERNAME).length;

async function exhaust(client: Record<string, string>): Promise<void> {
  for (let i = 0; i < FAILED_TOKEN_LIMIT; i++) {
    const res = await mcpRequest(server.baseUrl, junkToken(), 'tools/list', {}, client);
    assert.equal(res.status, 401, `junk token ${i + 1} is checked and refused`);
  }
}

describe('rejected bearer tokens are limited per client IP', () => {
  test('a new junk token each time is refused with 429 after the limit, without reaching Salesforce or the log', async () => {
    const client = freshClient();
    const rowsBefore = rejectedRows();
    await exhaust(client);
    const userinfoCalls = sf.calls.length;
    assert.equal(userinfoCalls, FAILED_TOKEN_LIMIT, 'each refused token cost one userinfo call');
    assert.equal(rejectedRows() - rowsBefore, FAILED_TOKEN_LIMIT);

    const blocked = await mcpRequest(server.baseUrl, junkToken(), 'tools/list', {}, client);

    assert.equal(blocked.status, 429);
    assert.ok(Number(blocked.headers.get('retry-after')) > 0, 'a 429 says when to retry');
    assert.equal(blocked.body?.error?.code, -32001);
    assert.equal(sf.calls.length, userinfoCalls, 'a blocked token never reaches Salesforce');
    assert.equal(rejectedRows() - rowsBefore, FAILED_TOKEN_LIMIT, 'a blocked token writes no log row');
  });

  test('a token that verified before the flood keeps working from the same IP', async () => {
    const client = freshClient();
    const token = addValidUser();
    assert.equal((await mcpRequest(server.baseUrl, token, 'tools/list', {}, client)).status, 200);

    await exhaust(client);

    assert.equal((await mcpRequest(server.baseUrl, junkToken(), 'tools/list', {}, client)).status, 429);
    assert.equal((await mcpRequest(server.baseUrl, token, 'tools/list', {}, client)).status, 200);
  });

  test('a valid simulator token that verified before the flood keeps working from the same IP', async () => {
    const client = freshClient();
    const token = createSimulatorToken({ profileId: '00e000000000777AAA', profileName: 'Limit Test' });
    assert.equal((await mcpRequest(server.baseUrl, token, 'tools/list', {}, client)).status, 200);

    await exhaust(client);

    assert.equal((await mcpRequest(server.baseUrl, token, 'tools/list', {}, client)).status, 200);
  });

  test('during a flood a token that has not verified yet waits, while other client IPs are unaffected', async () => {
    const flooded = freshClient();
    await exhaust(flooded);
    const token = addValidUser();

    assert.equal((await mcpRequest(server.baseUrl, token, 'tools/list', {}, flooded)).status, 429);
    assert.equal((await mcpRequest(server.baseUrl, token, 'tools/list', {}, freshClient())).status, 200);
    assert.equal((await mcpRequest(server.baseUrl, junkToken(), 'tools/list', {}, freshClient())).status, 401);
  });

  test('requests with no token and requests that verify do not count towards the limit', async () => {
    const client = freshClient();
    for (let i = 0; i < FAILED_TOKEN_LIMIT + 5; i++) {
      assert.equal((await mcpRequest(server.baseUrl, null, 'tools/list', {}, client)).status, 401);
    }
    for (let i = 0; i < FAILED_TOKEN_LIMIT + 5; i++) {
      assert.equal((await mcpRequest(server.baseUrl, addValidUser(), 'tools/list', {}, client)).status, 200);
    }

    await exhaust(client);
    assert.equal((await mcpRequest(server.baseUrl, junkToken(), 'tools/list', {}, client)).status, 429);
  });

  test('forged simulator tokens count like any other rejected token', async () => {
    const client = freshClient();
    for (let i = 0; i < FAILED_TOKEN_LIMIT; i++) {
      const forged = `sf_sim_${Buffer.from(JSON.stringify({ i })).toString('base64url')}.bad`;
      assert.equal((await mcpRequest(server.baseUrl, forged, 'tools/list', {}, client)).status, 401);
    }
    assert.equal((await mcpRequest(server.baseUrl, junkToken(), 'tools/list', {}, client)).status, 429);
  });
});
