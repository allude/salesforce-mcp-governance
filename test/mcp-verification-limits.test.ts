import './helpers/env.js';
// Covers what bounds the cost of junk /mcp bearer tokens without refusing valid ones:
// src/mcp/bearer.ts (one token parser for the limiters and the handler), src/security/clientIp.ts
// (IPv6 /64 keys, and when req.ip tells clients apart), src/security/failureWindow.ts,
// src/salesforce/verificationGate.ts, and the rejected-token cache and exemption in
// src/salesforce/client.ts, end to end through /mcp.
import { after, before, beforeEach, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Request } from 'express';
import { store, UNVERIFIED_CALLER_USERNAME } from '../src/db/store.js';
import { isPlausibleBearerToken, parseBearerToken } from '../src/mcp/bearer.js';
import { clientIpIsForwarded, rateLimitIpKey } from '../src/security/clientIp.js';
import { createFailureWindow } from '../src/security/failureWindow.js';
import { createVerificationGate, VerificationBusyError } from '../src/salesforce/verificationGate.js';
import { verificationGateStats, wasTokenRecentlyVerified } from '../src/salesforce/client.js';
import { installSalesforceMock, type SalesforceMock } from './helpers/salesforceMock.js';
import { mcpRequest, startTestServer, type TestServer } from './helpers/server.js';

describe('parseBearerToken', () => {
  test('reads the token after "Bearer" and one or more spaces, in any case', () => {
    assert.equal(parseBearerToken('Bearer abc'), 'abc');
    assert.equal(parseBearerToken('bearer   abc  '), 'abc');
    assert.equal(parseBearerToken('BEARER 00D000000000001!AQ.x'), '00D000000000001!AQ.x');
  });

  test('anything else is no token: other separators, a blank token, other schemes, non-strings', () => {
    for (const header of ['Bearer', 'Bearer ', 'Bearer    ', 'Bearer\tabc', 'Bearerabc', 'Basic abc', '', undefined, ['Bearer abc']]) {
      assert.equal(parseBearerToken(header), '', JSON.stringify(header));
    }
  });

  test('a token made only of a non-breaking space is still a token, and is not plausible', () => {
    const token = parseBearerToken('Bearer  ');
    assert.equal(token, ' ');
    assert.equal(isPlausibleBearerToken(token), false);
  });

  test('isPlausibleBearerToken accepts printable ASCII only, up to 4096 characters', () => {
    assert.equal(isPlausibleBearerToken('00D000000000001!AQ.x_y-z~+/='), true);
    assert.equal(isPlausibleBearerToken('a b'), false);
    assert.equal(isPlausibleBearerToken('ä'), false);
    assert.equal(isPlausibleBearerToken('x'.repeat(4097)), false);
  });
});

describe('rateLimitIpKey', () => {
  test('IPv6 addresses in one /64 share a key, and other /64s do not', () => {
    const key = rateLimitIpKey('2001:db8:1:2::1');
    assert.equal(key, '2001:db8:1:2::/64');
    assert.equal(rateLimitIpKey('2001:0db8:0001:0002:ffff:ffff:ffff:ffff'), key);
    assert.equal(rateLimitIpKey('2001:DB8:1:2:a:b:c:d%eth0'), key);
    assert.notEqual(rateLimitIpKey('2001:db8:1:3::1'), key);
  });

  test('IPv4 and IPv4-mapped IPv6 give the plain IPv4 address', () => {
    assert.equal(rateLimitIpKey('203.0.113.9'), '203.0.113.9');
    assert.equal(rateLimitIpKey('::ffff:203.0.113.9'), '203.0.113.9');
  });

  test('short and embedded-IPv4 forms expand correctly', () => {
    assert.equal(rateLimitIpKey('::1'), '0:0:0:0::/64');
    assert.equal(rateLimitIpKey('64:ff9b::192.0.2.33'), '64:ff9b:0:0::/64');
    assert.equal(rateLimitIpKey('fe80::'), 'fe80:0:0:0::/64');
  });

  test('a missing address is an empty key', () => {
    assert.equal(rateLimitIpKey(undefined), '');
  });
});

describe('clientIpIsForwarded', () => {
  // req.ip is what Express resolved: the socket address unless a trusted proxy named the client.
  const req = (remoteAddress: string, ip: string = remoteAddress) => ({ ip, socket: { remoteAddress } }) as unknown as Request;

  test('a connection whose address is req.ip may be a shared proxy, so per-IP limits are off', () => {
    // The portal proxy on loopback, on another container or host (MCP_BACKEND_URL), or a
    // TRUST_PROXY that does not cover the connecting hop: req.ip stays the socket address.
    for (const address of ['127.0.0.1', '::1', '::ffff:127.0.0.1', '172.18.0.3', '::ffff:10.0.0.5', '2001:db8::7']) {
      assert.equal(clientIpIsForwarded(req(address)), false, address);
    }
    assert.equal(clientIpIsForwarded(req('::ffff:172.18.0.3', '172.18.0.3')), false, 'mapped form of the same address');
    assert.equal(clientIpIsForwarded(req('2001:db8::7', '2001:db8::99')), false, 'same /64 as the proxy');
  });

  test('a client address supplied by a trusted proxy tells clients apart', () => {
    assert.equal(clientIpIsForwarded(req('127.0.0.1', '203.0.113.9')), true);
    assert.equal(clientIpIsForwarded(req('172.18.0.3', '2001:db8:1::5')), true);
  });

  test('a missing address is never treated as a client', () => {
    assert.equal(clientIpIsForwarded({ socket: {} } as unknown as Request), false);
  });
});

describe('createFailureWindow', () => {
  test('refuses after max failures until the window ends, then starts again', () => {
    const window = createFailureWindow({ windowMs: 60_000, max: 3, maxKeys: 10 });
    for (let i = 0; i < 3; i++) {
      assert.equal(window.retryAfterSeconds('a', 1_000), 0);
      window.record('a', 1_000);
    }
    assert.equal(window.retryAfterSeconds('a', 1_000), 60);
    assert.equal(window.retryAfterSeconds('a', 31_000), 30);
    assert.equal(window.retryAfterSeconds('b', 31_000), 0, 'other keys are unaffected');
    assert.equal(window.retryAfterSeconds('a', 61_000), 0, 'the window has ended');
  });

  test('stays bounded: at the key cap the oldest window is dropped', () => {
    const window = createFailureWindow({ windowMs: 60_000, max: 1, maxKeys: 2 });
    window.record('a', 0);
    window.record('b', 0);
    window.record('c', 0);
    assert.equal(window.retryAfterSeconds('a', 0), 0);
    assert.ok(window.retryAfterSeconds('b', 0) > 0);
    assert.ok(window.retryAfterSeconds('c', 0) > 0);
  });
});

describe('createVerificationGate', () => {
  const deferred = () => {
    let resolve!: () => void;
    const promise = new Promise<void>((r) => (resolve = r));
    return { promise, resolve };
  };

  test('runs at most maxConcurrent tasks and starts the next as one finishes', async () => {
    const gate = createVerificationGate({ maxConcurrent: 2, maxQueued: 10, maxWaitMs: 5_000 });
    const blockers = [deferred(), deferred(), deferred()];
    const started: number[] = [];
    const runs = blockers.map((b, i) => gate.run(false, async () => { started.push(i); await b.promise; return i; }));
    await new Promise((r) => setImmediate(r));
    assert.deepEqual(started, [0, 1]);
    assert.deepEqual(gate.stats(), { active: 2, queued: 1 });
    blockers[0].resolve();
    assert.equal(await runs[0], 0);
    await new Promise((r) => setImmediate(r));
    assert.deepEqual(started, [0, 1, 2]);
    blockers[1].resolve();
    blockers[2].resolve();
    assert.deepEqual(await Promise.all(runs), [0, 1, 2]);
    assert.deepEqual(gate.stats(), { active: 0, queued: 0 });
  });

  test('a priority caller goes ahead of ordinary waiters', async () => {
    const gate = createVerificationGate({ maxConcurrent: 1, maxQueued: 10, maxWaitMs: 5_000 });
    const first = deferred();
    const order: string[] = [];
    const running = gate.run(false, () => first.promise);
    const ordinary = gate.run(false, async () => { order.push('ordinary'); });
    const priority = gate.run(true, async () => { order.push('priority'); });
    first.resolve();
    await Promise.all([running, ordinary, priority]);
    assert.deepEqual(order, ['priority', 'ordinary']);
  });

  test('a full queue refuses ordinary callers, and sheds an ordinary waiter for a priority one', async () => {
    const gate = createVerificationGate({ maxConcurrent: 1, maxQueued: 1, maxWaitMs: 5_000 });
    const first = deferred();
    const running = gate.run(false, () => first.promise);
    const waiting = gate.run(false, async () => 'ordinary');
    await assert.rejects(gate.run(false, async () => 'refused'), VerificationBusyError);
    const priority = gate.run(true, async () => 'priority');
    await assert.rejects(waiting, VerificationBusyError);
    first.resolve();
    await running;
    assert.equal(await priority, 'priority');
  });

  test('a caller that waits longer than maxWaitMs is refused, and a failing task frees its slot', async () => {
    const gate = createVerificationGate({ maxConcurrent: 1, maxQueued: 5, maxWaitMs: 20 });
    const first = deferred();
    const running = gate.run(false, () => first.promise);
    await assert.rejects(gate.run(false, async () => 'late'), VerificationBusyError);
    first.resolve();
    await running;
    await assert.rejects(gate.run(false, async () => { throw new Error('boom'); }), /boom/);
    assert.equal(await gate.run(false, async () => 'free'), 'free');
  });
});

describe('/mcp behind the portal proxy with TRUST_PROXY off', () => {
  test('a flood of junk tokens from the shared loopback address never locks out a new valid token', () => {
    // A separate process, because config reads TRUST_PROXY once at startup and this file runs
    // with the test env's TRUST_PROXY=loopback.
    const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
    // The helpers load the test env, which sets TRUST_PROXY=loopback, so it is loaded first and
    // overridden before anything reads config.
    const script = `
      await import('./test/helpers/env.ts');
      process.env.TRUST_PROXY = 'false';
      const { config } = await import('./src/config.ts');
      if (config.trustProxy !== false) throw new Error('TRUST_PROXY override did not apply');
      const { installSalesforceMock } = await import('./test/helpers/salesforceMock.ts');
      const { startTestServer, mcpRequest } = await import('./test/helpers/server.ts');
      const sf = installSalesforceMock();
      const server = await startTestServer();
      const statuses = [];
      // Forged X-Forwarded-For values are ignored when the proxy is not trusted.
      for (let i = 0; i < 40; i++) {
        statuses.push((await mcpRequest(server.baseUrl, 'junk_shared_' + i, 'tools/list', {}, { 'X-Forwarded-For': '198.51.100.' + (i + 1) })).status);
      }
      sf.addUser('fresh_valid_token', {
        userId: '005000000000999AAA', organizationId: '00D000000000001AAA', username: 'fresh@acme.example',
        profileId: '00e000000000999AAA', profileName: 'Fresh',
      });
      const fresh = (await mcpRequest(server.baseUrl, 'fresh_valid_token', 'tools/list')).status;
      await server.close();
      sf.restore();
      console.log(JSON.stringify({ statuses, fresh }));
    `;
    const output = execFileSync(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', script], {
      cwd: repoRoot,
      env: { ...process.env, TRUST_PROXY: 'false' },
      stdio: 'pipe',
    }).toString();
    const result = JSON.parse(output.trim().split('\n').pop()!);

    assert.deepEqual([...new Set(result.statuses)], [401], 'every junk token is checked and refused, none answered 429');
    assert.equal(result.fresh, 200, 'a token never seen before still gets in');
  });
});

describe('/mcp end to end', () => {
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

  // The test env trusts X-Forwarded-For from loopback, so each test gets its own client.
  const freshClient = () => ({ 'X-Forwarded-For': `192.0.2.${++ipCounter}` });
  const rejectedRows = () =>
    store.getCopilotMcpLogs(5000).filter((row) => row.sfUsername === UNVERIFIED_CALLER_USERNAME).length;

  test('with a trusted proxy that names no client, a flood from the proxy address never locks out a new valid token', async () => {
    // No X-Forwarded-For: req.ip is the loopback socket address, shared by everyone behind it.
    const statuses = [];
    for (let i = 0; i < 40; i++) {
      statuses.push((await mcpRequest(server.baseUrl, `junk_unnamed_${i}`, 'tools/list')).status);
    }
    sf.addUser('unnamed_fresh_token', {
      userId: '005000000000998AAA', organizationId: '00D000000000001AAA', username: 'unnamed@acme.example',
      profileId: '00e000000000998AAA', profileName: 'Unnamed',
    });

    assert.deepEqual([...new Set(statuses)], [401], 'every junk token is checked and refused, none answered 429');
    assert.equal((await mcpRequest(server.baseUrl, 'unnamed_fresh_token', 'tools/list')).status, 200);
  });

  test('repeating a junk token reaches Salesforce once, and every attempt is still refused and logged', async () => {
    const client = freshClient();
    const token = `junk_${crypto.randomBytes(8).toString('hex')}`;
    const rowsBefore = rejectedRows();
    for (let i = 0; i < 3; i++) {
      assert.equal((await mcpRequest(server.baseUrl, token, 'tools/list', {}, client)).status, 401);
    }
    assert.equal(sf.calls.length, 1);
    assert.equal(rejectedRows() - rowsBefore, 3);
  });

  test('a junk token rejected at one host is still checked at another', async () => {
    const client = freshClient();
    const token = `junk_${crypto.randomBytes(8).toString('hex')}`;
    await mcpRequest(server.baseUrl, token, 'tools/list', {}, client);
    await mcpRequest(server.baseUrl, token, 'tools/list', {}, { ...client, 'X-Salesforce-Instance-Url': 'https://other.my.salesforce.com' });
    assert.deepEqual(sf.calls.map((call) => call.url.hostname), ['login.salesforce.com', 'other.my.salesforce.com']);
  });

  test('a malformed token is refused and logged without reaching Salesforce', async () => {
    const rowsBefore = rejectedRows();
    const res = await mcpRequest(server.baseUrl, 'abcédef', 'tools/list', {}, freshClient());
    assert.equal(res.status, 401);
    assert.equal(sf.calls.length, 0);
    assert.equal(rejectedRows() - rowsBefore, 1);
  });

  test('"Bearer" followed only by a non-breaking space is refused and logged like any bad token, without reaching Salesforce', async () => {
    const rowsBefore = rejectedRows();
    const { port } = new URL(server.baseUrl);
    const status = await new Promise<number>((resolve, reject) => {
      const req = http.request(
        {
          host: '127.0.0.1',
          port,
          path: '/mcp',
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Accept: 'application/json, text/event-stream',
            'X-Forwarded-For': `192.0.2.${++ipCounter}`,
          },
        },
        (res) => {
          res.resume();
          res.on('end', () => resolve(res.statusCode || 0));
        }
      );
      // Raw bytes, because fetch would refuse to send them: "Bearer " then U+00A0 as latin1.
      req.setHeader('Authorization', Buffer.from('Bearer  ', 'latin1').toString('latin1'));
      req.on('error', reject);
      req.end(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }));
    });
    assert.equal(status, 401);
    assert.equal(sf.calls.length, 0);
    // The limiters and the handler read the same token, so this row is also counted per IP.
    assert.equal(rejectedRows() - rowsBefore, 1);
  });

  test('a token that verified and then fails loses its exemption and counts towards the limit', async () => {
    const client = freshClient();
    const token = `valid_${crypto.randomBytes(8).toString('hex')}`;
    sf.addUser(token, {
      userId: '005000000000888AAA',
      organizationId: '00D000000000001AAA',
      username: 'revoked@acme.example',
      profileId: '00e000000000888AAA',
      profileName: 'Revoked Test',
    });
    assert.equal((await mcpRequest(server.baseUrl, token, 'tools/list', {}, client)).status, 200);

    // The Org ID lock now refuses this token's org, so every further call with it fails.
    store.updateSalesforceSettings({ enforceOrgIdLock: true, expectedOrgId: '00D000000000002AAA' });
    try {
      // The first failure arrives while the token is still exempt, so it is not counted; the
      // exemption ends with it, and the next 30 failures are.
      const statuses: number[] = [];
      for (let i = 0; i < 32; i++) {
        statuses.push((await mcpRequest(server.baseUrl, token, 'tools/list', {}, client)).status);
      }
      assert.deepEqual(statuses.slice(0, 31), Array(31).fill(401));
      assert.equal(statuses[31], 429, 'without the exemption the failures are counted');
    } finally {
      store.updateSalesforceSettings({ enforceOrgIdLock: false, expectedOrgId: '' });
    }
  });

  /** Makes every Salesforce request fail with `failure` until the returned restore is called. */
  function failSalesforce(failure: () => Promise<Response>): () => void {
    const mockedFetch = globalThis.fetch;
    globalThis.fetch = (async (input: any, init?: any) => {
      const url = new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url);
      if (/salesforce\.com$/.test(url.hostname)) return failure();
      return mockedFetch(input, init);
    }) as typeof fetch;
    return () => {
      globalThis.fetch = mockedFetch;
    };
  }

  test('when Salesforce cannot answer, the caller gets 503 with Retry-After, and the token is not remembered as rejected', async () => {
    const failures: Array<[string, () => Promise<Response>]> = [
      ['HTTP 503', async () => new Response('down', { status: 503 })],
      ['HTTP 429', async () => new Response('slow down', { status: 429 })],
      ['a timeout', async () => { throw new DOMException('The operation was aborted due to timeout', 'TimeoutError'); }],
      ['a network failure', async () => { throw new TypeError('fetch failed'); }],
    ];
    for (const [name, failure] of failures) {
      const client = freshClient();
      const token = `valid_${crypto.randomBytes(8).toString('hex')}`;
      sf.addUser(token, {
        userId: '005000000000887AAA', organizationId: '00D000000000001AAA', username: 'outage@acme.example',
        profileId: '00e000000000887AAA', profileName: 'Outage Test',
      });
      const rowsBefore = rejectedRows();
      const restore = failSalesforce(failure);
      let res;
      try {
        res = await mcpRequest(server.baseUrl, token, 'tools/list', {}, client);
      } finally {
        restore();
      }
      assert.equal(res.status, 503, name);
      assert.equal(res.headers.get('retry-after'), '5', name);
      assert.equal(res.headers.get('www-authenticate'), null, `${name}: the client is not told its token is invalid`);
      assert.equal(rejectedRows() - rowsBefore, 1, `${name}: the attempt is still logged`);
      assert.equal((await mcpRequest(server.baseUrl, token, 'tools/list', {}, client)).status, 200, `${name}: once Salesforce answers, the token gets in`);
    }
  });

  test('a Salesforce outage keeps a verified token exempt, while unverified tokens still count towards the limit', async () => {
    const client = freshClient();
    const token = `valid_${crypto.randomBytes(8).toString('hex')}`;
    sf.addUser(token, {
      userId: '005000000000886AAA', organizationId: '00D000000000001AAA', username: 'exempt@acme.example',
      profileId: '00e000000000886AAA', profileName: 'Exempt Test',
    });
    assert.equal((await mcpRequest(server.baseUrl, token, 'tools/list', {}, client)).status, 200);

    // Past the 2-minute identity cache, so the next call asks Salesforce again.
    const realNow = Date.now;
    Date.now = () => realNow() + 3 * 60 * 1000;
    const restore = failSalesforce(async () => new Response('down', { status: 503 }));
    try {
      assert.equal((await mcpRequest(server.baseUrl, token, 'tools/list', {}, client)).status, 503);
      assert.equal(wasTokenRecentlyVerified(token), true, 'no verdict, so the exemption stays');

      const junk: number[] = [];
      for (let i = 0; i < 31; i++) {
        junk.push((await mcpRequest(server.baseUrl, `junk_outage_${i}`, 'tools/list', {}, client)).status);
      }
      assert.deepEqual(junk.slice(0, 30), Array(30).fill(503));
      assert.equal(junk[30], 429, 'tokens that never verified are counted');

      assert.equal((await mcpRequest(server.baseUrl, token, 'tools/list', {}, client)).status, 503, 'the exempt token still reaches Salesforce');
    } finally {
      restore();
      Date.now = realNow;
    }
    assert.equal((await mcpRequest(server.baseUrl, token, 'tools/list', {}, client)).status, 200);
  });

  test('when verification is at capacity a caller gets 503 with Retry-After, and no log row', async () => {
    // Slow every Salesforce answer so the 8 slots and 100 queue places fill.
    const mockedFetch = globalThis.fetch;
    const release: Array<() => void> = [];
    globalThis.fetch = (async (input: any, init?: any) => {
      const url = new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url);
      if (/salesforce\.com$/.test(url.hostname)) await new Promise<void>((r) => release.push(r));
      return mockedFetch(input, init);
    }) as typeof fetch;
    try {
      // Distinct addresses, so the per-IP rejected-token count is not what answers here.
      const pending = Array.from({ length: 108 }, (_, i) =>
        mcpRequest(server.baseUrl, `junk_gate_${i}`, 'tools/list', {}, { 'X-Forwarded-For': `198.19.0.${i + 1}` })
      );
      while (verificationGateStats().queued < 100) await new Promise((r) => setTimeout(r, 5));
      const rowsBefore = rejectedRows();

      const busy = await mcpRequest(server.baseUrl, 'junk_gate_over', 'tools/list', {}, { 'X-Forwarded-For': '198.19.1.1' });

      assert.equal(busy.status, 503);
      assert.equal(busy.headers.get('retry-after'), '5');
      assert.equal(rejectedRows() - rowsBefore, 0);

      const drain = setInterval(() => release.splice(0).forEach((r) => r()), 2);
      const statuses = (await Promise.all(pending)).map((res) => res.status);
      clearInterval(drain);
      assert.deepEqual([...new Set(statuses)], [401], 'every queued caller was checked in turn');
    } finally {
      globalThis.fetch = mockedFetch;
      release.splice(0).forEach((r) => r());
    }
  });
});
