import './helpers/env.js';
import { test, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import net from 'node:net';
import { store } from '../src/db/store.js';
import { createSimulatorToken, validateSalesforceInstanceUrl } from '../src/salesforce/client.js';
import { AVAILABLE_MCP_ACTIONS } from '../src/types/governance.js';
import {
  installSalesforceMock,
  type FakeSalesforceUser,
  type SalesforceMock,
} from './helpers/salesforceMock.js';
import { mcpRequest, startTestServer, type TestServer } from './helpers/server.js';

// Covers the /mcp transport and Bearer-token handling:
// src/mcp/streamableHttp.ts, src/salesforce/client.ts and the CORS / discovery wiring in src/index.ts.

// ---------------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------------

const RESOURCE_METADATA_URL = 'http://localhost:3000/.well-known/oauth-protected-resource';
const SIM_PREFIX = 'sf_sim_';

// The app trusts its loopback proxy (TRUST_PROXY defaults to `loopback`), so a forwarded client
// address gives this file its own rate-limit buckets no matter how many /mcp or Admin API calls
// other test files in the same process already made from 127.0.0.1.
const CLIENT_IP = `198.51.100.${1 + crypto.randomInt(254)}`;

const PRINTABLE_ASCII = /^[\x20-\x7e]+$/;
// `Bearer k="v", k="v", ...` where every auth-param value is a quoted-string with no stray quote or
// backslash, i.e. reflected text could not have closed a value early or injected another param.
const WELL_FORMED_BEARER_CHALLENGE = /^Bearer [a-z_]+="[^"\\]*"(?:, [a-z_]+="[^"\\]*")*$/;

const uid = () => crypto.randomBytes(5).toString('hex');
const ALL_TOOL_IDS = AVAILABLE_MCP_ACTIONS.map((action) => action.id);

/** 18-char Salesforce-style ID; the fixed 'X' guarantees a letter in the case-sensitive first 15 chars. */
function sfId(keyPrefix: string): string {
  return `${keyPrefix}X${crypto.randomBytes(6).toString('hex').toUpperCase().slice(0, 11)}AAA`;
}

interface Harness {
  server: TestServer;
  sf: SalesforceMock;
}

/** Fake Salesforce at the fetch boundary + the in-process app on a random 127.0.0.1 port. */
async function startHarness(t: TestContext): Promise<Harness> {
  const sf = installSalesforceMock();
  t.after(() => sf.restore());
  const server = await startTestServer();
  t.after(() => server.close());
  return { server, sf };
}

function rpc(
  h: Harness,
  token: string | null,
  method: string,
  params: Record<string, unknown> = {},
  headers: Record<string, string> = {}
) {
  return mcpRequest(h.server.baseUrl, token, method, params, { 'X-Forwarded-For': CLIENT_IP, ...headers });
}

function toolNames(body: any): string[] {
  return ((body?.result?.tools ?? []) as Array<{ name: string }>).map((tool) => tool.name).sort();
}

function challengeOf(res: { headers: Headers }): string {
  return res.headers.get('www-authenticate') ?? '';
}

function headerList(headers: Headers, name: string): string[] {
  return (headers.get(name) ?? '')
    .split(',')
    .map((value) => value.trim().toLowerCase())
    .filter(Boolean);
}

function callsBearing(sf: SalesforceMock, token: string) {
  return sf.calls.filter((call) => call.authorization === `Bearer ${token}`);
}

function userinfoCallCount(sf: SalesforceMock, token: string): number {
  return callsBearing(sf, token).filter((call) => call.url.pathname === '/services/oauth2/userinfo').length;
}

interface SeededProfile {
  profileId: string;
  profileName: string;
}

/** Seeds Profile -> Group -> enabled Object granting `allowedActions`; removed again after the test. */
function seedProfile(t: TestContext, allowedActions: readonly string[]): SeededProfile {
  const suffix = uid();
  const profileId = sfId('00e');
  const profileName = `Transport Test Profile ${suffix}`;
  const objectName = `Transport_${suffix}__c`;
  store.upsertProfile(profileId, profileName);
  store.upsertObjectWithFields({ objectName, enabled: true });
  const group = store.upsertGroup({
    name: `Transport Test Group ${suffix}`,
    allowedActions: [...allowedActions],
    objectPermissions: [
      { objectName, canRead: true, canCreate: false, canUpdate: false, canDelete: false, allowedFields: ['Id', 'Name'] },
    ],
  });
  store.setProfileGroups(profileId, [group.id]);
  t.after(() => {
    store.deleteProfile(profileId);
    store.deleteGroup(group.id);
    store.deleteObject(objectName);
  });
  return { profileId, profileName };
}

/** Registers a fresh Bearer token that the mocked Salesforce userinfo accepts, and returns it. */
function addSalesforceUser(sf: SalesforceMock, user: Partial<FakeSalesforceUser> = {}): string {
  const token = `tok_transport_${uid()}${uid()}`;
  sf.addUser(token, {
    userId: sfId('005'),
    organizationId: sfId('00D'),
    username: `rep.${uid()}@acme.example`,
    profileId: sfId('00e'),
    profileName: `Unmapped Profile ${uid()}`,
    ...user,
  });
  return token;
}

/** Snapshots the Salesforce connection settings now and restores them after the test. */
function preserveSalesforceSettings(t: TestContext): void {
  const previous = store.getSalesforceSettings();
  t.after(() => {
    store.updateSalesforceSettings({
      instanceUrl: previous.instanceUrl,
      apiVersion: previous.apiVersion,
      expectedOrgId: previous.expectedOrgId,
      enforceOrgIdLock: previous.enforceOrgIdLock,
    });
  });
}

/** Runs `fn` with Date.now() shifted by `offsetMs`; client, server and token checks share this process. */
async function withClockOffset<T>(offsetMs: number, fn: () => Promise<T>): Promise<T> {
  const realNow = Date.now;
  Date.now = () => realNow() + offsetMs;
  try {
    return await fn();
  } finally {
    Date.now = realNow;
  }
}

function decodeSimulatorPayload(token: string): Record<string, unknown> {
  const [encoded] = token.slice(SIM_PREFIX.length).split('.');
  return JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
}

function encodeSimulatorPayload(payload: unknown): string {
  return Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
}

async function assertServerStillHealthy(baseUrl: string): Promise<void> {
  const res = await fetch(`${baseUrl}/healthz`);
  assert.equal(res.status, 200);
  assert.equal(((await res.json()) as { status?: string }).status, 'ok');
}

interface RawHttpResponse {
  /** 0 when the server dropped the connection without sending a response. */
  status: number;
  /** Header values exactly as the bytes that came over the wire. */
  headers: Map<string, Buffer>;
  body: string;
}

/** Writes `request` byte-for-byte; fetch() refuses to put raw non-ASCII or CR/LF bytes into a header. */
function rawHttpRequest(baseUrl: string, request: Buffer): Promise<RawHttpResponse> {
  const { hostname, port } = new URL(baseUrl);
  return new Promise((resolve, reject) => {
    const socket = net.connect(Number(port), hostname);
    const chunks: Buffer[] = [];
    let socketError: NodeJS.ErrnoException | undefined;
    socket.setTimeout(10_000, () => socket.destroy(new Error('raw HTTP request timed out')));
    socket.on('data', (chunk: Buffer) => chunks.push(chunk));
    socket.on('error', (err: NodeJS.ErrnoException) => {
      socketError = err;
    });
    socket.on('close', () => {
      const raw = Buffer.concat(chunks);
      const headEnd = raw.indexOf('\r\n\r\n');
      if (headEnd < 0) {
        if (raw.length === 0 && socketError?.code === 'ECONNRESET') {
          resolve({ status: 0, headers: new Map(), body: '' });
        } else {
          reject(socketError ?? new Error(`Incomplete HTTP response: ${JSON.stringify(raw.toString('latin1'))}`));
        }
        return;
      }
      const [statusLine, ...headerLines] = raw.subarray(0, headEnd).toString('latin1').split('\r\n');
      const headers = new Map<string, Buffer>();
      for (const line of headerLines) {
        const colon = line.indexOf(':');
        headers.set(line.slice(0, colon).trim().toLowerCase(), Buffer.from(line.slice(colon + 1).trim(), 'latin1'));
      }
      resolve({ status: Number(statusLine.split(' ')[1]), headers, body: raw.subarray(headEnd + 4).toString('utf8') });
    });
    socket.write(request);
  });
}

/** A complete `POST /mcp` tools/list request whose Authorization value is exactly `authorization`. */
function rawMcpRequest(baseUrl: string, authorization: Buffer): Buffer {
  const body = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} });
  const head =
    'POST /mcp HTTP/1.1\r\n' +
    `Host: ${new URL(baseUrl).host}\r\n` +
    'Content-Type: application/json\r\n' +
    'Accept: application/json, text/event-stream\r\n' +
    `X-Forwarded-For: ${CLIENT_IP}\r\n` +
    `Content-Length: ${Buffer.byteLength(body)}\r\n` +
    'Connection: close\r\n' +
    'Authorization: ';
  return Buffer.concat([Buffer.from(head, 'latin1'), authorization, Buffer.from(`\r\n\r\n${body}`, 'latin1')]);
}

/** A dedicated portal admin (random password), so this file never depends on the bootstrap admin's state. */
function createPortalAdmin(t: TestContext): { username: string; password: string } {
  const username = `transport.admin.${uid()}`;
  const password = crypto.randomBytes(18).toString('base64url');
  store.upsertPortalUser({ username, displayName: 'Transport Test Admin', password, role: 'Admin' });
  t.after(() => {
    try {
      store.deletePortalUser(username);
    } catch {
      // only refused when it is the last portal user; the throwaway DB is discarded anyway
    }
  });
  return { username, password };
}

/** Password login (like loginAsAdmin) but from this file's forwarded client IP; returns the session cookie. */
async function loginPortalAdmin(baseUrl: string, username: string, password: string): Promise<string> {
  const res = await fetch(`${baseUrl}/api/admin/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Forwarded-For': CLIENT_IP },
    body: JSON.stringify({ username, password }),
  });
  const text = await res.text();
  assert.equal(res.status, 200, `portal login failed: ${text}`);
  return (res.headers.get('set-cookie') || '').split(';')[0];
}

// ---------------------------------------------------------------------------------------------
// 1. Missing or non-Bearer Authorization
// ---------------------------------------------------------------------------------------------

test('/mcp without an Authorization header -> 401, JSON-RPC -32001 and a Bearer challenge with resource metadata', async (t) => {
  const h = await startHarness(t);
  preserveSalesforceSettings(t);
  store.updateSalesforceSettings({ instanceUrl: 'https://transport-challenge.my.salesforce.com' });

  const res = await rpc(h, null, 'tools/list');

  assert.equal(res.status, 401, JSON.stringify(res.body));
  assert.equal(res.body?.jsonrpc, '2.0');
  assert.equal(res.body?.error?.code, -32001);
  assert.equal(res.body?.id, null);
  const challenge = challengeOf(res);
  assert.ok(challenge.startsWith('Bearer realm="salesforce-mcp"'), challenge);
  assert.ok(challenge.includes(`resource_metadata="${RESOURCE_METADATA_URL}"`), challenge);
  assert.ok(
    challenge.includes('authorization_uri="https://transport-challenge.my.salesforce.com/services/oauth2/authorize"'),
    challenge
  );
  assert.match(challenge, WELL_FORMED_BEARER_CHALLENGE);
  assert.deepEqual(h.sf.calls, [], 'nothing is sent to Salesforce without a token');
});

test('/mcp with a non-Bearer scheme (Basic) -> the same 401 Bearer challenge as a missing header', async (t) => {
  const h = await startHarness(t);
  const basic = `Basic ${Buffer.from('copilot:not-a-bearer-token').toString('base64')}`;

  const res = await rpc(h, null, 'tools/list', {}, { Authorization: basic });
  const missing = await rpc(h, null, 'tools/list');

  assert.equal(res.status, 401, JSON.stringify(res.body));
  assert.equal(res.body?.error?.code, -32001);
  assert.ok(challengeOf(res).startsWith('Bearer realm="salesforce-mcp"'), challengeOf(res));
  assert.equal(challengeOf(res), challengeOf(missing));
  assert.deepEqual(h.sf.calls, [], 'Basic credentials are never forwarded to Salesforce');
});

// ---------------------------------------------------------------------------------------------
// 2. Invalid Salesforce token
// ---------------------------------------------------------------------------------------------

test('an invalid Salesforce token (userinfo 401) -> 401 invalid_token and a DENIED audit row for unverified_caller', async (t) => {
  const h = await startHarness(t);
  const token = `tok_revoked_${uid()}${uid()}`; // never registered with the mock, so userinfo answers 401
  const existingLogIds = new Set(store.getCopilotMcpLogs(1_000_000).map((row) => row.id));

  const res = await rpc(h, token, 'tools/list');

  assert.equal(res.status, 401, JSON.stringify(res.body));
  assert.equal(res.body?.error?.code, -32001);
  const challenge = challengeOf(res);
  assert.ok(challenge.startsWith('Bearer '), challenge);
  assert.ok(challenge.includes('error="invalid_token"'), challenge);
  assert.ok(challenge.includes(`resource_metadata="${RESOURCE_METADATA_URL}"`), challenge);
  assert.equal(userinfoCallCount(h.sf, token), 1, 'the token was checked against Salesforce userinfo');

  const newRows = store.getCopilotMcpLogs(1_000_000).filter((row) => !existingLogIds.has(row.id));
  const auditRows = newRows.filter((row) => row.sfUsername === 'unverified_caller');
  assert.equal(auditRows.length, 1, JSON.stringify(newRows));
  assert.equal(auditRows[0].status, 'DENIED');
  assert.equal(auditRows[0].toolName, 'mcp_authenticate');
  assert.ok(!JSON.stringify(auditRows[0]).includes(token), 'the raw token is never written to the audit log');
});

// ---------------------------------------------------------------------------------------------
// 3. Valid token: profile scoping and the identity cache
// ---------------------------------------------------------------------------------------------

test('a valid Salesforce token -> tools/list 200 listing exactly the tools its seeded profile grants', async (t) => {
  const h = await startHarness(t);
  const reader = seedProfile(t, ['list_enabled_objects', 'describe_object']);
  const writer = seedProfile(t, ['create_record']);
  const readerToken = addSalesforceUser(h.sf, { profileId: reader.profileId, profileName: reader.profileName });
  const writerToken = addSalesforceUser(h.sf, { profileId: writer.profileId, profileName: writer.profileName });

  const readerRes = await rpc(h, readerToken, 'tools/list');
  const writerRes = await rpc(h, writerToken, 'tools/list');

  assert.equal(readerRes.status, 200, JSON.stringify(readerRes.body));
  assert.deepEqual(toolNames(readerRes.body), ['describe_object', 'list_enabled_objects']);
  assert.equal(writerRes.status, 200, JSON.stringify(writerRes.body));
  assert.deepEqual(toolNames(writerRes.body), ['create_record']);
});

test('a verified identity is cached: repeat /mcp requests within 2 minutes do not call userinfo again', async (t) => {
  const h = await startHarness(t);
  const seeded = seedProfile(t, ['list_enabled_objects']);
  const token = addSalesforceUser(h.sf, { profileId: seeded.profileId, profileName: seeded.profileName });

  const first = await rpc(h, token, 'tools/list');
  assert.equal(first.status, 200, JSON.stringify(first.body));
  assert.equal(userinfoCallCount(h.sf, token), 1);

  const immediately = await rpc(h, token, 'tools/list');
  const nearTtl = await withClockOffset(110_000, () => rpc(h, token, 'tools/list'));

  for (const res of [immediately, nearTtl]) {
    assert.equal(res.status, 200, JSON.stringify(res.body));
    assert.deepEqual(toolNames(res.body), ['list_enabled_objects']);
  }
  assert.equal(userinfoCallCount(h.sf, token), 1, 'both follow-up requests were served from the identity cache');
});

test('the cached identity expires after 2 minutes and the token is re-verified with Salesforce', async (t) => {
  const h = await startHarness(t);
  const seeded = seedProfile(t, ['list_enabled_objects']);
  const token = addSalesforceUser(h.sf, { profileId: seeded.profileId, profileName: seeded.profileName });

  const first = await rpc(h, token, 'tools/list');
  assert.equal(first.status, 200, JSON.stringify(first.body));
  const afterTtl = await withClockOffset(121_000, () => rpc(h, token, 'tools/list'));

  assert.equal(afterTtl.status, 200, JSON.stringify(afterTtl.body));
  assert.equal(userinfoCallCount(h.sf, token), 2, 'an expired cache entry must not stand in for Salesforce');
});

// ---------------------------------------------------------------------------------------------
// 4. Simulator tokens
// ---------------------------------------------------------------------------------------------

test('createSimulatorToken mints sf_sim_<payload>.<sig>; /mcp accepts it, scoped to its profile, without calling Salesforce', async (t) => {
  const h = await startHarness(t);
  const seeded = seedProfile(t, ['list_enabled_objects', 'soql_query']);

  const token = createSimulatorToken({ profileId: seeded.profileId, profileName: seeded.profileName });

  assert.match(token, /^sf_sim_[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}$/); // base64url payload + HMAC-SHA256
  const payload = decodeSimulatorPayload(token);
  assert.equal(payload.profileId, seeded.profileId);
  assert.equal(payload.profileName, seeded.profileName);
  const ttlSeconds = Number(payload.exp) - Date.now() / 1000;
  assert.ok(ttlSeconds > 14 * 60 && ttlSeconds <= 15 * 60, `exp should be ~15 minutes out, got ${ttlSeconds}s`);

  const res = await rpc(h, token, 'tools/list');

  assert.equal(res.status, 200, JSON.stringify(res.body));
  assert.deepEqual(toolNames(res.body), ['list_enabled_objects', 'soql_query']);
  assert.deepEqual(h.sf.calls, [], 'simulator tokens never reach Salesforce');
  assert.deepEqual(h.sf.nonSalesforceCalls, []);
});

test('a hand-forged simulator token without a valid signature is rejected with 401', async (t) => {
  const h = await startHarness(t);
  const privileged = seedProfile(t, ALL_TOOL_IDS);
  const forgedPayload = encodeSimulatorPayload({
    userId: '005SIM000000001AAA',
    organizationId: '00DSIM000000001AAA',
    username: 'attacker@evil.example',
    email: 'attacker@evil.example',
    displayName: 'Forged',
    profileId: privileged.profileId,
    profileName: privileged.profileName,
    instanceUrl: 'https://company-demo.my.salesforce.com',
    exp: Math.floor(Date.now() / 1000) + 600,
  });
  const forgeries: Record<string, string> = {
    'unsigned base64url(JSON) payload': `${SIM_PREFIX}${forgedPayload}`,
    'empty signature': `${SIM_PREFIX}${forgedPayload}.`,
    'made-up signature': `${SIM_PREFIX}${forgedPayload}.${crypto.randomBytes(32).toString('base64url')}`,
    'keyless SHA-256 of the payload as signature': `${SIM_PREFIX}${forgedPayload}.${crypto
      .createHash('sha256')
      .update(forgedPayload)
      .digest('base64url')}`,
  };

  for (const [label, token] of Object.entries(forgeries)) {
    await t.test(label, async () => {
      const res = await rpc(h, token, 'tools/list');
      assert.equal(res.status, 401, JSON.stringify(res.body));
      assert.equal(res.body?.error?.code, -32001);
      assert.equal(res.body?.result, undefined);
      assert.ok(challengeOf(res).includes('error="invalid_token"'), challengeOf(res));
    });
  }
  assert.deepEqual(h.sf.calls, []);
});

test('a simulator token whose signed payload was modified, or re-paired with another signature, is rejected', async (t) => {
  const h = await startHarness(t);
  const basic = seedProfile(t, ['list_enabled_objects']);
  const privileged = seedProfile(t, ALL_TOOL_IDS);
  const genuine = createSimulatorToken({ profileId: basic.profileId, profileName: basic.profileName });
  const other = createSimulatorToken({ profileId: privileged.profileId, profileName: privileged.profileName });
  const [, genuineSignature] = genuine.slice(SIM_PREFIX.length).split('.');
  const [otherPayload] = other.slice(SIM_PREFIX.length).split('.');
  const payload = decodeSimulatorPayload(genuine);

  const tampered: Record<string, string> = {
    'profileId re-encoded to a privileged profile, original signature': `${SIM_PREFIX}${encodeSimulatorPayload({
      ...payload,
      profileId: privileged.profileId,
      profileName: privileged.profileName,
    })}.${genuineSignature}`,
    'exp pushed out a day, original signature': `${SIM_PREFIX}${encodeSimulatorPayload({
      ...payload,
      exp: Number(payload.exp) + 86_400,
    })}.${genuineSignature}`,
    "another genuine token's payload with this token's signature": `${SIM_PREFIX}${otherPayload}.${genuineSignature}`,
    'genuine token with an extra segment appended': `${genuine}.${genuineSignature}`,
  };

  for (const [label, token] of Object.entries(tampered)) {
    await t.test(label, async () => {
      const res = await rpc(h, token, 'tools/list');
      assert.equal(res.status, 401, JSON.stringify(res.body));
      assert.ok(challengeOf(res).includes('error="invalid_token"'), challengeOf(res));
    });
  }

  const control = await rpc(h, genuine, 'tools/list');
  assert.equal(control.status, 200, JSON.stringify(control.body));
  assert.deepEqual(toolNames(control.body), ['list_enabled_objects']);
  assert.deepEqual(h.sf.calls, []);
});

test('a simulator token is honoured until its 15-minute exp and rejected with 401 once exp is in the past', async (t) => {
  const h = await startHarness(t);
  const seeded = seedProfile(t, ['list_enabled_objects']);
  const token = createSimulatorToken({ profileId: seeded.profileId, profileName: seeded.profileName });

  const at14Minutes = await withClockOffset(14 * 60_000, () => rpc(h, token, 'tools/list'));
  const at16Minutes = await withClockOffset(16 * 60_000, () => rpc(h, token, 'tools/list'));

  assert.equal(at14Minutes.status, 200, JSON.stringify(at14Minutes.body));
  assert.equal(at16Minutes.status, 401, JSON.stringify(at16Minutes.body));
  assert.equal(at16Minutes.body?.error?.code, -32001);
  assert.ok(challengeOf(at16Minutes).includes('error="invalid_token"'), challengeOf(at16Minutes));
  assert.deepEqual(h.sf.calls, []);
});

// ---------------------------------------------------------------------------------------------
// 5. Crafted tokens: CR/LF, non-ASCII, header safety
// ---------------------------------------------------------------------------------------------

test("a crafted 'sf_sim_' + base64url('\\r\\n{é') token -> 401 (not 500) with a printable-ASCII challenge; server keeps serving", async (t) => {
  const h = await startHarness(t);
  const hostile = Buffer.from('\r\n{é', 'utf8').toString('base64url');
  const crafted: Record<string, string> = {
    'payload only': `${SIM_PREFIX}${hostile}`,
    'payload and signature segments': `${SIM_PREFIX}${hostile}.${hostile}`,
  };

  for (const [label, token] of Object.entries(crafted)) {
    await t.test(label, async () => {
      const res = await rpc(h, token, 'tools/list');
      assert.equal(res.status, 401, JSON.stringify(res.body));
      assert.equal(res.body?.error?.code, -32001);
      const challenge = challengeOf(res);
      assert.match(challenge, PRINTABLE_ASCII);
      assert.match(challenge, WELL_FORMED_BEARER_CHALLENGE);
    });
  }
  await assertServerStillHealthy(h.server.baseUrl);
});

test('raw non-ASCII bytes after sf_sim_ on the wire -> 401 whose WWW-Authenticate bytes are printable ASCII', async (t) => {
  const h = await startHarness(t);
  const bearerSim = Buffer.from(`Bearer ${SIM_PREFIX}`, 'latin1');
  const cases: Record<string, Buffer> = {
    'UTF-8 payload and signature': Buffer.concat([bearerSim, Buffer.from('é{ñ}.sïg', 'utf8')]),
    'Latin-1 bytes without a signature': Buffer.concat([bearerSim, Buffer.from([0xe9, 0x7b, 0xff])]),
    'tab plus UTF-8 inside the token': Buffer.concat([bearerSim, Buffer.from('\t{é', 'utf8')]),
  };

  for (const [label, authorization] of Object.entries(cases)) {
    await t.test(label, async () => {
      const res = await rawHttpRequest(h.server.baseUrl, rawMcpRequest(h.server.baseUrl, authorization));
      assert.equal(res.status, 401, res.body);
      const challenge = res.headers.get('www-authenticate');
      assert.ok(challenge, 'a WWW-Authenticate header is sent');
      assert.ok(
        [...challenge].every((byte) => byte >= 0x20 && byte <= 0x7e),
        `non-printable byte in ${JSON.stringify(challenge.toString('latin1'))}`
      );
      assert.match(challenge.toString('latin1'), WELL_FORMED_BEARER_CHALLENGE);
      assert.equal(JSON.parse(res.body)?.error?.code, -32001);
    });
  }
  await assertServerStillHealthy(h.server.baseUrl);
});

test('raw CR or LF bytes inside the Authorization header are refused at the HTTP layer (never 5xx); server keeps serving', async (t) => {
  const h = await startHarness(t);
  const cases: Record<string, Buffer> = {
    'bare CR': Buffer.from(`Bearer ${SIM_PREFIX}\r{\u00e9`, 'latin1'),
    'bare LF': Buffer.from(`Bearer ${SIM_PREFIX}\n{\u00e9`, 'latin1'),
    'CRLF followed by a junk header line': Buffer.from(`Bearer ${SIM_PREFIX}\r\n{\u00e9`, 'latin1'),
  };

  for (const [label, authorization] of Object.entries(cases)) {
    await t.test(label, async () => {
      const res = await rawHttpRequest(h.server.baseUrl, rawMcpRequest(h.server.baseUrl, authorization));
      assert.ok(res.status === 0 || (res.status >= 400 && res.status < 500), `status ${res.status}: ${res.body}`);
    });
  }
  await assertServerStillHealthy(h.server.baseUrl);
});

test('attacker-controlled text reflected into WWW-Authenticate stays inside one well-formed quoted-string', async (t) => {
  const h = await startHarness(t);
  const token = `tok_reflect_${uid()}`;
  // The URL parser keeps `"`, `,` and `=` in this host, and the host check echoes the host in its error.
  const hint = 'https://evil%22,error=%22none.example';

  const res = await rpc(h, token, 'tools/list', {}, { 'X-Salesforce-Instance-Url': hint });

  assert.equal(res.status, 401, JSON.stringify(res.body));
  const challenge = challengeOf(res);
  assert.match(challenge, PRINTABLE_ASCII);
  assert.match(challenge, WELL_FORMED_BEARER_CHALLENGE);
  assert.equal(challenge.match(/error="/g)?.length, 1, `only the server's own error param: ${challenge}`);
  assert.ok(challenge.includes('error="invalid_token"'), challenge);
  assert.deepEqual(h.sf.calls, []);
  assert.deepEqual(h.sf.nonSalesforceCalls, []);
});

// ---------------------------------------------------------------------------------------------
// 6. SSRF guard on X-Salesforce-Instance-Url and validateSalesforceInstanceUrl
// ---------------------------------------------------------------------------------------------

test('SSRF guard: an X-Salesforce-Instance-Url outside Salesforce is refused with 401 before any outbound call', async (t) => {
  const h = await startHarness(t);
  const hostileHints = [
    'http://127.0.0.1:9',
    'https://evil.example.com',
    'https://login.salesforce.com.evil.com',
    'https://user:pass@acme.my.salesforce.com',
  ];

  for (const hint of hostileHints) {
    await t.test(hint, async () => {
      // A token Salesforce would accept, so only the guard can stop the request.
      const token = addSalesforceUser(h.sf);
      const res = await rpc(h, token, 'tools/list', {}, { 'X-Salesforce-Instance-Url': hint });
      assert.equal(res.status, 401, JSON.stringify(res.body));
      assert.ok(challengeOf(res).includes('error="invalid_token"'), challengeOf(res));
      assert.deepEqual(callsBearing(h.sf, token), [], 'the token was not sent anywhere');
    });
  }
  assert.deepEqual(h.sf.nonSalesforceCalls, []);
});

test('SSRF guard: a Salesforce-domain X-Salesforce-Instance-Url is honoured for the userinfo call', async (t) => {
  const h = await startHarness(t);
  const seeded = seedProfile(t, ['list_enabled_objects']);
  const token = addSalesforceUser(h.sf, { profileId: seeded.profileId, profileName: seeded.profileName });

  const res = await rpc(h, token, 'tools/list', {}, {
    'X-Salesforce-Instance-Url': 'https://acme--dev.sandbox.my.salesforce.com',
  });

  assert.equal(res.status, 200, JSON.stringify(res.body));
  const userinfoOrigins = callsBearing(h.sf, token)
    .filter((call) => call.url.pathname === '/services/oauth2/userinfo')
    .map((call) => call.url.origin);
  assert.deepEqual(userinfoOrigins, ['https://acme--dev.sandbox.my.salesforce.com']);
  assert.deepEqual(h.sf.nonSalesforceCalls, []);
});

test('validateSalesforceInstanceUrl accepts production, sandbox and Lightning hosts and returns the bare origin', () => {
  const accepted: Array<[input: string, origin: string]> = [
    ['https://acme.my.salesforce.com', 'https://acme.my.salesforce.com'],
    ['https://login.salesforce.com', 'https://login.salesforce.com'],
    ['https://test.salesforce.com', 'https://test.salesforce.com'],
    ['https://acme--dev.sandbox.my.salesforce.com', 'https://acme--dev.sandbox.my.salesforce.com'],
    ['https://acme.lightning.force.com', 'https://acme.lightning.force.com'],
    ['https://ACME.My.Salesforce.com/services/data/v62.0/?q=1#frag', 'https://acme.my.salesforce.com'],
  ];
  for (const [input, origin] of accepted) {
    assert.equal(validateSalesforceInstanceUrl(input), origin, input);
  }
});

test('validateSalesforceInstanceUrl rejects foreign hosts, suffix tricks, credentials, non-HTTP schemes and garbage', () => {
  const rejected = [
    // foreign and internal hosts
    'https://evil.example.com',
    'http://127.0.0.1:9',
    'http://169.254.169.254/latest/meta-data',
    'http://localhost',
    // suffix and parser tricks
    'https://salesforce.com.evil.com',
    'https://login.salesforce.com.evil.com',
    'https://evilsalesforce.com',
    'https://evilforce.com',
    'https://acme.my.salesforce.com%2eevil.com',
    'https://evil.com\\.salesforce.com',
    'https://evil.com#.salesforce.com',
    'https://evil.com?.my.salesforce.com',
    'https://login.s\u0430lesforce.com', // Cyrillic 'а' homograph
    // embedded credentials
    'https://user:pass@acme.my.salesforce.com',
    'https://acme.my.salesforce.com@evil.com',
    // non-HTTP schemes
    'ftp://acme.my.salesforce.com',
    'file:///etc/passwd',
    'javascript:alert(1)//.salesforce.com',
    'wss://acme.my.salesforce.com',
    // garbage
    '',
    'not a url',
    'acme.my.salesforce.com',
    '//acme.my.salesforce.com',
    'https://',
  ];
  for (const input of rejected) {
    assert.throws(() => validateSalesforceInstanceUrl(input), Error, JSON.stringify(input));
  }
});

// ---------------------------------------------------------------------------------------------
// 7. Org ID lock
// ---------------------------------------------------------------------------------------------

test('Org ID lock: a token from the locked org is accepted when the lock holds the 15-char form of its 18-char ID', async (t) => {
  const h = await startHarness(t);
  preserveSalesforceSettings(t);
  const orgId = sfId('00D');
  store.updateSalesforceSettings({ enforceOrgIdLock: true, expectedOrgId: orgId.slice(0, 15) });
  const seeded = seedProfile(t, ['list_enabled_objects']);
  const token = addSalesforceUser(h.sf, {
    organizationId: orgId,
    profileId: seeded.profileId,
    profileName: seeded.profileName,
  });

  const res = await rpc(h, token, 'tools/list');

  assert.equal(res.status, 200, JSON.stringify(res.body));
  assert.deepEqual(toolNames(res.body), ['list_enabled_objects']);
});

test('Org ID lock: a token from any other org is rejected with 401', async (t) => {
  const h = await startHarness(t);
  preserveSalesforceSettings(t);
  const lockedOrg = sfId('00D');
  store.updateSalesforceSettings({ enforceOrgIdLock: true, expectedOrgId: lockedOrg.slice(0, 15) });
  const seeded = seedProfile(t, ['list_enabled_objects']);
  const otherOrgs: Record<string, string> = {
    'a different org': sfId('00D'),
    'the same 15 chars in another case (15-char IDs are case-sensitive)':
      lockedOrg.slice(0, 3) + lockedOrg.slice(3, 15).toLowerCase() + lockedOrg.slice(15),
  };

  for (const [label, organizationId] of Object.entries(otherOrgs)) {
    await t.test(label, async () => {
      const token = addSalesforceUser(h.sf, {
        organizationId,
        profileId: seeded.profileId,
        profileName: seeded.profileName,
      });
      const res = await rpc(h, token, 'tools/list');
      assert.equal(res.status, 401, JSON.stringify(res.body));
      assert.equal(res.body?.error?.code, -32001);
      assert.ok(challengeOf(res).includes('error="invalid_token"'), challengeOf(res));
    });
  }
});

test('Org ID lock also applies to an identity that was cached before the lock was enabled', async (t) => {
  const h = await startHarness(t);
  preserveSalesforceSettings(t);
  store.updateSalesforceSettings({ enforceOrgIdLock: false });
  const seeded = seedProfile(t, ['list_enabled_objects']);
  const lockedOrg = sfId('00D');
  const outsiderToken = addSalesforceUser(h.sf, {
    organizationId: sfId('00D'),
    profileId: seeded.profileId,
    profileName: seeded.profileName,
  });
  const insiderToken = addSalesforceUser(h.sf, {
    organizationId: lockedOrg,
    profileId: seeded.profileId,
    profileName: seeded.profileName,
  });

  const beforeLock = await rpc(h, outsiderToken, 'tools/list');
  assert.equal(beforeLock.status, 200, JSON.stringify(beforeLock.body));
  assert.equal(userinfoCallCount(h.sf, outsiderToken), 1, 'the outsider identity is now cached');

  store.updateSalesforceSettings({ enforceOrgIdLock: true, expectedOrgId: lockedOrg });
  const outsiderAfterLock = await rpc(h, outsiderToken, 'tools/list');
  const insiderAfterLock = await rpc(h, insiderToken, 'tools/list');

  assert.equal(outsiderAfterLock.status, 401, JSON.stringify(outsiderAfterLock.body));
  assert.ok(challengeOf(outsiderAfterLock).includes('error="invalid_token"'), challengeOf(outsiderAfterLock));
  assert.equal(insiderAfterLock.status, 200, JSON.stringify(insiderAfterLock.body));
});

// ---------------------------------------------------------------------------------------------
// 8. CORS
// ---------------------------------------------------------------------------------------------

test('CORS preflight on /mcp from any origin -> 204, Allow-Origin *, no credentials, WWW-Authenticate exposed', async (t) => {
  const h = await startHarness(t);

  const res = await fetch(`${h.server.baseUrl}/mcp`, {
    method: 'OPTIONS',
    headers: {
      Origin: 'https://copilotstudio.example',
      'Access-Control-Request-Method': 'POST',
      'Access-Control-Request-Headers': 'authorization, content-type, x-salesforce-instance-url',
      'X-Forwarded-For': CLIENT_IP,
    },
  });
  await res.arrayBuffer();

  assert.equal(res.status, 204);
  assert.equal(res.headers.get('access-control-allow-origin'), '*');
  assert.equal(res.headers.get('access-control-allow-credentials'), null);
  assert.ok(headerList(res.headers, 'access-control-expose-headers').includes('www-authenticate'));
  assert.ok(headerList(res.headers, 'access-control-allow-methods').includes('post'));
  assert.ok(headerList(res.headers, 'access-control-allow-headers').includes('authorization'));
});

test('a cross-origin 401 from /mcp is readable by a browser client: Allow-Origin *, WWW-Authenticate exposed, no credentials', async (t) => {
  const h = await startHarness(t);

  const res = await rpc(h, null, 'tools/list', {}, { Origin: 'https://copilotstudio.example' });

  assert.equal(res.status, 401);
  assert.equal(res.headers.get('access-control-allow-origin'), '*');
  assert.equal(res.headers.get('access-control-allow-credentials'), null);
  assert.ok(headerList(res.headers, 'access-control-expose-headers').includes('www-authenticate'));
});

test('the Admin API grants no CORS: GET /api/admin/session from http://evil.example has no Access-Control-Allow-Origin', async (t) => {
  const h = await startHarness(t);
  const admin = createPortalAdmin(t);
  const cookie = await loginPortalAdmin(h.server.baseUrl, admin.username, admin.password);

  for (const sessionCookie of [null, cookie]) {
    const res = await fetch(`${h.server.baseUrl}/api/admin/session`, {
      headers: {
        Origin: 'http://evil.example',
        'X-Forwarded-For': CLIENT_IP,
        ...(sessionCookie ? { Cookie: sessionCookie } : {}),
      },
    });
    const body = (await res.json()) as { authenticated?: boolean };
    const label = sessionCookie ? 'signed-in session' : 'anonymous';
    assert.equal(res.status, 200, label);
    assert.equal(body.authenticated, Boolean(sessionCookie), label);
    assert.equal(res.headers.get('access-control-allow-origin'), null, label);
    assert.equal(res.headers.get('access-control-allow-credentials'), null, label);
  }
});

test('the Admin API answers a foreign-origin preflight without granting CORS', async (t) => {
  const h = await startHarness(t);

  const res = await fetch(`${h.server.baseUrl}/api/admin/login`, {
    method: 'OPTIONS',
    headers: {
      Origin: 'http://evil.example',
      'Access-Control-Request-Method': 'POST',
      'Access-Control-Request-Headers': 'content-type, x-csrf-token',
      'X-Forwarded-For': CLIENT_IP,
    },
  });
  await res.arrayBuffer();

  assert.equal(res.headers.get('access-control-allow-origin'), null);
  assert.equal(res.headers.get('access-control-allow-credentials'), null);
  assert.equal(res.headers.get('access-control-allow-headers'), null);
});

// ---------------------------------------------------------------------------------------------
// 9. OAuth protected-resource discovery and JSON-RPC parse errors
// ---------------------------------------------------------------------------------------------

test('/.well-known/oauth-protected-resource -> resource /mcp, header bearer method, configured instance URL as authorization server', async (t) => {
  const h = await startHarness(t);
  preserveSalesforceSettings(t);
  const instanceUrl = `https://transport-${uid()}.my.salesforce.com`;
  store.updateSalesforceSettings({ instanceUrl });

  const res = await fetch(`${h.server.baseUrl}/.well-known/oauth-protected-resource`, {
    headers: { Origin: 'https://copilotstudio.example' },
  });
  const doc = (await res.json()) as Record<string, unknown>;

  assert.equal(res.status, 200);
  assert.equal(doc.resource, 'http://localhost:3000/mcp');
  assert.deepEqual(doc.bearer_methods_supported, ['header']);
  assert.deepEqual(doc.authorization_servers, [instanceUrl]);
  assert.equal(res.headers.get('access-control-allow-origin'), '*', 'discovery is readable cross-origin');
});

test('a malformed JSON body on /mcp -> 400 JSON-RPC parse error (-32700) as JSON, not an HTML error page', async (t) => {
  const h = await startHarness(t);
  const token = createSimulatorToken({ profileId: sfId('00e'), profileName: `Parse Error Profile ${uid()}` });

  const res = await fetch(`${h.server.baseUrl}/mcp`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
      Accept: 'application/json, text/event-stream',
      'X-Forwarded-For': CLIENT_IP,
    },
    body: '{"jsonrpc":"2.0","id":1,"method":"tools/list",',
  });
  const text = await res.text();

  assert.equal(res.status, 400, text);
  assert.match(res.headers.get('content-type') ?? '', /^application\/json/);
  assert.doesNotMatch(text, /<html|<!doctype|<pre>/i);
  assert.doesNotMatch(text, /SyntaxError|node_modules/, 'no parser internals or stack trace');
  const body = JSON.parse(text);
  assert.equal(body.jsonrpc, '2.0');
  assert.equal(body.error?.code, -32700);
  assert.equal(body.id, null);
});

test('the -32700 parse error from /mcp carries the same CORS headers as every other /mcp response', async (t) => {
  const h = await startHarness(t);
  const crossOrigin = {
    Origin: 'https://copilotstudio.example',
    'Content-Type': 'application/json',
    Accept: 'application/json, text/event-stream',
    'X-Forwarded-For': CLIENT_IP,
  };

  // Control: a well-formed but unauthenticated call is readable cross-origin...
  const unauthenticated = await fetch(`${h.server.baseUrl}/mcp`, {
    method: 'POST',
    headers: crossOrigin,
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }),
  });
  await unauthenticated.arrayBuffer();
  assert.equal(unauthenticated.headers.get('access-control-allow-origin'), '*');

  // ...so the JSON-RPC parse error built for MCP clients must be too, or a browser client only sees a CORS failure.
  const malformed = await fetch(`${h.server.baseUrl}/mcp`, {
    method: 'POST',
    headers: crossOrigin,
    body: '{"jsonrpc":"2.0","id":1,"method":"tools/list",',
  });
  const body = (await malformed.json()) as { error?: { code?: number } };

  assert.equal(malformed.status, 400);
  assert.equal(body.error?.code, -32700);
  assert.equal(malformed.headers.get('access-control-allow-origin'), '*', 'parse error is unreadable cross-origin');
  assert.equal(malformed.headers.get('access-control-allow-credentials'), null);
});
