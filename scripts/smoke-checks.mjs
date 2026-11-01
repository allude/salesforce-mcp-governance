// Live checks for scripts/smoke-e2e.sh. Talks only HTTP to the running servers.
import assert from 'node:assert/strict';

const portal = process.env.SMOKE_PORTAL_URL || 'http://127.0.0.1:3000';
const backend = process.env.SMOKE_BACKEND_URL || 'http://127.0.0.1:3001';
const publicUrl = process.env.SMOKE_PUBLIC_URL || 'http://localhost:3000';

let passed = 0;
async function check(name, fn) {
  try {
    await fn();
    passed++;
    console.log(`  ✔ ${name}`);
  } catch (err) {
    console.error(`  ✖ ${name}\n    ${err?.stack || err}`);
    process.exitCode = 1;
    throw err;
  }
}

async function call(base, path, { method = 'GET', headers = {}, body, redirect = 'manual' } = {}) {
  const res = await fetch(`${base}${path}`, {
    method,
    redirect,
    headers: { ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}), ...headers },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let json;
  try {
    json = text ? JSON.parse(text) : undefined;
  } catch {
    json = undefined;
  }
  return { status: res.status, headers: res.headers, text, json };
}

const MCP_HEADERS = { Accept: 'application/json, text/event-stream' };
const rpc = (method, params = {}) => ({ jsonrpc: '2.0', id: Math.floor(Math.random() * 1e6), method, params });

try {
  await check('POST :3000/mcp without a token is proxied to Express and returns 401 + WWW-Authenticate discovery header', async () => {
    const res = await call(portal, '/mcp', { method: 'POST', headers: MCP_HEADERS, body: rpc('tools/list') });
    assert.equal(res.status, 401);
    const challenge = res.headers.get('www-authenticate') || '';
    assert.match(challenge, /^Bearer /);
    assert.ok(challenge.includes(`resource_metadata="${publicUrl}/.well-known/oauth-protected-resource"`), challenge);
    assert.equal(res.json?.error?.code, -32001);
  });

  await check('POST :3000/mcp with a forged token returns 401 invalid_token', async () => {
    const forged = 'sf_sim_' + Buffer.from(JSON.stringify({ profileId: '00e000000000001AAA' })).toString('base64url');
    const res = await call(portal, '/mcp', {
      method: 'POST',
      headers: { ...MCP_HEADERS, Authorization: `Bearer ${forged}` },
      body: rpc('tools/list'),
    });
    assert.equal(res.status, 401);
    assert.match(res.headers.get('www-authenticate') || '', /error="invalid_token"/);
  });

  await check('GET :3000/.well-known/oauth-protected-resource is proxied (RFC 9728 metadata)', async () => {
    const res = await call(portal, '/.well-known/oauth-protected-resource');
    assert.equal(res.status, 200);
    assert.equal(res.json.resource, `${publicUrl}/mcp`);
    assert.ok(Array.isArray(res.json.authorization_servers) && res.json.authorization_servers.length === 1);
  });

  await check('GET :3000/healthz is proxied to the backend', async () => {
    const res = await call(portal, '/healthz');
    assert.equal(res.status, 200);
    assert.equal(res.json.status, 'ok');
  });

  await check('GET :3000/docs/architecture.md (resource_documentation) is proxied', async () => {
    const res = await call(portal, '/docs/architecture.md');
    assert.equal(res.status, 200);
    assert.ok(res.text.length > 100);
  });

  await check('GET :3000/ serves the Next.js Admin Portal; the legacy public/index.html SPA is gone', async () => {
    const page = await call(portal, '/');
    assert.equal(page.status, 200);
    assert.match(page.headers.get('content-type') || '', /text\/html/);
    assert.match(page.text, /_next\//);
    assert.equal(page.headers.get('x-frame-options'), 'DENY');
    assert.match(page.headers.get('content-security-policy') || '', /frame-ancestors 'none'/);
    const legacy = await call(portal, '/index.html');
    assert.equal(legacy.status, 404);
  });

  await check('GET :3001/ (Express) only serves API routes and redirects browsers to the portal', async () => {
    const res = await call(backend, '/');
    assert.equal(res.status, 302);
    assert.equal(res.headers.get('location'), publicUrl);
    const unknown = await call(backend, '/index.html');
    assert.equal(unknown.status, 404);
  });

  await check('GET :3000/api/admin/overview without a session is rejected (401)', async () => {
    const res = await call(portal, '/api/admin/overview');
    assert.equal(res.status, 401);
  });

  let cookie = '';
  let csrf = '';
  await check('POST :3000/api/admin/login with wrong password is rejected (401)', async () => {
    const res = await call(portal, '/api/admin/login', { method: 'POST', body: { username: 'admin', password: 'wrong' } });
    assert.equal(res.status, 401);
  });

  await check('POST :3000/api/admin/login with the bootstrap admin succeeds through the proxy', async () => {
    const res = await call(portal, '/api/admin/login', { method: 'POST', body: { username: 'admin', password: 'admin123' } });
    assert.equal(res.status, 200, res.text);
    cookie = (res.headers.get('set-cookie') || '').split(';')[0];
    csrf = res.json.csrfToken;
    assert.match(cookie, /^sf_mcp_admin_session=/);
    assert.ok(csrf);
    const session = await call(portal, '/api/admin/session', { headers: { Cookie: cookie } });
    assert.equal(session.json.authenticated, true);
  });

  const auth = () => ({ Cookie: cookie, 'X-CSRF-Token': csrf });

  await check('Mutations through the proxy require X-CSRF-Token (403 without it)', async () => {
    const res = await call(portal, '/api/admin/profiles', {
      method: 'POST',
      headers: { Cookie: cookie },
      body: { id: '00e000000000001AAA', name: 'Smoke Profile' },
    });
    assert.equal(res.status, 403);
  });

  await check('Build an access matrix through the proxy (object, group, profile, mapping)', async () => {
    const obj = await call(portal, '/api/admin/objects', {
      method: 'POST',
      headers: auth(),
      body: {
        objectName: 'Account',
        label: 'Account',
        fields: [
          { fieldName: 'Id', fieldType: 'Id' },
          { fieldName: 'Name', fieldType: 'Text' },
          { fieldName: 'Industry', fieldType: 'Picklist' },
        ],
      },
    });
    assert.equal(obj.status, 200, obj.text);
    const group = await call(portal, '/api/admin/groups', {
      method: 'POST',
      headers: auth(),
      body: {
        name: 'Smoke Readers',
        allowedActions: ['list_enabled_objects', 'soql_query'],
        objectPermissions: [
          { objectName: 'Account', canRead: true, canCreate: false, canUpdate: false, canDelete: false, allowedFields: ['Id', 'Name'] },
        ],
      },
    });
    assert.equal(group.status, 200, group.text);
    const profile = await call(portal, '/api/admin/profiles', {
      method: 'POST',
      headers: auth(),
      body: { id: '00e000000000001AAA', name: 'Smoke Profile' },
    });
    assert.equal(profile.status, 200, profile.text);
    const mapping = await call(portal, '/api/admin/profile-groups/00e000000000001AAA', {
      method: 'PUT',
      headers: auth(),
      body: { groupIds: [group.json.group.id] },
    });
    assert.equal(mapping.status, 200, mapping.text);
  });

  let simulatorToken = '';
  await check('Policy simulator through the proxy returns an evaluation and a signed simulator token', async () => {
    const res = await call(portal, '/api/admin/test-mcp-access', {
      method: 'POST',
      headers: auth(),
      body: { profileId: '00e000000000001AAA', toolName: 'soql_query', targetObject: 'Account' },
    });
    assert.equal(res.status, 200, res.text);
    assert.equal(res.json.evaluation.permitted, true);
    simulatorToken = res.json.simulatorBearerToken;
    assert.match(simulatorToken, /^sf_sim_[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
  });

  await check('MCP through the proxy with the simulator token: tools/list is scoped to the Profile, tools/call is enforced', async () => {
    const headers = { ...MCP_HEADERS, Authorization: `Bearer ${simulatorToken}` };
    const list = await call(portal, '/mcp', { method: 'POST', headers, body: rpc('tools/list') });
    assert.equal(list.status, 200, list.text);
    assert.deepEqual(list.json.result.tools.map((t) => t.name).sort(), ['list_enabled_objects', 'soql_query']);

    const allowed = await call(portal, '/mcp', {
      method: 'POST',
      headers,
      body: rpc('tools/call', { name: 'soql_query', arguments: { objectName: 'Account', fields: ['Id', 'Name'] } }),
    });
    assert.equal(allowed.status, 200, allowed.text);
    assert.notEqual(allowed.json.result.isError, true, allowed.text);

    const denied = await call(portal, '/mcp', {
      method: 'POST',
      headers,
      body: rpc('tools/call', { name: 'soql_query', arguments: { objectName: 'Account', fields: ['Industry'] } }),
    });
    assert.equal(denied.json.result.isError, true);

    const notGranted = await call(portal, '/mcp', {
      method: 'POST',
      headers,
      body: rpc('tools/call', { name: 'delete_record', arguments: { objectName: 'Account', recordId: '001000000000001AAA' } }),
    });
    assert.equal(notGranted.json.result.isError, true);
    assert.match(notGranted.json.result.content[0].text, /ACCESS_DENIED/);
  });

  await check('Matrix and audit logs are readable through the proxy (ALLOWED and DENIED calls were logged)', async () => {
    const res = await call(portal, '/api/admin/overview', { headers: { Cookie: cookie } });
    assert.equal(res.status, 200);
    assert.equal(res.json.profiles.length, 1);
    assert.equal(res.json.groups.length, 1);
    assert.equal(res.json.profileGroupMappings[0].groupIds.length, 1);
    const statuses = res.json.copilotLogs.map((l) => `${l.toolName}:${l.status}`);
    assert.ok(statuses.includes('soql_query:ALLOWED'), statuses.join(', '));
    assert.ok(statuses.includes('delete_record:DENIED'), statuses.join(', '));
    assert.ok(res.json.portalLogs.some((l) => l.action === 'LOGIN_SUCCESS'));
  });

  console.log(`\n✔ live E2E smoke test passed (${passed} checks)`);
} catch {
  console.error(`\n✖ live E2E smoke test failed after ${passed} passing checks`);
  process.exitCode = 1;
}
