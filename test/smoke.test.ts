import './helpers/env.js';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { installSalesforceMock } from './helpers/salesforceMock.js';
import { startTestServer, mcpRequest } from './helpers/server.js';

test('harness: in-process server answers /healthz and /mcp tools/list for a mocked Salesforce user', async (t) => {
  const sf = installSalesforceMock();
  const server = await startTestServer();
  t.after(async () => {
    await server.close();
    sf.restore();
  });

  const health = await fetch(`${server.baseUrl}/healthz`);
  assert.equal(health.status, 200);

  sf.addUser('tok_valid', {
    userId: '005000000000001AAA',
    organizationId: '00D000000000001AAA',
    username: 'rep@acme.com',
    profileId: '00e000000000001AAA',
    profileName: 'Sales Rep',
  });
  const res = await mcpRequest(server.baseUrl, 'tok_valid', 'tools/list');
  assert.equal(res.status, 200, JSON.stringify(res.body));
  assert.deepEqual(res.body.result.tools, []);
});
