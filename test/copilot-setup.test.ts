import './helpers/env.js';
// Covers the Copilot connector page: the values it tells admins to paste into Copilot Studio, and the
// readiness checks that say whether Copilot can reach the server and whether its users will see tools.
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import {
  copilotConnectorValues,
  customConnectorPattern,
  DEFAULT_COPILOT_SCOPES,
  firstCallReadiness,
  isPrivateHost,
  objectReadiness,
  profileAccessReadiness,
  salesforceHostReadiness,
  serverUrlReadiness,
} from '../src/components/views/copilotSetup.js';
import { SIMULATED_ORG_INSTANCE_URL } from '../src/salesforce/simulatedOrg.js';

describe('copilotConnectorValues', () => {
  test('reads the server URL, Salesforce host and scopes from the published metadata', () => {
    const values = copilotConnectorValues(
      {
        resource: 'https://mcp.example.com/mcp',
        authorization_servers: ['https://acme.my.salesforce.com/'],
        scopes_supported: ['api', 'refresh_token', 'openid'],
      },
      { origin: 'http://localhost:3000', instanceUrl: 'https://other.my.salesforce.com' }
    );
    assert.deepEqual(values, {
      serverUrl: 'https://mcp.example.com/mcp',
      salesforceBase: 'https://acme.my.salesforce.com',
      authorizationUrl: 'https://acme.my.salesforce.com/services/oauth2/authorize',
      tokenUrl: 'https://acme.my.salesforce.com/services/oauth2/token',
      refreshUrl: 'https://acme.my.salesforce.com/services/oauth2/token',
      scopes: 'api refresh_token openid',
    });
  });

  test('without metadata, falls back to the portal origin and the MCP token host', () => {
    const values = copilotConnectorValues(null, {
      origin: 'https://portal.example.com/',
      instanceUrl: 'https://acme.my.salesforce.com',
    });
    assert.equal(values.serverUrl, 'https://portal.example.com/mcp');
    assert.equal(values.authorizationUrl, 'https://acme.my.salesforce.com/services/oauth2/authorize');
    assert.equal(values.scopes, DEFAULT_COPILOT_SCOPES);
  });

  test('ignores malformed metadata fields instead of printing them', () => {
    const values = copilotConnectorValues(
      { resource: 42, authorization_servers: [null, ''], scopes_supported: 'api' },
      { origin: 'https://portal.example.com', instanceUrl: '' }
    );
    assert.equal(values.serverUrl, 'https://portal.example.com/mcp');
    assert.equal(values.salesforceBase, 'https://login.salesforce.com');
    assert.equal(values.scopes, DEFAULT_COPILOT_SCOPES);
  });
});

describe('customConnectorPattern', () => {
  test('matches every path on the MCP host, as a tenant data policy pattern', () => {
    assert.equal(customConnectorPattern('https://mcp.example.com/mcp'), 'https://mcp.example.com/*');
  });

  test('an unparsable URL gives a placeholder, not a pattern that matches nothing', () => {
    assert.equal(customConnectorPattern('nope'), 'https://<your-mcp-host>/*');
  });
});

describe('serverUrlReadiness', () => {
  test('the development default is unreachable from Microsoft cloud', () => {
    const check = serverUrlReadiness('http://localhost:3000/mcp');
    assert.equal(check.tone, 'err');
    assert.match(check.detail, /cannot reach localhost/);
  });

  test('a public host over plain HTTP is refused', () => {
    const check = serverUrlReadiness('http://mcp.example.com/mcp');
    assert.equal(check.tone, 'err');
    assert.match(check.detail, /HTTPS/);
  });

  test('a public HTTPS URL, such as a tunnel, is ready', () => {
    assert.equal(serverUrlReadiness('https://abc-123.trycloudflare.com/mcp').tone, 'ok');
  });

  test('an unparsable URL says so', () => {
    assert.equal(serverUrlReadiness('not a url').tone, 'err');
  });
});

describe('isPrivateHost', () => {
  test('loopback, private ranges, link-local and single-label names are private', () => {
    for (const host of [
      'localhost',
      'portal.localhost',
      '127.0.0.1',
      '10.1.2.3',
      '172.20.0.5',
      '192.168.1.10',
      '169.254.1.1',
      '100.100.1.1',
      '[::1]',
      'fd12:3456::1',
      'mcp-backend',
      'mcp.corp.internal',
      'printer.local',
    ]) {
      assert.equal(isPrivateHost(host), true, host);
    }
  });

  test('public names and addresses are not', () => {
    for (const host of ['mcp.example.com', '172.32.0.1', '8.8.8.8', 'fcbarcelona.com', '2606:4700::1111']) {
      assert.equal(isPrivateHost(host), false, host);
    }
  });
});

describe('salesforceHostReadiness', () => {
  test('a My Domain host is ready', () => {
    assert.equal(salesforceHostReadiness('https://acme.my.salesforce.com').tone, 'ok');
  });

  test('the generic login hosts work but point the admin at My Domain', () => {
    for (const host of ['https://login.salesforce.com', 'https://test.salesforce.com']) {
      const check = salesforceHostReadiness(host);
      assert.equal(check.tone, 'warn', host);
      assert.equal(check.fix?.view, 'settings-salesforce');
    }
  });

  test('the simulated org is never offered as a sign-in host', () => {
    const check = salesforceHostReadiness(SIMULATED_ORG_INSTANCE_URL);
    assert.equal(check.tone, 'err');
    assert.match(check.detail, /simulated org/);
  });
});

describe('profileAccessReadiness', () => {
  const groups = [
    { id: 'g-tools', allowedActions: ['soql_query'] },
    { id: 'g-empty', allowedActions: [] },
  ];

  test('a Profile mapped only to a group without tools does not count', () => {
    const check = profileAccessReadiness(groups, [{ profileId: 'p1', groupIds: ['g-empty'] }]);
    assert.equal(check.tone, 'err');
    assert.equal(check.fix?.view, 'matrix-profile-groups');
  });

  test('counts the Profiles that reach a group with tools', () => {
    const check = profileAccessReadiness(groups, [
      { profileId: 'p1', groupIds: ['g-empty', 'g-tools'] },
      { profileId: 'p2', groupIds: ['g-tools'] },
      { profileId: 'p3', groupIds: [] },
    ]);
    assert.equal(check.tone, 'ok');
    assert.match(check.detail, /^2 Profiles reach/);
  });
});

describe('objectReadiness', () => {
  test('warns while no object is enabled', () => {
    assert.equal(objectReadiness([{ enabled: false }]).tone, 'warn');
    assert.match(objectReadiness([{ enabled: true }, { enabled: false }]).detail, /^1 object is/);
  });
});

describe('firstCallReadiness', () => {
  test('waits for the first call, then reports its age on the server clock', () => {
    assert.equal(firstCallReadiness(null, Date.now()).tone, 'off');
    const now = Date.parse('2026-11-03T12:00:00Z');
    const check = firstCallReadiness('2026-11-03T11:55:00Z', now);
    assert.equal(check.tone, 'ok');
    assert.equal(check.detail, 'Last MCP call 5 min ago.');
  });
});
