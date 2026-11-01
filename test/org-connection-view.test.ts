import './helpers/env.js';
// Covers the decisions behind the Org Connection view: its status badge, the key replacement confirmation
// and the MCP token host warning.
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {
  connectionStatusBadge,
  dialogClickCounts,
  generateCertClick,
  generateCertRequestBody,
  privateKeyBadge,
  replaceKeyDialog,
  showSimulatedConnectionOption,
  storedKeyExists,
  REPLACE_KEY_WARNING,
  UNDECRYPTABLE_KEY_WARNING,
  KEY_REPLACED_NOTICE,
  mcpTokenHostWarning,
} from '../src/components/views/orgConnectionState.js';

describe('connectionStatusBadge', () => {
  test('a changed connection reads as not verified, in neither the connected nor the error colour', () => {
    assert.deepEqual(connectionStatusBadge('not_verified', ''), { label: 'Not Verified', variant: 'amber' });
  });

  test('the other statuses keep their meaning', () => {
    assert.deepEqual(connectionStatusBadge('connected', '00D1'), { label: 'Connected (00D1)', variant: 'emerald' });
    assert.deepEqual(connectionStatusBadge('error', ''), { label: 'Connection Error', variant: 'rose' });
    assert.deepEqual(connectionStatusBadge('disconnected', ''), { label: 'Not Connected', variant: 'slate' });
  });
});

describe('showSimulatedConnectionOption', () => {
  test('is offered wherever dev tools are enabled', () => {
    assert.equal(showSimulatedConnectionOption(true, 'jwt_bearer'), true);
    assert.equal(showSimulatedConnectionOption(true, 'simulated'), true);
  });

  test('is hidden in production unless simulated is the stored mode, which stays visible', () => {
    assert.equal(showSimulatedConnectionOption(false, 'jwt_bearer'), false);
    assert.equal(showSimulatedConnectionOption(false, 'simulated'), true);
  });

  test('choosing it writes no placeholder credentials into the form, where they would satisfy Live mode', () => {
    const view = fs.readFileSync(new URL('../src/components/views/SalesforceOrgConnectionView.tsx', import.meta.url), 'utf8');
    assert.ok(!view.includes('3MVG9_EXTERNAL_CONNECTED_APP_JWT'));
    assert.ok(!view.includes('mcp-metadata-sync@enterprise.my.salesforce.com'));
  });
});

describe('generating a certificate and key', () => {
  const noKey = { hasPrivateKey: false, privateKeyUndecryptable: false };
  const usableKey = { hasPrivateKey: true, privateKeyUndecryptable: false };
  const undecryptableKey = { hasPrivateKey: false, privateKeyUndecryptable: true };

  test('with no key stored, a click generates', () => {
    assert.equal(generateCertClick(noKey), 'generate');
  });

  test('with a key stored, a click only opens the confirmation', () => {
    assert.equal(generateCertClick(usableKey), 'replace');
  });

  test('an undecryptable key counts as a key that exists, with its own confirmation', () => {
    assert.equal(storedKeyExists(undecryptableKey), true);
    assert.equal(storedKeyExists(noKey), false);
    assert.equal(generateCertClick(undecryptableKey), 'destroy-undecryptable');
  });

  test('an undecryptable key does not read as no key', () => {
    assert.equal(privateKeyBadge(noKey).label, 'No Key Configured');
    assert.equal(privateKeyBadge(usableKey).variant, 'emerald');
    assert.notEqual(privateKeyBadge(undecryptableKey).label, 'No Key Configured');
    assert.equal(privateKeyBadge(undecryptableKey).variant, 'rose');
  });

  test('the undecryptable warning says restoring could recover the key and generating destroys it', () => {
    assert.match(UNDECRYPTABLE_KEY_WARNING, /Restoring the previous APP_SECRET_KEY could recover the key/);
    assert.match(UNDECRYPTABLE_KEY_WARNING, /Generating a new key destroys it/);
  });

  test('each confirmation says what it destroys and that the certificate must be uploaded', () => {
    const replace = replaceKeyDialog('replace');
    assert.deepEqual(replace.warnings, [REPLACE_KEY_WARNING]);

    const destroy = replaceKeyDialog('destroy-undecryptable');
    assert.deepEqual(destroy.warnings, [UNDECRYPTABLE_KEY_WARNING, REPLACE_KEY_WARNING]);
    assert.notEqual(destroy.confirmLabel, replace.confirmLabel);
  });

  test('the request confirms destroying a key only after that warning was shown', () => {
    assert.deepEqual(generateCertRequestBody('CN', null), { commonName: 'CN' });
    assert.deepEqual(generateCertRequestBody('CN', 'replace'), { commonName: 'CN' });
    assert.deepEqual(generateCertRequestBody('CN', 'destroy-undecryptable'), {
      commonName: 'CN',
      confirmReplaceUndecryptableKey: true,
    });
  });

  test('the second click of a double-click cannot answer the confirmation', () => {
    const openedAt = 1_000_000;
    assert.equal(dialogClickCounts(openedAt, openedAt), false);
    assert.equal(dialogClickCounts(openedAt, openedAt + 300), false);
    assert.equal(dialogClickCounts(openedAt, openedAt + 499), false);
    assert.equal(dialogClickCounts(openedAt, openedAt + 500), true);
  });

  test('the admin is told the new certificate must reach the Connected App, before and after', () => {
    assert.match(REPLACE_KEY_WARNING, /upload the new certificate to the Connected App/i);
    assert.match(KEY_REPLACED_NOTICE, /upload the new certificate to the Connected App/i);
  });
});

describe('mcpTokenHostWarning', () => {
  const connected = { connectionStatus: 'connected', loginUrl: 'https://test.salesforce.com', instanceUrl: 'https://login.salesforce.com' } as const;

  test('warns when a connection logs in through a sandbox and MCP verifies at production login', () => {
    assert.match(mcpTokenHostWarning(connected) ?? '', /login\.salesforce\.com/);
    for (const loginUrl of ['https://acme--uat.sandbox.my.salesforce.com', 'https://acme--uat.sandbox.lightning.force.com', 'https://TEST.salesforce.com/']) {
      assert.ok(mcpTokenHostWarning({ ...connected, loginUrl }), loginUrl);
    }
  });

  test('stays quiet when not connected', () => {
    for (const connectionStatus of ['disconnected', 'not_verified', 'error'] as const) {
      assert.equal(mcpTokenHostWarning({ ...connected, connectionStatus }), null);
    }
  });

  test('stays quiet for a production login or a host already moved off production login', () => {
    assert.equal(mcpTokenHostWarning({ ...connected, loginUrl: 'https://login.salesforce.com' }), null);
    assert.equal(mcpTokenHostWarning({ ...connected, loginUrl: 'https://acme.my.salesforce.com' }), null);
    assert.equal(mcpTokenHostWarning({ ...connected, instanceUrl: 'https://acme--uat.sandbox.my.salesforce.com' }), null);
  });

  test('a value that is not a URL does not throw', () => {
    assert.equal(mcpTokenHostWarning({ ...connected, loginUrl: 'not a url' }), null);
    assert.equal(mcpTokenHostWarning({ ...connected, instanceUrl: 'not a url' }), null);
  });
});
