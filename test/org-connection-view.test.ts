// Covers the decisions behind the Org Connection view: its status badge and the two-click key replacement.
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import {
  connectionStatusBadge,
  generateCertClick,
  generateCertLabel,
  REPLACE_KEY_WARNING,
  KEY_REPLACED_NOTICE,
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

describe('generating a certificate and key', () => {
  test('with no key stored, the first click generates', () => {
    assert.equal(generateCertClick(false, false), 'generate');
  });

  test('with a key stored, the first click only arms and the second generates', () => {
    assert.equal(generateCertClick(true, false), 'arm');
    assert.equal(generateCertClick(true, true), 'generate');
  });

  test('the label asks for the second click only while armed over a stored key', () => {
    assert.equal(generateCertLabel(true, false, 'Regenerate'), 'Regenerate');
    assert.equal(generateCertLabel(false, true, 'Generate'), 'Generate');
    assert.match(generateCertLabel(true, true, 'Regenerate'), /click again/i);
  });

  test('the admin is told the new certificate must reach the Connected App, before and after', () => {
    assert.match(REPLACE_KEY_WARNING, /upload the new certificate to the Connected App/i);
    assert.match(KEY_REPLACED_NOTICE, /upload the new certificate to the Connected App/i);
  });
});
