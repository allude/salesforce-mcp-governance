// Covers the Result shown in the portal audit drawer, derived from the logged action name.
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { portalAuditResult } from '../src/components/views/portalAudit.js';

describe('portalAuditResult', () => {
  for (const action of ['LOGIN_FAILED', 'OKTA_LOGIN_FAILED', 'CONNECT_SALESFORCE_ORG_FAILED']) {
    test(`${action} is shown as failed`, () => {
      assert.deepEqual(portalAuditResult(action), { label: 'FAILED', tone: 'err' });
    });
  }

  test('OKTA_LOGIN_DENIED is shown as denied', () => {
    assert.deepEqual(portalAuditResult('OKTA_LOGIN_DENIED'), { label: 'DENIED', tone: 'err' });
  });

  for (const action of ['LOGIN_SUCCESS', 'CONNECT_SALESFORCE_ORG', 'DELETE_FIELD', 'UPDATE_OKTA_SSO']) {
    test(`${action} is shown as a success`, () => {
      assert.deepEqual(portalAuditResult(action), { label: 'SUCCESS', tone: 'ok' });
    });
  }
});
