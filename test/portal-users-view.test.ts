import './helpers/env.js';
// The portal stores a role per administrator but no route reads it, so the Portal Administrators card
// must neither offer roles nor show a stored one as if it limited anything. Rendered to markup to
// exercise the real view.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { PortalAuthSettingsView } from '../src/components/views/DashboardAndLogsViews.js';
import { PORTAL_PASSWORD_MIN_LENGTH } from '../src/security/passwordPolicy.js';
import type { OktaConfig, PortalUser } from '../src/types/governance.js';

const okta: OktaConfig = {
  enabled: false,
  oktaDomain: '',
  issuer: '',
  clientId: '',
  hasClientSecret: false,
  redirectUri: '',
  adminGroup: '',
  updatedAt: '2026-01-01T00:00:00.000Z',
};

const user = (username: string, role: string): PortalUser => ({
  username,
  displayName: username,
  role,
  createdAt: '2026-01-01T00:00:00.000Z',
  lastLoginAt: null,
});

test('every administrator reads as a full admin, and the form offers no role', () => {
  const html = renderToStaticMarkup(
    createElement(PortalAuthSettingsView, {
      oktaSettings: okta,
      portalUsers: [user('admin', 'Super Admin'), user('auditor', 'Read-Only Auditor')],
      onSaveOkta: async () => okta,
      onCreatePortalUser: async () => {},
      onDeletePortalUser: async () => {},
    })
  );

  assert.equal(html.match(/>Full admin</g)?.length, 2, html);
  for (const role of ['Super Admin', 'Security Admin', 'RevOps Admin', 'Read-Only Auditor']) {
    assert.ok(!html.includes(role), `"${role}" should not appear`);
  }
  assert.ok(html.includes(`At least ${PORTAL_PASSWORD_MIN_LENGTH} characters.`));
});
