import './helpers/env.js';
// apiFetch carries the admin session cookie and CSRF token, so it may only reach /api/admin/*: never
// Copilot's /mcp (which authenticates its own bearer tokens), /auth/okta, or another origin.
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { AdminApiUrlError, assertAdminApiUrl } from '../src/components/shell/apiFetchGuard.js';

describe('assertAdminApiUrl', () => {
  test('admin API paths pass, with their query strings', () => {
    for (const url of ['/api/admin/overview', '/api/admin/groups/grp_1/history', '/api/admin/search?q=Acc%20ount', '/api/admin/mcp-logs?before=12']) {
      assert.doesNotThrow(() => assertAdminApiUrl(url), url);
    }
  });

  test('everything else is refused', () => {
    for (const url of [
      '/mcp',
      '/mcp?x=/api/admin/',
      '/auth/okta/login',
      '/.well-known/oauth-protected-resource',
      'https://evil.example/api/admin/overview',
      '//evil.example/api/admin/overview',
      '/api/admin/../../mcp',
      '/api/admin/%2e%2e/%2e%2e/mcp',
      '/api/admin/..%2fmcp',
      '/api/admin/x%5c..',
      '/api/admin\\..\\mcp',
      '/api/admin/x y',
      '/api/admin/x\n',
      '/api/administrator',
      'api/admin/overview',
      42,
    ]) {
      assert.throws(() => assertAdminApiUrl(url), AdminApiUrlError, String(url));
    }
  });

  test('the shell checks every apiFetch URL before sending credentials', () => {
    const shell = fs.readFileSync(new URL('../src/components/shell/PortalShell.tsx', import.meta.url), 'utf8');
    const body = shell.slice(shell.indexOf('const apiFetch = useCallback('));
    const guard = body.indexOf('assertAdminApiUrl(url)');
    assert.ok(guard > 0 && guard < body.indexOf('X-CSRF-Token'), 'checked before the CSRF header is set');
  });
});
