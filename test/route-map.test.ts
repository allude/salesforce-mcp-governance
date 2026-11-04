import './helpers/env.js';
// The portal's one route map (src/components/shell/routes.ts): one URL per view, searchParams that
// carry only identifiers and enums, canonical hrefs, and a `next` that cannot leave the portal.
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import {
  breadcrumb,
  buildHref,
  drawerParam,
  matchRoute,
  parseDrawer,
  parseViewParams,
  ROUTE_LIST,
  ROUTES,
  safePortalHref,
  VIEWS,
  viewHref,
} from '../src/components/shell/routes.js';

const PROFILE = '00e5g000001AbCdEAA';
const EVENT = 'mcp_lx2k3_0123456789abcdef';

describe('route map', () => {
  test('seven views, each with a home route, and every route matches its own path', () => {
    assert.equal(VIEWS.length, 7);
    for (const v of VIEWS) assert.equal(ROUTES[v.home].view, v.id);
    for (const r of ROUTE_LIST) {
      const sample = r.path.replace('[groupId]', 'grp_sales');
      assert.equal(matchRoute(sample)?.route.id, r.id, sample);
      assert.equal(matchRoute(`${sample}/`)?.route.id, r.id, 'trailing slash');
    }
    assert.deepEqual(VIEWS.map((v) => viewHref(v.id)), [
      '/dashboard',
      '/org/connection',
      '/access-groups/groups',
      '/simulator',
      '/logs/mcp',
      '/logs/admin',
      '/settings/security',
    ]);
  });

  test('unknown paths and path params of the wrong shape do not match', () => {
    for (const p of ['/', '/mcp', '/api/admin/overview', '/logs', '/access-groups/groups/a%2Fb', '/access-groups/groups/%E0%A4%A']) {
      assert.equal(matchRoute(p), null, p);
    }
    assert.deepEqual(matchRoute('/access-groups/groups/grp_sales')?.pathParams, { groupId: 'grp_sales' });
  });

  test('parse drops unknown keys, invalid values, repeats and defaults, and reports it was not canonical', () => {
    const r = ROUTES['logs-mcp'];
    const parsed = parseViewParams(r, new URLSearchParams('status=DENIED&q=secret&tool=nope&object=Account&object=Lead'));
    assert.deepEqual(parsed.values, { status: 'DENIED' });
    assert.equal(parsed.search, '?status=DENIED');
    assert.equal(parsed.changed, true);
    const canonical = parseViewParams(r, new URLSearchParams('status=DENIED&object=Account'));
    assert.equal(canonical.changed, false);
    const dash = parseViewParams(ROUTES.dashboard, new URLSearchParams('range=24h'));
    assert.deepEqual(dash.values, { range: '24h' });
    assert.equal(dash.search, '', 'the default is left out');
    assert.equal(dash.changed, true);
  });

  test('values that are not identifiers never reach a URL (SOQL, record values, free text)', () => {
    const href = buildHref('logs-mcp', {
      object: "Account WHERE Name = 'x'",
      user: 'not a username',
      status: 'ALLOWED',
    });
    assert.equal(href, '/logs/mcp?status=ALLOWED');
    assert.equal(buildHref('simulator', { profile: PROFILE, user: 'ana@acme.com', object: 'Account' }),
      `/simulator?profile=${PROFILE}&user=ana%40acme.com&object=Account`);
    assert.throws(() => buildHref('access-group', {}, { groupId: '../x' }));
  });

  test('keys come out in a fixed order, so one view has one URL', () => {
    assert.equal(
      buildHref('logs-mcp', { user: 'ana@acme.com', status: 'ERROR', drawer: `mcp:${EVENT}` }),
      `/logs/mcp?status=ERROR&user=ana%40acme.com&drawer=mcp%3A${EVENT}`
    );
  });

  test('drawer values round-trip and anything else is refused', () => {
    for (const ref of [
      { type: 'profile', id: PROFILE },
      { type: 'object', id: 'Account' },
      { type: 'group', id: 'new' },
      { type: 'group', id: 'grp_sales' },
      { type: 'mcp', id: EVENT },
      { type: 'audit', id: 'adm_lx2k3_0123456789abcdef' },
      { type: 'import' },
    ] as const) {
      const value = drawerParam(ref);
      assert.ok(value);
      assert.deepEqual(parseDrawer(value), ref);
    }
    for (const bad of ['profile:x', 'object:Account Name', 'mcp:123', 'javascript:alert(1)', 'simulator', '']) {
      assert.equal(parseDrawer(bad), null, bad);
    }
  });

  test('safePortalHref only answers portal pages, rebuilt from the map', () => {
    assert.equal(safePortalHref('/logs/mcp?status=DENIED&q=x'), '/logs/mcp?status=DENIED');
    assert.equal(safePortalHref('/access-groups/groups/grp_sales'), '/access-groups/groups/grp_sales');
    for (const bad of [
      'https://evil.example/dashboard',
      '//evil.example/dashboard',
      '/\\evil.example',
      '/mcp',
      '/api/admin/logout',
      '/auth/okta/login',
      'dashboard',
      '/nowhere',
      null,
      '',
    ]) {
      assert.equal(safePortalHref(bad as string | null), null, String(bad));
    }
  });

  test('breadcrumbs: section, view, tab when the view has tabs, then the entity', () => {
    assert.deepEqual(breadcrumb(matchRoute('/dashboard')!), ['Dashboard']);
    assert.deepEqual(breadcrumb(matchRoute('/org/objects')!, 'Account'), ['Configure', 'Org & Metadata Sync', 'Objects', 'Account']);
    assert.deepEqual(breadcrumb(matchRoute('/logs/mcp')!), ['Logs', 'MCP Traffic Logs']);
  });
});
