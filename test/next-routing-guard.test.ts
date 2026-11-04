import './helpers/env.js';
// next.config.ts proxies the backend's paths through array rewrites, which Next runs after the
// filesystem (pages and public/ files): an app route or public file under a proxied prefix would
// answer instead of the backend. The portal's security headers skip those prefixes on whole path
// segments, so a portal page that merely starts like one (/mcp-traffic) still gets them.
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
// Next's own route code, so sources match with Next's path-to-regexp options and app folders map
// to URLs as Next maps them. Custom routes are loaded and built as the router server does
// (server/lib/router-utils/filesystem.js).
import { buildCustomRoute } from 'next/dist/server/lib/router-utils/filesystem.js';
import { normalizeAppPath } from 'next/dist/shared/lib/router/utils/app-paths.js';
import {
  extractInterceptionRouteInformation,
  isInterceptionRouteAppPath,
} from 'next/dist/shared/lib/router/utils/interception-routes.js';
import nextConfig from '../next.config.js';
import { ROUTE_LIST } from '../src/components/shell/routes.js';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
// Required, not imported: an ESM default import of this CommonJS module gets its whole exports object.
const { default: loadCustomRoutes } = createRequire(import.meta.url)(
  'next/dist/lib/load-custom-routes.js',
) as typeof import('next/dist/lib/load-custom-routes.js');

const routes = await loadCustomRoutes({ ...nextConfig });
const headerRoutes = routes.headers.map((route) => buildCustomRoute('header', route));

// The static part of a rewrite source, before its first parameter or pattern: /docs/:path* -> /docs.
function literalPrefix(source: string): string {
  const segments = source.split('/').slice(1);
  const end = segments.findIndex((segment) => /[:(){}*+?\\]/.test(segment));
  return `/${segments.slice(0, end === -1 ? undefined : end).join('/')}`;
}

const { beforeFiles, afterFiles, fallback } = routes.rewrites;
const proxiedPrefixes = [...beforeFiles, ...afterFiles, ...fallback]
  .filter((rewrite) => !rewrite.destination.startsWith('/'))
  .map((rewrite) => literalPrefix(rewrite.source));

// Next matches rewrites case-insensitively unless experimental.caseSensitiveRoutes is set.
function isProxied(urlPath: string): boolean {
  const pathname = urlPath.toLowerCase();
  return proxiedPrefixes.some((prefix) => {
    const base = prefix.toLowerCase();
    return pathname === base || pathname.startsWith(`${base}/`);
  });
}

// The URL an app file or folder answers. An intercepting route such as @modal/(...)docs is also a
// beforeFiles rewrite of the path it intercepts (lib/generate-interception-routes-rewrites.js).
function appUrlPath(file: string): string {
  const appPath = normalizeAppPath(file);
  return isInterceptionRouteAppPath(appPath) ? extractInterceptionRouteInformation(appPath).interceptedRoute : appPath;
}

// Every file and folder under dir, relative to it.
function tree(dir: string): string[] {
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir, { recursive: true, encoding: 'utf8' }).map((entry) => entry.split(path.sep).join('/'));
}

function appliedHeaderKeys(pathname: string): string[] {
  return headerRoutes.filter((route) => route.match(pathname)).flatMap((route) => route.headers.map((header) => header.key));
}

describe('Next.js routes next to the proxied backend', () => {
  test('no app route or public file sits under a proxied prefix', () => {
    assert.ok(proxiedPrefixes.length > 0, 'the prefixes are read from rewrites()');
    const appFiles = tree(path.join(REPO_ROOT, 'src/app'));
    assert.ok(appFiles.includes('page.tsx'), 'the walk sees the portal page');
    // Route groups and parallel-route slots are left out of the URL, so (portal)/mcp still serves /mcp.
    // A dynamic segment such as [slug] is matched after the rewrites, so it cannot shadow them.
    const shadowing = [
      ...appFiles.filter((file) => isProxied(appUrlPath(file))).map((file) => `src/app/${file}`),
      ...tree(path.join(REPO_ROOT, 'public')).filter((file) => isProxied(`/${file}`)).map((file) => `public/${file}`),
    ];
    assert.deepEqual(shadowing, []);
  });

  test('portal pages get the security headers, including ones that start like a proxied prefix', () => {
    const portalPaths = ['/', '/settings', '/mcp-traffic', '/mcpx', '/docsearch', ...proxiedPrefixes.map((prefix) => `${prefix}x`)];
    for (const pathname of portalPaths) {
      const keys = appliedHeaderKeys(pathname);
      assert.ok(keys.includes('X-Frame-Options') && keys.includes('Content-Security-Policy'), pathname);
    }
  });

  test("proxied paths keep the backend's own headers", () => {
    const backendPaths = [
      '/mcp',
      '/mcp/anything',
      '/api/admin/x',
      '/auth/okta/callback',
      '/.well-known/oauth-protected-resource',
      '/docs',
      '/docs/x',
      '/healthz',
      ...proxiedPrefixes.flatMap((prefix) => [prefix, `${prefix}/`, `${prefix}/x`]),
    ];
    for (const pathname of backendPaths) assert.deepEqual(appliedHeaderKeys(pathname), [], pathname);
  });

  test('there is no proxy.ts or middleware, which would run in front of the proxied backend', () => {
    for (const dir of ['', 'src']) {
      for (const name of ['proxy', 'middleware']) {
        for (const ext of ['ts', 'tsx', 'js', 'mjs']) {
          const file = path.join(REPO_ROOT, dir, `${name}.${ext}`);
          assert.equal(fs.existsSync(file), false, file);
        }
      }
    }
  });

  test('every portal route in the route map has a page, outside the proxied prefixes, with its headers', () => {
    const appFiles = tree(path.join(REPO_ROOT, 'src/app'));
    const pages = new Set(appFiles.filter((f) => /(^|\/)page\.tsx$/.test(f)).map((f) => appUrlPath(f.replace(/\/?page\.tsx$/, '') || '/')));
    for (const route of ROUTE_LIST) {
      assert.ok(pages.has(route.path), `${route.path} has a page`);
      const sample = route.path.replace('[groupId]', 'grp_x');
      assert.equal(isProxied(sample), false, sample);
      const keys = appliedHeaderKeys(sample);
      assert.ok(keys.includes('X-Frame-Options') && keys.includes('Content-Security-Policy'), sample);
    }
  });

  test('section redirects stay on portal paths and land on a route in the map', () => {
    assert.ok(routes.redirects.length > 0);
    const paths = new Set(ROUTE_LIST.map((r) => r.path));
    for (const r of routes.redirects) {
      if ((r as { internal?: boolean }).internal) continue; // Next's own trailing-slash rule
      assert.equal(isProxied(r.source), false, r.source);
      assert.ok(paths.has(r.destination), r.destination);
    }
  });
});
