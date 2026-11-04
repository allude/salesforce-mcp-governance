/**
 * The portal's one route map. The sidebar, header breadcrumbs, command palette, cross-links and the
 * `(portal)` pages all read it, so a view has exactly one URL and one name. Each route lists the
 * searchParams it accepts, with their allowed values and defaults: parseViewParams drops anything
 * else, and buildHref writes the canonical form (defaults omitted, keys in a fixed order).
 *
 * What a URL may carry: only identifiers the MCP log may also store unredacted (Profile IDs, Salesforce
 * usernames, group ids, SObject and field API names, tool ids, log event ids) and enums. Never SOQL,
 * record IDs or values, free-text search, tokens or secrets. The free-text search boxes stay local.
 *
 * Pure: no React, no DOM, so its rules are unit-tested (test/route-map.test.ts).
 */
import { AVAILABLE_MCP_ACTIONS } from '@/types/governance';

export type RouteId =
  | 'dashboard'
  | 'org-connection'
  | 'org-profiles'
  | 'org-objects'
  | 'access-groups'
  | 'access-group'
  | 'access-matrix'
  | 'simulator'
  | 'logs-mcp'
  | 'logs-admin'
  | 'settings-security'
  | 'settings-copilot';

/** The sidebar's seven views: every route belongs to one. */
export type ViewId = 'dashboard' | 'org' | 'access-groups' | 'simulator' | 'logs-mcp' | 'logs-admin' | 'settings';

export type NavSectionId = 'overview' | 'configure' | 'logs' | 'security';

export const NAV_SECTIONS: ReadonlyArray<{ id: NavSectionId; label: string | null }> = [
  { id: 'overview', label: null },
  { id: 'configure', label: 'Configure' },
  { id: 'logs', label: 'Logs' },
  { id: 'security', label: 'Security' },
];

export interface ViewDef {
  id: ViewId;
  section: NavSectionId;
  label: string;
  /** Where the sidebar item goes: the view's first tab. */
  home: RouteId;
}

export const VIEWS: readonly ViewDef[] = [
  { id: 'dashboard', section: 'overview', label: 'Dashboard', home: 'dashboard' },
  { id: 'org', section: 'configure', label: 'Org & Metadata Sync', home: 'org-connection' },
  { id: 'access-groups', section: 'configure', label: 'Access Groups & Matrix Builder', home: 'access-groups' },
  { id: 'simulator', section: 'configure', label: 'Policy Simulator', home: 'simulator' },
  { id: 'logs-mcp', section: 'logs', label: 'MCP Traffic Logs', home: 'logs-mcp' },
  { id: 'logs-admin', section: 'logs', label: 'Admin Audit Logs', home: 'logs-admin' },
  { id: 'settings', section: 'security', label: 'Security & Auth Settings', home: 'settings-security' },
];

// ------------------------------------------------------------------------------------------------
// Parameter values
// ------------------------------------------------------------------------------------------------

const PROFILE_ID = /^[A-Za-z0-9]{15}(?:[A-Za-z0-9]{3})?$/;
const API_NAME = /^[A-Za-z][A-Za-z0-9_]{0,79}$/;
const FIELD_REF = /^[A-Za-z][A-Za-z0-9_]{0,79}\.[A-Za-z][A-Za-z0-9_]{0,79}$/;
const GROUP_ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,99}$/;
const EVENT_ID = /^(?:mcp|adm)_[a-z0-9]{1,16}_[a-f0-9]{16}$/;
const SF_USERNAME = /^[A-Za-z0-9._%+'-]{1,80}@[A-Za-z0-9.-]{1,120}$/;
const ACTION_CODE = /^[A-Z][A-Z0-9_]{0,63}$/;
const TOOL_IDS: readonly string[] = AVAILABLE_MCP_ACTIONS.map((a) => a.id);

export type ParamSpec =
  | { kind: 'enum'; values: readonly string[]; default?: string }
  | { kind: 'pattern'; pattern: RegExp };

const enumParam = (values: readonly string[], fallback?: string): ParamSpec => ({
  kind: 'enum',
  values,
  default: fallback,
});
const patternParam = (pattern: RegExp): ParamSpec => ({ kind: 'pattern', pattern });

/**
 * The open drawer, on any view: `profile:<Profile ID>`, `object:<SObject>`, `group:<group id>`,
 * `mcp:<event id>`, `audit:<event id>`, or one of the panels that hold no identifier.
 */
export const DRAWER_PATTERN =
  /^(?:profile:[A-Za-z0-9]{15}(?:[A-Za-z0-9]{3})?|object:[A-Za-z][A-Za-z0-9_]{0,79}|group:(?:new|[A-Za-z0-9][A-Za-z0-9_.:-]{0,99})|mcp:mcp_[a-z0-9]{1,16}_[a-f0-9]{16}|audit:adm_[a-z0-9]{1,16}_[a-f0-9]{16}|newprofile|import|sync)$/;

/** Accepted on every route. */
const GLOBAL_PARAMS: Record<string, ParamSpec> = { drawer: patternParam(DRAWER_PATTERN) };

export interface RouteDef {
  id: RouteId;
  view: ViewId;
  /** Path pattern; `[groupId]` is a path parameter. */
  path: string;
  /** The tab label within its view (or the view's title when it has no tabs). */
  title: string;
  /** searchParams, in canonical order. */
  params: Record<string, ParamSpec>;
}

export const ROUTES: Record<RouteId, RouteDef> = {
  dashboard: {
    id: 'dashboard',
    view: 'dashboard',
    path: '/dashboard',
    title: 'Dashboard',
    params: { range: enumParam(['1h', '24h', '7d'], '24h') },
  },
  'org-connection': { id: 'org-connection', view: 'org', path: '/org/connection', title: 'Connection', params: {} },
  'org-profiles': { id: 'org-profiles', view: 'org', path: '/org/profiles', title: 'Profiles', params: {} },
  'org-objects': {
    id: 'org-objects',
    view: 'org',
    path: '/org/objects',
    title: 'Objects',
    params: { status: enumParam(['enabled', 'disabled']), kind: enumParam(['std', 'custom']) },
  },
  'access-groups': {
    id: 'access-groups',
    view: 'access-groups',
    path: '/access-groups/groups',
    title: 'Groups',
    params: {},
  },
  'access-group': {
    id: 'access-group',
    view: 'access-groups',
    path: '/access-groups/groups/[groupId]',
    title: 'Groups',
    params: {},
  },
  'access-matrix': {
    id: 'access-matrix',
    view: 'access-groups',
    path: '/access-groups/matrix',
    title: 'Profile ↔ Group matrix',
    params: {},
  },
  simulator: {
    id: 'simulator',
    view: 'simulator',
    path: '/simulator',
    title: 'Policy Simulator',
    params: {
      profile: patternParam(PROFILE_ID),
      user: patternParam(SF_USERNAME),
      tool: enumParam(TOOL_IDS),
      object: patternParam(API_NAME),
    },
  },
  'logs-mcp': {
    id: 'logs-mcp',
    view: 'logs-mcp',
    path: '/logs/mcp',
    title: 'MCP Traffic Logs',
    params: {
      status: enumParam(['ALLOWED', 'DENIED', 'ERROR']),
      tool: enumParam(TOOL_IDS),
      object: patternParam(API_NAME),
      user: patternParam(SF_USERNAME),
    },
  },
  'logs-admin': {
    id: 'logs-admin',
    view: 'logs-admin',
    path: '/logs/admin',
    title: 'Admin Audit Logs',
    params: { method: enumParam(['okta_sso', 'password']), action: patternParam(ACTION_CODE) },
  },
  'settings-security': {
    id: 'settings-security',
    view: 'settings',
    path: '/settings/security',
    title: 'Security & Auth',
    params: {},
  },
  'settings-copilot': {
    id: 'settings-copilot',
    view: 'settings',
    path: '/settings/copilot',
    title: 'Copilot connector',
    params: {},
  },
};

export const ROUTE_LIST: readonly RouteDef[] = Object.values(ROUTES);

/** The tabs each view shows, in order (views with one route have none). */
export const VIEW_TABS: Partial<Record<ViewId, readonly RouteId[]>> = {
  org: ['org-connection', 'org-profiles', 'org-objects'],
  'access-groups': ['access-groups', 'access-matrix'],
  settings: ['settings-security', 'settings-copilot'],
};

/** Identifier shapes, for the views that build drawer values and links. */
export const IDENTIFIER_PATTERNS = {
  profileId: PROFILE_ID,
  apiName: API_NAME,
  fieldRef: FIELD_REF,
  groupId: GROUP_ID,
  eventId: EVENT_ID,
  sfUsername: SF_USERNAME,
} as const;

export function viewDef(id: ViewId): ViewDef {
  return VIEWS.find((v) => v.id === id)!;
}

// ------------------------------------------------------------------------------------------------
// Matching, parsing and building
// ------------------------------------------------------------------------------------------------

export interface RouteMatch {
  route: RouteDef;
  pathParams: Record<string, string>;
}

/** The route a pathname shows, or null. Path parameters must match their identifier shape. */
export function matchRoute(pathname: string): RouteMatch | null {
  const clean = pathname.replace(/\/+$/, '') || '/';
  for (const route of ROUTE_LIST) {
    const pattern = route.path.split('/');
    const parts = clean.split('/');
    if (pattern.length !== parts.length) continue;
    const pathParams: Record<string, string> = {};
    let ok = true;
    for (let i = 0; i < pattern.length && ok; i++) {
      const seg = pattern[i];
      if (seg.startsWith('[') && seg.endsWith(']')) {
        let value: string;
        try {
          value = decodeURIComponent(parts[i]);
        } catch {
          ok = false;
          break;
        }
        if (!GROUP_ID.test(value)) ok = false;
        else pathParams[seg.slice(1, -1)] = value;
      } else if (seg !== parts[i]) {
        ok = false;
      }
    }
    if (ok) return { route, pathParams };
  }
  return null;
}

export type ViewParams = Record<string, string>;

function accepts(spec: ParamSpec, value: string): boolean {
  return spec.kind === 'enum' ? spec.values.includes(value) : spec.pattern.test(value);
}

function specsFor(route: RouteDef): Array<[string, ParamSpec]> {
  return [...Object.entries(route.params), ...Object.entries(GLOBAL_PARAMS)];
}

export interface ParsedParams {
  /** Every accepted parameter, defaults filled in. */
  values: ViewParams;
  /** The canonical query string ('' or '?a=b'). */
  search: string;
  /** Whether the input carried anything unknown, invalid, repeated or default (so it is not canonical). */
  changed: boolean;
}

/** Reads a route's searchParams: unknown keys and invalid values are dropped, defaults filled in. */
export function parseViewParams(route: RouteDef, input: URLSearchParams): ParsedParams {
  const values: ViewParams = {};
  for (const [key, spec] of specsFor(route)) {
    const all = input.getAll(key);
    const value = all.length === 1 ? all[0] : undefined;
    if (value !== undefined && accepts(spec, value)) values[key] = value;
    else if (spec.kind === 'enum' && spec.default !== undefined) values[key] = spec.default;
  }
  const search = canonicalSearch(route, values);
  const original = input.toString();
  return { values, search, changed: (original ? `?${original}` : '') !== search };
}

function canonicalSearch(route: RouteDef, values: ViewParams): string {
  const out = new URLSearchParams();
  for (const [key, spec] of specsFor(route)) {
    const value = values[key];
    if (value === undefined || value === '' || !accepts(spec, value)) continue;
    if (spec.kind === 'enum' && spec.default === value) continue;
    out.set(key, value);
  }
  const text = out.toString();
  return text ? `?${text}` : '';
}

/**
 * The canonical href of a route. Invalid parameter values are dropped rather than written, so nothing
 * that is not an identifier or an enum can reach a URL through here.
 */
export function buildHref(
  id: RouteId,
  params: ViewParams = {},
  pathParams: Record<string, string> = {}
): string {
  const route = ROUTES[id];
  const path = route.path.replace(/\[(\w+)\]/g, (_, name: string) => {
    const value = pathParams[name];
    if (value === undefined || !GROUP_ID.test(value)) throw new Error(`buildHref(${id}): invalid ${name}`);
    return encodeURIComponent(value);
  });
  return `${path}${canonicalSearch(route, params)}`;
}

/**
 * A same-origin portal URL for `next` after sign-in, rebuilt from the route map so the router never
 * receives anything it did not build itself. Answers null for anything else (absolute URLs,
 * protocol-relative paths, backend paths such as /mcp or /api/admin, unknown pages).
 */
export function safePortalHref(candidate: string | null | undefined): string | null {
  if (!candidate || !candidate.startsWith('/') || candidate.startsWith('//') || candidate.includes('\\')) return null;
  let url: URL;
  try {
    url = new URL(candidate, 'http://portal.invalid');
  } catch {
    return null;
  }
  if (url.origin !== 'http://portal.invalid') return null;
  const match = matchRoute(url.pathname);
  if (!match) return null;
  const { values } = parseViewParams(match.route, url.searchParams);
  return buildHref(match.route.id, values, match.pathParams);
}

/** Where a sidebar item or the palette goes for a view. */
export function viewHref(id: ViewId): string {
  return buildHref(viewDef(id).home);
}

/** The breadcrumb for a route: section, view, tab (when the view has tabs) and an entity, if any. */
export function breadcrumb(match: RouteMatch, entity?: string): string[] {
  const view = viewDef(match.route.view);
  const section = NAV_SECTIONS.find((s) => s.id === view.section)?.label;
  const crumbs = [section, view.label].filter((c): c is string => Boolean(c));
  if (VIEW_TABS[view.id]) crumbs.push(match.route.title);
  if (entity) crumbs.push(entity);
  return crumbs;
}

// ------------------------------------------------------------------------------------------------
// Drawer values
// ------------------------------------------------------------------------------------------------

export type DrawerRef =
  | { type: 'profile'; id: string }
  | { type: 'object'; id: string }
  | { type: 'group'; id: string }
  | { type: 'mcp'; id: string }
  | { type: 'audit'; id: string }
  | { type: 'newprofile' | 'import' | 'sync' };

export function parseDrawer(value: string | undefined | null): DrawerRef | null {
  if (!value || !DRAWER_PATTERN.test(value)) return null;
  const colon = value.indexOf(':');
  if (colon === -1) return { type: value as 'newprofile' | 'import' | 'sync' };
  const type = value.slice(0, colon) as 'profile' | 'object' | 'group' | 'mcp' | 'audit';
  return { type, id: value.slice(colon + 1) };
}

export function drawerParam(ref: DrawerRef): string | null {
  const value = 'id' in ref ? `${ref.type}:${ref.id}` : ref.type;
  return DRAWER_PATTERN.test(value) ? value : null;
}
