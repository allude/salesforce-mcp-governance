import { Router, Request, Response, NextFunction } from 'express';
import crypto from 'node:crypto';
import {
  MembershipChangeError,
  runInTransaction,
  SIMULATE_MCP_CALL_ACTION,
  store,
  type MembershipDelta,
} from '../db/store.js';
import { parseProfilesCsv, parseSfdxFilesToObjects } from '../db/importers.js';
import {
  requireAdminAuth,
  issueAdminSessionCookie,
  clearAdminSessionCookie,
  isHttpsUrl,
  effectiveOktaRedirectUri,
  verifyAdminSessionFromRequest,
} from '../security/adminAuth.js';
import { PORTAL_PASSWORD_MIN_LENGTH } from '../security/passwordPolicy.js';
import {
  createSimulatorToken,
  resolveSalesforceUserFromToken,
  validateSalesforceInstanceUrl,
} from '../salesforce/client.js';
import {
  generateSelfSignedCertificateBundle,
  connectToSalesforceOrgViaJwt,
  inspectCertificatePem,
  validatePrivateKeyPem,
  fetchProfilesFromOrgSession,
  fetchOrgObjectsCatalog,
  fetchObjectsMetadataFromOrgSession,
  SalesforceOrgTokenSession,
} from '../salesforce/jwtConnection.js';
import { config, KNOWN_DEFAULT_PASSWORDS } from '../config.js';
import { parseObjectSyncPayload, parseProfileSyncPayload, type PayloadResult } from './orgSyncPayload.js';
import { LogPageQueryError, parseMcpLogPageQuery, parsePortalLogPageQuery } from './logPageQuery.js';
import { groupAuditFields, groupUpdateDiff } from './groupAuditDiff.js';
import { parseGroupObjectPermissions, parseGroupSaveRequest } from './groupPayload.js';
import { isSalesforceId, salesforceIdsMatch } from '../salesforce/ids.js';
import { assertNotSimulatedOrgHost } from '../salesforce/simulatedOrg.js';
import type { AccessGroup, SalesforceConnectionSettings } from '../types/governance.js';
import {
  decisionLogStatus,
  evaluatePolicy,
  evaluateToolAccess,
  loadPolicySnapshot,
  policyEvaluationResult,
  resolveEffectiveProfilePermissions,
} from '../rbac/policyEngine.js';
import { targetObjectArgument } from '../mcp/toolArguments.js';

export const adminRouter = Router();

type SalesforceSettingsInput = Parameters<typeof store.updateSalesforceSettings>[0];

/**
 * The Salesforce settings an admin may set from a request. Connection state (enabled, status, connected
 * org, last error) is written only by the connect and disconnect routes.
 */
function parseSalesforceSettingsInput(body: Record<string, any>): SalesforceSettingsInput {
  const input: SalesforceSettingsInput = {};
  if (body.instanceUrl !== undefined) {
    input.instanceUrl = validateSalesforceInstanceUrl(String(body.instanceUrl));
    // MCP sends real bearer tokens to this host, and the simulated one is not a real org.
    assertNotSimulatedOrgHost(input.instanceUrl, 'Salesforce instance URL');
  }
  if (body.loginUrl !== undefined) {
    // The signed JWT assertion is posted here, so it passes the same allowlist as instance URLs.
    input.loginUrl = validateSalesforceInstanceUrl(String(body.loginUrl));
    assertNotSimulatedOrgHost(input.loginUrl, 'Salesforce login URL');
  }
  if (body.apiVersion !== undefined) {
    if (!/^v\d+\.\d$/.test(String(body.apiVersion).trim())) {
      throw new Error('API version must look like v62.0.');
    }
    input.apiVersion = String(body.apiVersion).trim();
  }
  if (body.expectedOrgId !== undefined) {
    const orgId = String(body.expectedOrgId).trim();
    if (orgId && !/^00D[a-zA-Z0-9]{12}(?:[a-zA-Z0-9]{3})?$/.test(orgId)) {
      throw new Error('Expected Org ID must be a 15 or 18-character Salesforce Org ID (00D...).');
    }
    input.expectedOrgId = orgId;
  }
  if (body.enforceOrgIdLock !== undefined) {
    input.enforceOrgIdLock = Boolean(body.enforceOrgIdLock);
  }
  if (body.sfdxObjectsFolderPath !== undefined) {
    input.sfdxObjectsFolderPath = String(body.sfdxObjectsFolderPath);
  }
  if (body.authMode !== undefined) {
    if (body.authMode !== 'jwt_bearer' && body.authMode !== 'simulated') {
      throw new Error("Auth mode must be 'jwt_bearer' or 'simulated'.");
    }
    if (body.authMode === 'simulated' && config.isProd) {
      throw new Error('Simulated Salesforce connections are not available in production.');
    }
    input.authMode = body.authMode;
  }
  if (body.clientId !== undefined) input.clientId = String(body.clientId);
  if (body.username !== undefined) input.username = String(body.username);
  if (body.privateKeyPem !== undefined) input.privateKeyPem = String(body.privateKeyPem);
  if (body.certificatePem !== undefined) input.certificatePem = String(body.certificatePem);

  const current = store.getSalesforceSettings();
  if ((input.enforceOrgIdLock ?? current.enforceOrgIdLock) && !(input.expectedOrgId ?? current.expectedOrgId)) {
    throw new Error('Set an expected Org ID before enforcing the Org ID lock.');
  }
  return input;
}

/** What a connect proves. The private key and certificate body are compared too, but never logged. */
const VERIFIED_CONNECTION_FIELDS = [
  'authMode',
  'loginUrl',
  'clientId',
  'username',
  'expectedOrgId',
  'enforceOrgIdLock',
  'certificatePem',
  'certFingerprint',
] as const;

const NO_CONNECTED_ORG = {
  enabled: false,
  lastConnectedAt: null,
  lastError: '',
  connectedOrgId: '',
  connectedUser: '',
  syncInstanceUrl: '',
} satisfies SalesforceSettingsInput;

/** The settings an audit entry may show. An allowlist, so the key, certificate body and tokens stay out. */
function auditableSettings(settings: Omit<SalesforceConnectionSettings, 'updatedAt'>) {
  return {
    authMode: settings.authMode,
    loginUrl: settings.loginUrl,
    clientId: settings.clientId,
    username: settings.username,
    expectedOrgId: settings.expectedOrgId,
    enforceOrgIdLock: settings.enforceOrgIdLock,
    instanceUrl: settings.instanceUrl,
    syncInstanceUrl: settings.syncInstanceUrl,
    apiVersion: settings.apiVersion,
    sfdxObjectsFolderPath: settings.sfdxObjectsFolderPath,
    certFingerprint: settings.certFingerprint,
    connectionStatus: settings.connectionStatus,
    connectedOrgId: settings.connectedOrgId,
  };
}

function auditDiff(before: Omit<SalesforceConnectionSettings, 'updatedAt'>, after: typeof before): string {
  const from = auditableSettings(before);
  const to = auditableSettings(after);
  const changed: Record<string, { before: unknown; after: unknown }> = {};
  for (const field of Object.keys(from) as Array<keyof typeof from>) {
    if (from[field] !== to[field]) changed[field] = { before: from[field], after: to[field] };
  }
  return JSON.stringify(changed);
}

/** How the settings changed, for a Portal Admin log entry. Values are JSON so a username cannot fake a line. */
function auditChanges(
  before: Omit<SalesforceConnectionSettings, 'updatedAt'>,
  after: typeof before,
  privateKeyReplaced: boolean
): string {
  return `Changes: ${auditDiff(before, after)}. privateKeyReplaced: ${privateKeyReplaced}.`;
}

/**
 * Saves settings outside a verified connect. A change to anything a connect proves ends the verified
 * state, so nothing keeps reporting an org those settings were never tried against. A disconnected
 * org has no such state to end and stays disconnected.
 */
function saveSalesforceSettings(input: SalesforceSettingsInput) {
  return runInTransaction(() => {
    const before = store.getSalesforceSettingsWithSecrets();
    const saved = store.updateSalesforceSettings(input);
    const after = store.getSalesforceSettingsWithSecrets();
    const privateKeyReplaced = after.privateKeyPem !== before.privateKeyPem;
    const changed = privateKeyReplaced || VERIFIED_CONNECTION_FIELDS.some((f) => after[f] !== before[f]);
    const updated =
      changed && before.connectionStatus !== 'disconnected'
        ? store.updateSalesforceSettings({ ...NO_CONNECTED_ORG, connectionStatus: 'not_verified' })
        : saved;
    return { before, updated, privateKeyReplaced };
  });
}

/**
 * Why a production Okta save must be refused, if it should be. The issuer's discovery and token
 * endpoints receive the client secret, and the redirect URI receives the authorization code.
 * A blank issuer is allowed, as one not configured yet. A blank redirect URI means the BASE_URL
 * default, which sign-in also refuses when it is http, so an enabled result is judged by that default.
 * The result is judged after merging with the stored row, so `{enabled: true}` cannot switch on a
 * stored http issuer. A result left disabled may keep a bad stored value, so that an admin can still
 * turn Okta off (the portal resends the stored redirect URI), but it cannot introduce a new one.
 */
function insecureOktaUrlError(body: Record<string, unknown>): string | null {
  const submitted: Array<[string, unknown]> = [
    ['Okta Issuer', body.issuer],
    ['Okta Redirect URI', body.redirectUri],
  ];
  for (const [label, value] of submitted) {
    if (value !== undefined && value !== null && typeof value !== 'string') {
      return `${label} must be an https:// URL in production.`;
    }
  }
  const stored = store.getOktaConfig();
  const next = store.resolveOktaSave(body);
  const results: Array<[string, string, string]> = [
    ['Okta Issuer', next.issuer, stored.issuer],
    ['Okta Redirect URI', next.redirectUri, stored.redirectUri],
  ];
  for (const [label, url, storedUrl] of results) {
    if (!url || isHttpsUrl(url)) continue;
    if (next.enabled || url !== storedUrl) {
      return `${label} must be an https:// URL in production.`;
    }
  }
  if (next.enabled && !next.redirectUri && !isHttpsUrl(effectiveOktaRedirectUri(''))) {
    return 'Okta Redirect URI is blank, so it defaults to one under BASE_URL, and that must be an https:// URL in production. Enter an https:// redirect URI or set an https BASE_URL.';
  }
  return null;
}

/** Express 4 ignores rejected promises, so async handlers must hand failures to `next` explicitly. */
const asyncRoute =
  (handler: (req: Request, res: Response) => Promise<void>) =>
  (req: Request, res: Response, next: NextFunction) => {
    handler(req, res).catch(next);
  };

/**
 * The id that ties together every Portal Admin log row one Admin API request writes. It is made here,
 * once per request, and never taken from the client, so a caller cannot file its rows under another
 * request's id. The response carries it as X-Correlation-Id.
 */
function correlationIdFor(res: Response): string {
  if (typeof res.locals.correlationId !== 'string') {
    res.locals.correlationId = crypto.randomUUID();
    if (!res.headersSent) res.setHeader('X-Correlation-Id', res.locals.correlationId);
  }
  return res.locals.correlationId;
}

function getAdminInfo(req: Request): {
  username: string;
  authMethod: 'password' | 'okta_sso';
  ip: string;
  correlationId: string | undefined;
} {
  const session = (req as any).adminSession;
  return {
    username: session?.email || 'admin',
    authMethod: session?.authMethod === 'okta_oidc' ? 'okta_sso' : 'password',
    ip: req.ip || '127.0.0.1',
    // Also reached before this router runs (a sync body the JSON parser refused), hence made on demand.
    correlationId: req.res ? correlationIdFor(req.res) : undefined,
  };
}

const SYNC_OBJECTS_TARGET = 'Salesforce > Objects';
const SYNC_PROFILES_TARGET = 'Salesforce > Profiles';
const SYNCED_NAMES_LOGGED = 50;

/** One clause of a sync's audit entry; empty when there is nothing to name. */
function namesClause(heading: string, names: string[], limit = names.length): string {
  if (names.length === 0) return '';
  const extra = names.length > limit ? `, and ${names.length - limit} more` : '';
  return ` ${heading}: ${names.slice(0, limit).join(', ')}${extra}.`;
}

function recordSyncFailure(req: Request, action: string, target: string, reason: string): void {
  const actor = getAdminInfo(req);
  store.recordPortalAdminLog({
    adminUsername: actor.username,
    authMethod: actor.authMethod,
    action,
    target,
    details: `Sync from Salesforce Org failed and changed nothing: ${reason.slice(0, 500)}`,
    ipAddress: actor.ip,
    correlationId: actor.correlationId,
  });
}

/** For failures before the route runs, such as a body the JSON parser refused. */
export function recordObjectSyncFailure(req: Request, reason: string): void {
  recordSyncFailure(req, 'SYNC_OBJECTS_FROM_ORG_FAILED', SYNC_OBJECTS_TARGET, reason);
}

function recordProfileSyncFailure(req: Request, reason: string): void {
  recordSyncFailure(req, 'SYNC_PROFILES_FROM_ORG_FAILED', SYNC_PROFILES_TARGET, reason);
}

// First, so that every Admin API response names its request, the signed-out ones included.
adminRouter.use((_req: Request, res: Response, next: NextFunction) => {
  correlationIdFor(res);
  next();
});

/**
 * GET /api/admin/session
 * Checks if the portal user is currently signed in (no auto-login bypass).
 */
adminRouter.get('/session', asyncRoute(async (req: Request, res: Response) => {
  const session = await verifyAdminSessionFromRequest(req);
  const okta = store.getOktaConfig();

  res.json({
    authenticated: Boolean(session),
    user: session
      ? {
          username: session.email,
          name: session.name,
          authMethod: session.authMethod,
          groups: session.groups || [],
        }
      : null,
    csrfToken: session?.csrfToken || null,
    oktaSso: {
      enabled: okta.enabled,
      oktaDomain: okta.oktaDomain,
    },
  });
}));

/**
 * POST /api/admin/login
 * Signs into the portal using Username + Password.
 */
adminRouter.post('/login', asyncRoute(async (req: Request, res: Response) => {
  const { username, email, password } = req.body || {};
  const identifierInput = username ?? email;
  if (
    (identifierInput !== undefined && typeof identifierInput !== 'string') ||
    (password !== undefined && typeof password !== 'string')
  ) {
    res.status(400).json({ error: 'Username and password must be strings.' });
    return;
  }
  const loginIdentifier = (identifierInput || '').trim();
  const rawPassword = password || '';

  if (!loginIdentifier || !rawPassword) {
    res.status(400).json({ error: 'Username and password are required.' });
    return;
  }

  const verifiedUser = store.verifyPortalUserCredentials(
    loginIdentifier,
    rawPassword
  );
  if (!verifiedUser) {
    const attemptedUsername = loginIdentifier.slice(0, 120);
    store.recordPortalAdminLog({
      adminUsername: attemptedUsername,
      authMethod: 'password',
      action: 'LOGIN_FAILED',
      target: 'Portal Auth',
      details: `Failed password login attempt for username "${attemptedUsername}".`,
      ipAddress: req.ip || '127.0.0.1',
      correlationId: correlationIdFor(res),
    });
    res.status(401).json({ error: 'Invalid username or password.' });
    return;
  }

  const { csrfToken } = await issueAdminSessionCookie(res, {
    sub: `portal_${verifiedUser.username}`,
    email: verifiedUser.username,
    name: verifiedUser.displayName,
    authMethod: 'local_bootstrap',
    groups: [verifiedUser.role],
  });

  store.recordPortalAdminLog({
    adminUsername: verifiedUser.username,
    authMethod: 'password',
    action: 'LOGIN_SUCCESS',
    target: 'Portal Auth',
    details: `User "${verifiedUser.username}" (${verifiedUser.role}) signed in with username and password.`,
    ipAddress: req.ip || '127.0.0.1',
    correlationId: correlationIdFor(res),
  });

  res.json({
    success: true,
    csrfToken,
    user: {
      username: verifiedUser.username,
      name: verifiedUser.displayName,
      role: verifiedUser.role,
      authMethod: 'password',
    },
  });
}));

/**
 * POST /api/admin/logout
 */
adminRouter.post('/logout', asyncRoute(async (req: Request, res: Response) => {
  const session = await verifyAdminSessionFromRequest(req);
  if (session) {
    store.recordPortalAdminLog({
      adminUsername: session.email,
      authMethod: session.authMethod === 'okta_oidc' ? 'okta_sso' : 'password',
      action: 'LOGOUT',
      target: 'Portal Auth',
      details: `User "${session.email}" signed out of the portal.`,
      ipAddress: req.ip || '127.0.0.1',
      correlationId: correlationIdFor(res),
    });
  }
  clearAdminSessionCookie(res);
  res.json({ success: true });
}));

// ============================================================================
// PROTECTED PORTAL API ROUTES
// ============================================================================
adminRouter.use((req: Request, res: Response, next: NextFunction) => {
  requireAdminAuth(req, res, next).catch(next);
});

// Each list holds up to this many rows of ordinary traffic, plus its own smaller allowances of simulated
// rows and (MCP only) rejected-token rows, merged newest first. Simulated rows are told apart by
// `simulated` or the SIMULATE_MCP_CALL action, rejected tokens by the unverified_caller user.
const OVERVIEW_LOG_ROWS = 150;
const OVERVIEW_SIMULATED_LOG_ROWS = 50;
const OVERVIEW_REJECTED_LOG_ROWS = 50;

/**
 * GET /api/admin/overview
 */
adminRouter.get('/overview', (_req: Request, res: Response) => {
  const profiles = store.getProfiles();
  const objects = store.getObjects();
  const groups = store.getGroups();
  const profileGroupMappings = store.getProfileGroupMappings();
  const copilotLogs = store.getCopilotMcpLogsCappedByKind(
    OVERVIEW_LOG_ROWS,
    OVERVIEW_SIMULATED_LOG_ROWS,
    OVERVIEW_REJECTED_LOG_ROWS
  );
  const portalLogs = store.getPortalAdminLogsCappedByKind(OVERVIEW_LOG_ROWS, OVERVIEW_SIMULATED_LOG_ROWS);
  const okta = store.getOktaConfig();
  const sfSettings = store.getSalesforceSettings();
  const portalUsers = store.getPortalUsers();

  // Totals cover every real logged call; the log lists themselves are only the latest rows.
  const mcpStats = store.getCopilotMcpLogStats();

  res.json({
    serverTime: new Date().toISOString(),
    stats: {
      totalMcpRequests: mcpStats.total,
      allowedMcpRequests: mcpStats.allowed,
      deniedMcpRequests: mcpStats.denied,
      erroredMcpRequests: mcpStats.errors,
      lastMcpCallAt: store.getLastRealMcpCallAt(),
      totalProfiles: profiles.length,
      totalObjects: objects.length,
      enabledObjects: objects.filter((o) => o.enabled).length,
      totalGroups: groups.length,
    },
    profiles,
    objects,
    groups,
    profileGroupMappings,
    // Read in the same tick as the four lists above, so it is the revision they show.
    policyRevision: store.getPolicyRevision(),
    copilotLogs,
    portalLogs,
    // The Logs views state these, so rows a cap left out are not read as missing activity.
    logCaps: {
      copilotLogs: {
        calls: OVERVIEW_LOG_ROWS,
        simulated: OVERVIEW_SIMULATED_LOG_ROWS,
        rejected: OVERVIEW_REJECTED_LOG_ROWS,
      },
      portalLogs: { events: OVERVIEW_LOG_ROWS, simulations: OVERVIEW_SIMULATED_LOG_ROWS },
    },
    devToolsEnabled: !config.isProd,
    oktaSettings: {
      enabled: okta.enabled,
      oktaDomain: okta.oktaDomain,
      issuer: okta.issuer,
      clientId: okta.clientId,
      hasClientSecret: okta.hasClientSecret,
      redirectUri: okta.redirectUri,
      adminGroup: okta.adminGroup,
      updatedAt: okta.updatedAt,
    },
    sfSettings,
    portalUsers,
  });
});

/** Answers a malformed paging query with 400 and anything else as the page itself. */
function sendLogPage<T>(res: Response, read: () => T) {
  let page: T;
  try {
    page = read();
  } catch (err) {
    if (!(err instanceof LogPageQueryError)) throw err;
    res.status(400).json({ error: err.message });
    return;
  }
  res.json(page);
}

/**
 * GET /api/admin/mcp-logs?before=&limit=&status=&simulated=&tool=&object=
 * Pages back through the whole Copilot MCP log, newest first, so rows past the /overview caps stay
 * reachable. Read-only.
 */
adminRouter.get('/mcp-logs', (req: Request, res: Response) => {
  sendLogPage(res, () => store.getCopilotMcpLogPage(parseMcpLogPageQuery(req.query)));
});

/**
 * GET /api/admin/portal-logs?before=&limit=&action=&authMethod=
 * Pages back through the whole portal audit log, newest first. Read-only.
 */
adminRouter.get('/portal-logs', (req: Request, res: Response) => {
  sendLogPage(res, () => store.getPortalAdminLogPage(parsePortalLogPageQuery(req.query)));
});

// ============================================================================
// 1. SALESFORCE -> PROFILES (Add/Update, CSV Import, Delete)
// ============================================================================
adminRouter.post('/profiles', (req: Request, res: Response) => {
  const { id, name, creating } = req.body || {};
  if (!id || !name) {
    res.status(400).json({ error: 'Profile ID and Profile Name are required.' });
    return;
  }
  // Only a new ID is checked, so a row stored before this rule can still be renamed.
  if (!isSalesforceId(String(id)) && !store.getProfileById(String(id))) {
    res.status(400).json({ error: 'Profile ID must be a 15 or 18 character Salesforce ID.' });
    return;
  }

  // Only the New Profile form sets `creating`: someone pasting an ID there means a new Profile, so
  // finding it stored in any form, the exact one included, is news to them, not a rename to apply
  // over the stored row.
  if (creating === true) {
    const cleanId = String(id).trim();
    const forms = store.getProfiles().filter((p) => salesforceIdsMatch(p.id, cleanId));
    if (forms.length > 0) {
      res.status(409).json({
        error: `This Profile is already stored as ${forms[0].id} ("${forms[0].name}"). Open that row to edit it.`,
      });
      return;
    }
  }

  const result = store.upsertProfile(String(id), String(name));
  if (result.nameKept) {
    const forms = store
      .getProfiles()
      .filter((p) => salesforceIdsMatch(p.id, result.profile.id))
      .map((p) => p.id);
    res.status(409).json({
      error: `This Profile is stored under ${forms.join(' and ')}, and that name would change which row is in force. Delete one or pull Profiles from the org, then rename it.`,
    });
    return;
  }
  const actor = getAdminInfo(req);
  store.recordPortalAdminLog({
    adminUsername: actor.username,
    authMethod: actor.authMethod,
    action: result.action === 'inserted' ? 'CREATE_PROFILE' : 'UPDATE_PROFILE',
    target: `Profile: ${result.profile.name} (${result.profile.id})`,
    details: `${
      result.action === 'inserted' ? 'Added new' : 'Updated existing'
    } Salesforce Profile "${result.profile.name}" with ID "${result.profile.id}".${
      result.previousId ? ` Its ID was upgraded from "${result.previousId}", keeping its Access Groups.` : ''
    }`,
    ipAddress: actor.ip,
    correlationId: actor.correlationId,
    targetType: 'profile',
    targetId: result.profile.id,
  });

  res.json({
    profile: result.profile,
    profiles: store.getProfiles(),
  });
});

/**
 * POST /api/admin/profiles/import-csv
 * Accepts either `{ csvText: string }` or `{ rows: Array<{ id: string, name: string }> }`
 */
adminRouter.post('/profiles/import-csv', (req: Request, res: Response) => {
  const { csvText, rows } = req.body || {};
  const parsedRows: Array<{ id: string; name: string }> = [];

  if (Array.isArray(rows)) {
    for (const r of rows) {
      if (r && r.id && r.name) {
        parsedRows.push({ id: String(r.id).trim(), name: String(r.name).trim() });
      }
    }
  } else if (typeof csvText === 'string') {
    parsedRows.push(...parseProfilesCsv(csvText));
  }

  if (parsedRows.length === 0) {
    res.status(400).json({
      error:
        'No valid (id, name) rows found in CSV. Expected 2 columns: id, name.',
    });
    return;
  }

  const summary = store.importProfilesFromCsvRows(parsedRows);
  const actor = getAdminInfo(req);
  store.recordPortalAdminLog({
    adminUsername: actor.username,
    authMethod: actor.authMethod,
    action: 'IMPORT_PROFILES_CSV',
    target: 'Salesforce > Profiles',
    details: `Imported ${parsedRows.length} profile rows from CSV (${summary.inserted} added, ${summary.updated} updated; ${summary.total} total profiles).${
      summary.idsUpgraded ? ` ${summary.idsUpgraded} upgraded to their 18-character ID, keeping Access Groups.` : ''
    }${
      summary.namesKept ? ` ${summary.namesKept} kept their name because they are stored under two ID forms.` : ''
    }`,
    ipAddress: actor.ip,
    correlationId: actor.correlationId,
  });

  res.json({
    summary,
    profiles: store.getProfiles(),
  });
});

adminRouter.delete('/profiles/:id', (req: Request, res: Response) => {
  const id = String(req.params.id);
  const existing = store.getProfileById(id);
  const deleted = store.deleteProfile(id);
  if (!deleted) {
    res.status(404).json({ error: 'Profile not found.' });
    return;
  }

  const actor = getAdminInfo(req);
  store.recordPortalAdminLog({
    adminUsername: actor.username,
    authMethod: actor.authMethod,
    action: 'DELETE_PROFILE',
    target: `Profile: ${existing?.name || id} (${id})`,
    details: `Deleted Salesforce Profile "${existing?.name || id}" (${id}).`,
    ipAddress: actor.ip,
    correlationId: actor.correlationId,
    targetType: 'profile',
    targetId: id.trim(),
  });

  res.json({ profiles: store.getProfiles() });
});

async function getActiveSalesforceOrgSession(): Promise<SalesforceOrgTokenSession> {
  const sfSecrets = store.getSalesforceSettingsWithSecrets();
  const active =
    sfSecrets.connectionStatus === 'connected' ||
    (sfSecrets.enabled && sfSecrets.connectionStatus !== 'not_verified');
  if (!active) {
    throw new Error(
      'Salesforce Org connection is not active. Go to "Connect to Salesforce Org" to connect via JWT Bearer.'
    );
  }
  return connectToSalesforceOrgViaJwt({
    authMode: sfSecrets.authMode,
    loginUrl: sfSecrets.loginUrl,
    clientId: sfSecrets.clientId,
    username: sfSecrets.username,
    privateKeyPem: sfSecrets.privateKeyPem,
    privateKeyUndecryptable: sfSecrets.privateKeyUndecryptable,
    apiVersion: sfSecrets.apiVersion,
    expectedOrgId: sfSecrets.expectedOrgId,
    enforceOrgIdLock: sfSecrets.enforceOrgIdLock,
  });
}

/**
 * POST /api/admin/profiles/pull-preview
 * Connects to the configured Salesforce Org via JWT and previews profile additions, updates, and removals.
 */
adminRouter.post(
  '/profiles/pull-preview',
  async (req: Request, res: Response) => {
    try {
      const session = await getActiveSalesforceOrgSession();
      let orgProfiles = await fetchProfilesFromOrgSession(session);

      // Optional test parameter `simulateRemovedProfileIds` for verifying removal alerts in Simulated Org mode
      const { simulateRemovedProfileIds } = req.body || {};
      if (
        session.authMode === 'simulated' &&
        Array.isArray(simulateRemovedProfileIds) &&
        simulateRemovedProfileIds.length > 0
      ) {
        const simRemSet = new Set(simulateRemovedProfileIds.map(String));
        orgProfiles = orgProfiles.filter((p) => !simRemSet.has(p.id));
      }

      const preview = store.previewProfilesSyncFromOrg(orgProfiles, {
        orgId: session.orgId,
        instanceUrl: session.instanceUrl,
      });

      res.json({ preview });
    } catch (err: any) {
      res.status(400).json({
        error: err.message || 'Failed to pull profiles from Salesforce Org.',
      });
    }
  }
);

/**
 * POST /api/admin/profiles/pull-apply
 * Applies the selected profile additions/updates and deletes only the removed profiles chosen by the admin.
 */
adminRouter.post('/profiles/pull-apply', (req: Request, res: Response) => {
  const parsed = parseProfileSyncPayload(req.body);
  if (!parsed.ok) {
    recordProfileSyncFailure(req, parsed.error);
    res.status(400).json({ error: parsed.error });
    return;
  }

  const actor = getAdminInfo(req);
  let summary: ReturnType<typeof store.applyProfilesSyncFromOrg>;
  try {
    // The audit entry shares the transaction: an applied change can never go unlogged.
    summary = runInTransaction(() => {
      const applied = store.applyProfilesSyncFromOrg(parsed.value);
      store.recordPortalAdminLog({
        adminUsername: actor.username,
        authMethod: actor.authMethod,
        action: 'SYNC_PROFILES_FROM_ORG',
        target: SYNC_PROFILES_TARGET,
        details:
          `Synced Profiles from Salesforce Org (${applied.inserted} added, ${applied.updated} updated, ${applied.removed} removed, ${applied.keptMissing} missing profiles kept).` +
          namesClause('Synced', applied.affected.upserted, SYNCED_NAMES_LOGGED) +
          namesClause('Removed', applied.affected.removed) +
          namesClause('Kept as missing', applied.affected.keptMissing) +
          namesClause('Access Groups that lost a Profile', applied.affected.groupsLosingMembers) +
          namesClause('Stored ID upgraded to the 18-character form', applied.affected.idsUpgraded) +
          namesClause('Duplicate rows merged', applied.affected.duplicatesMerged) +
          namesClause('Access granted by merging duplicates', applied.affected.accessGranted) +
          namesClause('Duplicate rows left unchanged because their groups differ', applied.affected.duplicatesUnresolved),
        ipAddress: actor.ip,
        correlationId: actor.correlationId,
      });
      return applied;
    });
  } catch (err: any) {
    console.error('[admin] Profile sync apply failed:', err);
    recordProfileSyncFailure(req, String(err?.message || err));
    res.status(500).json({ error: 'The Profile sync failed, so nothing was changed. The reason is in the Portal Admin log.' });
    return;
  }

  res.json({
    summary,
    profiles: store.getProfiles(),
    profileGroupMappings: store.getProfileGroupMappings(),
  });
});

// ============================================================================
// 2. SALESFORCE -> OBJECTS (Import SFDX Folder, Local Disk Sync, Toggle On/Off)
// ============================================================================
/**
 * POST /api/admin/objects/import-sfdx-files
 * Receives XML files uploaded from the user's browser when they select their SFDX `objects/` folder
 */
adminRouter.post('/objects/import-sfdx-files', (req: Request, res: Response) => {
  const { files } = req.body || {};
  if (!Array.isArray(files) || files.length === 0) {
    res.status(400).json({
      error: 'No SFDX object/field XML files provided.',
    });
    return;
  }

  const parsed = parseSfdxFilesToObjects(files);
  if (parsed.length === 0) {
    res.status(400).json({
      error:
        'Could not find any .object-meta.xml, .field-meta.xml, or .object files in the selected folder.',
    });
    return;
  }

  const summary = store.importObjectsFromParsedSfdx(parsed);
  const actor = getAdminInfo(req);
  store.recordPortalAdminLog({
    adminUsername: actor.username,
    authMethod: actor.authMethod,
    action: 'IMPORT_SFDX_OBJECTS_FOLDER',
    target: 'Salesforce > Objects',
    details: `Imported ${summary.objectsImported} Salesforce Objects and ${summary.fieldsImported} Fields from uploaded SFDX objects folder.`,
    ipAddress: actor.ip,
    correlationId: actor.correlationId,
  });

  res.json({
    summary,
    objects: store.getObjects(),
  });
});

/**
 * POST /api/admin/objects/import-local-folder
 * Development only: reads a local SFDX `force-app/main/default/objects` directory path on the server.
 * Refused in production, where it would read any directory the server process can.
 */
adminRouter.post('/objects/import-local-folder', (req: Request, res: Response) => {
  if (config.isProd) {
    res.status(403).json({ error: 'Importing from a server folder is only available outside production.' });
    return;
  }
  const { folderPath } = req.body || {};
  if (!folderPath || typeof folderPath !== 'string') {
    res.status(400).json({
      error: 'A local folder path to your SFDX objects directory is required.',
    });
    return;
  }

  try {
    const summary = store.importObjectsFromLocalDiskFolder(folderPath);
    const actor = getAdminInfo(req);
    store.recordPortalAdminLog({
      adminUsername: actor.username,
      authMethod: actor.authMethod,
      action: 'SYNC_LOCAL_SFDX_FOLDER',
      target: summary.resolvedPath,
      details: `Synced ${summary.objectsImported} Objects and ${summary.fieldsImported} Fields from local SFDX directory "${summary.resolvedPath}".`,
      ipAddress: actor.ip,
      correlationId: actor.correlationId,
    });

    res.json({
      summary,
      objects: store.getObjects(),
    });
  } catch (err: any) {
    res.status(400).json({ error: err.message || 'Failed to read folder path.' });
  }
});

/**
 * POST /api/admin/objects
 * Manually create or update an object and its fields
 */
adminRouter.post('/objects', (req: Request, res: Response) => {
  const { objectName, label, fields } = req.body || {};
  if (!objectName) {
    res.status(400).json({ error: 'Object API Name is required.' });
    return;
  }

  let saved;
  try {
    saved = store.upsertObjectWithFields({
      objectName: store.resolveObjectName(String(objectName)),
      label: label ? String(label) : undefined,
      // The missing-in-org flag belongs to org sync, so a client cannot set or clear it here.
      fields: Array.isArray(fields) ? fields.map(({ missingInOrg: _ignored, ...field }) => field) : undefined,
    });
  } catch (err: any) {
    res.status(400).json({ error: err?.message || 'Invalid object.' });
    return;
  }

  const actor = getAdminInfo(req);
  store.recordPortalAdminLog({
    adminUsername: actor.username,
    authMethod: actor.authMethod,
    action: 'UPSERT_OBJECT',
    target: `Object: ${saved.objectName}`,
    details: `Saved Salesforce Object "${saved.objectName}" (${saved.fields.length} fields).`,
    ipAddress: actor.ip,
    correlationId: actor.correlationId,
    targetType: 'object',
    targetId: saved.objectName,
  });

  res.json({
    object: saved,
    objects: store.getObjects(),
  });
});

/**
 * PUT /api/admin/objects/:objectName/toggle
 */
adminRouter.put('/objects/:objectName/toggle', (req: Request, res: Response) => {
  const objectName = String(req.params.objectName);
  const { enabled } = req.body || {};
  const updated = store.toggleObject(objectName, Boolean(enabled));
  if (!updated) {
    res.status(404).json({ error: `Object '${objectName}' not found.` });
    return;
  }

  const actor = getAdminInfo(req);
  store.recordPortalAdminLog({
    adminUsername: actor.username,
    authMethod: actor.authMethod,
    action: 'TOGGLE_OBJECT',
    target: `Object: ${objectName}`,
    details: `Toggled Salesforce Object "${objectName}" ${
      updated.enabled ? 'ON (Enabled)' : 'OFF (Disabled)'
    }.`,
    ipAddress: actor.ip,
    correlationId: actor.correlationId,
    targetType: 'object',
    targetId: updated.objectName,
  });

  res.json({
    object: updated,
    objects: store.getObjects(),
  });
});

/**
 * PUT /api/admin/objects/:objectName/fields/:fieldName/toggle
 */
adminRouter.put(
  '/objects/:objectName/fields/:fieldName/toggle',
  (req: Request, res: Response) => {
    const objectName = String(req.params.objectName);
    const fieldName = String(req.params.fieldName);
    const { enabled } = req.body || {};
    const updated = store.toggleObjectField(
      objectName,
      fieldName,
      Boolean(enabled)
    );
    if (!updated) {
      res.status(404).json({ error: `Field '${fieldName}' on object '${objectName}' not found.` });
      return;
    }

    const actor = getAdminInfo(req);
    store.recordPortalAdminLog({
      adminUsername: actor.username,
      authMethod: actor.authMethod,
      action: 'TOGGLE_FIELD',
      target: `${objectName}.${fieldName}`,
      details: `Toggled field "${objectName}.${fieldName}" ${
        enabled ? 'ON (Enabled)' : 'OFF (Disabled)'
      }.`,
      ipAddress: actor.ip,
      correlationId: actor.correlationId,
      targetType: 'field',
      targetId: `${objectName}.${fieldName}`,
    });

    res.json({
      object: updated,
      objects: store.getObjects(),
    });
  }
);

adminRouter.put(
  '/objects/:objectName/fields/bulk',
  (req: Request, res: Response) => {
    const objectName = String(req.params.objectName);
    const { enabled } = req.body || {};
    const targetObj = store
      .getObjects()
      .find((o) => o.objectName === objectName);
    if (!targetObj) {
      res.status(404).json({ error: `Object '${objectName}' not found.` });
      return;
    }

    // One transaction, so every field changes or none does, as one policy revision.
    runInTransaction(() => {
      for (const f of targetObj.fields) {
        store.toggleObjectField(objectName, f.fieldName, Boolean(enabled));
      }
    });

    const actor = getAdminInfo(req);
    store.recordPortalAdminLog({
      adminUsername: actor.username,
      authMethod: actor.authMethod,
      action: 'BULK_TOGGLE_FIELDS',
      target: `Object: ${objectName}`,
      details: `Toggled all ${targetObj.fields.length} fields on "${objectName}" ${
        enabled ? 'ON (Enabled)' : 'OFF (Disabled)'
      }.`,
      ipAddress: actor.ip,
      correlationId: actor.correlationId,
      targetType: 'object',
      targetId: targetObj.objectName,
    });

    res.json({
      objects: store.getObjects(),
    });
  }
);

adminRouter.delete(
  '/objects/:objectName/fields/:fieldName',
  (req: Request, res: Response) => {
    const objectName = String(req.params.objectName);
    const fieldName = String(req.params.fieldName);
    const updated = store.deleteObjectField(objectName, fieldName);
    if (!updated) {
      res.status(404).json({ error: `Field '${objectName}.${fieldName}' not found.` });
      return;
    }

    const actor = getAdminInfo(req);
    store.recordPortalAdminLog({
      adminUsername: actor.username,
      authMethod: actor.authMethod,
      action: 'DELETE_FIELD',
      target: `${objectName}.${fieldName}`,
      details: `Deleted field "${objectName}.${fieldName}" from MCP Server object schema.`,
      ipAddress: actor.ip,
      correlationId: actor.correlationId,
      targetType: 'field',
      targetId: `${objectName}.${fieldName}`,
    });

    res.json({
      object: updated,
      objects: store.getObjects(),
    });
  }
);

adminRouter.delete('/objects/:objectName', (req: Request, res: Response) => {
  const objectName = String(req.params.objectName);
  const revokedFrom = store
    .getGroups()
    .filter((g) => g.objectPermissions.some((p) => String(p.objectName).toLowerCase() === objectName.toLowerCase()));
  const deleted = store.deleteObject(objectName);
  if (!deleted) {
    res.status(404).json({ error: `Object '${objectName}' not found.` });
    return;
  }

  const actor = getAdminInfo(req);
  store.recordPortalAdminLog({
    adminUsername: actor.username,
    authMethod: actor.authMethod,
    action: 'DELETE_OBJECT',
    target: `Object: ${objectName}`,
    details: `Deleted Salesforce Object "${objectName}" and its fields from the MCP Server${
      revokedFrom.length > 0
        ? ` and revoked it from ${revokedFrom.length} Access Group(s): ${revokedFrom.map((g) => g.name).join(', ')}`
        : ''
    }.`,
    ipAddress: actor.ip,
    correlationId: actor.correlationId,
    targetType: 'object',
    targetId: objectName,
  });

  res.json({ objects: store.getObjects() });
});

/**
 * GET /api/admin/objects/org-catalog
 * Returns the catalog of Objects available in the connected Salesforce Org so the admin can pick which to pull.
 */
adminRouter.get(
  '/objects/org-catalog',
  async (_req: Request, res: Response) => {
    try {
      const session = await getActiveSalesforceOrgSession();
      const catalog = await fetchOrgObjectsCatalog(session);
      res.json({
        orgId: session.orgId,
        instanceUrl: session.instanceUrl,
        catalog,
      });
    } catch (err: any) {
      res.status(400).json({
        error:
          err.message ||
          'Failed to fetch Objects catalog from Salesforce Org.',
      });
    }
  }
);

/**
 * POST /api/admin/objects/pull-preview
 * Pulls live Object & Field metadata from the connected Salesforce Org for the requested objects
 * (plus any currently tracked objects if `includeTracked` is true) and computes the reconciliation diff.
 */
adminRouter.post(
  '/objects/pull-preview',
  async (req: Request, res: Response) => {
    try {
      const session = await getActiveSalesforceOrgSession();
      const {
        objectNames,
        includeTracked = true,
        simulateRemovedObjects,
        simulateRemovedFields,
      } = req.body || {};

      const trackedNames = store.getObjects().map((o) => o.objectName);
      const requestedNames: string[] = Array.isArray(objectNames)
        ? objectNames.map(String)
        : [];
      const combinedNames = Array.from(
        new Set([
          ...requestedNames,
          ...(includeTracked ? trackedNames : []),
        ])
      );

      if (combinedNames.length === 0) {
        res.status(400).json({
          error:
            'Select at least one Salesforce Object to pull from the org.',
        });
        return;
      }

      let pulledMetadata = await fetchObjectsMetadataFromOrgSession(
        session,
        combinedNames
      );

      // Support optional simulated removals when testing in Simulated Org mode
      if (session.authMode === 'simulated') {
        if (Array.isArray(simulateRemovedObjects)) {
          const remObjSet = new Set(
            simulateRemovedObjects.map((s: any) => String(s).toLowerCase())
          );
          pulledMetadata = pulledMetadata.map((m) =>
            remObjSet.has(m.objectName.toLowerCase())
              ? { ...m, existsInOrg: false, fields: [] }
              : m
          );
        }
        if (Array.isArray(simulateRemovedFields)) {
          const remFieldSet = new Set(
            simulateRemovedFields.map((s: any) => String(s).toLowerCase())
          );
          pulledMetadata = pulledMetadata.map((m) => ({
            ...m,
            fields: m.fields.filter(
              (f) =>
                !remFieldSet.has(
                  `${m.objectName.toLowerCase()}.${f.fieldName.toLowerCase()}`
                )
            ),
          }));
        }
      }

      const preview = store.previewObjectsSyncFromOrg(pulledMetadata, {
        orgId: session.orgId,
        instanceUrl: session.instanceUrl,
      });

      res.json({
        preview,
        pulledMetadata,
      });
    } catch (err: any) {
      res.status(400).json({
        error:
          err.message ||
          'Failed to pull Object & Field metadata from Salesforce Org.',
      });
    }
  }
);

/**
 * POST /api/admin/objects/pull-apply
 * Applies the Object & Field sync from Salesforce Org, removing ONLY the objects and fields
 * that the admin explicitly checked for removal.
 */
adminRouter.post('/objects/pull-apply', (req: Request, res: Response) => {
  const parsed = parseObjectSyncPayload(req.body);
  if (!parsed.ok) {
    recordObjectSyncFailure(req, parsed.error);
    res.status(400).json({ error: parsed.error });
    return;
  }

  const actor = getAdminInfo(req);
  let summary: ReturnType<typeof store.applyObjectsSyncFromOrg>;
  try {
    // The audit entry shares the transaction: an applied change can never go unlogged.
    summary = runInTransaction(() => {
      const applied = store.applyObjectsSyncFromOrg(parsed.value);
      store.recordPortalAdminLog({
        adminUsername: actor.username,
        authMethod: actor.authMethod,
        action: 'SYNC_OBJECTS_FROM_ORG',
        target: SYNC_OBJECTS_TARGET,
        // Only the routine list is capped: what was removed changes access and is bounded by local rows.
        details:
          `Synced Objects from Salesforce Org (${applied.objectsUpserted} objects/${applied.fieldsUpserted} fields synced; ${applied.objectsRemoved} objects & ${applied.fieldsRemoved} fields removed; ${applied.objectsKeptMissing} objects & ${applied.fieldsKeptMissing} fields kept).` +
          namesClause('Synced', applied.affected.objectsSynced, SYNCED_NAMES_LOGGED) +
          namesClause('Removed objects', applied.affected.objectsRemoved) +
          namesClause('Removed fields', applied.affected.fieldsRemoved) +
          namesClause('Kept as missing', [...applied.affected.objectsKeptMissing, ...applied.affected.fieldsKeptMissing]) +
          namesClause('Access Groups that lost grants', applied.affected.groupsLosingGrants),
        ipAddress: actor.ip,
        correlationId: actor.correlationId,
      });
      return applied;
    });
  } catch (err: any) {
    console.error('[admin] Object sync apply failed:', err);
    recordObjectSyncFailure(req, String(err?.message || err));
    res.status(500).json({ error: 'The Object sync failed, so nothing was changed. The reason is in the Portal Admin log.' });
    return;
  }

  res.json({
    summary,
    objects: store.getObjects(),
  });
});

// ============================================================================
// 3. ACCESS MATRIX -> GROUPS & PROFILE-GROUP MATRIX
// ============================================================================
/**
 * POST /api/admin/groups
 * Creates a group (no id) or updates the group with `id` (404 when there is none). The grants are
 * checked against Salesforce > Objects and stored in the catalog's spelling (see groupPayload.ts).
 * An update that sends `expectedVersion` is refused with 409 when the group has changed since, so a
 * stale editor cannot undo a change it never saw. That check comes before the grants are checked:
 * deleting an Object or field revokes it from its groups (a new version), and the draft of an editor
 * that loaded the group earlier still names it, which must read as the reload 409, not a 400.
 */
adminRouter.post('/groups', (req: Request, res: Response) => {
  const parsed = parseGroupSaveRequest(req.body || {});
  if (!parsed.ok) {
    res.status(400).json({ error: parsed.error });
    return;
  }
  const request = parsed.value;

  const actor = getAdminInfo(req);
  let outcome: { saved: AccessGroup } | { status: 400 | 404 | 409; body: Record<string, unknown> };
  try {
    // The checks against the stored groups, the change and its audit entry share one transaction:
    // a saved group can never go unlogged, nor be saved over a version the client did not load.
    outcome = runInTransaction(() => {
      const groups = store.getGroups();
      const before = request.id ? groups.find((g) => g.id === request.id) : undefined;
      if (request.id && !before) {
        return { status: 404 as const, body: { error: 'Group not found.' } };
      }
      if (before && request.expectedVersion !== undefined && request.expectedVersion !== before.version) {
        return {
          status: 409 as const,
          body: {
            error: `Access Group "${before.name}" changed since it was loaded, so nothing was saved. Reload it and try again.`,
            group: before,
          },
        };
      }
      const grants = parseGroupObjectPermissions(request.objectPermissions);
      if (!grants.ok) {
        return { status: 400 as const, body: { error: grants.error } };
      }
      // Names are unique ignoring case. A group that keeps its own name may still share it with a
      // case variant an older version allowed, so that neither becomes impossible to save.
      const nameTaken =
        before?.name !== request.name &&
        groups.some((g) => g.id !== before?.id && g.name.toLowerCase() === request.name.toLowerCase());
      if (nameTaken) {
        return { status: 409 as const, body: { error: `An Access Group named "${request.name}" already exists.` } };
      }

      const group = store.upsertGroup({
        id: before?.id,
        name: request.name,
        description: request.description,
        allowedActions: request.allowedActions,
        objectPermissions: grants.value,
      });
      store.recordPortalAdminLog({
        adminUsername: actor.username,
        authMethod: actor.authMethod,
        action: before ? 'UPDATE_GROUP' : 'CREATE_GROUP',
        target: `Group: ${group.name}`,
        details: `${before ? 'Updated' : 'Created'} Access Group "${
          group.name
        }" (${group.allowedActions.length} MCP actions, ${
          group.objectPermissions.length
        } objects configured).`,
        ipAddress: actor.ip,
        correlationId: actor.correlationId,
        targetType: 'group',
        targetId: group.id,
        diff: before ? groupUpdateDiff(before, group) : { after: groupAuditFields(group) },
      });
      return { saved: group };
    });
  } catch (err: any) {
    if (/UNIQUE constraint failed: access_groups\.name/.test(String(err?.message))) {
      res.status(409).json({ error: `An Access Group named "${request.name}" already exists.` });
      return;
    }
    throw err;
  }

  if ('status' in outcome) {
    res.status(outcome.status).json(outcome.body);
    return;
  }
  res.json({
    group: outcome.saved,
    groups: store.getGroups(),
  });
});

adminRouter.delete('/groups/:id', (req: Request, res: Response) => {
  const id = String(req.params.id);
  const actor = getAdminInfo(req);
  // The delete and its audit entry share one transaction: a deleted group can never go unlogged.
  const deleted = runInTransaction(() => {
    const existing = store.getGroups().find((g) => g.id === id);
    if (!existing) return false;
    // Deleting the group also ends its memberships (ON DELETE CASCADE), so the diff names those Profiles.
    const profileIds = store
      .getProfileGroupMappings()
      .filter((m) => m.groupIds.includes(id))
      .map((m) => m.profileId);
    if (!store.deleteGroup(id)) return false;
    store.recordPortalAdminLog({
      adminUsername: actor.username,
      authMethod: actor.authMethod,
      action: 'DELETE_GROUP',
      target: `Group: ${existing.name}`,
      details: `Deleted Access Group "${existing.name}".`,
      ipAddress: actor.ip,
      correlationId: actor.correlationId,
      targetType: 'group',
      targetId: id,
      diff: { before: { ...groupAuditFields(existing), profileIds } },
    });
    return true;
  });
  if (!deleted) {
    res.status(404).json({ error: 'Group not found.' });
    return;
  }

  res.json({
    groups: store.getGroups(),
    profileGroupMappings: store.getProfileGroupMappings(),
  });
});

const MEMBERSHIP_NAMES_LOGGED = 50;

const isIdList = (value: unknown): value is string[] =>
  Array.isArray(value) && value.every((id) => typeof id === 'string');

/** Reads `{ add, remove }`: either may be left out, but not both. */
function parseMembershipDelta(body: Record<string, any>, missing: string): PayloadResult<MembershipDelta> {
  const { add, remove } = body;
  if (add === undefined && remove === undefined) return { ok: false, error: missing };
  if (add !== undefined && !isIdList(add)) return { ok: false, error: 'add must be an array of ids.' };
  if (remove !== undefined && !isIdList(remove)) return { ok: false, error: 'remove must be an array of ids.' };
  return { ok: true, value: { add: add ?? [], remove: remove ?? [] } };
}

type ProfileGroupsRequest = { delta: MembershipDelta } | { groupIds: string[]; expectedGroupIds: string[] };

/** Reads the PUT body: `{ add, remove }`, or a full replacement `{ groupIds, expectedGroupIds }`. */
function parseProfileGroupsRequest(body: Record<string, any>): PayloadResult<ProfileGroupsRequest> {
  if (body.groupIds === undefined) {
    const delta = parseMembershipDelta(body, 'Send { add, remove } or { groupIds, expectedGroupIds }.');
    return delta.ok ? { ok: true, value: { delta: delta.value } } : delta;
  }
  if (body.add !== undefined || body.remove !== undefined) {
    return { ok: false, error: 'Send either { add, remove } or { groupIds, expectedGroupIds }, not both.' };
  }
  if (!isIdList(body.groupIds)) return { ok: false, error: 'groupIds must be an array of group ids.' };
  if (!isIdList(body.expectedGroupIds)) {
    return {
      ok: false,
      error:
        'A full replacement needs expectedGroupIds, the group ids it was built from. Use { add, remove } to change single memberships.',
    };
  }
  return { ok: true, value: { groupIds: body.groupIds, expectedGroupIds: body.expectedGroupIds } };
}

const sameIdSet = (a: string[], b: string[]) => {
  const left = new Set(a);
  const right = new Set(b);
  return left.size === right.size && [...left].every((id) => right.has(id));
};

/** The audit text for what a membership request changed, which may be nothing. */
function membershipChangeClauses(added: string[], removed: string[]): string {
  if (added.length === 0 && removed.length === 0) return ' Nothing changed.';
  return (
    namesClause('Added', added, MEMBERSHIP_NAMES_LOGGED) + namesClause('Removed', removed, MEMBERSHIP_NAMES_LOGGED)
  );
}

/**
 * PUT /api/admin/profile-groups/:profileId
 * Changes the Groups mapped to a Salesforce Profile. `{ add, remove }` changes only the memberships it
 * names. A full replacement `{ groupIds }` must carry the `expectedGroupIds` it was built from and is
 * refused with 409 if the stored groups differ, so a stale screen cannot re-grant a revoked group.
 */
adminRouter.put(
  '/profile-groups/:profileId',
  (req: Request, res: Response) => {
    const profileId = String(req.params.profileId);
    const parsed = parseProfileGroupsRequest(req.body || {});
    if (!parsed.ok) {
      res.status(400).json({ error: parsed.error });
      return;
    }

    const profile = store.getProfileById(profileId);
    if (!profile) {
      res.status(404).json({ error: `Profile '${profileId}' not found.` });
      return;
    }

    const request = parsed.value;
    const actor = getAdminInfo(req);
    let outcome: ReturnType<typeof store.applyMembershipDelta> | { conflict: string[] };
    try {
      // The check against the stored groups, the change and its audit entry share one transaction.
      outcome = runInTransaction(() => {
        let delta: MembershipDelta;
        if ('delta' in request) {
          delta = request.delta;
        } else {
          const stored = store.getProfileGroupIds(profile.id);
          if (!sameIdSet(stored, request.expectedGroupIds)) return { conflict: stored };
          delta = {
            add: request.groupIds.filter((gid) => !stored.includes(gid)),
            remove: stored.filter((gid) => !request.groupIds.includes(gid)),
          };
        }
        const change = store.applyMembershipDelta(profile.id, delta);
        const allGroups = store.getGroups();
        const groupName = (gid: string) => allGroups.find((g) => g.id === gid)?.name || gid;
        const groupNames = change.mapping.groupIds.map(groupName);
        store.recordPortalAdminLog({
          adminUsername: actor.username,
          authMethod: actor.authMethod,
          action: 'UPDATE_PROFILE_GROUPS',
          target: `Profile: ${profile.name} (${profile.id})`,
          details:
            `Mapped Profile "${profile.name}" to Groups: [${
              groupNames.length > 0 ? groupNames.join(', ') : 'None'
            }].` + membershipChangeClauses(change.added.map(groupName), change.removed.map(groupName)),
          ipAddress: actor.ip,
          correlationId: actor.correlationId,
          targetType: 'profile',
          targetId: profile.id,
          diff: { added: change.added, removed: change.removed },
        });
        return change;
      });
    } catch (err: any) {
      if (!(err instanceof MembershipChangeError)) throw err;
      res.status(400).json({ error: err.message });
      return;
    }

    if ('conflict' in outcome) {
      res.status(409).json({
        error: `The Groups of Profile "${profile.name}" changed since this list was loaded, so nothing was saved. Reload and try again.`,
        mapping: { profileId: profile.id, groupIds: outcome.conflict },
      });
      return;
    }
    res.json({
      mapping: outcome.mapping,
      profileGroupMappings: store.getProfileGroupMappings(),
    });
  }
);

/**
 * POST /api/admin/groups/:id/profiles
 * Adds Profiles to and removes Profiles from one Access Group (`{ add, remove }`, Profile ids). Every
 * other membership stays as it is.
 */
adminRouter.post('/groups/:id/profiles', (req: Request, res: Response) => {
  const id = String(req.params.id);
  const parsed = parseMembershipDelta(req.body || {}, 'Send { add, remove } with Profile ids.');
  if (!parsed.ok) {
    res.status(400).json({ error: parsed.error });
    return;
  }

  const group = store.getGroups().find((g) => g.id === id);
  if (!group) {
    res.status(404).json({ error: 'Group not found.' });
    return;
  }

  const actor = getAdminInfo(req);
  let change: ReturnType<typeof store.applyGroupMembershipDelta>;
  try {
    change = runInTransaction(() => {
      const applied = store.applyGroupMembershipDelta(group.id, parsed.value);
      const profileNames = new Map(store.getProfiles().map((p) => [p.id, p.name]));
      const profileLabel = (pid: string) => `${profileNames.get(pid) || pid} (${pid})`;
      const count = applied.membership.profileIds.length;
      store.recordPortalAdminLog({
        adminUsername: actor.username,
        authMethod: actor.authMethod,
        action: 'UPDATE_PROFILE_GROUPS',
        target: `Group: ${group.name}`,
        details:
          `Access Group "${group.name}" is mapped to ${count} Profile${count === 1 ? '' : 's'}.` +
          membershipChangeClauses(applied.added.map(profileLabel), applied.removed.map(profileLabel)),
        ipAddress: actor.ip,
        correlationId: actor.correlationId,
        targetType: 'group',
        targetId: group.id,
        diff: { added: applied.added, removed: applied.removed },
      });
      return applied;
    });
  } catch (err: any) {
    if (!(err instanceof MembershipChangeError)) throw err;
    res.status(400).json({ error: err.message });
    return;
  }

  res.json({
    membership: change.membership,
    profileGroupMappings: store.getProfileGroupMappings(),
  });
});

// ============================================================================
// 4. SETTINGS (Okta SSO, Salesforce Connection, Portal Users, Test MCP Call)
// ============================================================================
adminRouter.put('/okta', (req: Request, res: Response) => {
  if (config.isProd) {
    const insecure = insecureOktaUrlError(req.body || {});
    if (insecure) {
      res.status(400).json({ error: insecure });
      return;
    }
  }
  const updated = store.updateOktaConfig(req.body || {});
  const actor = getAdminInfo(req);
  store.recordPortalAdminLog({
    adminUsername: actor.username,
    authMethod: actor.authMethod,
    action: 'UPDATE_OKTA_SSO',
    target: `Okta SSO (${updated.oktaDomain || 'Disabled'})`,
    details: `Updated Okta SSO configuration (Enabled: ${updated.enabled}, Domain: ${updated.oktaDomain}).`,
    ipAddress: actor.ip,
    correlationId: actor.correlationId,
    targetType: 'settings',
    targetId: 'okta',
  });
  res.json({ oktaSettings: updated });
});

adminRouter.put('/sf-settings', (req: Request, res: Response) => {
  let input: SalesforceSettingsInput;
  try {
    input = parseSalesforceSettingsInput(req.body || {});
  } catch (err: any) {
    res.status(400).json({ error: err?.message || 'Invalid Salesforce settings.' });
    return;
  }

  let saved;
  try {
    saved = saveSalesforceSettings(input);
  } catch (err: any) {
    // e.g. a private key that cannot be parsed
    res.status(400).json({ error: err?.message || 'Invalid Salesforce settings.' });
    return;
  }
  const { updated } = saved;
  const actor = getAdminInfo(req);
  store.recordPortalAdminLog({
    adminUsername: actor.username,
    authMethod: actor.authMethod,
    action: 'UPDATE_SF_SETTINGS',
    target: 'Salesforce Org Connection',
    details: `Updated Salesforce Org connection settings (Mode: ${updated.authMode}, Login URL: ${updated.loginUrl}, User: ${updated.username || 'Not set'}, OrgId: ${updated.expectedOrgId || 'Any'}, Instance: ${updated.instanceUrl}). ${auditChanges(saved.before, updated, saved.privateKeyReplaced)}`,
    ipAddress: actor.ip,
    correlationId: actor.correlationId,
    targetType: 'settings',
    targetId: 'salesforce_connection',
  });
  res.json({ sfSettings: updated });
});

/**
 * POST /api/admin/sf-settings/generate-cert
 * Generates a 2048-bit RSA Private Key + self-signed X.509 Certificate (.crt) for Salesforce Connected App JWT flow.
 */
adminRouter.post('/sf-settings/generate-cert', (req: Request, res: Response) => {
  try {
    const { commonName, confirmReplaceUndecryptableKey } = req.body || {};
    const actor = getAdminInfo(req);
    const current = store.getSalesforceSettings();
    // Restoring APP_SECRET_KEY can still recover this key until it is overwritten, so the portal's
    // warning is not enough: only a caller that says it knows may destroy it.
    const replacesUndecryptableKey = current.privateKeyUndecryptable;
    if (replacesUndecryptableKey && confirmReplaceUndecryptableKey !== true) {
      store.recordPortalAdminLog({
        adminUsername: actor.username,
        authMethod: actor.authMethod,
        action: 'GENERATE_SF_JWT_CERT_DENIED',
        target: 'Salesforce JWT Certificate',
        details: 'Refused to overwrite a stored private key that cannot be decrypted: the request did not confirm it.',
        ipAddress: actor.ip,
        correlationId: actor.correlationId,
        targetType: 'settings',
        targetId: 'salesforce_connection',
      });
      res.status(409).json({
        error:
          'The stored private key cannot be decrypted with the current APP_SECRET_KEY. Restoring that key could recover it, and generating a new one destroys it. Set confirmReplaceUndecryptableKey to replace it anyway.',
        sfSettings: current,
      });
      return;
    }
    const bundle = generateSelfSignedCertificateBundle(
      commonName ? String(commonName) : 'Salesforce MCP Metadata Sync'
    );
    const { before, updated, privateKeyReplaced } = saveSalesforceSettings({
      privateKeyPem: bundle.privateKeyPem,
      certificatePem: bundle.certificatePem,
      certFingerprint: bundle.fingerprintSha256,
    });

    store.recordPortalAdminLog({
      adminUsername: actor.username,
      authMethod: actor.authMethod,
      action: 'GENERATE_SF_JWT_CERT',
      target: 'Salesforce JWT Certificate',
      details: `Generated new 2048-bit RSA Private Key & X.509 Certificate (SHA-256: ${bundle.fingerprintSha256.slice(0, 23)}...) for Salesforce Connected App. ${auditChanges(before, updated, privateKeyReplaced)} undecryptableKeyDestroyed: ${replacesUndecryptableKey}.`,
      ipAddress: actor.ip,
      correlationId: actor.correlationId,
      targetType: 'settings',
      targetId: 'salesforce_connection',
    });

    res.json({
      sfSettings: updated,
      certificatePem: bundle.certificatePem,
      fingerprintSha256: bundle.fingerprintSha256,
      validTo: bundle.validTo,
    });
  } catch (err: any) {
    res.status(400).json({
      error: err.message || 'Failed to generate X.509 certificate.',
    });
  }
});

/**
 * POST /api/admin/sf-settings/connect
 * Verifies the stored settings with any changes from the request over OAuth 2.0 JWT Bearer, and saves
 * those changes only if that succeeds, so a failed attempt leaves a working key and settings in place.
 */
adminRouter.post(
  '/sf-settings/connect',
  asyncRoute(async (req: Request, res: Response) => {
    const actor = getAdminInfo(req);
    const logFailure = (errMsg: string, changes: string) =>
      store.recordPortalAdminLog({
        adminUsername: actor.username,
        authMethod: actor.authMethod,
        action: 'CONNECT_SALESFORCE_ORG_FAILED',
        target: 'Salesforce Org Connection',
        details: `Salesforce JWT connection failed: ${errMsg} ${changes}`,
        ipAddress: actor.ip,
        correlationId: actor.correlationId,
        targetType: 'settings',
        targetId: 'salesforce_connection',
      });

    let input: SalesforceSettingsInput;
    try {
      // instance_url is MCP's token host. A request cannot set it here: the store decides from the session.
      const { instanceUrl: _mcpHost, ...parsed } = parseSalesforceSettingsInput(req.body || {});
      input = parsed;
      if (input.privateKeyPem?.trim()) {
        input.privateKeyPem = validatePrivateKeyPem(input.privateKeyPem);
      }
    } catch (err: any) {
      // A bad request says nothing about the org, so the connection status stays as it was.
      const errMsg = err?.message || 'Invalid Salesforce settings.';
      const current = store.getSalesforceSettings();
      logFailure(errMsg, auditChanges(current, current, false));
      res.status(400).json({ error: errMsg, sfSettings: current });
      return;
    }

    const stored = store.getSalesforceSettingsWithSecrets();
    const replacesKey = Boolean(input.privateKeyPem?.trim());
    try {
      const session = await connectToSalesforceOrgViaJwt({
        ...stored,
        ...input,
        privateKeyPem: replacesKey ? (input.privateKeyPem as string) : stored.privateKeyPem,
        privateKeyUndecryptable: replacesKey ? false : stored.privateKeyUndecryptable,
      });

      // A save made during the exchange was not what got verified.
      if (store.getSalesforceSettings().updatedAt !== stored.updatedAt) {
        throw new Error('Salesforce settings changed while connecting. Connect again to verify them.');
      }
      const updated = store.saveVerifiedSalesforceConnection(input, session);
      const privateKeyReplaced = replacesKey && input.privateKeyPem !== stored.privateKeyPem;

      store.recordPortalAdminLog({
        adminUsername: actor.username,
        authMethod: actor.authMethod,
        action: 'CONNECT_SALESFORCE_ORG',
        target: `Salesforce Org (${session.orgId})`,
        details: `Connected to Salesforce Org "${session.orgId}" at ${session.instanceUrl} as "${session.username}" via ${
          session.authMode === 'simulated'
            ? 'Simulated JWT Org'
            : 'OAuth 2.0 JWT Bearer'
        }. ${auditChanges(stored, updated, privateKeyReplaced)}`,
        ipAddress: actor.ip,
        correlationId: actor.correlationId,
        targetType: 'settings',
        targetId: 'salesforce_connection',
      });

      res.json({
        connected: true,
        sfSettings: updated,
      });
    } catch (err: any) {
      const errMsg = err.message || 'Failed to connect to Salesforce Org.';
      // With a stored key that cannot be decrypted nothing was tried, so this is no verdict on the
      // submitted settings. They are saved for the retry once APP_SECRET_KEY is restored; the key stays.
      const unverifiable = stored.privateKeyUndecryptable && !replacesKey;
      if (unverifiable) saveSalesforceSettings(input);
      const updated = store.updateSalesforceSettings({
        connectionStatus: 'error',
        lastError: errMsg,
      });

      // What the admin tried is part of the record, separately from what actually changed.
      const attempted = unverifiable
        ? '{}'
        : auditDiff(stored, {
            ...stored,
            ...input,
            clientId: (input.clientId ?? stored.clientId).trim(),
            username: (input.username ?? stored.username).trim(),
            certFingerprint:
              (input.certificatePem && inspectCertificatePem(input.certificatePem.trim())?.fingerprintSha256) ||
              stored.certFingerprint,
          });
      logFailure(
        errMsg,
        `${auditChanges(stored, updated, false)} Not saved: ${attempted}. privateKeySubmitted: ${replacesKey}.`
      );

      res.status(400).json({
        error: errMsg,
        sfSettings: updated,
      });
    }
  })
);

/**
 * POST /api/admin/sf-settings/disconnect
 * Disconnects the active Salesforce Org metadata connection.
 */
adminRouter.post('/sf-settings/disconnect', (req: Request, res: Response) => {
  const updated = store.updateSalesforceSettings({ ...NO_CONNECTED_ORG, connectionStatus: 'disconnected' });

  const actor = getAdminInfo(req);
  store.recordPortalAdminLog({
    adminUsername: actor.username,
    authMethod: actor.authMethod,
    action: 'DISCONNECT_SALESFORCE_ORG',
    target: 'Salesforce Org Connection',
    details: 'Disconnected Salesforce Org metadata sync connection.',
    ipAddress: actor.ip,
    correlationId: actor.correlationId,
    targetType: 'settings',
    targetId: 'salesforce_connection',
  });

  res.json({ sfSettings: updated });
});

adminRouter.post('/portal-users', (req: Request, res: Response) => {
  const { username, displayName, password, role } = req.body || {};
  if (!username || !password) {
    res.status(400).json({ error: 'Username and password are required.' });
    return;
  }
  // Startup refuses a production database holding a publicly known password, so one saved here
  // would stop the next boot.
  const newPassword = String(password);
  if (newPassword.length < PORTAL_PASSWORD_MIN_LENGTH) {
    res.status(400).json({ error: `The password must be at least ${PORTAL_PASSWORD_MIN_LENGTH} characters.` });
    return;
  }
  if (config.isProd && KNOWN_DEFAULT_PASSWORDS.includes(newPassword)) {
    res.status(400).json({ error: 'That password is publicly known and cannot be used in production.' });
    return;
  }

  const saved = store.upsertPortalUser({
    username: String(username),
    displayName: displayName ? String(displayName) : undefined,
    password: newPassword,
    role: role ? String(role) : undefined,
  });

  const actor = getAdminInfo(req);
  store.recordPortalAdminLog({
    adminUsername: actor.username,
    authMethod: actor.authMethod,
    action: 'UPSERT_PORTAL_USER',
    target: `Portal User: ${saved.username}`,
    details: `Created or updated portal administrator "${saved.username}" (${saved.role}).`,
    ipAddress: actor.ip,
    correlationId: actor.correlationId,
    targetType: 'portal_user',
    targetId: saved.username,
  });

  res.json({ portalUsers: store.getPortalUsers() });
});

adminRouter.delete('/portal-users/:username', (req: Request, res: Response) => {
  const username = String(req.params.username);
  try {
    // The row is filed under the stored username, as the create was, whatever spelling the URL used.
    const storedUsername = store.findPortalUsername(username);
    if (storedUsername === undefined || !store.deletePortalUser(storedUsername)) {
      res.status(404).json({ error: `Portal user '${username}' not found.` });
      return;
    }
    const actor = getAdminInfo(req);
    store.recordPortalAdminLog({
      adminUsername: actor.username,
      authMethod: actor.authMethod,
      action: 'DELETE_PORTAL_USER',
      target: `Portal User: ${username}`,
      details: `Deleted portal user "${username}".`,
      ipAddress: actor.ip,
      correlationId: actor.correlationId,
      targetType: 'portal_user',
      targetId: storedUsername,
    });
    res.json({ portalUsers: store.getPortalUsers() });
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
});

/**
 * POST /api/admin/test-mcp-access
 * Allows testing what a given Profile ID can do based on its current Profile Group Matrix
 */
adminRouter.post('/test-mcp-access', async (req: Request, res: Response) => {
  try {
    await runMcpAccessSimulation(req, res);
  } catch (err: any) {
    res.status(400).json({ error: err?.message || 'Simulation failed.' });
  }
});

async function runMcpAccessSimulation(req: Request, res: Response): Promise<void> {
  const { profileId, toolName, targetObject, samplePayload, username } =
    req.body || {};
  const profile = store.getProfileById(String(profileId || ''));
  const simToken = createSimulatorToken({
    profileId: String(profileId || ''),
    profileName: profile?.name || String(profileId || ''),
    username: username ? String(username) : undefined,
  });

  const user = await resolveSalesforceUserFromToken(simToken);
  const snapshot = loadPolicySnapshot();
  const effective = resolveEffectiveProfilePermissions(
    user.profileId,
    user.profileName,
    snapshot
  );
  // A sample payload is evaluated as the call's arguments, so the field, WHERE and argument checks
  // apply as on /mcp. Without one, only the tool and the Object are checked. The Object is targetObject
  // when it is given, whatever the payload names, so the logged target is always the one decided on;
  // the payload's objectName counts only without one.
  const simulatedTool = String(toolName || 'list_enabled_objects');
  const hasSamplePayload = Boolean(samplePayload && typeof samplePayload === 'object' && !Array.isArray(samplePayload));
  const args: Record<string, unknown> = {
    ...(hasSamplePayload ? samplePayload : {}),
    ...(targetObject ? { objectName: String(targetObject) } : {}),
  };
  const simulatedTarget = targetObjectArgument(args);
  const decision = hasSamplePayload
    ? evaluatePolicy(user, simulatedTool, args, snapshot)
    : evaluateToolAccess(user, simulatedTool, targetObject ? String(targetObject) : undefined, snapshot);
  const { decision: _decision, ...evaluation } = policyEvaluationResult(decision);
  const status = decisionLogStatus(decision);

  // Also record this test call into the Copilot MCP log (with sensitive data stripped!)
  store.recordCopilotMcpLog({
    simulated: true,
    sfUsername: user.username,
    profileId: user.profileId,
    profileName: effective.profileName,
    matchedGroups: evaluation.matchedGroups,
    toolName: simulatedTool,
    targetObject: simulatedTarget,
    status,
    latencyMs: Math.floor(18 + Math.random() * 65),
    rawRequestPayload: samplePayload || {
      objectName: targetObject || '*',
      tool: toolName,
    },
    rawResponseSummary: {
      permitted: evaluation.permitted,
      reason: evaluation.reason,
      allowedFields: evaluation.allowedFields,
    },
  });

  // The MCP row only shows the simulated name, so this row is what ties it to the acting admin.
  const actor = getAdminInfo(req);
  store.recordPortalAdminLog({
    adminUsername: actor.username,
    authMethod: actor.authMethod,
    action: SIMULATE_MCP_CALL_ACTION,
    target: `Profile: ${effective.profileName} (${effective.profileId})`,
    details: `Simulated ${simulatedTool} on ${simulatedTarget} as "${user.username}": ${status}.${config.isProd ? '' : ' A 15-minute simulator token was issued.'}`,
    ipAddress: actor.ip,
    correlationId: actor.correlationId,
  });

  res.json({
    // /mcp refuses simulator tokens in production, so none is handed out there.
    ...(config.isProd ? {} : { simulatorBearerToken: simToken }),
    evaluation,
    decision,
    effectivePermissions: {
      profileId: effective.profileId,
      profileName: effective.profileName,
      assignedGroups: effective.assignedGroups,
      allowedActions: Array.from(effective.allowedActions),
    },
  });
}

/**
 * POST /api/admin/workspace/seed-sample
 * Development only: creates sample Access Groups and replaces the group mappings of the sample
 * Profiles (and of any Profile whose name matches one). Refused in production, where it could give
 * real Profiles write and delete access.
 */
adminRouter.post('/workspace/seed-sample', (req: Request, res: Response) => {
  if (config.isProd) {
    res.status(403).json({ error: 'Sample data can only be loaded outside production.' });
    return;
  }
  const actor = getAdminInfo(req);
  const existingObjects = store.getObjects();
  // Matched case-insensitively, and saved under the catalog's spelling, as POST /groups would save them.
  const catalogObject = (objName: string) =>
    existingObjects.find((o) => o.objectName.toLowerCase() === objName.toLowerCase());
  const objFieldNames = (objName: string, exclude: string[] = []): string[] => {
    const found = catalogObject(objName);
    if (!found) return [];
    const excluded = new Set(exclude.map((name) => name.toLowerCase()));
    return found.fields
      .filter((f) => f.enabled && !excluded.has(f.fieldName.toLowerCase()))
      .map((f) => f.fieldName);
  };

  // Ensure standard profiles exist if none or few exist
  const baseProfiles = [
    { id: '00e5g000001A9xLAAS', name: 'System Administrator' },
    { id: '00e5g000001B2k9AAC', name: 'Enterprise Sales AE' },
    { id: '00e5g000001B2kAAAS', name: 'Sales Development Rep (SDR)' },
    { id: '00e5g000001C4mQAAQ', name: 'Sales Operations Analyst' },
    { id: '00e5g000001D8pRAAU', name: 'Customer Support Tier 1' },
    { id: '00e5g000001D8pSAAU', name: 'Customer Support Escalations' },
    { id: '00e5g000001E1vWAAS', name: 'Solutions Engineer' },
    { id: '00e5g000001F7nZAAS', name: 'Marketing Operations' },
    { id: '00e5g000001G3qTAAS', name: 'Finance & Deal Desk' },
    { id: '00e5g000001H9wUAAS', name: 'Read-Only Executive' },
    { id: '00e5g000001J0yVAAS', name: 'Partner Community User' },
    { id: '00e5g000001K2zWAAS', name: 'Integration Bot (Copilot)' },
  ];

  // Upsert the 5 reference Enterprise Access Groups
  const sampleGroups = [
    {
      id: 'grp-sales-ro',
      name: 'Sales · Read-only',
      description: 'Read access to core CRM pipeline objects via Copilot.',
      allowedActions: [
        'list_enabled_objects',
        'describe_object',
        'soql_query',
        'get_record',
      ],
      objectPermissions: [
        {
          objectName: 'Account',
          canRead: true,
          canCreate: false,
          canUpdate: false,
          canDelete: false,
          allowedFields: objFieldNames('Account'),
        },
        {
          objectName: 'Contact',
          canRead: true,
          canCreate: false,
          canUpdate: false,
          canDelete: false,
          allowedFields: objFieldNames('Contact', ['Birthdate']),
        },
        {
          objectName: 'Opportunity',
          canRead: true,
          canCreate: false,
          canUpdate: false,
          canDelete: false,
          allowedFields: objFieldNames('Opportunity', ['Discount_Pct__c']),
        },
        {
          objectName: 'Lead',
          canRead: true,
          canCreate: false,
          canUpdate: false,
          canDelete: false,
          allowedFields: objFieldNames('Lead'),
        },
      ],
    },
    {
      id: 'grp-sales-rw',
      name: 'Sales · Pipeline Editor',
      description: 'Create & update pipeline records; no deletes.',
      allowedActions: [
        'list_enabled_objects',
        'describe_object',
        'soql_query',
        'get_record',
        'create_record',
        'update_record',
      ],
      objectPermissions: [
        {
          objectName: 'Account',
          canRead: true,
          canCreate: false,
          canUpdate: true,
          canDelete: false,
          allowedFields: objFieldNames('Account'),
        },
        {
          objectName: 'Contact',
          canRead: true,
          canCreate: true,
          canUpdate: true,
          canDelete: false,
          allowedFields: objFieldNames('Contact', ['Birthdate']),
        },
        {
          objectName: 'Opportunity',
          canRead: true,
          canCreate: true,
          canUpdate: true,
          canDelete: false,
          allowedFields: objFieldNames('Opportunity'),
        },
        {
          objectName: 'Lead',
          canRead: true,
          canCreate: true,
          canUpdate: true,
          canDelete: false,
          allowedFields: objFieldNames('Lead'),
        },
        {
          objectName: 'Task',
          canRead: true,
          canCreate: true,
          canUpdate: true,
          canDelete: false,
          allowedFields: objFieldNames('Task'),
        },
      ],
    },
    {
      id: 'grp-svc-cases',
      name: 'Service · Case Handler',
      description: 'Triage, update, and comment on customer cases.',
      allowedActions: [
        'list_enabled_objects',
        'describe_object',
        'soql_query',
        'get_record',
        'create_record',
        'update_record',
      ],
      objectPermissions: [
        {
          objectName: 'Account',
          canRead: true,
          canCreate: false,
          canUpdate: false,
          canDelete: false,
          allowedFields: objFieldNames('Account', ['AnnualRevenue']),
        },
        {
          objectName: 'Contact',
          canRead: true,
          canCreate: false,
          canUpdate: true,
          canDelete: false,
          allowedFields: objFieldNames('Contact', ['Birthdate']),
        },
        {
          objectName: 'Case',
          canRead: true,
          canCreate: true,
          canUpdate: true,
          canDelete: false,
          allowedFields: objFieldNames('Case'),
        },
        {
          objectName: 'Task',
          canRead: true,
          canCreate: true,
          canUpdate: true,
          canDelete: false,
          allowedFields: objFieldNames('Task'),
        },
      ],
    },
    {
      id: 'grp-revops',
      name: 'RevOps · Quote Approver',
      description: 'Full analytics, quote approval, and pipeline updates.',
      allowedActions: [
        'list_enabled_objects',
        'describe_object',
        'soql_query',
        'get_record',
        'update_record',
      ],
      objectPermissions: [
        {
          objectName: 'Account',
          canRead: true,
          canCreate: false,
          canUpdate: true,
          canDelete: false,
          allowedFields: objFieldNames('Account'),
        },
        {
          objectName: 'Opportunity',
          canRead: true,
          canCreate: false,
          canUpdate: true,
          canDelete: false,
          allowedFields: objFieldNames('Opportunity'),
        },
        {
          objectName: 'Quote__c',
          canRead: true,
          canCreate: true,
          canUpdate: true,
          canDelete: false,
          allowedFields: objFieldNames('Quote__c'),
        },
        {
          objectName: 'Campaign',
          canRead: true,
          canCreate: false,
          canUpdate: false,
          canDelete: false,
          allowedFields: objFieldNames('Campaign'),
        },
      ],
    },
    {
      id: 'grp-admin',
      name: 'Platform Admin',
      description: 'Unrestricted MCP tool & object access for administrators.',
      allowedActions: [
        'list_enabled_objects',
        'describe_object',
        'soql_query',
        'get_record',
        'create_record',
        'update_record',
        'delete_record',
      ],
      objectPermissions: existingObjects
        .filter((o) => o.enabled)
        .slice(0, 12)
        .map((o) => ({
          objectName: o.objectName,
          canRead: true,
          canCreate: true,
          canUpdate: true,
          canDelete: true,
          allowedFields: o.fields.filter((f) => f.enabled).map((f) => f.fieldName),
        })),
    },
  ];

  // One transaction, so loading the matrix is all or nothing, and one policy revision.
  runInTransaction(() => {
    for (const p of baseProfiles) {
      if (!store.getProfileById(p.id)) {
        store.upsertProfile(p.id, p.name);
      }
    }

    for (const g of sampleGroups) {
      // A grant for an Object the catalog does not have could not be saved through POST /groups either.
      const objectPermissions = g.objectPermissions.flatMap((p) => {
        const found = catalogObject(p.objectName);
        return found ? [{ ...p, objectName: found.objectName }] : [];
      });
      const sample = { ...g, objectPermissions };
      if (store.getGroups().some((existing) => existing.id === g.id)) store.upsertGroup(sample);
      else store.createGroup(sample);
    }

    // Assign profiles to groups
    const allProfiles = store.getProfiles();
    const findProf = (id: string, nameFragment: string) =>
      allProfiles.find((p) => p.id === id) ||
      allProfiles.find((p) =>
        p.name.toLowerCase().includes(nameFragment.toLowerCase())
      );

    const mappingsToApply: Array<{ id?: string; groups: string[] }> = [
      { id: findProf('00e5g000001A9xLAAS', 'System Administrator')?.id, groups: ['grp-admin'] },
      { id: findProf('00e5g000001B2k9AAC', 'Enterprise Sales AE')?.id, groups: ['grp-sales-ro', 'grp-sales-rw'] },
      { id: findProf('00e5g000001B2kAAAS', 'Sales Development')?.id, groups: ['grp-sales-ro'] },
      { id: findProf('00e5g000001C4mQAAQ', 'Sales Operations')?.id, groups: ['grp-sales-ro', 'grp-revops'] },
      { id: findProf('00e5g000001D8pRAAU', 'Customer Support Tier 1')?.id, groups: ['grp-svc-cases'] },
      { id: findProf('00e5g000001D8pSAAU', 'Customer Support Escalations')?.id, groups: ['grp-svc-cases', 'grp-sales-ro'] },
      { id: findProf('00e5g000001E1vWAAS', 'Solutions Engineer')?.id, groups: ['grp-sales-ro'] },
      { id: findProf('00e5g000001F7nZAAS', 'Marketing')?.id, groups: ['grp-sales-ro'] },
      { id: findProf('00e5g000001G3qTAAS', 'Finance')?.id, groups: ['grp-revops'] },
      { id: findProf('00e5g000001H9wUAAS', 'Read-Only')?.id, groups: ['grp-sales-ro'] },
      { id: findProf('00e5g000001K2zWAAS', 'Integration Bot')?.id, groups: ['grp-sales-rw', 'grp-svc-cases'] },
    ];

    for (const m of mappingsToApply) {
      if (m.id) {
        store.setProfileGroups(m.id, m.groups);
      }
    }
  });

  store.recordPortalAdminLog({
    adminUsername: actor.username,
    authMethod: actor.authMethod,
    action: 'SEED_ENTERPRISE_MATRIX',
    target: 'Access Matrix & Governance Policy',
    details: `Loaded reference Enterprise Governance Matrix (${sampleGroups.length} Access Groups and Profile-to-Group mappings).`,
    ipAddress: actor.ip,
    correlationId: actor.correlationId,
  });

  res.json({
    profiles: store.getProfiles(),
    objects: store.getObjects(),
    groups: store.getGroups(),
    profileGroupMappings: store.getProfileGroupMappings(),
  });
});
