import { Router, Request, Response, NextFunction } from 'express';
import { store } from '../db/store.js';
import { parseProfilesCsv, parseSfdxFilesToObjects } from '../db/importers.js';
import {
  requireAdminAuth,
  issueAdminSessionCookie,
  clearAdminSessionCookie,
  verifyAdminSessionFromRequest,
} from '../security/adminAuth.js';
import {
  createSimulatorToken,
  resolveSalesforceUserFromToken,
  validateSalesforceInstanceUrl,
} from '../salesforce/client.js';
import {
  generateSelfSignedCertificateBundle,
  connectToSalesforceOrgViaJwt,
  fetchProfilesFromOrgSession,
  fetchOrgObjectsCatalog,
  fetchObjectsMetadataFromOrgSession,
  SalesforceOrgTokenSession,
} from '../salesforce/jwtConnection.js';
import { config } from '../config.js';
import {
  evaluateMcpToolCall,
  resolveEffectiveProfilePermissions,
} from '../rbac/policyEngine.js';

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
  }
  if (body.loginUrl !== undefined) {
    // The signed JWT assertion is posted here, so it passes the same allowlist as instance URLs.
    input.loginUrl = validateSalesforceInstanceUrl(String(body.loginUrl));
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

/**
 * Why a production Okta save must be refused, if it should be. The issuer's discovery and token
 * endpoints receive the client secret, and the redirect URI receives the authorization code.
 * A blank value is allowed: it means the https issuer derived from the domain, or the default URI.
 */
function insecureOktaUrlError(body: Record<string, unknown>): string | null {
  const urls: Array<[string, unknown]> = [
    ['Okta Issuer', body.issuer],
    ['Okta Redirect URI', body.redirectUri],
  ];
  for (const [label, value] of urls) {
    if (value === undefined || value === null) continue;
    const url = typeof value === 'string' ? value.trim() : null;
    if (url === '') continue;
    if (url === null || !/^https:\/\//i.test(url) || !URL.canParse(url)) {
      return `${label} must be an https:// URL in production.`;
    }
  }
  return null;
}

/** Express 4 ignores rejected promises, so async handlers must hand failures to `next` explicitly. */
const asyncRoute =
  (handler: (req: Request, res: Response) => Promise<void>) =>
  (req: Request, res: Response, next: NextFunction) => {
    handler(req, res).catch(next);
  };

function getAdminInfo(req: Request): {
  username: string;
  authMethod: 'password' | 'okta_sso';
  ip: string;
} {
  const session = (req as any).adminSession;
  return {
    username: session?.email || 'admin',
    authMethod: session?.authMethod === 'okta_oidc' ? 'okta_sso' : 'password',
    ip: req.ip || '127.0.0.1',
  };
}

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

/**
 * GET /api/admin/overview
 */
adminRouter.get('/overview', (_req: Request, res: Response) => {
  const profiles = store.getProfiles();
  const objects = store.getObjects();
  const groups = store.getGroups();
  const profileGroupMappings = store.getProfileGroupMappings();
  const copilotLogs = store.getCopilotMcpLogs(150);
  const portalLogs = store.getPortalAdminLogs(150);
  const okta = store.getOktaConfig();
  const sfSettings = store.getSalesforceSettings();
  const portalUsers = store.getPortalUsers();

  // Totals cover every logged call; the log lists themselves are the latest 150 rows.
  const mcpStats = store.getCopilotMcpLogStats();

  res.json({
    stats: {
      totalMcpRequests: mcpStats.total,
      allowedMcpRequests: mcpStats.allowed,
      deniedMcpRequests: mcpStats.denied,
      erroredMcpRequests: mcpStats.errors,
      totalProfiles: profiles.length,
      totalObjects: objects.length,
      enabledObjects: objects.filter((o) => o.enabled).length,
      totalGroups: groups.length,
    },
    profiles,
    objects,
    groups,
    profileGroupMappings,
    copilotLogs,
    portalLogs,
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

// ============================================================================
// 1. SALESFORCE -> PROFILES (Add/Update, CSV Import, Delete)
// ============================================================================
adminRouter.post('/profiles', (req: Request, res: Response) => {
  const { id, name } = req.body || {};
  if (!id || !name) {
    res.status(400).json({ error: 'Profile ID and Profile Name are required.' });
    return;
  }

  const result = store.upsertProfile(String(id), String(name));
  const actor = getAdminInfo(req);
  store.recordPortalAdminLog({
    adminUsername: actor.username,
    authMethod: actor.authMethod,
    action: result.action === 'inserted' ? 'CREATE_PROFILE' : 'UPDATE_PROFILE',
    target: `Profile: ${result.profile.name} (${result.profile.id})`,
    details: `${
      result.action === 'inserted' ? 'Added new' : 'Updated existing'
    } Salesforce Profile "${result.profile.name}" with ID "${result.profile.id}".`,
    ipAddress: actor.ip,
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
    details: `Imported ${parsedRows.length} profile rows from CSV (${summary.inserted} added, ${summary.updated} updated; ${summary.total} total profiles).`,
    ipAddress: actor.ip,
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
  });

  res.json({ profiles: store.getProfiles() });
});

async function getActiveSalesforceOrgSession(): Promise<SalesforceOrgTokenSession> {
  const sfSecrets = store.getSalesforceSettingsWithSecrets();
  if (!sfSecrets.enabled && sfSecrets.connectionStatus !== 'connected') {
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
  const { upserts, removeProfileIds, keptMissingProfileIds } = req.body || {};
  if (!Array.isArray(upserts)) {
    res.status(400).json({ error: 'upserts array is required.' });
    return;
  }

  const summary = store.applyProfilesSyncFromOrg({
    upserts: upserts.map((u: any) => ({
      id: String(u.id || ''),
      name: String(u.name || ''),
    })),
    removeProfileIds: Array.isArray(removeProfileIds)
      ? removeProfileIds.map(String)
      : [],
    keptMissingProfileIds: Array.isArray(keptMissingProfileIds)
      ? keptMissingProfileIds.map(String)
      : [],
  });

  const actor = getAdminInfo(req);
  store.recordPortalAdminLog({
    adminUsername: actor.username,
    authMethod: actor.authMethod,
    action: 'SYNC_PROFILES_FROM_ORG',
    target: 'Salesforce > Profiles',
    details: `Synced Profiles from Salesforce Org (${summary.inserted} added, ${summary.updated} updated, ${summary.removed} removed, ${summary.keptMissing} missing profiles kept).`,
    ipAddress: actor.ip,
  });

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
  });

  res.json({
    summary,
    objects: store.getObjects(),
  });
});

/**
 * POST /api/admin/objects/import-local-folder
 * Reads a local SFDX `force-app/main/default/objects` directory path on the server
 */
adminRouter.post('/objects/import-local-folder', (req: Request, res: Response) => {
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

    for (const f of targetObj.fields) {
      store.toggleObjectField(objectName, f.fieldName, Boolean(enabled));
    }

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
  const { pulledMetadata, removeObjectNames, removeFields } = req.body || {};
  if (!Array.isArray(pulledMetadata)) {
    res.status(400).json({ error: 'pulledMetadata array is required.' });
    return;
  }

  const summary = store.applyObjectsSyncFromOrg({
    pulledMetadata,
    removeObjectNames: Array.isArray(removeObjectNames)
      ? removeObjectNames.map(String)
      : [],
    removeFields: Array.isArray(removeFields)
      ? removeFields.map((f: any) => ({
          objectName: String(f.objectName || ''),
          fieldName: String(f.fieldName || ''),
        }))
      : [],
  });

  const actor = getAdminInfo(req);
  store.recordPortalAdminLog({
    adminUsername: actor.username,
    authMethod: actor.authMethod,
    action: 'SYNC_OBJECTS_FROM_ORG',
    target: 'Salesforce > Objects',
    details: `Synced Objects from Salesforce Org (${summary.objectsUpserted} objects/${summary.fieldsUpserted} fields synced; ${summary.objectsRemoved} objects & ${summary.fieldsRemoved} fields removed; ${summary.objectsKeptMissing} objects & ${summary.fieldsKeptMissing} fields kept).`,
    ipAddress: actor.ip,
  });

  res.json({
    summary,
    objects: store.getObjects(),
  });
});

// ============================================================================
// 3. ACCESS MATRIX -> GROUPS & PROFILE-GROUP MATRIX
// ============================================================================
adminRouter.post('/groups', (req: Request, res: Response) => {
  const { id, name, description, allowedActions, objectPermissions } =
    req.body || {};
  if (!name) {
    res.status(400).json({ error: 'Group name is required.' });
    return;
  }

  const isUpdate = Boolean(id && store.getGroups().some((g) => g.id === id));
  let saved;
  try {
    saved = store.upsertGroup({
      id: id ? String(id) : undefined,
      name: String(name),
      description: description ? String(description) : '',
      allowedActions: Array.isArray(allowedActions) ? allowedActions : [],
      objectPermissions: Array.isArray(objectPermissions)
        ? objectPermissions
        : [],
    });
  } catch (err: any) {
    if (/UNIQUE constraint failed: access_groups\.name/.test(String(err?.message))) {
      res.status(409).json({ error: `An Access Group named "${String(name).trim()}" already exists.` });
      return;
    }
    throw err;
  }

  const actor = getAdminInfo(req);
  store.recordPortalAdminLog({
    adminUsername: actor.username,
    authMethod: actor.authMethod,
    action: isUpdate ? 'UPDATE_GROUP' : 'CREATE_GROUP',
    target: `Group: ${saved.name}`,
    details: `${isUpdate ? 'Updated' : 'Created'} Access Group "${
      saved.name
    }" (${saved.allowedActions.length} MCP actions, ${
      saved.objectPermissions.length
    } objects configured).`,
    ipAddress: actor.ip,
  });

  res.json({
    group: saved,
    groups: store.getGroups(),
  });
});

adminRouter.delete('/groups/:id', (req: Request, res: Response) => {
  const id = String(req.params.id);
  const existing = store.getGroups().find((g) => g.id === id);
  const deleted = store.deleteGroup(id);
  if (!deleted) {
    res.status(404).json({ error: 'Group not found.' });
    return;
  }

  const actor = getAdminInfo(req);
  store.recordPortalAdminLog({
    adminUsername: actor.username,
    authMethod: actor.authMethod,
    action: 'DELETE_GROUP',
    target: `Group: ${existing?.name || id}`,
    details: `Deleted Access Group "${existing?.name || id}".`,
    ipAddress: actor.ip,
  });

  res.json({
    groups: store.getGroups(),
    profileGroupMappings: store.getProfileGroupMappings(),
  });
});

/**
 * PUT /api/admin/profile-groups/:profileId
 * Assigns one or more Groups to a Salesforce Profile
 */
adminRouter.put(
  '/profile-groups/:profileId',
  (req: Request, res: Response) => {
    const profileId = String(req.params.profileId);
    const { groupIds } = req.body || {};
    if (!Array.isArray(groupIds)) {
      res.status(400).json({ error: 'groupIds array is required.' });
      return;
    }

    const profile = store.getProfileById(profileId);
    if (!profile) {
      res.status(404).json({ error: `Profile '${profileId}' not found.` });
      return;
    }

    let updated;
    try {
      updated = store.setProfileGroups(
        profileId,
        groupIds.map((g) => String(g))
      );
    } catch (err: any) {
      res.status(400).json({ error: err?.message || 'Invalid groupIds.' });
      return;
    }
    const allGroups = store.getGroups();
    const groupNames = updated.groupIds.map(
      (gid) => allGroups.find((g) => g.id === gid)?.name || gid
    );

    const actor = getAdminInfo(req);
    store.recordPortalAdminLog({
      adminUsername: actor.username,
      authMethod: actor.authMethod,
      action: 'UPDATE_PROFILE_GROUPS',
      target: `Profile: ${profile.name} (${profile.id})`,
      details: `Mapped Profile "${profile.name}" to Groups: [${
        groupNames.length > 0 ? groupNames.join(', ') : 'None'
      }].`,
      ipAddress: actor.ip,
    });

    res.json({
      mapping: updated,
      profileGroupMappings: store.getProfileGroupMappings(),
    });
  }
);

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

  let updated;
  try {
    updated = store.updateSalesforceSettings(input);
  } catch (err: any) {
    // e.g. a private key that cannot be parsed
    res.status(400).json({ error: err?.message || 'Invalid Salesforce settings.' });
    return;
  }
  const actor = getAdminInfo(req);
  store.recordPortalAdminLog({
    adminUsername: actor.username,
    authMethod: actor.authMethod,
    action: 'UPDATE_SF_SETTINGS',
    target: 'Salesforce Org Connection',
    details: `Updated Salesforce Org connection settings (Mode: ${updated.authMode}, Login URL: ${updated.loginUrl}, User: ${updated.username || 'Not set'}, OrgId: ${updated.expectedOrgId || 'Any'}, Instance: ${updated.instanceUrl}).`,
    ipAddress: actor.ip,
  });
  res.json({ sfSettings: updated });
});

/**
 * POST /api/admin/sf-settings/generate-cert
 * Generates a 2048-bit RSA Private Key + self-signed X.509 Certificate (.crt) for Salesforce Connected App JWT flow.
 */
adminRouter.post('/sf-settings/generate-cert', (req: Request, res: Response) => {
  try {
    const { commonName } = req.body || {};
    const bundle = generateSelfSignedCertificateBundle(
      commonName ? String(commonName) : 'Salesforce MCP Metadata Sync'
    );
    const updated = store.updateSalesforceSettings({
      privateKeyPem: bundle.privateKeyPem,
      certificatePem: bundle.certificatePem,
      certFingerprint: bundle.fingerprintSha256,
    });

    const actor = getAdminInfo(req);
    store.recordPortalAdminLog({
      adminUsername: actor.username,
      authMethod: actor.authMethod,
      action: 'GENERATE_SF_JWT_CERT',
      target: 'Salesforce JWT Certificate',
      details: `Generated new 2048-bit RSA Private Key & X.509 Certificate (SHA-256: ${bundle.fingerprintSha256.slice(0, 23)}...) for Salesforce Connected App.`,
      ipAddress: actor.ip,
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
 * Saves credentials and verifies OAuth 2.0 JWT Bearer connection against the Salesforce Org.
 */
adminRouter.post(
  '/sf-settings/connect',
  asyncRoute(async (req: Request, res: Response) => {
    const actor = getAdminInfo(req);
    try {
      // Save any provided settings first
      if (req.body && Object.keys(req.body).length > 0) {
        store.updateSalesforceSettings(parseSalesforceSettingsInput(req.body));
      }

      const secrets = store.getSalesforceSettingsWithSecrets();
      const session = await connectToSalesforceOrgViaJwt({
        authMode: secrets.authMode,
        loginUrl: secrets.loginUrl,
        clientId: secrets.clientId,
        username: secrets.username,
        privateKeyPem: secrets.privateKeyPem,
        privateKeyUndecryptable: secrets.privateKeyUndecryptable,
        apiVersion: secrets.apiVersion,
        expectedOrgId: secrets.expectedOrgId,
        enforceOrgIdLock: secrets.enforceOrgIdLock,
      });

      const updated = store.updateSalesforceSettings({
        enabled: true,
        connectionStatus: 'connected',
        lastConnectedAt: new Date().toISOString(),
        lastError: '',
        connectedOrgId: session.orgId,
        connectedUser: session.username,
        instanceUrl: session.instanceUrl,
      });

      store.recordPortalAdminLog({
        adminUsername: actor.username,
        authMethod: actor.authMethod,
        action: 'CONNECT_SALESFORCE_ORG',
        target: `Salesforce Org (${session.orgId})`,
        details: `Connected to Salesforce Org "${session.orgId}" at ${session.instanceUrl} as "${session.username}" via ${
          session.authMode === 'simulated'
            ? 'Simulated JWT Org'
            : 'OAuth 2.0 JWT Bearer'
        }.`,
        ipAddress: actor.ip,
      });

      res.json({
        connected: true,
        sfSettings: updated,
      });
    } catch (err: any) {
      const errMsg = err.message || 'Failed to connect to Salesforce Org.';
      const updated = store.updateSalesforceSettings({
        connectionStatus: 'error',
        lastError: errMsg,
      });

      store.recordPortalAdminLog({
        adminUsername: actor.username,
        authMethod: actor.authMethod,
        action: 'CONNECT_SALESFORCE_ORG_FAILED',
        target: 'Salesforce Org Connection',
        details: `Salesforce JWT connection failed: ${errMsg}`,
        ipAddress: actor.ip,
      });

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
  const updated = store.updateSalesforceSettings({
    enabled: false,
    connectionStatus: 'disconnected',
    lastError: '',
  });

  const actor = getAdminInfo(req);
  store.recordPortalAdminLog({
    adminUsername: actor.username,
    authMethod: actor.authMethod,
    action: 'DISCONNECT_SALESFORCE_ORG',
    target: 'Salesforce Org Connection',
    details: 'Disconnected Salesforce Org metadata sync connection.',
    ipAddress: actor.ip,
  });

  res.json({ sfSettings: updated });
});

adminRouter.post('/portal-users', (req: Request, res: Response) => {
  const { username, displayName, password, role } = req.body || {};
  if (!username || !password) {
    res.status(400).json({ error: 'Username and password are required.' });
    return;
  }

  const saved = store.upsertPortalUser({
    username: String(username),
    displayName: displayName ? String(displayName) : undefined,
    password: String(password),
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
  });

  res.json({ portalUsers: store.getPortalUsers() });
});

adminRouter.delete('/portal-users/:username', (req: Request, res: Response) => {
  const username = String(req.params.username);
  try {
    if (!store.deletePortalUser(username)) {
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
    username: username
      ? String(username).trim()
      : 'copilot.user@enterprise.com',
  });

  const user = await resolveSalesforceUserFromToken(simToken);
  const effective = resolveEffectiveProfilePermissions(
    user.profileId,
    user.profileName
  );
  const evaluation = evaluateMcpToolCall(
    user,
    String(toolName || 'list_enabled_objects'),
    targetObject ? String(targetObject) : undefined
  );

  // Also record this test call into the Copilot MCP log (with sensitive data stripped!)
  store.recordCopilotMcpLog({
    sfUsername: user.username,
    profileId: user.profileId,
    profileName: effective.profileName,
    matchedGroups: evaluation.matchedGroups,
    toolName: String(toolName || 'list_enabled_objects'),
    targetObject: String(targetObject || '*'),
    status: evaluation.permitted ? 'ALLOWED' : 'DENIED',
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

  res.json({
    simulatorBearerToken: simToken,
    evaluation,
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
  const objFieldNames = (objName: string, exclude: string[] = []): string[] => {
    const found = existingObjects.find((o) => o.objectName === objName);
    if (!found) return [];
    return found.fields
      .filter((f) => f.enabled && !exclude.includes(f.fieldName))
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
  for (const p of baseProfiles) {
    if (!store.getProfileById(p.id)) {
      store.upsertProfile(p.id, p.name);
    }
  }

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

  for (const g of sampleGroups) {
    store.upsertGroup(g);
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

  store.recordPortalAdminLog({
    adminUsername: actor.username,
    authMethod: actor.authMethod,
    action: 'SEED_ENTERPRISE_MATRIX',
    target: 'Access Matrix & Governance Policy',
    details: `Loaded reference Enterprise Governance Matrix (${sampleGroups.length} Access Groups and Profile-to-Group mappings).`,
    ipAddress: actor.ip,
  });

  res.json({
    profiles: store.getProfiles(),
    objects: store.getObjects(),
    groups: store.getGroups(),
    profileGroupMappings: store.getProfileGroupMappings(),
  });
});
