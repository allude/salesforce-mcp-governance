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
  evaluateMcpToolCall,
  resolveEffectiveProfilePermissions,
} from '../rbac/policyEngine.js';

export const adminRouter = Router();

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
      objectName: String(objectName),
      label: label ? String(label) : undefined,
      fields: Array.isArray(fields) ? fields : undefined,
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
  const body = req.body || {};
  const input: Record<string, unknown> = {};
  if (body.instanceUrl !== undefined) {
    try {
      input.instanceUrl = validateSalesforceInstanceUrl(String(body.instanceUrl));
    } catch (err: any) {
      res.status(400).json({ error: err?.message || 'Invalid Salesforce instance URL.' });
      return;
    }
  }
  if (body.apiVersion !== undefined) {
    if (!/^v\d+\.\d$/.test(String(body.apiVersion).trim())) {
      res.status(400).json({ error: 'API version must look like v62.0.' });
      return;
    }
    input.apiVersion = String(body.apiVersion).trim();
  }
  if (body.expectedOrgId !== undefined) {
    const orgId = String(body.expectedOrgId).trim();
    if (orgId && !/^00D[a-zA-Z0-9]{12}(?:[a-zA-Z0-9]{3})?$/.test(orgId)) {
      res.status(400).json({ error: 'Expected Org ID must be a 15 or 18-character Salesforce Org ID (00D...).' });
      return;
    }
    input.expectedOrgId = orgId;
  }
  if (body.enforceOrgIdLock !== undefined) {
    input.enforceOrgIdLock = Boolean(body.enforceOrgIdLock);
  }
  if (body.sfdxObjectsFolderPath !== undefined) {
    input.sfdxObjectsFolderPath = String(body.sfdxObjectsFolderPath);
  }
  const effectiveOrgId = (input.expectedOrgId as string | undefined) ?? store.getSalesforceSettings().expectedOrgId;
  const effectiveLock = (input.enforceOrgIdLock as boolean | undefined) ?? store.getSalesforceSettings().enforceOrgIdLock;
  if (effectiveLock && !effectiveOrgId) {
    res.status(400).json({ error: 'Set an expected Org ID before enforcing the Org ID lock.' });
    return;
  }

  const updated = store.updateSalesforceSettings(input);
  const actor = getAdminInfo(req);
  store.recordPortalAdminLog({
    adminUsername: actor.username,
    authMethod: actor.authMethod,
    action: 'UPDATE_SF_SETTINGS',
    target: 'Salesforce Connection Settings',
    details: `Updated Salesforce settings (OrgId: ${updated.expectedOrgId || 'Any'}, Instance: ${updated.instanceUrl}).`,
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
  const { profileId, toolName, targetObject, samplePayload } = req.body || {};
  const profile = store.getProfileById(String(profileId || ''));
  const simToken = createSimulatorToken({
    profileId: String(profileId || ''),
    profileName: profile?.name || String(profileId || ''),
    username: 'copilot.user@enterprise.com',
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
    latencyMs: 4,
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
