import crypto from 'node:crypto';
import { config } from '../config.js';
import { store } from '../db/store.js';
import { hashToken, timingSafeStringEqual } from '../security/crypto.js';

export interface VerifiedSalesforceUser {
  userId: string;
  organizationId: string;
  username: string;
  email: string;
  displayName: string;
  profileId: string;
  profileName: string;
  instanceUrl: string;
  accessToken: string;
}

interface CachedIdentity {
  user: Omit<VerifiedSalesforceUser, 'accessToken'>;
  expiresAt: number;
}

// Short-lived cache (2 minutes) keyed by SHA-256 hash of Bearer token
const identityCache = new Map<string, CachedIdentity>();
const CACHE_TTL_MS = 120 * 1000;
const CACHE_MAX_ENTRIES = 5000;

const SIMULATOR_TOKEN_PREFIX = 'sf_sim_';
const SIMULATOR_TOKEN_TTL_SECONDS = 15 * 60;

/**
 * Validates that a Salesforce instance URL belongs to an allowed Salesforce domain
 * (`SALESFORCE_ALLOWED_DOMAINS`) to prevent Server-Side Request Forgery (SSRF) via crafted URLs.
 * Entries starting with `.` match the domain and any subdomain; other entries must match exactly.
 */
export function validateSalesforceInstanceUrl(rawUrl: string): string {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new Error('Invalid Salesforce instance URL');
  }

  // The bearer token goes to this host, so plain HTTP is refused in every environment.
  if (parsed.protocol !== 'https:') {
    throw new Error('Salesforce instance URL must use HTTPS');
  }
  if (parsed.username || parsed.password) {
    throw new Error('Salesforce instance URL must not contain credentials');
  }

  const host = parsed.hostname.toLowerCase();
  // URL parsing keeps characters such as `"` and `%` in hosts; the origin is later written into
  // headers, so only plain DNS labels are accepted.
  if (!/^[a-z0-9-]+(\.[a-z0-9-]+)*$/.test(host)) {
    throw new Error('Salesforce instance host is not a valid DNS name');
  }
  const allowed = config.salesforce.allowedDomains.some((domain) =>
    domain.startsWith('.')
      ? host.endsWith(domain) || host === domain.slice(1)
      : host === domain
  );
  if (!allowed) {
    throw new Error(`Salesforce instance host '${host}' is not in SALESFORCE_ALLOWED_DOMAINS`);
  }

  return parsed.origin;
}

/**
 * The authorization server advertised to MCP clients (401 challenge and RFC 9728 metadata):
 * the saved instance URL, else `SALESFORCE_LOGIN_URL`, each used only if it passes
 * `validateSalesforceInstanceUrl` (a database saved before that check may hold any string).
 */
export function salesforceAuthorizationBase(): string {
  for (const candidate of [store.getSalesforceSettings().instanceUrl, config.salesforce.loginUrl]) {
    if (!candidate) continue;
    try {
      return validateSalesforceInstanceUrl(candidate);
    } catch {
      // fall through to the next candidate
    }
  }
  return 'https://login.salesforce.com';
}

/** Salesforce IDs are 15-char case-sensitive or 18-char with a checksum suffix; compare on the first 15. */
export function salesforceIdsMatch(a: string, b: string): boolean {
  const left = (a || '').trim();
  const right = (b || '').trim();
  if (!left || !right) return false;
  if (left === right) return true;
  const isSfId = (v: string) => /^[a-zA-Z0-9]{15}([a-zA-Z0-9]{3})?$/.test(v);
  return isSfId(left) && isSfId(right) && left.slice(0, 15) === right.slice(0, 15);
}

/** Rejects identities from any org other than the configured one when the Org ID lock is on. */
function enforceOrgIdLock(organizationId: string): void {
  const { enforceOrgIdLock, expectedOrgId } = store.getSalesforceSettings();
  if (enforceOrgIdLock && expectedOrgId && !salesforceIdsMatch(organizationId, expectedOrgId)) {
    throw new Error('Salesforce org is not permitted by the Org ID lock');
  }
}

function cacheIdentity(tokenHash: string, entry: CachedIdentity): void {
  if (identityCache.size >= CACHE_MAX_ENTRIES) {
    const now = Date.now();
    for (const [key, value] of identityCache) {
      if (value.expiresAt <= now) identityCache.delete(key);
    }
    while (identityCache.size >= CACHE_MAX_ENTRIES) {
      const oldest = identityCache.keys().next().value;
      if (oldest === undefined) break;
      identityCache.delete(oldest);
    }
  }
  identityCache.set(tokenHash, entry);
}

/**
 * Validates a Salesforce OAuth 2.0 Bearer token and resolves the user's exact
 * Salesforce Profile ID and Profile Name.
 *
 * Also supports HMAC-signed, short-lived Simulator tokens (`sf_sim_<payload>.<signature>`)
 * minted by the Admin Portal's Interactive Policy Simulator. They never reach Salesforce.
 */
export async function resolveSalesforceUserFromToken(
  bearerToken: string,
  instanceUrlHint?: string
): Promise<VerifiedSalesforceUser> {
  if (!bearerToken) {
    throw new Error('Missing Salesforce Bearer token');
  }

  // 1. Check if this is an Admin Simulator token for testing RBAC policies locally
  if (bearerToken.startsWith(SIMULATOR_TOKEN_PREFIX)) {
    return verifySimulatorToken(bearerToken);
  }

  const tokenHash = hashToken(bearerToken);
  const cached = identityCache.get(tokenHash);
  if (cached && cached.expiresAt > Date.now()) {
    enforceOrgIdLock(cached.user.organizationId);
    return { ...cached.user, accessToken: bearerToken };
  }

  const sfSettings = store.getSalesforceSettings();
  const baseLoginUrl = validateSalesforceInstanceUrl(
    instanceUrlHint || sfSettings.instanceUrl || 'https://login.salesforce.com'
  );

  // 2. Call Salesforce OIDC /services/oauth2/userinfo to verify token & get user_id + custom_domain
  const userInfoRes = await fetch(`${baseLoginUrl}/services/oauth2/userinfo`, {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${bearerToken}`,
      Accept: 'application/json',
    },
  });

  if (!userInfoRes.ok) {
    throw new Error(`Salesforce token verification failed (HTTP ${userInfoRes.status})`);
  }

  const userInfo = (await userInfoRes.json()) as any;
  const userId: string = userInfo.user_id;
  const orgId: string = userInfo.organization_id;
  if (typeof userId !== 'string' || !userId || typeof orgId !== 'string' || !orgId) {
    throw new Error('Salesforce userinfo response is missing user_id or organization_id');
  }
  enforceOrgIdLock(orgId);

  // Determine the user's REST API instance URL from userinfo urls.custom_domain or urls.rest
  let instanceUrl = validateSalesforceInstanceUrl(sfSettings.instanceUrl || baseLoginUrl);
  if (userInfo.urls?.custom_domain) {
    instanceUrl = validateSalesforceInstanceUrl(userInfo.urls.custom_domain);
  } else if (userInfo.urls?.rest) {
    const restOrigin = new URL(userInfo.urls.rest).origin;
    instanceUrl = validateSalesforceInstanceUrl(restOrigin);
  }

  // 3. Query the User's ProfileId and Profile.Name via Salesforce REST API
  const apiVersion = sfSettings.apiVersion || config.salesforce.apiVersion;
  const soql = `SELECT Id, Username, Name, Email, ProfileId, Profile.Name FROM User WHERE Id = '${escapeSoqlString(userId)}' LIMIT 1`;
  const queryRes = await fetch(
    `${instanceUrl}/services/data/${apiVersion}/query?q=${encodeURIComponent(soql)}`,
    {
      headers: {
        Authorization: `Bearer ${bearerToken}`,
        Accept: 'application/json',
      },
    }
  );

  // Fail closed: if the User/Profile lookup fails, the caller has no Profile (and so no tools)
  // instead of a guessed one that could match a registered Profile by name.
  let profileId = '';
  let profileName = '';

  if (queryRes.ok) {
    const queryData = (await queryRes.json()) as any;
    const userRecord = queryData.records?.[0];
    if (userRecord) {
      profileId = String(userRecord.ProfileId || '');
      profileName = String(userRecord.Profile?.Name || '');
    }
  }

  const verifiedUser: Omit<VerifiedSalesforceUser, 'accessToken'> = {
    userId,
    organizationId: orgId,
    username: userInfo.preferred_username || userInfo.email || userId,
    email: userInfo.email || '',
    displayName: userInfo.name || userInfo.preferred_username || 'Salesforce User',
    profileId,
    profileName,
    instanceUrl,
  };

  cacheIdentity(tokenHash, {
    user: verifiedUser,
    expiresAt: Date.now() + CACHE_TTL_MS,
  });

  return {
    ...verifiedUser,
    accessToken: bearerToken,
  };
}

/**
 * Executes a Salesforce REST API request using the authenticated user's Bearer token.
 */
export async function salesforceRestRequest<T = any>(
  user: VerifiedSalesforceUser,
  method: 'GET' | 'POST' | 'PATCH' | 'DELETE',
  relativePath: string,
  body?: Record<string, unknown>
): Promise<T> {
  // If using simulator token, return realistic simulated Salesforce REST responses
  if (user.accessToken.startsWith(SIMULATOR_TOKEN_PREFIX)) {
    return simulateSalesforceRestResponse(user, method, relativePath, body) as unknown as T;
  }

  const sfSettings = store.getSalesforceSettings();
  const apiVersion = sfSettings.apiVersion || config.salesforce.apiVersion;
  const cleanInstance = validateSalesforceInstanceUrl(user.instanceUrl);
  const fullUrl = relativePath.startsWith('/services/')
    ? `${cleanInstance}${relativePath}`
    : `${cleanInstance}/services/data/${apiVersion}${relativePath.startsWith('/') ? '' : '/'}${relativePath}`;

  const headers: Record<string, string> = {
    Authorization: `Bearer ${user.accessToken}`,
    Accept: 'application/json',
  };
  if (body) {
    headers['Content-Type'] = 'application/json';
  }

  const response = await fetch(fullUrl, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });

  if (response.status === 204) {
    return { success: true, status: 204 } as unknown as T;
  }

  const text = await response.text();
  let json: any;
  try {
    json = text ? JSON.parse(text) : {};
  } catch {
    json = { raw: text };
  }

  if (!response.ok) {
    const sfErr = Array.isArray(json) ? json[0] : json;
    const errMsg = sfErr?.message || sfErr?.error_description || `Salesforce API error (${response.status})`;
    const errCode = sfErr?.errorCode || sfErr?.error || 'SF_API_ERROR';
    throw new Error(`[${errCode}] ${errMsg}`);
  }

  return json as T;
}

/**
 * Pulls all Profiles from a live Salesforce Org using a provided Salesforce Admin Access Token + Instance URL.
 */
export async function fetchAllProfilesFromSalesforceOrg(
  instanceUrl: string,
  accessToken: string
): Promise<Array<{ Id: string; Name: string; UserType: string; PermissionsModifyAllData?: boolean }>> {
  const cleanInstance = validateSalesforceInstanceUrl(instanceUrl);
  const sfSettings = store.getSalesforceSettings();
  const apiVersion = sfSettings.apiVersion || config.salesforce.apiVersion;

  const soql = 'SELECT Id, Name, UserType, PermissionsModifyAllData FROM Profile ORDER BY Name ASC';
  const res = await fetch(
    `${cleanInstance}/services/data/${apiVersion}/query?q=${encodeURIComponent(soql)}`,
    {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: 'application/json',
      },
    }
  );

  if (!res.ok) {
    const errText = await res.text();
    throw new Error(`Failed to fetch Profiles from Salesforce (${res.status}): ${errText}`);
  }

  const data = (await res.json()) as any;
  return data.records || [];
}

export function escapeSoqlString(val: string): string {
  return val.replace(/\\/g, '\\\\').replace(/'/g, "\\'");
}

let simulatorSigningKey: Buffer | null = null;
function getSimulatorSigningKey(): Buffer {
  if (!simulatorSigningKey) {
    // Dedicated sub-key so simulator signatures never share key material with JWTs or AES-GCM.
    simulatorSigningKey = Buffer.from(
      crypto.hkdfSync('sha256', Buffer.from(config.appSecretKey, 'hex'), Buffer.alloc(0), 'sf-mcp simulator token v1', 32)
    );
  }
  return simulatorSigningKey;
}

function signSimulatorPayload(encodedPayload: string): string {
  return crypto.createHmac('sha256', getSimulatorSigningKey()).update(encodedPayload).digest('base64url');
}

/**
 * Creates an HMAC-signed simulation token (valid 15 minutes) for testing Profile RBAC policies on `/mcp`.
 * Only authenticated portal admins can mint one, via `POST /api/admin/test-mcp-access`.
 */
export function createSimulatorToken(params: {
  profileId: string;
  profileName: string;
  username?: string;
  email?: string;
}): string {
  const payload = {
    userId: '005SIM000000001AAA',
    organizationId: '00DSIM000000001AAA',
    username: params.username || 'alex.demo@company.my.salesforce.com',
    email: params.email || 'alex.demo@company.com',
    displayName: `Simulated User (${params.profileName})`,
    profileId: params.profileId,
    profileName: params.profileName,
    instanceUrl: 'https://company-demo.my.salesforce.com',
    exp: Math.floor(Date.now() / 1000) + SIMULATOR_TOKEN_TTL_SECONDS,
  };
  const encoded = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  return `${SIMULATOR_TOKEN_PREFIX}${encoded}.${signSimulatorPayload(encoded)}`;
}

function verifySimulatorToken(token: string): VerifiedSalesforceUser {
  const [encoded, signature, ...rest] = token.slice(SIMULATOR_TOKEN_PREFIX.length).split('.');
  if (!encoded || !signature || rest.length > 0) {
    throw new Error('Invalid simulator token');
  }
  if (!timingSafeStringEqual(signature, signSimulatorPayload(encoded))) {
    throw new Error('Invalid simulator token signature');
  }

  let decoded: any;
  try {
    decoded = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
  } catch {
    throw new Error('Invalid simulator token');
  }
  if (typeof decoded?.exp !== 'number' || decoded.exp * 1000 <= Date.now()) {
    throw new Error('Simulator token has expired');
  }

  return {
    userId: String(decoded.userId || ''),
    organizationId: String(decoded.organizationId || ''),
    username: String(decoded.username || ''),
    email: String(decoded.email || ''),
    displayName: String(decoded.displayName || ''),
    profileId: String(decoded.profileId || ''),
    profileName: String(decoded.profileName || ''),
    instanceUrl: String(decoded.instanceUrl || ''),
    accessToken: token,
  };
}

function simulateSalesforceRestResponse(
  user: VerifiedSalesforceUser,
  method: string,
  relativePath: string,
  body?: Record<string, unknown>
): any {
  if (relativePath.startsWith('/query')) {
    return {
      totalSize: 2,
      done: true,
      executedAsUser: user.username,
      executedWithProfile: user.profileName,
      records: [
        {
          attributes: { type: 'Opportunity', url: '/services/data/v62.0/sobjects/Opportunity/00600000001A1B2AAK' },
          Id: '00600000001A1B2AAK',
          Name: 'Acme Corp - Enterprise Copilot Expansion',
          StageName: 'Negotiation/Review',
          Amount: 185000,
          CloseDate: '2026-12-15',
        },
        {
          attributes: { type: 'Opportunity', url: '/services/data/v62.0/sobjects/Opportunity/00600000001A1B3AAK' },
          Id: '00600000001A1B3AAK',
          Name: 'Globex Financial - Zero Trust Upgrade',
          StageName: 'Proposal/Price Quote',
          Amount: 92000,
          CloseDate: '2026-11-30',
        },
      ],
    };
  }

  if (relativePath.startsWith('/search')) {
    return {
      searchRecords: [
        {
          attributes: { type: 'Account', url: '/services/data/v62.0/sobjects/Account/00100000001A1B2AAK' },
          Id: '00100000001A1B2AAK',
          Name: 'Acme Corporation',
        },
      ],
    };
  }

  if (relativePath.includes('/describe')) {
    const parts = relativePath.split('/');
    const sobject = parts[parts.indexOf('sobjects') + 1] || 'Account';
    return {
      name: sobject,
      label: sobject,
      custom: sobject.endsWith('__c'),
      queryable: true,
      createable: true,
      updateable: true,
      deletable: true,
      fields: [
        { name: 'Id', label: 'Record ID', type: 'id', updateable: false },
        { name: 'Name', label: 'Name', type: 'string', updateable: true },
        { name: 'OwnerId', label: 'Owner ID', type: 'reference', updateable: true },
        { name: 'CreatedDate', label: 'Created Date', type: 'datetime', updateable: false },
      ],
    };
  }

  if (method === 'POST' && relativePath.includes('/sobjects/')) {
    return {
      id: '006SIM000009999AAA',
      success: true,
      errors: [],
      createdFields: body,
      executedAsProfile: user.profileName,
    };
  }

  if (method === 'PATCH' && relativePath.includes('/sobjects/')) {
    return {
      success: true,
      status: 204,
      updatedFields: body,
      executedAsProfile: user.profileName,
    };
  }

  if (method === 'DELETE' && relativePath.includes('/sobjects/')) {
    return {
      success: true,
      status: 204,
      deletedByProfile: user.profileName,
    };
  }

  return {
    Id: relativePath.split('/').pop(),
    Name: 'Sample Salesforce Record',
    ExecutedByUser: user.username,
    Profile: user.profileName,
  };
}
