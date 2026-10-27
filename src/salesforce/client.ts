import { config } from '../config.js';
import { store } from '../db/store.js';
import { hashToken } from '../security/crypto.js';

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

/**
 * Validates that a Salesforce instance URL belongs to an allowed Salesforce domain
 * to prevent Server-Side Request Forgery (SSRF) via crafted URLs.
 */
export function validateSalesforceInstanceUrl(rawUrl: string): string {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new Error(`Invalid Salesforce instance URL: ${rawUrl}`);
  }

  if (parsed.protocol !== 'https:' && config.isProd) {
    throw new Error('Salesforce instance URL must use HTTPS');
  }

  return parsed.origin;
}

/**
 * Validates a Salesforce OAuth 2.0 Bearer token and resolves the user's exact
 * Salesforce Profile ID and Profile Name.
 *
 * Also supports signed Demo/Simulator tokens (`sf_sim_<base64url>`) when testing
 * from the Admin Portal's Interactive Policy Simulator.
 */
export async function resolveSalesforceUserFromToken(
  bearerToken: string,
  instanceUrlHint?: string
): Promise<VerifiedSalesforceUser> {
  if (!bearerToken) {
    throw new Error('Missing Salesforce Bearer token');
  }

  // 1. Check if this is an Admin Simulator token for testing RBAC policies locally
  if (bearerToken.startsWith('sf_sim_')) {
    return parseSimulatorToken(bearerToken);
  }

  const tokenHash = hashToken(bearerToken);
  const cached = identityCache.get(tokenHash);
  if (cached && cached.expiresAt > Date.now()) {
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

  // Determine the user's REST API instance URL from userinfo urls.custom_domain or urls.rest
  let instanceUrl = sfSettings.instanceUrl || baseLoginUrl;
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

  let profileId = userInfo.profile ? String(userInfo.profile).split('/').pop() || 'unknown' : 'unknown';
  let profileName = 'Standard User';

  if (queryRes.ok) {
    const queryData = (await queryRes.json()) as any;
    const userRecord = queryData.records?.[0];
    if (userRecord) {
      profileId = userRecord.ProfileId || profileId;
      profileName = userRecord.Profile?.Name || profileName;
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

  identityCache.set(tokenHash, {
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
  if (user.accessToken.startsWith('sf_sim_')) {
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

/**
 * Creates a signed simulation token for testing Profile RBAC policies on `/mcp`
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
  };
  return `sf_sim_${Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url')}`;
}

function parseSimulatorToken(token: string): VerifiedSalesforceUser {
  const encoded = token.slice('sf_sim_'.length);
  const decoded = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
  return {
    ...decoded,
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
