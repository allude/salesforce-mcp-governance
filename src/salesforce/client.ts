import crypto from 'node:crypto';
import { config } from '../config.js';
import { store } from '../db/store.js';
import { hashToken, timingSafeStringEqual } from '../security/crypto.js';
import { salesforceIdsMatch } from './ids.js';
import { assertNotSimulatedOrgHost } from './simulatedOrg.js';
import { createVerificationGate } from './verificationGate.js';
import { isPlausibleBearerToken } from '../mcp/bearer.js';

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
  /** Set only by verifySimulatorToken, so it cannot be claimed by a caller. */
  simulated?: true;
}

interface CachedIdentity {
  user: Omit<VerifiedSalesforceUser, 'accessToken'>;
  expiresAt: number;
}

// Short-lived cache (2 minutes) keyed by SHA-256 hash of Bearer token
const identityCache = new Map<string, CachedIdentity>();
const CACHE_TTL_MS = 120 * 1000;
const CACHE_MAX_ENTRIES = 5000;

// Hashes of tokens that passed verification in the last hour, with their expiry. Only the /mcp
// failed-attempt limiter reads this, so a caller whose token already proved valid keeps working
// while someone floods the same client IP with bad tokens. It never skips verification itself.
const recentlyVerifiedTokens = new Map<string, number>();
const RECENTLY_VERIFIED_TTL_MS = 60 * 60 * 1000;

// Tokens Salesforce answered 401 for, keyed by token hash and the host asked, so repeating a junk
// token costs nothing. Only a definite 401 is remembered; a 5xx or a timeout may pass.
const recentlyRejectedTokens = new Map<string, number>();
const RECENTLY_REJECTED_TTL_MS = 5 * 60 * 1000;

const VERIFICATION_TIMEOUT_MS = 10 * 1000;
const verificationGate = createVerificationGate({ maxConcurrent: 8, maxQueued: 100, maxWaitMs: 10 * 1000 });

/**
 * Salesforce could not give a verdict on the token: it timed out, could not be reached, or answered
 * 5xx or 429. Not a verdict on the token, so a token that verified before keeps its exemption and
 * the caller is told to retry rather than that its token is invalid.
 */
export class SalesforceUnavailableError extends Error {
  constructor(detail: string) {
    super(`Salesforce could not verify the token right now (${detail}); try again shortly`);
    this.name = 'SalesforceUnavailableError';
  }
}

const isAbort = (err: unknown) => err instanceof Error && (err.name === 'TimeoutError' || err.name === 'AbortError');

/** fetch with the verification timeout; a timeout or network failure is SalesforceUnavailableError. */
async function fetchForVerification(url: string, headers: Record<string, string>): Promise<Response> {
  try {
    return await fetch(url, { headers, signal: AbortSignal.timeout(VERIFICATION_TIMEOUT_MS) });
  } catch (err) {
    throw new SalesforceUnavailableError(isAbort(err) ? 'timed out' : 'not reachable');
  }
}

/** Reads a JSON body; the verification timeout also covers the body, and that is not a verdict either. */
async function readVerificationJson(res: Response): Promise<any> {
  try {
    return await res.json();
  } catch (err) {
    if (isAbort(err)) throw new SalesforceUnavailableError('timed out');
    throw err;
  }
}

const SIMULATOR_TOKEN_PREFIX = 'sf_sim_';
const SIMULATOR_TOKEN_TTL_SECONDS = 15 * 60;
const SIMULATED_IDENTITY_PREFIX = 'simulated:';
const SIMULATED_NAME_MAX_LENGTH = 64;
const DEFAULT_SIMULATED_NAME = 'test-user';

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

export { salesforceIdsMatch };

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

/** Sets `key` to expire after `ttlMs`, evicting expired and then oldest entries at the size cap. */
function rememberUntil(entries: Map<string, number>, key: string, ttlMs: number): void {
  const now = Date.now();
  if (!entries.has(key) && entries.size >= CACHE_MAX_ENTRIES) {
    for (const [k, expiresAt] of entries) {
      if (expiresAt <= now) entries.delete(k);
    }
    while (entries.size >= CACHE_MAX_ENTRIES) {
      const oldest = entries.keys().next().value;
      if (oldest === undefined) break;
      entries.delete(oldest);
    }
  }
  // Delete first so a refreshed entry moves to the end and is evicted last.
  entries.delete(key);
  entries.set(key, now + ttlMs);
}

const isLive = (entries: Map<string, number>, key: string) => {
  const expiresAt = entries.get(key);
  return expiresAt !== undefined && expiresAt > Date.now();
};

function rememberVerifiedToken(tokenHash: string): void {
  rememberUntil(recentlyVerifiedTokens, tokenHash, RECENTLY_VERIFIED_TTL_MS);
}

const wasHashRecentlyVerified = (tokenHash: string) => isLive(recentlyVerifiedTokens, tokenHash);

function rememberRejectedToken(rejectionKey: string): void {
  rememberUntil(recentlyRejectedTokens, rejectionKey, RECENTLY_REJECTED_TTL_MS);
}

const wasRecentlyRejected = (rejectionKey: string) => isLive(recentlyRejectedTokens, rejectionKey);

/** True when this exact bearer token passed verification within the last hour. */
export function wasTokenRecentlyVerified(bearerToken: string): boolean {
  return Boolean(bearerToken) && wasHashRecentlyVerified(hashToken(bearerToken));
}

/** Verifications running and waiting at the gate, for tests and diagnostics. */
export function verificationGateStats(): { active: number; queued: number } {
  return verificationGate.stats();
}

/**
 * Ends a token's exemption once it fails verification, so a token that verified once (and was
 * later revoked, or is sent with a hint where it is not valid) counts as rejected again.
 */
export function forgetVerifiedToken(bearerToken: string): void {
  if (bearerToken) recentlyVerifiedTokens.delete(hashToken(bearerToken));
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
    const simulatedUser = verifySimulatorToken(bearerToken);
    rememberVerifiedToken(hashToken(bearerToken));
    return simulatedUser;
  }

  if (!isPlausibleBearerToken(bearerToken)) {
    throw new Error('Malformed Salesforce Bearer token');
  }

  // The caller's real token goes to the hint on a cache miss, and the allowlist alone admits the simulated host.
  if (instanceUrlHint) assertNotSimulatedOrgHost(instanceUrlHint, 'Salesforce instance URL');

  const tokenHash = hashToken(bearerToken);
  const cached = identityCache.get(tokenHash);
  if (cached && cached.expiresAt > Date.now()) {
    enforceOrgIdLock(cached.user.organizationId);
    rememberVerifiedToken(tokenHash);
    return { ...cached.user, accessToken: bearerToken };
  }

  const sfSettings = store.getSalesforceSettings();
  const baseLoginUrl = validateSalesforceInstanceUrl(
    instanceUrlHint || sfSettings.instanceUrl || 'https://login.salesforce.com'
  );
  // A stored instance URL can name the simulated host too (a database saved before the hostname match,
  // or SALESFORCE_LOGIN_URL seeded with it), and the allowlist admits it, so both hosts the token may
  // reach are checked here, before it is sent anywhere.
  assertNotSimulatedOrgHost(baseLoginUrl, 'Salesforce instance URL');
  const fallbackInstanceUrl = validateSalesforceInstanceUrl(sfSettings.instanceUrl || baseLoginUrl);
  assertNotSimulatedOrgHost(fallbackInstanceUrl, 'Salesforce instance URL');

  const rejectionKey = `${tokenHash}|${baseLoginUrl}`;
  const refuseIfRecentlyRejected = () => {
    if (wasRecentlyRejected(rejectionKey)) throw new Error('Salesforce token verification failed (HTTP 401)');
  };
  refuseIfRecentlyRejected();

  return verificationGate.run(wasHashRecentlyVerified(tokenHash), async () => {
    // Another request with this token may have finished verifying, or been rejected, while this one waited.
    const verifiedMeanwhile = identityCache.get(tokenHash);
    if (verifiedMeanwhile && verifiedMeanwhile.expiresAt > Date.now()) {
      enforceOrgIdLock(verifiedMeanwhile.user.organizationId);
      rememberVerifiedToken(tokenHash);
      return { ...verifiedMeanwhile.user, accessToken: bearerToken };
    }
    refuseIfRecentlyRejected();
    return verifyWithSalesforce(bearerToken, tokenHash, rejectionKey, baseLoginUrl, fallbackInstanceUrl, sfSettings.apiVersion);
  });
}

async function verifyWithSalesforce(
  bearerToken: string,
  tokenHash: string,
  rejectionKey: string,
  baseLoginUrl: string,
  fallbackInstanceUrl: string,
  storedApiVersion: string
): Promise<VerifiedSalesforceUser> {
  // 2. Call Salesforce OIDC /services/oauth2/userinfo to verify token & get user_id + custom_domain
  const userInfoRes = await fetchForVerification(`${baseLoginUrl}/services/oauth2/userinfo`, {
    Authorization: `Bearer ${bearerToken}`,
    Accept: 'application/json',
  });

  if (!userInfoRes.ok) {
    // Only a 401 says the token itself is invalid; 5xx and 429 are passing faults, not verdicts.
    if (userInfoRes.status >= 500 || userInfoRes.status === 429) {
      throw new SalesforceUnavailableError(`HTTP ${userInfoRes.status}`);
    }
    if (userInfoRes.status === 401) rememberRejectedToken(rejectionKey);
    throw new Error(`Salesforce token verification failed (HTTP ${userInfoRes.status})`);
  }

  const userInfo = await readVerificationJson(userInfoRes);
  const userId: string = userInfo.user_id;
  const orgId: string = userInfo.organization_id;
  if (typeof userId !== 'string' || !userId || typeof orgId !== 'string' || !orgId) {
    throw new Error('Salesforce userinfo response is missing user_id or organization_id');
  }
  enforceOrgIdLock(orgId);

  // Determine the user's REST API instance URL from userinfo urls.custom_domain or urls.rest
  let instanceUrl = fallbackInstanceUrl;
  if (userInfo.urls?.custom_domain) {
    instanceUrl = validateSalesforceInstanceUrl(userInfo.urls.custom_domain);
  } else if (userInfo.urls?.rest) {
    const restOrigin = new URL(userInfo.urls.rest).origin;
    instanceUrl = validateSalesforceInstanceUrl(restOrigin);
  }
  // The profile lookup and every later tool call send the token here.
  assertNotSimulatedOrgHost(instanceUrl, 'Salesforce instance URL');

  // 3. Query the User's ProfileId and Profile.Name via Salesforce REST API
  const apiVersion = storedApiVersion || config.salesforce.apiVersion;
  const soql = `SELECT Id, Username, Name, Email, ProfileId, Profile.Name FROM User WHERE Id = '${escapeSoqlString(userId)}' LIMIT 1`;
  const queryRes = await fetchForVerification(
    `${instanceUrl}/services/data/${apiVersion}/query?q=${encodeURIComponent(soql)}`,
    {
      Authorization: `Bearer ${bearerToken}`,
      Accept: 'application/json',
    }
  );

  // Fail closed: if the User/Profile lookup fails, the caller has no Profile (and so no tools)
  // instead of a guessed one that could match a registered Profile by name.
  let profileId = '';
  let profileName = '';

  if (queryRes.ok) {
    const queryData = await readVerificationJson(queryRes);
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
  rememberVerifiedToken(tokenHash);

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
 * The identity simulated traffic is logged under. Admins choose the name, so the prefix keeps it
 * from passing as a real Salesforce user; removing control and bidi characters keeps it from being
 * made to look like something else in the log.
 */
function simulatedIdentity(rawName: unknown): string {
  const cleaned = String(rawName ?? '')
    .replace(/[\p{C}\p{Zl}\p{Zp}]/gu, '')
    .trim()
    .replace(/^(simulated:\s*)+/i, '');
  const name = Array.from(cleaned).slice(0, SIMULATED_NAME_MAX_LENGTH).join('').trim();
  return `${SIMULATED_IDENTITY_PREFIX}${name || DEFAULT_SIMULATED_NAME}`;
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
    username: simulatedIdentity(params.username),
    email: params.email || 'simulated.user@example.invalid',
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
    // Applied here too: a token minted before this rule existed stays valid for up to 15 minutes.
    username: simulatedIdentity(decoded.username),
    email: String(decoded.email || ''),
    displayName: String(decoded.displayName || ''),
    profileId: String(decoded.profileId || ''),
    profileName: String(decoded.profileName || ''),
    instanceUrl: String(decoded.instanceUrl || ''),
    accessToken: token,
    simulated: true,
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
