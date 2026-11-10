import { Request, Response, NextFunction } from 'express';
import * as jose from 'jose';
import crypto from 'node:crypto';
import { config } from '../config.js';
import { store } from '../db/store.js';
import {
  timingSafeStringEqual,
  generatePkcePair,
  generateStateToken,
} from './crypto.js';

export interface AdminSessionClaims {
  sub: string;
  email: string;
  name: string;
  authMethod: 'okta_oidc' | 'local_bootstrap';
  groups?: string[];
  csrfToken: string;
  /** The server-side session record's id (see store.createAdminSession). */
  jti?: string;
  /** When the holder last proved who they are (sign-in or step-up), epoch milliseconds. */
  reauthenticatedAt?: number;
}

const SESSION_COOKIE_NAME = 'sf_mcp_admin_session';
const OIDC_FLOW_COOKIE_NAME = 'sf_mcp_oidc_flow';
const SECRET_KEY = new TextEncoder().encode(config.appSecretKey);

/** A session ends this long after it started, however active. */
export const SESSION_ABSOLUTE_TIMEOUT_MS = 8 * 60 * 60 * 1000;
/** ... and this long after its last request. */
export const SESSION_IDLE_TIMEOUT_MS = 60 * 60 * 1000;
/** last_seen_at is written at most this often, so polling does not write on every request. */
const SESSION_TOUCH_INTERVAL_MS = 60 * 1000;
/** Security settings and account changes need a sign-in or step-up this recent. */
export const STEP_UP_WINDOW_MS = 10 * 60 * 1000;

/**
 * Starts an admin session: a server-side record (revocable, idle timeout) and a signed JWT cookie that
 * names it (`HttpOnly`, `SameSite=Lax`, `Secure` in prod). The cookie alone is never enough: logout,
 * a deleted account or an idle hour ends the record, and with it the cookie.
 */
export async function issueAdminSessionCookie(
  res: Response,
  claims: Omit<AdminSessionClaims, 'csrfToken' | 'jti' | 'reauthenticatedAt'>
): Promise<{ csrfToken: string }> {
  const csrfToken = crypto.randomBytes(24).toString('base64url');
  const jti = crypto.randomBytes(18).toString('base64url');
  const nowMs = Date.now();
  store.createAdminSession({
    jti,
    // Password sessions are tied to the portal account; Okta ones to the Okta subject.
    subject: claims.authMethod === 'local_bootstrap' ? claims.email : claims.sub,
    authMethod: claims.authMethod,
    nowMs,
    expiresAtMs: nowMs + SESSION_ABSOLUTE_TIMEOUT_MS,
  });
  const token = await new jose.SignJWT({ ...claims, csrfToken })
    .setProtectedHeader({ alg: 'HS256' })
    .setJti(jti)
    .setIssuedAt()
    .setIssuer('salesforce-mcp-admin')
    .setAudience('salesforce-mcp-admin-portal')
    .setExpirationTime(Math.floor((nowMs + SESSION_ABSOLUTE_TIMEOUT_MS) / 1000))
    .sign(SECRET_KEY);

  res.cookie(SESSION_COOKIE_NAME, token, {
    httpOnly: true,
    secure: config.isProd,
    sameSite: 'lax',
    path: '/',
    maxAge: SESSION_ABSOLUTE_TIMEOUT_MS,
  });

  return { csrfToken };
}

export function clearAdminSessionCookie(res: Response): void {
  res.clearCookie(SESSION_COOKIE_NAME, { path: '/' });
}

/** Ends the session the request's cookie names, if any, so the cookie stops working even if kept. */
export async function revokeAdminSessionFromRequest(req: Request): Promise<void> {
  const token = req.cookies?.[SESSION_COOKIE_NAME];
  if (!token) return;
  try {
    const { payload } = await jose.jwtVerify(token, SECRET_KEY, {
      issuer: 'salesforce-mcp-admin',
      audience: 'salesforce-mcp-admin-portal',
    });
    if (typeof payload.jti === 'string') store.revokeAdminSession(payload.jti);
  } catch {
    // nothing to revoke
  }
}

export async function verifyAdminSessionFromRequest(
  req: Request
): Promise<AdminSessionClaims | null> {
  const token = req.cookies?.[SESSION_COOKIE_NAME];
  if (!token) return null;

  try {
    const { payload } = await jose.jwtVerify(token, SECRET_KEY, {
      issuer: 'salesforce-mcp-admin',
      audience: 'salesforce-mcp-admin-portal',
    });

    // A cookie whose server-side record is missing (issued before sessions were recorded, or by
    // another database), revoked, expired or idle too long is no session.
    const jti = typeof payload.jti === 'string' ? payload.jti : '';
    const record = jti ? store.getAdminSession(jti) : null;
    const nowMs = Date.now();
    if (
      !record ||
      record.revokedAt !== null ||
      record.expiresAt <= nowMs ||
      nowMs - record.lastSeenAt > SESSION_IDLE_TIMEOUT_MS
    ) {
      return null;
    }

    const claims: AdminSessionClaims = {
      sub: String(payload.sub || ''),
      email: String(payload.email || ''),
      name: String(payload.name || ''),
      authMethod: (payload.authMethod as 'okta_oidc' | 'local_bootstrap') || 'local_bootstrap',
      groups: Array.isArray(payload.groups) ? (payload.groups as string[]) : [],
      csrfToken: String(payload.csrfToken || ''),
      jti,
      reauthenticatedAt: record.reauthenticatedAt,
    };
    // The record and the cookie must agree on whose session this is.
    if (record.authMethod !== claims.authMethod) return null;
    // Password sessions end as soon as the portal user is deleted.
    if (claims.authMethod === 'local_bootstrap' && !store.portalUserExists(claims.email)) {
      return null;
    }
    if (nowMs - record.lastSeenAt >= SESSION_TOUCH_INTERVAL_MS) store.touchAdminSession(jti, nowMs);
    return claims;
  } catch {
    return null;
  }
}

/**
 * Guards the routes that change who can sign in or what MCP trusts (portal users, Okta, the Salesforce
 * connection and its Org ID lock). A stolen or unattended session must prove its holder again first:
 * a sign-in or step-up (POST /api/admin/reauth, or signing in with Okta again) within STEP_UP_WINDOW_MS.
 * Runs after requireAdminAuth.
 */
export function requireRecentAuthentication(req: Request, res: Response, next: NextFunction): void {
  const session = (req as any).adminSession as AdminSessionClaims | undefined;
  const reauthenticatedAt = session?.reauthenticatedAt ?? 0;
  if (!session || Date.now() - reauthenticatedAt > STEP_UP_WINDOW_MS) {
    res.status(403).json({
      error:
        session?.authMethod === 'okta_oidc'
          ? 'Sign in with Okta again to change security settings.'
          : 'Confirm your password (and authenticator code) to change security settings.',
      code: 'REAUTH_REQUIRED',
      authMethod: session?.authMethod ?? null,
    });
    return;
  }
  next();
}

/**
 * Express middleware protecting `/api/admin/*` endpoints.
 * Enforces both valid Admin Session JWT cookie AND anti-CSRF token on state-changing requests.
 */
export async function requireAdminAuth(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  const session = await verifyAdminSessionFromRequest(req);
  if (!session) {
    res.status(401).json({ error: 'Unauthorized: Admin authentication required' });
    return;
  }

  // Enforce CSRF check on state-mutating methods
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) {
    const csrfHeader = req.headers['x-csrf-token'];
    if (
      typeof csrfHeader !== 'string' ||
      !session.csrfToken ||
      !timingSafeStringEqual(csrfHeader, session.csrfToken)
    ) {
      res.status(403).json({ error: 'Forbidden: Invalid or missing X-CSRF-Token header' });
      return;
    }
  }

  (req as any).adminUser = session;
  (req as any).adminSession = session;
  next();
}

/** Whether a URL is parseable and https. Okta's issuer and redirect URI carry secrets, so production requires it. */
export function isHttpsUrl(url: string): boolean {
  return /^https:\/\//i.test(url) && URL.canParse(url);
}

/** Where Okta sends the authorization code: the stored redirect URI, or the default under BASE_URL. */
export function effectiveOktaRedirectUri(storedRedirectUri: string): string {
  return storedRedirectUri || `${config.baseUrl}/auth/okta/callback`;
}

/**
 * Why production refuses an Okta sign-in, if it does. A stored row can predate the settings check, or
 * come from OKTA_ISSUER / OKTA_REDIRECT_URI, and a blank redirect URI follows BASE_URL, so sign-in
 * checks the issuer and the effective redirect URI itself.
 */
function insecureOktaSignInDetails(okta: { issuer: string; redirectUri: string }): string | null {
  if (!config.isProd) return null;
  if (!isHttpsUrl(okta.issuer)) {
    return 'The configured Okta issuer is not an https:// URL, so production refused the sign-in.';
  }
  if (!isHttpsUrl(effectiveOktaRedirectUri(okta.redirectUri))) {
    return okta.redirectUri
      ? 'The configured Okta redirect URI is not an https:// URL, so production refused the sign-in.'
      : 'The Okta redirect URI is blank and its BASE_URL default is not an https:// URL, so production refused the sign-in.';
  }
  return null;
}

/**
 * Initiates the Okta OIDC Authorization Code Flow with PKCE (`/auth/okta/login`).
 */
export async function handleOktaLoginRedirect(req: Request, res: Response): Promise<void> {
  const okta = store.getOktaConfig();
  if (!okta.enabled || !okta.issuer || !okta.clientId) {
    res.status(400).send(
      'Okta SSO is not enabled or configured yet. Sign in with bootstrap credentials to configure Okta first.'
    );
    return;
  }
  const insecure = insecureOktaSignInDetails(okta);
  if (insecure) {
    redirectWithAuthError(res, 'sso_failed', req.ip || '127.0.0.1', insecure);
    return;
  }

  const { codeVerifier, codeChallenge } = generatePkcePair();
  const state = generateStateToken();
  const nonce = generateStateToken();

  // Store PKCE verifier + state + nonce in a short-lived signed cookie (10 minutes)
  const reauth = req.query.reauth === '1';
  const flowToken = await new jose.SignJWT({ codeVerifier, state, nonce, reauth })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime('10m')
    .sign(SECRET_KEY);

  res.cookie(OIDC_FLOW_COOKIE_NAME, flowToken, {
    httpOnly: true,
    secure: config.isProd,
    sameSite: 'lax',
    path: '/',
    maxAge: 10 * 60 * 1000,
  });

  // Discover authorization endpoint from Okta issuer metadata or standard Okta OAuth path
  let authorizeEndpoint = `${okta.issuer.replace(/\/+$/, '')}/v1/authorize`;
  try {
    const discoveryRes = await fetch(
      `${okta.issuer.replace(/\/+$/, '')}/.well-known/openid-configuration`
    );
    if (discoveryRes.ok) {
      const metadata = (await discoveryRes.json()) as any;
      if (metadata.authorization_endpoint) {
        authorizeEndpoint = metadata.authorization_endpoint;
      }
    }
  } catch {
    // Fallback to standard /v1/authorize
  }

  const redirectUri = effectiveOktaRedirectUri(okta.redirectUri);
  const authUrl = new URL(authorizeEndpoint);
  authUrl.searchParams.set('client_id', okta.clientId);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('scope', 'openid profile email groups');
  authUrl.searchParams.set('redirect_uri', redirectUri);
  authUrl.searchParams.set('state', state);
  authUrl.searchParams.set('nonce', nonce);
  authUrl.searchParams.set('code_challenge', codeChallenge);
  authUrl.searchParams.set('code_challenge_method', 'S256');
  // Step-up (`?reauth=1`): Okta must authenticate the user now, not reuse its own session.
  if (reauth) {
    authUrl.searchParams.set('prompt', 'login');
    authUrl.searchParams.set('max_age', '0');
  }

  res.redirect(authUrl.toString());
}

/**
 * The portal shows a fixed message per code (src/app/page.tsx), so a crafted link cannot put
 * arbitrary text on the login screen. Details go to the Portal Admin log instead.
 */
type OktaAuthErrorCode =
  | 'okta_error'
  | 'invalid_callback'
  | 'expired_state'
  | 'state_mismatch'
  | 'group_denied'
  | 'sso_failed';

function redirectWithAuthError(
  res: Response,
  code: OktaAuthErrorCode,
  clientIp: string,
  details: string
): void {
  store.recordPortalAdminLog({
    adminUsername: 'okta_user',
    authMethod: 'okta_sso',
    action: 'OKTA_LOGIN_FAILED',
    target: 'Portal Auth',
    details: `Okta sign-in failed (${code}): ${details}`.slice(0, 1000),
    ipAddress: clientIp,
  });
  res.redirect(`/?auth_error=${code}`);
}

/**
 * Handles the Okta OIDC callback (`/auth/okta/callback`), verifies `state`, `nonce`,
 * cryptographic JWKS signature on the Okta `id_token`, and optional group membership.
 */
export async function handleOktaCallback(req: Request, res: Response): Promise<void> {
  const { code, state, error, error_description } = req.query;
  // req.ip honours X-Forwarded-For only from trusted proxies (see `trust proxy` in index.ts)
  const clientIp = req.ip || '127.0.0.1';

  const flowCookie = req.cookies?.[OIDC_FLOW_COOKIE_NAME];
  res.clearCookie(OIDC_FLOW_COOKIE_NAME, { path: '/' });

  let flowClaims: { codeVerifier: string; state: string; nonce: string; reauth?: boolean } | null = null;
  if (flowCookie) {
    try {
      const { payload } = await jose.jwtVerify(flowCookie, SECRET_KEY);
      flowClaims = payload as any;
    } catch {
      flowClaims = null;
    }
  }
  const stateMatches = !!flowClaims && typeof state === 'string' && timingSafeStringEqual(state, String(flowClaims.state));

  if (error) {
    // Anyone can send a browser here with ?error=..., so Okta's text is logged only for a
    // callback that matches a login this browser started.
    if (stateMatches) {
      const text = String(error_description || error).replace(/[^\x20-\x7e]/g, ' ').slice(0, 300);
      redirectWithAuthError(res, 'okta_error', clientIp, `Okta returned an error: ${text}`);
    } else {
      redirectWithAuthError(res, 'invalid_callback', clientIp, 'Okta error callback without a matching login state (error text not logged).');
    }
    return;
  }

  if (!flowCookie || typeof code !== 'string' || typeof state !== 'string') {
    redirectWithAuthError(res, 'invalid_callback', clientIp, 'Missing login state cookie, code or state.');
    return;
  }

  if (!flowClaims) {
    redirectWithAuthError(res, 'expired_state', clientIp, 'The login state cookie expired or is invalid.');
    return;
  }

  if (!stateMatches) {
    redirectWithAuthError(res, 'state_mismatch', clientIp, 'The OIDC state parameter did not match.');
    return;
  }

  const okta = store.getOktaConfig();
  const insecure = insecureOktaSignInDetails(okta);
  if (insecure) {
    redirectWithAuthError(res, 'sso_failed', clientIp, insecure);
    return;
  }
  const issuer = okta.issuer.replace(/\/+$/, '');
  const redirectUri = effectiveOktaRedirectUri(okta.redirectUri);

  try {
    // 1. Discover Okta token_endpoint and jwks_uri
    let tokenEndpoint = `${issuer}/v1/token`;
    let jwksUri = `${issuer}/v1/keys`;

    const discoveryRes = await fetch(`${issuer}/.well-known/openid-configuration`);
    if (discoveryRes.ok) {
      const metadata = (await discoveryRes.json()) as any;
      if (metadata.token_endpoint) tokenEndpoint = metadata.token_endpoint;
      if (metadata.jwks_uri) jwksUri = metadata.jwks_uri;
    }

    // 2. Exchange authorization code + PKCE code_verifier for tokens
    const bodyParams = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: redirectUri,
      client_id: okta.clientId,
      code_verifier: flowClaims.codeVerifier,
    });
    if (okta.clientSecret) {
      bodyParams.set('client_secret', okta.clientSecret);
    }

    const tokenRes = await fetch(tokenEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'application/json',
      },
      body: bodyParams.toString(),
    });

    if (!tokenRes.ok) {
      const errText = await tokenRes.text();
      throw new Error(`Okta token exchange failed (${tokenRes.status}): ${errText}`);
    }

    const tokenData = (await tokenRes.json()) as any;
    const idToken = tokenData.id_token;
    if (!idToken) {
      throw new Error('Okta did not return an id_token');
    }

    // 3. Cryptographically verify the Okta ID Token against Okta's remote JWKS
    const JWKS = jose.createRemoteJWKSet(new URL(jwksUri));
    const { payload } = await jose.jwtVerify(idToken, JWKS, {
      issuer,
      audience: okta.clientId,
    });

    // A nonce was sent with the authorization request, so the ID token must echo it back.
    if (typeof payload.nonce !== 'string' || !timingSafeStringEqual(payload.nonce, String(flowClaims.nonce))) {
      throw new Error('OIDC nonce mismatch');
    }
    // A step-up asked Okta to authenticate the user again (max_age=0): the token must say it did.
    if (flowClaims.reauth === true) {
      const authTime = typeof payload.auth_time === 'number' ? payload.auth_time : 0;
      if (Date.now() / 1000 - authTime > 5 * 60) {
        throw new Error('Okta did not re-authenticate the user for the step-up sign-in');
      }
    }

    const groups = Array.isArray(payload.groups) ? (payload.groups as string[]) : [];
    // Fail closed: with no required group configured, every user assigned to the Okta app would be
    // an admin, so nobody is.
    const requiredGroup = okta.adminGroup.trim();
    if (!requiredGroup || !groups.includes(requiredGroup)) {
      store.recordPortalAdminLog({
        adminUsername: String(payload.email || payload.sub || 'okta_user'),
        authMethod: 'okta_sso',
        action: 'OKTA_LOGIN_DENIED',
        target: 'Portal Auth',
        details: requiredGroup
          ? `Denied Okta login: missing required group '${requiredGroup}'`
          : 'Denied Okta login: no required admin group is configured in Okta SSO settings.',
        ipAddress: clientIp,
      });
      res.redirect('/?auth_error=group_denied');
      return;
    }

    const email = String(payload.email || payload.preferred_username || payload.sub);
    const name = String(payload.name || email);

    // Signing in again (also how an Okta admin steps up) replaces this browser's previous session.
    await revokeAdminSessionFromRequest(req);
    await issueAdminSessionCookie(res, {
      sub: String(payload.sub),
      email,
      name,
      authMethod: 'okta_oidc',
      groups,
    });

    store.recordPortalAdminLog({
      adminUsername: email,
      authMethod: 'okta_sso',
      action: 'LOGIN_OKTA_SSO',
      target: 'Portal Auth',
      details: `Signed in via Okta OIDC + PKCE (${name})`,
      ipAddress: clientIp,
    });

    res.redirect('/');
  } catch (err: any) {
    redirectWithAuthError(res, 'sso_failed', clientIp, err?.message || 'Okta authentication failed');
  }
}
