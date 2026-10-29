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
}

const SESSION_COOKIE_NAME = 'sf_mcp_admin_session';
const OIDC_FLOW_COOKIE_NAME = 'sf_mcp_oidc_flow';
const SECRET_KEY = new TextEncoder().encode(config.appSecretKey);

/**
 * Signs an encrypted/verified JWT admin session cookie (`HttpOnly`, `SameSite=Lax`, `Secure` in prod)
 */
export async function issueAdminSessionCookie(
  res: Response,
  claims: Omit<AdminSessionClaims, 'csrfToken'>
): Promise<{ csrfToken: string }> {
  const csrfToken = crypto.randomBytes(24).toString('base64url');
  const token = await new jose.SignJWT({ ...claims, csrfToken })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setIssuer('salesforce-mcp-admin')
    .setAudience('salesforce-mcp-admin-portal')
    .setExpirationTime('8h')
    .sign(SECRET_KEY);

  res.cookie(SESSION_COOKIE_NAME, token, {
    httpOnly: true,
    secure: config.isProd,
    sameSite: 'lax',
    path: '/',
    maxAge: 8 * 60 * 60 * 1000, // 8 hours
  });

  return { csrfToken };
}

export function clearAdminSessionCookie(res: Response): void {
  res.clearCookie(SESSION_COOKIE_NAME, { path: '/' });
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

    const claims: AdminSessionClaims = {
      sub: String(payload.sub || ''),
      email: String(payload.email || ''),
      name: String(payload.name || ''),
      authMethod: (payload.authMethod as 'okta_oidc' | 'local_bootstrap') || 'local_bootstrap',
      groups: Array.isArray(payload.groups) ? (payload.groups as string[]) : [],
      csrfToken: String(payload.csrfToken || ''),
    };
    // Password sessions end as soon as the portal user is deleted.
    if (claims.authMethod === 'local_bootstrap' && !store.portalUserExists(claims.email)) {
      return null;
    }
    return claims;
  } catch {
    return null;
  }
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

  const { codeVerifier, codeChallenge } = generatePkcePair();
  const state = generateStateToken();
  const nonce = generateStateToken();

  // Store PKCE verifier + state + nonce in a short-lived signed cookie (10 minutes)
  const flowToken = await new jose.SignJWT({ codeVerifier, state, nonce })
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

  const redirectUri = okta.redirectUri || `${config.baseUrl}/auth/okta/callback`;
  const authUrl = new URL(authorizeEndpoint);
  authUrl.searchParams.set('client_id', okta.clientId);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('scope', 'openid profile email groups');
  authUrl.searchParams.set('redirect_uri', redirectUri);
  authUrl.searchParams.set('state', state);
  authUrl.searchParams.set('nonce', nonce);
  authUrl.searchParams.set('code_challenge', codeChallenge);
  authUrl.searchParams.set('code_challenge_method', 'S256');

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

  if (error) {
    redirectWithAuthError(res, 'okta_error', clientIp, String(error_description || error));
    return;
  }

  const flowCookie = req.cookies?.[OIDC_FLOW_COOKIE_NAME];
  res.clearCookie(OIDC_FLOW_COOKIE_NAME, { path: '/' });

  if (!flowCookie || typeof code !== 'string' || typeof state !== 'string') {
    redirectWithAuthError(res, 'invalid_callback', clientIp, 'Missing login state cookie, code or state.');
    return;
  }

  let flowClaims: { codeVerifier: string; state: string; nonce: string };
  try {
    const { payload } = await jose.jwtVerify(flowCookie, SECRET_KEY);
    flowClaims = payload as any;
  } catch {
    redirectWithAuthError(res, 'expired_state', clientIp, 'The login state cookie expired or is invalid.');
    return;
  }

  if (!timingSafeStringEqual(state, flowClaims.state)) {
    redirectWithAuthError(res, 'state_mismatch', clientIp, 'The OIDC state parameter did not match.');
    return;
  }

  const okta = store.getOktaConfig();
  const issuer = okta.issuer.replace(/\/+$/, '');
  const redirectUri = okta.redirectUri || `${config.baseUrl}/auth/okta/callback`;

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

    const groups = Array.isArray(payload.groups) ? (payload.groups as string[]) : [];
    if (okta.adminGroup && !groups.includes(okta.adminGroup)) {
      store.recordPortalAdminLog({
        adminUsername: String(payload.email || payload.sub || 'okta_user'),
        authMethod: 'okta_sso',
        action: 'OKTA_LOGIN_DENIED',
        target: 'Portal Auth',
        details: `Denied Okta login: missing required group '${okta.adminGroup}'`,
        ipAddress: clientIp,
      });
      res.redirect('/?auth_error=group_denied');
      return;
    }

    const email = String(payload.email || payload.preferred_username || payload.sub);
    const name = String(payload.name || email);

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
