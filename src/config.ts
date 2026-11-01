import dotenv from 'dotenv';
import crypto from 'node:crypto';
import path from 'node:path';

dotenv.config();

type Env = Record<string, string | undefined>;

// Publicly known keys that must never protect production data: the deterministic development
// fallback below and the sample value shipped in `.env.example`.
export const DEV_FALLBACK_SECRET_KEY = crypto
  .createHash('sha256')
  .update('salesforce-mcp-dev-secret-key-2026')
  .digest('hex');
const EXAMPLE_SECRET_KEY = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

// Single non-production default for the break-glass portal login (seeded into an empty database).
export const DEFAULT_BOOTSTRAP_ADMIN = { username: 'admin', password: 'admin123' } as const;

// Passwords that are public (this repo's defaults, past and present); never acceptable in production.
export const KNOWN_DEFAULT_PASSWORDS: readonly string[] = [DEFAULT_BOOTSTRAP_ADMIN.password, 'ChangeMeInProd!2026'];

/**
 * Resolves the 32-byte (64 hex chars) key used for AES-256-GCM secrets at rest and JWT signing.
 * Production refuses to start without a real key; development and test fall back to a
 * deterministic, publicly known key with a warning so local runs keep working.
 */
export function resolveAppSecretKey(env: Env, warn: (msg: string) => void = console.warn): string {
  const raw = (env.APP_SECRET_KEY || '').trim();
  const wellFormed = /^[0-9a-fA-F]{64}$/.test(raw);

  if (env.NODE_ENV === 'production') {
    if (!raw) {
      throw new Error(
        'FATAL: APP_SECRET_KEY must be set in production (64 hex characters, e.g. `openssl rand -hex 32`).'
      );
    }
    if (!wellFormed) {
      throw new Error('FATAL: APP_SECRET_KEY must be exactly 64 hex characters (32 bytes).');
    }
    if ([DEV_FALLBACK_SECRET_KEY, EXAMPLE_SECRET_KEY].includes(raw.toLowerCase())) {
      throw new Error(
        'FATAL: APP_SECRET_KEY is a publicly known development value. Generate a new one with `openssl rand -hex 32`.'
      );
    }
    return raw;
  }

  if (wellFormed) {
    if ([DEV_FALLBACK_SECRET_KEY, EXAMPLE_SECRET_KEY].includes(raw.toLowerCase())) {
      warn(
        '[config] APP_SECRET_KEY is the publicly known sample value. Anyone can forge admin sessions; use it for local development only (production refuses to start with it).'
      );
    }
    return raw;
  }
  warn(
    raw
      ? '[config] APP_SECRET_KEY is not 64 hex characters; using the insecure development key instead. Never do this in production.'
      : '[config] APP_SECRET_KEY is not set; using the insecure development key. Never do this in production.'
  );
  return DEV_FALLBACK_SECRET_KEY;
}

export function resolveBootstrapAdmin(
  env: Env,
  warn: (msg: string) => void = console.warn
): {
  username: string;
  password: string;
  usesDefaultPassword: boolean;
} {
  if (env.ADMIN_BOOTSTRAP_EMAIL) {
    warn('[config] ADMIN_BOOTSTRAP_EMAIL is no longer read; set ADMIN_BOOTSTRAP_USERNAME instead.');
  }
  const password = env.ADMIN_BOOTSTRAP_PASSWORD || DEFAULT_BOOTSTRAP_ADMIN.password;
  return {
    // ADMIN_USERNAME is the legacy name this setting was read from.
    username: (env.ADMIN_BOOTSTRAP_USERNAME || env.ADMIN_USERNAME || DEFAULT_BOOTSTRAP_ADMIN.username).trim(),
    password,
    usesDefaultPassword: KNOWN_DEFAULT_PASSWORDS.includes(password),
  };
}

/**
 * Express `trust proxy` setting. Off by default: the Next.js proxy forwards X-Forwarded-For
 * unchanged, so trusting it is only safe behind a load balancer that appends the client address
 * (then set TRUST_PROXY=loopback, or a hop count / subnet list).
 */
function parseTrustProxy(raw: string | undefined): boolean | number | string {
  const value = (raw || 'false').trim();
  if (value === 'true') return true;
  if (value === 'false') return false;
  if (/^\d+$/.test(value)) return Number(value);
  return value;
}

export function buildConfig(env: Env) {
  const nodeEnv = env.NODE_ENV || 'development';
  return {
    // Express MCP + Admin API backend port. The Next.js portal on :3000 proxies to it.
    port: parseInt(env.PORT || '3001', 10),
    // Public origin clients use (the Next.js portal, which proxies /mcp, /api/admin, /auth/okta, /.well-known).
    baseUrl: (env.BASE_URL || 'http://localhost:3000').replace(/\/+$/, ''),
    nodeEnv,
    isProd: nodeEnv === 'production',
    dbPath: env.DB_PATH || path.join(process.cwd(), 'data', 'mcp-governance.sqlite'),
    trustProxy: parseTrustProxy(env.TRUST_PROXY),

    // 32-byte key (64 hex chars) for AES-256-GCM encryption, JWT and simulator-token signing
    appSecretKey: resolveAppSecretKey(env),

    // Bootstrap Admin Credentials (break-glass / initial setup before Okta SSO)
    bootstrapAdmin: resolveBootstrapAdmin(env),

    // Initial Okta settings, seeded into the database on first start (then edited in the Admin Portal)
    okta: {
      issuer: env.OKTA_ISSUER || '',
      clientId: env.OKTA_CLIENT_ID || '',
      clientSecret: env.OKTA_CLIENT_SECRET || '',
      redirectUri: env.OKTA_REDIRECT_URI || '',
      requiredGroup: env.OKTA_REQUIRED_GROUP || 'MCP-Admins',
    },

    // Salesforce defaults
    salesforce: {
      loginUrl: env.SALESFORCE_LOGIN_URL || 'https://login.salesforce.com',
      allowedDomains: (env.SALESFORCE_ALLOWED_DOMAINS || '.my.salesforce.com,.salesforce.com,.force.com')
        .split(',')
        .map((d) => d.trim().toLowerCase())
        .filter(Boolean),
      apiVersion: env.SALESFORCE_API_VERSION || 'v62.0',
    },
  };
}

export const config = buildConfig(process.env);
