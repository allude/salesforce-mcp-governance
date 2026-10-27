import dotenv from 'dotenv';
import crypto from 'node:crypto';
import path from 'node:path';

dotenv.config();

const defaultSecret = crypto.createHash('sha256').update('salesforce-mcp-dev-secret-key-2026').digest('hex');

export const config = {
  port: parseInt(process.env.PORT || '3000', 10),
  baseUrl: process.env.BASE_URL || 'http://localhost:3000',
  nodeEnv: process.env.NODE_ENV || 'development',
  isProd: process.env.NODE_ENV === 'production',
  dbPath: process.env.DB_PATH || path.join(process.cwd(), 'data', 'mcp-governance.sqlite'),

  // 32-byte key (64 hex chars) for AES-256-GCM encryption & JWT signing
  appSecretKey: process.env.APP_SECRET_KEY && process.env.APP_SECRET_KEY.length === 64
    ? process.env.APP_SECRET_KEY
    : defaultSecret,

  // Bootstrap Admin Credentials (break-glass / initial setup before Okta SSO)
  bootstrapAdminEmail: process.env.ADMIN_BOOTSTRAP_EMAIL || 'admin@company.com',
  bootstrapAdminPassword: process.env.ADMIN_BOOTSTRAP_PASSWORD || 'ChangeMeInProd!2026',

  // Default Okta env vars (can be overridden dynamically in the Admin Portal)
  okta: {
    issuer: process.env.OKTA_ISSUER || '',
    clientId: process.env.OKTA_CLIENT_ID || '',
    clientSecret: process.env.OKTA_CLIENT_SECRET || '',
    redirectUri: process.env.OKTA_REDIRECT_URI || 'http://localhost:3000/auth/okta/callback',
    requiredGroup: process.env.OKTA_REQUIRED_GROUP || '',
  },

  // Salesforce defaults
  salesforce: {
    loginUrl: process.env.SALESFORCE_LOGIN_URL || 'https://login.salesforce.com',
    allowedDomains: (process.env.SALESFORCE_ALLOWED_DOMAINS || '.my.salesforce.com,.salesforce.com,.force.com')
      .split(',')
      .map((d) => d.trim().toLowerCase())
      .filter(Boolean),
    apiVersion: process.env.SALESFORCE_API_VERSION || 'v62.0',
    adminClientId: process.env.SALESFORCE_ADMIN_CLIENT_ID || '',
    adminClientSecret: process.env.SALESFORCE_ADMIN_CLIENT_SECRET || '',
    adminRedirectUri: process.env.SALESFORCE_ADMIN_REDIRECT_URI || 'http://localhost:3000/api/admin/salesforce/callback',
  },
};
