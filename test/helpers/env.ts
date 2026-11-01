// Side-effect module: import it FIRST in every test file, before anything from src/.
// It points config/store at a throwaway SQLite database and a random secret key, so tests never
// touch real data. node:test runs each test file in its own process, so each file gets its own DB.
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export const testTmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sf-mcp-test-'));

// (Next.js types mark NODE_ENV read-only, hence the cast)
(process.env as Record<string, string | undefined>).NODE_ENV = 'test';
process.env.DB_PATH = path.join(testTmpDir, 'governance.sqlite');
process.env.APP_SECRET_KEY = crypto.randomBytes(32).toString('hex');
// Every config input is set explicitly: dotenv never overrides a defined key (even an empty one),
// so a developer's local .env cannot leak into the tests.
const testEnv: Record<string, string> = {
  SALESFORCE_ALLOWED_DOMAINS: '.my.salesforce.com,.salesforce.com,.force.com',
  SALESFORCE_LOGIN_URL: 'https://login.salesforce.com',
  SALESFORCE_API_VERSION: 'v62.0',
  BASE_URL: 'http://localhost:3000',
  // The tests act as a trusted proxy, using X-Forwarded-For to simulate distinct clients.
  TRUST_PROXY: 'loopback',
  ADMIN_BOOTSTRAP_USERNAME: 'admin',
  // Random and non-default, so a seed that ignored the configured password would be caught.
  ADMIN_BOOTSTRAP_PASSWORD: `test-${crypto.randomBytes(12).toString('hex')}`,
  ADMIN_USERNAME: '',
  ADMIN_BOOTSTRAP_EMAIL: '',
  OKTA_ISSUER: '',
  OKTA_CLIENT_ID: '',
  OKTA_CLIENT_SECRET: '',
  OKTA_REDIRECT_URI: '',
  OKTA_REQUIRED_GROUP: 'MCP-Admins',
};
Object.assign(process.env, testEnv);

export const TEST_ADMIN = { username: testEnv.ADMIN_BOOTSTRAP_USERNAME, password: testEnv.ADMIN_BOOTSTRAP_PASSWORD };

process.on('exit', () => {
  fs.rmSync(testTmpDir, { recursive: true, force: true });
});
