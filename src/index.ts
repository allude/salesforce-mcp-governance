import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import rateLimit from 'express-rate-limit';
import path from 'node:path';
import { config } from './config.js';
import { store } from './db/store.js';
import { handleMcpStreamableHttpRequest } from './mcp/streamableHttp.js';
import {
  handleOktaLoginRedirect,
  handleOktaCallback,
} from './security/adminAuth.js';
import { adminRouter } from './routes/adminRoutes.js';

export const app = express();

// 1. Strict Security Headers (CSP, HSTS, X-Frame-Options)
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
        styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
        fontSrc: ["'self'", 'https://fonts.gstatic.com'],
        imgSrc: ["'self'", 'data:', 'https:'],
        connectSrc: ["'self'"],
      },
    },
  })
);

app.use(
  cors({
    origin: true,
    credentials: true,
    exposedHeaders: ['WWW-Authenticate', 'Mcp-Session-Id'],
  })
);

app.use(express.json({ limit: '1mb' }));
app.use(cookieParser());

// 2. Rate Limiting for Auth & MCP Endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many authentication attempts, please try again later.' },
});

const mcpLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
});

// 3. RFC 9728 OAuth 2.0 Protected Resource Metadata (For MCP OAuth Discovery & Copilot Studio)
app.get('/.well-known/oauth-protected-resource', (_req, res) => {
  const sfSettings = store.getSalesforceSettings();
  const authBase = sfSettings.instanceUrl || 'https://login.salesforce.com';
  res.json({
    resource: `${config.baseUrl}/mcp`,
    authorization_servers: [authBase],
    bearer_methods_supported: ['header'],
    scopes_supported: ['api', 'refresh_token', 'openid', 'profile', 'email'],
    resource_documentation: `${config.baseUrl}/docs/architecture.md`,
  });
});

// Healthcheck
app.get('/healthz', (_req, res) => {
  res.json({
    status: 'ok',
    service: 'salesforce-zero-trust-mcp',
    transport: 'streamable-http',
    timestamp: new Date().toISOString(),
  });
});

// 4. Streamable HTTP MCP Endpoint (POST, GET, DELETE /mcp)
app.all('/mcp', mcpLimiter, handleMcpStreamableHttpRequest);

// 5. Okta OIDC SSO Routes for Admin Control Plane
app.get('/auth/okta/login', authLimiter, handleOktaLoginRedirect);
app.get('/auth/okta/callback', authLimiter, handleOktaCallback);

// 6. Admin Control Plane REST API
app.use('/api/admin', authLimiter, adminRouter);

// 7. Serve Architecture Diagrams & Admin Web Frontend
app.use('/docs', express.static(path.join(process.cwd(), 'docs')));
app.use(express.static(path.join(process.cwd(), 'public')));

// Fallback to Admin SPA index.html
app.get('*', (_req, res) => {
  res.sendFile(path.join(process.cwd(), 'public', 'index.html'));
});

if (process.env.NODE_ENV !== 'test') {
  app.listen(config.port, () => {
    console.log(`\n========================================================================`);
    console.log(`🛡️  Salesforce Zero-Trust MCP Server & Admin Control Plane`);
    console.log(`========================================================================`);
    console.log(`🌐 Admin Web Portal (Okta SSO):  ${config.baseUrl}`);
    console.log(`🔌 Streamable HTTP MCP Endpoint: ${config.baseUrl}/mcp`);
    console.log(`🔐 OAuth Resource Metadata:      ${config.baseUrl}/.well-known/oauth-protected-resource`);
    console.log(`🔑 Bootstrap Admin Login:        ${config.bootstrapAdminEmail}`);
    console.log(`========================================================================\n`);
  });
}
