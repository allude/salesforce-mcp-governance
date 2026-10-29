import express, { NextFunction, Request, Response } from 'express';
import helmet from 'helmet';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import rateLimit from 'express-rate-limit';
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { config } from './config.js';
import { store } from './db/store.js';
import { handleMcpStreamableHttpRequest } from './mcp/streamableHttp.js';
import {
  handleOktaLoginRedirect,
  handleOktaCallback,
  requireAdminAuth,
} from './security/adminAuth.js';
import { adminRouter } from './routes/adminRoutes.js';
import { hashToken } from './security/crypto.js';

export const app = express();

// req.ip feeds rate-limit keys and audit-log IPs. TRUST_PROXY is off by default because the
// Next.js proxy passes X-Forwarded-For through unchanged; enable it (e.g. `loopback`) only behind a
// load balancer that appends the client address.
app.set('trust proxy', config.trustProxy);

// 1. Strict Security Headers (CSP, HSTS, X-Frame-Options). This server only returns JSON
// and the read-only /docs files; the Admin Portal UI is served by Next.js.
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'none'"],
        imgSrc: ["'self'"],
        frameAncestors: ["'none'"],
      },
    },
  })
);

// CORS only for the bearer-token MCP surface. Never with credentials, so no other origin can
// ride the admin session cookie. The Admin API has no CORS: the portal reaches it same-origin
// through the Next.js proxy.
const mcpCors = cors({
  origin: '*',
  credentials: false,
  exposedHeaders: ['WWW-Authenticate', 'Mcp-Session-Id'],
});

// Mounted before the body parsers so even a 400 parse error or a 413 carries the CORS headers.
app.use(['/mcp', '/.well-known'], mcpCors);

app.use(cookieParser());
// A whole SFDX objects/ folder uploaded from the browser can exceed the default 1 MB body limit,
// so that one route accepts up to 25 MB, and only after the admin session + CSRF check.
app.use(
  '/api/admin/objects/import-sfdx-files',
  (req: Request, res: Response, next: NextFunction) => {
    requireAdminAuth(req, res, next).catch(next);
  },
  express.json({ limit: '25mb' })
);
app.use(express.json({ limit: '1mb' }));

// 2. Rate Limiting for Auth & MCP Endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many authentication attempts, please try again later.' },
});

// Password login only counts failed attempts, so normal sign-ins never lock an admin out.
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true,
  message: { error: 'Too many authentication attempts, please try again later.' },
});

// Also per username, so changing IP (or X-Forwarded-For) cannot be used to brute-force one account.
const loginPerUserLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true,
  keyGenerator: (req: Request) => {
    const identifier = req.body?.username ?? req.body?.email;
    return `user:${typeof identifier === 'string' ? identifier.trim().toLowerCase().slice(0, 200) : ''}`;
  },
  message: { error: 'Too many failed sign-in attempts for this account, please try again later.' },
});

// Behind the portal proxy every request can share one IP (TRUST_PROXY=false), so callers that
// identify themselves get their own bucket: admins by session cookie, MCP clients by bearer token.
// Anonymous traffic is keyed by IP and cannot use up an authenticated caller's allowance.
const adminApiLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req: Request) => {
    const session = req.cookies?.sf_mcp_admin_session;
    return typeof session === 'string' && session ? `session:${hashToken(session)}` : `ip:${req.ip}`;
  },
  message: { error: 'Too many requests, please slow down.' },
});

const mcpLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req: Request) => {
    const auth = req.headers.authorization;
    const token = typeof auth === 'string' && /^bearer\s+/i.test(auth) ? auth.replace(/^bearer\s+/i, '').trim() : '';
    return token ? `token:${hashToken(token)}` : `ip:${req.ip}`;
  },
});

// 3. RFC 9728 OAuth 2.0 Protected Resource Metadata (For MCP OAuth Discovery & Copilot Studio)
app.get('/.well-known/oauth-protected-resource', (_req, res) => {
  const sfSettings = store.getSalesforceSettings();
  const authBase = sfSettings.instanceUrl || config.salesforce.loginUrl;
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

// 4. Streamable HTTP MCP Endpoint (POST, GET, DELETE /mcp; mcpCors above answers OPTIONS preflights)
app.all('/mcp', mcpLimiter, (req: Request, res: Response, next: NextFunction) => {
  handleMcpStreamableHttpRequest(req, res).catch(next);
});

// 5. Okta OIDC SSO Routes for Admin Control Plane
app.get('/auth/okta/login', authLimiter, (req: Request, res: Response, next: NextFunction) => {
  handleOktaLoginRedirect(req, res).catch(next);
});
app.get('/auth/okta/callback', authLimiter, (req: Request, res: Response, next: NextFunction) => {
  handleOktaCallback(req, res).catch(next);
});

// 6. Admin Control Plane REST API
app.post('/api/admin/login', loginLimiter, loginPerUserLimiter);
app.use('/api/admin', adminApiLimiter, adminRouter);

// 7. Read-only documentation referenced by the OAuth resource metadata
app.use('/docs', express.static(path.join(process.cwd(), 'docs')));

// The Admin Portal is the Next.js app; send browsers that land on the backend there.
app.get('/', (req: Request, res: Response) => {
  const portal = new URL(config.baseUrl);
  if (req.get('host') !== portal.host) {
    res.redirect(302, config.baseUrl);
    return;
  }
  res.json({ service: 'salesforce-zero-trust-mcp', adminPortal: config.baseUrl, mcpEndpoint: `${config.baseUrl}/mcp` });
});

app.use((_req: Request, res: Response) => {
  res.status(404).json({ error: 'Not found' });
});

// JSON errors instead of Express's default HTML stack trace page
app.use((err: any, req: Request, res: Response, _next: NextFunction) => {
  const status = Number(err?.status || err?.statusCode) || 500;
  if (status >= 500) {
    console.error('[server] Unhandled request error:', err);
  }
  if (res.headersSent) {
    res.end();
    return;
  }
  if (req.path === '/mcp' && err?.type === 'entity.parse.failed') {
    res.status(400).json({ jsonrpc: '2.0', error: { code: -32700, message: 'Parse error' }, id: null });
    return;
  }
  res.status(status).json({ error: status >= 500 ? 'Internal server error' : String(err?.message || 'Request error') });
});

function isEntryModule(): boolean {
  const entry = process.argv[1];
  if (!entry) return false;
  try {
    return import.meta.url === pathToFileURL(fs.realpathSync(entry)).href;
  } catch {
    return false;
  }
}

// Only listen when run directly (tsx src/index.ts or node dist/index.js); tests import `app`.
if (isEntryModule()) {
  // Safety net: a missed rejection must be logged, not take the whole server down (Node exits by default).
  process.on('unhandledRejection', (reason) => {
    console.error('[server] Unhandled promise rejection:', reason);
  });

  const server = app.listen(config.port, () => {
    const address = server.address();
    const boundPort = typeof address === 'object' && address ? address.port : config.port;
    console.log(`\n========================================================================`);
    console.log(`🛡️  Salesforce Zero-Trust MCP Server & Admin API (Express backend)`);
    console.log(`========================================================================`);
    console.log(`🔧 Backend listening on:         http://localhost:${boundPort}`);
    console.log(`🌐 Admin Portal (Next.js):       ${config.baseUrl}`);
    console.log(`🔌 Streamable HTTP MCP Endpoint: ${config.baseUrl}/mcp`);
    console.log(`🔐 OAuth Resource Metadata:      ${config.baseUrl}/.well-known/oauth-protected-resource`);
    console.log(`🔑 Bootstrap Admin Username:     ${config.bootstrapAdmin.username}`);
    console.log(`========================================================================\n`);
  });
}
