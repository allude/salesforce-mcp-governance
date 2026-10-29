# 🛡️ Enterprise Salesforce MCP Server & Governance Control Plane

A Zero-Trust, Streamable HTTP **Model Context Protocol (MCP)** Server that connects **Microsoft Copilot Studio** (and any MCP client) to the **Salesforce REST API** using **per-user delegated OAuth 2.0 tokens**, governed by a **Salesforce Profile → Access Group → Tools / Objects / Fields policy engine**, and administered through a **Next.js Admin Portal** with **Okta OIDC SSO**.

---

## 🖼️ Architecture Diagram

![Enterprise Salesforce MCP Architecture](./docs/architecture-diagram.jpg)

* **High-Res Diagram (JPG):** [`architecture-diagram.jpg`](./architecture-diagram.jpg) / [`docs/architecture-diagram.jpg`](./docs/architecture-diagram.jpg)
* **Vector Diagram (SVG):** [`architecture-diagram.svg`](./architecture-diagram.svg) / [`docs/architecture-diagram.svg`](./docs/architecture-diagram.svg)

The stack is two processes:

| Process | Port | What it serves |
| :--- | :--- | :--- |
| **Next.js Admin Portal** (`src/app/`, `src/components/`) | `3000` | The admin UI. It proxies `/mcp`, `/api/admin/*`, `/auth/okta/*`, `/.well-known/*`, `/healthz` and `/docs/*` to the backend (`next.config.ts`), so `http://localhost:3000` is the one public origin. |
| **Express MCP backend** (`src/index.ts`) | `3001` | `POST /mcp` (Streamable HTTP MCP), `/.well-known/oauth-protected-resource`, `/api/admin/*`, `/auth/okta/*`, `/healthz`, `/docs/*`. It serves no UI; browsers that open it are redirected to the portal. |

---

## 📚 Documentation Index

1. **[Architecture & Sequence Flows (`docs/architecture.md`)](./docs/architecture.md)**: the runtime plane (per-user Salesforce OAuth + Streamable HTTP `/mcp`) and the admin plane (Next.js portal + Okta OIDC + policy engine), and why `/mcp` answers `401` + `WWW-Authenticate` instead of a browser redirect.
2. **[Security & Zero-Trust Design (`docs/security-model.md`)](./docs/security-model.md)**: per-user token passthrough, Profile → Group RBAC with object CRUD and field allowlists, SOQL filter validation, SSRF domain allowlisting, Org ID lock, signed simulator tokens, AES-256-GCM secrets at rest, Okta OIDC + PKCE + JWKS, CSRF and CORS rules, and the PII-stripped audit trail.
3. **[Microsoft Copilot Studio & Salesforce Connected App Setup (`docs/copilot-studio-setup.md`)](./docs/copilot-studio-setup.md)**
4. **[Okta SSO & Admin Portal Guide (`docs/okta-admin-setup.md`)](./docs/okta-admin-setup.md)**: bootstrap login, Okta OIDC, importing Profiles (CSV) and Objects (SFDX), building Access Groups, and the policy simulator.
5. **[API & MCP Tools Reference (`docs/api-and-tools-reference.md`)](./docs/api-and-tools-reference.md)**: the 7 MCP tools (`list_enabled_objects`, `describe_object`, `soql_query`, `get_record`, `create_record`, `update_record`, `delete_record`), RFC 9728 discovery, and every Admin REST endpoint.

---

## 🚀 Quick Start

Requires **Node.js 22.13+** (the store uses the built-in `node:sqlite`, no flag needed).

### 1. Install dependencies
```bash
npm install
```

### 2. Configure the environment (optional for local dev)
```bash
cp .env.example .env
```
Everything has a development default. The ones that matter:

| Variable | Default | Notes |
| :--- | :--- | :--- |
| `PORT` | `3001` | Backend port when you run it directly (`node dist/index.js`, `tsx src/index.ts`). `npm run dev` uses `MCP_BACKEND_PORT` (default `3001`) and `PORTAL_PORT` (default `3000`) instead. |
| `BASE_URL` | `http://localhost:3000` | Public origin (the portal). Used in OAuth metadata and Okta redirects. |
| `MCP_BACKEND_URL` | `http://localhost:3001` | Where the portal proxies to. Read by `next dev`, and baked in at `next build` for `next start`. `npm run dev` and `npm start` also read it, `MCP_BACKEND_PORT` and `PORTAL_PORT` from `.env`; real environment variables take precedence. |
| `APP_SECRET_KEY` | development key | 64 hex chars (`openssl rand -hex 32`). **Required in production**: the backend refuses to start if it is missing, malformed, or a publicly known sample. In development and test a deterministic insecure key is used, with a warning. |
| `ADMIN_BOOTSTRAP_USERNAME` / `ADMIN_BOOTSTRAP_PASSWORD` | `admin` / `admin123` | Break-glass portal login, seeded only into an empty database. Production refuses to start while any portal account uses a publicly known password, and rotates the bootstrap account to a strong `ADMIN_BOOTSTRAP_PASSWORD`. |
| `DB_PATH` | `./data/mcp-governance.sqlite` | SQLite database file. |
| `SALESFORCE_ALLOWED_DOMAINS` | `.my.salesforce.com,.salesforce.com,.force.com` | SSRF allowlist for every Salesforce URL the server calls. |
| `TRUST_PROXY` | `false` | Express `trust proxy`. Leave `false` unless a load balancer in front of the portal appends `X-Forwarded-For`; then set `loopback` so per-IP rate limits and audit logs see real client IPs. (The Next.js proxy forwards the header unchanged, so trusting it without such a balancer lets clients forge it.) |

### 3. Start both services
```bash
npm run dev
```
This runs the Express backend on `:3001` (`tsx watch`) and the Next.js portal on `:3000` together, with prefixed logs; Ctrl+C stops both. If either service dies, the other is stopped too and the command exits non-zero (so a supervisor restarts the stack). To run them separately use `npm run dev:mcp` and `npm run dev:web`.

* **Admin Portal:** `http://localhost:3000`. Sign in with **`admin` / `admin123`** (or your `ADMIN_BOOTSTRAP_*` values).
* **Streamable HTTP MCP endpoint:** `http://localhost:3000/mcp`
* **OAuth 2.0 Protected Resource Metadata (RFC 9728):** `http://localhost:3000/.well-known/oauth-protected-resource`

Connect an MCP client with a Salesforce access token, for example Claude Code:
```bash
claude mcp add --scope user --transport http salesforce-mcp http://localhost:3000/mcp --header 'Authorization: Bearer <salesforce-access-token>'
```
Use single quotes: Salesforce session IDs contain `!`, which zsh and bash expand inside double quotes.

### 4. Production build and start
```bash
npm run build
```
```bash
APP_SECRET_KEY=<64-hex> ADMIN_BOOTSTRAP_PASSWORD=<strong> npm start
```
`npm start` runs the backend with `NODE_ENV=production` (unless you set it), so it refuses to start without a real `APP_SECRET_KEY` or while a portal account uses a publicly known password. `npm run build` compiles the backend to `dist/` (`tsconfig.server.json`) and builds the portal. `npm start` runs `node dist/index.js` and `next start` on `:3000`, using the backend port the portal was built to proxy to (`MCP_BACKEND_URL` at build time, default `:3001`).

### 5. Verify
| Command | What it runs |
| :--- | :--- |
| `npm run typecheck` | `tsc --noEmit` over the backend, portal and tests |
| `npm test` | Unit and integration suites (`test/*.test.ts`, `node:test`) plus the self-test (`src/test-self.ts`). Every suite uses its own throwaway SQLite database and mocks Salesforce at the network boundary. |
| `npm run test:e2e` | Live smoke test (`scripts/smoke-e2e.sh`): builds, boots both servers on `:3001`/`:3000` against a temp database, checks the proxy, MCP auth, admin login, the policy simulator and the audit log, then shuts everything down. Ports 3000 and 3001 must be free. |
| `npm run verify` | All of the above in order |

---

## 🗂️ Repository Structure

```text
salesforce-mcp/
├── README.md                          # Project overview & quick start
├── .env.example                       # Environment variable template
├── package.json                       # Dependencies & scripts
├── tsconfig.json                      # TypeScript config (portal, backend, tests; no emit)
├── tsconfig.server.json               # Backend build config (emits dist/)
├── next.config.ts                     # Portal -> backend rewrites
├── architecture-diagram.{jpg,svg}     # Architecture diagram
├── docs/                              # Architecture, security, setup and API reference
├── scripts/
│   ├── run-stack.mjs                  # Starts backend + portal together (npm run dev / npm start)
│   ├── smoke-e2e.sh                   # Live end-to-end smoke test (npm run test:e2e)
│   └── smoke-checks.mjs               # HTTP checks used by the smoke test
├── test/
│   ├── helpers/                       # Isolated env, in-process server, Salesforce fetch mock
│   └── *.test.ts                      # node:test suites
└── src/
    ├── app/                           # Next.js App Router Admin Portal (page.tsx, layout.tsx)
    ├── components/                    # Portal views (Salesforce, Access Matrix, Dashboard & Logs)
    ├── index.ts                       # Express app: security headers, CORS, rate limits, routes
    ├── config.ts                      # Environment config, APP_SECRET_KEY guard, bootstrap admin
    ├── db/store.ts                    # SQLite (node:sqlite, WAL) store: profiles, objects, groups, settings, audit logs
    ├── db/importers.ts                # Profile CSV and SFDX / Metadata API XML parsers
    ├── mcp/server.ts                  # Request-scoped MCP server: tool visibility + governed tool handlers
    ├── mcp/soqlGuard.ts               # Validates soql_query WHERE filters against the field allowlist
    ├── mcp/streamableHttp.ts          # Stateless Streamable HTTP (/mcp) handler and 401 challenge
    ├── rbac/policyEngine.ts           # Profile -> Group -> Tool / Object CRUD / Field policy engine
    ├── routes/adminRoutes.ts          # Admin REST API (imports, matrix, settings, users, simulator)
    ├── salesforce/client.ts           # Token verification, Org ID lock, SSRF guard, REST client, simulator tokens
    ├── security/adminAuth.ts          # Admin session JWT, CSRF, Okta OIDC + PKCE + JWKS
    ├── security/crypto.ts             # AES-256-GCM secrets at rest, timing-safe helpers, PKCE
    └── test-self.ts                   # Quick self-test against a throwaway database
```
