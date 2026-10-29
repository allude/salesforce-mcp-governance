---
name: verify-and-test
description: >-
  Pre-commit verification and local server lifecycle runbook for testing the Express
  MCP backend (:3001), Next.js Control Plane (:3000), test suites, and live E2E smoke test.
---

# Verification & Local Server Lifecycle Skill (`verify-and-test`)

Use this skill before committing code changes or when restarting the local development stack.

## Architecture of the Running Stack

- **Port `3001` (Backend)**: Express server (`src/index.ts`) serving:
  - `POST /mcp` (Streamable HTTP MCP endpoint for Microsoft Copilot)
  - `GET /.well-known/oauth-protected-resource` (RFC 9728 OAuth metadata)
  - `/api/admin/*` (Control Plane REST API backed by SQLite `data/mcp-governance.sqlite`)
  - `/auth/okta/*` (Okta OIDC + PKCE login & callback)
  - `/docs/*` (read-only docs referenced by the OAuth metadata). It serves no UI: `GET /` redirects to the portal.
- **Port `3000` (Frontend)**: Next.js App Router (`src/app/page.tsx`) which proxies `/api/admin/*`, `/auth/okta/*`, `/mcp`, `/.well-known/*`, `/healthz` and `/docs/*` to `MCP_BACKEND_URL` (default `http://localhost:3001`) via `next.config.ts`.

---

## Pre-Commit Verification Commands

Run the full gate before committing (ports 3000 and 3001 must be free for the last step):

```bash
npm run verify
```

It runs, in order:

| Step | Command | What it checks |
| :--- | :--- | :--- |
| Typecheck | `npm run typecheck` | `tsc --noEmit` over backend, portal and tests |
| Tests | `npm test` | `test/*.test.ts` (node:test, each file gets its own throwaway SQLite DB and a Salesforce `fetch` mock) plus `src/test-self.ts` |
| Build | `npm run build` | Backend compile to `dist/` (`tsconfig.server.json`) + `next build` |
| Live E2E | `npm run test:e2e` | `scripts/smoke-e2e.sh`: boots `node dist/index.js` on :3001 and `next start` on :3000 against a temp DB, checks the proxy, the `/mcp` 401 challenge, admin login + CSRF, the policy simulator and the audit log, then kills both servers |

Run a single suite while iterating (single process, hard timeout so nothing hangs):

```bash
NODE_ENV=test perl -e 'alarm shift; exec @ARGV' 180 node --import tsx --test test/policy-engine.test.ts
```

Test rules: import `./helpers/env.js` first in every test file (it isolates the DB and secrets), mock Salesforce only through `installSalesforceMock()` from `test/helpers/salesforceMock.ts`, and never point a test at the real `data/` database.

---

## Restarting the Local Stack

1. Stop any existing processes on ports `3001` and `3000`.
2. Development (watch mode, both services, prefixed logs, Ctrl+C stops both):
   ```bash
   npm run dev
   ```
3. Production-style (after `npm run build`):
   ```bash
   npm start
   ```
   In production set `NODE_ENV=production`, a real `APP_SECRET_KEY` (64 hex chars) and, for an empty database, `ADMIN_BOOTSTRAP_PASSWORD`. The backend refuses to start otherwise.
