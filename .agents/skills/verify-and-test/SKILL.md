---
name: verify-and-test
description: >-
  Pre-commit verification and local server lifecycle runbook for testing the Express
  MCP backend (:3001), Next.js Control Plane (:3000), and self-test suite.
---

# Verification & Local Server Lifecycle Skill (`verify-and-test`)

Use this skill before committing code changes or when restarting the local development stack.

## Architecture of the Running Stack

- **Port `3001` (Backend)**: Express server (`src/index.ts`) serving:
  - `POST /mcp` (Streamable HTTP MCP endpoint for Microsoft Copilot)
  - `GET /.well-known/oauth-protected-resource` (RFC 9728 OAuth metadata)
  - `/api/admin/*` (Control Plane REST API backed by SQLite `data/mcp-governance.sqlite`)
  - `/auth/okta/*` (Okta OIDC + PKCE login & callback)
- **Port `3000` (Frontend)**: Next.js App Router (`src/app/page.tsx`) which proxies `/api/admin/*`, `/auth/okta/*`, `/mcp`, and `/.well-known/*` to `http://127.0.0.1:3001` via `next.config.ts`.

---

## Pre-Commit Verification Commands

Always run both the automated self-test and the Next.js production build before committing:

```bash
NODE_ENV=test npx tsx src/test-self.ts && npx next build
```

### What `src/test-self.ts` Verifies:
1. Unauthenticated `GET /api/admin/session` returns `authenticated: false` (no login bypass).
2. `POST /api/admin/login` authenticates the bootstrap admin and issues a signed session cookie + CSRF token.
3. Fresh SQLite state has **0 demo data** (`0` profiles, `0` objects, `0` groups, `0` copilot logs).
4. `store.recordCopilotMcpLog` strips sensitive literal values and record arrays (`<REDACTED>`) before writing to SQLite, and cleans up after itself so the database stays empty.

---

## Restarting the Local Stack

After `npx next build` succeeds:
1. Stop any existing background tasks on ports `3001` and `3000`.
2. Start the Express MCP & SQLite backend on port `3001`:
   ```bash
   PORT=3001 npx tsx src/index.ts
   ```
3. Start the Next.js Control Plane server on port `3000`:
   ```bash
   npx next start --port 3000
   ```
