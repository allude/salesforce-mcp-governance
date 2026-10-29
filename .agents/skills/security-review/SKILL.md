---
name: security-review
description: >-
  Security audit checklist for reviewing changes to authentication, Salesforce REST API
  calls, RBAC policy evaluation, and PII log redaction in the Salesforce MCP Server.
---

# Security & Zero-Trust Review Skill (`security-review`)

Use this skill when reviewing code changes, debugging authentication issues, or auditing the security posture of the repository before committing.

## Security Audit Checklist

### 1. Dual-Plane Authentication Isolation
- **Runtime Plane (`POST /mcp` in `src/mcp/streamableHttp.ts`)**:
  - Must require `Authorization: Bearer <SALESFORCE_TOKEN>` on every request.
  - When missing or invalid, must return `401 Unauthorized` with RFC 9728 `WWW-Authenticate` header pointing to `/.well-known/oauth-protected-resource`.
  - Never allow portal session cookies (`sf_mcp_admin_session`) to authenticate `/mcp` calls.
  - Simulator tokens (`sf_sim_<payload>.<signature>`) must be HMAC-verified and unexpired (`verifySimulatorToken` in `src/salesforce/client.ts`); never accept an unsigned one.
  - When the Org ID lock is on (`enforceOrgIdLock` + `expectedOrgId`), identities from other orgs must be rejected, including cached ones.
  - Reflected error text in `WWW-Authenticate` must stay header-safe (`toHeaderSafe`), and async handlers must pass rejections to `next` so a bad request can never crash the process.
- **Control Plane (`/api/admin/*` in `src/routes/adminRoutes.ts` & `src/security/adminAuth.ts`)**:
  - Must require `requireAdminAuth` middleware on all routes except `/api/admin/session`, `/api/admin/login`, and `/api/admin/logout`.
  - All `POST`, `PUT`, `PATCH`, and `DELETE` requests under `requireAdminAuth` must validate `X-CSRF-Token` using `timingSafeStringEqual`.
  - No CORS on `/api/admin/*` or `/auth/*` (the portal is same-origin through the Next.js proxy). `/mcp` and `/.well-known` allow any origin but never `credentials`.

### 2. Password & Secret Storage (`src/db/store.ts`, `src/security/crypto.ts`, `src/config.ts`)
- `APP_SECRET_KEY` must be a real 64-hex key in production; `resolveAppSecretKey` throws on a missing, malformed or publicly known key. Never add a silent fallback.
- Local portal user passwords in `portal_users` must be hashed with `crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512')` with a per-user random 16-byte salt and verified with `crypto.timingSafeEqual`.
- Okta OIDC Client Secrets in `okta_config` must be encrypted at rest using `encryptSecret(...)` (AES-256-GCM) and never returned in plaintext by `GET /api/admin/overview` (only `hasClientSecret: boolean`).

### 3. SSRF & SOQL Injection Prevention (`src/salesforce/client.ts` & `src/mcp/server.ts`)
- Every Salesforce instance URL must be validated by `validateSalesforceInstanceUrl(rawUrl)` before `fetch` is called. It enforces `SALESFORCE_ALLOWED_DOMAINS` (suffix entries start with `.`), HTTPS in production, and no embedded credentials.
- Every SOQL query must validate requested field names against the caller's `evaluation.allowedFields` allowlist, validate any caller-supplied `whereClause` with `assertSafeSoqlWhereClause` (allowed fields only, no subqueries), and escape string literals it builds with `escapeSoqlString`.

### 4. PII & Customer Data Stripping in Copilot Logs (`src/db/store.ts`)
- Inspect `stripSensitivePayloadData(input)` in `src/db/store.ts`.
- Verify that `mcp_copilot_logs` never stores raw Salesforce record arrays (`records` must be replaced with `"[REDACTED N RECORDS]"`) or literal values in SOQL `WHERE` clauses (`'...'` replaced with `'[REDACTED]'`).
