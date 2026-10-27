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
- **Control Plane (`/api/admin/*` in `src/routes/adminRoutes.ts` & `src/security/adminAuth.ts`)**:
  - Must require `requireAdminAuth` middleware on all routes except `/api/admin/session`, `/api/admin/login`, and `/api/admin/logout`.
  - All `POST`, `PUT`, `PATCH`, and `DELETE` requests under `requireAdminAuth` must validate `X-CSRF-Token` using `timingSafeStringEqual`.

### 2. Password & Secret Storage (`src/db/store.ts` & `src/security/crypto.ts`)
- Local portal user passwords in `portal_users` must be hashed with `crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512')` with a per-user random 16-byte salt and verified with `crypto.timingSafeEqual`.
- Okta OIDC Client Secrets in `okta_config` must be encrypted at rest using `encryptSecret(...)` (AES-256-GCM) and never returned in plaintext by `GET /api/admin/overview` (only `hasClientSecret: boolean`).

### 3. SSRF & SOQL Injection Prevention (`src/salesforce/client.ts` & `src/mcp/server.ts`)
- Every Salesforce instance URL must be validated by `validateSalesforceInstanceUrl(rawUrl)` before `fetch` is called.
- Every SOQL query must validate requested field names against the caller's `evaluation.allowedFields` allowlist and escape string literals with `escapeSoqlString`.

### 4. PII & Customer Data Stripping in Copilot Logs (`src/db/store.ts`)
- Inspect `stripSensitivePayloadData(input)` in `src/db/store.ts`.
- Verify that `mcp_copilot_logs` never stores raw Salesforce record arrays (`records` must be replaced with `"[REDACTED N RECORDS]"`) or literal values in SOQL `WHERE` clauses (`'...'` replaced with `'[REDACTED]'`).
