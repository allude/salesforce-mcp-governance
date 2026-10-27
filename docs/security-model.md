# 🔐 Zero-Trust Security Model & Threat Mitigations

This document details the security architecture implemented across both the **Streamable HTTP MCP Runtime (`/mcp`)** and the **Admin Control Plane (`/`, `/api/admin/*`)**.

---

## 1. Zero Shared Service Accounts on `/mcp`

* **Threat:** Many integrations use a single "System Admin" integration user token on the backend, meaning any Copilot user can accidentally (or via prompt injection) query or modify executive salaries, closed deals, or restricted objects.
* **Mitigation:** The `/mcp` endpoint **never** uses a shared token. Every request requires a per-user `Authorization: Bearer <token>` issued to the individual end user by Salesforce.
* **Verification:** In [`src/salesforce/client.ts`](../src/salesforce/client.ts), `resolveSalesforceUserFromToken()` validates the token against Salesforce's `/services/oauth2/userinfo` endpoint and queries `SELECT Id, Username, Name, Email, ProfileId, Profile.Name FROM User WHERE Id = '<userId>'`.
* **Safe Caching:** Verified user identity and Profile metadata are cached in memory for 120 seconds keyed by a **SHA-256 cryptographic digest** (`hashToken()`) of the Bearer token—raw tokens are never written to disk or audit logs.

---

## 2. Two-Stage Profile RBAC Enforcement (`tools/list` + `tools/call`)

Even when a user has Salesforce permissions to delete records in the Salesforce UI, you may not want an AI agent (Copilot) to be able to execute `delete_record` or modify certain objects for that user's Salesforce Profile.

Implemented in [`src/rbac/policyEngine.ts`](../src/rbac/policyEngine.ts) and [`src/mcp/server.ts`](../src/mcp/server.ts):

1. **Discovery-Time Filtering (`tools/list`):**
   When Copilot connects to `/mcp` with a user's Bearer token, `getAllowedToolsForUser()` filters the MCP tool catalog so Copilot only sees the tools enabled for that user's Salesforce Profile.
2. **Execution-Time Enforcement (`tools/call`):**
   Every tool call runs `evaluateProfilePolicy(user, toolName, targetObject, clientIp)`:
   * Checks if the user's Salesforce Profile is **active/enabled**.
   * Checks if the **MCP Tool** (`soql_query`, `sosl_search`, `describe_object`, `get_record`, `create_record`, `update_record`, `delete_record`) is checked for that Profile.
   * Checks if the **Target sObject** (extracted from `args.objectName` or parsed from the `FROM <sObject>` clause of a SOQL query) is in the Profile's `allowedObjects` list (or `*`).
   * Enforces the Profile's **Max Query Limit** (`enforceSoqlLimit()`) on every SOQL query so an LLM cannot pull 50,000 rows in a single call.
   * Enforces read-only `SELECT` validation on `soql_query` and strict regex validation on `objectName` and 15/18-character Salesforce `recordId` values.

---

## 3. Server-Side Request Forgery (SSRF) Protection

* **Threat:** If an attacker passes a crafted `X-Salesforce-Instance-Url` header or spoofed userinfo URL pointing to internal cloud metadata (`http://169.254.169.254`) or an external attacker server, the MCP server could leak the Bearer token.
* **Mitigation:** `validateSalesforceInstanceUrl()` in [`src/salesforce/client.ts`](../src/salesforce/client.ts) strictly parses the URL, requires `https:` in production, and verifies the hostname against the trusted Salesforce domain suffix allowlist (`.my.salesforce.com`, `.salesforce.com`, `.force.com`).

---

## 4. Okta OIDC SSO with PKCE (`S256`) & Remote JWKS Verification

Implemented in [`src/security/adminAuth.ts`](../src/security/adminAuth.ts):

1. **PKCE (`S256`) + State + Nonce:**
   When an administrator clicks **Sign in with Okta SSO** (`/auth/okta/login`), the server generates a cryptographically random 32-byte `code_verifier`, computes its SHA-256 base64url `code_challenge`, and generates random `state` and `nonce` values stored in a short-lived (10-minute) signed `HttpOnly` cookie.
2. **Cryptographic JWKS Verification:**
   In `/auth/okta/callback`, after exchanging the authorization code and `code_verifier` at Okta's token endpoint, the server fetches Okta's public JSON Web Key Set (`jwks_uri`) via `jose.createRemoteJWKSet()` and verifies:
   * Digital signature of the `id_token`
   * `iss` (Okta Issuer URL)
   * `aud` (Okta Client ID)
   * `exp` (Expiration timestamp)
   * `nonce` (Constant-time comparison with `timingSafeStringEqual`)
3. **Optional Okta Group RBAC:**
   If `requiredGroup` (e.g., `MCP-Administrators`) is configured, the server inspects the `groups` claim in the verified Okta ID token and denies access if the user is not a member.

---

## 5. Admin Session Hardening, CSRF Protection & Encryption at Rest

* **Encrypted Secrets at Rest (`AES-256-GCM`):**
  Okta Client Secrets stored in SQLite (`okta_settings.client_secret_enc`) are encrypted using `AES-256-GCM` with a random 96-bit IV and 128-bit authentication tag ([`src/security/crypto.ts`](../src/security/crypto.ts)). The Admin API masks secrets as `••••••••` when returning configuration to the browser.
* **Signed `HttpOnly` Session Cookies:**
  Admin sessions use `HS256` signed JWTs stored in an `HttpOnly`, `SameSite=Lax`, `Secure` (in production) cookie (`sf_mcp_admin_session`) with an 8-hour expiration.
* **Synchronizer / Double-Submit CSRF Protection:**
  Every admin session embeds a random `csrfToken`. All state-changing Admin API requests (`POST`, `PUT`, `PATCH`, `DELETE` under `/api/admin/*`) require a matching `X-CSRF-Token` header verified using constant-time comparison (`timingSafeStringEqual()`).
* **Constant-Time Credential Verification:**
  Bootstrap login compares both email and password hashes using `crypto.timingSafeEqual` over SHA-256 digests so attackers cannot use response-time side channels.
* **Helmet CSP & Rate Limiting:**
  Configured in [`src/index.ts`](../src/index.ts) using `helmet` Content Security Policy headers and `express-rate-limit` on both `/auth/*`, `/api/admin/*`, and `/mcp`.

---

## 6. Immutable Governance Audit Trail

Every Admin login, Okta SSO event, Profile Sync, Policy Matrix update, and runtime MCP tool decision (`PERMIT` or `DENY`) is logged in the `audit_logs` SQLite table with timestamp, actor email, Salesforce Profile name, tool name, target sObject, decision, reason, and client IP address.
