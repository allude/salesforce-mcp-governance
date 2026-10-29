# 🔐 Zero-Trust Security Model & Threat Mitigations

This document describes the security controls in the **Streamable HTTP MCP runtime (`/mcp`)** and the **Admin Control Plane (Next.js portal + `/api/admin/*`)**, with pointers to the code that implements each one.

---

## 1. Zero Shared Service Accounts on `/mcp`

* **Threat:** a single integration-user token on the backend lets any Copilot user (or a prompt injection) read or change data that user could never see.
* **Mitigation:** `/mcp` never uses a shared token. Every request must carry the end user's own Salesforce `Authorization: Bearer <token>`, and every Salesforce call is made with that token, so Salesforce still enforces sharing rules, object CRUD and field-level security for that user.
* **Verification:** `resolveSalesforceUserFromToken()` in [`src/salesforce/client.ts`](../src/salesforce/client.ts) validates the token against `/services/oauth2/userinfo` and then reads `SELECT Id, Username, Name, Email, ProfileId, Profile.Name FROM User WHERE Id = '<userId>'` with the same token.
* **Safe caching:** the verified identity (never the token) is cached for 120 seconds under a SHA-256 digest of the token (`hashToken()`), capped at 5,000 entries. Raw tokens are never written to disk or to the audit log.
* **Challenge, not redirect:** without a valid token, `/mcp` returns `401` with an RFC 9728 `WWW-Authenticate` header ([`src/mcp/streamableHttp.ts`](../src/mcp/streamableHttp.ts)). Reflected error text is reduced to printable ASCII so a crafted token can never break the header or crash the process, and every async handler passes failures to Express's error handler.

---

## 2. Profile → Access Group → Tool / Object / Field Enforcement

Implemented in [`src/rbac/policyEngine.ts`](../src/rbac/policyEngine.ts) and [`src/mcp/server.ts`](../src/mcp/server.ts).

* **Default deny.** A caller whose Salesforce Profile is not registered in **Salesforce > Profiles**, or has no Access Groups, sees no tools and every call is denied.
* **Profile matching.** The caller's `ProfileId` (from the `User` lookup) is matched to registered Profiles by ID, treating the 15- and 18-character forms of the same ID as equal. If no ID matches, the Profile name is used as a fallback. If the `User`/`Profile` lookup itself fails (e.g. the token lacks the `api` scope), the caller gets no Profile at all, so no tools; the server never guesses one.
* **Effective permissions** are the union of the Profile's groups: allowed MCP actions, per-object `canRead` / `canCreate` / `canUpdate` / `canDelete`, and allowed fields, intersected with the Objects and Fields enabled globally in **Salesforce > Objects**. An object entry that grants no CRUD flag contributes nothing (not even its fields), so the result never depends on the order of groups. Deleting an Object removes it from every group, so re-importing it cannot silently restore access. Profile → Group mappings are replaced atomically, and unknown group IDs are rejected before anything changes.
* **Discovery-time filtering:** `getVisibleToolsForUser()` limits `tools/list` to the granted actions.
* **Execution-time enforcement:** `evaluateMcpToolCall()` runs before any Salesforce call and denies:
  * unknown tool names, even if a group lists them;
  * tools not granted by any group;
  * object-scoped tools called without an `objectName`;
  * objects that are disabled or not granted, and operations without the matching CRUD flag.
* **Field and filter allowlists:** the handlers reject any requested, returned or written field outside the allowed set. `soql_query`'s `whereClause` is tokenised by [`src/mcp/soqlGuard.ts`](../src/mcp/soqlGuard.ts) and may only reference allowed fields and literals. Subqueries, relationship paths, bind variables and other syntax are refused, so a filter cannot be used to probe a hidden field or another object. `recordId` must be a 15/18-character ID before it goes into a URL path. Object and field names must be plain Salesforce API names (`Account`, `Amount__c`): the SFDX importer skips anything else, `POST /api/admin/objects` rejects it, and the tool handlers re-check every name before putting it into SOQL or a REST path, so crafted metadata cannot smuggle a subquery or relationship path into a query. Query limits are capped at 200 rows.
* **Logging:** a denial is returned as an MCP tool error with `ACCESS_DENIED` and logged as `DENIED`; Salesforce or argument errors are logged as `ERROR`.

---

## 3. Server-Side Request Forgery (SSRF) Protection

* **Threat:** a crafted `X-Salesforce-Instance-Url` header, a mis-set instance URL, or a userinfo response pointing at internal hosts (`http://169.254.169.254`) or an attacker's server could make the backend send requests, and the user's Bearer token, somewhere else.
* **Mitigation:** `validateSalesforceInstanceUrl()` in [`src/salesforce/client.ts`](../src/salesforce/client.ts) runs on every URL before `fetch`: the instance-URL hint, the configured instance URL, and the `custom_domain` / `rest` URLs returned by userinfo. It requires the host to match `SALESFORCE_ALLOWED_DOMAINS` (entries starting with `.` match that domain and its subdomains, so `login.salesforce.com.evil.com` is rejected), requires `https:` in production (`http:` only outside production), and rejects URLs with embedded credentials.

---

## 4. Org ID Lock

When **Reject tokens from other orgs** is on and an expected Org ID is set (**Settings > Portal Login & Okta SSO > Salesforce Connection & Org ID Lock**, or `PUT /api/admin/sf-settings`), tokens from any other Salesforce org are rejected with `401`, including identities that were already cached. 15- and 18-character Org IDs are compared on their 15-character form.

---

## 5. Signed Policy-Simulator Tokens

The portal's policy simulator (`POST /api/admin/test-mcp-access`, admins only) issues `sf_sim_<payload>.<signature>` tokens so an admin can exercise `/mcp` as a given Profile. Each token is signed with HMAC-SHA256 under a sub-key derived (HKDF) from `APP_SECRET_KEY` and expires after 15 minutes. Simulated calls never reach Salesforce. Unsigned, tampered or expired simulator tokens are rejected.

---

## 6. Okta OIDC SSO with PKCE (`S256`) & Remote JWKS Verification

Implemented in [`src/security/adminAuth.ts`](../src/security/adminAuth.ts):

1. **PKCE (`S256`) + state + nonce:** `/auth/okta/login` generates a random 32-byte `code_verifier`, its SHA-256 `code_challenge`, and random `state` and `nonce`, stored in a signed, `HttpOnly`, 10-minute cookie.
2. **Callback verification:** `/auth/okta/callback` checks `state` in constant time, exchanges the code with the `code_verifier`, then verifies the `id_token` with Okta's JWKS (`jose.createRemoteJWKSet()`): signature, `iss`, `aud` (client ID) and `exp`. The `nonce` claim is required and compared in constant time.
3. **Required Okta group:** if an admin group is configured (default `MCP-Admins`), the `groups` claim must contain it, or the login is denied and logged as `OKTA_LOGIN_DENIED`.
4. **Errors:** every other callback failure is logged as `OKTA_LOGIN_FAILED` with its details, and the browser is redirected with a fixed error code only (`/?auth_error=state_mismatch` etc.). The portal maps codes to fixed messages, so a crafted link cannot put attacker-chosen text on the login screen.

---

## 7. Admin Sessions, CSRF, CORS & Rate Limits

* **Session cookie:** admin sessions are `HS256` JWTs in an `HttpOnly`, `SameSite=Lax` cookie (`sf_mcp_admin_session`, `Secure` in production) that expire after 8 hours. A password session stops working as soon as its portal user is deleted.
* **CSRF:** every session embeds a random `csrfToken`. All state-changing Admin API requests except `login` and `logout` require a matching `X-CSRF-Token` header, compared with `timingSafeStringEqual()` (the portal sends it on logout too).
* **CORS:** the Admin API and Okta routes send no CORS headers. The portal reaches them same-origin through the Next.js proxy, so no other origin can read admin responses or the CSRF token. `/mcp` and `/.well-known` allow any origin, but never with credentials.
* **Rate limits** ([`src/index.ts`](../src/index.ts)): `/mcp` allows 120 requests per minute per bearer token, and the Admin API 300 per minute per admin session; requests without a token or session are limited per client IP, so anonymous traffic cannot use up an authenticated caller's allowance. Failed password logins are limited to 60 per 15 minutes per client IP and 20 per 15 minutes per username, and the Okta routes to 60 per 15 minutes per client IP.
* **Client IP:** `TRUST_PROXY` defaults to `false`, because the Next.js proxy forwards `X-Forwarded-For` unchanged and a client could otherwise forge it to dodge per-IP limits and falsify audit-log IPs. With the default, every request arriving through the portal has the portal's address, so the per-IP limits (anonymous traffic, failed logins, Okta routes) act as one shared limit and audit logs show the proxy IP. Behind a load balancer or TLS proxy that appends the client address to `X-Forwarded-For`, set `TRUST_PROXY=loopback` (or a hop count / subnet list) to get real client IPs.
* **Headers:** `helmet` sets HSTS, `X-Content-Type-Options`, a deny-by-default Content Security Policy and frame protection. The backend serves no HTML.

---

## 8. Secrets, Passwords & Fail-Fast Configuration

* **`APP_SECRET_KEY`** ([`src/config.ts`](../src/config.ts)) is the 32-byte key for AES-256-GCM, session JWTs and simulator-token signing. In production the backend refuses to start if it is missing, not 64 hex characters, or a publicly known value (the development fallback or the `.env.example` sample). In development and test it falls back to a deterministic, insecure key and prints a warning.
* **Secrets at rest:** the Okta client secret is stored in `okta_config.client_secret_enc`, encrypted with AES-256-GCM (random 96-bit IV, 128-bit auth tag) by [`src/security/crypto.ts`](../src/security/crypto.ts). The Admin API only ever returns `hasClientSecret`.
* **Portal passwords** are hashed with PBKDF2-SHA512 (100,000 iterations, per-user random 16-byte salt) and verified with `crypto.timingSafeEqual`.
* **Bootstrap admin:** an empty database is seeded with one portal user from `ADMIN_BOOTSTRAP_USERNAME` / `ADMIN_BOOTSTRAP_PASSWORD` (default `admin` / `admin123`). In production the backend refuses to seed a publicly known password (`admin123`, or the old sample `ChangeMeInProd!2026`). It also refuses to start while any existing portal account still uses one (for example a database created by `npm run dev`); setting `ADMIN_BOOTSTRAP_USERNAME` to that account and a strong `ADMIN_BOOTSTRAP_PASSWORD` rotates it at startup.
* **Input hardening:** every async route hands failures to Express's error handler, login rejects non-string credentials with `400`, and the entry process logs (rather than dies on) any unhandled promise rejection.

---

## 9. Governance Audit Trail (PII Stripped)

* **`mcp_copilot_logs`:** one row per `tools/call` (`ALLOWED`, `DENIED` or `ERROR`), per rejected token (`unverified_caller`), and per policy simulation, with the Salesforce user, Profile, matched groups, tool, target object and latency. `stripSensitivePayloadData()` in [`src/db/store.ts`](../src/db/store.ts) runs on every payload before it is stored: record arrays become `[REDACTED N RECORDS]`, string literals in SOQL become `'[REDACTED]'`, and any other value except a short list of structural keys (object, tool and field names, limits, IDs) becomes `<REDACTED:type>`.
* **`portal_admin_logs`:** every portal login, failed login, logout, Okta login or denial, and every successful mutation, with admin username, auth method, action code, target and client IP.
* Neither table can be cleared through the API.

---

## 10. Known Limitations

* The Profile **name** fallback means a token from another org whose Profile has the same name as a registered one is matched. Its calls still run with that user's own token against their own org. Turn on the **Org ID lock** to reject other orgs entirely.
* `POST /api/admin/objects/import-local-folder` reads XML files from any directory the backend process can access. It is admin-only and audit-logged.
* The per-username login limit means anyone can temporarily block password sign-in for a known username (20 failures, 15 minutes). Okta SSO is unaffected.
* Logging out clears the session cookie, but a stolen session JWT stays valid until it expires (8 hours), and changing a portal user's password does not end their existing sessions (deleting the user does). Rotating `APP_SECRET_KEY` invalidates every session.
