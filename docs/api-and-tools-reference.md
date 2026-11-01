# 📘 API & MCP Tools Reference

This document specifies the **MCP Streamable HTTP endpoint**, the **MCP tools**, the **OAuth 2.0 discovery metadata**, and the **Admin Control Plane REST API**.

All paths below are served by the Express backend (`src/index.ts`, port `3001`) and reached through the Next.js portal's proxy on the public origin (`BASE_URL`, default `http://localhost:3000`).

---

## 1. MCP Runtime & Discovery Endpoints

### `POST /mcp` (Streamable HTTP JSON-RPC 2.0 endpoint)
Stateless Model Context Protocol endpoint used by Microsoft Copilot Studio and other MCP clients. Every request is authenticated on its own; there are no MCP sessions.

* **Required headers:**
  ```http
  Authorization: Bearer <USER_SALESFORCE_ACCESS_TOKEN>
  Content-Type: application/json
  Accept: application/json, text/event-stream
  ```
* **Optional headers:**
  * `X-Salesforce-Instance-Url`: hint for the user's Salesforce My Domain. It must pass the SSRF allowlist (`SALESFORCE_ALLOWED_DOMAINS`), or the request is rejected.
* **`401 Unauthorized` (missing token):** JSON-RPC error `-32001` with the RFC 9728 challenge, so Copilot Studio starts the user's OAuth sign-in:
  ```http
  HTTP/1.1 401 Unauthorized
  WWW-Authenticate: Bearer realm="salesforce-mcp", resource_metadata="https://mcp.yourcompany.com/.well-known/oauth-protected-resource", authorization_uri="https://login.salesforce.com/services/oauth2/authorize"
  ```
* **`401 Unauthorized` (invalid, expired, wrong-org or forged token):** `WWW-Authenticate: Bearer error="invalid_token", error_description="...", resource_metadata="..."`. The attempt is written to the Copilot MCP log as `unverified_caller` / `DENIED`.
* **`400`:** a body that is not valid JSON gets the JSON-RPC parse error `-32700`.
* **CORS:** any origin, never with credentials. `WWW-Authenticate` and `Mcp-Session-Id` are exposed.
* **Rate limit:** 120 requests per minute per bearer token (requests without a token: per client IP).

**Simulator tokens.** `POST /api/admin/test-mcp-access` returns a `simulatorBearerToken` (`sf_sim_<payload>.<signature>`). It is HMAC-signed with a key derived from `APP_SECRET_KEY`, expires after 15 minutes, and lets an admin exercise `/mcp` as a given Profile. Calls made with it get simulated Salesforce responses and never reach Salesforce. Unsigned, tampered or expired simulator tokens get `401`.

### `GET /.well-known/oauth-protected-resource`
RFC 9728 OAuth 2.0 Protected Resource Metadata. `authorization_servers` is the instance URL from the portal's Salesforce settings:
```json
{
  "resource": "http://localhost:3000/mcp",
  "authorization_servers": ["https://login.salesforce.com"],
  "bearer_methods_supported": ["header"],
  "scopes_supported": ["api", "refresh_token", "openid", "profile", "email"],
  "resource_documentation": "http://localhost:3000/docs/architecture.md"
}
```

### `GET /healthz`
Returns `{ "status": "ok", "service": "salesforce-zero-trust-mcp", "transport": "streamable-http", "timestamp": "..." }`.

---

## 2. MCP Tools Catalog (Governed per Salesforce Profile)

`tools/list` returns only the tools granted by the Access Groups mapped to the caller's Salesforce Profile. `tools/call` re-checks the tool, the target object's CRUD permission and every field before anything is sent to Salesforce, and writes one audit row per call (`ALLOWED`, `DENIED` or `ERROR`).

| Tool | Category | Arguments | What it does |
| :--- | :--- | :--- | :--- |
| `list_enabled_objects` | Discovery | `{}` | Lists the objects the caller's groups grant, with CRUD flags and allowed-field counts. Answered from the policy; no Salesforce call. |
| `describe_object` | Discovery | `{ "objectName": "Opportunity" }` | Returns the caller's CRUD permissions and allowed fields on the object. Answered from the policy; no Salesforce call. Requires read access. |
| `soql_query` | Read | `{ "objectName": "Opportunity", "fields": ["Id", "Name", "StageName"], "whereClause": "StageName = 'Closed Won' AND Amount > 1000", "limit": 50 }` | `GET /services/data/<version>/query?q=SELECT <fields> FROM <object> [WHERE ...] LIMIT <n>`. `fields` defaults to every allowed field; `limit` defaults to 50, max 200. |
| `get_record` | Read | `{ "objectName": "Opportunity", "recordId": "006...", "fields": ["Id", "Name"] }` | `GET /services/data/<version>/sobjects/<object>/<id>?fields=...`. `fields` defaults to every allowed field. |
| `create_record` | Write | `{ "objectName": "Lead", "fields": { "LastName": "Smith", "Company": "Acme" } }` | `POST /services/data/<version>/sobjects/<object>`. Returns the new record id. |
| `update_record` | Write | `{ "objectName": "Opportunity", "recordId": "006...", "fields": { "StageName": "Closed Won" } }` | `PATCH /services/data/<version>/sobjects/<object>/<id>` |
| `delete_record` | Delete | `{ "objectName": "Opportunity", "recordId": "006..." }` | `DELETE /services/data/<version>/sobjects/<object>/<id>` |

Argument rules enforced by the server:
* Every tool except `list_enabled_objects` requires `objectName`. The object must be enabled in **Salesforce > Objects** and granted by one of the caller's groups; it is matched case-insensitively and the canonical API name is used in the request.
* Read tools need `canRead`, `create_record` needs `canCreate`, `update_record` needs `canUpdate`, `delete_record` needs `canDelete`.
* Every requested or written field must be in the caller's allowed fields: the union of the groups' field lists, intersected with the fields enabled globally.
* `whereClause` may only use allowed fields (plus `Id`), literals (strings, numbers, dates, date literals such as `LAST_N_DAYS:30`, `NULL`, `TRUE`, `FALSE`), comparison operators, `AND` / `OR` / `NOT`, `LIKE`, `IN`, `INCLUDES`, `EXCLUDES` and parentheses. Subqueries, relationship paths, bind variables and other syntax are rejected (`src/mcp/soqlGuard.ts`).
* `recordId` must be a 15- or 18-character Salesforce ID.
* Unknown tool names are denied even if a group lists them.

### Denial response format
A denied call returns an MCP tool error (`isError: true`) and is logged as `DENIED`:
```json
{
  "error": "ACCESS_DENIED",
  "tool": "delete_record",
  "targetObject": "Account",
  "profileId": "00e5g000000AbCdAAK",
  "profileName": "Read Only",
  "reason": "MCP Action 'delete_record' is not granted by any Group assigned to Profile 'Read Only' (Groups: Readers)."
}
```
A field or filter outside the allowlist returns `{ "error": "ACCESS_DENIED", "tool", "targetObject", "reason" }`, also logged as `DENIED`. Salesforce API failures and invalid arguments return `{ "error": "<message>" }` and are logged as `ERROR`.

---

## 3. Admin Control Plane & Okta OIDC Endpoints

Every route under `/api/admin/*` except `session`, `login` and `logout` requires the `sf_mcp_admin_session` `HttpOnly` cookie (`401` without it). State-changing requests (`POST`, `PUT`, `PATCH`, `DELETE`) also require a matching `X-CSRF-Token` header (`403` without it). Each successful mutation writes a Portal Admin log entry. There is no CORS on these routes; the portal calls them same-origin through the Next.js proxy.

Rate limits: 300 Admin API requests per minute per admin session (per client IP without one); 60 failed password logins per 15 minutes per client IP and 20 per username; 60 Okta login/callback requests per 15 minutes per client IP. Client IPs are only distinguished behind a load balancer that appends `X-Forwarded-For` and with `TRUST_PROXY` set accordingly; otherwise all portal traffic shares the per-IP limits.

| Method & Path | Description |
| :--- | :--- |
| `GET /auth/okta/login` | Starts the Okta OIDC Authorization Code + PKCE (`S256`) flow (only when Okta SSO is enabled in the portal). |
| `GET /auth/okta/callback` | Verifies `state`, exchanges the code with the PKCE verifier, verifies the ID token signature (remote JWKS), issuer, audience and `nonce`, checks the required Okta group, then issues the session cookie. On failure it redirects to `/?auth_error=<code>` (`okta_error`, `invalid_callback`, `expired_state`, `state_mismatch`, `group_denied`, `sso_failed`); the portal shows a fixed message per code and the details go to the Portal Admin log (`OKTA_LOGIN_FAILED` / `OKTA_LOGIN_DENIED`). |
| `GET /api/admin/session` | Current sign-in state, the session's CSRF token, and whether Okta SSO is enabled. |
| `POST /api/admin/login` | Username + password login for portal users (`{ "username", "password" }`, both strings; `400` otherwise). The bootstrap admin is seeded from `ADMIN_BOOTSTRAP_USERNAME` / `ADMIN_BOOTSTRAP_PASSWORD` (default `admin` / `admin123`). |
| `POST /api/admin/logout` | Clears the session cookie. |
| `GET /api/admin/overview` | Full portal state: stats (totals over every logged call: allowed, denied by policy, and Salesforce/argument errors), profiles, objects (with fields), groups, profile-group mappings, the last 150 Copilot MCP and Portal Admin log entries, Okta settings (`hasClientSecret` only, never the secret), Salesforce settings and portal users. |
| `POST /api/admin/profiles` | Add or update a Salesforce Profile (`{ "id": "00e...", "name": "..." }`). |
| `POST /api/admin/profiles/import-csv` | Bulk upsert Profiles from `{ "csvText": "id,name\n00e...,System Administrator" }` or `{ "rows": [{ "id", "name" }] }`. Quoted values may contain commas. A header row naming the columns (`Id,Name`, in any order, extra columns ignored) is used to find them; otherwise the first two columns are id and name. |
| `DELETE /api/admin/profiles/:id` | Delete a Profile (and its group mappings). |
| `POST /api/admin/objects` | Add or update an Object and its fields (`{ "objectName", "label", "fields": [{ "fieldName", "label", "fieldType", "isCustom", "required", "enabled" }] }`). Names must be Salesforce API names (`400` otherwise). `enabled` is applied when sent; when omitted, existing fields keep their toggle. |
| `POST /api/admin/objects/import-sfdx-files` | Import Objects and Fields from SFDX source files uploaded by the browser (`{ "files": [{ "relativePath", "content" }] }`, up to 25 MB). Supports `objects/<Obj>/<Obj>.object-meta.xml`, `objects/<Obj>/fields/<Field>.field-meta.xml` and classic `objects/<Obj>.object`. Re-imports keep manual toggles. |
| `POST /api/admin/objects/import-local-folder` | Import from a directory on the server (`{ "folderPath": "/path/to/force-app/main/default/objects" }`) and remember the path. |
| `PUT /api/admin/objects/:objectName/toggle` | Enable or disable an Object globally (`{ "enabled": true }`). |
| `PUT /api/admin/objects/:objectName/fields/:fieldName/toggle` | Enable or disable a Field globally (`{ "enabled": false }`). |
| `DELETE /api/admin/objects/:objectName` | Delete an Object and its fields, and remove it from every Access Group. |
| `POST /api/admin/groups` | Create (no `id`) or update (with `id`) an Access Group (`{ "id"?, "name", "description", "allowedActions": ["soql_query", ...], "objectPermissions": [{ "objectName", "canRead", "canCreate", "canUpdate", "canDelete", "allowedFields": [...] }] }`). `409` if another group already has the name. |
| `DELETE /api/admin/groups/:id` | Delete a group (and its profile mappings). |
| `PUT /api/admin/profile-groups/:profileId` | Replace the groups mapped to a Profile (`{ "groupIds": [...] }`), atomically. `400` (and no change) if any group id does not exist. |
| `PUT /api/admin/okta` | Update Okta SSO settings (`enabled`, `oktaDomain`, `issuer`, `clientId`, `clientSecret`, `redirectUri`, `adminGroup`). The client secret is encrypted with AES-256-GCM and never returned. |
| `PUT /api/admin/sf-settings` | Update Salesforce settings (`instanceUrl`, `apiVersion`, `expectedOrgId`, `enforceOrgIdLock`, `sfdxObjectsFolderPath`). `400` if the instance URL is outside `SALESFORCE_ALLOWED_DOMAINS`, the API version is not like `v62.0`, the Org ID is not a `00D...` ID, or the lock is enabled without an Org ID. |
| `POST /api/admin/portal-users` | Create or update a portal user (`{ "username", "displayName", "password", "role" }`). Usernames are case-insensitive; updating a password keeps the user's role and display name unless new ones are sent. |
| `DELETE /api/admin/portal-users/:username` | Delete a portal user. The last remaining user cannot be deleted. |
| `POST /api/admin/test-mcp-access` | Policy simulator: `{ "profileId", "toolName", "targetObject" }` returns the evaluation, the Profile's effective permissions and a signed 15-minute `simulatorBearerToken`, and logs the simulated call in the Copilot MCP log. |
