# 📘 API & MCP Tools Reference

This document specifies all **MCP Streamable HTTP endpoints**, **MCP Tools**, **OAuth 2.0 Discovery metadata**, and **Admin Control Plane REST APIs**.

---

## 1. MCP Runtime & Discovery Endpoints

### `POST /mcp` (Streamable HTTP JSON-RPC 2.0 Endpoint)
Primary Model Context Protocol endpoint used by Microsoft Copilot Studio and other MCP clients.

* **Required Headers:**
  ```http
  Authorization: Bearer <USER_SALESFORCE_ACCESS_TOKEN>
  Content-Type: application/json
  Accept: application/json, text/event-stream
  ```
* **Optional Headers:**
  * `X-Salesforce-Instance-Url`: Hint for the user's Salesforce MyDomain (validated against the SSRF domain allowlist).
* **Error Response (`401 Unauthorized`):**
  Returned when the `Authorization` header is missing, expired, or invalid. Includes the RFC 9728 `WWW-Authenticate` header so Copilot Studio triggers the user OAuth sign-in flow:
  ```http
  HTTP/1.1 401 Unauthorized
  WWW-Authenticate: Bearer realm="salesforce-mcp", resource_metadata="https://mcp.yourcompany.com/.well-known/oauth-protected-resource", authorization_uri="https://login.salesforce.com/services/oauth2/authorize"
  ```

### `GET /.well-known/oauth-protected-resource`
Returns RFC 9728 OAuth 2.0 Protected Resource Metadata advertising the Salesforce authorization server and supported scopes:
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
Returns server health and transport status.

---

## 2. MCP Tools Catalog (Governed per Salesforce Profile)

Both `tools/list` and `tools/call` dynamically filter and enforce permissions based on the authenticated user's Salesforce Profile.

| Tool Name | Category | Risk Level | Input Arguments | Salesforce REST API Endpoint Called |
| :--- | :--- | :--- | :--- | :--- |
| `soql_query` | Read | Low | `{ "query": "SELECT Id, Name FROM Opportunity WHERE IsClosed = false" }` | `GET /services/data/v62.0/query?q=...` |
| `sosl_search` | Read | Low | `{ "search": "FIND {Acme} IN ALL FIELDS RETURNING Account(Id, Name)" }` | `GET /services/data/v62.0/search?q=...` |
| `describe_object` | Metadata | Low | `{ "objectName": "Opportunity" }` | `GET /services/data/v62.0/sobjects/{objectName}/describe` |
| `get_record` | Read | Low | `{ "objectName": "Opportunity", "recordId": "006...", "fields": ["Id", "Name"] }` | `GET /services/data/v62.0/sobjects/{objectName}/{recordId}` |
| `create_record` | Write | Medium | `{ "objectName": "Lead", "fields": { "LastName": "Smith", "Company": "Acme" } }` | `POST /services/data/v62.0/sobjects/{objectName}` |
| `update_record` | Write | Medium | `{ "objectName": "Opportunity", "recordId": "006...", "fields": { "StageName": "Closed Won" } }` | `PATCH /services/data/v62.0/sobjects/{objectName}/{recordId}` |
| `delete_record` | Destructive | High | `{ "objectName": "Opportunity", "recordId": "006..." }` | `DELETE /services/data/v62.0/sobjects/{objectName}/{recordId}` |

### Policy Denial Response Format
If a user in Copilot invokes a tool or targets an sObject that is disabled for their Salesforce Profile in the Admin Matrix, `tools/call` returns an MCP tool error (`isError: true`) and records a `DENY` entry in the audit log:
```json
{
  "error": "PROFILE_POLICY_DENIED",
  "message": "Action 'delete_record' is not enabled for Salesforce Profile 'Read Only'. Allowed tools: [soql_query, sosl_search, describe_object, get_record]",
  "user": "auditor@company.com",
  "salesforceProfile": "Read Only",
  "requestedTool": "delete_record",
  "targetObject": "Account"
}
```

---

## 3. Admin Control Plane & Okta OIDC Endpoints

All state-changing requests (`POST`, `PUT`, `DELETE`) under `/api/admin/*` require both a valid `sf_mcp_admin_session` `HttpOnly` cookie and a matching `X-CSRF-Token` header.

| Method & Path | Description |
| :--- | :--- |
| `GET /auth/okta/login` | Initiates Okta OIDC Authorization Code + PKCE (`S256`) login flow. |
| `GET /auth/okta/callback` | Handles Okta OIDC callback, verifies `state`, `nonce`, and remote JWKS signature, checks optional Okta group membership, and issues `sf_mcp_admin_session` cookie. |
| `GET /api/admin/session` | Returns current admin authentication status, CSRF token, and enabled login methods. |
| `POST /api/admin/login` | Authenticates via bootstrap admin credentials (when allowed). |
| `POST /api/admin/logout` | Clears the `sf_mcp_admin_session` cookie. |
| `GET /api/admin/overview` | Returns full dashboard state: Profile RBAC matrix, tools catalog, Salesforce settings, masked Okta config, and recent audit logs. |
| `PUT /api/admin/profiles/:profileId` | Updates a Salesforce Profile's enabled status, allowed MCP tools, allowed sObjects, and max query row limit. |
| `POST /api/admin/profiles` | Creates a new Salesforce Profile policy rule in the matrix. |
| `DELETE /api/admin/profiles/:profileId` | Removes a Profile policy rule from the matrix. |
| `POST /api/admin/salesforce/sync-profiles` | Queries `SELECT Id, Name, UserType, PermissionsModifyAllData FROM Profile` from a live Salesforce Org (or syncs sample enterprise profiles) into the RBAC matrix. |
| `PUT /api/admin/salesforce/settings` | Updates Salesforce login URL, API version, and fallback policy for unconfigured profiles (`read_only` vs `deny_all`). |
| `PUT /api/admin/okta` | Updates Okta OIDC SSO configuration and encrypts the Client Secret with `AES-256-GCM`. |
| `POST /api/admin/simulator/test` | Generates a signed simulator token for any Salesforce Profile and evaluates tool/object permissions. |
