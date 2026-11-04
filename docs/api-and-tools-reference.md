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
* **Rate limit:** 120 requests per minute per bearer token (requests without a token: per client IP). Where a trusted proxy named the client (`TRUST_PROXY` set and an `X-Forwarded-For` address that differs from the connecting one), rejected tokens are also limited to 30 per minute per client IP (IPv6: per `/64`); after that, tokens that have not verified within the last hour get `429` with `Retry-After` until the window ends, without reaching Salesforce. Otherwise, including the default `TRUST_PROXY=false`, the connecting address may be the portal proxy that every caller shares, so that limit is off. In every mode, a token Salesforce rejected is refused for 5 minutes without another call. Salesforce verifications are capped at 8 at a time with 100 waiting; past that, or after 10 seconds of waiting, the answer is `503` with `Retry-After: 5`. The same `503` (not `401`) answers when Salesforce times out, cannot be reached, or returns `5xx` / `429`, so clients keep their token and retry. See [Security model](security-model.md) for details.

**Simulator tokens.** Outside production, `POST /api/admin/test-mcp-access` returns a `simulatorBearerToken` (`sf_sim_<payload>.<signature>`). It is HMAC-signed with a key derived from `APP_SECRET_KEY`, expires after 15 minutes, and lets an admin exercise `/mcp` as a given Profile. Calls made with it get simulated Salesforce responses and never reach Salesforce, and are logged with `simulated: true` under the name `simulated:<name>`. Each simulation also writes a `SIMULATE_MCP_CALL` portal admin log row naming the admin. Unsigned, tampered or expired simulator tokens get `401`. In production no simulator token is issued, and `/mcp` answers any `sf_sim_` token with `401`, logged and counted like any other rejected token.

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

`tools/list` returns only the tools granted by the Access Groups mapped to the caller's Salesforce Profile. `tools/call` re-checks the tool, the target object's CRUD permission, every field, the `whereClause` and the arguments before anything is sent to Salesforce (the decision pipeline in the [Security model](security-model.md)), and writes one audit row per call (`ALLOWED`, `DENIED` or `ERROR`).

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
* Every tool except `list_enabled_objects` requires `objectName`; `list_enabled_objects` ignores one. The object must be enabled in **Salesforce > Objects** and granted by one of the caller's groups; it is matched case-insensitively and the canonical API name is used in the request.
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
A field or filter outside the allowlist returns `{ "error": "ACCESS_DENIED", "tool", "targetObject", "reason" }`, also logged as `DENIED`. Invalid arguments (a malformed `recordId`, a `fields` value that is not a map of field values, a field name that cannot be read as text, a `whereClause` that cannot be read) return `{ "error": "<message>" }` and are logged as `DENIED`, since the call was refused; a missing `objectName`, or one that is not an API name, gets the `ACCESS_DENIED` payload above. Salesforce API failures return `{ "error": "<message>" }` and are logged as `ERROR`, as is a call the policy could not be evaluated for (`{ "error": "The access policy could not be evaluated, so the call is refused." }`, or `{ "error": "Object '<name>' is not a valid Salesforce API name." }` for an Object stored under such a name before names were validated).

---

## 3. Admin Control Plane & Okta OIDC Endpoints

Every route under `/api/admin/*` except `session`, `login` and `logout` requires the `sf_mcp_admin_session` `HttpOnly` cookie (`401` without it). State-changing requests (`POST`, `PUT`, `PATCH`, `DELETE`) also require a matching `X-CSRF-Token` header (`403` without it). Each successful mutation writes a Portal Admin log entry (see [Portal Admin log rows](#portal-admin-log-rows)). A request refused with `400`, `403`, `404` or `409` writes none, except where the refusal is itself the record (`LOGIN_FAILED`, `SYNC_*_FROM_ORG_FAILED`, `CONNECT_SALESFORCE_ORG_FAILED`, `GENERATE_SF_JWT_CERT_DENIED`). There is no CORS on these routes; the portal calls them same-origin through the Next.js proxy.

Every response from the Admin API router carries an `X-Correlation-Id` header: a UUID the server makes for that request. Every Portal Admin log row the request writes carries the same value as `correlationId`. An `X-Correlation-Id` sent by the client is ignored.

Rate limits: 300 Admin API requests per minute per admin session (per client IP without one); 60 failed password logins per 15 minutes per client IP and 20 per username; 60 Okta login/callback requests per 15 minutes per client IP. Client IPs are only distinguished behind a load balancer that appends `X-Forwarded-For` and with `TRUST_PROXY` set accordingly; otherwise all portal traffic shares the per-IP limits.

| Method & Path | Description |
| :--- | :--- |
| `GET /auth/okta/login` | Starts the Okta OIDC Authorization Code + PKCE (`S256`) flow (only when Okta SSO is enabled in the portal). |
| `GET /auth/okta/callback` | Verifies `state`, exchanges the code with the PKCE verifier, verifies the ID token signature (remote JWKS), issuer, audience and `nonce`, checks the required Okta group, then issues the session cookie. On failure it redirects to `/?auth_error=<code>` (`okta_error`, `invalid_callback`, `expired_state`, `state_mismatch`, `group_denied`, `sso_failed`); the portal shows a fixed message per code and the details go to the Portal Admin log (`OKTA_LOGIN_FAILED` / `OKTA_LOGIN_DENIED`). |
| `GET /api/admin/session` | Current sign-in state, the session's CSRF token, and whether Okta SSO is enabled. |
| `POST /api/admin/login` | Username + password login for portal users (`{ "username", "password" }`, both strings; `400` otherwise). The bootstrap admin is seeded from `ADMIN_BOOTSTRAP_USERNAME` / `ADMIN_BOOTSTRAP_PASSWORD` (default `admin` / `admin123`). |
| `POST /api/admin/logout` | Clears the session cookie. |
| `GET /api/admin/overview` | Full portal state: `serverTime` (the server's clock as an ISO timestamp), stats (totals over every logged call: allowed, denied by the policy or for invalid arguments, and errors, which are Salesforce failures), profiles, objects (with fields), groups, profile-group mappings, the Copilot MCP and Portal Admin log entries (each list holds the latest 150 ordinary rows plus the latest 50 simulated rows, merged newest first, and the Copilot MCP list also the latest 50 rejected-token rows; simulated rows carry `simulated: true` or the `SIMULATE_MCP_CALL` action, rejected-token rows the `unverified_caller` user and the `mcp_authenticate` tool), `logCaps` (those per-kind limits, which the Logs views state), `policyRevision` (the [policy revision](#policy-revision) the profiles, objects, groups and mappings are at), Okta settings (`hasClientSecret` only, never the secret), Salesforce settings and portal users. |
| `GET /api/admin/mcp-logs` | Read-only page of the whole Copilot MCP log, newest first: `{ "rows", "nextBefore" }`. Each row carries `seq`, its write order (the `/overview` rows carry it too). Pass `before=<nextBefore>` for the next older page; `nextBefore` is `null` after the oldest matching row. `limit` is 1 to 1000 (default 200). Optional filters: `status` (`ALLOWED`, `DENIED`, `ERROR`), `simulated` (`true`, `false`), `tool`, `object`. `400` for any malformed parameter. The portal uses it for **Load older** and for CSV exports. |
| `GET /api/admin/portal-logs` | The same paging over the whole Portal Admin log, with optional `action` and `authMethod` (`password`, `okta_sso`) filters. Rows are described under [Portal Admin log rows](#portal-admin-log-rows). |
| `POST /api/admin/profiles` | Add or update a Salesforce Profile (`{ "id": "00e...", "name": "..." }`). |
| `POST /api/admin/profiles/import-csv` | Bulk upsert Profiles from `{ "csvText": "id,name\n00e...,System Administrator" }` or `{ "rows": [{ "id", "name" }] }`. Quoted values may contain commas. A header row naming the columns (`Id,Name`, in any order, extra columns ignored) is used to find them; otherwise the first two columns are id and name. Every row is saved or none is. |
| `DELETE /api/admin/profiles/:id` | Delete a Profile (and its group mappings). |
| `POST /api/admin/objects` | Add or update an Object and its fields (`{ "objectName", "label", "fields": [{ "fieldName", "label", "fieldType", "isCustom", "required", "enabled" }] }`). Names must be Salesforce API names (`400` otherwise). `enabled` is applied when sent; when omitted, existing fields keep their toggle. |
| `POST /api/admin/objects/import-sfdx-files` | Import Objects and Fields from SFDX source files uploaded by the browser (`{ "files": [{ "relativePath", "content" }] }`, up to 25 MB). Supports `objects/<Obj>/<Obj>.object-meta.xml`, `objects/<Obj>/fields/<Field>.field-meta.xml` and classic `objects/<Obj>.object`. Re-imports keep manual toggles. Every Object is saved or none is. |
| `POST /api/admin/objects/import-local-folder` | Development only: import from a directory on the server (`{ "folderPath": "/path/to/force-app/main/default/objects" }`) and remember the path. `403` in production. |
| `PUT /api/admin/objects/:objectName/toggle` | Enable or disable an Object globally (`{ "enabled": true }`). |
| `PUT /api/admin/objects/:objectName/fields/:fieldName/toggle` | Enable or disable a Field globally (`{ "enabled": false }`). |
| `DELETE /api/admin/objects/:objectName` | Delete an Object and its fields, and remove it from every Access Group. |
| `POST /api/admin/groups` | Create (no `id`) or update (with `id`) an Access Group (`{ "id"?, "expectedVersion"?, "name", "description", "allowedActions": ["soql_query", ...], "objectPermissions": [{ "objectName", "canRead", "canCreate", "canUpdate", "canDelete", "allowedFields": [...] }] }`). Answers `{ "group", "groups" }`; every group carries a `version`, 1 when created and one more on every saved change. **Validation** (`400`, and nothing is saved): `name` is trimmed and must be 1 to 80 characters, `description` is trimmed and at most 500; every action id must be a catalog tool; `objectPermissions` must be an array of objects whose `objectName` is an Object in **Salesforce > Objects** (matched case-insensitively; a globally disabled Object is accepted) and whose `allowedFields` (default `[]`) are that Object's fields. Each flag must be `true` or `false` (left out means `false`); `"false"`, `1` or `null` is refused. The error names the entry and key, e.g. `objectPermissions[2].canRead must be true or false.`, and of what was sent shows only the Object or field name typed. **Stored form:** Object and field names in the catalog's spelling, all four flags, other keys dropped, and the entries that name one Object in any case merged into one (flags OR-ed, fields of the entries that grant something unioned, plus the Object's `Id` when one of them grants Read, Create or Update but names no field, which the policy engine read as `Id`), so the response is not always an echo of the request. **Updates:** `404` (`Group not found.`) when no group has the `id`; an id never creates a group. With `expectedVersion`, an update of a group whose `version` has changed since is refused with `409` `{ "error", "group" }` (the group as stored now) and saves nothing; the portal always sends it. The id and version are checked before the grants, so a draft that still names an Object or field deleted since (which revoked it from the group, a new version) gets this `409`, not a `400` about the name. Without `expectedVersion` (clients from before versions) the update is accepted. `409` if another group has the name, ignoring case (a group keeping its own name is not refused for a case variant an older version allowed). |
| `DELETE /api/admin/groups/:id` | Delete a group (and its profile mappings). |
| `PUT /api/admin/profile-groups/:profileId` | Change the groups mapped to a Profile. `{ "add": [...], "remove": [...] }` (either may be left out) adds and removes only the memberships it names, so a stale screen cannot undo a change made elsewhere. A full replacement `{ "groupIds": [...], "expectedGroupIds": [...] }` must name the groups it was built from: `409` (and no change, with the stored `mapping`) when they differ from the stored set, `400` without `expectedGroupIds`. `400` (and no change) if any group id does not exist or is both added and removed. A request that changes nothing still answers `200` with the current mapping. |
| `POST /api/admin/groups/:id/profiles` | Add Profiles to and remove Profiles from one group (`{ "add": ["00e..."], "remove": [...] }`), atomically, leaving every other membership as it is. `404` for an unknown group, `400` (and no change) if any Profile id does not exist. |
| `PUT /api/admin/okta` | Update Okta SSO settings (`enabled`, `oktaDomain`, `issuer`, `clientId`, `clientSecret`, `redirectUri`, `adminGroup`). The client secret is encrypted with AES-256-GCM and never returned. |
| `PUT /api/admin/sf-settings` | Update Salesforce settings (`instanceUrl`, `apiVersion`, `expectedOrgId`, `enforceOrgIdLock`, `sfdxObjectsFolderPath`). `400` if the instance URL is outside `SALESFORCE_ALLOWED_DOMAINS`, the API version is not like `v62.0`, the Org ID is not a `00D...` ID, or the lock is enabled without an Org ID. `instanceUrl` is where MCP verifies bearer tokens. The org connection routes record their own host in `syncInstanceUrl`. A real connect also writes that host to `instanceUrl` while it is uninitialised (blank, `login.salesforce.com`, `test.salesforce.com`, or the simulated host) and never changes any other value. A simulated connect never writes it. |
| `POST /api/admin/portal-users` | Create or update a portal user (`{ "username", "displayName", "password", "role" }`). Usernames are case-insensitive; updating a password keeps the user's role and display name unless new ones are sent. The password must be at least 12 characters, and production refuses the publicly known default passwords (`400` either way). The role is stored but not enforced: every portal user has full access. |
| `DELETE /api/admin/portal-users/:username` | Delete a portal user. The last remaining user cannot be deleted. |
| `POST /api/admin/test-mcp-access` | Policy simulator: `{ "profileId", "toolName", "targetObject", "samplePayload"?, "username"? }` returns the `evaluation` (`{ "permitted", "reason", "matchedGroups", "allowedFields", "objectName"?, "skippedGroupEntries"? }`, as before), the `decision` it was read from (see [Test-MCP-access decision](#test-mcp-access-decision)), the Profile's `effectivePermissions` and, outside production, a signed 15-minute `simulatorBearerToken`, and logs the simulated call in the Copilot MCP log (`ALLOWED`, `DENIED`, or `ERROR` for an `error` decision). A `samplePayload` object is evaluated as the call's arguments, as `/mcp` would evaluate them, so a field, filter or argument `/mcp` would refuse is refused here too. Without one, only the tool and Object stages are checked, as before. The Object evaluated is `targetObject` when it is given, whatever `objectName` the sample payload names (a different one, `null` or `""`); the payload's `objectName` is used only without a `targetObject`. Both log rows (the Copilot MCP row's target and the `SIMULATE_MCP_CALL` row's details) name the Object evaluated, or `*` when there is none. |

### Test-MCP-access decision

The simulator's `decision` is the policy engine's result for the simulated call, the same one `/mcp` acts on:

```json
{
  "outcome": "denied",
  "code": "FIELD_NOT_PERMITTED",
  "reason": "Fields [SSN__c] on Case are not permitted for Profile 'Support'.",
  "objectName": null,
  "allowedFields": [],
  "steps": [
    { "stage": "tool", "result": "pass", "grantingGroupIds": [], "objectName": null, "fieldNames": [], "ruleId": null },
    { "stage": "identity", "result": "pass", "grantingGroupIds": [], "objectName": null, "fieldNames": [], "ruleId": null },
    { "stage": "groups", "result": "pass", "grantingGroupIds": [], "objectName": null, "fieldNames": [], "ruleId": null },
    { "stage": "tool_grant", "result": "pass", "grantingGroupIds": ["grp_support"], "objectName": null, "fieldNames": [], "ruleId": null },
    { "stage": "object", "result": "pass", "grantingGroupIds": ["grp_support"], "objectName": "Case", "fieldNames": [], "ruleId": null },
    { "stage": "crud", "result": "pass", "grantingGroupIds": ["grp_support"], "objectName": "Case", "fieldNames": [], "ruleId": null },
    { "stage": "fields", "result": "fail", "grantingGroupIds": [], "objectName": "Case", "fieldNames": ["SSN__c"], "ruleId": null }
  ],
  "assignedGroups": [{ "id": "grp_support", "name": "Support" }],
  "decidingGroupIds": [],
  "identity": { "callerProfileId": "00e5g000001D8pRAAU", "matchedProfileId": "00e5g000001D8pRAAU", "matchMethod": "id" },
  "policyRevision": 42
}
```

| Field | Meaning |
| :--- | :--- |
| `outcome` | `allowed`, `denied` (a permission refused it), `invalid` (the arguments are malformed) or `error` (the policy could not be evaluated; allows nothing). |
| `code` | `ALLOWED`, `TOOL_UNKNOWN`, `PROFILE_UNREGISTERED`, `NO_GROUPS`, `TOOL_NOT_GRANTED`, `OBJECT_NOT_GRANTED`, `OBJECT_BLOCKED` (granted, but disabled or not listed in **Salesforce > Objects**), `CRUD_MISSING`, `FIELD_NOT_PERMITTED`, `WHERE_FIELD_NOT_PERMITTED`, `INPUT_INVALID` or `INTERNAL_ERROR`. `ROW_FILTER` is reserved. |
| `reason` | The text the evaluation and `/mcp` give. |
| `objectName`, `allowedFields` | The Object's catalog spelling and the caller's allowed fields on it, for an allowed call of an object-scoped tool; otherwise `null` and `[]`. |
| `steps` | One per stage reached, in order (`tool`, `identity`, `groups`, `tool_grant`, then for object-scoped tools `object` and `crud`; with a sample payload, `fields` for the tools that select or write fields, `where` for `soql_query`, and last an `input` pass, which says the arguments were checked and passed); nothing after the step that failed. A malformed argument fails an `input` step. An `error` decision has no failed step: its steps are those passed before evaluation stopped. `grantingGroupIds` are the assigned groups that grant what the step checked, `fieldNames` the fields requested (on a pass) or refused (on a fail), and `ruleId` is reserved for row filters (`null`). |
| `assignedGroups` | Every group mapped to the Profile. |
| `decidingGroupIds` | For an allowed call, the groups named by its passing `tool_grant`, `object`, `crud` and `fields` steps; otherwise `[]`. |
| `identity` | The caller's Profile ID, the registered Profile it matched (or `null`), and how: `id`, `name` (the Profile name fallback) or `none`. |
| `policyRevision` | The [policy revision](#policy-revision) the decision was made on. |
| `skippedGroupEntries` | Present only when a stored group entry was skipped as malformed (see the security model). |

### Portal Admin log rows

`GET /api/admin/portal-logs` and the `portalLogs` list of `GET /api/admin/overview` return the same row:

| Field | Meaning |
| :--- | :--- |
| `id`, `timestamp`, `seq` | Row id, ISO time, and write order (the paging cursor). |
| `adminUsername`, `authMethod`, `ipAddress` | Who acted, how they signed in (`password`, `okta_sso`), and the client IP. |
| `action`, `target`, `details` | The action code and the free-text target and summary, as shown in the portal. |
| `result` | `SUCCESS`, `FAILED` or `DENIED`. A row written by a release from before this column (on upgrade, or later after a rollback onto the same database) gets it from the action name at the next boot: `*_FAILED` is `FAILED`, `*_DENIED` is `DENIED`, anything else `SUCCESS`. That rule is also the default for a row written without one. |
| `targetType`, `targetId` | What the action changed, by a stable id: `group` and the group id, `profile` and the Profile id, `object` and the Object API name, `field` and `Object.Field`, `portal_user` and the stored username (whatever spelling the request used), or `settings` and `okta` / `salesforce_connection`. Both are `""` when the action has no single target (imports, org syncs, sign-ins, the sample matrix, simulations), and on rows written before these columns existed, where they were not recorded. |
| `diff` | What changed, as names, ids and flags, or `null` (none, or a row from before these columns). `CREATE_GROUP` holds `{ "after" }` and `DELETE_GROUP` `{ "before" }`, the group's `name`, `description`, `allowedActions` and `objectPermissions` (a deleted group's `before` also lists the `profileIds` that lost it). `UPDATE_GROUP` holds `{ "before", "after" }` with only what changed: the fields whose value changed and, of `objectPermissions`, the grants removed or changed (in `before`) and added or changed (in `after`); a save that changes nothing holds two empty objects. Each grant is recorded as the policy engine reads it: its `objectName`, its four flags (`true` only when stored as `true`) and its `allowedFields`, and nothing else stored with it; an entry the engine skips as malformed (see the security model) grants nothing and is left out, and a name that is not a Salesforce API name is recorded as `<invalid:len=N>`. A name or description over 1,000 characters is cut, and the side lists it under `truncated`. `UPDATE_PROFILE_GROUPS` holds `{ "added", "removed" }`: group ids when the target is a Profile, Profile ids when it is a group. Settings, Okta, org connection and portal user rows keep no diff, so no secret, password, key or token can reach one. A diff over 64 KB is not kept: the row holds `{ "truncated": true, "length": N }` instead. |
| `correlationId` | The request that wrote the row; the same as that response's `X-Correlation-Id`. A row written outside an Admin API request (Okta sign-in) has an id of its own. It is `""` on rows written before this column existed: not recorded, so rows sharing `""` are not one request. |

`POST /api/admin/groups`, `DELETE /api/admin/groups/:id`, `PUT /api/admin/profile-groups/:profileId`, `POST /api/admin/groups/:id/profiles` and both `pull-apply` routes write their change and its row in one transaction: if the row cannot be written, the change is rolled back and the route answers `500`. The CSV export of the audit log keeps its earlier columns.

### Policy revision

`policyRevision` is one counter for everything `/mcp` decides from: **Salesforce > Profiles**, **Salesforce > Objects** and their fields, the Access Groups and the Profile ↔ Group mappings. It is `1` on a new database and on one upgraded from a release without it, never goes down, and is kept in the database, so a restart does not change it unless the policy was changed by something other than this release (below). Every change this release commits to any of those raises it by exactly one, however many rows the change touches: saving or deleting an Access Group (with the mappings a delete ends), a grant revoked by deleting its Object or field, either mapping route, adding, renaming or deleting a Profile or upgrading its ID to 18 characters, a CSV import, saving, toggling, bulk-toggling or deleting an Object or field, an SFDX import, either org sync apply, loading the sample matrix, and the upgrade's one-time grant canonicalization when it changes a group. Every stored value counts except timestamps and a group's `version`, so a new label or description counts too. A request that stores what is already stored (an empty delta, a toggle to the value it has, a group saved unchanged, whose `version` still goes up, or a re-import of the same files) changes nothing and leaves it alone. A change that is rolled back, for example because its audit row could not be written, leaves it as it was. Changes written to the database by something other than this release, such as an older release run on it after a rollback or a hand edit, are counted together as one revision the next time this release starts, before it serves a request. A hand edit made while it runs is in force under the revision it found until then. Okta settings, portal users, sign-ins and sessions, the Salesforce connection settings (the Org ID lock included) and certificates, and both logs are not part of it: they decide who can authenticate, not what the policy allows.
