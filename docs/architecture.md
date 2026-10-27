# 🏗️ Architecture & Sequence Flows

![Enterprise Salesforce MCP Architecture](./architecture-diagram.jpg)

## 1. Key Architectural Insight: How Per-User OAuth Works in MCP

A common misconception when building an authenticated MCP server for Microsoft Copilot Studio is assuming the MCP server itself acts like a traditional web website that responds with an `HTTP 302 Redirect` to `login.salesforce.com` when a user isn't signed in.

### Why `HTTP 302 Redirect` Does Not Work on `/mcp`
1. **End users never browse to `/mcp` directly.** Microsoft Copilot Studio's cloud orchestrator sends background `POST /mcp` JSON-RPC 2.0 requests.
2. If your `/mcp` endpoint returns an HTML login screen or a `302 Found` redirect, Copilot Studio's JSON-RPC parser fails the tool invocation.

### How Delegated Per-User OAuth 2.0 Actually Works
1. **Unauthenticated Challenge (`401 Unauthorized`):** If a request arrives at `POST /mcp` without a valid `Authorization: Bearer <token>`, the MCP server responds with `HTTP 401 Unauthorized` and a `WWW-Authenticate` header pointing to `/.well-known/oauth-protected-resource` (RFC 9728).
2. **Copilot Studio OAuth Sign-In Card:** Microsoft Copilot Studio manages the OAuth 2.0 Authorization Code flow with Salesforce. When a user invokes a Salesforce action in Teams or M365 Copilot for the first time, Copilot renders a native **"Sign in to Salesforce"** card.
3. **Token Lifecycle Management:** Once the user authenticates in Salesforce, Copilot Studio securely stores that specific user's `access_token` and `refresh_token` in the Power Platform Token Store and automatically refreshes expired tokens.
4. **Stateless Token Passthrough:** On every MCP request (`tools/list` and `tools/call`), Copilot Studio sends:
   ```http
   POST /mcp HTTP/1.1
   Authorization: Bearer <USER_SALESFORCE_ACCESS_TOKEN>
   Content-Type: application/json
   Accept: application/json, text/event-stream
   ```
5. **Dual-Layer Enforcement (MCP Profile RBAC + Salesforce Native Security):**
   * **Layer 1 (MCP Server Policy Engine):** The MCP server verifies the token against Salesforce, resolves the user's `ProfileId` and `Profile.Name`, and checks the **Admin RBAC Matrix**:
     * When Copilot calls `tools/list`, the MCP server dynamically filters the returned tool list so the user's Copilot session only sees tools allowed for their Salesforce Profile.
     * When Copilot calls `tools/call`, the MCP server verifies that both the **Tool** (e.g., `update_record`, `delete_record`) and the **Target sObject** (e.g., `Opportunity`) are permitted for that user's Salesforce Profile.
   * **Layer 2 (Salesforce REST API):** The MCP server executes the REST API call (`/services/data/v62.0/...`) using the user's own Bearer token. Salesforce natively enforces Org-Wide Defaults (OWD), Role Hierarchy, Sharing Rules, Object CRUD, and Field-Level Security (FLS).

---

## 2. End-to-End Sequence Diagram

```mermaid
sequenceDiagram
    autonumber
    actor User as End User (Teams / M365)
    participant Copilot as Microsoft Copilot Studio
    participant SFAuth as Salesforce OAuth 2.0
    participant MCP as Salesforce MCP Server (/mcp)
    participant RBAC as Profile RBAC Policy Engine (SQLite)
    participant SFAPI as Salesforce REST API
    actor Admin as MCP Administrator
    participant Okta as Okta SSO (OIDC + PKCE)

    rect rgb(30, 41, 59)
    Note over Admin,SFAPI: Plane 1: Admin Control Plane (Okta SSO + Profile RBAC Configuration)
    Admin->>MCP: Access Admin Web Portal (/)
    MCP->>Okta: Redirect to Okta OIDC (/authorize + PKCE S256)
    Okta-->>Admin: Authenticate Admin & MFA
    Okta-->>MCP: Authorization Code -> Verify ID Token via Okta JWKS
    Admin->>MCP: Click "Sync Salesforce Profiles"
    MCP->>SFAPI: Query Profiles (SELECT Id, Name, UserType FROM Profile)
    SFAPI-->>MCP: Returns Org Profiles (System Admin, Sales Rep, Support, etc.)
    MCP->>RBAC: Upsert Profiles & Default Tool Matrix
    Admin->>RBAC: Configure Allowed MCP Tools & sObjects per Salesforce Profile
    end

    rect rgb(15, 23, 42)
    Note over User,SFAPI: Plane 2: Runtime MCP Execution Plane (Per-User Delegated Auth)
    User->>Copilot: "Update Opportunity Stage to Closed Won"
    alt User not authenticated in Copilot Studio
        Copilot->>User: Display Salesforce Sign-In Card
        User->>SFAuth: Login & Consent (Per-User OAuth 2.0)
        SFAuth-->>Copilot: Per-User Access Token & Refresh Token
    end
    Copilot->>MCP: POST /mcp (tools/call: update_record)<br/>Header: Authorization: Bearer <USER_SF_TOKEN>
    MCP->>SFAPI: Verify Token & Resolve User Identity + ProfileId<br/>(/services/oauth2/userinfo + User.Profile.Name)
    SFAPI-->>MCP: User Verified (Profile: "Custom: Sales Representative")
    MCP->>RBAC: Evaluate if "Custom: Sales Representative" can run "update_record" on "Opportunity"
    alt Tool & Object Allowed for Profile
        RBAC-->>MCP: PERMIT (Allowed + Max Row Limit)
        MCP->>SFAPI: PATCH /services/data/v62.0/sobjects/Opportunity/{id}<br/>Header: Authorization: Bearer <USER_SF_TOKEN>
        SFAPI-->>MCP: 204 No Content (Updated as User)
        MCP-->>Copilot: MCP Tool Result (Success)
        Copilot-->>User: "Opportunity updated to Closed Won!"
    else Tool or Object Denied for Profile
        RBAC-->>MCP: DENY (Action blocked for Profile)
        MCP-->>Copilot: MCP Tool Error (PROFILE_POLICY_DENIED)
        Copilot-->>User: "Your Salesforce profile does not permit this action via Copilot."
    end
    end
```

---

## 3. Two-Plane System Architecture

| Plane | Purpose | Authentication Mechanism | Key Endpoints |
| :--- | :--- | :--- | :--- |
| **Runtime MCP Plane** | Handles JSON-RPC 2.0 tool discovery and execution from Microsoft Copilot Studio | Per-User Salesforce OAuth 2.0 Bearer Token (`Authorization: Bearer <token>`) | `POST /mcp`<br/>`GET /.well-known/oauth-protected-resource` |
| **Admin Control Plane** | Web UI for syncing Salesforce Profiles, configuring per-profile tool/object permissions, configuring Okta SSO, and viewing audit logs | Okta OIDC Authorization Code Flow with PKCE (`S256`) + Remote JWKS Verification (plus optional break-glass bootstrap login) | `GET /`<br/>`GET /auth/okta/login`<br/>`GET /auth/okta/callback`<br/>`/api/admin/*` |
