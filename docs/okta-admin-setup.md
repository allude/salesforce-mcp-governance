# 🔑 Okta SSO & Admin Portal Configuration Guide

The **Salesforce MCP Server** includes a built-in Web Administration Control Plane at `GET /` for managing **Salesforce Profile RBAC Policies**, syncing Profiles from your Salesforce Org, testing Profile policies in an interactive simulator, and configuring **Okta OpenID Connect (OIDC) Single Sign-On**.

---

## 1. Initial Bootstrap Login (Before Okta SSO is Configured)

When you first start the server (`npm run dev`), Okta SSO is not yet enabled, so you can sign in using the bootstrap credentials configured in `.env` (or `.env.example`):

* **URL:** `http://localhost:3000`
* **Default Bootstrap Email:** `admin@company.com`
* **Default Bootstrap Password:** `ChangeMeInProd!2026`

> **Production Note:** Always set a strong `APP_SECRET_KEY` (64 hex chars) and `ADMIN_BOOTSTRAP_PASSWORD` in `.env`, or disable local fallback login completely once Okta SSO is verified.

---

## 2. Setting Up Okta OIDC SSO for the Admin Portal

### Step A: Create an OIDC Web Application in Okta
1. Sign in to your **Okta Admin Console**.
2. Navigate to **Applications** &rarr; **Applications** &rarr; **Create App Integration**.
3. Choose:
   * **Sign-in method:** `OIDC - OpenID Connect`
   * **Application type:** `Web Application`
4. Click **Next** and configure:
   * **App integration name:** `Salesforce MCP Admin Portal`
   * **Grant type:** Check **Authorization Code**
   * **Proof Key for Code Exchange (PKCE):** Check **Require PKCE as additional verification** (our server automatically uses `S256` PKCE on `/auth/okta/login` and `/auth/okta/callback`).
   * **Sign-in redirect URIs:**
     ```text
     http://localhost:3000/auth/okta/callback
     ```
     *(In production, use `https://<your-mcp-domain>/auth/okta/callback`)*
   * **Sign-out redirect URIs:**
     ```text
     http://localhost:3000
     ```
5. **(Optional) Configure Okta Group Claim for Admin RBAC:**
   * If you want only members of a specific Okta group (e.g., `MCP-Administrators`) to access the Admin Portal, go to **Sign On** tab &rarr; **OpenID Connect ID Token** &rarr; **Groups claim type** &rarr; **Filter**: `Matches regex` `.*` with claim name `groups`.
6. Copy the **Client ID**, **Client Secret**, and your **Okta Issuer URL** (e.g., `https://your-company.okta.com/oauth2/default` or `https://your-company.okta.com`).

### Step B: Enable Okta SSO in the MCP Admin Portal
1. Open the MCP Admin Portal (`http://localhost:3000`) and go to tab **3. Okta SSO Admin Configuration**.
2. Check **Enable Okta OIDC SSO for Admin Portal**.
3. Enter:
   * **Okta Issuer URL:** `https://<your-org>.okta.com/oauth2/default`
   * **Okta OIDC Client ID:** `0oa...`
   * **Okta OIDC Client Secret:** `<your-client-secret>` *(Encrypted at rest in SQLite using `AES-256-GCM`)*
   * **Okta Redirect Callback URI:** `http://localhost:3000/auth/okta/callback`
   * **Required Okta Group Claim (Optional):** e.g., `MCP-Administrators`
4. Choose whether to keep **Allow Local Break-Glass Password Login alongside Okta SSO** checked while testing, or uncheck it to enforce **Strict Okta-Only Mode**.
5. Click **Save Okta SSO Configuration**.
6. Sign out—you will now see the **🔐 Sign in with Okta SSO (OIDC + PKCE)** button on the login screen.

---

## 3. Pulling All Profiles from Your Salesforce Org

To configure which MCP actions are available per Salesforce Profile:

1. In the Admin Portal, open tab **2. Sync Profiles from Salesforce Org**.
2. Enter your **Salesforce Instance URL** (e.g., `https://yourcompany.my.salesforce.com`) and a valid **Salesforce Access Token** (you can grab one quickly from the Salesforce CLI via `sf org display --target-org <alias>`).
3. Click **⚡ Sync Profiles from Live Salesforce Org**.
4. The server queries your Salesforce Org REST API:
   ```sql
   SELECT Id, Name, UserType, PermissionsModifyAllData FROM Profile ORDER BY Name ASC
   ```
5. Every Standard and Custom Profile in your Salesforce Org is imported into **1. Salesforce Profile RBAC Matrix**:
   * Existing Profile configurations are preserved.
   * Newly discovered Profiles default safely to **Read-Only** tools (`soql_query`, `sosl_search`, `describe_object`, `get_record`) unless `PermissionsModifyAllData` is true.

---

## 4. Configuring Actions per Salesforce Profile

In tab **1. Salesforce Profile RBAC Matrix**, for each Salesforce Profile you can configure:

| Setting | Description |
| :--- | :--- |
| **Active Toggle** | Completely enables or disables MCP access for users with this Salesforce Profile. |
| **SOQL Query (`soql_query`)** | Permits read-only `SELECT` queries. |
| **SOSL Search (`sosl_search`)** | Permits `FIND {...}` multi-object text searches. |
| **Describe (`describe_object`)** | Permits inspecting object fields and picklists. |
| **Get Record (`get_record`)** | Permits fetching a single record by ID. |
| **Create Record (`create_record`)** | Permits creating new records (`POST /sobjects/{sObject}`). |
| **Update Record (`update_record`)** | Permits updating existing records (`PATCH /sobjects/{sObject}/{id}`). |
| **Delete Record (`delete_record`)** | Permits deleting records (`DELETE /sobjects/{sObject}/{id}`). |
| **Allowed sObjects** | Either `*` (all objects the user has Salesforce CRUD/FLS access to) or an explicit comma-separated allowlist such as `Account, Contact, Opportunity, Case`. |
| **Max Rows** | Automatically caps `LIMIT` on any SOQL query executed by users with this Profile (1–2000). |
