# 🔑 Okta SSO & Admin Portal Configuration Guide

The **Admin Portal** is the Next.js app on `http://localhost:3000` (`src/app/`). It talks to the Express backend on `:3001` through the portal's proxy. Use it to register **Salesforce Profiles**, import **Objects & Fields**, build **Access Groups**, map Profiles to Groups, test policies in the simulator, read the audit logs, and configure **Okta OpenID Connect (OIDC) Single Sign-On**.

---

## 1. Initial Bootstrap Login (Before Okta SSO is Configured)

Start both services with `npm run dev`. On first start the backend seeds one portal user into the empty database from `ADMIN_BOOTSTRAP_USERNAME` / `ADMIN_BOOTSTRAP_PASSWORD`:

* **URL:** `http://localhost:3000`
* **Default username:** `admin`
* **Default password:** `admin123`

> **Production note:** set `NODE_ENV=production`, a real `APP_SECRET_KEY` (64 hex characters, `openssl rand -hex 32`) and a strong `ADMIN_BOOTSTRAP_PASSWORD`. The backend refuses to start with a missing or publicly known `APP_SECRET_KEY`, or while any portal account uses a publicly known password (set `ADMIN_BOOTSTRAP_USERNAME` to that account and a strong `ADMIN_BOOTSTRAP_PASSWORD` to rotate it at startup). `npm start` runs the backend with `NODE_ENV=production`. The bootstrap values are only used when the database has no portal users; manage further users under **Settings > Portal Login & Okta SSO**.

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
   * The portal requires membership of an Okta group (default `MCP-Admins`). To make that work, go to **Sign On** tab &rarr; **OpenID Connect ID Token** &rarr; **Groups claim type** &rarr; **Filter**: `Matches regex` `.*` with claim name `groups`.
6. Copy the **Client ID**, **Client Secret**, and your **Okta Issuer URL** (e.g., `https://your-company.okta.com/oauth2/default` or `https://your-company.okta.com`).

### Step B: Enable Okta SSO in the Admin Portal
1. Open the Admin Portal (`http://localhost:3000`) and go to **Settings > Portal Login & Okta SSO**.
2. Turn on **Okta SSO**.
3. Enter:
   * **Okta Domain:** `your-org.okta.com`.
   * **Issuer (optional):** leave empty to use `https://<domain>/oauth2/default`; enter e.g. `https://your-org.okta.com` for the org authorization server. A custom issuer is kept across saves until you change the domain or clear the field.
   * **Client ID:** `0oa...`
   * **Client Secret:** `<your-client-secret>` *(encrypted at rest in SQLite with AES-256-GCM, never returned by the API)*
   * **Required Okta Group Claim:** e.g. `MCP-Admins`. Users whose ID token `groups` claim lacks it are denied.
   * **Redirect URI (optional):** leave empty to use `<BASE_URL>/auth/okta/callback`, which follows `BASE_URL` if it changes. It must match the URI registered in Okta.
4. Save. Okta sign-in errors (for example a missing group) are shown on the login screen.
5. Sign out. The login screen now offers **Sign In with Okta SSO** next to the username and password form.

You can also pre-fill these settings from `OKTA_ISSUER`, `OKTA_CLIENT_ID`, `OKTA_CLIENT_SECRET`, `OKTA_REDIRECT_URI` and `OKTA_REQUIRED_GROUP` before the first start. SSO stays off until you enable it in the portal.

---

## 3. Registering Salesforce Profiles

Every Copilot user is matched to a Profile registered here by the `ProfileId` of their Salesforce user (15- and 18-character IDs match each other). If no registered ID matches, the user's Profile name is matched instead, so keep Profile names unique. Users whose Profile matches neither get no tools at all.

Pulling Profiles from the org stores each one under its 18-character ID and keeps its Access Group assignments. If an older version left a Profile stored under both forms, the pull merges the rows when that adds no access beyond the row in force, or when only one row has groups, which the review names. If the rows have different groups and merging would add access, both stay unchanged and the review lists them: delete one or give them the same groups, then pull again.

1. Export your Profiles, for example with the Salesforce CLI:
   ```bash
   sf data query --query "SELECT Id, Name FROM Profile ORDER BY Name" --result-format csv --target-org <alias>
   ```
2. In **Salesforce > Profiles**, click **Upload CSV File** or **Paste CSV**. The format is two columns, `id,name`; a header row is skipped and existing Profiles are updated. A row in either ID form updates the Profile already stored, and an 18-character ID upgrades a stored 15-character one, keeping its Access Groups. You can also add one Profile at a time; **Add profile** refuses an ID already stored in its other form and names the stored row, which you can open to edit.

## 4. Importing Objects & Fields

In **Salesforce > Objects**, either select your SFDX `objects/` folder in the browser (**Select SFDX objects/ Folder**) or enter a folder path on the server (**Sync from Local Path**). The importer reads `objects/<Obj>/<Obj>.object-meta.xml`, `objects/<Obj>/fields/*.field-meta.xml` and classic `objects/<Obj>.object` files; the object label comes from the object's own top-level `<label>`. Toggle Objects and individual Fields on or off; disabled ones are unavailable to every group. Re-importing keeps your toggles.

Deleting an Object also removes it from every Access Group, so re-importing it later does not silently restore access; grant it again explicitly.

---

## 5. Building Access Groups and the Profile Group Matrix

1. In **Access Matrix > Groups**, create a group and choose:
   * **MCP actions:** any of `list_enabled_objects`, `describe_object`, `soql_query`, `get_record`, `create_record`, `update_record`, `delete_record`.
   * **Objects:** for each Object, `Read`, `Create`, `Update`, `Delete`, and the **allowed fields**. An Object row with no CRUD box ticked grants nothing, including its fields.
2. In **Access Matrix > Profile Group Matrix**, assign groups to each Profile. A Profile's permissions are the union of its groups, limited to globally enabled Objects and Fields.
3. Use the **policy simulator** on the Dashboard to check what a Profile can do with a given tool and object. The underlying API call (`POST /api/admin/test-mcp-access`) also returns a signed 15-minute `simulatorBearerToken` you can use against `/mcp`; calls made with it get simulated Salesforce data and never reach Salesforce.
4. To lock the server to your org, open **Org Connection (JWT)**, turn on **Enforce Salesforce Org ID Lock** and enter the expected Org ID (`00D...`). The same page sets the login URL, the API version and the **MCP token host**, which is where MCP verifies users' tokens. The token host must be inside `SALESFORCE_ALLOWED_DOMAINS` and cannot be the simulated org's host. A successful live connect moves it to the connected org's host only while it is blank, `login.salesforce.com` or `test.salesforce.com`, and never replaces a host you set to anything else.
5. Watch **Logs > Copilot MCP Traffic (PII Stripped)** for every runtime decision (`ALLOWED`, `DENIED`, `ERROR`), and **Logs > Portal Admin Activity** for every admin change. Each view opens with the latest rows of each kind, which its toolbar names (for example `latest 150 calls + latest 50 simulated + latest 50 rejected`), so older rows of one kind can be missing between rows of another; **Load older** below the table reads back through the whole log without gaps. **Export CSV** reads the whole log with the view's filters applied, up to the newest 10,000 matching rows; when that limit cuts an export, the file name ends in `-newest-10000-rows` and the portal says so.
