# 🔌 Microsoft Copilot Studio & Salesforce Connected App Setup Guide

This guide walks through connecting **Microsoft Copilot Studio** to your **Salesforce MCP Server** so every user in Microsoft Teams or M365 Copilot authenticates with their own Salesforce credentials.

---

## Step 1: Create a Connected App (or External Client App) in Salesforce

1. Log in to **Salesforce Setup**.
2. In the Quick Find box, search for **App Manager** and click **New Connected App** (or **New External Client App**).
3. Fill in the Basic Information:
   * **Connected App Name:** `Microsoft Copilot MCP Connector`
   * **API Name:** `Microsoft_Copilot_MCP_Connector`
   * **Contact Email:** Your admin email
4. Under **API (Enable OAuth Settings)**:
   * Check **Enable OAuth Settings**.
   * **Callback URL:** Paste the Redirect URL provided by Microsoft Copilot Studio when you create the OAuth 2.0 tool (typically looks like `https://global.consent.azure-apim.net/redirect/...`).
   * **Selected OAuth Scopes:**
     * `Manage user data via APIs (api)`
     * `Perform requests at any time (refresh_token, offline_access)`
     * `Access unique user identifiers (openid)`
     * `Access basic information (id, profile, email, address, phone)`
   * **PKCE Note for Copilot Studio:** If using Copilot Studio's Generic OAuth 2.0 provider without PKCE enabled on the Power Platform connector, uncheck *"Require Proof Key for Code Exchange (PKCE) extension for Supported Authorization Flows"*, or enable PKCE in your Copilot Studio connector settings.
   * Check **Require Secret for Web Server Flow** and **Require Secret for Refresh Token Flow**.
5. Save the Connected App and click **Manage Consumer Details** to copy your **Consumer Key (`Client ID`)** and **Consumer Secret (`Client Secret`)**.

---

## Step 2: Expose Your Salesforce MCP Server over HTTPS

Microsoft Copilot Studio runs in the cloud and requires a public **HTTPS** endpoint for your MCP Server (`https://<your-mcp-domain>/mcp`).

* **Production Deployment:** Deploy this repository to **Azure Container Apps**, **Azure App Service**, **AWS ECS/App Runner**, **Google Cloud Run**, or **Render**. Run `npm run build`, then `npm start` (backend on `:3001`, portal on `:3000`), and expose only the portal port. Set `NODE_ENV=production`, `BASE_URL=https://mcp.yourcompany.com`, a real `APP_SECRET_KEY` (`openssl rand -hex 32`) and `ADMIN_BOOTSTRAP_PASSWORD`. Set `MCP_BACKEND_URL` at build time if the backend is not on `http://localhost:3001`.
* **Local Testing with Tunnel:** During development (`npm run dev`), expose the portal port `3000` over HTTPS with Cloudflare Tunnel or ngrok. The portal proxies `/mcp` and `/.well-known/*` to the backend. Then set `BASE_URL=https://<tunnel-host>` (in `.env`) and restart, so the 401 challenge and the RFC 9728 metadata advertise the tunnel URL instead of `http://localhost:3000`:
  ```bash
  npx cloudflared tunnel --url http://localhost:3000
  # or
  ngrok http 3000
  ```

---

## Step 3: Add the MCP Server in Microsoft Copilot Studio

1. Open [Microsoft Copilot Studio](https://copilotstudio.microsoft.com) and select your Agent.
2. Navigate to **Tools** &rarr; **Add a tool** &rarr; **New tool** &rarr; **Model Context Protocol (MCP)**.
3. Enter the MCP Server details:
   * **Server Name:** `Salesforce CRM (Zero-Trust MCP)`
   * **Description:** `List, describe, query (SOQL), get, create, update and delete the Salesforce records the signed-in user's Profile allows.`
   * **Server URL (Streamable HTTP Endpoint):**
     ```text
     https://<your-mcp-server-domain>/mcp
     ```
4. Under **Authentication**, select **OAuth 2.0** &rarr; **Manual / Generic OAuth 2.0**:
   * **Client ID:** `<Your Salesforce Connected App Consumer Key>`
   * **Client Secret:** `<Your Salesforce Connected App Consumer Secret>`
   * **Authorization URL:**
     ```text
     https://<your-domain>.my.salesforce.com/services/oauth2/authorize
     ```
     *(Or `https://login.salesforce.com/services/oauth2/authorize`)*
   * **Token URL:**
     ```text
     https://<your-domain>.my.salesforce.com/services/oauth2/token
     ```
   * **Refresh URL:**
     ```text
     https://<your-domain>.my.salesforce.com/services/oauth2/token
     ```
   * **Scopes:**
     ```text
     api refresh_token openid profile email
     ```
5. Click **Create / Save**. Copy the generated **Redirect URL** shown by Copilot Studio and verify it matches the **Callback URL** in your Salesforce Connected App (Step 1).
6. Ensure the tool's authentication mode in your Agent is set to **End user authentication (User's credentials)** rather than Maker-provided credentials.

---

## Step 4: Test the End-User Flow in Copilot Studio / Microsoft Teams

Before testing, register the test user's Salesforce Profile in the Admin Portal and map it to an Access Group that grants some tools (see the [Admin Portal guide](./okta-admin-setup.md)). Users whose Profile is not registered see no tools.

1. Open the **Test your agent** pane in Copilot Studio and ask:
   > *"Show my open Opportunities in Salesforce"*
2. Copilot Studio will display a **Sign in to Salesforce** card.
3. Click **Sign in**, log in as a Salesforce user (e.g. a user with the `Standard User` or `Custom: Sales Representative` Profile), and approve access.
4. Copilot Studio sends `POST /mcp` with `Authorization: Bearer <USER_SF_TOKEN>` to your MCP server.
5. Open the Admin Portal (`https://<your-mcp-server-domain>/`) &rarr; **Logs > Copilot MCP Traffic (PII Stripped)** to see the verified user, their resolved Salesforce Profile, and each `ALLOWED` / `DENIED` / `ERROR` decision.
