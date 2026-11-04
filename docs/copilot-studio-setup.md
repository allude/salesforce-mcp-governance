# 🔌 Microsoft Copilot Studio & Salesforce External Client App Setup Guide

This guide connects a **Microsoft Copilot Studio** agent to this **Salesforce MCP Server**, then publishes the agent to **Microsoft Teams** and **Microsoft 365 Copilot**. Every user signs in with their own Salesforce account, and the Admin Portal decides which tools, objects and fields they get.

> **The Admin Portal has this guide built in.** Open **Connect clients → Microsoft Copilot**. It fills in your Server URL and Salesforce OAuth URLs from the server's own OAuth metadata, gives each value a copy button, and checks whether Copilot can reach the server and whether any Profile has been granted tools.

## Before You Start

| What you need | Where |
| :--- | :--- |
| A Copilot Studio licence (a user licence with Copilot Credits, or pay-as-you-go) in a Power Platform environment where you can create agents. A trial cannot publish, and a Microsoft 365 Copilot licence alone does not cover these agents. Tool calls use Copilot Credits. | [Copilot Studio licensing](https://learn.microsoft.com/en-us/microsoft-copilot-studio/billing-licensing) |
| An agent built in Copilot Studio's **classic experience** (home page **… → Open classic experience**). Microsoft documents manual OAuth for MCP only there, and an agent cannot move between experiences later. | [Switch experiences](https://learn.microsoft.com/en-us/microsoft-copilot-studio/agents-experience/switch-experiences) |
| **Generative orchestration** on (agent **Settings → Generative AI → Orchestration**: Yes, the default). Only generative orchestration calls MCP tools. | [Generative orchestration](https://learn.microsoft.com/en-us/microsoft-copilot-studio/advanced-generative-actions) |
| A data policy that lets the agent use a custom connector. Copilot Studio creates one for the MCP server; classify it (or a tenant pattern such as `https://<your-mcp-host>/*`) as **Business**, the same group as the Teams and Microsoft 365 channel. | [Power Platform admin center](https://admin.powerplatform.microsoft.com/security/dataprotection/dlp) · [Data policies for Copilot Studio](https://learn.microsoft.com/en-us/microsoft-copilot-studio/admin-data-loss-prevention) |
| A Salesforce admin who can create External Client Apps | [Create an External Client App](https://help.salesforce.com/s/articleView?id=xcloud.create_a_local_external_client_app.htm&type=5) |
| This server on a public HTTPS URL | Step 1 |

---

## Step 1: Expose Your Salesforce MCP Server over HTTPS

Copilot Studio calls the MCP server from Microsoft's cloud, so `localhost` and private addresses do not work. It supports the Streamable HTTP transport, which `/mcp` serves. The portal proxies `/mcp` and `/.well-known/*` to the backend, so publish the portal port (`3000`) and set `BASE_URL` to its public origin. The Server URL is `BASE_URL` followed by `/mcp`.

* **Production Deployment:** Deploy this repository to **Azure Container Apps**, **Azure App Service**, **AWS ECS/App Runner**, **Google Cloud Run**, or **Render**. Run `npm run build`, then `npm start` (backend on `:3001`, portal on `:3000`), and expose only the portal port. Set `NODE_ENV=production`, `BASE_URL=https://mcp.yourcompany.com`, a real `APP_SECRET_KEY` (`openssl rand -hex 32`) and `ADMIN_BOOTSTRAP_PASSWORD`. Set `MCP_BACKEND_URL` at build time if the backend is not on `http://localhost:3001`.
* **Local Testing with Tunnel:** During development (`npm run dev`), expose the portal port `3000` over HTTPS with Cloudflare Tunnel or ngrok. Then set `BASE_URL=https://<tunnel-host>` (in `.env`) and restart, so the 401 challenge and the RFC 9728 metadata advertise the tunnel URL instead of `http://localhost:3000`:
  ```bash
  npx cloudflared tunnel --url http://localhost:3000
  # or
  ngrok http 3000
  ```

Check it from outside your network. It should answer `401` with a `WWW-Authenticate` header that names `resource_metadata`:
```bash
curl -i -X POST https://<your-mcp-server-domain>/mcp
```

---

## Step 2: Create an External Client App in Salesforce

Since Spring '26 Salesforce restricts creating new Connected Apps, so use an **External Client App**. An existing Connected App still works with the same OAuth settings; its key and secret are under **Manage Consumer Details**. See [Connected Apps and External Client Apps](https://developer.salesforce.com/docs/platform/api-rest/guide/intro-oauth-and-connected-apps.html).

1. In **Salesforce Setup**, search Quick Find for **External Client App Manager** and click **New External Client App**.
2. Fill in the basic information:
   * **External Client App Name:** `Microsoft Copilot MCP Connector`
   * **Contact Email:** your admin email
   * **Distribution State:** `Local`
3. Under **API (Enable OAuth Settings)**, tick **Enable OAuth**:
   * **Callback URL:** `https://global.consent.azure-apim.net/redirect` for now. Copilot Studio gives you the real Redirect URL in Step 3, and you replace this in Step 4.
   * **OAuth Scopes:**
     * `Manage user data via APIs (api)`
     * `Perform requests at any time (refresh_token, offline_access)`
     * `Access unique user identifiers (openid)`
     * `Access the identity URL service (id, profile, email, address, phone)`
   * **Flow Enablement:** leave these options off. Copilot Studio uses the standard authorization code (web server) flow.
   * **Security:** keep **Require secret for Web Server Flow** and **Require secret for Refresh Token Flow** ticked. Untick **Require Proof Key for Code Exchange (PKCE) extension for Supported Authorization Flows**: Copilot Studio's manual OAuth 2.0 sends the client secret but no PKCE challenge, so Salesforce would refuse the sign-in.
4. Click **Create**. On the **Policies** tab, click **Edit** and under **OAuth Policies** set:
   * **Permitted Users:** *All users may self-authorize* (each user approves on first sign-in), or *Admin approved users are pre-authorized* and add the Profiles or permission sets allowed to use Copilot.
   * **IP Relaxation:** *Relax IP restrictions* if your Profiles have Login IP Ranges. The token exchange runs from Microsoft's network.
   * **Refresh Token Policy:** how long users stay signed in before Copilot asks them again. Leave refresh token rotation off until you have tested it with Copilot.
5. On the **Settings** tab, under **OAuth Settings**, click **Consumer Key and Secret**, verify with the emailed code, and copy the **Consumer Key** (`Client ID`) and **Consumer Secret** (`Client Secret`).

---

## Step 3: Add the MCP Server in Microsoft Copilot Studio

1. Open [Microsoft Copilot Studio](https://copilotstudio.microsoft.com), pick your environment, and open your agent (or create one in the classic experience).
2. On the agent's **Tools** page, select **Add a tool** → **New tool** → **Model Context Protocol** (some tenants skip the **New tool** step).
3. Fill in the MCP wizard:

   | Field | Value |
   | :--- | :--- |
   | **Server name** | `Salesforce CRM` |
   | **Server description** | `Lists, describes, queries (SOQL), reads, creates, updates and deletes the Salesforce records the signed-in user's Profile allows.` Generative orchestration reads this to decide when to call Salesforce. |
   | **Server URL** | `https://<your-mcp-server-domain>/mcp` |
   | **Authentication** | **OAuth 2.0**, type **Manual** (the other types need Dynamic Client Registration, which Salesforce does not offer here) |
   | **Client ID** | Consumer Key from Step 2 |
   | **Client secret** | Consumer Secret from Step 2 |
   | **Authorization URL** | `https://<your-domain>.my.salesforce.com/services/oauth2/authorize` |
   | **Token URL template** | `https://<your-domain>.my.salesforce.com/services/oauth2/token` |
   | **Refresh URL** | `https://<your-domain>.my.salesforce.com/services/oauth2/token` |
   | **Scopes** | `api refresh_token openid profile email` |

   Use the same Salesforce host as the portal's **MCP token host** (Org Connection): the server verifies each user's token there. The server publishes it as `authorization_servers` at `/.well-known/oauth-protected-resource`.
4. Click **Create**. Copilot Studio shows a callback **Redirect URL**, usually `https://global.consent.azure-apim.net/redirect/…` with a suffix unique to this connector. Copy all of it, and leave the wizard open.

See [Connect your agent to an existing MCP server](https://learn.microsoft.com/en-us/microsoft-copilot-studio/mcp-add-existing-server-to-agent).

---

## Step 4: Paste the Redirect URL into Salesforce

1. In **External Client App Manager**, open `Microsoft Copilot MCP Connector`, go to the **Settings** tab and click **Edit**.
2. Under **OAuth Settings**, replace the placeholder **Callback URL** with the Redirect URL from Step 3, exactly as shown, and save.
3. Salesforce says changes to an External Client App can take up to 30 minutes to apply. Until then, sign-in may fail with `redirect_uri_mismatch`.

---

## Step 5: Connect, and Make Each User Sign In as Themselves

1. Back in the wizard, select **Next**. In the **Add tool** dialog, choose **Create a new connection**, sign in to Salesforce, and select **Add to agent**.
2. Open the tool from the agent's **Tools** page. Under **Details → Additional details**, keep **Credentials to use** on **End user credentials** (newer pages call it user authentication). With maker-provided credentials every user would act as you, with your Profile's access.
3. Keep the agent's own sign-in on **Authenticate with Microsoft** (agent **Settings → Security → Authentication**). With **No authentication**, tools cannot use each user's credentials.
4. The tool's **Tools** section lists what *your* Profile allows, with a toggle for each. Turn off any the agent should never call (for example `delete_record`). Each user still gets only what their own Profile allows; anything else is denied and logged.

See [Manage the server's tools](https://learn.microsoft.com/en-us/microsoft-copilot-studio/mcp-add-components-to-agent) and [End-user authentication](https://learn.microsoft.com/en-us/microsoft-copilot-studio/configure-enduser-authentication).

---

## Step 6: Give Users' Profiles Access in the Admin Portal

Register each user's Salesforce Profile in the Admin Portal and map it to an Access Group that grants tools (see the [Admin Portal guide](./okta-admin-setup.md)). Users whose Profile is not registered and mapped see no tools.

---

## Step 7: Test the End-User Flow in Copilot Studio

1. Select **Test** to open **Test your agent**, and ask:
   > *"Show my open Opportunities in Salesforce"*
2. The agent shows a connection card. Select **Connect**, sign in as a Salesforce user (e.g. one with the `Standard User` or `Custom: Sales Representative` Profile), and select **Allow**; the tool call then retries. **… → Manage connections** resets the test chat's sign-in.
3. Copilot Studio sends `POST /mcp` with `Authorization: Bearer <USER_SF_TOKEN>` to your MCP server.
4. Open the Admin Portal (`https://<your-mcp-server-domain>/`) → **Logs & Security → MCP traffic** to see the verified user, their resolved Salesforce Profile, and each `ALLOWED` / `DENIED` / `ERROR` decision.

---

## Step 8: Publish to Microsoft Teams and Microsoft 365 Copilot

1. Select **Publish** and confirm. Publish again after every change.
2. Go to **Channels**, select **Teams and Microsoft 365 Copilot**, keep **Make agent available in Microsoft 365 Copilot** ticked, and select **Add channel**.
3. Under **Availability options**, copy a link, show it to your teammates and the users you shared the agent with, or select **Show to everyone in my org** to submit it to the org catalog.
4. An admin approves an org catalog submission in the [Microsoft 365 admin center](https://admin.microsoft.com/#/agents/all) (**Agents → All agents → Requests**) or the [Teams admin center](https://admin.teams.microsoft.com/policies/manage-apps) (**Teams apps → Manage apps**). See [Agent requests](https://learn.microsoft.com/en-us/microsoft-agent-365/admin/agent-requests).
5. If users cannot install it, check that Microsoft 365 admin center **Agents → Settings** allows agents built by your organization, and that Teams allows custom apps. See [Why an agent will not install](https://learn.microsoft.com/en-us/troubleshoot/power-platform/copilot-studio/authoring/prevent-agent-install).
6. Each user signs in to Salesforce the first time the agent calls a tool for them. In Microsoft 365 Copilot that is **Open Connection Manager → Connect**, then **Retry**.

See [Publish an agent to Teams and Microsoft 365 Copilot](https://learn.microsoft.com/en-us/microsoft-copilot-studio/publication-add-bot-to-microsoft-teams).

---

## Troubleshooting

| What you see | Likely cause | Fix |
| :--- | :--- | :--- |
| Copilot Studio cannot reach or list the server | `BASE_URL` is not public HTTPS, or the tunnel stopped | Run the `curl` check in Step 1 from outside your network |
| Salesforce says `redirect_uri_mismatch` | The Callback URL does not match Copilot's Redirect URL exactly, or Salesforce has not applied it yet | Repeat Step 4, then wait up to 30 minutes |
| Salesforce says `invalid_request` about a code challenge | The Salesforce app requires PKCE | Untick **Require PKCE** (Step 2) |
| Users are blocked before the consent screen | **Permitted Users** is admin approved, and their Profile or permission set is not on the app | Add them on the app's **Policies** tab, or allow self-authorization |
| The agent has no Salesforce tools, or every call is denied | The user's Profile is not mapped to a group that grants tools | Map it under **Access matrix → Profile ↔ Group** |
| MCP traffic shows `Unverified Token` | The token comes from a different org or host than the MCP token host, or the Org ID lock refused it | Check **Salesforce → Org Connection** |
| Users sign in again every few hours | The `refresh_token` scope is missing, the Refresh Token Policy expires tokens early, or refresh token rotation is on | Add the scope on both sides (Steps 2 and 3) and review the policy. Some tenants report manual OAuth asking again when the access token expires. |
| The agent cannot use the tool, or a data policy error appears | A data policy puts the MCP custom connector in a different group from the channel | Classify the connector as **Business** (Before You Start) |
| You need to change the Client ID or secret later | Copilot Studio does not reopen the OAuth settings | Edit the custom connector's **Security** tab in Power Apps, and enter the secret again each time you save |
