# 🛡️ Enterprise Salesforce MCP Server & Governance Control Plane

A Zero-Trust, Streamable HTTP **Model Context Protocol (MCP)** Server that connects **Microsoft Copilot Studio** (and any MCP OAuth 2.1 client) to the **Salesforce REST API** using **per-user delegated OAuth 2.0 authentication**, governed by a **Salesforce Profile-based Action RBAC Engine** and administered through an **Okta OIDC Single Sign-On (SSO) Web Control Plane**.

---

## 🖼️ Architecture Diagram

![Enterprise Salesforce MCP Architecture](./docs/architecture-diagram.jpg)

* **High-Res Diagram (JPG):** [`architecture-diagram.jpg`](./architecture-diagram.jpg) / [`docs/architecture-diagram.jpg`](./docs/architecture-diagram.jpg)
* **Vector Diagram (SVG):** [`architecture-diagram.svg`](./architecture-diagram.svg) / [`docs/architecture-diagram.svg`](./docs/architecture-diagram.svg)

---

## 📚 Documentation Index

All project documentation is organized in markdown files inside this repository:

1. **[Architecture & Sequence Flows (`docs/architecture.md`)](./docs/architecture.md)**  
   Detailed breakdown of the Runtime Execution Plane (Per-User Salesforce OAuth 2.0 + Streamable HTTP `/mcp`) and the Admin Control Plane (Okta OIDC SSO + Profile Policy Engine), including why MCP servers return `401 Unauthorized` + `WWW-Authenticate` instead of browser `302` redirects.
2. **[Security & Zero-Trust Design (`docs/security-model.md`)](./docs/security-model.md)**  
   Deep dive into the 7 layers of defense-in-depth: Per-User Token Passthrough, Dynamic Profile Resolution, Profile-to-Tool & Object RBAC Matrix, SSRF Domain Allowlisting, AES-256-GCM Secret Encryption at Rest, Okta OIDC + PKCE + Remote JWKS Verification, and CSRF/CSP Hardening.
3. **[Microsoft Copilot Studio & Salesforce Connected App Setup (`docs/copilot-studio-setup.md`)](./docs/copilot-studio-setup.md)**  
   Step-by-step instructions to create your Salesforce Connected App / External Client App and wire up the Streamable HTTP MCP connector inside Microsoft Copilot Studio.
4. **[Okta SSO & Admin Portal Guide (`docs/okta-admin-setup.md`)](./docs/okta-admin-setup.md)**  
   How to configure Okta OpenID Connect (OIDC) with PKCE and Group-based RBAC to lock down the Admin Web Portal, sync all Salesforce Profiles from your org, and simulate Profile policies.
5. **[API & MCP Tools Reference (`docs/api-and-tools-reference.md`)](./docs/api-and-tools-reference.md)**  
   Complete specification of the 7 MCP tools (`soql_query`, `sosl_search`, `describe_object`, `get_record`, `create_record`, `update_record`, `delete_record`), RFC 9728 discovery endpoints, and Admin REST API endpoints.

---

## 🚀 Quick Start

### 1. Install Dependencies
```bash
npm install
```

### 2. Configure Environment (Optional for Local Dev)
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```
By default in development, the server runs on `http://localhost:3000` with bootstrap admin credentials:
* **Admin Email:** `admin@company.com`
* **Admin Password:** `ChangeMeInProd!2026`

### 3. Start the Server
```bash
npm run dev
```
* **Admin Web Portal (Okta SSO & Profile RBAC Matrix):** `http://localhost:3000`
* **Streamable HTTP MCP Endpoint:** `http://localhost:3000/mcp`
* **OAuth 2.0 Protected Resource Metadata (RFC 9728):** `http://localhost:3000/.well-known/oauth-protected-resource`

### 4. Run Verification Self-Tests
```bash
npm test
```

---

## 🗂️ Repository Structure

```text
salesforce-mcp/
├── README.md                          # Project overview & quick start
├── architecture-diagram.jpg           # High-res architecture diagram
├── architecture-diagram.svg           # Vector architecture diagram
├── .env.example                       # Environment variable template
├── package.json                       # Dependencies & scripts
├── tsconfig.json                      # TypeScript configuration
├── docs/
│   ├── architecture.md                # Runtime & Admin plane architecture + sequence diagrams
│   ├── security-model.md              # Zero-Trust security controls & threat mitigations
│   ├── copilot-studio-setup.md        # Salesforce Connected App + MS Copilot Studio guide
│   ├── okta-admin-setup.md            # Okta OIDC SSO + Profile Sync administration guide
│   ├── api-and-tools-reference.md     # MCP Tools & Admin REST API reference
│   ├── architecture-diagram.jpg       # Architecture diagram (served in Admin UI)
│   └── architecture-diagram.svg       # Vector diagram (served in Admin UI)
├── public/
│   └── index.html                     # Enterprise Admin Web Portal (SPA)
└── src/
    ├── index.ts                       # Express app, Helmet CSP, Rate Limiters, Routes
    ├── config.ts                      # Environment & runtime configuration
    ├── db/
    │   └── store.ts                   # SQLite WAL store (Profiles, Okta config, Audit Logs)
    ├── mcp/
    │   ├── server.ts                  # Request-scoped MCP Server with Profile RBAC filtering
    │   └── streamableHttp.ts          # Stateless Streamable HTTP (/mcp) handler
    ├── rbac/
    │   └── policyEngine.ts            # Salesforce Profile-to-Tool & Object Policy Engine
    ├── routes/
    │   └── adminRoutes.ts             # Admin REST API (Sync Profiles, Okta config, Simulator)
    ├── salesforce/
    │   └── client.ts                  # Salesforce REST API client, Token verifier, SSRF guard
    ├── security/
    │   ├── adminAuth.ts               # Okta OIDC + PKCE + JWKS verifier & JWT/CSRF middleware
    │   └── crypto.ts                  # AES-256-GCM encryption at rest & timing-safe helpers
    └── test-self.ts                   # Automated end-to-end security & MCP test suite
```
