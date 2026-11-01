---
name: admin-feature-builder
description: >-
  Full-stack workflow for building or updating features in the Admin Control Plane
  (SQLite store -> Express Admin API with CSRF & Portal Audit Logging -> Shared Types -> Next.js UI).
---

# Admin Control Plane Feature Builder (`admin-feature-builder`)

Use this skill when adding or modifying configuration views, tables, importers, or settings in the Web Administration Portal.

## Core Design Rules
1. **Zero Demo Data**: Never seed fake profiles, fake objects, fake groups, or fake logs in `src/db/store.ts`. Only initialize system singletons (`portal_users` bootstrap admin, `okta_config`, `sf_connection_settings`).
2. **Information-Dense UI**: Keep tables compact (`text-xs`), high-contrast (`bg-white`, `border-slate-200`, `text-slate-900`, `indigo-600` accents), and actionable without unnecessary marketing fluff.
3. **Mandatory Portal Admin Audit Logging**: Every state-changing route (`POST`, `PUT`, `DELETE`) in `src/routes/adminRoutes.ts` must call `store.recordPortalAdminLog(...)` with the authenticated admin's username, auth method (`password` or `okta_sso`), action code, target, and human-readable details.

---

## 4-Layer Implementation Workflow

### 1. Database Layer (`src/db/store.ts`)
- Define the SQLite table in `db.exec(...)` using `CREATE TABLE IF NOT EXISTS` and appropriate `FOREIGN KEY ... ON DELETE CASCADE` constraints.
- Add synchronous typed helper methods on the `store` object using `node:sqlite` (`DatabaseSync`).

### 2. Shared TypeScript Contracts (`src/types/governance.ts`)
- Export the entity interface and include it in `PortalOverviewPayload` if it is part of the main control plane state returned by `GET /api/admin/overview`.

### 3. Express Admin API Layer (`src/routes/adminRoutes.ts`)
- All protected endpoints must be registered after the `adminRouter.use(...)` that calls `requireAdminAuth` (it is async, so its rejection is passed to `next`), and wrapped in `asyncRoute(...)` so errors reach the JSON error handler. Together they ensure both the `HttpOnly` JWT session cookie (`sf_mcp_admin_session`) and `X-CSRF-Token` header are verified.
- Extract the actor via `const actor = getAdminInfo(req);` and log the mutation:
  ```ts
  store.recordPortalAdminLog({
    adminUsername: actor.username,
    authMethod: actor.authMethod,
    action: 'YOUR_ACTION_CODE',
    target: 'Target Resource Name',
    details: 'Concise description of what was created, updated, or deleted.',
    ipAddress: actor.ip,
  });
  ```
- Include the new collection in `GET /api/admin/overview` if the UI needs it on load.

### 4. Next.js Portal UI (`src/components/views/` & `src/app/page.tsx`)
- Use the `apiFetch` helper passed from `src/app/page.tsx`—it automatically attaches `credentials: 'include'`, `Content-Type: application/json`, and `X-CSRF-Token`.
- Call `await onRefresh()` and `onShowToast(...)` after every successful mutation so the UI state and sidebar badges update immediately.
- Ensure all JSX text escapes raw `>` characters (`&gt;`) so Next.js Turbopack builds cleanly.
