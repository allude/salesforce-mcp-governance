'use client';

import React, { useState, useEffect, useCallback } from 'react';
import type {
  SalesforceProfile,
  SalesforceObject,
  AccessGroup,
  ProfileGroupMapping,
  CopilotMcpLogRecord,
  PortalAdminLogRecord,
  OktaSsoSettings,
  SalesforceConnectionSettings,
  PortalUserSummary,
  AdminSession,
  McpActionType,
  GroupObjectPermission,
  NavViewId,
} from '@/types/governance';
import {
  TrafficDashboardView,
  CopilotMcpLogsView,
  PortalAdminLogsView,
  PortalAuthSettingsView,
} from '@/components/views/DashboardAndLogsViews';
import {
  SalesforceProfilesView,
  SalesforceObjectsView,
} from '@/components/views/SalesforceViews';
import {
  AccessGroupsView,
  ProfileGroupMatrixView,
} from '@/components/views/AccessMatrixViews';
import { SalesforceOrgConnectionView } from '@/components/views/SalesforceOrgConnectionView';
import {
  FlyoutDrawer,
  type FlyoutState,
} from '@/components/views/FlyoutDrawer';
import { CommandPalette } from '@/components/views/CommandPalette';

type ActiveView =
  | 'dashboard'
  | 'profiles'
  | 'objects'
  | 'sf-connection'
  | 'groups'
  | 'matrix'
  | 'traffic'
  | 'audit'
  | 'auth-settings';

const VIEW_META: Record<ActiveView, { crumb: string; title: string }> = {
  dashboard: { crumb: 'Overview', title: 'Dashboard' },
  profiles: {
    crumb: 'Configure the MCP server · Salesforce',
    title: 'Profiles',
  },
  objects: {
    crumb: 'Configure the MCP server · Salesforce',
    title: 'Objects',
  },
  'sf-connection': {
    crumb: 'Configure the MCP server · Salesforce',
    title: 'Org Connection (JWT)',
  },
  groups: {
    crumb: 'Configure the MCP server · Access matrix',
    title: 'Groups',
  },
  matrix: {
    crumb: 'Configure the MCP server · Access matrix',
    title: 'Profile ↔ Group',
  },
  traffic: { crumb: 'Logs', title: 'MCP traffic log' },
  audit: { crumb: 'Logs', title: 'Portal audit log' },
  'auth-settings': { crumb: 'Logs & Security', title: 'Portal Auth & SSO' },
};

export default function AdminPortalPage() {
  // Session & Auth state
  const [session, setSession] = useState<AdminSession | null>(null);
  const [csrfToken, setCsrfToken] = useState<string>('');
  const [authLoading, setAuthLoading] = useState(true);
  const [loginUsername, setLoginUsername] = useState('admin');
  const [loginPassword, setLoginPassword] = useState('admin123');
  const [oktaEmail, setOktaEmail] = useState('elena.rostova@acme.io');
  const [loginError, setLoginError] = useState('');
  const [loginBusy, setLoginBusy] = useState(false);

  // Navigation & UI state
  const [view, setView] = useState<ActiveView>('dashboard');
  const [flyout, setFlyout] = useState<FlyoutState | null>(null);
  const [cmdkOpen, setCmdkOpen] = useState(false);
  const [theme, setTheme] = useState<'dark' | 'light'>('dark');
  const [liveStream, setLiveStream] = useState(true);
  const [toast, setToast] = useState<string | null>(null);
  const [trafficSearchFilter, setTrafficSearchFilter] = useState('');
  const [orgCatalogTrigger, setOrgCatalogTrigger] = useState(0);

  // Workspace Data state
  const [profiles, setProfiles] = useState<SalesforceProfile[]>([]);
  const [objects, setObjects] = useState<SalesforceObject[]>([]);
  const [groups, setGroups] = useState<AccessGroup[]>([]);
  const [mappings, setMappings] = useState<ProfileGroupMapping[]>([]);
  const [copilotLogs, setCopilotLogs] = useState<CopilotMcpLogRecord[]>([]);
  const [portalLogs, setPortalLogs] = useState<PortalAdminLogRecord[]>([]);
  const [oktaSettings, setOktaSettings] = useState<OktaSsoSettings>({
    enabled: true,
    oktaDomain: 'https://acme-enterprise.okta.com',
    clientId: '0oa8x92kLpQ7EnterpriseMcp',
    issuer: 'https://acme-enterprise.okta.com/oauth2/default',
    hasClientSecret: false,
    redirectUri: 'http://localhost:3000/api/admin/okta/callback',
    adminGroup: 'MCP-Admins',
    updatedAt: '',
  });
  const [sfSettings, setSfSettings] =
    useState<SalesforceConnectionSettings | null>(null);
  const [portalUsers, setPortalUsers] = useState<PortalUserSummary[]>([]);

  const notify = useCallback((msg: string) => {
    setToast(msg);
  }, []);

  useEffect(() => {
    if (!toast) return;
    const t = setTimeout(() => setToast(null), 3200);
    return () => clearTimeout(t);
  }, [toast]);

  // Theme initialization & sync
  useEffect(() => {
    const saved =
      typeof window !== 'undefined'
        ? (localStorage.getItem('mcp_portal_theme') as 'dark' | 'light' | null)
        : null;
    const initial = saved === 'light' ? 'light' : 'dark';
    setTheme(initial);
    document.documentElement.setAttribute('data-theme', initial);
  }, []);

  const toggleTheme = useCallback(() => {
    setTheme((prev) => {
      const next = prev === 'dark' ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', next);
      try {
        localStorage.setItem('mcp_portal_theme', next);
      } catch {
        // ignore
      }
      return next;
    });
  }, []);

  // Global Cmd+K / Ctrl+K shortcut
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setCmdkOpen((o) => !o);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  // Authenticated API helper with CSRF header
  const apiFetch = useCallback(
    async <T = any>(url: string, options: RequestInit = {}): Promise<T> => {
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
        ...(options.headers as Record<string, string>),
      };
      if (csrfToken) {
        headers['x-csrf-token'] = csrfToken;
      }
      const res = await fetch(url, {
        ...options,
        credentials: 'include',
        headers,
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        throw new Error(data.error || `Request failed (${res.status})`);
      }
      return data as T;
    },
    [csrfToken]
  );

  const fetchWorkspace = useCallback(async () => {
    try {
      const res = await fetch('/api/admin/overview', {
        credentials: 'include',
      });
      if (!res.ok) return;
      const data = await res.json();
      setProfiles(data.profiles || []);
      setObjects(data.objects || []);
      setGroups(data.groups || []);
      setMappings(data.profileGroupMappings || []);
      setCopilotLogs(data.copilotLogs || []);
      setPortalLogs(data.portalLogs || []);
      if (data.oktaSettings) setOktaSettings(data.oktaSettings);
      if (data.sfSettings) setSfSettings(data.sfSettings);
      if (data.portalUsers) setPortalUsers(data.portalUsers);
    } catch {
      // ignore transient poll error
    }
  }, []);

  // Check session on mount
  useEffect(() => {
    (async () => {
      try {
        const res = await fetch('/api/admin/session', {
          credentials: 'include',
        });
        const data = await res.json();
        if (data.authenticated && data.user) {
          setSession({
            username: data.user.username,
            name: data.user.name,
            displayName: data.user.name,
            role: data.user.groups?.[0] || 'Platform Admin',
            authMethod: data.user.authMethod,
            groups: data.user.groups,
          });
          if (data.csrfToken) setCsrfToken(data.csrfToken);
          await fetchWorkspace();
        }
      } catch {
        // not logged in
      } finally {
        setAuthLoading(false);
      }
    })();
  }, [fetchWorkspace]);

  // Live refresh interval when liveStream is active
  useEffect(() => {
    if (!session || !liveStream) return;
    const iv = setInterval(() => {
      fetchWorkspace();
    }, 5000);
    return () => clearInterval(iv);
  }, [session, liveStream, fetchWorkspace]);

  // Auth handlers
  const handlePasswordLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoginError('');
    setLoginBusy(true);
    try {
      const res = await fetch('/api/admin/login', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: loginUsername,
          password: loginPassword,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Authentication failed');
      }
      setSession({
        username: data.user.username,
        name: data.user.name,
        displayName: data.user.name,
        role: data.user.role || 'Platform Admin',
        authMethod: data.user.authMethod,
      });
      if (data.csrfToken) setCsrfToken(data.csrfToken);
      await fetchWorkspace();
      notify(`Signed in as ${data.user.name}`);
    } catch (err: any) {
      setLoginError(err.message || 'Sign-in failed');
    } finally {
      setLoginBusy(false);
    }
  };

  const handleOktaLogin = async () => {
    setLoginError('');
    setLoginBusy(true);
    try {
      const res = await fetch('/api/admin/login-okta', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: oktaEmail || 'elena.rostova@acme.io',
          displayName: 'Elena Rostova',
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Okta SSO login failed');
      }
      setSession({
        username: data.user.username,
        name: data.user.name,
        displayName: data.user.name,
        role: data.user.role || 'Okta SSO Admin',
        authMethod: 'okta_sso',
      });
      if (data.csrfToken) setCsrfToken(data.csrfToken);
      await fetchWorkspace();
      notify('Authenticated via Okta OIDC Single Sign-On');
    } catch (err: any) {
      setLoginError(err.message || 'Okta SSO failed');
    } finally {
      setLoginBusy(false);
    }
  };

  const handleLogout = async () => {
    try {
      await apiFetch('/api/admin/logout', { method: 'POST' });
    } catch {
      // ignore
    }
    setSession(null);
    setFlyout(null);
  };

  // Mutation handlers
  const handleUpsertProfile = async (id: string, name: string) => {
    const data = await apiFetch('/api/admin/profiles', {
      method: 'POST',
      body: JSON.stringify({ id, name }),
    });
    if (data.profiles) setProfiles(data.profiles);
    await fetchWorkspace();
    notify(`Saved profile "${name}"`);
  };

  const handleDeleteProfile = async (id: string) => {
    const data = await apiFetch(
      `/api/admin/profiles/${encodeURIComponent(id)}`,
      { method: 'DELETE' }
    );
    if (data.profiles) setProfiles(data.profiles);
    await fetchWorkspace();
    notify(`Removed profile ${id}`);
  };

  const handleImportCsv = async (csvText: string) => {
    const data = await apiFetch('/api/admin/profiles/import-csv', {
      method: 'POST',
      body: JSON.stringify({ csvText }),
    });
    if (data.profiles) setProfiles(data.profiles);
    await fetchWorkspace();
    notify(
      `Imported profiles from CSV (${data.summary?.inserted || 0} added, ${
        data.summary?.updated || 0
      } updated)`
    );
  };

  const handleToggleProfileGroup = async (
    profileId: string,
    groupId: string
  ) => {
    const existing =
      mappings.find((m) => m.profileId === profileId)?.groupIds || [];
    const has = existing.includes(groupId);
    const nextGroupIds = has
      ? existing.filter((x) => x !== groupId)
      : [...existing, groupId];

    const data = await apiFetch(
      `/api/admin/profile-groups/${encodeURIComponent(profileId)}`,
      {
        method: 'PUT',
        body: JSON.stringify({ groupIds: nextGroupIds }),
      }
    );
    if (data.profileGroupMappings) setMappings(data.profileGroupMappings);
    await fetchWorkspace();
  };

  const handleToggleObject = async (objectName: string, enabled: boolean) => {
    const data = await apiFetch(
      `/api/admin/objects/${encodeURIComponent(objectName)}/toggle`,
      {
        method: 'PUT',
        body: JSON.stringify({ enabled }),
      }
    );
    if (data.objects) setObjects(data.objects);
    notify(`${objectName} ${enabled ? 'enabled' : 'disabled'}`);
  };

  const handleBulkToggleAllObjects = async (enabled: boolean) => {
    for (const o of objects) {
      if (o.enabled !== enabled) {
        await apiFetch(
          `/api/admin/objects/${encodeURIComponent(o.objectName)}/toggle`,
          {
            method: 'PUT',
            body: JSON.stringify({ enabled }),
          }
        );
      }
    }
    await fetchWorkspace();
    notify(`${enabled ? 'Enabled' : 'Disabled'} all Salesforce objects`);
  };

  const handleToggleField = async (
    objectName: string,
    fieldName: string,
    enabled: boolean
  ) => {
    const data = await apiFetch(
      `/api/admin/objects/${encodeURIComponent(
        objectName
      )}/fields/${encodeURIComponent(fieldName)}/toggle`,
      {
        method: 'PUT',
        body: JSON.stringify({ enabled }),
      }
    );
    if (data.objects) setObjects(data.objects);
  };

  const handleBulkToggleFields = async (
    objectName: string,
    enabled: boolean
  ) => {
    const data = await apiFetch(
      `/api/admin/objects/${encodeURIComponent(objectName)}/fields/bulk`,
      {
        method: 'PUT',
        body: JSON.stringify({ enabled }),
      }
    );
    if (data.objects) setObjects(data.objects);
    notify(
      `${enabled ? 'Enabled' : 'Disabled'} all fields on ${objectName}`
    );
  };

  const handleSyncSfdxPath = async (folderPath: string) => {
    const data = await apiFetch('/api/admin/objects/import-local-folder', {
      method: 'POST',
      body: JSON.stringify({ folderPath }),
    });
    if (data.objects) setObjects(data.objects);
    await fetchWorkspace();
    notify(
      `Synced ${data.summary?.objectsImported || 0} objects from ${folderPath}`
    );
  };

  const handleSyncUploadedFiles = async (
    files: Array<{ relativePath: string; content: string }>
  ) => {
    const data = await apiFetch('/api/admin/objects/import-sfdx-files', {
      method: 'POST',
      body: JSON.stringify({ files }),
    });
    if (data.objects) setObjects(data.objects);
    await fetchWorkspace();
    notify(
      `Synced ${
        data.summary?.objectsImported || 0
      } SObjects from uploaded SFDX bundle`
    );
  };

  const handleSaveGroup = async (group: {
    id?: string;
    name: string;
    description: string;
    allowedActions: McpActionType[];
    objectPermissions: GroupObjectPermission[];
  }) => {
    const data = await apiFetch('/api/admin/groups', {
      method: 'POST',
      body: JSON.stringify(group),
    });
    if (data.groups) setGroups(data.groups);
    await fetchWorkspace();
    notify(`Saved access group "${group.name}"`);
    return data.group;
  };

  const handleDeleteGroup = async (groupId: string) => {
    const data = await apiFetch(
      `/api/admin/groups/${encodeURIComponent(groupId)}`,
      { method: 'DELETE' }
    );
    if (data.groups) setGroups(data.groups);
    if (data.profileGroupMappings) setMappings(data.profileGroupMappings);
    await fetchWorkspace();
    notify('Deleted access group');
  };

  const handleSeedEnterpriseMatrix = async () => {
    const data = await apiFetch('/api/admin/workspace/seed-sample', {
      method: 'POST',
    });
    if (data.profiles) setProfiles(data.profiles);
    if (data.objects) setObjects(data.objects);
    if (data.groups) setGroups(data.groups);
    if (data.profileGroupMappings) setMappings(data.profileGroupMappings);
    await fetchWorkspace();
    notify('Loaded Reference Enterprise Access Matrix (5 Groups + Mappings)');
  };

  const handleTestMcpCall = async (payload: {
    profileId: string;
    toolName: string;
    targetObject: string;
    username?: string;
    samplePayload?: Record<string, unknown>;
  }) => {
    return apiFetch('/api/admin/test-mcp-access', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  };

  // Org Pull handlers
  const handlePreviewPullProfilesFromOrg = async () => {
    const data = await apiFetch('/api/admin/profiles/pull-preview', {
      method: 'POST',
    });
    return data.preview;
  };

  const handleApplyPullProfilesFromOrg = async (payload: {
    upserts: Array<{ id: string; name: string }>;
    removeProfileIds: string[];
    keptMissingProfileIds: string[];
  }) => {
    const data = await apiFetch('/api/admin/profiles/pull-apply', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
    if (data.profiles) setProfiles(data.profiles);
    await fetchWorkspace();
    notify(
      `Synced Profiles from Salesforce Org (${
        (data.summary?.inserted || 0) + (data.summary?.updated || 0)
      } upserted)`
    );
  };

  const handleFetchOrgObjectCatalog = async () => {
    const data = await apiFetch('/api/admin/objects/org-catalog');
    return data.catalog || [];
  };

  const handlePreviewPullObjectsFromOrg = async (objectNames: string[]) => {
    const data = await apiFetch('/api/admin/objects/pull-preview', {
      method: 'POST',
      body: JSON.stringify({ objectNames, includeTracked: true }),
    });
    return {
      preview: data.preview,
      pulledMetadata: data.pulledMetadata,
    };
  };

  const handleApplyPullObjectsFromOrg = async (payload: {
    pulledMetadata: any[];
    removeObjectNames: string[];
    removeFields: Array<{ objectName: string; fieldName: string }>;
  }) => {
    const data = await apiFetch('/api/admin/objects/pull-apply', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
    if (data.objects) setObjects(data.objects);
    await fetchWorkspace();
    notify(
      `Synced ${data.summary?.objectsUpserted || 0} SObjects (${
        data.summary?.fieldsUpserted || 0
      } fields) from Salesforce Org`
    );
  };

  const mapNavIdToView = (navId: NavViewId): ActiveView => {
    if (navId === 'sf-profiles') return 'profiles';
    if (navId === 'sf-objects') return 'objects';
    if (navId === 'matrix-groups') return 'groups';
    if (navId === 'matrix-profile-groups') return 'matrix';
    if (navId === 'logs-copilot') return 'traffic';
    if (navId === 'logs-portal') return 'audit';
    if (navId === 'settings-auth') return 'auth-settings';
    if (navId === 'settings-salesforce') return 'sf-connection';
    return 'dashboard';
  };

  // Loading state
  if (authLoading) {
    return (
      <div
        style={{
          height: '100vh',
          display: 'grid',
          placeItems: 'center',
          background: 'var(--bg)',
          color: 'var(--t2)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <span className="dot ok" />
          <span className="mono">
            Initializing Salesforce MCP Control Plane…
          </span>
        </div>
      </div>
    );
  }

  // Unauthenticated Login View
  if (!session) {
    return (
      <div
        style={{
          minHeight: '100vh',
          display: 'grid',
          placeItems: 'center',
          background:
            'radial-gradient(circle at 50% 0%, rgba(0,163,255,0.12), transparent 55%), var(--bg)',
          padding: 20,
        }}
      >
        <div
          className="card"
          style={{
            width: '100%',
            maxWidth: 430,
            boxShadow: 'var(--shadow-lg)',
          }}
        >
          <div className="card-h" style={{ padding: '16px 20px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <div className="brand-mark">
                <svg
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="2.2"
                >
                  <path d="M12 2L3 7v10l9 5 9-5V7l-9-5z" />
                  <path d="M12 8v8M8 10l4 2 4-2" />
                </svg>
              </div>
              <div>
                <div className="brand-t">Salesforce MCP</div>
                <div className="brand-s">
                  v2.4 · Enterprise Governance Control Plane
                </div>
              </div>
            </div>
            <button
              type="button"
              className="btn gh sm"
              onClick={toggleTheme}
              title="Toggle Dark / Light Theme"
            >
              {theme === 'dark' ? '☀' : '☾'}
            </button>
          </div>

          <div className="card-b" style={{ padding: 20 }}>
            {loginError && (
              <div
                style={{
                  marginBottom: 14,
                  padding: '8px 12px',
                  borderRadius: 6,
                  border: '1px solid rgba(248,113,113,0.4)',
                  background: 'var(--err-d)',
                  color: 'var(--err)',
                  fontSize: 12,
                }}
              >
                {loginError}
              </div>
            )}

            {/* Okta OIDC SSO */}
            <div style={{ marginBottom: 16 }}>
              <div className="fld" style={{ marginBottom: 8 }}>
                <label>Enterprise Single Sign-On (Okta OIDC)</label>
                <input
                  className="inp mono"
                  value={oktaEmail}
                  onChange={(e) => setOktaEmail(e.target.value)}
                  placeholder="elena.rostova@acme.io"
                />
              </div>
              <button
                type="button"
                className="btn pri"
                style={{ width: '100%', padding: '8px 12px' }}
                disabled={loginBusy}
                onClick={handleOktaLogin}
              >
                <span className="dot ok" />
                Continue with Okta SSO
              </button>
            </div>

            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 10,
                margin: '14px 0',
                color: 'var(--t3)',
                fontSize: 11,
              }}
            >
              <div
                style={{ flex: 1, height: 1, background: 'var(--bd)' }}
              />
              <span>OR LOCAL ADMINISTRATOR</span>
              <div
                style={{ flex: 1, height: 1, background: 'var(--bd)' }}
              />
            </div>

            <form onSubmit={handlePasswordLogin}>
              <div className="fld">
                <label>Username</label>
                <input
                  className="inp mono"
                  value={loginUsername}
                  onChange={(e) => setLoginUsername(e.target.value)}
                />
              </div>
              <div className="fld">
                <div
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                  }}
                >
                  <label>Password</label>
                  <button
                    type="button"
                    className="btn gh sm"
                    style={{ padding: '1px 5px', fontSize: 10.5 }}
                    onClick={() => {
                      setLoginUsername('admin');
                      setLoginPassword('admin123');
                    }}
                  >
                    Fill default (admin / admin123)
                  </button>
                </div>
                <input
                  type="password"
                  className="inp mono"
                  value={loginPassword}
                  onChange={(e) => setLoginPassword(e.target.value)}
                />
              </div>
              <button
                type="submit"
                className="btn"
                style={{ width: '100%', padding: '8px 12px' }}
                disabled={loginBusy}
              >
                Sign in with password
              </button>
            </form>
          </div>
        </div>
      </div>
    );
  }

  // Computed counts for sidebar
  const enabledObjectsCount = objects.filter((o) => o.enabled).length;
  const assignedProfilesCount = profiles.filter((p) => {
    const found = mappings.find((m) => m.profileId === p.id);
    return found && found.groupIds.length > 0;
  }).length;
  const meta = VIEW_META[view] || VIEW_META.dashboard;
  const selectedFlyoutId =
    flyout?.data?.id || flyout?.data?.objectName || undefined;
  const displayUser = session.displayName || session.name || session.username;

  return (
    <div className="shell">
      {/* LEFT SIDEBAR */}
      <aside className="sb">
        <div className="brand">
          <div className="brand-mark">
            <svg
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2.2"
            >
              <path d="M12 2L3 7v10l9 5 9-5V7l-9-5z" />
              <path d="M12 8v8M8 10l4 2 4-2" />
            </svg>
          </div>
          <div>
            <div className="brand-t">Salesforce MCP</div>
            <div className="brand-s">v2.4 · admin portal</div>
          </div>
        </div>

        <nav className="nav" aria-label="Primary">
          <div className="nav-sec">
            <button
              type="button"
              className={`nav-it ${view === 'dashboard' ? 'on' : ''}`}
              onClick={() => setView('dashboard')}
            >
              <span>
                <svg
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="1.75"
                >
                  <rect x="3" y="3" width="7" height="9" rx="1.5" />
                  <rect x="14" y="3" width="7" height="5" rx="1.5" />
                  <rect x="14" y="12" width="7" height="9" rx="1.5" />
                  <rect x="3" y="16" width="7" height="5" rx="1.5" />
                </svg>
                Dashboard
              </span>
            </button>
          </div>

          <div className="nav-sec">
            <div className="nav-h">Configure the MCP server</div>

            <div className="nav-grp">
              <svg
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="1.75"
              >
                <path d="M17.5 19a4.5 4.5 0 0 0 .5-8.97A6 6 0 0 0 6.2 8.5 4 4 0 0 0 6 16.5" />
              </svg>
              Salesforce
            </div>
            <div className="nav-sub">
              <button
                type="button"
                className={`nav-it ${view === 'profiles' ? 'on' : ''}`}
                onClick={() => setView('profiles')}
              >
                <span>Profiles</span>
                <span className="ct">{profiles.length}</span>
              </button>
              <button
                type="button"
                className={`nav-it ${view === 'objects' ? 'on' : ''}`}
                onClick={() => setView('objects')}
              >
                <span>Objects</span>
                <span className="ct">
                  {enabledObjectsCount}/{objects.length}
                </span>
              </button>
              <button
                type="button"
                className={`nav-it ${view === 'sf-connection' ? 'on' : ''}`}
                onClick={() => setView('sf-connection')}
              >
                <span>Org Connection (JWT)</span>
                <span
                  className={`dot ${
                    sfSettings?.connectionStatus === 'connected' ? 'ok' : 'off'
                  }`}
                />
              </button>
            </div>

            <div className="nav-grp" style={{ marginTop: 10 }}>
              <svg
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="1.75"
              >
                <path d="M12 3l8 4v5c0 5-3.5 8.5-8 9-4.5-.5-8-4-8-9V7l8-4z" />
              </svg>
              Access matrix
            </div>
            <div className="nav-sub">
              <button
                type="button"
                className={`nav-it ${view === 'groups' ? 'on' : ''}`}
                onClick={() => setView('groups')}
              >
                <span>Groups</span>
                <span className="ct">{groups.length}</span>
              </button>
              <button
                type="button"
                className={`nav-it ${view === 'matrix' ? 'on' : ''}`}
                onClick={() => setView('matrix')}
              >
                <span>Profile &harr; Group</span>
                <span className="ct">
                  {assignedProfilesCount}/{profiles.length}
                </span>
              </button>
            </div>
          </div>

          <div className="nav-sec">
            <div className="nav-h">Logs &amp; Security</div>
            <button
              type="button"
              className={`nav-it ${view === 'traffic' ? 'on' : ''}`}
              onClick={() => setView('traffic')}
            >
              <span>
                <svg
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="1.75"
                >
                  <path d="M3 12h4l3-7 4 14 3-7h4" />
                </svg>
                MCP traffic
              </span>
              <span className="ct">{copilotLogs.length}</span>
            </button>
            <button
              type="button"
              className={`nav-it ${view === 'audit' ? 'on' : ''}`}
              onClick={() => setView('audit')}
            >
              <span>
                <svg
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="1.75"
                >
                  <path d="M9 12h6M9 16h6M7 4h10a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2z" />
                </svg>
                Portal audit
              </span>
              <span className="ct">{portalLogs.length}</span>
            </button>
            <button
              type="button"
              className={`nav-it ${view === 'auth-settings' ? 'on' : ''}`}
              onClick={() => setView('auth-settings')}
            >
              <span>
                <svg
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="1.75"
                >
                  <rect x="4" y="11" width="16" height="9" rx="2" />
                  <path d="M8 11V7a4 4 0 0 1 8 0v4" />
                </svg>
                Portal Auth &amp; SSO
              </span>
            </button>
          </div>
        </nav>

        <div className="sb-ft">
          <div className="u-row">
            <div className="av">
              {displayUser
                .split(' ')
                .map((s: string) => s[0])
                .join('')
                .slice(0, 2)
                .toUpperCase()}
            </div>
            <div className="u-meta">
              <div className="u-name">{displayUser}</div>
              <div className="u-role">
                <span className="dot ok" />
                <span>
                  {String(session.authMethod).toLowerCase().includes('okta')
                    ? 'Okta SSO'
                    : 'Password'}
                </span>
                <span>· {session.role || 'Admin'}</span>
              </div>
            </div>
          </div>
          <div style={{ display: 'flex', gap: 6 }}>
            <button
              type="button"
              className="btn sm"
              style={{ flex: 1, justifyContent: 'center' }}
              onClick={() => setView('auth-settings')}
            >
              SSO Settings
            </button>
            <button
              type="button"
              className="btn sm"
              onClick={handleLogout}
              title="Sign out"
            >
              Sign out
            </button>
          </div>
        </div>
      </aside>

      {/* MAIN WORKSPACE */}
      <div className="main">
        <header className="top">
          <div className="crumb">
            <span>{meta.crumb}</span>
            <span className="sep">/</span>
            <b>{meta.title}</b>
          </div>

          <div className="top-r">
            <button
              type="button"
              className="pill"
              onClick={() => setCmdkOpen(true)}
              title="Open Command Palette (⌘K)"
            >
              <span>Search / Jump</span>
              <span className="kbd">⌘K</span>
            </button>

            <button
              type="button"
              className="pill"
              onClick={() => setFlyout({ type: 'simulator' })}
              title="Test MCP tool access & generate live telemetry"
            >
              <span className="dot ok" />
              <span>Copilot MCP connected</span>
            </button>

            <button
              type="button"
              className="pill"
              onClick={() => setView('sf-connection')}
              title="Configure Salesforce OAuth 2.0 JWT Bearer connection"
            >
              <span
                className={`dot ${
                  sfSettings?.connectionStatus === 'connected' ? 'ok' : 'warn'
                }`}
              />
              <span>
                Salesforce ·{' '}
                <span className="mono">
                  {sfSettings?.connectionStatus === 'connected'
                    ? sfSettings.connectedOrgId
                    : 'JWT setup'}
                </span>
              </span>
            </button>

            <button
              type="button"
              className={`live-chip ${liveStream ? 'on' : ''}`}
              onClick={() => setLiveStream((v) => !v)}
              title="Toggle live telemetry auto-refresh"
            >
              <span className={`dot ${liveStream ? 'ok' : 'off'}`} />
              {liveStream ? 'Live' : 'Paused'}
            </button>

            <button
              type="button"
              className="btn gh sm"
              onClick={toggleTheme}
              title={`Switch to ${theme === 'dark' ? 'Light' : 'Dark'} theme`}
            >
              {theme === 'dark' ? '☀' : '☾'}
            </button>
          </div>
        </header>

        <main className="cnt">
          {view === 'dashboard' && (
            <TrafficDashboardView
              copilotLogs={copilotLogs}
              portalLogs={portalLogs}
              profiles={profiles}
              objects={objects}
              groups={groups}
              mappings={mappings}
              sfSettings={sfSettings}
              selectedFlyoutId={selectedFlyoutId}
              onNavigateTab={(next) => setView(next as ActiveView)}
              onOpenFlyout={(f) => setFlyout(f)}
              onSeedEnterpriseMatrix={handleSeedEnterpriseMatrix}
            />
          )}

          {view === 'profiles' && (
            <SalesforceProfilesView
              profiles={profiles}
              groups={groups}
              objects={objects}
              mappings={mappings}
              sfSettings={sfSettings}
              selectedFlyoutId={selectedFlyoutId}
              onOpenFlyout={(f) => setFlyout(f)}
              onPreviewPullProfilesFromOrg={handlePreviewPullProfilesFromOrg}
              onApplyPullProfilesFromOrg={handleApplyPullProfilesFromOrg}
              onNavigateToOrgConnection={() => setView('sf-connection')}
            />
          )}

          {view === 'objects' && (
            <SalesforceObjectsView
              objects={objects}
              groups={groups}
              sfSettings={sfSettings}
              selectedFlyoutId={selectedFlyoutId}
              externalCatalogTrigger={orgCatalogTrigger}
              onToggleObject={handleToggleObject}
              onBulkToggleAllObjects={handleBulkToggleAllObjects}
              onOpenFlyout={(f) => setFlyout(f)}
              onFetchOrgObjectCatalog={handleFetchOrgObjectCatalog}
              onPreviewPullObjectsFromOrg={handlePreviewPullObjectsFromOrg}
              onApplyPullObjectsFromOrg={handleApplyPullObjectsFromOrg}
              onNavigateToOrgConnection={() => setView('sf-connection')}
            />
          )}

          {view === 'sf-connection' && sfSettings && (
            <SalesforceOrgConnectionView
              sfSettings={sfSettings}
              apiFetch={apiFetch}
              onRefresh={fetchWorkspace}
              onShowToast={(msg) => notify(msg)}
              onNavigate={(navId) => setView(mapNavIdToView(navId))}
            />
          )}

          {view === 'groups' && (
            <AccessGroupsView
              groups={groups}
              objects={objects}
              profiles={profiles}
              mappings={mappings}
              selectedFlyoutId={selectedFlyoutId}
              onOpenFlyout={(f) => setFlyout(f)}
              onSeedEnterpriseMatrix={handleSeedEnterpriseMatrix}
            />
          )}

          {view === 'matrix' && (
            <ProfileGroupMatrixView
              profiles={profiles}
              groups={groups}
              objects={objects}
              mappings={mappings}
              onToggleProfileGroup={handleToggleProfileGroup}
              onOpenFlyout={(f) => setFlyout(f)}
              onSeedEnterpriseMatrix={handleSeedEnterpriseMatrix}
            />
          )}

          {view === 'traffic' && (
            <CopilotMcpLogsView
              logs={copilotLogs}
              objects={objects}
              selectedFlyoutId={selectedFlyoutId}
              initialSearch={trafficSearchFilter}
              onClearLogs={async () => {
                setCopilotLogs([]);
                notify('Cleared view buffer');
              }}
              onOpenFlyout={(f) => setFlyout(f)}
            />
          )}

          {view === 'audit' && (
            <PortalAdminLogsView
              logs={portalLogs}
              selectedFlyoutId={selectedFlyoutId}
              onOpenFlyout={(f) => setFlyout(f)}
            />
          )}

          {view === 'auth-settings' && (
            <PortalAuthSettingsView
              oktaSettings={oktaSettings}
              portalUsers={portalUsers}
              onSaveOkta={async (updated) => {
                const data = await apiFetch('/api/admin/okta', {
                  method: 'PUT',
                  body: JSON.stringify(updated),
                });
                if (data.oktaSettings) setOktaSettings(data.oktaSettings);
                await fetchWorkspace();
                notify('Updated Okta OIDC SSO settings');
              }}
              onCreatePortalUser={async (user) => {
                const data = await apiFetch('/api/admin/portal-users', {
                  method: 'POST',
                  body: JSON.stringify(user),
                });
                if (data.portalUsers) setPortalUsers(data.portalUsers);
                await fetchWorkspace();
                notify(`Saved administrator "${user.username}"`);
              }}
              onDeletePortalUser={async (username) => {
                const data = await apiFetch(
                  `/api/admin/portal-users/${encodeURIComponent(username)}`,
                  { method: 'DELETE' }
                );
                if (data.portalUsers) setPortalUsers(data.portalUsers);
                await fetchWorkspace();
                notify(`Removed administrator "${username}"`);
              }}
            />
          )}
        </main>
      </div>

      {/* CONTEXTUAL SLIDE-OVER FLYOUT DRAWER */}
      <FlyoutDrawer
        flyout={flyout}
        onClose={() => setFlyout(null)}
        onOpenFlyout={(next) => setFlyout(next)}
        onNavigateView={(nextView, filterUser) => {
          if (filterUser !== undefined) setTrafficSearchFilter(filterUser);
          setView(nextView as ActiveView);
        }}
        profiles={profiles}
        objects={objects}
        groups={groups}
        mappings={mappings}
        sfSettings={sfSettings}
        onUpsertProfile={handleUpsertProfile}
        onDeleteProfile={handleDeleteProfile}
        onImportCsv={handleImportCsv}
        onToggleProfileGroup={handleToggleProfileGroup}
        onToggleObject={handleToggleObject}
        onToggleField={handleToggleField}
        onBulkToggleFields={handleBulkToggleFields}
        onSyncSfdxPath={handleSyncSfdxPath}
        onSyncUploadedFiles={handleSyncUploadedFiles}
        onOpenOrgObjectCatalogModal={() => {
          setView('objects');
          setOrgCatalogTrigger((c) => c + 1);
        }}
        onSaveGroup={handleSaveGroup}
        onDeleteGroup={handleDeleteGroup}
        onTestMcpCall={handleTestMcpCall}
        onRefreshWorkspace={fetchWorkspace}
        notify={notify}
      />

      {/* COMMAND PALETTE (Cmd+K) */}
      <CommandPalette
        open={cmdkOpen}
        onClose={() => setCmdkOpen(false)}
        onNavigateView={(v) => setView(v as ActiveView)}
        onOpenFlyout={(f) => setFlyout(f)}
        onSeedEnterpriseMatrix={handleSeedEnterpriseMatrix}
        onToggleTheme={toggleTheme}
        theme={theme}
        profiles={profiles}
        objects={objects}
        groups={groups}
      />

      {/* TOAST BANNER */}
      {toast && (
        <div className="toast-banner" role="status">
          <span className="dot ok" />
          <span>{toast}</span>
        </div>
      )}
    </div>
  );
}
