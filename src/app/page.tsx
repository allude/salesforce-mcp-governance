'use client';

import React, { useState, useEffect, useCallback, useRef } from 'react';
import type {
  SalesforceProfile,
  SalesforceObject,
  AccessGroup,
  ProfileGroupMapping,
  CopilotMcpLogRecord,
  McpActivityFigures,
  McpTrafficSeries,
  PortalAdminLogRecord,
  OktaSsoSettings,
  SalesforceConnectionSettings,
  PortalUserSummary,
  AdminSession,
  AccessGroupChangeSource,
  AccessGroupHistoryEntry,
  NavViewId,
} from '@/types/governance';
import type { AccessGroupDraft } from '@/components/views/accessGroupDraft';
import {
  TrafficDashboardView,
  type McpRequestStats,
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
import { CopilotConnectorView } from '@/components/views/CopilotConnectorView';
import {
  FlyoutDrawer,
  type FlyoutState,
} from '@/components/views/FlyoutDrawer';
import { CommandPalette } from '@/components/views/CommandPalette';
import { profileSyncResultMessage } from '@/components/views/profileSyncReview';
import { mcpActivityStatus } from '@/components/views/mcpActivity';
import { useModalDialog } from '@/components/views/useModalDialog';
import { isCommandPaletteShortcut } from '@/components/views/shortcuts';
import { estimateClockOffsetMs } from '@/components/views/trafficChart';
import { DEFAULT_OVERVIEW_LOG_CAPS, logPageUrl, type OverviewLogCaps } from '@/components/views/logHistory';
import {
  ENTERPRISE_MATRIX_WARNING,
  enterpriseMatrixAction,
} from '@/components/views/enterpriseMatrix';

type ActiveView =
  | 'dashboard'
  | 'profiles'
  | 'objects'
  | 'sf-connection'
  | 'groups'
  | 'matrix'
  | 'copilot'
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
  copilot: { crumb: 'Connect clients', title: 'Microsoft Copilot' },
  traffic: { crumb: 'Logs', title: 'MCP traffic log' },
  audit: { crumb: 'Logs', title: 'Portal audit log' },
  'auth-settings': { crumb: 'Logs & Security', title: 'Portal Auth & SSO' },
};

// Fixed messages for the codes /auth/okta/callback redirects with; any other value is ignored
// so a crafted link cannot put its own text on the login screen.
const OKTA_AUTH_ERRORS: Record<string, string> = {
  okta_error: 'Okta returned an error. Details are in the Portal audit log.',
  invalid_callback: 'The Okta sign-in response was incomplete. Please try again.',
  expired_state: 'The Okta sign-in took too long or was started in another browser. Please try again.',
  state_mismatch: 'The Okta sign-in response did not match this browser session. Please try again.',
  group_denied: 'Your Okta account is not in the group required for this portal.',
  sso_failed: 'Okta sign-in failed. Details are in the Portal audit log.',
};

/** Parses a JSON body without throwing on HTML/text error pages (e.g. a proxy 500). */
async function readJsonBody(res: Response): Promise<any> {
  const text = await res.text();
  try {
    return text ? JSON.parse(text) : {};
  } catch {
    return { error: `${res.status} ${res.statusText || 'Request failed'}` };
  }
}

function toAdminSession(user: any): AdminSession {
  return {
    username: user.username,
    name: user.name,
    displayName: user.name,
    role: user.role || user.groups?.[0] || 'Platform Admin',
    authMethod: user.authMethod,
    groups: user.groups,
  };
}

export default function AdminPortalPage() {
  // Session & Auth state
  const [session, setSession] = useState<AdminSession | null>(null);
  const [csrfToken, setCsrfToken] = useState<string>('');
  const [authLoading, setAuthLoading] = useState(true);
  const [loginUsername, setLoginUsername] = useState('');
  const [loginPassword, setLoginPassword] = useState('');
  const [oktaEnabled, setOktaEnabled] = useState(false);
  const savingProfileIds = useRef<Set<string>>(new Set());
  const [loginError, setLoginError] = useState('');
  const [loginBusy, setLoginBusy] = useState(false);

  // Navigation & UI state
  const [view, setView] = useState<ActiveView>('dashboard');
  const [flyout, setFlyout] = useState<FlyoutState | null>(null);
  const [cmdkOpen, setCmdkOpen] = useState(false);
  const [theme, setTheme] = useState<'dark' | 'light'>('dark');
  const [liveStream, setLiveStream] = useState(true);
  const [toast, setToast] = useState<{ msg: string; isError: boolean } | null>(null);
  const [trafficSearchFilter, setTrafficSearchFilter] = useState('');
  const [orgCatalogTrigger, setOrgCatalogTrigger] = useState(0);

  // Workspace Data state
  const [profiles, setProfiles] = useState<SalesforceProfile[]>([]);
  const [objects, setObjects] = useState<SalesforceObject[]>([]);
  const [groups, setGroups] = useState<AccessGroup[]>([]);
  const [mappings, setMappings] = useState<ProfileGroupMapping[]>([]);
  const [copilotLogs, setCopilotLogs] = useState<CopilotMcpLogRecord[]>([]);
  const [portalLogs, setPortalLogs] = useState<PortalAdminLogRecord[]>([]);
  const [logCaps, setLogCaps] = useState<OverviewLogCaps>(DEFAULT_OVERVIEW_LOG_CAPS);
  const [oktaSettings, setOktaSettings] = useState<OktaSsoSettings>({
    enabled: false,
    oktaDomain: '',
    clientId: '',
    issuer: '',
    hasClientSecret: false,
    redirectUri: '',
    adminGroup: '',
    updatedAt: '',
  });
  const [sfSettings, setSfSettings] =
    useState<SalesforceConnectionSettings | null>(null);
  const [portalUsers, setPortalUsers] = useState<PortalUserSummary[]>([]);
  const [mcpStats, setMcpStats] = useState<McpRequestStats | null>(null);
  const [recentMcpActivity, setRecentMcpActivity] = useState<McpActivityFigures | null>(null);
  const [mcpTraffic, setMcpTraffic] = useState<McpTrafficSeries | null>(null);
  const [clockNow, setClockNow] = useState(() => Date.now());
  const [clockOffsetMs, setClockOffsetMs] = useState(0);
  // Starts off so the burst button cannot show in production before the first overview loads.
  const [devToolsEnabled, setDevToolsEnabled] = useState(false);
  const [seedConfirmOpen, setSeedConfirmOpen] = useState(false);
  const seedConfirmModal = useModalDialog(seedConfirmOpen, () => setSeedConfirmOpen(false));

  const notify = useCallback((msg: string, isError = false) => {
    setToast({ msg, isError });
  }, []);

  /** Shows a failed change to the admin, then rethrows so the caller keeps its form or drawer open. */
  const reportFailure =
    <A extends unknown[], R>(fn: (...args: A) => Promise<R>) =>
    async (...args: A): Promise<R> => {
      try {
        return await fn(...args);
      } catch (err: any) {
        notify(err?.message || 'The change could not be saved.', true);
        throw err;
      }
    };

  /** For one-click actions with nothing to keep open: shows the failure and ends there. */
  const reportFailureAndStop =
    <A extends unknown[]>(fn: (...args: A) => Promise<unknown>) =>
    async (...args: A): Promise<void> => {
      try {
        await fn(...args);
      } catch (err: any) {
        notify(err?.message || 'The change could not be saved.', true);
      }
    };

  useEffect(() => {
    if (!toast) return;
    const t = setTimeout(() => setToast(null), toast.isError ? 8000 : 3200);
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

  // Global Cmd+K / Ctrl+K shortcut. An open modal dialog (useModalDialog) stops the chord in its
  // capture-phase listener, so it never reaches this one.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (isCommandPaletteShortcut(e)) {
        e.preventDefault();
        setCmdkOpen((o) => !o);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  // Refreshes what the login screen offers (Okta may have been enabled while signed in).
  const refreshLoginOptions = useCallback(async () => {
    try {
      const res = await fetch('/api/admin/session', { credentials: 'include' });
      const data = await readJsonBody(res);
      setOktaEnabled(Boolean(data.oktaSso?.enabled));
    } catch {
      // keep the previous value
    }
  }, []);

  const handleSessionExpired = useCallback(() => {
    setSession(null);
    setFlyout(null);
    setCsrfToken('');
    setLoginPassword('');
    setLoginError('Your session has ended. Please sign in again.');
    void refreshLoginOptions();
  }, [refreshLoginOptions]);

  const fetchWorkspace = useCallback(async () => {
    try {
      const sentAt = Date.now();
      const res = await fetch('/api/admin/overview', {
        credentials: 'include',
      });
      if (res.status === 401) {
        handleSessionExpired();
        return;
      }
      if (!res.ok) return;
      const data = await readJsonBody(res);
      const receivedAt = Date.now();
      setClockOffsetMs(estimateClockOffsetMs(data.serverTime, sentAt, receivedAt));
      // New rows are measured against a fresh reading, not the last 30-second tick.
      setClockNow(receivedAt);
      setProfiles(data.profiles || []);
      setObjects(data.objects || []);
      setGroups(data.groups || []);
      setMappings(data.profileGroupMappings || []);
      setCopilotLogs(data.copilotLogs || []);
      setMcpStats(data.stats || null);
      setRecentMcpActivity(data.mcpActivity || null);
      setMcpTraffic(data.mcpTraffic || null);
      setDevToolsEnabled(data.devToolsEnabled === true);
      setPortalLogs(data.portalLogs || []);
      if (data.logCaps) setLogCaps(data.logCaps);
      if (data.oktaSettings) setOktaSettings(data.oktaSettings);
      if (data.sfSettings) setSfSettings(data.sfSettings);
      if (data.portalUsers) setPortalUsers(data.portalUsers);
    } catch {
      // ignore transient poll error
    }
  }, [handleSessionExpired]);

  // Authenticated API helper with CSRF header
  const apiFetch = useCallback(
    async <T = any>(url: string, options: RequestInit = {}): Promise<T> => {
      const send = (token: string) => {
        const headers = new Headers(options.headers || {});
        if (!headers.has('Content-Type') && options.body) {
          headers.set('Content-Type', 'application/json');
        }
        if (token) {
          headers.set('X-CSRF-Token', token);
        }
        return fetch(url, { ...options, credentials: 'include', headers });
      };

      let res = await send(csrfToken);
      let data = await readJsonBody(res);

      // Signed in again in another tab: pick up the session's current CSRF token and retry once,
      // but only if it is still the same account. Never replay a change as someone else.
      if (res.status === 403 && /CSRF/i.test(String(data.error))) {
        const sessionRes = await fetch('/api/admin/session', { credentials: 'include' });
        const current = await readJsonBody(sessionRes);
        if (current.authenticated && current.csrfToken) {
          const sameAccount =
            current.user?.username === session?.username &&
            current.user?.authMethod === session?.authMethod;
          setCsrfToken(current.csrfToken);
          if (!sameAccount) {
            setSession(toAdminSession(current.user));
            await fetchWorkspace();
            throw new Error(
              `This browser is now signed in as "${current.user?.username}" (another tab). The change was not applied; review it and try again.`
            );
          }
          res = await send(current.csrfToken);
          data = await readJsonBody(res);
        }
      }

      if (res.status === 401) {
        handleSessionExpired();
      }
      if (!res.ok) {
        throw new Error(data.error || `Request failed (${res.status})`);
      }
      return data as T;
    },
    [csrfToken, session, fetchWorkspace, handleSessionExpired]
  );

  // Check session on mount
  useEffect(() => {
    // Okta callback failures come back as /?auth_error=<code>
    const params = new URLSearchParams(window.location.search);
    const authError = params.get('auth_error');
    if (authError) {
      setLoginError(OKTA_AUTH_ERRORS[authError] || 'Okta sign-in failed. Please try again.');
      params.delete('auth_error');
      const query = params.toString();
      window.history.replaceState(null, '', `${window.location.pathname}${query ? `?${query}` : ''}`);
    }
    (async () => {
      try {
        const res = await fetch('/api/admin/session', {
          credentials: 'include',
        });
        const data = await readJsonBody(res);
        if (!res.ok) {
          setLoginError(
            `The MCP backend is not reachable (${res.status}). Start it with \`npm run dev\` (backend on :3001).`
          );
        }
        setOktaEnabled(Boolean(data.oktaSso?.enabled));
        if (data.authenticated && data.user) {
          setSession(toAdminSession(data.user));
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

  // Keeps relative times moving while the live refresh is paused
  useEffect(() => {
    if (!session) return;
    setClockNow(Date.now());
    const iv = setInterval(() => setClockNow(Date.now()), 30000);
    return () => clearInterval(iv);
  }, [session]);

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
      const data = await readJsonBody(res);
      if (!res.ok) {
        throw new Error(data.error || 'Authentication failed');
      }
      setSession(toAdminSession(data.user));
      setLoginPassword('');
      if (data.csrfToken) setCsrfToken(data.csrfToken);
      await fetchWorkspace();
      notify(`Signed in as ${data.user.name}`);
    } catch (err: any) {
      setLoginError(err.message || 'Sign-in failed');
    } finally {
      setLoginBusy(false);
    }
  };

  const handleLogout = async () => {
    try {
      await apiFetch('/api/admin/logout', { method: 'POST' });
    } catch (err: any) {
      // Keep the user signed in so they know the session is still active.
      notify(err?.message || 'Sign out failed');
      return;
    }
    setSession(null);
    setFlyout(null);
    setCsrfToken('');
    setLoginPassword('');
    void refreshLoginOptions();
  };

  // Mutation handlers
  const handleUpsertProfile = async (
    id: string,
    name: string,
    options?: { creating?: boolean }
  ) => {
    const data = await apiFetch('/api/admin/profiles', {
      method: 'POST',
      body: JSON.stringify({ id, name, creating: options?.creating === true }),
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
      } updated${
        data.summary?.namesKept
          ? `; ${data.summary.namesKept} stored under two ID forms kept their name`
          : ''
      })`
    );
  };

  const handleToggleProfileGroup = async (
    profileId: string,
    groupId: string
  ) => {
    // One save per Profile at a time: a second click would send a replacement list computed from
    // stale state, which could silently undo a revocation.
    if (savingProfileIds.current.has(profileId)) return;
    savingProfileIds.current.add(profileId);
    try {
      await saveProfileGroupToggle(profileId, groupId);
    } finally {
      savingProfileIds.current.delete(profileId);
      // Always reload so the row shows what the server actually stored
      await fetchWorkspace();
    }
  };

  const saveProfileGroupToggle = async (
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

  const handleSaveGroup = async (
    group: AccessGroupDraft & { source: AccessGroupChangeSource; sourceDetail: string }
  ) => {
    const data = await apiFetch('/api/admin/groups', {
      method: 'POST',
      body: JSON.stringify(group),
    });
    if (data.groups) setGroups(data.groups);
    await fetchWorkspace();
    const notAvailable = Array.isArray(data.issues) ? data.issues.length : 0;
    notify(
      `Saved access group "${group.name}"${
        notAvailable > 0 ? `, with ${notAvailable} item${notAvailable === 1 ? '' : 's'} not available or broken` : ''
      }`
    );
    return data.group;
  };

  const handleLoadGroupHistory = useCallback(
    async (groupId: string): Promise<AccessGroupHistoryEntry[]> => {
      const data = await apiFetch(`/api/admin/groups/${encodeURIComponent(groupId)}/history`);
      return data.history || [];
    },
    [apiFetch]
  );

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
  const requestSeedEnterpriseMatrix = enterpriseMatrixAction(devToolsEnabled, () =>
    setSeedConfirmOpen(true)
  );

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
    notify(profileSyncResultMessage(data.summary));
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
    if (navId === 'connect-copilot') return 'copilot';
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

            {/* Okta OIDC SSO: the server redirects to Okta and verifies the callback */}
            {oktaEnabled && (
              <>
                <a
                  className="btn pri"
                  style={{ width: '100%', padding: '8px 12px', marginBottom: 16 }}
                  href="/auth/okta/login"
                >
                  <span className="dot ok" />
                  Continue with Okta SSO
                </a>
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
              </>
            )}

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
                  {process.env.NODE_ENV !== 'production' && (
                    <button
                      type="button"
                      className="btn gh sm"
                      style={{ padding: '1px 5px', fontSize: 10.5 }}
                      onClick={() => {
                        setLoginUsername('admin');
                        setLoginPassword('admin123');
                      }}
                    >
                      Fill development default
                    </button>
                  )}
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
  // Read on the server's clock, which stamps the call, so the pill agrees with the chart under skew.
  const mcpActivity = mcpActivityStatus(mcpStats ? mcpStats.lastMcpCallAt : undefined, clockNow + clockOffsetMs);
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
            <div className="nav-h">Connect clients</div>
            <button
              type="button"
              className={`nav-it ${view === 'copilot' ? 'on' : ''}`}
              onClick={() => setView('copilot')}
            >
              <span>
                <svg
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="1.75"
                >
                  <path d="M9 7V3M15 7V3M7 7h10v4a5 5 0 0 1-10 0V7zM12 16v5" />
                </svg>
                Microsoft Copilot
              </span>
            </button>
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
              <span className="ct">{mcpStats?.totalMcpRequests ?? copilotLogs.length}</span>
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
          <div style={{ display: 'flex' }}>
            <button
              type="button"
              className="btn sm"
              style={{ flex: 1, justifyContent: 'center' }}
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
              title="Time of the last real MCP call; simulated calls are not counted. Click to open the MCP call simulator."
              aria-label={`${mcpActivity.label}. Open the MCP call simulator`}
            >
              <span className={`dot ${mcpActivity.tone}`} />
              <span>{mcpActivity.label}</span>
              <span className="kbd">Simulate</span>
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
                    : sfSettings?.connectionStatus === 'not_verified'
                    ? 'not verified'
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
              clockNow={clockNow}
              clockOffsetMs={clockOffsetMs}
              copilotLogs={copilotLogs}
              mcpStats={mcpStats}
              mcpActivity={recentMcpActivity}
              mcpTraffic={mcpTraffic}
              portalLogs={portalLogs}
              profiles={profiles}
              objects={objects}
              groups={groups}
              mappings={mappings}
              sfSettings={sfSettings}
              selectedFlyoutId={selectedFlyoutId}
              onNavigateTab={(next) => setView(next as ActiveView)}
              onOpenFlyout={(f) => setFlyout(f)}
              onSeedEnterpriseMatrix={requestSeedEnterpriseMatrix}
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
              onApplyPullProfilesFromOrg={reportFailure(handleApplyPullProfilesFromOrg)}
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
              onToggleObject={reportFailureAndStop(handleToggleObject)}
              onBulkToggleAllObjects={reportFailureAndStop(handleBulkToggleAllObjects)}
              onOpenFlyout={(f) => setFlyout(f)}
              onFetchOrgObjectCatalog={handleFetchOrgObjectCatalog}
              onPreviewPullObjectsFromOrg={handlePreviewPullObjectsFromOrg}
              onApplyPullObjectsFromOrg={reportFailure(handleApplyPullObjectsFromOrg)}
              onNavigateToOrgConnection={() => setView('sf-connection')}
            />
          )}

          {view === 'sf-connection' && sfSettings && (
            <SalesforceOrgConnectionView
              sfSettings={sfSettings}
              apiFetch={apiFetch}
              onRefresh={fetchWorkspace}
              onShowToast={notify}
              onNavigate={(navId) => setView(mapNavIdToView(navId))}
              devToolsEnabled={devToolsEnabled}
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
              onSeedEnterpriseMatrix={requestSeedEnterpriseMatrix}
              notify={notify}
            />
          )}

          {view === 'matrix' && (
            <ProfileGroupMatrixView
              profiles={profiles}
              groups={groups}
              objects={objects}
              mappings={mappings}
              onToggleProfileGroup={reportFailureAndStop(handleToggleProfileGroup)}
              onOpenFlyout={(f) => setFlyout(f)}
              onSeedEnterpriseMatrix={requestSeedEnterpriseMatrix}
            />
          )}

          {view === 'copilot' && (
            <CopilotConnectorView
              sfSettings={sfSettings}
              groups={groups}
              mappings={mappings}
              objects={objects}
              lastMcpCallAt={mcpStats?.lastMcpCallAt}
              serverNow={clockNow + clockOffsetMs}
              onShowToast={notify}
              onNavigate={(navId) => setView(mapNavIdToView(navId))}
            />
          )}

          {view === 'traffic' && (
            <CopilotMcpLogsView
              logs={copilotLogs}
              objects={objects}
              selectedFlyoutId={selectedFlyoutId}
              initialSearch={trafficSearchFilter}
              caps={logCaps.copilotLogs}
              fetchLogPage={(query) => apiFetch(logPageUrl('/api/admin/mcp-logs', query))}
              onNotify={notify}
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
              caps={logCaps.portalLogs}
              fetchLogPage={(query) => apiFetch(logPageUrl('/api/admin/portal-logs', query))}
              onNotify={notify}
              onOpenFlyout={(f) => setFlyout(f)}
            />
          )}

          {view === 'auth-settings' && (
            <PortalAuthSettingsView
              oktaSettings={oktaSettings}
              portalUsers={portalUsers}
              onSaveOkta={reportFailure(async (updated) => {
                const data = await apiFetch('/api/admin/okta', {
                  method: 'PUT',
                  body: JSON.stringify(updated),
                });
                if (data.oktaSettings) setOktaSettings(data.oktaSettings);
                await fetchWorkspace();
                notify('Updated Okta OIDC SSO settings');
                return data.oktaSettings;
              })}
              onCreatePortalUser={reportFailure(async (user) => {
                const data = await apiFetch('/api/admin/portal-users', {
                  method: 'POST',
                  body: JSON.stringify(user),
                });
                if (data.portalUsers) setPortalUsers(data.portalUsers);
                await fetchWorkspace();
                notify(`Saved administrator "${user.username}"`);
              })}
              onDeletePortalUser={reportFailureAndStop(async (username) => {
                const data = await apiFetch(
                  `/api/admin/portal-users/${encodeURIComponent(username)}`,
                  { method: 'DELETE' }
                );
                if (data.portalUsers) setPortalUsers(data.portalUsers);
                await fetchWorkspace();
                notify(`Removed administrator "${username}"`);
              })}
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
        devToolsEnabled={devToolsEnabled}
        onUpsertProfile={reportFailure(handleUpsertProfile)}
        onDeleteProfile={reportFailure(handleDeleteProfile)}
        onImportCsv={reportFailure(handleImportCsv)}
        onToggleProfileGroup={reportFailureAndStop(handleToggleProfileGroup)}
        onToggleObject={reportFailureAndStop(handleToggleObject)}
        onToggleField={reportFailureAndStop(handleToggleField)}
        onBulkToggleFields={reportFailureAndStop(handleBulkToggleFields)}
        onSyncSfdxPath={reportFailure(handleSyncSfdxPath)}
        onSyncUploadedFiles={reportFailure(handleSyncUploadedFiles)}
        onOpenOrgObjectCatalogModal={() => {
          setView('objects');
          setOrgCatalogTrigger((c) => c + 1);
        }}
        onSaveGroup={reportFailure(handleSaveGroup)}
        onDeleteGroup={reportFailure(handleDeleteGroup)}
        onLoadGroupHistory={handleLoadGroupHistory}
        onTestMcpCall={reportFailure(handleTestMcpCall)}
        onRefreshWorkspace={fetchWorkspace}
        notify={notify}
      />

      {/* COMMAND PALETTE (Cmd+K) */}
      <CommandPalette
        open={cmdkOpen}
        onClose={() => setCmdkOpen(false)}
        onNavigateView={(v) => setView(v as ActiveView)}
        onOpenFlyout={(f) => setFlyout(f)}
        onSeedEnterpriseMatrix={requestSeedEnterpriseMatrix}
        onToggleTheme={toggleTheme}
        theme={theme}
        profiles={profiles}
        objects={objects}
        groups={groups}
      />

      {/* SAMPLE MATRIX CONFIRMATION */}
      {seedConfirmOpen && (
        <div className="cmdk-scrim" onClick={seedConfirmModal.close}>
          <div
            ref={seedConfirmModal.dialogRef}
            className="cmdk-box"
            role="alertdialog"
            aria-modal="true"
            aria-labelledby="seed-confirm-title"
            aria-describedby="seed-confirm-body"
            tabIndex={-1}
            style={{ maxWidth: 480 }}
            onClick={(e) => e.stopPropagation()}
          >
            <div className="card-h">
              <div className="card-t" id="seed-confirm-title">
                Load the sample enterprise matrix?
              </div>
            </div>
            <div className="card-b">
              <p id="seed-confirm-body" style={{ fontSize: 12.5, color: 'var(--t2)' }}>
                {ENTERPRISE_MATRIX_WARNING}
              </p>
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'flex-end',
                  gap: 8,
                  marginTop: 12,
                }}
              >
                <button
                  ref={seedConfirmModal.initialFocusRef}
                  type="button"
                  className="btn"
                  onClick={seedConfirmModal.close}
                >
                  Cancel
                </button>
                <button
                  type="button"
                  className="btn dng"
                  onClick={() => {
                    seedConfirmModal.close();
                    void reportFailureAndStop(handleSeedEnterpriseMatrix)();
                  }}
                >
                  Replace mappings and load
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TOAST BANNER */}
      {toast && (
        <div className="toast-banner" role={toast.isError ? 'alert' : 'status'}>
          <span className={`dot ${toast.isError ? 'err' : 'ok'}`} />
          <span>{toast.msg}</span>
        </div>
      )}
    </div>
  );
}
