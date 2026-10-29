'use client';

import React, { useState, useEffect, useCallback } from 'react';
import {
  LayoutDashboard,
  Users,
  Database,
  Layers,
  Grid,
  Activity,
  FileText,
  KeyRound,
  LogOut,
  RefreshCw,
  Shield,
  Lock,
  CheckCircle2,
  ChevronRight,
} from 'lucide-react';
import { NavViewId, PortalOverviewPayload } from '@/types/governance';
import {
  SalesforceProfilesView,
  SalesforceObjectsView,
} from '@/components/views/SalesforceViews';
import {
  AccessGroupsView,
  ProfileGroupMatrixView,
} from '@/components/views/AccessMatrixViews';
import {
  TrafficDashboardView,
  CopilotMcpLogsView,
  PortalAdminLogsView,
  PortalAuthSettingsView,
} from '@/components/views/DashboardAndLogsViews';

// Fixed messages for the codes /auth/okta/callback redirects with; any other value is ignored
// so a crafted link cannot put its own text on the login screen.
const OKTA_AUTH_ERRORS: Record<string, string> = {
  okta_error: 'Okta returned an error. Details are in Logs > Portal Admin Activity.',
  invalid_callback: 'The Okta sign-in response was incomplete. Please try again.',
  expired_state: 'The Okta sign-in took too long or was started in another browser. Please try again.',
  state_mismatch: 'The Okta sign-in response did not match this browser session. Please try again.',
  group_denied: 'Your Okta account is not in the group required for this portal.',
  sso_failed: 'Okta sign-in failed. Details are in Logs > Portal Admin Activity.',
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

export default function McpGovernancePortal() {
  const [authenticated, setAuthenticated] = useState<boolean>(false);
  const [checkingSession, setCheckingSession] = useState<boolean>(true);
  const [currentUser, setCurrentUser] = useState<{
    username: string;
    name: string;
    authMethod: string;
  } | null>(null);
  const [csrfToken, setCsrfToken] = useState<string>('');
  const [oktaEnabled, setOktaEnabled] = useState<boolean>(false);

  // Login Form State
  const [loginUsername, setLoginUsername] = useState('');
  const [loginPassword, setLoginPassword] = useState('');
  const [loginError, setLoginError] = useState<string | null>(null);
  const [loggingIn, setLoggingIn] = useState(false);

  // Active Navigation & Overview State
  const [activeView, setActiveView] = useState<NavViewId>('dashboard');
  const [overview, setOverview] = useState<PortalOverviewPayload | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [toast, setToast] = useState<{
    message: string;
    isError?: boolean;
  } | null>(null);

  const showToast = useCallback((message: string, isError?: boolean) => {
    setToast({ message, isError });
    setTimeout(() => {
      setToast((prev) => (prev?.message === message ? null : prev));
    }, 3500);
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
    setAuthenticated(false);
    setCurrentUser(null);
    setOverview(null);
    setCsrfToken('');
    setLoginPassword('');
    setLoginError('Your session has ended. Please sign in again.');
    void refreshLoginOptions();
  }, [refreshLoginOptions]);

  const fetchOverview = useCallback(async () => {
    const res = await fetch('/api/admin/overview', {
      credentials: 'include',
    });
    if (res.status === 401) {
      handleSessionExpired();
      return;
    }
    const data = await readJsonBody(res);
    if (res.ok) {
      setOverview(data as PortalOverviewPayload);
    } else {
      showToast(data.error || `Could not load portal data (${res.status})`, true);
    }
  }, [handleSessionExpired, showToast]);

  const checkSession = useCallback(async () => {
    setCheckingSession(true);
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

      if (data.authenticated) {
        setAuthenticated(true);
        setCurrentUser(data.user);
        setCsrfToken(data.csrfToken || '');
        await fetchOverview();
      } else {
        setAuthenticated(false);
        setCurrentUser(null);
      }
    } catch {
      setAuthenticated(false);
    } finally {
      setCheckingSession(false);
    }
  }, [fetchOverview]);

  useEffect(() => {
    // Okta callback failures come back as /?auth_error=<message>
    const params = new URLSearchParams(window.location.search);
    const authError = params.get('auth_error');
    if (authError) {
      setLoginError(OKTA_AUTH_ERRORS[authError] || 'Okta sign-in failed. Please try again.');
      params.delete('auth_error');
      const query = params.toString();
      window.history.replaceState(null, '', `${window.location.pathname}${query ? `?${query}` : ''}`);
    }
    checkSession();
  }, [checkSession]);

  const apiFetch = useCallback(
    async <T = any>(url: string, options?: RequestInit): Promise<T> => {
      const send = (token: string) => {
        const headers = new Headers(options?.headers || {});
        if (!headers.has('Content-Type') && options?.body) {
          headers.set('Content-Type', 'application/json');
        }
        if (token) {
          headers.set('X-CSRF-Token', token);
        }
        return fetch(url, {
          ...options,
          credentials: 'include',
          headers,
        });
      };

      let res = await send(csrfToken);
      let data = await readJsonBody(res);

      // Signed in again in another tab: pick up the session's current CSRF token and retry once,
      // but only if it is still the same account. Never replay a change as someone else.
      if (res.status === 403 && /CSRF/i.test(String(data.error))) {
        const sessionRes = await fetch('/api/admin/session', { credentials: 'include' });
        const session = await readJsonBody(sessionRes);
        if (session.authenticated && session.csrfToken) {
          const sameAccount =
            session.user?.username === currentUser?.username &&
            session.user?.authMethod === currentUser?.authMethod;
          setCsrfToken(session.csrfToken);
          if (!sameAccount) {
            setCurrentUser(session.user);
            await fetchOverview();
            throw new Error(
              `This browser is now signed in as "${session.user?.username}" (another tab). The change was not applied; review it and try again.`
            );
          }
          res = await send(session.csrfToken);
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
    [csrfToken, currentUser, fetchOverview, handleSessionExpired]
  );

  const handleLoginSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoginError(null);
    setLoggingIn(true);
    try {
      const res = await fetch('/api/admin/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          username: loginUsername.trim(),
          password: loginPassword,
        }),
      });
      const data = await readJsonBody(res);
      if (!res.ok) {
        setLoginError(data.error || 'Login failed');
        return;
      }
      setCsrfToken(data.csrfToken);
      setCurrentUser(data.user);
      setAuthenticated(true);
      setLoginPassword('');
      setLoginError(null);
      await fetchOverview();
    } catch (err: any) {
      setLoginError(err.message || 'Network error');
    } finally {
      setLoggingIn(false);
    }
  };

  const handleLogout = async () => {
    try {
      const res = await fetch('/api/admin/logout', {
        method: 'POST',
        credentials: 'include',
        headers: csrfToken ? { 'X-CSRF-Token': csrfToken } : undefined,
      });
      if (!res.ok) {
        throw new Error(`Sign out failed (${res.status})`);
      }
    } catch (err: any) {
      // Keep the user signed in so they know the session is still active.
      showToast(err?.message || 'Sign out failed', true);
      return;
    }
    setAuthenticated(false);
    setCurrentUser(null);
    setOverview(null);
    setCsrfToken('');
    setLoginPassword('');
    void refreshLoginOptions();
  };

  const handleManualRefresh = async () => {
    setRefreshing(true);
    try {
      await fetchOverview();
    } finally {
      setRefreshing(false);
    }
  };

  if (checkingSession) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-slate-50 text-xs font-semibold text-slate-500">
        Checking portal session...
      </div>
    );
  }

  // =========================================================================
  // 1. PORTAL LOGIN SCREEN (Username/Password OR Okta SSO)
  // =========================================================================
  if (!authenticated) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-slate-100 p-4">
        <div className="w-full max-w-md rounded-2xl border border-slate-200 bg-white p-7 shadow-lg">
          <div className="flex items-center gap-3 border-b border-slate-100 pb-4">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-indigo-600 text-white">
              <Shield className="h-5 w-5" />
            </div>
            <div>
              <h1 className="text-base font-bold text-slate-900">
                Salesforce MCP Server Portal
              </h1>
              <p className="text-xs text-slate-500">
                Sign in with Username & Password or Okta SSO to administer the MCP server
              </p>
            </div>
          </div>

          {loginError && (
            <div className="mt-4 rounded-xl border border-rose-200 bg-rose-50 px-3.5 py-2.5 text-xs font-semibold text-rose-700">
              {loginError}
            </div>
          )}

          <form onSubmit={handleLoginSubmit} className="mt-5 space-y-4">
            <div>
              <label className="block text-xs font-semibold text-slate-700">
                Username
              </label>
              <input
                type="text"
                required
                value={loginUsername}
                onChange={(e) => setLoginUsername(e.target.value)}
                placeholder="admin"
                className="mt-1 w-full rounded-xl border border-slate-200 bg-slate-50 px-3.5 py-2 text-xs text-slate-900 focus:border-indigo-500 focus:bg-white focus:outline-none"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-700">
                Password
              </label>
              <input
                type="password"
                required
                value={loginPassword}
                onChange={(e) => setLoginPassword(e.target.value)}
                placeholder="••••••••"
                className="mt-1 w-full rounded-xl border border-slate-200 bg-slate-50 px-3.5 py-2 text-xs text-slate-900 focus:border-indigo-500 focus:bg-white focus:outline-none"
              />
            </div>

            <button
              type="submit"
              disabled={loggingIn}
              className="w-full rounded-xl bg-indigo-600 py-2.5 text-xs font-bold text-white shadow-xs transition hover:bg-indigo-700 disabled:opacity-50"
            >
              {loggingIn ? 'Signing in...' : 'Sign In with Username & Password'}
            </button>
          </form>

          <div className="my-4 flex items-center gap-3">
            <div className="h-px flex-1 bg-slate-200" />
            <span className="text-[11px] font-semibold text-slate-400 uppercase">
              or
            </span>
            <div className="h-px flex-1 bg-slate-200" />
          </div>

          {oktaEnabled ? (
            <a
              href="/auth/okta/login"
              className="flex w-full items-center justify-center gap-2 rounded-xl border border-slate-200 bg-white py-2.5 text-xs font-bold text-slate-800 transition hover:bg-slate-50"
            >
              <KeyRound className="h-4 w-4 text-indigo-600" />
              <span>Sign In with Okta SSO</span>
            </a>
          ) : (
            <div
              aria-disabled="true"
              className="flex w-full cursor-not-allowed items-center justify-center gap-2 rounded-xl border border-slate-200 bg-slate-50 py-2.5 text-xs font-bold text-slate-400"
            >
              <KeyRound className="h-4 w-4" />
              <span>
                Sign In with Okta SSO{' '}
                <span className="font-normal">(Configure after login)</span>
              </span>
            </div>
          )}

          {process.env.NODE_ENV !== 'production' && (
            <p className="mt-4 text-center font-mono text-[11px] text-slate-400">
              Development default login: <strong className="text-slate-600">admin</strong> /{' '}
              <strong className="text-slate-600">admin123</strong> (unless ADMIN_BOOTSTRAP_* is set)
            </p>
          )}
        </div>
      </div>
    );
  }

  // =========================================================================
  // 2. AUTHENTICATED PORTAL SHELL
  // =========================================================================
  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 antialiased">
      {toast && (
        <div
          className={`fixed right-6 bottom-6 z-50 flex items-center gap-2 rounded-xl border px-4 py-2.5 text-xs font-semibold shadow-lg ${
            toast.isError
              ? 'border-rose-200 bg-rose-600 text-white'
              : 'border-slate-800 bg-slate-900 text-white'
          }`}
        >
          <CheckCircle2 className="h-4 w-4 text-indigo-400" />
          <span>{toast.message}</span>
        </div>
      )}

      {/* Fixed Left Sidebar */}
      <aside className="fixed inset-y-0 left-0 z-30 flex w-64 flex-col border-r border-slate-200 bg-white">
        {/* Brand Header */}
        <div className="flex h-14 items-center justify-between border-b border-slate-100 px-4">
          <div className="flex items-center gap-2.5">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-indigo-600 text-white">
              <Shield className="h-4 w-4" />
            </div>
            <div>
              <div className="text-xs font-bold text-slate-900">
                Salesforce MCP
              </div>
              <div className="text-[10px] text-slate-400">
                Copilot Control Portal
              </div>
            </div>
          </div>
        </div>

        {/* Navigation Links */}
        <nav className="flex-1 space-y-5 overflow-y-auto px-3 py-4 text-xs">
          {/* Top Dashboard Link */}
          <div>
            <button
              onClick={() => setActiveView('dashboard')}
              className={`flex w-full items-center justify-between rounded-lg px-3 py-2 font-semibold transition ${
                activeView === 'dashboard'
                  ? 'bg-indigo-50 text-indigo-600'
                  : 'text-slate-700 hover:bg-slate-50'
              }`}
            >
              <span className="flex items-center gap-2.5">
                <LayoutDashboard className="h-4 w-4" />
                <span>Dashboard (Traffic)</span>
              </span>
            </button>
          </div>

          {/* Configure the MCP Server Section Header */}
          <div className="border-t border-slate-100 pt-3">
            <div className="px-2 text-[10px] font-extrabold tracking-wider text-indigo-600 uppercase">
              Configure the MCP Server
            </div>

            {/* # Salesforce */}
            <div className="mt-3">
              <div className="px-2.5 pb-1 text-[11px] font-bold text-slate-400 uppercase">
                # Salesforce
              </div>
              <div className="space-y-1">
                <button
                  onClick={() => setActiveView('sf-profiles')}
                  className={`flex w-full items-center justify-between rounded-lg px-3 py-2 font-medium transition ${
                    activeView === 'sf-profiles'
                      ? 'bg-indigo-50 font-semibold text-indigo-600'
                      : 'text-slate-600 hover:bg-slate-50 hover:text-slate-900'
                  }`}
                >
                  <span className="flex items-center gap-2">
                    <Users className="h-3.5 w-3.5" />
                    <span>Profiles</span>
                  </span>
                  <span className="rounded bg-slate-100 px-1.5 py-0.5 font-mono text-[10px] text-slate-600">
                    {overview?.profiles.length || 0}
                  </span>
                </button>

                <button
                  onClick={() => setActiveView('sf-objects')}
                  className={`flex w-full items-center justify-between rounded-lg px-3 py-2 font-medium transition ${
                    activeView === 'sf-objects'
                      ? 'bg-indigo-50 font-semibold text-indigo-600'
                      : 'text-slate-600 hover:bg-slate-50 hover:text-slate-900'
                  }`}
                >
                  <span className="flex items-center gap-2">
                    <Database className="h-3.5 w-3.5" />
                    <span>Objects</span>
                  </span>
                  <span className="rounded bg-slate-100 px-1.5 py-0.5 font-mono text-[10px] text-slate-600">
                    {overview?.stats.enabledObjects || 0}/
                    {overview?.stats.totalObjects || 0}
                  </span>
                </button>
              </div>
            </div>

            {/* # Access Matrix */}
            <div className="mt-4">
              <div className="px-2.5 pb-1 text-[11px] font-bold text-slate-400 uppercase">
                # Access Matrix
              </div>
              <div className="space-y-1">
                <button
                  onClick={() => setActiveView('matrix-groups')}
                  className={`flex w-full items-center justify-between rounded-lg px-3 py-2 font-medium transition ${
                    activeView === 'matrix-groups'
                      ? 'bg-indigo-50 font-semibold text-indigo-600'
                      : 'text-slate-600 hover:bg-slate-50 hover:text-slate-900'
                  }`}
                >
                  <span className="flex items-center gap-2">
                    <Layers className="h-3.5 w-3.5" />
                    <span>Groups</span>
                  </span>
                  <span className="rounded bg-slate-100 px-1.5 py-0.5 font-mono text-[10px] text-slate-600">
                    {overview?.groups.length || 0}
                  </span>
                </button>

                <button
                  onClick={() => setActiveView('matrix-profile-groups')}
                  className={`flex w-full items-center justify-between rounded-lg px-3 py-2 font-medium transition ${
                    activeView === 'matrix-profile-groups'
                      ? 'bg-indigo-50 font-semibold text-indigo-600'
                      : 'text-slate-600 hover:bg-slate-50 hover:text-slate-900'
                  }`}
                >
                  <span className="flex items-center gap-2">
                    <Grid className="h-3.5 w-3.5" />
                    <span>Profile Group Matrix</span>
                  </span>
                </button>
              </div>
            </div>

            {/* # Audit Logs & Portal Auth */}
            <div className="mt-4 border-t border-slate-100 pt-3">
              <div className="px-2.5 pb-1 text-[11px] font-bold text-slate-400 uppercase">
                # Logs & Administration
              </div>
              <div className="space-y-1">
                <button
                  onClick={() => setActiveView('logs-copilot')}
                  className={`flex w-full items-center justify-between rounded-lg px-3 py-2 font-medium transition ${
                    activeView === 'logs-copilot'
                      ? 'bg-indigo-50 font-semibold text-indigo-600'
                      : 'text-slate-600 hover:bg-slate-50 hover:text-slate-900'
                  }`}
                >
                  <span className="flex items-center gap-2">
                    <Activity className="h-3.5 w-3.5" />
                    <span>Copilot MCP Logs</span>
                  </span>
                  <span className="rounded bg-slate-100 px-1.5 py-0.5 font-mono text-[10px] text-slate-600">
                    {overview?.copilotLogs.length || 0}
                  </span>
                </button>

                <button
                  onClick={() => setActiveView('logs-portal')}
                  className={`flex w-full items-center justify-between rounded-lg px-3 py-2 font-medium transition ${
                    activeView === 'logs-portal'
                      ? 'bg-indigo-50 font-semibold text-indigo-600'
                      : 'text-slate-600 hover:bg-slate-50 hover:text-slate-900'
                  }`}
                >
                  <span className="flex items-center gap-2">
                    <FileText className="h-3.5 w-3.5" />
                    <span>Portal Admin Logs</span>
                  </span>
                  <span className="rounded bg-slate-100 px-1.5 py-0.5 font-mono text-[10px] text-slate-600">
                    {overview?.portalLogs.length || 0}
                  </span>
                </button>

                <button
                  onClick={() => setActiveView('settings-auth')}
                  className={`flex w-full items-center justify-between rounded-lg px-3 py-2 font-medium transition ${
                    activeView === 'settings-auth'
                      ? 'bg-indigo-50 font-semibold text-indigo-600'
                      : 'text-slate-600 hover:bg-slate-50 hover:text-slate-900'
                  }`}
                >
                  <span className="flex items-center gap-2">
                    <KeyRound className="h-3.5 w-3.5" />
                    <span>Portal Login & Okta SSO</span>
                  </span>
                </button>
              </div>
            </div>
          </div>
        </nav>

        {/* Signed-in User Footer */}
        <div className="border-t border-slate-100 p-3">
          <div className="flex items-center justify-between rounded-xl bg-slate-50 px-3 py-2 text-xs">
            <div className="min-w-0">
              <div className="truncate font-bold text-slate-900">
                {currentUser?.username}
              </div>
              <div className="truncate text-[10px] text-slate-500">
                {currentUser?.authMethod === 'okta_oidc'
                  ? 'Okta SSO'
                  : 'Password Auth'}
              </div>
            </div>
            <button
              onClick={handleLogout}
              title="Sign Out"
              className="rounded-lg p-1.5 text-slate-500 hover:bg-slate-200 hover:text-slate-900"
            >
              <LogOut className="h-4 w-4" />
            </button>
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="pl-64">
        <header className="sticky top-0 z-20 flex h-14 items-center justify-between border-b border-slate-200 bg-white/95 px-6 backdrop-blur-xs">
          <div className="flex items-center gap-2 text-xs">
            <span className="font-semibold text-slate-400">MCP Server</span>
            <ChevronRight className="h-3.5 w-3.5 text-slate-300" />
            <span className="font-bold text-slate-900">
              {activeView === 'dashboard' && 'Dashboard (Traffic Overview)'}
              {activeView === 'sf-profiles' && 'Salesforce > Profiles'}
              {activeView === 'sf-objects' && 'Salesforce > Objects'}
              {activeView === 'matrix-groups' && 'Access Matrix > Groups'}
              {activeView === 'matrix-profile-groups' &&
                'Access Matrix > Profile Group Matrix'}
              {activeView === 'logs-copilot' &&
                'Logs > Copilot MCP Traffic (PII Stripped)'}
              {activeView === 'logs-portal' && 'Logs > Portal Admin Activity'}
              {activeView === 'settings-auth' &&
                'Settings > Portal Login & Okta SSO'}
            </span>
          </div>

          <div className="flex items-center gap-3">
            <span className="rounded-md bg-emerald-50 px-2.5 py-1 font-mono text-[11px] font-semibold text-emerald-700">
              POST /mcp Active
            </span>
            <button
              onClick={handleManualRefresh}
              className="rounded-lg border border-slate-200 p-1.5 text-slate-600 hover:bg-slate-50"
              title="Refresh Data"
            >
              <RefreshCw
                className={`h-3.5 w-3.5 ${
                  refreshing ? 'animate-spin text-indigo-600' : ''
                }`}
              />
            </button>
          </div>
        </header>

        <main className="mx-auto max-w-[1440px] p-6">
          {!overview ? (
            <div className="py-16 text-center text-xs text-slate-400">
              Loading MCP Server state...
            </div>
          ) : (
            <>
              {activeView === 'dashboard' && (
                <TrafficDashboardView
                  overview={overview}
                  apiFetch={apiFetch}
                  onRefresh={handleManualRefresh}
                  onShowToast={showToast}
                  onNavigate={setActiveView}
                />
              )}

              {activeView === 'sf-profiles' && (
                <SalesforceProfilesView
                  profiles={overview.profiles}
                  groups={overview.groups}
                  mappings={overview.profileGroupMappings}
                  apiFetch={apiFetch}
                  onRefresh={handleManualRefresh}
                  onShowToast={showToast}
                  onNavigate={setActiveView}
                />
              )}

              {activeView === 'sf-objects' && (
                <SalesforceObjectsView
                  objects={overview.objects}
                  savedFolderPath={overview.sfSettings.sfdxObjectsFolderPath}
                  apiFetch={apiFetch}
                  onRefresh={handleManualRefresh}
                  onShowToast={showToast}
                />
              )}

              {activeView === 'matrix-groups' && (
                <AccessGroupsView
                  groups={overview.groups}
                  objects={overview.objects}
                  apiFetch={apiFetch}
                  onRefresh={handleManualRefresh}
                  onShowToast={showToast}
                  onNavigate={setActiveView}
                />
              )}

              {activeView === 'matrix-profile-groups' && (
                <ProfileGroupMatrixView
                  profiles={overview.profiles}
                  groups={overview.groups}
                  mappings={overview.profileGroupMappings}
                  apiFetch={apiFetch}
                  onRefresh={handleManualRefresh}
                  onShowToast={showToast}
                  onNavigate={setActiveView}
                />
              )}

              {activeView === 'logs-copilot' && (
                <CopilotMcpLogsView logs={overview.copilotLogs} />
              )}

              {activeView === 'logs-portal' && (
                <PortalAdminLogsView logs={overview.portalLogs} />
              )}

              {activeView === 'settings-auth' && (
                <PortalAuthSettingsView
                  overview={overview}
                  apiFetch={apiFetch}
                  onRefresh={handleManualRefresh}
                  onShowToast={showToast}
                />
              )}
            </>
          )}
        </main>
      </div>
    </div>
  );
}
