'use client';

import React, { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react';
import { usePathname, useRouter, useSearchParams } from 'next/navigation';
import type {
  AccessGroup,
  AccessGroupChangeSource,
  AccessGroupHistoryEntry,
  AdminSession,
  CopilotMcpLogRecord,
  McpActivityFigures,
  McpTrafficSeries,
  OktaSsoSettings,
  PortalAdminLogRecord,
  PortalUserSummary,
  ProfileGroupMapping,
  SalesforceConnectionSettings,
  SalesforceObject,
  SalesforceProfile,
  SearchHit,
  ShellSummary,
} from '@/types/governance';
import type { McpRequestStats } from '@/components/views/DashboardAndLogsViews';
import { FlyoutDrawer, type FlyoutState } from '@/components/views/FlyoutDrawer';
import { CommandPalette } from '@/components/views/CommandPalette';
import { newAccessGroupDraft, type AccessGroupDraft, type WorkspaceSnapshot } from '@/components/views/accessGroupDraft';
import { profileSyncResultMessage } from '@/components/views/profileSyncReview';
import { isCommandPaletteShortcut } from '@/components/views/shortcuts';
import { estimateClockOffsetMs } from '@/components/views/trafficChart';
import { DEFAULT_OVERVIEW_LOG_CAPS, type OverviewLogCaps } from '@/components/views/logHistory';
import { ENTERPRISE_MATRIX_WARNING, enterpriseMatrixAction } from '@/components/views/enterpriseMatrix';
import { anyModalOpen } from '@/components/views/useModalDialog';
import { Dialog, ToastRegion } from '@/components/ui/primitives';
import { dismissToast, pushToast, toastDuration, type ToastItem, type ToastKind } from '@/components/ui/toastQueue';
import { assertAdminApiUrl } from './apiFetchGuard';
import { DraftProvider, useDraftActions, useDraftState } from './draftContext';
import { discardSummary, needsDiscardConfirm } from './policyDraft';
import { createPoller } from './poller';
import { applyTheme, readJsonBody, readTheme, toAdminSession } from './portalClient';
import { LoginForm } from './LoginForm';
import {
  buildHref,
  drawerParam,
  matchRoute,
  parseDrawer,
  parseViewParams,
  ROUTES,
  safePortalHref,
  type DrawerRef,
  type RouteId,
  type ViewParams,
} from './routes';
import { Sidebar } from './Sidebar';
import { Header } from './Header';
import { UnsavedChangesBars } from './UnsavedChangesBars';
import { ViewSkeleton } from './ViewSkeleton';

/** How often the shell asks /summary whether anything changed. */
export const SUMMARY_POLL_MS = 5_000;
/** /overview is reloaded when /summary's ETag changed, or at least this often (logs, traffic). */
const OVERVIEW_MAX_AGE_MS = 30_000;
/** A refresh that hangs (backend stopped mid-request) counts as failed, so the chip turns Degraded. */
const POLL_TIMEOUT_MS = 4_000;

function withTimeout(signal: AbortSignal, ms: number): AbortSignal {
  return AbortSignal.any([signal, AbortSignal.timeout(ms)]);
}

type Session = AdminSession & { expiresAt: string | null };

export interface PortalData {
  profiles: SalesforceProfile[];
  objects: SalesforceObject[];
  groups: AccessGroup[];
  mappings: ProfileGroupMapping[];
  copilotLogs: CopilotMcpLogRecord[];
  portalLogs: PortalAdminLogRecord[];
  logCaps: OverviewLogCaps;
  oktaSettings: OktaSsoSettings;
  sfSettings: SalesforceConnectionSettings | null;
  portalUsers: PortalUserSummary[];
  mcpStats: McpRequestStats | null;
  mcpActivity: McpActivityFigures | null;
  mcpTraffic: McpTrafficSeries | null;
  devToolsEnabled: boolean;
  /** When /overview last answered, on this browser's clock. */
  clockNow: number;
  clockOffsetMs: number;
}

const EMPTY_OKTA: OktaSsoSettings = {
  enabled: false,
  oktaDomain: '',
  clientId: '',
  issuer: '',
  hasClientSecret: false,
  redirectUri: '',
  adminGroup: '',
  updatedAt: '',
};

const EMPTY_DATA: PortalData = {
  profiles: [],
  objects: [],
  groups: [],
  mappings: [],
  copilotLogs: [],
  portalLogs: [],
  logCaps: DEFAULT_OVERVIEW_LOG_CAPS,
  oktaSettings: EMPTY_OKTA,
  sfSettings: null,
  portalUsers: [],
  mcpStats: null,
  mcpActivity: null,
  mcpTraffic: null,
  devToolsEnabled: false,
  clockNow: Date.now(),
  clockOffsetMs: 0,
};

export interface NotifyOptions {
  undo?: { label?: string; run: () => void };
}

export interface PortalContextValue {
  session: Session;
  data: PortalData;
  summary: ShellSummary | null;
  /** Authenticated fetch for /api/admin/* only (assertAdminApiUrl), with the CSRF header. */
  apiFetch: <T = any>(url: string, options?: RequestInit) => Promise<T>;
  /** Reloads /overview (and the shell summary). Answers the snapshot, or null when it failed. */
  refresh: () => Promise<WorkspaceSnapshot | null>;
  notify: (msg: string, isError?: boolean, options?: NotifyOptions) => void;
  /** Shows a failure as an error toast, then rethrows so the caller keeps its form open. */
  reportFailure: <A extends unknown[], R>(fn: (...args: A) => Promise<R>) => (...args: A) => Promise<R>;
  /** Shows a failure as an error toast and ends there (one-click actions). */
  reportFailureAndStop: <A extends unknown[]>(fn: (...args: A) => Promise<unknown>) => (...args: A) => Promise<void>;
  /** Goes to a route, asking first when that would throw away an unsaved form. */
  navigate: (route: RouteId, params?: ViewParams, pathParams?: Record<string, string>) => void;
  /** Opens a drawer: written to the URL (`?drawer=`), so reload, Back and shared links keep it. */
  openFlyout: (next: FlyoutState) => void;
  /** The id the open drawer shows (for the row highlight). */
  selectedFlyoutId: string | undefined;
  /** Bumped to open the org object catalog on the Objects view. */
  orgCatalogTrigger: number;
  /** Absent in production, where the server refuses sample data. */
  requestSeedEnterpriseMatrix: (() => void) | undefined;
  handlers: ReturnType<typeof useWorkspaceHandlers>;
}

const PortalContext = createContext<PortalContextValue | null>(null);

export function usePortal(): PortalContextValue {
  const value = useContext(PortalContext);
  if (!value) throw new Error('usePortal() is only available inside the (portal) layout');
  return value;
}

/**
 * The (portal) layout's client shell: session gate, the workspace data and the refresh loop, the
 * sidebar and header, the drawer and command palette (kept mounted across views, so a group draft
 * survives navigation), toasts and the unsaved-changes guards.
 */
export function PortalShell({ children }: { children: React.ReactNode }) {
  return (
    <DraftProvider>
      <PortalShellInner>{children}</PortalShellInner>
    </DraftProvider>
  );
}

function currentHref(): string {
  return `${window.location.pathname}${window.location.search}`;
}

function PortalShellInner({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const drafts = useDraftState();
  const draftActions = useDraftActions()!;

  const [session, setSession] = useState<Session | null>(null);
  const [oktaEnabled, setOktaEnabled] = useState(false);
  const csrfRef = useRef('');
  const sessionRef = useRef<Session | null>(null);
  sessionRef.current = session;
  const [reauthOpen, setReauthOpen] = useState(false);
  const reauthRef = useRef(false);
  reauthRef.current = reauthOpen;

  const [data, setData] = useState<PortalData>(EMPTY_DATA);
  /** The shell has something to show (first /overview answered, or failed and keeps retrying). */
  const [loaded, setLoaded] = useState(false);
  /** /overview has answered at least once: only then can a shared link be said to name nothing. */
  const [dataReady, setDataReady] = useState(false);
  const [summary, setSummary] = useState<ShellSummary | null>(null);
  const summaryEtag = useRef<string | null>(null);
  const lastOverviewAt = useRef(0);

  const [live, setLive] = useState(true);
  const [lastOkAt, setLastOkAt] = useState<number | null>(null);
  const [failures, setFailures] = useState(0);

  const [toasts, setToasts] = useState<ToastItem[]>([]);
  const toastSeq = useRef(0);
  const [theme, setTheme] = useState<'dark' | 'light'>('dark');
  const [cmdkOpen, setCmdkOpen] = useState(false);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [orgCatalogTrigger, setOrgCatalogTrigger] = useState(0);
  const [seedConfirmOpen, setSeedConfirmOpen] = useState(false);

  /** A guarded action waiting for the admin's answer. */
  const [pendingLeave, setPendingLeave] = useState<{
    keys: string[];
    run: () => void;
    verb: string;
    /** Sign out discards only once the server has signed out (run does it). */
    discardFirst?: boolean;
    onCancel?: () => void;
  } | null>(null);
  const [closePrompt, setClosePrompt] = useState<{ key: string } | null>(null);

  // ----------------------------------------------------------------------------------------------
  // Toasts
  // ----------------------------------------------------------------------------------------------
  const notify = useCallback((message: string, isError = false, options: NotifyOptions = {}) => {
    const kind: ToastKind = isError ? 'error' : 'success';
    const id = ++toastSeq.current;
    const durationMs = toastDuration(kind, Boolean(options.undo));
    setToasts((q) => pushToast(q, { id, kind, message, undo: options.undo, durationMs }));
    if (durationMs !== null) {
      window.setTimeout(() => setToasts((q) => dismissToast(q, id)), durationMs);
    }
  }, []);

  const reportFailure = useCallback(
    <A extends unknown[], R>(fn: (...args: A) => Promise<R>) =>
      async (...args: A): Promise<R> => {
        try {
          return await fn(...args);
        } catch (err: any) {
          notify(err?.message || 'The change could not be saved.', true);
          throw err;
        }
      },
    [notify]
  );
  const reportFailureAndStop = useCallback(
    <A extends unknown[]>(fn: (...args: A) => Promise<unknown>) =>
      async (...args: A): Promise<void> => {
        try {
          await fn(...args);
        } catch (err: any) {
          notify(err?.message || 'The change could not be saved.', true);
        }
      },
    [notify]
  );

  // ----------------------------------------------------------------------------------------------
  // Theme and shortcuts
  // ----------------------------------------------------------------------------------------------
  useEffect(() => setTheme(readTheme()), []);
  const toggleTheme = useCallback(() => {
    setTheme((prev) => {
      const next = prev === 'dark' ? 'light' : 'dark';
      applyTheme(next);
      return next;
    });
  }, []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      // An open modal stops the chord in its capture-phase listener; this is a second fence.
      if (isCommandPaletteShortcut(e) && !anyModalOpen()) {
        e.preventDefault();
        setCmdkOpen(true);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  // ----------------------------------------------------------------------------------------------
  // Session and data
  // ----------------------------------------------------------------------------------------------
  /** A 401 from any call: sign in again in a dialog, keeping every draft on the page. */
  const handleSessionExpired = useCallback(() => {
    if (!sessionRef.current) return;
    setReauthOpen(true);
    void fetch('/api/admin/session', { credentials: 'include' })
      .then(readJsonBody)
      .then((d) => setOktaEnabled(Boolean(d.oktaSso?.enabled)))
      .catch(() => undefined);
  }, []);

  const loadOverview = useCallback(
    async (signal?: AbortSignal): Promise<WorkspaceSnapshot> => {
      const sentAt = Date.now();
      const res = await fetch('/api/admin/overview', { credentials: 'include', cache: 'no-store', signal });
      if (res.status === 401) {
        handleSessionExpired();
        throw Object.assign(new Error('Session ended'), { status: 401 });
      }
      if (!res.ok) throw new Error(`Overview failed (${res.status})`);
      const d = await readJsonBody(res);
      const receivedAt = Date.now();
      lastOverviewAt.current = receivedAt;
      setData((prev) => ({
        profiles: d.profiles || [],
        objects: d.objects || [],
        groups: d.groups || [],
        mappings: d.profileGroupMappings || [],
        copilotLogs: d.copilotLogs || [],
        portalLogs: d.portalLogs || [],
        logCaps: d.logCaps || prev.logCaps,
        oktaSettings: d.oktaSettings || prev.oktaSettings,
        sfSettings: d.sfSettings || prev.sfSettings,
        portalUsers: d.portalUsers || prev.portalUsers,
        mcpStats: d.stats || null,
        mcpActivity: d.mcpActivity || null,
        mcpTraffic: d.mcpTraffic || null,
        devToolsEnabled: d.devToolsEnabled === true,
        clockNow: receivedAt,
        clockOffsetMs: estimateClockOffsetMs(d.serverTime, sentAt, receivedAt),
      }));
      setLoaded(true);
      setDataReady(true);
      return { groups: d.groups || [], objects: d.objects || [] };
    },
    [handleSessionExpired]
  );

  /** GET /summary with If-None-Match. Answers whether it changed since the last answer. */
  const loadSummary = useCallback(
    async (signal?: AbortSignal): Promise<boolean> => {
      const headers = new Headers();
      if (summaryEtag.current) headers.set('If-None-Match', summaryEtag.current);
      const res = await fetch('/api/admin/summary', { credentials: 'include', cache: 'no-store', headers, signal });
      if (res.status === 304) return false;
      if (res.status === 401) {
        handleSessionExpired();
        throw Object.assign(new Error('Session ended'), { status: 401 });
      }
      if (!res.ok) throw new Error(`Summary failed (${res.status})`);
      const body = (await readJsonBody(res)) as ShellSummary;
      summaryEtag.current = res.headers.get('ETag');
      setSummary(body);
      return true;
    },
    [handleSessionExpired]
  );

  const refresh = useCallback(async (): Promise<WorkspaceSnapshot | null> => {
    try {
      const snapshot = await loadOverview();
      void loadSummary().catch(() => undefined);
      return snapshot;
    } catch {
      return null;
    }
  }, [loadOverview, loadSummary]);

  const apiFetch = useCallback(
    async <T = any,>(url: string, options: RequestInit = {}): Promise<T> => {
      // Only the admin API: a view can never send the session cookie and CSRF token anywhere else.
      assertAdminApiUrl(url);
      const send = (token: string) => {
        const headers = new Headers(options.headers || {});
        if (!headers.has('Content-Type') && options.body) headers.set('Content-Type', 'application/json');
        if (token) headers.set('X-CSRF-Token', token);
        return fetch(url, { ...options, credentials: 'include', headers });
      };

      let res = await send(csrfRef.current);
      let body = await readJsonBody(res);

      // Signed in again in another tab: pick up the session's current CSRF token and retry once, but
      // only if it is still the same account. Never replay a change as someone else.
      if (res.status === 403 && /CSRF/i.test(String(body.error))) {
        const current = await readJsonBody(await fetch('/api/admin/session', { credentials: 'include' }));
        if (current.authenticated && current.csrfToken) {
          const was = sessionRef.current;
          const sameAccount =
            current.user?.username === was?.username && current.user?.authMethod === was?.authMethod;
          csrfRef.current = current.csrfToken;
          if (!sameAccount) {
            setSession(toAdminSession(current.user, current.expiresAt));
            await refresh();
            throw new Error(
              `This browser is now signed in as "${current.user?.username}" (another tab). The change was not applied; review it and try again.`
            );
          }
          res = await send(current.csrfToken);
          body = await readJsonBody(res);
        } else if (!current.authenticated) {
          handleSessionExpired();
          throw Object.assign(new Error('Your session has ended. Sign in again, then retry the change.'), {
            status: 401,
          });
        }
      }

      if (res.status === 401) handleSessionExpired();
      if (!res.ok) {
        // The status and body ride along, for a caller that acts on a particular refusal (a 409).
        throw Object.assign(new Error(body.error || `Request failed (${res.status})`), {
          status: res.status,
          body,
        });
      }
      return body as T;
    },
    [refresh, handleSessionExpired]
  );

  // Session gate: no session sends the admin to the sign-in page, which brings them back here.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const res = await fetch('/api/admin/session', { credentials: 'include', cache: 'no-store' });
        const d = await readJsonBody(res);
        if (cancelled) return;
        setOktaEnabled(Boolean(d.oktaSso?.enabled));
        if (res.ok && d.authenticated && d.user) {
          csrfRef.current = d.csrfToken || '';
          // The refresh loop's first run loads /summary and /overview.
          setSession(toAdminSession(d.user, d.expiresAt));
          return;
        }
        // Rebuilt from the route map, so only identifiers and enums ride along (no free text).
        const next = safePortalHref(currentHref());
        router.replace(res.ok && next ? `/?next=${encodeURIComponent(next)}` : '/');
      } catch {
        if (!cancelled) router.replace('/');
      }
    })();
    return () => {
      cancelled = true;
    };
    // Runs once per mount of the layout; the router is stable.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // ----------------------------------------------------------------------------------------------
  // Refresh loop: /summary every 5 s, /overview when it changed or every 30 s; paused while hidden.
  // ----------------------------------------------------------------------------------------------
  const pollerRef = useRef<ReturnType<typeof createPoller> | null>(null);
  useEffect(() => {
    if (!session || reauthOpen || !live) return;
    const poller = createPoller({
      intervalMs: SUMMARY_POLL_MS,
      isHidden: () => document.visibilityState === 'hidden',
      run: async (signal) => {
        const changed = await loadSummary(withTimeout(signal, POLL_TIMEOUT_MS));
        if (changed || Date.now() - lastOverviewAt.current >= OVERVIEW_MAX_AGE_MS) {
          await loadOverview(withTimeout(signal, POLL_TIMEOUT_MS * 2));
        }
      },
      onResult: (r) => {
        if (r.ok) {
          setLastOkAt(r.at);
          setFailures(0);
        } else if ((r.error as any)?.status !== 401) {
          setFailures((n) => n + 1);
          setLoaded((was) => {
            if (!was) notify('The workspace could not be loaded. The shell keeps retrying.', true);
            return true;
          });
        }
      },
    });
    pollerRef.current = poller;
    const onVisibility = () => poller.visibilityChanged();
    document.addEventListener('visibilitychange', onVisibility);
    poller.start();
    return () => {
      document.removeEventListener('visibilitychange', onVisibility);
      poller.stop();
      pollerRef.current = null;
    };
    // session identity changes only on sign-in; the loaders are stable.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [Boolean(session), reauthOpen, live, loadSummary, loadOverview]);

  // Relative times keep moving while the refresh is paused (as the old page's 30 s tick did).
  useEffect(() => {
    if (!session) return;
    const iv = window.setInterval(() => setData((prev) => ({ ...prev, clockNow: Date.now() })), 30_000);
    return () => window.clearInterval(iv);
  }, [Boolean(session)]); // eslint-disable-line react-hooks/exhaustive-deps

  const retryNow = useCallback(() => {
    void pollerRef.current?.refresh();
  }, []);

  // Reload or closing the tab with unsaved work asks first (the browser's own prompt).
  const dirty = Object.keys(drafts).length > 0;
  useEffect(() => {
    if (!dirty) return;
    const onBeforeUnload = (e: BeforeUnloadEvent) => {
      e.preventDefault();
      e.returnValue = '';
    };
    window.addEventListener('beforeunload', onBeforeUnload);
    return () => window.removeEventListener('beforeunload', onBeforeUnload);
  }, [dirty]);

  // ----------------------------------------------------------------------------------------------
  // Navigation and the drawer in the URL
  // ----------------------------------------------------------------------------------------------
  const match = useMemo(() => matchRoute(pathname), [pathname]);
  const drawerRef: DrawerRef | null = useMemo(() => {
    if (match?.route.id === 'access-group') return { type: 'group', id: match.pathParams.groupId };
    return parseDrawer(searchParams.get('drawer'));
  }, [match, searchParams]);

  /** Form drafts are lost when their view unmounts; group drafts live in the drawer, which stays. */
  const formDraftKeys = useCallback(
    () => Object.values(draftActions.read()).filter((e) => e.scope !== 'policy').map((e) => e.key),
    [draftActions]
  );

  const guarded = useCallback(
    (keys: string[], verb: string, run: () => void) => {
      if (keys.length > 0 && needsDiscardConfirm(draftActions.read(), keys)) setPendingLeave({ keys, run, verb });
      else run();
    },
    [draftActions]
  );

  const navigate = useCallback(
    (route: RouteId, params: ViewParams = {}, pathParams: Record<string, string> = {}) => {
      let href: string;
      try {
        href = buildHref(route, params, pathParams);
      } catch {
        return;
      }
      setSidebarOpen(false);
      if (href === currentHref()) return;
      guarded(formDraftKeys(), 'Leave', () => router.push(href));
    },
    [guarded, formDraftKeys, router]
  );

  /** Sidebar and tab links: plain <Link>s, guarded like navigate. */
  const guardLink = useCallback(
    (e: React.MouseEvent<HTMLAnchorElement>, href: string) => {
      if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
      setSidebarOpen(false);
      const keys = formDraftKeys();
      if (keys.length > 0 && needsDiscardConfirm(draftActions.read(), keys)) {
        e.preventDefault();
        setPendingLeave({ keys, run: () => router.push(href), verb: 'Leave' });
      }
    },
    [formDraftKeys, draftActions, router]
  );

  /** What a click opened, kept with its richer data (an import, a template) while the URL names it. */
  const [flyoutMemo, setFlyoutMemo] = useState<{ param: string | null; flyout: FlyoutState } | null>(null);
  const newGroupDraft = useRef<{ param: string; data: AccessGroupDraft } | null>(null);

  const flyout: FlyoutState | null = useMemo(() => {
    if (flyoutMemo && flyoutMemo.param === null) return flyoutMemo.flyout;
    if (!drawerRef) return null;
    const param = drawerParam(drawerRef);
    if (flyoutMemo && param !== null && flyoutMemo.param === param) return flyoutMemo.flyout;
    switch (drawerRef.type) {
      case 'profile': {
        const p = data.profiles.find((x) => x.id === drawerRef.id);
        return p ? { type: 'profile', data: p } : null;
      }
      case 'object': {
        const o = data.objects.find((x) => x.objectName === drawerRef.id);
        return o ? { type: 'object', data: o } : null;
      }
      case 'group': {
        if (drawerRef.id === 'new') {
          if (!newGroupDraft.current || newGroupDraft.current.param !== param) {
            newGroupDraft.current = { param: param!, data: newAccessGroupDraft() };
          }
          return { type: 'group', data: newGroupDraft.current.data };
        }
        const g = data.groups.find((x) => x.id === drawerRef.id);
        return g ? { type: 'group', data: g } : null;
      }
      case 'mcp': {
        const r = data.copilotLogs.find((x: any) => x.id === drawerRef.id);
        return r ? { type: 'traffic', data: r } : null;
      }
      case 'audit': {
        const r = data.portalLogs.find((x: any) => x.id === drawerRef.id);
        return r ? { type: 'audit', data: r } : null;
      }
      default:
        return { type: drawerRef.type };
    }
  }, [drawerRef, flyoutMemo, data]);

  // A shared link to something this workspace does not hold (or no longer loads): say so, drop it.
  useEffect(() => {
    if (!dataReady || !drawerRef || flyout) return;
    const what =
      drawerRef.type === 'mcp' || drawerRef.type === 'audit'
        ? 'That log event is not in the loaded history.'
        : `That ${drawerRef.type} is not in this workspace.`;
    notify(what, true);
    if (match?.route.id === 'access-group') router.replace(buildHref('access-groups'));
    else {
      const params = new URLSearchParams(window.location.search);
      params.delete('drawer');
      const q = params.toString();
      window.history.replaceState(null, '', `${window.location.pathname}${q ? `?${q}` : ''}`);
    }
  }, [dataReady, drawerRef, flyout, match, notify, router]);

  // The drawer the URL no longer names is closed (Back, a link): forget what a click put in memory.
  useEffect(() => {
    if (!flyoutMemo || flyoutMemo.param === null) return;
    if (!drawerRef || drawerParam(drawerRef) !== flyoutMemo.param) setFlyoutMemo(null);
  }, [drawerRef, flyoutMemo]);

  const writeDrawer = useCallback(
    (ref: DrawerRef | null, mode: 'push' | 'replace' = 'push') => {
      const m = matchRoute(window.location.pathname);
      if (!m) return;
      const write = (href: string) =>
        mode === 'push'
          ? window.history.pushState(null, '', href)
          : window.history.replaceState(null, '', href);
      // The Groups tab shows a group at its own path; elsewhere (the Matrix tab too) it is ?drawer=.
      if (ref?.type === 'group' && ref.id !== 'new' && (m.route.id === 'access-groups' || m.route.id === 'access-group')) {
        write(buildHref('access-group', {}, { groupId: ref.id }));
        return;
      }
      const route = m.route.id === 'access-group' ? ROUTES['access-groups'] : m.route;
      const { values } = parseViewParams(route, new URLSearchParams(window.location.search));
      const param = ref ? drawerParam(ref) : null;
      const next = { ...values };
      if (param) next.drawer = param;
      else delete next.drawer;
      const href = buildHref(route.id, next, route.id === m.route.id ? m.pathParams : {});
      if (href !== currentHref()) write(href);
    },
    []
  );

  const groupKeyOf = (f: FlyoutState | null) => (f?.type === 'group' ? `group:${f.data?.id || 'new'}` : null);

  const openFlyout = useCallback(
    (next: FlyoutState) => {
      if (next.type === 'simulator') {
        const d = next.data || {};
        navigate('simulator', {
          profile: d.profileId || '',
          user: d.username || '',
          tool: d.toolName || '',
          object: d.targetObject || '',
        });
        return;
      }
      let ref: DrawerRef;
      switch (next.type) {
        case 'profile':
          ref = { type: 'profile', id: String(next.data?.id ?? '') };
          break;
        case 'object':
          ref = { type: 'object', id: String(next.data?.objectName ?? '') };
          break;
        case 'group':
          ref = { type: 'group', id: next.data?.id ? String(next.data.id) : 'new' };
          break;
        case 'traffic':
          ref = { type: 'mcp', id: String(next.data?.id ?? '') };
          break;
        case 'audit':
          ref = { type: 'audit', id: String(next.data?.id ?? '') };
          break;
        default:
          ref = { type: next.type };
      }
      const param = drawerParam(ref);
      const open = () => {
        setFlyoutMemo({ param, flyout: next });
        // Something the URL may not carry (an id of another shape) still opens, in memory only.
        if (param) writeDrawer(ref);
      };
      // Opening another group would replace a group's unsaved draft.
      const targetKey = next.type === 'group' ? `group:${next.data?.id || 'new'}` : null;
      const isImport = next.type === 'group' && Boolean(next.data?.importDraft);
      const losing = Object.keys(draftActions.read()).filter(
        (k) => k.startsWith('group:') && next.type === 'group' && (k !== targetKey || isImport)
      );
      guarded(losing, 'Discard', () => {
        if (losing.length) draftActions.discard(losing);
        open();
      });
    },
    [navigate, writeDrawer, guarded, draftActions]
  );

  const doCloseFlyout = useCallback(() => {
    setFlyoutMemo(null);
    if (matchRoute(window.location.pathname)?.route.id === 'access-group') {
      window.history.pushState(null, '', buildHref('access-groups'));
    } else {
      writeDrawer(null);
    }
  }, [writeDrawer]);

  const closeFlyout = useCallback(() => {
    const key = groupKeyOf(flyout);
    if (key && draftActions.read()[key]) setClosePrompt({ key });
    else doCloseFlyout();
  }, [flyout, draftActions, doCloseFlyout]);

  /**
   * The URL (Back, Forward, a typed link) names another group while one has an unsaved draft: the
   * drawer would load it over the draft. Hold it and ask; Keep editing goes back to the draft's group.
   * Opening by click (openFlyout) already asked, and leaves its own memo.
   */
  const blockingDraftKey = useMemo(() => {
    if (flyout?.type !== 'group' || flyout.data?.importDraft) return null;
    const key = groupKeyOf(flyout);
    const param = drawerRef ? drawerParam(drawerRef) : null;
    if (flyoutMemo && flyoutMemo.param === param) return null;
    return Object.keys(drafts).find((k) => k.startsWith('group:') && k !== key) ?? null;
  }, [flyout, drawerRef, flyoutMemo, drafts]);

  useEffect(() => {
    if (!blockingDraftKey) return;
    const draftId = blockingDraftKey.slice('group:'.length);
    setPendingLeave({
      keys: [blockingDraftKey],
      verb: 'Open',
      run: () => undefined,
      onCancel: () => writeDrawer({ type: 'group', id: draftId }, 'replace'),
    });
  }, [blockingDraftKey, writeDrawer]);

  const shownFlyout = blockingDraftKey ? null : flyout;

  const selectedFlyoutId: string | undefined = flyout?.data?.id || flyout?.data?.objectName || undefined;

  // ----------------------------------------------------------------------------------------------
  // Mutations
  // ----------------------------------------------------------------------------------------------
  const handlers = useWorkspaceHandlers({ apiFetch, refresh, notify, setData, data });

  const requestSeedEnterpriseMatrix = enterpriseMatrixAction(data.devToolsEnabled, () => setSeedConfirmOpen(true));

  const signOut = useCallback(() => {
    const run = async () => {
      try {
        const res = await fetch('/api/admin/logout', {
          method: 'POST',
          credentials: 'include',
          headers: { 'X-CSRF-Token': csrfRef.current },
        });
        // 401: the session had already ended, which is what Sign out wants anyway.
        if (!res.ok && res.status !== 401) {
          const body = await readJsonBody(res);
          throw new Error(body.error || `Sign out failed (${res.status})`);
        }
      } catch (err: any) {
        // Still signed in: the drafts stay.
        notify(err?.message || 'Sign out failed', true);
        return;
      }
      draftActions.discard();
      setSession(null);
      csrfRef.current = '';
      router.replace('/');
    };
    const keys = Object.keys(draftActions.read());
    if (keys.length > 0) setPendingLeave({ keys, run, verb: 'Sign out', discardFirst: false });
    else void run();
  }, [draftActions, notify, router]);

  const searchIdentifiers = useCallback(
    async (q: string, signal: AbortSignal): Promise<SearchHit[]> => {
      const res = await apiFetch<{ hits: SearchHit[] }>(`/api/admin/search?q=${encodeURIComponent(q)}`, { signal });
      return res.hits || [];
    },
    [apiFetch]
  );

  const openDrawerRef = useCallback(
    async (ref: DrawerRef) => {
      switch (ref.type) {
        case 'profile': {
          const p = data.profiles.find((x) => x.id === ref.id);
          if (p) return openFlyout({ type: 'profile', data: p });
          break;
        }
        case 'object':
        case 'group': {
          if (ref.type === 'group' && ref.id === 'new') return openFlyout({ type: 'group', data: newAccessGroupDraft() });
          const find = (snap: { groups: AccessGroup[]; objects: SalesforceObject[] }) =>
            ref.type === 'group'
              ? snap.groups.find((g) => g.id === ref.id)
              : snap.objects.find((o) => o.objectName === ref.id);
          // A search hit can be newer than the loaded lists (made in another tab): reload, then open.
          const hit = find(data) ?? (await refresh().then((snap) => (snap ? find(snap) : undefined)));
          if (hit) return openFlyout({ type: ref.type, data: hit });
          break;
        }
        case 'mcp':
        case 'audit': {
          // The loaded history holds the latest events only; search finds older ones too.
          const inMemory =
            ref.type === 'mcp'
              ? data.copilotLogs.find((r: any) => r.id === ref.id)
              : data.portalLogs.find((r: any) => r.id === ref.id);
          if (inMemory) return openFlyout({ type: ref.type === 'mcp' ? 'traffic' : 'audit', data: inMemory });
          notify(`${ref.id} is older than the loaded history; find it in its log with "Load older".`, true);
          navigate(ref.type === 'mcp' ? 'logs-mcp' : 'logs-admin');
          return;
        }
        default:
          return openFlyout({ type: ref.type });
      }
      notify(`That ${ref.type} is not in this workspace any more.`, true);
    },
    [openFlyout, data, notify, refresh, navigate]
  );

  // ----------------------------------------------------------------------------------------------
  // Render
  // ----------------------------------------------------------------------------------------------
  const contextValue: PortalContextValue | null = session
    ? {
        session,
        data,
        summary,
        apiFetch,
        refresh,
        notify,
        reportFailure,
        reportFailureAndStop,
        navigate,
        openFlyout,
        selectedFlyoutId,
        orgCatalogTrigger,
        requestSeedEnterpriseMatrix,
        handlers,
      }
    : null;

  if (!session || !contextValue) {
    return (
      <div className="boot" role="status" aria-live="polite">
        <span className="dot" aria-hidden="true" />
        <span className="mono">Checking your session…</span>
      </div>
    );
  }

  return (
    <PortalContext.Provider value={contextValue}>
      <div className={`shell${sidebarOpen ? ' sb-open' : ''}`}>
        <Sidebar
          pathname={pathname}
          summary={summary}
          sfSettings={data.sfSettings}
          session={session}
          onLink={guardLink}
          onSignOut={signOut}
          onClose={() => setSidebarOpen(false)}
        />
        {sidebarOpen && <div className="sb-scrim" onClick={() => setSidebarOpen(false)} aria-hidden="true" />}
        <div className="main">
          <Header
            match={match}
            entity={flyout ? flyoutEntity(flyout) : undefined}
            summary={summary}
            sfSettings={data.sfSettings}
            mcpStats={data.mcpStats}
            clockOffsetMs={data.clockOffsetMs}
            live={live}
            lastOkAt={lastOkAt}
            failures={failures}
            theme={theme}
            onToggleLive={() => setLive((v) => !v)}
            onRetry={retryNow}
            onOpenPalette={() => setCmdkOpen(true)}
            onOpenSidebar={() => setSidebarOpen(true)}
            onToggleTheme={toggleTheme}
            onLink={guardLink}
          />
          <UnsavedChangesBars
            onReview={(scope) => draftActions.review(scope)}
            onDiscard={(keys) => draftActions.discard(keys)}
          />
          <main className="cnt" id="main">
            {loaded ? children : <ViewSkeleton />}
          </main>
        </div>

        <FlyoutDrawer
          flyout={shownFlyout}
          onClose={closeFlyout}
          onOpenFlyout={openFlyout}
          onNavigateView={(route, filterUser) => navigate(route, filterUser ? { user: filterUser } : {})}
          profiles={data.profiles}
          objects={data.objects}
          groups={data.groups}
          mappings={data.mappings}
          sfSettings={data.sfSettings}
          devToolsEnabled={data.devToolsEnabled}
          onUpsertProfile={reportFailure(handlers.upsertProfile)}
          onDeleteProfile={reportFailure(handlers.deleteProfile)}
          onImportCsv={reportFailure(handlers.importCsv)}
          onToggleProfileGroup={reportFailureAndStop(handlers.toggleProfileGroup)}
          onToggleObject={reportFailureAndStop(handlers.toggleObject)}
          onToggleField={reportFailureAndStop(handlers.toggleField)}
          onBulkToggleFields={reportFailureAndStop(handlers.bulkToggleFields)}
          onSyncSfdxPath={reportFailure(handlers.syncSfdxPath)}
          onSyncUploadedFiles={reportFailure(handlers.syncUploadedFiles)}
          onOpenOrgObjectCatalogModal={() => {
            navigate('org-objects');
            setOrgCatalogTrigger((c) => c + 1);
          }}
          onSaveGroup={reportFailure(handlers.saveGroup)}
          onDeleteGroup={reportFailure(handlers.deleteGroup)}
          onLoadGroupHistory={handlers.loadGroupHistory}
          onRefreshWorkspace={refresh}
          notify={notify}
        />

        <CommandPalette
          open={cmdkOpen}
          onClose={() => setCmdkOpen(false)}
          onNavigate={(route, params) => navigate(route, params)}
          onOpenDrawer={openDrawerRef}
          onNewGroup={() => openDrawerRef({ type: 'group', id: 'new' })}
          onSeedEnterpriseMatrix={requestSeedEnterpriseMatrix}
          onToggleTheme={toggleTheme}
          theme={theme}
          profiles={data.profiles}
          objects={data.objects}
          groups={data.groups}
          searchIdentifiers={searchIdentifiers}
        />

        {/* SAMPLE MATRIX CONFIRMATION */}
        <Dialog
          open={seedConfirmOpen}
          onClose={() => setSeedConfirmOpen(false)}
          role="alertdialog"
          title="Load the sample enterprise matrix?"
          description={ENTERPRISE_MATRIX_WARNING}
          footer={({ close, initialFocusRef }) => (
            <>
              <button ref={initialFocusRef} type="button" className="btn" onClick={close}>
                Cancel
              </button>
              <button
                type="button"
                className="btn dng"
                onClick={() => {
                  close();
                  void reportFailureAndStop(handlers.seedEnterpriseMatrix)();
                }}
              >
                Replace mappings and load
              </button>
            </>
          )}
        />

        {/* LEAVING WITH UNSAVED CHANGES */}
        <Dialog
          open={pendingLeave !== null}
          onClose={() => {
            const cancel = pendingLeave?.onCancel;
            setPendingLeave(null);
            cancel?.();
          }}
          role="alertdialog"
          title="Discard unsaved changes?"
          description="These changes have not been saved and will be lost:"
          footer={({ close, initialFocusRef }) => (
            <>
              <button ref={initialFocusRef} type="button" className="btn" onClick={close}>
                Keep editing
              </button>
              <button
                type="button"
                className="btn dng"
                onClick={() => {
                  const pending = pendingLeave;
                  setPendingLeave(null);
                  if (!pending) return;
                  if (pending.discardFirst !== false) draftActions.discard(pending.keys);
                  pending.run();
                }}
              >
                Discard and {pendingLeave?.verb.toLowerCase() ?? 'leave'}
              </button>
            </>
          )}
        >
          <ul className="dlg-list">
            {pendingLeave && discardSummary(drafts, pendingLeave.keys).map((line) => <li key={line}>{line}</li>)}
          </ul>
        </Dialog>

        {/* CLOSING THE DRAWER ON A GROUP DRAFT */}
        <Dialog
          open={closePrompt !== null}
          onClose={() => setClosePrompt(null)}
          role="alertdialog"
          title="This group has unsaved changes"
          description="Keep the draft to come back to it from the Unsaved Changes bar, or discard it."
          footer={({ close, initialFocusRef }) => (
            <>
              <button ref={initialFocusRef} type="button" className="btn" onClick={close}>
                Keep editing
              </button>
              <button
                type="button"
                className="btn"
                onClick={() => {
                  setClosePrompt(null);
                  doCloseFlyout();
                }}
              >
                Close and keep draft
              </button>
              <button
                type="button"
                className="btn dng"
                onClick={() => {
                  const key = closePrompt?.key;
                  setClosePrompt(null);
                  if (key) draftActions.discard([key]);
                  doCloseFlyout();
                }}
              >
                Discard
              </button>
            </>
          )}
        />

        {/* SIGN IN AGAIN (401): the page and its drafts stay */}
        <Dialog
          open={reauthOpen}
          onClose={() => undefined}
          title="Your session has ended"
          description="Sign in again to continue. Unsaved changes on this page are kept."
          width={430}
          initialFocus="box"
        >
          <LoginForm
            oktaEnabled={oktaEnabled}
            lockedUsername={session.authMethod === 'password' ? session.username : undefined}
            oktaNote={oktaEnabled ? 'Okta sign-in leaves this page: unsaved changes are lost.' : undefined}
            autoFocus
            onSignedIn={async ({ user, csrfToken, expiresAt }) => {
              csrfRef.current = csrfToken;
              setSession(toAdminSession(user, expiresAt));
              setReauthOpen(false);
              await refresh();
            }}
          />
        </Dialog>

        <ToastRegion toasts={toasts} onDismiss={(id) => setToasts((q) => dismissToast(q, id))} />
      </div>
    </PortalContext.Provider>
  );
}

function flyoutEntity(f: FlyoutState): string | undefined {
  const d = f.data || {};
  switch (f.type) {
    case 'profile':
      return d.name || d.id;
    case 'object':
      return d.objectName;
    case 'group':
      return d.name || (d.id ? d.id : 'New group');
    case 'traffic':
    case 'audit':
      return d.id;
    default:
      return undefined;
  }
}

// ------------------------------------------------------------------------------------------------
// Workspace mutations (moved from the old single page unchanged, apart from the Undo toast).
// ------------------------------------------------------------------------------------------------
function useWorkspaceHandlers({
  apiFetch,
  refresh,
  notify,
  setData,
  data,
}: {
  apiFetch: PortalContextValue['apiFetch'];
  refresh: () => Promise<WorkspaceSnapshot | null>;
  notify: PortalContextValue['notify'];
  setData: React.Dispatch<React.SetStateAction<PortalData>>;
  data: PortalData;
}) {
  const savingProfileIds = useRef<Set<string>>(new Set());
  const dataRef = useRef(data);
  dataRef.current = data;
  const patch = (p: Partial<PortalData>) => setData((prev) => ({ ...prev, ...p }));

  const upsertProfile = async (id: string, name: string, options?: { creating?: boolean }) => {
    const d = await apiFetch('/api/admin/profiles', {
      method: 'POST',
      body: JSON.stringify({ id, name, creating: options?.creating === true }),
    });
    if (d.profiles) patch({ profiles: d.profiles });
    await refresh();
    notify(`Saved profile "${name}"`);
  };

  const deleteProfile = async (id: string) => {
    const d = await apiFetch(`/api/admin/profiles/${encodeURIComponent(id)}`, { method: 'DELETE' });
    if (d.profiles) patch({ profiles: d.profiles });
    await refresh();
    notify(`Removed profile ${id}`);
  };

  const importCsv = async (csvText: string) => {
    const d = await apiFetch('/api/admin/profiles/import-csv', { method: 'POST', body: JSON.stringify({ csvText }) });
    if (d.profiles) patch({ profiles: d.profiles });
    await refresh();
    notify(
      `Imported profiles from CSV (${d.summary?.inserted || 0} added, ${d.summary?.updated || 0} updated${
        d.summary?.namesKept ? `; ${d.summary.namesKept} stored under two ID forms kept their name` : ''
      })`
    );
  };

  const saveProfileGroupToggle = async (profileId: string, groupId: string) => {
    const has = (dataRef.current.mappings.find((m) => m.profileId === profileId)?.groupIds || []).includes(groupId);
    // Only the toggled membership is sent, so a group changed in another tab stays as it was.
    const d = await apiFetch(`/api/admin/profile-groups/${encodeURIComponent(profileId)}`, {
      method: 'PUT',
      body: JSON.stringify(has ? { remove: [groupId] } : { add: [groupId] }),
    });
    if (d.profileGroupMappings) patch({ mappings: d.profileGroupMappings });
  };

  const toggleProfileGroup = async (profileId: string, groupId: string) => {
    // One save per Profile at a time: a second click before the reload would read the same state and
    // repeat the first toggle instead of reversing it.
    if (savingProfileIds.current.has(profileId)) return;
    savingProfileIds.current.add(profileId);
    try {
      await saveProfileGroupToggle(profileId, groupId);
    } finally {
      savingProfileIds.current.delete(profileId);
      await refresh();
    }
  };

  const putObjectEnabled = async (objectName: string, enabled: boolean) => {
    const d = await apiFetch(`/api/admin/objects/${encodeURIComponent(objectName)}/toggle`, {
      method: 'PUT',
      body: JSON.stringify({ enabled }),
    });
    if (d.objects) patch({ objects: d.objects });
  };

  const toggleObject = async (objectName: string, enabled: boolean) => {
    await putObjectEnabled(objectName, enabled);
    void refresh();
    // Enabling or disabling an SObject is safe to reverse, so it gets an Undo.
    notify(`${objectName} ${enabled ? 'enabled' : 'disabled'}`, false, {
      undo: {
        run: () => {
          void putObjectEnabled(objectName, !enabled)
            .then(() => refresh())
            .then(() => notify(`${objectName} ${enabled ? 'disabled' : 'enabled'} again`))
            .catch((err: any) => notify(err?.message || 'The change could not be undone.', true));
        },
      },
    });
  };

  const bulkToggleAllObjects = async (enabled: boolean) => {
    for (const o of dataRef.current.objects) {
      if (o.enabled !== enabled) {
        await apiFetch(`/api/admin/objects/${encodeURIComponent(o.objectName)}/toggle`, {
          method: 'PUT',
          body: JSON.stringify({ enabled }),
        });
      }
    }
    await refresh();
    notify(`${enabled ? 'Enabled' : 'Disabled'} all Salesforce objects`);
  };

  const toggleField = async (objectName: string, fieldName: string, enabled: boolean) => {
    const d = await apiFetch(
      `/api/admin/objects/${encodeURIComponent(objectName)}/fields/${encodeURIComponent(fieldName)}/toggle`,
      { method: 'PUT', body: JSON.stringify({ enabled }) }
    );
    if (d.objects) patch({ objects: d.objects });
  };

  const bulkToggleFields = async (objectName: string, enabled: boolean) => {
    const d = await apiFetch(`/api/admin/objects/${encodeURIComponent(objectName)}/fields/bulk`, {
      method: 'PUT',
      body: JSON.stringify({ enabled }),
    });
    if (d.objects) patch({ objects: d.objects });
    notify(`${enabled ? 'Enabled' : 'Disabled'} all fields on ${objectName}`);
  };

  const syncSfdxPath = async (folderPath: string) => {
    const d = await apiFetch('/api/admin/objects/import-local-folder', {
      method: 'POST',
      body: JSON.stringify({ folderPath }),
    });
    if (d.objects) patch({ objects: d.objects });
    await refresh();
    notify(`Synced ${d.summary?.objectsImported || 0} objects from ${folderPath}`);
  };

  const syncUploadedFiles = async (files: Array<{ relativePath: string; content: string }>) => {
    const d = await apiFetch('/api/admin/objects/import-sfdx-files', { method: 'POST', body: JSON.stringify({ files }) });
    if (d.objects) patch({ objects: d.objects });
    await refresh();
    notify(`Synced ${d.summary?.objectsImported || 0} SObjects from uploaded SFDX bundle`);
  };

  /** Saves a group from the drawer, whichever view (Visual, XML) or source (import, restore) it came from. */
  const saveGroup = async (group: AccessGroupDraft & { source: AccessGroupChangeSource; sourceDetail: string }) => {
    const { version, ...fields } = group;
    const d = await apiFetch('/api/admin/groups', {
      method: 'POST',
      // An update names the version it was built from, so a group changed elsewhere since is refused
      // (409, with the current group for the drawer's "Reload group") instead of overwritten.
      body: JSON.stringify(fields.id ? { ...fields, expectedVersion: version } : fields),
    });
    if (d.groups) patch({ groups: d.groups });
    await refresh();
    const notAvailable = Array.isArray(d.issues) ? d.issues.length : 0;
    notify(
      `Saved access group "${group.name}"${
        notAvailable > 0 ? `, with ${notAvailable} item${notAvailable === 1 ? '' : 's'} not available or broken` : ''
      }`
    );
    return d.group;
  };

  const loadGroupHistory = useCallback(
    async (groupId: string): Promise<AccessGroupHistoryEntry[]> => {
      const d = await apiFetch(`/api/admin/groups/${encodeURIComponent(groupId)}/history`);
      return d.history || [];
    },
    [apiFetch]
  );

  const deleteGroup = async (groupId: string) => {
    const d = await apiFetch(`/api/admin/groups/${encodeURIComponent(groupId)}`, { method: 'DELETE' });
    if (d.groups) patch({ groups: d.groups });
    if (d.profileGroupMappings) patch({ mappings: d.profileGroupMappings });
    await refresh();
    notify('Deleted access group');
  };

  const seedEnterpriseMatrix = async () => {
    const d = await apiFetch('/api/admin/workspace/seed-sample', { method: 'POST' });
    patch({
      ...(d.profiles ? { profiles: d.profiles } : {}),
      ...(d.objects ? { objects: d.objects } : {}),
      ...(d.groups ? { groups: d.groups } : {}),
      ...(d.profileGroupMappings ? { mappings: d.profileGroupMappings } : {}),
    });
    await refresh();
    notify('Loaded Reference Enterprise Access Matrix (5 Groups + Mappings)');
  };

  const testMcpCall = async (payload: {
    profileId: string;
    toolName: string;
    targetObject: string;
    username?: string;
    samplePayload?: Record<string, unknown>;
  }) => apiFetch('/api/admin/test-mcp-access', { method: 'POST', body: JSON.stringify(payload) });

  const previewPullProfilesFromOrg = async () => {
    const d = await apiFetch('/api/admin/profiles/pull-preview', { method: 'POST' });
    return d.preview;
  };

  const applyPullProfilesFromOrg = async (payload: {
    upserts: Array<{ id: string; name: string }>;
    removeProfileIds: string[];
    keptMissingProfileIds: string[];
  }) => {
    const d = await apiFetch('/api/admin/profiles/pull-apply', { method: 'POST', body: JSON.stringify(payload) });
    if (d.profiles) patch({ profiles: d.profiles });
    await refresh();
    notify(profileSyncResultMessage(d.summary));
  };

  const fetchOrgObjectCatalog = async () => {
    const d = await apiFetch('/api/admin/objects/org-catalog');
    return d.catalog || [];
  };

  const previewPullObjectsFromOrg = async (objectNames: string[]) => {
    const d = await apiFetch('/api/admin/objects/pull-preview', {
      method: 'POST',
      body: JSON.stringify({ objectNames, includeTracked: true }),
    });
    return { preview: d.preview, pulledMetadata: d.pulledMetadata };
  };

  const applyPullObjectsFromOrg = async (payload: {
    pulledMetadata: any[];
    removeObjectNames: string[];
    removeFields: Array<{ objectName: string; fieldName: string }>;
  }) => {
    const d = await apiFetch('/api/admin/objects/pull-apply', { method: 'POST', body: JSON.stringify(payload) });
    if (d.objects) patch({ objects: d.objects });
    await refresh();
    notify(
      `Synced ${d.summary?.objectsUpserted || 0} SObjects (${d.summary?.fieldsUpserted || 0} fields) from Salesforce Org`
    );
  };

  const saveOkta = async (updated: any) => {
    const d = await apiFetch('/api/admin/okta', { method: 'PUT', body: JSON.stringify(updated) });
    if (d.oktaSettings) patch({ oktaSettings: d.oktaSettings });
    await refresh();
    notify('Updated Okta OIDC SSO settings');
    return d.oktaSettings;
  };

  const createPortalUser = async (user: any) => {
    const d = await apiFetch('/api/admin/portal-users', { method: 'POST', body: JSON.stringify(user) });
    if (d.portalUsers) patch({ portalUsers: d.portalUsers });
    await refresh();
    notify(`Saved administrator "${user.username}"`);
  };

  const deletePortalUser = async (username: string) => {
    const d = await apiFetch(`/api/admin/portal-users/${encodeURIComponent(username)}`, { method: 'DELETE' });
    if (d.portalUsers) patch({ portalUsers: d.portalUsers });
    await refresh();
    notify(`Removed administrator "${username}"`);
  };

  return {
    upsertProfile,
    deleteProfile,
    importCsv,
    toggleProfileGroup,
    toggleObject,
    bulkToggleAllObjects,
    toggleField,
    bulkToggleFields,
    syncSfdxPath,
    syncUploadedFiles,
    saveGroup,
    loadGroupHistory,
    deleteGroup,
    seedEnterpriseMatrix,
    testMcpCall,
    previewPullProfilesFromOrg,
    applyPullProfilesFromOrg,
    fetchOrgObjectCatalog,
    previewPullObjectsFromOrg,
    applyPullObjectsFromOrg,
    saveOkta,
    createPortalUser,
    deletePortalUser,
  };
}
