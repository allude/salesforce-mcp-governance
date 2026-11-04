'use client';

/**
 * The (portal) pages' client bodies: each reads the shell (usePortal) and its own searchParams
 * (useViewParams) and renders one view. The app/(portal) page files only pick one of these.
 */
import React from 'react';
import {
  CopilotMcpLogsView,
  PortalAdminLogsView,
  PortalAuthSettingsView,
  TrafficDashboardView,
  type AdminLogRouteFilters,
  type McpLogRouteFilters,
} from '@/components/views/DashboardAndLogsViews';
import { SalesforceObjectsView, SalesforceProfilesView, type ObjectRouteFilters } from '@/components/views/SalesforceViews';
import { AccessGroupsView, ProfileGroupMatrixView } from '@/components/views/AccessMatrixViews';
import { SalesforceOrgConnectionView } from '@/components/views/SalesforceOrgConnectionView';
import { CopilotConnectorView } from '@/components/views/CopilotConnectorView';
import { PolicySimulatorView } from '@/components/views/PolicySimulatorView';
import { logPageUrl } from '@/components/views/logHistory';
import type { TrafficRange } from '@/components/views/trafficChart';
import { usePortal } from './PortalShell';
import { useViewParams } from './useViewParams';
import { ViewSkeleton } from './ViewSkeleton';

export function DashboardPage() {
  const p = usePortal();
  const { values, set } = useViewParams('dashboard');
  const d = p.data;
  return (
    <TrafficDashboardView
      clockNow={d.clockNow}
      clockOffsetMs={d.clockOffsetMs}
      copilotLogs={d.copilotLogs}
      mcpStats={d.mcpStats}
      mcpActivity={d.mcpActivity}
      mcpTraffic={d.mcpTraffic}
      portalLogs={d.portalLogs}
      profiles={d.profiles}
      objects={d.objects}
      groups={d.groups}
      mappings={d.mappings}
      sfSettings={d.sfSettings}
      selectedFlyoutId={p.selectedFlyoutId}
      onNavigateTab={(route) => p.navigate(route)}
      onOpenFlyout={p.openFlyout}
      onSeedEnterpriseMatrix={p.requestSeedEnterpriseMatrix}
      range={values.range as TrafficRange}
      onRangeChange={(range) => set({ range })}
    />
  );
}

export function OrgConnectionPage() {
  const p = usePortal();
  if (!p.data.sfSettings) return <ViewSkeleton />;
  return (
    <SalesforceOrgConnectionView
      sfSettings={p.data.sfSettings}
      apiFetch={p.apiFetch}
      onRefresh={p.refresh}
      onShowToast={p.notify}
      onNavigate={(route) => p.navigate(route)}
      devToolsEnabled={p.data.devToolsEnabled}
    />
  );
}

export function OrgProfilesPage() {
  const p = usePortal();
  useViewParams('org-profiles');
  const d = p.data;
  return (
    <SalesforceProfilesView
      profiles={d.profiles}
      groups={d.groups}
      objects={d.objects}
      mappings={d.mappings}
      sfSettings={d.sfSettings}
      selectedFlyoutId={p.selectedFlyoutId}
      onOpenFlyout={p.openFlyout}
      onPreviewPullProfilesFromOrg={p.handlers.previewPullProfilesFromOrg}
      onApplyPullProfilesFromOrg={p.reportFailure(p.handlers.applyPullProfilesFromOrg)}
      onNavigateToOrgConnection={() => p.navigate('org-connection')}
    />
  );
}

export function OrgObjectsPage() {
  const p = usePortal();
  const { values, set } = useViewParams('org-objects');
  const d = p.data;
  const filters: ObjectRouteFilters = {
    status: (values.status as ObjectRouteFilters['status']) || 'all',
    kind: (values.kind as ObjectRouteFilters['kind']) || 'all',
  };
  return (
    <SalesforceObjectsView
      objects={d.objects}
      groups={d.groups}
      sfSettings={d.sfSettings}
      selectedFlyoutId={p.selectedFlyoutId}
      externalCatalogTrigger={p.orgCatalogTrigger}
      onToggleObject={p.reportFailureAndStop(p.handlers.toggleObject)}
      onBulkToggleAllObjects={p.reportFailureAndStop(p.handlers.bulkToggleAllObjects)}
      onOpenFlyout={p.openFlyout}
      onFetchOrgObjectCatalog={p.handlers.fetchOrgObjectCatalog}
      onPreviewPullObjectsFromOrg={p.handlers.previewPullObjectsFromOrg}
      onApplyPullObjectsFromOrg={p.reportFailure(p.handlers.applyPullObjectsFromOrg)}
      onNavigateToOrgConnection={() => p.navigate('org-connection')}
      routeFilters={filters}
      onRouteFiltersChange={(f) => set({ status: f.status === 'all' ? '' : f.status, kind: f.kind === 'all' ? '' : f.kind })}
    />
  );
}

/** /access-groups/groups and /access-groups/groups/[groupId] (the shell opens that group's drawer). */
export function AccessGroupsPage() {
  const p = usePortal();
  const d = p.data;
  return (
    <AccessGroupsView
      groups={d.groups}
      objects={d.objects}
      profiles={d.profiles}
      mappings={d.mappings}
      selectedFlyoutId={p.selectedFlyoutId}
      onOpenFlyout={p.openFlyout}
      onSeedEnterpriseMatrix={p.requestSeedEnterpriseMatrix}
      notify={p.notify}
    />
  );
}

export function AccessMatrixPage() {
  const p = usePortal();
  useViewParams('access-matrix');
  const d = p.data;
  return (
    <ProfileGroupMatrixView
      profiles={d.profiles}
      groups={d.groups}
      objects={d.objects}
      mappings={d.mappings}
      onToggleProfileGroup={p.reportFailureAndStop(p.handlers.toggleProfileGroup)}
      onOpenFlyout={p.openFlyout}
      onSeedEnterpriseMatrix={p.requestSeedEnterpriseMatrix}
    />
  );
}

export function SimulatorPage() {
  const p = usePortal();
  const { values, set } = useViewParams('simulator');
  return (
    <PolicySimulatorView
      profiles={p.data.profiles}
      objects={p.data.objects}
      prefill={{
        profileId: values.profile,
        username: values.user,
        toolName: values.tool,
        targetObject: values.object,
      }}
      onSelectionChange={(s) =>
        set(
          { profile: s.profileId, user: s.username, tool: s.toolName, object: s.targetObject },
          // Typing a username must not add a Back step per keystroke.
          'replace'
        )
      }
      devToolsEnabled={p.data.devToolsEnabled}
      onTestMcpCall={p.reportFailure(p.handlers.testMcpCall)}
      onRefreshWorkspace={p.refresh}
      notify={p.notify}
    />
  );
}

export function LogsMcpPage() {
  const p = usePortal();
  const { values, set } = useViewParams('logs-mcp');
  const filters: McpLogRouteFilters = {
    status: (values.status as McpLogRouteFilters['status']) || 'all',
    tool: values.tool || 'all',
    object: values.object || 'all',
  };
  return (
    <CopilotMcpLogsView
      // A link from a drawer ("this user's calls") seeds the local search; keyed so it re-seeds.
      key={values.user || ''}
      logs={p.data.copilotLogs}
      objects={p.data.objects}
      selectedFlyoutId={p.selectedFlyoutId}
      initialSearch={values.user || ''}
      caps={p.data.logCaps.copilotLogs}
      fetchLogPage={(query) => p.apiFetch(logPageUrl('/api/admin/mcp-logs', query))}
      onNotify={p.notify}
      onOpenFlyout={p.openFlyout}
      routeFilters={filters}
      onRouteFiltersChange={(f) =>
        set({
          status: f.status === 'all' ? '' : f.status,
          tool: f.tool === 'all' ? '' : f.tool,
          object: f.object === 'all' ? '' : f.object,
        })
      }
    />
  );
}

export function LogsAdminPage() {
  const p = usePortal();
  const { values, set } = useViewParams('logs-admin');
  const filters: AdminLogRouteFilters = {
    method: (values.method as AdminLogRouteFilters['method']) || 'all',
    action: values.action || 'all',
  };
  return (
    <PortalAdminLogsView
      logs={p.data.portalLogs}
      selectedFlyoutId={p.selectedFlyoutId}
      caps={p.data.logCaps.portalLogs}
      fetchLogPage={(query) => p.apiFetch(logPageUrl('/api/admin/portal-logs', query))}
      onNotify={p.notify}
      onOpenFlyout={p.openFlyout}
      routeFilters={filters}
      onRouteFiltersChange={(f) =>
        set({ method: f.method === 'all' ? '' : f.method, action: f.action === 'all' ? '' : f.action })
      }
    />
  );
}

export function SettingsSecurityPage() {
  const p = usePortal();
  return (
    <PortalAuthSettingsView
      oktaSettings={p.data.oktaSettings}
      portalUsers={p.data.portalUsers}
      onSaveOkta={p.reportFailure(p.handlers.saveOkta)}
      onCreatePortalUser={p.reportFailure(p.handlers.createPortalUser)}
      onDeletePortalUser={p.reportFailureAndStop(p.handlers.deletePortalUser)}
    />
  );
}

export function SettingsCopilotPage() {
  const p = usePortal();
  const d = p.data;
  return (
    <CopilotConnectorView
      sfSettings={d.sfSettings}
      groups={d.groups}
      mappings={d.mappings}
      objects={d.objects}
      lastMcpCallAt={p.summary ? p.summary.lastMcpCallAt : d.mcpStats?.lastMcpCallAt}
      serverNow={d.clockNow + d.clockOffsetMs}
      onShowToast={p.notify}
      onNavigate={(route) => p.navigate(route)}
    />
  );
}
