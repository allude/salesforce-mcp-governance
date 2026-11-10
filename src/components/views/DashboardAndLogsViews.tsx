'use client';

import React, { useState, useMemo } from 'react';
import type {
  CopilotMcpLogEntry,
  McpActivityFigures,
  McpTrafficSeries,
  PortalAdminLogEntry,
  SalesforceProfile,
  SalesforceObjectConfig,
  AccessGroup,
  ProfileGroupMapping,
  OktaConfig,
  PortalUser,
  TotpSetup,
  SalesforceConnectionSettings,
} from '@/types/governance';
import { MCP_TOOL_CATALOG, formatShortTime } from '@/components/ui/primitives';
import { PORTAL_PASSWORD_MIN_LENGTH } from '@/security/passwordPolicy';
import type { FlyoutState } from './FlyoutDrawer';
import { realTraffic } from './simulatedTraffic';
import { portalAuditCsv, trafficLogCsv } from './csvExport';
import {
  auditLogKinds,
  auditRouteQuery,
  auditRowMatches,
  describeHeldLogs,
  LOG_EXPORT_MAX_ROWS,
  LOG_EXPORT_PAGE_ROWS,
  exportCutMessage,
  exportFileName,
  emptyOlderRows,
  heldLogGaps,
  loadOlderRows,
  mergeNewestFirst,
  readAllRows,
  trafficLogKinds,
  trafficRouteQuery,
  trafficRowMatches,
  type LogPage,
  type LogQuery,
  type OlderRowsState,
  type OverviewLogCaps,
} from './logHistory';
import { trafficBuckets, trafficChartSubtitle, type TrafficRange } from './trafficChart';
import { SUCCESS_RATE_TARGET, activityWindowLabel, successRate } from './dashboardFigures';

// ============================================================================
// 1. DASHBOARD VIEW
// ============================================================================
export interface McpRequestStats {
  totalMcpRequests: number;
  allowedMcpRequests: number;
  deniedMcpRequests: number;
  erroredMcpRequests: number;
  lastMcpCallAt: string | null;
}

interface TrafficDashboardProps {
  /** Ticks while the live refresh is paused, so calls keep ageing through the buckets. */
  clockNow: number;
  /** Added to clockNow to read it on the server's clock, which stamps the log rows. */
  clockOffsetMs: number;
  mcpStats?: McpRequestStats | null;
  /** Recent verified calls, from the server; null until it has answered. */
  mcpActivity?: McpActivityFigures | null;
  /** The chart's counts, from the server; null until it has answered. */
  mcpTraffic?: McpTrafficSeries | null;
  copilotLogs: CopilotMcpLogEntry[];
  portalLogs: PortalAdminLogEntry[];
  profiles: SalesforceProfile[];
  objects: SalesforceObjectConfig[];
  groups: AccessGroup[];
  mappings?: ProfileGroupMapping[];
  sfSettings?: SalesforceConnectionSettings | null;
  selectedFlyoutId?: string;
  onNavigateTab: (tab: string) => void;
  onOpenFlyout: (flyout: FlyoutState) => void;
  onSeedEnterpriseMatrix?: () => void;
}

export function TrafficDashboardView({
  clockNow,
  clockOffsetMs,
  copilotLogs,
  mcpStats,
  mcpActivity,
  mcpTraffic,
  profiles,
  objects,
  groups,
  mappings = [],
  sfSettings,
  onNavigateTab,
  onOpenFlyout,
  onSeedEnterpriseMatrix,
}: TrafficDashboardProps) {
  const [range, setRange] = useState<TrafficRange>('24h');

  const getProfileGroupIds = (profileId: string): string[] => {
    const found = mappings.find((m) => m.profileId === profileId);
    return found ? found.groupIds : [];
  };

  const realLogs = useMemo(() => realTraffic(copilotLogs), [copilotLogs]);

  // KPI metrics
  // Totals and activity figures come from the server: copilotLogs holds only the latest rows of each
  // kind, so a figure taken from it would weigh rejected tokens and verified calls unevenly.
  const totalCalls = mcpStats?.totalMcpRequests ?? realLogs.length;
  const allowedCalls =
    mcpStats?.allowedMcpRequests ??
    realLogs.filter((l) => l.status === 'ALLOWED').length;
  const deniedCalls =
    mcpStats?.deniedMcpRequests ??
    realLogs.filter((l) => l.status === 'DENIED').length;
  const errorCalls =
    mcpStats?.erroredMcpRequests ??
    realLogs.filter((l) => l.status === 'ERROR').length;
  const success = successRate(totalCalls, errorCalls);

  const activityWindow = activityWindowLabel(mcpActivity, clockNow + clockOffsetMs);
  const verifiedCalls = mcpActivity?.verifiedCalls ?? 0;
  const p95Latency = mcpActivity?.p95LatencyMs ?? 0;
  const avgLatency = mcpActivity?.avgLatencyMs ?? 0;
  const uniqueUsers = mcpActivity?.activeUsers ?? 0;
  const uniqueProfilesInLogs = mcpActivity?.activeProfiles ?? 0;

  const buckets = useMemo(
    () => trafficBuckets(mcpTraffic?.[range], range, clockNow + clockOffsetMs),
    [mcpTraffic, range, clockNow, clockOffsetMs]
  );
  const callsInRange = buckets.reduce((acc, b) => acc + b.ok + b.warn + b.err, 0);

  const maxBucket = Math.max(
    1,
    ...buckets.map((b) => b.ok + b.warn + b.err)
  );

  const topTools = mcpActivity?.topTools ?? [];
  const maxToolCount = Math.max(1, ...topTools.map((t) => t.calls));
  const topUsers = mcpActivity?.topUsers ?? [];
  const maxUserCount = Math.max(1, ...topUsers.map((u) => u.calls));

  // Governance health / Needs attention
  const unassignedProfiles = profiles.filter(
    (p) => getProfileGroupIds(p.id).length === 0
  );
  const disabledObjects = objects.filter((o) => !o.enabled);
  const missingInOrgCount =
    profiles.filter((p) => p.missingInOrg).length +
    objects.filter(
      (o) => o.missingInOrg || o.fields.some((f) => f.missingInOrg)
    ).length;
  const destructiveGroups = groups.filter((g) =>
    g.allowedActions?.includes('delete_record')
  );
  const recentDenials = realLogs
    .filter((l) => l.status === 'DENIED')
    .slice(0, 5);

  const totalFields = objects.reduce((acc, o) => acc + o.fields.length, 0);
  const enabledFields = objects.reduce(
    (acc, o) => acc + o.fields.filter((f) => f.enabled).length,
    0
  );

  return (
    <div>
      <div className="ph">
        <div className="ph-l">
          <h1>Dashboard</h1>
          <p>MCP server traffic, policy health, and recent activity.</p>
        </div>
        <div className="ph-act">
          {groups.length <= 1 && onSeedEnterpriseMatrix && (
            <button
              type="button"
              className="btn"
              onClick={onSeedEnterpriseMatrix}
              title="Populate 5 standard Enterprise Access Groups & Profile mappings"
            >
              Load enterprise matrix
            </button>
          )}
          <button
            type="button"
            className="btn"
            onClick={() => onOpenFlyout({ type: 'simulator' })}
          >
            Simulate MCP call
          </button>
          <button
            type="button"
            className="btn"
            onClick={() => onNavigateTab('traffic')}
          >
            View traffic log
          </button>
          <button
            type="button"
            className="btn pri"
            onClick={() => onNavigateTab('matrix')}
          >
            Configure access matrix
          </button>
        </div>
      </div>

      {/* KPI Strip */}
      <div className="kpis">
        <div className="kpi">
          <div className="k-lbl">
            <span>MCP requests</span>
            <span className="mono">ALL TIME</span>
          </div>
          <div className="k-val">{totalCalls}</div>
          <div className="k-sub">
            <span>
              Allowed: <b style={{ color: 'var(--tx)' }}>{allowedCalls}</b> ·
              Denied: <b style={{ color: 'var(--warn)' }}>{deniedCalls}</b>
            </span>
          </div>
        </div>

        <div className="kpi">
          <div className="k-lbl">
            <span>Success rate</span>
            <span className={`dot ${success.meetsTarget ? 'ok' : 'err'}`} />
          </div>
          <div className="k-val">{success.label}%</div>
          <div className="k-sub">
            <span>
              {errorCalls} errors · denials are not failures · target ≥{' '}
              {SUCCESS_RATE_TARGET.toFixed(1)}%
            </span>
          </div>
        </div>

        <div className="kpi">
          <div className="k-lbl">
            <span>Policy denials</span>
            <span className="dot warn" />
          </div>
          <div className="k-val">{deniedCalls}</div>
          <div className="k-sub">
            <span>
              {totalCalls
                ? ((deniedCalls / totalCalls) * 100).toFixed(1)
                : '0.0'}
              % of traffic · RBAC enforced
            </span>
          </div>
        </div>

        <div className="kpi">
          <div className="k-lbl">
            <span>p95 latency</span>
            <span className="mono">ms</span>
          </div>
          <div className="k-val">{p95Latency}</div>
          <div className="k-sub">
            <span>
              avg {avgLatency} ms · {verifiedCalls} verified calls,{' '}
              {activityWindow}
            </span>
          </div>
        </div>

        <div className="kpi">
          <div className="k-lbl">
            <span>Active users</span>
            <span className="mono">Copilot</span>
          </div>
          <div className="k-val">{uniqueUsers}</div>
          <div className="k-sub">
            <span>
              across {uniqueProfilesInLogs} profiles, {activityWindow}
            </span>
          </div>
        </div>
      </div>

      {/* Traffic Chart + Governance Needs Attention */}
      <div className="g2">
        <div className="card">
          <div className="card-h">
            <div>
              <div className="card-t">MCP server traffic</div>
              <div className="card-s">
                {trafficChartSubtitle(range, callsInRange)}
              </div>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <div className="leg">
                <span>
                  <i style={{ background: 'rgba(0,163,255,0.8)' }} /> Allowed
                </span>
                <span>
                  <i style={{ background: 'rgba(251,191,36,0.9)' }} /> Denied
                </span>
                <span>
                  <i style={{ background: 'rgba(248,113,113,0.9)' }} /> Error
                </span>
              </div>
              <div className="seg">
                {(['1h', '24h', '7d'] as const).map((k) => (
                  <button
                    key={k}
                    type="button"
                    className={range === k ? 'on' : ''}
                    onClick={() => setRange(k)}
                  >
                    {k.toUpperCase()}
                  </button>
                ))}
              </div>
            </div>
          </div>
          <div className="card-b">
            <div className="bars">
              {buckets.map((b, i) => {
                const tot = b.ok + b.warn + b.err;
                const h = tot > 0 ? Math.max(8, (tot / maxBucket) * 108) : 3;
                const okH = tot ? (b.ok / tot) * h : 0;
                const warnH = tot ? (b.warn / tot) * h : 0;
                const errH = tot ? (b.err / tot) * h : 0;
                return (
                  <div
                    className="b-col"
                    key={i}
                    title={`${b.span} — ${b.ok} allowed, ${b.warn} denied, ${b.err} error`}
                  >
                    <div className="b-stk" style={{ height: `${h}px` }}>
                      <div
                        className="b-seg ok"
                        style={{ height: `${okH}px` }}
                      />
                      <div
                        className="b-seg warn"
                        style={{ height: `${warnH}px` }}
                      />
                      <div
                        className="b-seg err"
                        style={{ height: `${errH}px` }}
                      />
                    </div>
                    <div className="b-lbl">
                      {(buckets.length - 1 - i) % 3 === 0 ? b.lbl : ''}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        <div className="card">
          <div className="card-h">
            <div>
              <div className="card-t">Needs attention</div>
              <div className="card-s">Governance checks on current config</div>
            </div>
            <span className="tag mono">
              {unassignedProfiles.length +
                disabledObjects.length +
                destructiveGroups.length +
                missingInOrgCount}{' '}
              items
            </span>
          </div>
          <div
            className="card-b"
            style={{ display: 'flex', flexDirection: 'column', gap: 8 }}
          >
            {unassignedProfiles.length > 0 && (
              <div
                className="chk-row"
                style={{
                  border: '1px solid var(--bd)',
                  borderRadius: 6,
                  cursor: 'pointer',
                }}
                onClick={() => onNavigateTab('matrix')}
              >
                <div>
                  <div
                    style={{ display: 'flex', alignItems: 'center', gap: 6 }}
                  >
                    <span className="dot warn" />
                    <b>
                      {unassignedProfiles.length} profile
                      {unassignedProfiles.length > 1 ? 's' : ''} have no group
                      assigned
                    </b>
                  </div>
                  <div
                    style={{
                      fontSize: 11.5,
                      color: 'var(--t3)',
                      marginTop: 2,
                    }}
                  >
                    {unassignedProfiles
                      .slice(0, 3)
                      .map((p) => p.name)
                      .join(', ')}
                    {unassignedProfiles.length > 3
                      ? ` +${unassignedProfiles.length - 3} more`
                      : ''}{' '}
                    — all MCP calls denied
                  </div>
                </div>
                <span className="tag">Assign &rarr;</span>
              </div>
            )}

            {disabledObjects.length > 0 && (
              <div
                className="chk-row"
                style={{
                  border: '1px solid var(--bd)',
                  borderRadius: 6,
                  cursor: 'pointer',
                }}
                onClick={() => onNavigateTab('objects')}
              >
                <div>
                  <div
                    style={{ display: 'flex', alignItems: 'center', gap: 6 }}
                  >
                    <span className="dot off" />
                    <b>
                      {disabledObjects.length} object
                      {disabledObjects.length > 1 ? 's' : ''} switched off
                    </b>
                  </div>
                  <div
                    style={{
                      fontSize: 11.5,
                      color: 'var(--t3)',
                      marginTop: 2,
                    }}
                  >
                    {disabledObjects
                      .slice(0, 4)
                      .map((o) => o.objectName)
                      .join(', ')}
                    {disabledObjects.length > 4
                      ? ` +${disabledObjects.length - 4} more`
                      : ''}{' '}
                    — review fields before enabling
                  </div>
                </div>
                <span className="tag">Review &rarr;</span>
              </div>
            )}

            {missingInOrgCount > 0 && (
              <div
                className="chk-row"
                style={{
                  border: '1px solid var(--bd)',
                  borderRadius: 6,
                  cursor: 'pointer',
                }}
                onClick={() => onNavigateTab('objects')}
              >
                <div>
                  <div
                    style={{ display: 'flex', alignItems: 'center', gap: 6 }}
                  >
                    <span className="dot warn" />
                    <b>
                      {missingInOrgCount} metadata item
                      {missingInOrgCount > 1 ? 's' : ''} flagged Missing in Org
                    </b>
                  </div>
                  <div
                    style={{
                      fontSize: 11.5,
                      color: 'var(--t3)',
                      marginTop: 2,
                    }}
                  >
                    Drift detected between local governance store and Salesforce
                    org
                  </div>
                </div>
                <span className="tag warn">Reconcile &rarr;</span>
              </div>
            )}

            {destructiveGroups.length > 0 && (
              <div
                className="chk-row"
                style={{
                  border: '1px solid var(--bd)',
                  borderRadius: 6,
                  cursor: 'pointer',
                }}
                onClick={() => onNavigateTab('groups')}
              >
                <div>
                  <div
                    style={{ display: 'flex', alignItems: 'center', gap: 6 }}
                  >
                    <span className="dot err" />
                    <b>
                      {destructiveGroups.length} group
                      {destructiveGroups.length > 1 ? 's' : ''} allow{' '}
                      <span className="mono">delete_record</span>
                    </b>
                  </div>
                  <div
                    style={{
                      fontSize: 11.5,
                      color: 'var(--t3)',
                      marginTop: 2,
                    }}
                  >
                    {destructiveGroups.map((g) => g.name).join(', ')}
                  </div>
                </div>
                <span className="tag">Inspect &rarr;</span>
              </div>
            )}

            <div
              className="chk-row"
              style={{
                border: '1px solid var(--bd)',
                borderRadius: 6,
                cursor: 'pointer',
              }}
              onClick={() => onNavigateTab('sf-connection')}
            >
              <div>
                <div
                  style={{ display: 'flex', alignItems: 'center', gap: 6 }}
                >
                  <span
                    className={`dot ${
                      sfSettings?.connectionStatus === 'connected'
                        ? 'ok'
                        : 'warn'
                    }`}
                  />
                  <b>
                    Salesforce Org JWT:{' '}
                    {sfSettings?.connectionStatus === 'connected'
                      ? `Connected (${sfSettings.connectedOrgId})`
                      : sfSettings?.connectionStatus === 'not_verified'
                      ? 'Not verified'
                      : 'Disconnected'}
                  </b>
                </div>
                <div
                  style={{
                    fontSize: 11.5,
                    color: 'var(--t3)',
                    marginTop: 2,
                  }}
                >
                  {sfSettings?.connectionStatus === 'connected'
                    ? `User: ${sfSettings.connectedUser} · ${sfSettings.syncInstanceUrl}`
                    : sfSettings?.connectionStatus === 'not_verified'
                    ? 'Settings changed. Connect & Verify again to pull live Profiles & Objects'
                    : 'Configure OAuth 2.0 JWT Bearer to pull live Profiles & Objects'}
                </div>
              </div>
              <span className="tag">Org JWT &rarr;</span>
            </div>

            <div
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                padding: '6px 4px 0',
                fontSize: 11.5,
                color: 'var(--t3)',
              }}
            >
              <span>Config summary</span>
              <span className="mono">
                {objects.filter((o) => o.enabled).length}/{objects.length}{' '}
                objects · {enabledFields}/{totalFields} fields · {groups.length}{' '}
                groups
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Bottom 3 Cards */}
      <div className="g3">
        <div className="card">
          <div className="card-h">
            <div className="card-t">Most used tools</div>
            <span className="card-s">by verified calls, {activityWindow}</span>
          </div>
          <div
            className="card-b"
            style={{ display: 'flex', flexDirection: 'column', gap: 8 }}
          >
            {topTools.length === 0 ? (
              <div className="empty">No verified MCP calls in the {activityWindow}.</div>
            ) : (
              topTools.map(({ toolName: tool, calls: n }) => (
                <div key={tool}>
                  <div
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      fontSize: 12,
                      marginBottom: 3,
                    }}
                  >
                    <span className="mono">{tool}</span>
                    <span className="mono" style={{ color: 'var(--t2)' }}>
                      {n}
                    </span>
                  </div>
                  <div
                    style={{
                      height: 5,
                      background: 'var(--bg)',
                      borderRadius: 3,
                      overflow: 'hidden',
                    }}
                  >
                    <div
                      style={{
                        width: `${(n / maxToolCount) * 100}%`,
                        height: '100%',
                        background:
                          tool === 'delete_record'
                            ? 'var(--err)'
                            : 'var(--acc)',
                      }}
                    />
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        <div className="card">
          <div className="card-h">
            <div className="card-t">Most active users</div>
            <span className="card-s">Copilot callers, {activityWindow}</span>
          </div>
          <div
            className="card-b"
            style={{ display: 'flex', flexDirection: 'column', gap: 8 }}
          >
            {topUsers.length === 0 ? (
              <div className="empty">No verified callers in the {activityWindow}.</div>
            ) : (
              topUsers.map((u) => (
                <div key={u.username}>
                  <div
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      fontSize: 12,
                      marginBottom: 3,
                    }}
                  >
                    <span>
                      {u.username}{' '}
                      <span style={{ color: 'var(--t3)', fontSize: 11 }}>
                        · {u.profileName}
                      </span>
                    </span>
                    <span className="mono" style={{ color: 'var(--t2)' }}>
                      {u.calls}
                    </span>
                  </div>
                  <div
                    style={{
                      height: 5,
                      background: 'var(--bg)',
                      borderRadius: 3,
                      overflow: 'hidden',
                    }}
                  >
                    <div
                      style={{
                        width: `${(u.calls / maxUserCount) * 100}%`,
                        height: '100%',
                        background: 'var(--acc)',
                      }}
                    />
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        <div className="card">
          <div className="card-h">
            <div className="card-t">Recent denials</div>
            <button
              type="button"
              className="btn gh sm"
              onClick={() => onNavigateTab('traffic')}
            >
              View in log &rarr;
            </button>
          </div>
          <div className="card-b" style={{ padding: 0 }}>
            {recentDenials.length === 0 ? (
              <div className="empty">No policy denials in window.</div>
            ) : (
              recentDenials.map((r) => (
                <div
                  key={r.id}
                  className="chk-row"
                  style={{ cursor: 'pointer', padding: '8px 14px' }}
                  onClick={() => onOpenFlyout({ type: 'traffic', data: r })}
                >
                  <div>
                    <div className="mono" style={{ fontSize: 11.5 }}>
                      {r.toolName}({r.targetObject})
                    </div>
                    <div style={{ fontSize: 11, color: 'var(--t3)' }}>
                      {r.sfUsername} · {r.profileName}
                    </div>
                  </div>
                  <span className="mono" style={{ color: 'var(--t3)' }}>
                    {formatShortTime(r.timestamp)}
                  </span>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

// ============================================================================
// 2. COPILOT MCP TRAFFIC LOG VIEW
// ============================================================================

/** Reads one page of a paged log route; the views pass the filters and cursor as the query. */
export type FetchLogPage<T> = (query: LogQuery) => Promise<LogPage<T>>;

function downloadCsv(csv: string, fileName: string) {
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = fileName;
  a.click();
  URL.revokeObjectURL(url);
}

/**
 * Older rows read through a paged log route, held beside the capped /overview list. `cursor` is
 * undefined before the first page and null once the oldest row has been read. `reload` drops the
 * loaded pages and reads down from the newest row again, which closes a gap live refreshes opened.
 */
function useOlderLogRows<T extends { id: string; seq?: number }>(
  logs: T[],
  fetchPage: FetchLogPage<T>,
  onNotify: (msg: string, isError?: boolean) => void
) {
  const [state, setState] = useState<OlderRowsState<T>>(emptyOlderRows);
  const [loading, setLoading] = useState(false);
  // Bumped by each read, so only the pages of the newest read are kept.
  const generation = React.useRef(0);
  const held = useMemo(() => mergeNewestFirst(logs, state.older), [logs, state.older]);

  const read = async (from: OlderRowsState<T>) => {
    if (loading || from.cursor === null) return;
    const run = ++generation.current;
    setLoading(true);
    try {
      const next = await loadOlderRows((before, limit) => fetchPage({ before, limit }), from, logs);
      if (run === generation.current) setState(next);
    } catch (err) {
      onNotify(`Could not load older rows: ${err instanceof Error ? err.message : String(err)}`, true);
    } finally {
      setLoading(false);
    }
  };

  const loadOlder = () => read(state);
  const reload = () => read(emptyOlderRows<T>());

  return {
    held,
    older: state.older,
    cursor: state.cursor,
    loadedTop: state.loadedTop,
    loading,
    loadOlder,
    reload,
  };
}

/** The toolbar's account of the rows held, with a Reload button when live refreshes opened a gap. */
function HeldLogsNote({
  text,
  gap,
  loading,
  onReload,
}: {
  text: string;
  gap: boolean;
  loading: boolean;
  onReload: () => void;
}) {
  return (
    <>
      <span className="mono" style={{ color: 'var(--t3)' }} title="What this view holds">
        ({text})
      </span>
      {gap && (
        <button type="button" className="btn sm" disabled={loading} onClick={onReload}>
          {loading ? 'Loading…' : 'Reload'}
        </button>
      )}
    </>
  );
}

/** Exports every matching row through the paged route, up to the export limit, and says when it was cut. */
function useLogExport<T>(
  fetchPage: FetchLogPage<T>,
  onNotify: (msg: string, isError?: boolean) => void
) {
  const [exporting, setExporting] = useState(false);
  const exportRows = async (
    routeQuery: LogQuery,
    keep: (row: T) => boolean,
    toCsv: (rows: T[]) => string,
    fileBase: string
  ) => {
    if (exporting) return;
    setExporting(true);
    try {
      // The route cannot apply the free-text search, so the limits count rows after `keep`.
      const { rows, cut } = await readAllRows(
        (before, limit) => fetchPage({ ...routeQuery, before, limit }),
        LOG_EXPORT_MAX_ROWS,
        LOG_EXPORT_PAGE_ROWS,
        { keep }
      );
      const date = new Date().toISOString().slice(0, 10);
      downloadCsv(toCsv(rows), exportFileName(fileBase, date, cut));
      if (cut) onNotify(exportCutMessage(cut));
    } catch (err) {
      onNotify(`Export failed: ${err instanceof Error ? err.message : String(err)}`, true);
    } finally {
      setExporting(false);
    }
  };
  return { exporting, exportRows };
}

function LoadOlderFooter({
  cursor,
  loading,
  onLoad,
}: {
  cursor: number | null | undefined;
  loading: boolean;
  onLoad: () => void;
}) {
  return (
    <div className="tbl-more">
      {cursor === null ? (
        <span>Start of the log reached.</span>
      ) : (
        <button type="button" className="btn sm" disabled={loading} onClick={onLoad}>
          {loading ? 'Loading…' : 'Load older'}
        </button>
      )}
    </div>
  );
}

interface CopilotMcpLogsViewProps {
  logs: CopilotMcpLogEntry[];
  objects: SalesforceObjectConfig[];
  selectedFlyoutId?: string;
  initialSearch?: string;
  caps: OverviewLogCaps['copilotLogs'];
  fetchLogPage: FetchLogPage<CopilotMcpLogEntry>;
  onNotify: (msg: string, isError?: boolean) => void;
  onOpenFlyout: (flyout: FlyoutState) => void;
}

export function CopilotMcpLogsView({
  logs,
  objects,
  selectedFlyoutId,
  initialSearch = '',
  caps,
  fetchLogPage,
  onNotify,
  onOpenFlyout,
}: CopilotMcpLogsViewProps) {
  const [q, setQ] = useState(initialSearch);
  const [statusFilter, setStatusFilter] = useState<
    'all' | 'ALLOWED' | 'DENIED' | 'ERROR'
  >('all');
  const [toolFilter, setToolFilter] = useState('all');
  const [objFilter, setObjFilter] = useState('all');
  const history = useOlderLogRows(logs, fetchLogPage, onNotify);
  const { exporting, exportRows } = useLogExport(fetchLogPage, onNotify);

  React.useEffect(() => {
    if (initialSearch) setQ(initialSearch);
  }, [initialSearch]);

  const filters = useMemo(
    () => ({ status: statusFilter, tool: toolFilter, object: objFilter, search: q }),
    [statusFilter, toolFilter, objFilter, q]
  );
  const rows = useMemo(
    () => history.held.filter((r) => trafficRowMatches(r, filters)),
    [history.held, filters]
  );

  const exportCsv = () =>
    exportRows(trafficRouteQuery(filters), (r) => trafficRowMatches(r, filters), trafficLogCsv, 'mcp-traffic-log');

  const kinds = trafficLogKinds(caps);
  const gap = heldLogGaps({ overview: logs, loadedTop: history.loadedTop, kinds }).length > 0;
  const heldText = describeHeldLogs({
    overview: logs,
    older: history.older,
    cursor: history.cursor,
    kinds,
    loadedTop: history.loadedTop,
  });

  return (
    <div>
      <div className="ph">
        <div className="ph-l">
          <h1>MCP traffic log</h1>
          <p>
            Every tool call from Microsoft Copilot Studio to the Salesforce MCP
            server. Sensitive field values are redacted before storage.
          </p>
        </div>
        <div className="ph-act">
          <button
            type="button"
            className="btn pri"
            onClick={() => onOpenFlyout({ type: 'simulator' })}
          >
            Simulate MCP call
          </button>
          <button type="button" className="btn" onClick={exportCsv} disabled={exporting}>
            {exporting ? 'Exporting…' : 'Export CSV'}
          </button>
        </div>
      </div>

      <div className="card">
        <div className="tbar">
          <div className="tbar-l">
            <div className="srch">
              <svg
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="1.75"
              >
                <circle cx="11" cy="11" r="7" />
                <path d="M20 20l-3.5-3.5" />
              </svg>
              <input
                placeholder="Search user, profile, tool, object…"
                value={q}
                onChange={(e) => setQ(e.target.value)}
              />
            </div>
            <div className="seg">
              {(
                [
                  ['all', 'All'],
                  ['ALLOWED', 'Allowed'],
                  ['DENIED', 'Denied'],
                ] as const
              ).map(([k, lbl]) => (
                <button
                  key={k}
                  type="button"
                  className={statusFilter === k ? 'on' : ''}
                  onClick={() => setStatusFilter(k)}
                >
                  {lbl}
                </button>
              ))}
            </div>
            <select
              className="inp"
              style={{ width: 'auto', padding: '4px 8px', fontSize: 12 }}
              value={toolFilter}
              onChange={(e) => setToolFilter(e.target.value)}
            >
              <option value="all">All tools</option>
              {MCP_TOOL_CATALOG.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.label}
                </option>
              ))}
            </select>
            <select
              className="inp"
              style={{ width: 'auto', padding: '4px 8px', fontSize: 12 }}
              value={objFilter}
              onChange={(e) => setObjFilter(e.target.value)}
            >
              <option value="all">All objects</option>
              {objects.map((o) => (
                <option key={o.objectName} value={o.objectName}>
                  {o.objectName}
                </option>
              ))}
            </select>
          </div>
          <div className="tbar-r">
            <span className="tag ok">
              <span className="dot ok" /> PII redaction active
            </span>
            <span className="mono" style={{ color: 'var(--t3)' }}>
              {rows.length} of {history.held.length} events
            </span>
            <HeldLogsNote text={heldText} gap={gap} loading={history.loading} onReload={history.reload} />
          </div>
        </div>

        <div className="tbl-wrap">
          <table className="tbl">
            <thead>
              <tr>
                <th>Time</th>
                <th>User</th>
                <th>Salesforce profile</th>
                <th>Matched groups</th>
                <th>MCP tool</th>
                <th>Object</th>
                <th>Latency</th>
                <th>Result</th>
              </tr>
            </thead>
            <tbody>
              {rows.length === 0 ? (
                <tr>
                  <td colSpan={8} className="empty">
                    No matching traffic events. Click &ldquo;Simulate MCP
                    call&rdquo; to test live policy evaluation.
                  </td>
                </tr>
              ) : (
                rows.map((r) => (
                  <tr
                    key={r.id}
                    className={`row ${
                      selectedFlyoutId === r.id ? 'sel' : ''
                    }`}
                    onClick={() =>
                      onOpenFlyout({ type: 'traffic', data: r })
                    }
                  >
                    <td className="mono" style={{ color: 'var(--t2)' }}>
                      {formatShortTime(r.timestamp)}
                    </td>
                    <td>
                      {r.sfUsername}
                      {r.simulated && (
                        <>
                          {' '}
                          <span className="tag warn">SIMULATED</span>
                        </>
                      )}
                    </td>
                    <td>
                      <div>{r.profileName}</div>
                      <div
                        className="mono"
                        style={{ color: 'var(--t3)', fontSize: 10.5 }}
                      >
                        {r.profileId}
                      </div>
                    </td>
                    <td>
                      {!r.matchedGroups || r.matchedGroups.length === 0 ? (
                        <span className="tag warn">None</span>
                      ) : (
                        <div
                          style={{
                            display: 'flex',
                            gap: 4,
                            flexWrap: 'wrap',
                          }}
                        >
                          {r.matchedGroups.map((gn) => (
                            <span key={gn} className="tag">
                              {gn}
                            </span>
                          ))}
                        </div>
                      )}
                    </td>
                    <td className="mono">{r.toolName}</td>
                    <td className="mono">{r.targetObject}</td>
                    <td className="mono" style={{ color: 'var(--t2)' }}>
                      {r.latencyMs} ms
                    </td>
                    <td>
                      <span
                        className={`tag ${
                          r.status === 'ALLOWED'
                            ? 'ok'
                            : r.status === 'DENIED'
                              ? 'warn'
                              : 'err'
                        }`}
                      >
                        <span
                          className={`dot ${
                            r.status === 'ALLOWED'
                              ? 'ok'
                              : r.status === 'DENIED'
                                ? 'warn'
                                : 'err'
                          }`}
                        />
                        {r.status}
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
        <LoadOlderFooter cursor={history.cursor} loading={history.loading} onLoad={history.loadOlder} />
      </div>
    </div>
  );
}

// ============================================================================
// 3. PORTAL AUDIT LOG VIEW
// ============================================================================
interface PortalAdminLogsViewProps {
  logs: PortalAdminLogEntry[];
  selectedFlyoutId?: string;
  caps: OverviewLogCaps['portalLogs'];
  fetchLogPage: FetchLogPage<PortalAdminLogEntry>;
  onNotify: (msg: string, isError?: boolean) => void;
  onOpenFlyout: (flyout: FlyoutState) => void;
}

export function PortalAdminLogsView({
  logs,
  selectedFlyoutId,
  caps,
  fetchLogPage,
  onNotify,
  onOpenFlyout,
}: PortalAdminLogsViewProps) {
  const [q, setQ] = useState('');
  const [method, setMethod] = useState<'all' | 'okta_sso' | 'password'>(
    'all'
  );
  const [actionFilter, setActionFilter] = useState('all');
  const history = useOlderLogRows(logs, fetchLogPage, onNotify);
  const { exporting, exportRows } = useLogExport(fetchLogPage, onNotify);

  const uniqueActions = useMemo(
    () => Array.from(new Set(history.held.map((l) => l.action))),
    [history.held]
  );

  const filters = useMemo(
    () => ({ method, action: actionFilter, search: q }),
    [method, actionFilter, q]
  );
  const rows = useMemo(
    () => history.held.filter((r) => auditRowMatches(r, filters)),
    [history.held, filters]
  );

  const exportCsv = () =>
    exportRows(auditRouteQuery(filters), (r) => auditRowMatches(r, filters), portalAuditCsv, 'portal-audit-log');

  const kinds = auditLogKinds(caps);
  const gap = heldLogGaps({ overview: logs, loadedTop: history.loadedTop, kinds }).length > 0;
  const heldText = describeHeldLogs({
    overview: logs,
    older: history.older,
    cursor: history.cursor,
    kinds,
    loadedTop: history.loadedTop,
  });

  return (
    <div>
      <div className="ph">
        <div className="ph-l">
          <h1>Portal audit log</h1>
          <p>
            Administrative sign-ins and configuration changes in this control
            plane.
          </p>
        </div>
        <div className="ph-act">
          <button type="button" className="btn" onClick={exportCsv} disabled={exporting}>
            {exporting ? 'Exporting…' : 'Export CSV'}
          </button>
        </div>
      </div>

      <div className="card">
        <div className="tbar">
          <div className="tbar-l">
            <div className="srch">
              <svg
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="1.75"
              >
                <circle cx="11" cy="11" r="7" />
                <path d="M20 20l-3.5-3.5" />
              </svg>
              <input
                placeholder="Search admin, action, target, details…"
                value={q}
                onChange={(e) => setQ(e.target.value)}
              />
            </div>
            <div className="seg">
              {(
                [
                  ['all', 'All'],
                  ['okta_sso', 'Okta SSO'],
                  ['password', 'Password'],
                ] as const
              ).map(([k, lbl]) => (
                <button
                  key={k}
                  type="button"
                  className={method === k ? 'on' : ''}
                  onClick={() => setMethod(k)}
                >
                  {lbl}
                </button>
              ))}
            </div>
            <select
              className="inp"
              style={{ width: 'auto', padding: '4px 8px', fontSize: 12 }}
              value={actionFilter}
              onChange={(e) => setActionFilter(e.target.value)}
            >
              <option value="all">All actions</option>
              {uniqueActions.map((a) => (
                <option key={a} value={a}>
                  {a}
                </option>
              ))}
            </select>
          </div>
          <div className="tbar-r">
            <span className="mono" style={{ color: 'var(--t3)' }}>
              {rows.length} of {history.held.length} events
            </span>
            <HeldLogsNote text={heldText} gap={gap} loading={history.loading} onReload={history.reload} />
          </div>
        </div>

        <div className="tbl-wrap">
          <table className="tbl">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Administrator</th>
                <th>Sign-in method</th>
                <th>Action</th>
                <th>Target</th>
                <th>Details</th>
                <th>Source IP</th>
              </tr>
            </thead>
            <tbody>
              {rows.length === 0 ? (
                <tr>
                  <td colSpan={7} className="empty">
                    No matching portal audit events.
                  </td>
                </tr>
              ) : (
                rows.map((r) => (
                  <tr
                    key={r.id}
                    className={`row ${
                      selectedFlyoutId === r.id ? 'sel' : ''
                    }`}
                    onClick={() => onOpenFlyout({ type: 'audit', data: r })}
                  >
                    <td className="mono" style={{ color: 'var(--t2)' }}>
                      {r.timestamp.slice(0, 19).replace('T', ' ')}
                    </td>
                    <td>{r.adminUsername}</td>
                    <td>
                      <span
                        className={`tag ${
                          r.authMethod === 'okta_sso' ? 'acc' : ''
                        }`}
                      >
                        {r.authMethod === 'okta_sso' ? 'Okta SSO' : 'Password'}
                      </span>
                    </td>
                    <td>
                      <span className="tag mono">{r.action}</span>
                    </td>
                    <td className="mono">{r.target}</td>
                    <td style={{ color: 'var(--t2)' }}>{r.details}</td>
                    <td className="mono" style={{ color: 'var(--t3)' }}>
                      {r.ipAddress}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
        <LoadOlderFooter cursor={history.cursor} loading={history.loading} onLoad={history.loadOlder} />
      </div>
    </div>
  );
}

// ============================================================================
// 4. PORTAL AUTH & OKTA SSO SETTINGS VIEW
// ============================================================================
interface PortalAuthSettingsViewProps {
  oktaSettings: OktaConfig;
  portalUsers: PortalUser[];
  onSaveOkta: (settings: Partial<OktaConfig> & { clientSecret?: string }) => Promise<OktaConfig>;
  /** Answers the new account's authenticator secret when the server issued one (production). */
  onCreatePortalUser: (user: {
    username: string;
    displayName?: string;
    password: string;
  }) => Promise<TotpSetup | null | void>;
  onDeletePortalUser: (username: string) => Promise<void>;
  /** The signed-in password account, or null for an Okta session (Okta enforces its own MFA). */
  currentAccount?: { username: string; totpEnrolled: boolean } | null;
  onStartTotpSetup?: () => Promise<TotpSetup>;
  onConfirmTotp?: (code: string) => Promise<void>;
}

/** A secret shown once: its setup key in groups of four and the otpauth:// URI an app can import. */
function TotpSecretPanel({ setup, title }: { setup: TotpSetup; title: string }) {
  return (
    <div
      role="status"
      style={{
        border: '1px solid var(--bd)',
        borderRadius: 6,
        padding: '10px 12px',
        margin: '10px 0',
        fontSize: 12,
      }}
    >
      <div style={{ fontWeight: 600, marginBottom: 4 }}>{title}</div>
      <div style={{ color: 'var(--t3)', marginBottom: 6 }}>
        Add it to an authenticator app now. It is not shown again.
      </div>
      <div className="mono" style={{ wordBreak: 'break-all' }}>
        Setup key: {setup.secret.replace(/(.{4})/g, '$1 ').trim()}
      </div>
      <div className="mono" style={{ wordBreak: 'break-all', color: 'var(--t3)', marginTop: 4 }}>
        {setup.otpauthUri}
      </div>
    </div>
  );
}

export function PortalAuthSettingsView({
  oktaSettings,
  portalUsers,
  onSaveOkta,
  onCreatePortalUser,
  onDeletePortalUser,
  currentAccount = null,
  onStartTotpSetup,
  onConfirmTotp,
}: PortalAuthSettingsViewProps) {
  // The new account's authenticator secret (production issues one), shown once to hand over.
  const [createdTotp, setCreatedTotp] = useState<TotpSetup | null>(null);
  // This account's enrollment: a pending secret waits for one code from the app before it takes effect.
  const [pendingTotp, setPendingTotp] = useState<TotpSetup | null>(null);
  const [totpCode, setTotpCode] = useState('');
  const [totpError, setTotpError] = useState('');
  const [totpBusy, setTotpBusy] = useState(false);
  const [oktaDraft, setOktaDraft] = useState<OktaConfig>(oktaSettings);
  const [oktaClientSecret, setOktaClientSecret] = useState('');
  // Only send the issuer when the admin edited it, so changing the domain re-derives a default issuer
  const [oktaIssuerEdited, setOktaIssuerEdited] = useState(false);
  const [newUsername, setNewUsername] = useState('');
  const [newDisplayName, setNewDisplayName] = useState('');
  const [newPassword, setNewPassword] = useState('');
  // Why the last Create administrator failed; the toast fades, this stays until the form is edited.
  const [createUserError, setCreateUserError] = useState('');
  const [busy, setBusy] = useState(false);
  const newPasswordTooShort = newPassword.length < PORTAL_PASSWORD_MIN_LENGTH;

  // The live poll delivers a new settings object every few seconds. Only a real change reaches the
  // form, and never over unsaved edits.
  const oktaBaseline = React.useRef(oktaSettings);
  React.useEffect(() => {
    const baseline = oktaBaseline.current;
    if (JSON.stringify(oktaSettings) === JSON.stringify(baseline)) return;
    oktaBaseline.current = oktaSettings;
    setOktaDraft((draft) =>
      JSON.stringify(draft) === JSON.stringify(baseline) ? oktaSettings : draft
    );
  }, [oktaSettings]);

  return (
    <div>
      <div className="ph">
        <div className="ph-l">
          <h1>Portal Auth &amp; Okta SSO</h1>
          <p>
            Configure Okta OIDC Single Sign-On and local emergency administrator
            accounts for this control plane.
          </p>
        </div>
      </div>

      <div className="g2">
        {/* Okta SSO Card */}
        <div className="card">
          <div className="card-h">
            <div>
              <div className="card-t">Okta OIDC Single Sign-On</div>
              <div className="card-s">
                Enterprise identity provider configuration
              </div>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span
                className={`tag ${oktaDraft.enabled ? 'ok' : ''}`}
              >
                {oktaDraft.enabled ? 'Enabled' : 'Disabled'}
              </span>
              <button
                type="button"
                className={`sw ${oktaDraft.enabled ? 'on' : ''}`}
                onClick={() =>
                  setOktaDraft({ ...oktaDraft, enabled: !oktaDraft.enabled })
                }
              />
            </div>
          </div>
          <div className="card-b">
            <div className="fld">
              <label>Okta Organization Domain</label>
              <input
                className="inp mono"
                value={oktaDraft.oktaDomain}
                onChange={(e) =>
                  setOktaDraft({ ...oktaDraft, oktaDomain: e.target.value })
                }
                placeholder="https://acme-enterprise.okta.com"
              />
            </div>
            <div className="fld">
              <label>OIDC Client ID</label>
              <input
                className="inp mono"
                value={oktaDraft.clientId}
                onChange={(e) =>
                  setOktaDraft({ ...oktaDraft, clientId: e.target.value })
                }
                placeholder="0oa8x92kLpQ7EnterpriseMcp"
              />
            </div>
            <div className="fld">
              <label>Authorization Server Issuer URI</label>
              <input
                className="inp mono"
                value={oktaDraft.issuer}
                onChange={(e) => {
                  setOktaDraft({ ...oktaDraft, issuer: e.target.value });
                  setOktaIssuerEdited(true);
                }}
                placeholder="https://acme-enterprise.okta.com/oauth2/default"
              />
            </div>
            <div className="fld">
              <label>OIDC Client Secret</label>
              <input
                type="password"
                autoComplete="new-password"
                className="inp mono"
                value={oktaClientSecret}
                onChange={(e) => setOktaClientSecret(e.target.value)}
                placeholder={
                  oktaDraft.hasClientSecret
                    ? 'Stored. Leave blank to keep it.'
                    : 'Paste the client secret'
                }
              />
            </div>
            <div className="fld">
              <label>Required Okta Group Claim</label>
              <input
                className="inp mono"
                value={oktaDraft.adminGroup}
                onChange={(e) =>
                  setOktaDraft({ ...oktaDraft, adminGroup: e.target.value })
                }
                placeholder="MCP-Admins"
              />
            </div>
            <div className="fld">
              <label>Redirect URI (optional)</label>
              <input
                className="inp mono"
                value={oktaDraft.redirectUri}
                onChange={(e) =>
                  setOktaDraft({ ...oktaDraft, redirectUri: e.target.value })
                }
                placeholder="<BASE_URL>/auth/okta/callback"
              />
            </div>
            <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
              <button
                type="button"
                className="btn pri"
                disabled={busy}
                onClick={async () => {
                  setBusy(true);
                  try {
                    const saved = await onSaveOkta({
                      ...oktaDraft,
                      // Empty issuer means "derive https://<domain>/oauth2/default"; untouched means "keep or re-derive"
                      issuer: oktaIssuerEdited ? oktaDraft.issuer.trim() : undefined,
                      clientSecret: oktaClientSecret.trim() || undefined,
                      redirectUri: oktaDraft.redirectUri.trim(),
                    });
                    oktaBaseline.current = saved;
                    setOktaDraft(saved);
                    setOktaClientSecret('');
                    setOktaIssuerEdited(false);
                  } catch {
                    // The error toast is already showing; stay here so the admin can retry.
                  } finally {
                    setBusy(false);
                  }
                }}
              >
                Save Okta configuration
              </button>
            </div>
          </div>
        </div>

        {/* Local Administrators Card */}
        <div className="card">
          <div className="card-h">
            <div>
              <div className="card-t">Portal Administrators</div>
              <div className="card-s">
                Local password accounts (PBKDF2-SHA512 hashed). Every administrator
                has full access. Production asks every password sign-in for an
                authenticator code.
              </div>
            </div>
            <span className="tag mono">{portalUsers.length} users</span>
          </div>
          <div className="card-b">
            <div className="chk-list" style={{ marginBottom: 14 }}>
              {portalUsers.map((u) => (
                <div className="chk-row" key={u.username}>
                  <div>
                    <div style={{ fontWeight: 500 }}>
                      {u.displayName}{' '}
                      {/* Roles are not enforced yet, so a stored role would claim limits that do not exist. */}
                      <span className="tag" style={{ marginLeft: 4 }}>
                        Full admin
                      </span>
                    </div>
                    <div className="mono" style={{ color: 'var(--t3)' }}>
                      {u.username}{' '}
                      <span className={`tag ${u.totpEnrolled ? 'ok' : 'warn'}`} style={{ marginLeft: 4 }}>
                        {u.totpEnrolled ? 'Authenticator' : 'No authenticator'}
                      </span>
                    </div>
                  </div>
                  {u.username !== 'admin' ? (
                    <button
                      type="button"
                      className="btn dng sm"
                      onClick={() => onDeletePortalUser(u.username)}
                    >
                      Remove
                    </button>
                  ) : (
                    <span className="tag ok">Primary root</span>
                  )}
                </div>
              ))}
            </div>

            {currentAccount && onStartTotpSetup && onConfirmTotp && (
              <div style={{ marginBottom: 14 }}>
                <div className="sec-h">
                  <span className="sec-t">Your authenticator app</span>
                  <span className={`tag ${currentAccount.totpEnrolled ? 'ok' : 'warn'}`}>
                    {currentAccount.totpEnrolled ? 'Enrolled' : 'Not set up'}
                  </span>
                </div>
                {!pendingTotp ? (
                  <button
                    type="button"
                    className="btn"
                    disabled={totpBusy}
                    onClick={async () => {
                      setTotpBusy(true);
                      setTotpError('');
                      try {
                        setPendingTotp(await onStartTotpSetup());
                        setTotpCode('');
                      } catch (err: any) {
                        setTotpError(err?.message || 'Could not start the setup.');
                      } finally {
                        setTotpBusy(false);
                      }
                    }}
                  >
                    {currentAccount.totpEnrolled ? 'Replace authenticator app' : 'Set up authenticator app'}
                  </button>
                ) : (
                  <form
                    onSubmit={async (e) => {
                      e.preventDefault();
                      setTotpBusy(true);
                      setTotpError('');
                      try {
                        await onConfirmTotp(totpCode);
                        setPendingTotp(null);
                        setTotpCode('');
                      } catch (err: any) {
                        setTotpError(err?.message || 'That code did not match.');
                      } finally {
                        setTotpBusy(false);
                      }
                    }}
                  >
                    <TotpSecretPanel setup={pendingTotp} title={`New authenticator for ${currentAccount.username}`} />
                    <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                      <input
                        className="inp mono"
                        aria-label="Code from the authenticator app"
                        inputMode="numeric"
                        autoComplete="one-time-code"
                        maxLength={6}
                        placeholder="Code from the app"
                        value={totpCode}
                        onChange={(e) => {
                          setTotpCode(e.target.value.replace(/\D/g, ''));
                          setTotpError('');
                        }}
                      />
                      <button type="submit" className="btn pri" disabled={totpBusy || totpCode.length !== 6}>
                        Confirm
                      </button>
                      <button
                        type="button"
                        className="btn gh"
                        onClick={() => {
                          setPendingTotp(null);
                          setTotpCode('');
                          setTotpError('');
                        }}
                      >
                        Cancel
                      </button>
                    </div>
                  </form>
                )}
                {totpError && (
                  <div role="alert" style={{ marginTop: 6, fontSize: 11, color: 'var(--err)' }}>
                    {totpError}
                  </div>
                )}
              </div>
            )}

            <div className="sec-h">
              <span className="sec-t">Add administrator</span>
            </div>
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: '1fr 1fr',
                gap: 8,
                marginBottom: 8,
              }}
            >
              <input
                className="inp"
                placeholder="Username (e.g. secops)"
                value={newUsername}
                onChange={(e) => {
                  setNewUsername(e.target.value);
                  setCreateUserError('');
                }}
              />
              <input
                className="inp"
                placeholder="Display name"
                value={newDisplayName}
                onChange={(e) => {
                  setNewDisplayName(e.target.value);
                  setCreateUserError('');
                }}
              />
              <div className="fld" style={{ gridColumn: '1 / -1', marginBottom: 0 }}>
                <input
                  type="password"
                  className="inp"
                  placeholder="Password"
                  value={newPassword}
                  onChange={(e) => {
                    setNewPassword(e.target.value);
                    setCreateUserError('');
                  }}
                  aria-invalid={newPassword !== '' && newPasswordTooShort}
                />
                <div
                  className="hint"
                  style={newPassword !== '' && newPasswordTooShort ? { color: 'var(--err)' } : undefined}
                >
                  At least {PORTAL_PASSWORD_MIN_LENGTH} characters.
                </div>
              </div>
            </div>
            <div style={{ display: 'flex', justifyContent: 'flex-end', alignItems: 'center', gap: 10 }}>
              {createUserError && (
                <span role="alert" style={{ marginRight: 'auto', fontSize: 11, color: 'var(--err)' }}>
                  {createUserError}
                </span>
              )}
              <button
                type="button"
                className="btn pri"
                disabled={busy || !newUsername.trim() || newPasswordTooShort}
                onClick={async () => {
                  setBusy(true);
                  setCreateUserError('');
                  try {
                    const issued = await onCreatePortalUser({
                      username: newUsername.trim(),
                      // Omitted when blank so updating an existing user's password keeps their display name
                      displayName: newDisplayName.trim() || undefined,
                      password: newPassword,
                    });
                    setCreatedTotp(issued ? { username: newUsername.trim(), ...issued } : null);
                    setNewUsername('');
                    setNewDisplayName('');
                    setNewPassword('');
                  } catch (err: any) {
                    // The toast is showing too; stay here so the admin can read it and retry.
                    setCreateUserError(err?.message || 'The administrator could not be saved.');
                  } finally {
                    setBusy(false);
                  }
                }}
              >
                Create administrator
              </button>
            </div>
            {createdTotp && (
              <>
                <TotpSecretPanel
                  setup={createdTotp}
                  title={`Authenticator for ${createdTotp.username}: hand this over securely`}
                />
                <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
                  <button type="button" className="btn gh sm" onClick={() => setCreatedTotp(null)}>
                    Done
                  </button>
                </div>
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
