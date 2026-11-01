'use client';

import React, { useState, useMemo } from 'react';
import type {
  CopilotMcpLogEntry,
  PortalAdminLogEntry,
  SalesforceProfile,
  SalesforceObjectConfig,
  AccessGroup,
  ProfileGroupMapping,
  OktaConfig,
  PortalUser,
  SalesforceConnectionSettings,
} from '@/types/governance';
import { MCP_TOOL_CATALOG, formatShortTime } from '@/components/ui/primitives';
import type { FlyoutState } from './FlyoutDrawer';
import { realTraffic } from './simulatedTraffic';

// ============================================================================
// 1. DASHBOARD VIEW
// ============================================================================
export interface McpRequestStats {
  totalMcpRequests: number;
  allowedMcpRequests: number;
  deniedMcpRequests: number;
  erroredMcpRequests: number;
}

interface TrafficDashboardProps {
  mcpStats?: McpRequestStats | null;
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
  copilotLogs,
  mcpStats,
  profiles,
  objects,
  groups,
  mappings = [],
  sfSettings,
  onNavigateTab,
  onOpenFlyout,
  onSeedEnterpriseMatrix,
}: TrafficDashboardProps) {
  const [range, setRange] = useState<'1h' | '24h' | '7d'>('24h');

  const getProfileGroupIds = (profileId: string): string[] => {
    const found = mappings.find((m) => m.profileId === profileId);
    return found ? found.groupIds : [];
  };

  const realLogs = useMemo(() => realTraffic(copilotLogs), [copilotLogs]);

  // KPI metrics
  // Totals come from the server: copilotLogs holds only the latest rows. The latency and user
  // figures below are computed from those rows and labelled as such.
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
  const successRate = totalCalls
    ? ((allowedCalls / totalCalls) * 100).toFixed(1)
    : '100.0';

  const sortedLatencies = useMemo(
    () =>
      realLogs
        .map((l) => l.latencyMs || 0)
        .sort((a, b) => a - b),
    [realLogs]
  );
  const p95Latency = sortedLatencies.length
    ? sortedLatencies[Math.floor(sortedLatencies.length * 0.95)]
    : 0;
  const avgLatency = sortedLatencies.length
    ? Math.round(
        sortedLatencies.reduce((acc, v) => acc + v, 0) / sortedLatencies.length
      )
    : 0;

  const uniqueUsers = useMemo(
    () => new Set(realLogs.map((l) => l.sfUsername)).size,
    [realLogs]
  );
  const uniqueProfilesInLogs = useMemo(
    () => new Set(realLogs.map((l) => l.profileId)).size,
    [realLogs]
  );

  // Stacked bar chart buckets (24 bars)
  const buckets = useMemo(() => {
    const count = range === '1h' ? 12 : range === '24h' ? 24 : 14;
    const result = Array.from({ length: count }, (_, idx) => {
      const lbl =
        range === '1h'
          ? `-${(count - 1 - idx) * 5}m`
          : range === '24h'
            ? `${String(idx).padStart(2, '0')}:00`
            : `D-${count - 1 - idx}`;
      return { lbl, ok: 0, warn: 0, err: 0 };
    });

    if (realLogs.length === 0) return result;

    // Distribute real logs across buckets (by timestamp hash/hour so chart is informative & deterministic)
    realLogs.forEach((log, i) => {
      const d = new Date(log.timestamp);
      const bucketIdx = !Number.isNaN(d.getTime())
        ? range === '24h'
          ? d.getHours() % count
          : (d.getMinutes() + i) % count
        : i % count;
      const b = result[bucketIdx];
      if (!b) return;
      if (log.status === 'ALLOWED') b.ok += 1;
      else if (log.status === 'DENIED') b.warn += 1;
      else b.err += 1;
    });

    return result;
  }, [realLogs, range]);

  const maxBucket = Math.max(
    1,
    ...buckets.map((b) => b.ok + b.warn + b.err)
  );

  // Top tools
  const topTools = useMemo(() => {
    const counts: Record<string, number> = {};
    realLogs.forEach((l) => {
      counts[l.toolName] = (counts[l.toolName] || 0) + 1;
    });
    return Object.entries(counts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 6);
  }, [realLogs]);
  const maxToolCount = Math.max(1, ...topTools.map((t) => t[1]));

  // Top users
  const topUsers = useMemo(() => {
    const map: Record<
      string,
      { user: string; profile: string; n: number; denied: number }
    > = {};
    realLogs.forEach((l) => {
      if (!map[l.sfUsername]) {
        map[l.sfUsername] = {
          user: l.sfUsername,
          profile: l.profileName,
          n: 0,
          denied: 0,
        };
      }
      map[l.sfUsername].n += 1;
      if (l.status === 'DENIED') map[l.sfUsername].denied += 1;
    });
    return Object.values(map)
      .sort((a, b) => b.n - a.n)
      .slice(0, 5);
  }, [realLogs]);
  const maxUserCount = Math.max(1, ...topUsers.map((u) => u.n));

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
            <span className="dot ok" />
          </div>
          <div className="k-val">{successRate}%</div>
          <div className="k-sub">
            <span>
              {errorCalls} transport errors · target ≥ 98.0%
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
            <span>avg {avgLatency} ms · latest {realLogs.length} calls</span>
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
              across {uniqueProfilesInLogs} profiles in the latest{' '}
              {realLogs.length} calls
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
                Requests per bucket by policy outcome
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
                    title={`${b.lbl} — ${b.ok} allowed, ${b.warn} denied, ${b.err} error`}
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
                      {i % 3 === 0 ? b.lbl.replace(':00', 'h') : ''}
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
            <span className="card-s">by call count</span>
          </div>
          <div
            className="card-b"
            style={{ display: 'flex', flexDirection: 'column', gap: 8 }}
          >
            {topTools.length === 0 ? (
              <div className="empty">No MCP tool calls recorded yet.</div>
            ) : (
              topTools.map(([tool, n]) => (
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
            <span className="card-s">Copilot callers</span>
          </div>
          <div
            className="card-b"
            style={{ display: 'flex', flexDirection: 'column', gap: 8 }}
          >
            {topUsers.length === 0 ? (
              <div className="empty">No active callers yet.</div>
            ) : (
              topUsers.map((u) => (
                <div key={u.user}>
                  <div
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      fontSize: 12,
                      marginBottom: 3,
                    }}
                  >
                    <span>
                      {u.user}{' '}
                      <span style={{ color: 'var(--t3)', fontSize: 11 }}>
                        · {u.profile}
                      </span>
                    </span>
                    <span className="mono" style={{ color: 'var(--t2)' }}>
                      {u.n}
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
                        width: `${(u.n / maxUserCount) * 100}%`,
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
interface CopilotMcpLogsViewProps {
  logs: CopilotMcpLogEntry[];
  objects: SalesforceObjectConfig[];
  selectedFlyoutId?: string;
  initialSearch?: string;
  onClearLogs: () => Promise<void>;
  onOpenFlyout: (flyout: FlyoutState) => void;
}

export function CopilotMcpLogsView({
  logs,
  objects,
  selectedFlyoutId,
  initialSearch = '',
  onClearLogs,
  onOpenFlyout,
}: CopilotMcpLogsViewProps) {
  const [q, setQ] = useState(initialSearch);
  const [statusFilter, setStatusFilter] = useState<
    'all' | 'ALLOWED' | 'DENIED' | 'ERROR'
  >('all');
  const [toolFilter, setToolFilter] = useState('all');
  const [objFilter, setObjFilter] = useState('all');

  React.useEffect(() => {
    if (initialSearch) setQ(initialSearch);
  }, [initialSearch]);

  const rows = useMemo(() => {
    return logs.filter(
      (r) =>
        (statusFilter === 'all' || r.status === statusFilter) &&
        (toolFilter === 'all' || r.toolName === toolFilter) &&
        (objFilter === 'all' || r.targetObject === objFilter) &&
        (!q ||
          r.sfUsername.toLowerCase().includes(q.toLowerCase()) ||
          r.profileName.toLowerCase().includes(q.toLowerCase()) ||
          r.toolName.toLowerCase().includes(q.toLowerCase()) ||
          r.targetObject.toLowerCase().includes(q.toLowerCase()) ||
          r.profileId.toLowerCase().includes(q.toLowerCase()))
    );
  }, [logs, statusFilter, toolFilter, objFilter, q]);

  const exportCsv = () => {
    const header =
      'Id,Timestamp,User,ProfileId,ProfileName,Tool,TargetObject,Status,LatencyMs,Simulated\n';
    const body = rows
      .map(
        (r) =>
          `"${r.id}","${r.timestamp}","${r.sfUsername}","${r.profileId}","${r.profileName}","${r.toolName}","${r.targetObject}","${r.status}",${r.latencyMs},${r.simulated ? 'true' : 'false'}`
      )
      .join('\n');
    const blob = new Blob([header + body], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `mcp-traffic-log-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

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
          <button type="button" className="btn" onClick={exportCsv}>
            Export CSV
          </button>
          {logs.length > 0 && (
            <button type="button" className="btn dng" onClick={onClearLogs}>
              Clear log
            </button>
          )}
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
              {rows.length} of {logs.length} events
            </span>
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
  onOpenFlyout: (flyout: FlyoutState) => void;
}

export function PortalAdminLogsView({
  logs,
  selectedFlyoutId,
  onOpenFlyout,
}: PortalAdminLogsViewProps) {
  const [q, setQ] = useState('');
  const [method, setMethod] = useState<'all' | 'okta_sso' | 'password'>(
    'all'
  );
  const [actionFilter, setActionFilter] = useState('all');

  const uniqueActions = useMemo(
    () => Array.from(new Set(logs.map((l) => l.action))),
    [logs]
  );

  const rows = useMemo(() => {
    return logs.filter(
      (r) =>
        (method === 'all' || r.authMethod === method) &&
        (actionFilter === 'all' || r.action === actionFilter) &&
        (!q ||
          r.adminUsername.toLowerCase().includes(q.toLowerCase()) ||
          r.action.toLowerCase().includes(q.toLowerCase()) ||
          r.target.toLowerCase().includes(q.toLowerCase()) ||
          r.details.toLowerCase().includes(q.toLowerCase()))
    );
  }, [logs, method, actionFilter, q]);

  const exportCsv = () => {
    const header =
      'Id,Timestamp,AdminUsername,AuthMethod,Action,Target,Details,IpAddress\n';
    const body = rows
      .map(
        (r) =>
          `"${r.id}","${r.timestamp}","${r.adminUsername}","${r.authMethod}","${r.action}","${r.target}","${r.details.replace(/"/g, '""')}","${r.ipAddress}"`
      )
      .join('\n');
    const blob = new Blob([header + body], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `portal-audit-log-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

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
          <button type="button" className="btn" onClick={exportCsv}>
            Export CSV
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
              {rows.length} events
            </span>
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
  onCreatePortalUser: (user: {
    username: string;
    displayName?: string;
    password: string;
    role: string;
  }) => Promise<void>;
  onDeletePortalUser: (username: string) => Promise<void>;
}

export function PortalAuthSettingsView({
  oktaSettings,
  portalUsers,
  onSaveOkta,
  onCreatePortalUser,
  onDeletePortalUser,
}: PortalAuthSettingsViewProps) {
  const [oktaDraft, setOktaDraft] = useState<OktaConfig>(oktaSettings);
  const [oktaClientSecret, setOktaClientSecret] = useState('');
  // Only send the issuer when the admin edited it, so changing the domain re-derives a default issuer
  const [oktaIssuerEdited, setOktaIssuerEdited] = useState(false);
  const [newUsername, setNewUsername] = useState('');
  const [newDisplayName, setNewDisplayName] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [newRole, setNewRole] = useState('Security Admin');
  const [busy, setBusy] = useState(false);

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
                Local password accounts (scrypt hashed)
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
                      <span className="tag" style={{ marginLeft: 4 }}>
                        {u.role}
                      </span>
                    </div>
                    <div className="mono" style={{ color: 'var(--t3)' }}>
                      {u.username}
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
                onChange={(e) => setNewUsername(e.target.value)}
              />
              <input
                className="inp"
                placeholder="Display name"
                value={newDisplayName}
                onChange={(e) => setNewDisplayName(e.target.value)}
              />
              <input
                type="password"
                className="inp"
                placeholder="Password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
              />
              <select
                className="inp"
                value={newRole}
                onChange={(e) => setNewRole(e.target.value)}
              >
                <option value="Super Admin">Super Admin</option>
                <option value="Security Admin">Security Admin</option>
                <option value="RevOps Admin">RevOps Admin</option>
                <option value="Read-Only Auditor">Read-Only Auditor</option>
              </select>
            </div>
            <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
              <button
                type="button"
                className="btn pri"
                disabled={busy || !newUsername.trim() || !newPassword.trim()}
                onClick={async () => {
                  setBusy(true);
                  try {
                    await onCreatePortalUser({
                      username: newUsername.trim(),
                      // Omitted when blank so updating an existing user's password keeps their display name
                      displayName: newDisplayName.trim() || undefined,
                      password: newPassword,
                      role: newRole,
                    });
                    setNewUsername('');
                    setNewDisplayName('');
                    setNewPassword('');
                  } catch {
                    // The error toast is already showing; stay here so the admin can retry.
                  } finally {
                    setBusy(false);
                  }
                }}
              >
                Create administrator
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
