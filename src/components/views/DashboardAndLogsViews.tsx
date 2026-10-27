'use client';

import React, { useState } from 'react';
import {
  Activity,
  ShieldCheck,
  ShieldAlert,
  Users,
  Database,
  Layers,
  Play,
  Search,
  X,
  KeyRound,
  Lock,
  Plus,
  Trash2,
  Save,
  Terminal,
  UserCheck,
  ArrowRight,
} from 'lucide-react';
import {
  PortalOverviewPayload,
  CopilotMcpLogRecord,
  PortalAdminLogRecord,
  AVAILABLE_MCP_ACTIONS,
  NavViewId,
} from '@/types/governance';
import { Card, Badge, Switch } from '@/components/ui/primitives';

// ============================================================================
// 1. LANDING DASHBOARD (Traffic on the MCP Server + Quick Test + Both Log Previews)
// ============================================================================
export function TrafficDashboardView({
  overview,
  apiFetch,
  onRefresh,
  onShowToast,
  onNavigate,
}: {
  overview: PortalOverviewPayload;
  apiFetch: <T = any>(url: string, options?: RequestInit) => Promise<T>;
  onRefresh: () => Promise<void>;
  onShowToast: (msg: string, isError?: boolean) => void;
  onNavigate: (view: NavViewId) => void;
}) {
  const [testProfileId, setTestProfileId] = useState(
    overview.profiles[0]?.id || ''
  );
  const [testTool, setTestTool] = useState<string>('soql_query');
  const [testObject, setTestObject] = useState(
    overview.objects[0]?.objectName || 'Account'
  );
  const [testing, setTesting] = useState(false);
  const [lastTestResult, setLastTestResult] = useState<any>(null);

  const handleRunTestCall = async (e: React.FormEvent) => {
    e.preventDefault();
    setTesting(true);
    try {
      const res = await apiFetch('/api/admin/test-mcp-access', {
        method: 'POST',
        body: JSON.stringify({
          profileId: testProfileId || overview.profiles[0]?.id || '00e000000000000',
          toolName: testTool,
          targetObject: testObject,
          samplePayload: {
            objectName: testObject,
            fields: ['Id', 'Name'],
            whereClause: "Name = 'Sensitive Customer Name'",
            customerSecretValue: 'SSN-999-00-1234',
          },
        }),
      });
      setLastTestResult(res);
      await onRefresh();
      onShowToast(
        res.evaluation?.permitted
          ? 'MCP Call Permitted (Logged with PII stripped)'
          : 'MCP Call Denied by Profile Group Matrix'
      );
    } catch (err: any) {
      onShowToast(err.message, true);
    } finally {
      setTesting(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Dense KPI Strip */}
      <div className="grid grid-cols-2 gap-3.5 sm:grid-cols-3 lg:grid-cols-6">
        <Card className="p-4">
          <div className="text-[11px] font-bold tracking-wider text-slate-400 uppercase">
            MCP Requests
          </div>
          <div className="mt-1 font-mono text-2xl font-bold text-slate-900">
            {overview.stats.totalMcpRequests}
          </div>
          <div className="mt-1 text-[11px] text-slate-500">
            Copilot runtime traffic
          </div>
        </Card>

        <Card className="p-4">
          <div className="text-[11px] font-bold tracking-wider text-emerald-600 uppercase">
            Allowed Calls
          </div>
          <div className="mt-1 font-mono text-2xl font-bold text-emerald-600">
            {overview.stats.allowedMcpRequests}
          </div>
          <div className="mt-1 text-[11px] text-slate-500">
            Passed Group Matrix
          </div>
        </Card>

        <Card className="p-4">
          <div className="text-[11px] font-bold tracking-wider text-rose-600 uppercase">
            Denied Calls
          </div>
          <div className="mt-1 font-mono text-2xl font-bold text-rose-600">
            {overview.stats.deniedMcpRequests}
          </div>
          <div className="mt-1 text-[11px] text-slate-500">
            Blocked by policy
          </div>
        </Card>

        <Card
          className="cursor-pointer p-4 transition hover:border-indigo-300"
          onClick={() => onNavigate('sf-profiles')}
        >
          <div className="text-[11px] font-bold tracking-wider text-slate-400 uppercase">
            SF Profiles
          </div>
          <div className="mt-1 font-mono text-2xl font-bold text-slate-900">
            {overview.stats.totalProfiles}
          </div>
          <div className="mt-1 text-[11px] text-indigo-600">
            Manage Profiles →
          </div>
        </Card>

        <Card
          className="cursor-pointer p-4 transition hover:border-indigo-300"
          onClick={() => onNavigate('sf-objects')}
        >
          <div className="text-[11px] font-bold tracking-wider text-slate-400 uppercase">
            SF Objects
          </div>
          <div className="mt-1 font-mono text-2xl font-bold text-slate-900">
            {overview.stats.enabledObjects}{' '}
            <span className="text-sm font-normal text-slate-400">
              / {overview.stats.totalObjects}
            </span>
          </div>
          <div className="mt-1 text-[11px] text-indigo-600">
            Enabled Objects →
          </div>
        </Card>

        <Card
          className="cursor-pointer p-4 transition hover:border-indigo-300"
          onClick={() => onNavigate('matrix-groups')}
        >
          <div className="text-[11px] font-bold tracking-wider text-slate-400 uppercase">
            Access Groups
          </div>
          <div className="mt-1 font-mono text-2xl font-bold text-slate-900">
            {overview.stats.totalGroups}
          </div>
          <div className="mt-1 text-[11px] text-indigo-600">
            Configure Groups →
          </div>
        </Card>
      </div>

      {/* Live Policy Simulator Bar (Test MCP Server Traffic) */}
      <Card className="p-4">
        <div className="mb-3 flex items-center justify-between">
          <div>
            <h3 className="text-xs font-bold tracking-wider text-slate-800 uppercase">
              Test Copilot → MCP Server Request (Simulates Traffic & Logs with PII Stripped)
            </h3>
            <p className="text-[11px] text-slate-500">
              Select a Salesforce Profile, MCP Action, and Object to verify effective permissions from your Profile Group Matrix.
            </p>
          </div>
          <span className="font-mono text-[11px] text-slate-400">
            POST /mcp
          </span>
        </div>

        <form
          onSubmit={handleRunTestCall}
          className="grid grid-cols-1 gap-2.5 sm:grid-cols-4"
        >
          <input
            type="text"
            value={testProfileId}
            onChange={(e) => setTestProfileId(e.target.value)}
            placeholder={
              overview.profiles[0]?.id || 'Enter Profile ID (e.g. 00e...)'
            }
            list="dashboard-profile-list"
            className="rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5 font-mono text-xs text-slate-900 focus:border-indigo-500 focus:bg-white focus:outline-none"
          />
          <datalist id="dashboard-profile-list">
            {overview.profiles.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </datalist>

          <select
            value={testTool}
            onChange={(e) => setTestTool(e.target.value)}
            className="rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5 font-mono text-xs text-slate-900 focus:border-indigo-500 focus:bg-white focus:outline-none"
          >
            {AVAILABLE_MCP_ACTIONS.map((a) => (
              <option key={a.id} value={a.id}>
                {a.id} ({a.category})
              </option>
            ))}
          </select>

          <input
            type="text"
            value={testObject}
            onChange={(e) => setTestObject(e.target.value)}
            placeholder="Target Object (e.g. Account)"
            list="dashboard-object-list"
            className="rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5 font-mono text-xs text-slate-900 focus:border-indigo-500 focus:bg-white focus:outline-none"
          />
          <datalist id="dashboard-object-list">
            {overview.objects.map((o) => (
              <option key={o.objectName} value={o.objectName}>
                {o.label}
              </option>
            ))}
          </datalist>

          <button
            type="submit"
            disabled={testing}
            className="inline-flex items-center justify-center gap-1.5 rounded-lg bg-indigo-600 px-4 py-1.5 text-xs font-semibold text-white hover:bg-indigo-700 disabled:opacity-50"
          >
            <Play className="h-3.5 w-3.5" />
            {testing ? 'Testing...' : 'Send Test MCP Call'}
          </button>
        </form>

        {lastTestResult && (
          <div className="mt-3 rounded-xl border border-slate-200 bg-slate-50 p-3 text-xs">
            <div className="flex items-center justify-between">
              <span className="font-semibold text-slate-800">
                Result:{' '}
                {lastTestResult.evaluation?.permitted ? (
                  <span className="text-emerald-600">ALLOWED</span>
                ) : (
                  <span className="text-rose-600">DENIED</span>
                )}
              </span>
              <span className="font-mono text-[11px] text-slate-500">
                {lastTestResult.evaluation?.reason}
              </span>
            </div>
          </div>
        )}
      </Card>

      {/* Two Separate Live Log Feeds Side-by-Side */}
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
        {/* Feed 1: Users hitting MCP Server from Copilot (PII Stripped) */}
        <Card className="overflow-hidden">
          <div className="flex items-center justify-between border-b border-slate-200/80 bg-slate-50/70 px-4 py-3">
            <div>
              <h3 className="text-xs font-bold text-slate-900">
                1. Copilot → MCP Server Traffic Logs (PII Stripped)
              </h3>
              <p className="text-[11px] text-slate-500">
                Users hitting `/mcp` from Microsoft Copilot & tools invoked
              </p>
            </div>
            <button
              onClick={() => onNavigate('logs-copilot')}
              className="inline-flex items-center gap-1 text-xs font-semibold text-indigo-600 hover:underline"
            >
              <span>View All ({overview.copilotLogs.length})</span>
              <ArrowRight className="h-3 w-3" />
            </button>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-left text-xs">
              <thead>
                <tr className="border-b border-slate-100 bg-slate-50/40 text-[10px] font-bold tracking-wider text-slate-400 uppercase">
                  <th className="py-2 pr-2 pl-4">Time</th>
                  <th className="px-2 py-2">Copilot User / Profile</th>
                  <th className="px-2 py-2">Tool & Object</th>
                  <th className="py-2 pr-4 pl-2 text-right">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {overview.copilotLogs.length === 0 ? (
                  <tr>
                    <td
                      colSpan={4}
                      className="py-8 text-center text-xs text-slate-400"
                    >
                      No Copilot MCP traffic recorded yet.
                    </td>
                  </tr>
                ) : (
                  overview.copilotLogs.slice(0, 8).map((l) => (
                    <tr key={l.id} className="hover:bg-slate-50">
                      <td className="py-2 pr-2 pl-4 font-mono text-[11px] text-slate-500">
                        {new Date(l.timestamp).toLocaleTimeString()}
                      </td>
                      <td className="px-2 py-2">
                        <div className="font-medium text-slate-900">
                          {l.sfUsername}
                        </div>
                        <div className="font-mono text-[10px] text-slate-400">
                          {l.profileName} ({l.profileId})
                        </div>
                      </td>
                      <td className="px-2 py-2 font-mono text-[11px] text-slate-800">
                        {l.toolName}{' '}
                        {l.targetObject && l.targetObject !== '*'
                          ? `(${l.targetObject})`
                          : ''}
                      </td>
                      <td className="py-2 pr-4 pl-2 text-right">
                        <Badge
                          variant={
                            l.status === 'ALLOWED' ? 'emerald' : 'rose'
                          }
                        >
                          {l.status}
                        </Badge>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </Card>

        {/* Feed 2: Portal Admin Users & Configuration Actions */}
        <Card className="overflow-hidden">
          <div className="flex items-center justify-between border-b border-slate-200/80 bg-slate-50/70 px-4 py-3">
            <div>
              <h3 className="text-xs font-bold text-slate-900">
                2. Web Portal Admin Sign-Ins & Configuration Logs
              </h3>
              <p className="text-[11px] text-slate-500">
                Portal users signing in & configuration changes made
              </p>
            </div>
            <button
              onClick={() => onNavigate('logs-portal')}
              className="inline-flex items-center gap-1 text-xs font-semibold text-indigo-600 hover:underline"
            >
              <span>View All ({overview.portalLogs.length})</span>
              <ArrowRight className="h-3 w-3" />
            </button>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-left text-xs">
              <thead>
                <tr className="border-b border-slate-100 bg-slate-50/40 text-[10px] font-bold tracking-wider text-slate-400 uppercase">
                  <th className="py-2 pr-2 pl-4">Time</th>
                  <th className="px-2 py-2">Portal User</th>
                  <th className="px-2 py-2">Action</th>
                  <th className="py-2 pr-4 pl-2">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {overview.portalLogs.length === 0 ? (
                  <tr>
                    <td
                      colSpan={4}
                      className="py-8 text-center text-xs text-slate-400"
                    >
                      No portal actions recorded yet.
                    </td>
                  </tr>
                ) : (
                  overview.portalLogs.slice(0, 8).map((p) => (
                    <tr key={p.id} className="hover:bg-slate-50">
                      <td className="py-2 pr-2 pl-4 font-mono text-[11px] text-slate-500">
                        {new Date(p.timestamp).toLocaleTimeString()}
                      </td>
                      <td className="px-2 py-2">
                        <span className="font-semibold text-slate-900">
                          {p.adminUsername}
                        </span>
                        <span className="ml-1.5 rounded bg-slate-100 px-1.5 py-0.5 font-mono text-[10px] text-slate-500">
                          {p.authMethod}
                        </span>
                      </td>
                      <td className="px-2 py-2">
                        <Badge variant="indigo">{p.action}</Badge>
                      </td>
                      <td className="max-w-xs truncate py-2 pr-4 pl-2 text-[11px] text-slate-600">
                        {p.details}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </Card>
      </div>
    </div>
  );
}

// ============================================================================
// 2. COPILOT MCP SERVER LOGS VIEW (With Sensitive Data Stripped Out)
// ============================================================================
export function CopilotMcpLogsView({
  logs,
}: {
  logs: CopilotMcpLogRecord[];
}) {
  const [search, setSearch] = useState('');
  const [selectedLog, setSelectedLog] = useState<CopilotMcpLogRecord | null>(
    null
  );

  const filtered = logs.filter(
    (l) =>
      !search.trim() ||
      l.sfUsername.toLowerCase().includes(search.toLowerCase()) ||
      l.profileName.toLowerCase().includes(search.toLowerCase()) ||
      l.profileId.toLowerCase().includes(search.toLowerCase()) ||
      l.toolName.toLowerCase().includes(search.toLowerCase()) ||
      l.targetObject.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="space-y-5">
      <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-center">
        <div>
          <h2 className="text-base font-bold text-slate-900">
            Copilot → MCP Server Execution Logs (Sensitive Data Stripped)
          </h2>
          <p className="text-xs text-slate-500">
            Logs every user hitting the MCP server from Microsoft Copilot, the tool used, matched Access Groups, and structure-only payload with literal data values stripped out (`&lt;REDACTED&gt;`).
          </p>
        </div>

        <div className="relative">
          <Search className="pointer-events-none absolute top-1/2 left-2.5 h-3.5 w-3.5 -translate-y-1/2 text-slate-400" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Filter user, profile, tool, object..."
            className="w-64 rounded-lg border border-slate-200 bg-white py-1.5 pr-3 pl-8 text-xs text-slate-800 focus:border-indigo-500 focus:outline-none"
          />
        </div>
      </div>

      <Card className="overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-left text-xs">
            <thead>
              <tr className="border-b border-slate-200/80 bg-slate-50/70 text-[11px] font-bold tracking-wider text-slate-400 uppercase">
                <th className="py-2.5 pr-3 pl-4">Timestamp</th>
                <th className="px-3 py-2.5">Salesforce User</th>
                <th className="px-3 py-2.5">Profile</th>
                <th className="px-3 py-2.5">Matched Groups</th>
                <th className="px-3 py-2.5">Tool & Object</th>
                <th className="px-3 py-2.5">Status</th>
                <th className="py-2.5 pr-4 pl-3 text-right">Payload</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {filtered.length === 0 ? (
                <tr>
                  <td
                    colSpan={7}
                    className="py-10 text-center text-xs text-slate-400"
                  >
                    No Copilot MCP requests logged yet.
                  </td>
                </tr>
              ) : (
                filtered.map((l) => (
                  <tr
                    key={l.id}
                    onClick={() => setSelectedLog(l)}
                    className="cursor-pointer hover:bg-slate-50/90"
                  >
                    <td className="py-2.5 pr-3 pl-4 font-mono text-[11px] text-slate-500">
                      {new Date(l.timestamp).toLocaleString()}
                    </td>
                    <td className="px-3 py-2.5 font-medium text-slate-900">
                      {l.sfUsername}
                    </td>
                    <td className="px-3 py-2.5">
                      <div className="font-medium text-slate-800">
                        {l.profileName}
                      </div>
                      <div className="font-mono text-[10px] text-slate-400">
                        {l.profileId}
                      </div>
                    </td>
                    <td className="px-3 py-2.5">
                      {l.matchedGroups.length === 0 ? (
                        <span className="text-[11px] text-slate-400">None</span>
                      ) : (
                        <div className="flex flex-wrap gap-1">
                          {l.matchedGroups.map((g) => (
                            <Badge key={g} variant="indigo">
                              {g}
                            </Badge>
                          ))}
                        </div>
                      )}
                    </td>
                    <td className="px-3 py-2.5 font-mono text-xs font-semibold text-slate-800">
                      {l.toolName}{' '}
                      {l.targetObject && l.targetObject !== '*'
                        ? `→ ${l.targetObject}`
                        : ''}
                    </td>
                    <td className="px-3 py-2.5">
                      <Badge
                        variant={l.status === 'ALLOWED' ? 'emerald' : 'rose'}
                      >
                        {l.status}
                      </Badge>
                    </td>
                    <td className="py-2.5 pr-4 pl-3 text-right">
                      <button
                        type="button"
                        className="rounded-md border border-slate-200 bg-white px-2.5 py-1 text-[11px] font-semibold text-indigo-600 hover:bg-indigo-50"
                      >
                        View Stripped Payload
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </Card>

      {/* Slide-over Sanitized Payload Drawer */}
      {selectedLog && (
        <div
          className="fixed inset-0 z-50 flex justify-end bg-slate-900/30 backdrop-blur-[1px]"
          onClick={() => setSelectedLog(null)}
        >
          <div
            className="flex h-full w-full max-w-xl flex-col border-l border-slate-200 bg-white shadow-2xl"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between border-b border-slate-200 px-6 py-4">
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-mono text-sm font-bold text-indigo-600">
                    {selectedLog.toolName}
                  </span>
                  <Badge
                    variant={
                      selectedLog.status === 'ALLOWED' ? 'emerald' : 'rose'
                    }
                  >
                    {selectedLog.status}
                  </Badge>
                </div>
                <p className="mt-0.5 font-mono text-[11px] text-slate-400">
                  {selectedLog.id} •{' '}
                  {new Date(selectedLog.timestamp).toLocaleString()}
                </p>
              </div>
              <button
                onClick={() => setSelectedLog(null)}
                className="rounded-lg border border-slate-200 p-1.5 text-slate-500 hover:bg-slate-100"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <div className="flex-1 space-y-5 overflow-y-auto p-6 text-xs">
              <div className="grid grid-cols-2 gap-3 rounded-xl border border-slate-200 bg-slate-50 p-3.5">
                <div>
                  <span className="text-[10px] font-bold text-slate-400 uppercase">
                    Copilot Caller
                  </span>
                  <p className="mt-0.5 font-semibold text-slate-900">
                    {selectedLog.sfUsername}
                  </p>
                </div>
                <div>
                  <span className="text-[10px] font-bold text-slate-400 uppercase">
                    Salesforce Profile
                  </span>
                  <p className="mt-0.5 font-semibold text-slate-900">
                    {selectedLog.profileName}
                  </p>
                  <p className="font-mono text-[11px] text-indigo-600">
                    {selectedLog.profileId}
                  </p>
                </div>
              </div>

              <div>
                <h4 className="mb-1.5 text-xs font-bold text-slate-700 uppercase">
                  Sanitized Request Payload (Literal Values Stripped)
                </h4>
                <pre className="overflow-x-auto rounded-xl bg-slate-900 p-4 font-mono text-xs text-slate-100">
                  {selectedLog.sanitizedRequestPayload}
                </pre>
              </div>

              <div>
                <h4 className="mb-1.5 text-xs font-bold text-slate-700 uppercase">
                  Sanitized Response Summary (Records Stripped)
                </h4>
                <pre className="overflow-x-auto rounded-xl bg-slate-900 p-4 font-mono text-xs text-emerald-300">
                  {selectedLog.sanitizedResponseSummary}
                </pre>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ============================================================================
// 3. PORTAL ADMIN AUDIT LOGS VIEW (Users signing into portal & actions taken)
// ============================================================================
export function PortalAdminLogsView({
  logs,
}: {
  logs: PortalAdminLogRecord[];
}) {
  const [search, setSearch] = useState('');

  const filtered = logs.filter(
    (l) =>
      !search.trim() ||
      l.adminUsername.toLowerCase().includes(search.toLowerCase()) ||
      l.action.toLowerCase().includes(search.toLowerCase()) ||
      l.target.toLowerCase().includes(search.toLowerCase()) ||
      l.details.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="space-y-5">
      <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-center">
        <div>
          <h2 className="text-base font-bold text-slate-900">
            Web Portal Admin Sign-Ins & Configuration Audit Logs
          </h2>
          <p className="text-xs text-slate-500">
            Tracks everyone who signs into this administration portal (via Username/Password or Okta SSO) and every configuration change they make.
          </p>
        </div>

        <div className="relative">
          <Search className="pointer-events-none absolute top-1/2 left-2.5 h-3.5 w-3.5 -translate-y-1/2 text-slate-400" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Filter portal user, action, target..."
            className="w-64 rounded-lg border border-slate-200 bg-white py-1.5 pr-3 pl-8 text-xs text-slate-800 focus:border-indigo-500 focus:outline-none"
          />
        </div>
      </div>

      <Card className="overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-left text-xs">
            <thead>
              <tr className="border-b border-slate-200/80 bg-slate-50/70 text-[11px] font-bold tracking-wider text-slate-400 uppercase">
                <th className="py-2.5 pr-3 pl-4">Timestamp</th>
                <th className="px-3 py-2.5">Portal User</th>
                <th className="px-3 py-2.5">Auth Method</th>
                <th className="px-3 py-2.5">Action</th>
                <th className="px-3 py-2.5">Target</th>
                <th className="px-3 py-2.5">Details</th>
                <th className="py-2.5 pr-4 pl-3 text-right">IP</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {filtered.length === 0 ? (
                <tr>
                  <td
                    colSpan={7}
                    className="py-10 text-center text-xs text-slate-400"
                  >
                    No portal admin logs recorded yet.
                  </td>
                </tr>
              ) : (
                filtered.map((l) => (
                  <tr key={l.id} className="hover:bg-slate-50/80">
                    <td className="py-2.5 pr-3 pl-4 font-mono text-[11px] whitespace-nowrap text-slate-500">
                      {new Date(l.timestamp).toLocaleString()}
                    </td>
                    <td className="px-3 py-2.5 font-semibold text-slate-900">
                      {l.adminUsername}
                    </td>
                    <td className="px-3 py-2.5">
                      <Badge
                        variant={
                          l.authMethod === 'okta_sso' ? 'indigo' : 'slate'
                        }
                      >
                        {l.authMethod === 'okta_sso'
                          ? 'Okta SSO'
                          : 'Username / Password'}
                      </Badge>
                    </td>
                    <td className="px-3 py-2.5">
                      <span className="rounded bg-indigo-50 px-2 py-0.5 font-mono text-[11px] font-bold text-indigo-700">
                        {l.action}
                      </span>
                    </td>
                    <td className="px-3 py-2.5 font-mono text-[11px] text-slate-800">
                      {l.target}
                    </td>
                    <td className="max-w-md px-3 py-2.5 text-slate-600">
                      {l.details}
                    </td>
                    <td className="py-2.5 pr-4 pl-3 text-right font-mono text-[11px] text-slate-400">
                      {l.ipAddress}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}

// ============================================================================
// 4. PORTAL AUTH & OKTA SSO SETTINGS VIEW
// ============================================================================
export function PortalAuthSettingsView({
  overview,
  apiFetch,
  onRefresh,
  onShowToast,
}: {
  overview: PortalOverviewPayload;
  apiFetch: <T = any>(url: string, options?: RequestInit) => Promise<T>;
  onRefresh: () => Promise<void>;
  onShowToast: (msg: string, isError?: boolean) => void;
}) {
  // Okta SSO State
  const [oktaEnabled, setOktaEnabled] = useState(overview.oktaSettings.enabled);
  const [oktaDomain, setOktaDomain] = useState(
    overview.oktaSettings.oktaDomain
  );
  const [clientId, setClientId] = useState(overview.oktaSettings.clientId);
  const [clientSecret, setClientSecret] = useState('');
  const [adminGroup, setAdminGroup] = useState(
    overview.oktaSettings.adminGroup
  );

  // New Portal User State
  const [newUsername, setNewUsername] = useState('');
  const [newDisplayName, setNewDisplayName] = useState('');
  const [newPassword, setNewPassword] = useState('');

  const handleSaveOkta = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await apiFetch('/api/admin/okta', {
        method: 'PUT',
        body: JSON.stringify({
          enabled: oktaEnabled,
          oktaDomain,
          clientId,
          clientSecret: clientSecret.trim() || undefined,
          adminGroup,
        }),
      });
      setClientSecret('');
      await onRefresh();
      onShowToast('Saved Okta SSO configuration');
    } catch (err: any) {
      onShowToast(err.message, true);
    }
  };

  const handleAddPortalUser = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newUsername.trim() || !newPassword.trim()) return;
    try {
      await apiFetch('/api/admin/portal-users', {
        method: 'POST',
        body: JSON.stringify({
          username: newUsername.trim(),
          displayName: newDisplayName.trim() || newUsername.trim(),
          password: newPassword,
        }),
      });
      setNewUsername('');
      setNewDisplayName('');
      setNewPassword('');
      await onRefresh();
      onShowToast(`Saved portal user "${newUsername.trim()}"`);
    } catch (err: any) {
      onShowToast(err.message, true);
    }
  };

  const handleDeletePortalUser = async (username: string) => {
    try {
      await apiFetch(
        `/api/admin/portal-users/${encodeURIComponent(username)}`,
        {
          method: 'DELETE',
        }
      );
      await onRefresh();
      onShowToast(`Deleted portal user "${username}"`);
    } catch (err: any) {
      onShowToast(err.message, true);
    }
  };

  return (
    <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
      {/* Left: Local Portal Users (Username & Password) */}
      <Card className="p-5">
        <h3 className="text-sm font-bold text-slate-900">
          Portal Username & Password Accounts
        </h3>
        <p className="mt-0.5 text-xs text-slate-500">
          Manage local administrator accounts that can sign into this portal with a username and password.
        </p>

        <form onSubmit={handleAddPortalUser} className="mt-4 space-y-3">
          <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-3">
            <input
              type="text"
              required
              value={newUsername}
              onChange={(e) => setNewUsername(e.target.value)}
              placeholder="Username (e.g. alex)"
              className="rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5 text-xs text-slate-900 focus:border-indigo-500 focus:bg-white focus:outline-none"
            />
            <input
              type="text"
              value={newDisplayName}
              onChange={(e) => setNewDisplayName(e.target.value)}
              placeholder="Display Name"
              className="rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5 text-xs text-slate-900 focus:border-indigo-500 focus:bg-white focus:outline-none"
            />
            <input
              type="password"
              required
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              placeholder="New Password"
              className="rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5 text-xs text-slate-900 focus:border-indigo-500 focus:bg-white focus:outline-none"
            />
          </div>
          <button
            type="submit"
            className="inline-flex items-center gap-1.5 rounded-lg bg-slate-900 px-3.5 py-1.5 text-xs font-semibold text-white hover:bg-slate-800"
          >
            <Plus className="h-3.5 w-3.5" />
            Add / Update Password User
          </button>
        </form>

        <div className="mt-5 divide-y divide-slate-100 border-t border-slate-100">
          {overview.portalUsers.map((u) => (
            <div
              key={u.username}
              className="flex items-center justify-between py-2.5 text-xs"
            >
              <div>
                <span className="font-mono font-bold text-slate-900">
                  {u.username}
                </span>
                <span className="ml-2 text-slate-500">({u.displayName})</span>
              </div>
              <div className="flex items-center gap-2">
                <Badge variant="slate">{u.role}</Badge>
                {overview.portalUsers.length > 1 && (
                  <button
                    type="button"
                    onClick={() => handleDeletePortalUser(u.username)}
                    className="rounded p-1 text-slate-400 hover:bg-rose-50 hover:text-rose-600"
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      </Card>

      {/* Right: Okta OIDC SSO Configuration */}
      <Card className="p-5">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-bold text-slate-900">
              Okta OIDC Single Sign-On (SSO)
            </h3>
            <p className="mt-0.5 text-xs text-slate-500">
              Allow portal administrators to sign in using Okta OIDC + PKCE.
            </p>
          </div>
          <Switch checked={oktaEnabled} onCheckedChange={setOktaEnabled} />
        </div>

        <form onSubmit={handleSaveOkta} className="mt-4 space-y-3">
          <div>
            <label className="block text-xs font-semibold text-slate-700">
              Okta Domain
            </label>
            <input
              type="text"
              value={oktaDomain}
              onChange={(e) => setOktaDomain(e.target.value)}
              placeholder="your-org.okta.com"
              className="mt-1 w-full rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5 font-mono text-xs text-slate-900 focus:border-indigo-500 focus:bg-white focus:outline-none"
            />
          </div>

          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <div>
              <label className="block text-xs font-semibold text-slate-700">
                OIDC Client ID
              </label>
              <input
                type="text"
                value={clientId}
                onChange={(e) => setClientId(e.target.value)}
                placeholder="0oa..."
                className="mt-1 w-full rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5 font-mono text-xs text-slate-900 focus:border-indigo-500 focus:bg-white focus:outline-none"
              />
            </div>
            <div>
              <label className="block text-xs font-semibold text-slate-700">
                OIDC Client Secret
              </label>
              <input
                type="password"
                value={clientSecret}
                onChange={(e) => setClientSecret(e.target.value)}
                placeholder={
                  overview.oktaSettings.hasClientSecret
                    ? '•••••••• (Saved)'
                    : 'Enter Client Secret'
                }
                className="mt-1 w-full rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5 font-mono text-xs text-slate-900 focus:border-indigo-500 focus:bg-white focus:outline-none"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-700">
              Required Okta Group Claim
            </label>
            <input
              type="text"
              value={adminGroup}
              onChange={(e) => setAdminGroup(e.target.value)}
              placeholder="MCP-Admins"
              className="mt-1 w-full rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5 font-mono text-xs text-slate-900 focus:border-indigo-500 focus:bg-white focus:outline-none"
            />
          </div>

          <div className="pt-2">
            <button
              type="submit"
              className="inline-flex items-center gap-1.5 rounded-lg bg-indigo-600 px-4 py-1.5 text-xs font-semibold text-white hover:bg-indigo-700"
            >
              <Save className="h-3.5 w-3.5" />
              Save Okta Configuration
            </button>
          </div>
        </form>
      </Card>
    </div>
  );
}
