'use client';

import React, { useEffect, useState } from 'react';
import type { McpActionType, SalesforceObject, SalesforceProfile } from '@/types/governance';
import { MCP_TOOL_CATALOG, StatusBadge } from '@/components/ui/primitives';
import { DEFAULT_SIMULATED_USERNAME, trafficBurstCalls } from './simulatedTraffic';
import type { WorkspaceSnapshot } from './accessGroupDraft';

export interface SimulatorPrefill {
  profileId?: string;
  username?: string;
  toolName?: string;
  targetObject?: string;
}

interface PolicySimulatorViewProps {
  profiles: SalesforceProfile[];
  objects: SalesforceObject[];
  /** From the URL (/simulator?profile=&user=&tool=&object=): where the form starts. */
  prefill: SimulatorPrefill;
  /** The form's identifiers, written back to the URL so a reload or a shared link keeps them. */
  onSelectionChange: (selection: Required<SimulatorPrefill>) => void;
  /** From the server: false in production, where the traffic burst is hidden. */
  devToolsEnabled: boolean;
  onTestMcpCall: (payload: {
    profileId: string;
    toolName: string;
    targetObject: string;
    username?: string;
    samplePayload?: Record<string, unknown>;
  }) => Promise<any>;
  onRefreshWorkspace: () => Promise<WorkspaceSnapshot | null>;
  notify: (msg: string, isError?: boolean) => void;
}

/**
 * The Policy Simulator (Tier B: a simulation). It evaluates one call against the policy as stored,
 * through POST /api/admin/test-mcp-access, and logs it as a simulated call.
 */
export function PolicySimulatorView({
  profiles,
  objects,
  prefill,
  onSelectionChange,
  devToolsEnabled,
  onTestMcpCall,
  onRefreshWorkspace,
  notify,
}: PolicySimulatorViewProps) {
  const [busy, setBusy] = useState(false);
  const [simProfileId, setSimProfileId] = useState(prefill.profileId || '');
  const [simUsername, setSimUsername] = useState(prefill.username || DEFAULT_SIMULATED_USERNAME);
  const [simTool, setSimTool] = useState<McpActionType>((prefill.toolName as McpActionType) || 'soql_query');
  const [simObject, setSimObject] = useState(prefill.targetObject || '');
  const [simResult, setSimResult] = useState<any>(null);

  // A prefill that arrives later (another link, the header's Simulate) replaces the form's choice.
  useEffect(() => {
    if (prefill.profileId) setSimProfileId(prefill.profileId);
    if (prefill.username) setSimUsername(prefill.username);
    if (prefill.toolName) setSimTool(prefill.toolName as McpActionType);
    if (prefill.targetObject) setSimObject(prefill.targetObject);
  }, [prefill.profileId, prefill.username, prefill.toolName, prefill.targetObject]);

  // Until the workspace has loaded there is nothing to choose from; then the first of each.
  useEffect(() => {
    if (!simProfileId && profiles[0]) setSimProfileId(profiles[0].id);
  }, [profiles, simProfileId]);
  useEffect(() => {
    if (!simObject && objects[0]) setSimObject(objects[0].objectName);
  }, [objects, simObject]);

  useEffect(() => {
    onSelectionChange({ profileId: simProfileId, username: simUsername, toolName: simTool, targetObject: simObject });
    // onSelectionChange is the page's URL writer; only the values matter here.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [simProfileId, simUsername, simTool, simObject]);

  const handleRunBurst = async () => {
    setBusy(true);
    try {
      const sampleCalls = trafficBurstCalls(profiles.map((p) => p.id));
      let lastRes = null;
      for (const call of sampleCalls) {
        lastRes = await onTestMcpCall(call);
      }
      setSimResult(lastRes);
      await onRefreshWorkspace();
      notify('Simulated 6 Copilot MCP traffic events');
    } catch {
      // The error toast is already showing; stay here so the admin can retry.
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="card sim-frame">
      <div className="card-h">
        <div>
          <div className="card-t">Live MCP Policy Simulator</div>
          <div className="card-s">Evaluate Profile-to-Group RBAC &amp; generate Copilot test traffic</div>
        </div>
        <span className="tag marker">Simulation</span>
      </div>
      <div className="card-b">
          <div className="sec">
            <div className="fld">
              <label>Caller Salesforce Profile</label>
              <select
                className="inp"
                value={simProfileId}
                onChange={(e) => setSimProfileId(e.target.value)}
              >
                {profiles.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name} ({p.id})
                  </option>
                ))}
              </select>
            </div>
            <div className="fld">
              <label>Simulated Copilot User</label>
              <input
                className="inp"
                value={simUsername}
                onChange={(e) => setSimUsername(e.target.value)}
                placeholder={DEFAULT_SIMULATED_USERNAME}
              />
              <div style={{ fontSize: 11, color: 'var(--t3)', marginTop: 4 }}>
                Logged as simulated:&lt;name&gt; and tagged SIMULATED.
              </div>
            </div>
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: '1fr 1fr',
                gap: 10,
              }}
            >
              <div className="fld">
                <label>MCP Tool</label>
                <select
                  className="inp mono"
                  value={simTool}
                  onChange={(e) =>
                    setSimTool(e.target.value as McpActionType)
                  }
                >
                  {MCP_TOOL_CATALOG.map((t) => (
                    <option key={t.id} value={t.id}>
                      {t.label} ({t.risk})
                    </option>
                  ))}
                </select>
              </div>
              <div className="fld">
                <label>Target SObject</label>
                <select
                  className="inp mono"
                  value={simObject}
                  onChange={(e) => setSimObject(e.target.value)}
                >
                  {objects.map((o) => (
                    <option key={o.objectName} value={o.objectName}>
                      {o.objectName} {!o.enabled ? '(Disabled)' : ''}
                    </option>
                  ))}
                </select>
              </div>
            </div>
            <div style={{ display: 'flex', gap: 8, marginTop: 4 }}>
              <button
                type="button"
                className="btn pri"
                disabled={busy}
                onClick={async () => {
                  setBusy(true);
                  try {
                    const res = await onTestMcpCall({
                      profileId: simProfileId,
                      toolName: simTool,
                      targetObject: simObject,
                      username: simUsername,
                    });
                    setSimResult(res);
                    await onRefreshWorkspace();
                  } catch {
                    // The error toast is already showing; stay here so the admin can retry.
                  } finally {
                    setBusy(false);
                  }
                }}
              >
                Run MCP Policy Check
              </button>
              {devToolsEnabled && (
                <button
                  type="button"
                  className="btn"
                  disabled={busy}
                  onClick={handleRunBurst}
                >
                  Run 6-Event Traffic Burst
                </button>
              )}
            </div>
          </div>

          {simResult?.evaluation && (
            <div className="sec">
              <div className="sec-h">
                <span className="sec-t">Policy Evaluation Result</span>
                <StatusBadge
                  status={simResult.evaluation.permitted ? 'ALLOWED' : 'DENIED'}
                  label={simResult.evaluation.permitted ? 'ALLOWED' : 'DENIED BY POLICY'}
                />
              </div>
              <dl className="kv" style={{ marginBottom: 10 }}>
                <dt>Decision reason</dt>
                <dd>{simResult.evaluation.reason}</dd>
                <dt>Matched groups</dt>
                <dd>
                  {(simResult.evaluation.matchedGroups || []).length > 0
                    ? simResult.evaluation.matchedGroups.join(', ')
                    : 'None'}
                </dd>
                <dt>Allowed fields</dt>
                <dd className="mono">
                  {(simResult.evaluation.allowedFields || []).length > 0
                    ? `${simResult.evaluation.allowedFields.length} fields (${simResult.evaluation.allowedFields.slice(0, 6).join(', ')}${simResult.evaluation.allowedFields.length > 6 ? '…' : ''})`
                    : '0 fields'}
                </dd>
              </dl>
              {simResult.simulatorBearerToken && (
                <div>
                  <div
                    style={{
                      fontSize: 11,
                      color: 'var(--t3)',
                      marginBottom: 4,
                    }}
                  >
                    Signed Simulator Bearer Token (for{' '}
                    <span className="mono">POST /mcp</span>):
                  </div>
                  <pre className="code">
                    {simResult.simulatorBearerToken}
                  </pre>
                </div>
              )}
            </div>
          )}
      </div>
    </div>
  );
}
