import './helpers/env.js';
// The Logs toolbars say which rows the view holds, so gaps left by the per-kind /overview caps are
// not read as quiet periods. Rendered to markup to exercise the real views.
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { CopilotMcpLogsView, PortalAdminLogsView } from '../src/components/views/DashboardAndLogsViews.js';
import {
  DEFAULT_OVERVIEW_LOG_CAPS,
  REJECTED_TOKEN_USERNAME,
  SIMULATION_ACTION,
  auditLogKinds,
  describeHeldLogs,
  trafficLogKinds,
} from '../src/components/views/logHistory.js';
import { SIMULATE_MCP_CALL_ACTION, UNVERIFIED_CALLER_USERNAME } from '../src/db/store.js';
import type { CopilotMcpLogEntry, PortalAdminLogEntry } from '../src/types/governance.js';

let seq = 0;
const call = (kind: 'real' | 'simulated' | 'rejected'): CopilotMcpLogEntry => {
  seq += 1;
  return {
    id: `mcp_${seq}`,
    seq,
    timestamp: new Date(Date.UTC(2026, 10, 1, 0, 0, seq)).toISOString(),
    sfUsername: kind === 'rejected' ? REJECTED_TOKEN_USERNAME : kind === 'simulated' ? 'simulated:test-user' : 'jane@acme.com',
    profileId: '00e000000000001',
    profileName: 'P',
    matchedGroups: [],
    toolName: kind === 'rejected' ? 'mcp_authenticate' : 'soql_query',
    targetObject: 'Account',
    status: 'DENIED',
    latencyMs: 1,
    sanitizedRequestPayload: '{}',
    sanitizedResponseSummary: '{}',
    ...(kind === 'simulated' ? { simulated: true as const } : {}),
  };
};

const audit = (action: string): PortalAdminLogEntry => {
  seq += 1;
  return {
    id: `adm_${seq}`,
    seq,
    timestamp: new Date(Date.UTC(2026, 10, 1, 0, 0, seq)).toISOString(),
    adminUsername: 'admin',
    authMethod: 'password',
    action,
    target: 'T',
    details: 'D',
    ipAddress: '127.0.0.1',
  };
};

const times = <T>(n: number, make: () => T) => Array.from({ length: n }, make);
const newestFirst = <T extends { seq?: number }>(rows: T[]) => [...rows].sort((a, b) => (b.seq ?? 0) - (a.seq ?? 0));
const mcpKinds = trafficLogKinds(DEFAULT_OVERVIEW_LOG_CAPS.copilotLogs);
const portalKinds = auditLogKinds(DEFAULT_OVERVIEW_LOG_CAPS.portalLogs);

describe('describeHeldLogs', () => {
  test('names each capped kind as its latest rows', () => {
    const overview = newestFirst([...times(150, () => call('real')), ...times(50, () => call('simulated')), ...times(50, () => call('rejected'))]);
    assert.equal(
      describeHeldLogs({ overview, older: [], cursor: undefined, kinds: mcpKinds }),
      'latest 150 calls + latest 50 simulated + latest 50 rejected'
    );
  });

  test('says a kind under its cap is held in full, and leaves out kinds with no rows', () => {
    const overview = newestFirst([...times(3, () => call('real')), ...times(50, () => call('simulated'))]);
    assert.equal(
      describeHeldLogs({ overview, older: [], cursor: undefined, kinds: mcpKinds }),
      'all 3 calls + latest 50 simulated'
    );
    assert.equal(describeHeldLogs({ overview: [], older: [], cursor: undefined, kinds: mcpKinds }), 'no events');
  });

  test('portal lists name simulations apart from other events', () => {
    const overview = newestFirst([...times(150, () => audit('UPDATE_GROUP')), ...times(12, () => audit(SIMULATION_ACTION))]);
    assert.equal(
      describeHeldLogs({ overview, older: [], cursor: undefined, kinds: portalKinds }),
      'latest 150 events + all 12 simulations'
    );
  });

  test('after Load older, states the unbroken range and counts the older capped rows', () => {
    const oldReal = times(5, () => call('real'));
    const loaded = newestFirst(times(200, () => call('simulated')));
    const overview = newestFirst([...oldReal, ...loaded.slice(0, 50)]);
    const oldest = loaded[loaded.length - 1];
    assert.equal(
      describeHeldLogs({ overview, older: loaded, cursor: oldest.seq, kinds: mcpKinds }),
      `every event since ${oldest.timestamp.slice(0, 19).replace('T', ' ')} UTC + 5 older from the latest-row lists`
    );
    assert.equal(
      describeHeldLogs({ overview: loaded.slice(0, 50), older: loaded, cursor: oldest.seq, kinds: mcpKinds }),
      `every event since ${oldest.timestamp.slice(0, 19).replace('T', ' ')} UTC`
    );
  });

  test('once the start of the log is reached, the view holds all of it', () => {
    assert.equal(describeHeldLogs({ overview: [], older: [call('real')], cursor: null, kinds: mcpKinds }), 'the whole log');
  });

  test('the portal markers match what the store writes', () => {
    assert.equal(REJECTED_TOKEN_USERNAME, UNVERIFIED_CALLER_USERNAME);
    assert.equal(SIMULATION_ACTION, SIMULATE_MCP_CALL_ACTION);
  });
});

describe('Logs toolbars', () => {
  const noPage = async () => ({ rows: [], nextBefore: null });

  test('the MCP traffic toolbar states which rows the view holds', () => {
    const logs = newestFirst([...times(150, () => call('real')), ...times(50, () => call('simulated')), ...times(7, () => call('rejected'))]);
    const html = renderToStaticMarkup(
      createElement(CopilotMcpLogsView, {
        logs,
        objects: [],
        caps: DEFAULT_OVERVIEW_LOG_CAPS.copilotLogs,
        fetchLogPage: noPage,
        onNotify: () => {},
        onClearLogs: async () => {},
        onOpenFlyout: () => {},
      })
    );
    assert.ok(html.includes('(latest 150 calls + latest 50 simulated + all 7 rejected)'), html.slice(0, 500));
    assert.ok(html.includes('Load older'));
  });

  test('the portal audit toolbar states which rows the view holds', () => {
    const logs = newestFirst([...times(20, () => audit('LOGIN_SUCCESS')), ...times(50, () => audit(SIMULATION_ACTION))]);
    const html = renderToStaticMarkup(
      createElement(PortalAdminLogsView, {
        logs,
        caps: DEFAULT_OVERVIEW_LOG_CAPS.portalLogs,
        fetchLogPage: noPage,
        onNotify: () => {},
        onOpenFlyout: () => {},
      })
    );
    assert.ok(html.includes('(all 20 events + latest 50 simulations)'), html.slice(0, 500));
    assert.ok(html.includes('70 of 70 events'));
    assert.ok(html.includes('Load older'));
  });
});
