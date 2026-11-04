'use client';

import React, { useEffect, useState } from 'react';
import Link from 'next/link';
import type { SalesforceConnectionSettings, ShellSummary } from '@/types/governance';
import type { McpRequestStats } from '@/components/views/DashboardAndLogsViews';
import { OrgStatus } from '@/components/views/OrgStatus';
import { mcpActivityStatus } from '@/components/views/mcpActivity';
import { statusToneClass } from '@/components/ui/statusTone';
import { breadcrumb, buildHref, type RouteMatch } from './routes';
import { freshness } from './freshness';

/** "Updated 4s ago · Live": ticks on its own so the rest of the shell does not re-render each second. */
function FreshnessChip({
  live,
  lastOkAt,
  failures,
  onToggleLive,
  onRetry,
}: {
  live: boolean;
  lastOkAt: number | null;
  failures: number;
  onToggleLive: () => void;
  onRetry: () => void;
}) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const iv = window.setInterval(() => setNow(Date.now()), 1_000);
    return () => window.clearInterval(iv);
  }, []);
  const f = freshness({ live, lastOkAt, failures, now });
  return (
    <div className={`live-chip fresh-${f.state}`} data-state={f.state}>
      <span className={`dot ${statusToneClass(f.tone)}`} aria-hidden="true" />
      <span className="live-lbl" aria-live="polite">
        <span className={`txt-${f.tone}`}>{f.label}</span>
        <span className="live-upd"> · {f.updated}</span>
      </span>
      {f.state === 'degraded' && (
        <button type="button" className="btn gh sm" onClick={onRetry}>
          Retry now
        </button>
      )}
      <button
        type="button"
        className="btn gh sm"
        onClick={onToggleLive}
        aria-pressed={!live}
        title={live ? 'Pause the automatic refresh' : 'Resume the automatic refresh'}
      >
        {live ? 'Pause' : 'Resume'}
      </button>
    </div>
  );
}

/** "Last MCP call 2 min ago", as text: real calls only, on the server's clock. */
function LastMcpCall({ lastCallAt, clockOffsetMs }: { lastCallAt: string | null | undefined; clockOffsetMs: number }) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const iv = window.setInterval(() => setNow(Date.now()), 15_000);
    return () => window.clearInterval(iv);
  }, []);
  const status = mcpActivityStatus(lastCallAt, now + clockOffsetMs);
  return (
    <span className="top-txt" title="Time of the last real MCP call; simulated calls are not counted">
      {status.label}
    </span>
  );
}

export function Header({
  match,
  entity,
  summary,
  sfSettings,
  mcpStats,
  clockOffsetMs,
  live,
  lastOkAt,
  failures,
  theme,
  onToggleLive,
  onRetry,
  onOpenPalette,
  onOpenSidebar,
  onToggleTheme,
  onLink,
}: {
  match: RouteMatch | null;
  entity?: string;
  summary: ShellSummary | null;
  sfSettings: SalesforceConnectionSettings | null;
  mcpStats: McpRequestStats | null;
  clockOffsetMs: number;
  live: boolean;
  lastOkAt: number | null;
  failures: number;
  theme: 'dark' | 'light';
  onToggleLive: () => void;
  onRetry: () => void;
  onOpenPalette: () => void;
  onOpenSidebar: () => void;
  onToggleTheme: () => void;
  onLink: (e: React.MouseEvent<HTMLAnchorElement>, href: string) => void;
}) {
  const crumbs = match ? breadcrumb(match, entity) : [];
  const orgHref = buildHref('org-connection');
  const simHref = buildHref('simulator');
  const org = summary?.org;
  const lastCallAt = summary ? summary.lastMcpCallAt : mcpStats?.lastMcpCallAt;
  return (
    <header className="top">
      <button type="button" className="btn gh sm sb-open" onClick={onOpenSidebar} aria-label="Open navigation">
        ☰
      </button>
      <nav className="crumb" aria-label="Breadcrumb">
        <ol>
          {crumbs.map((c, i) => (
            <li key={`${i}-${c}`} aria-current={i === crumbs.length - 1 ? 'page' : undefined}>
              {i === crumbs.length - 1 ? <b>{c}</b> : <span>{c}</span>}
              {i < crumbs.length - 1 && (
                <span className="sep" aria-hidden="true">
                  /
                </span>
              )}
            </li>
          ))}
        </ol>
      </nav>

      <div className="top-r">
        <button type="button" className="pill" onClick={onOpenPalette} title="Open the command palette (⌘K)">
          <span>Search / Jump</span>
          <span className="kbd">⌘K</span>
        </button>

        <Link href={orgHref} className="pill" onClick={(e) => onLink(e, orgHref)} title="Salesforce org connection">
          <OrgStatus
            status={org?.connectionStatus ?? sfSettings?.connectionStatus}
            orgId={org?.connectedOrgId ?? sfSettings?.connectedOrgId}
            simulated={(org?.authMode ?? sfSettings?.authMode) === 'simulated'}
          />
        </Link>

        <LastMcpCall lastCallAt={lastCallAt} clockOffsetMs={clockOffsetMs} />

        <FreshnessChip live={live} lastOkAt={lastOkAt} failures={failures} onToggleLive={onToggleLive} onRetry={onRetry} />

        <Link href={simHref} className="btn sm" onClick={(e) => onLink(e, simHref)}>
          Simulate
        </Link>

        <button
          type="button"
          className="btn gh sm"
          onClick={onToggleTheme}
          aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}
        >
          {theme === 'dark' ? '☀' : '☾'}
        </button>
      </div>
    </header>
  );
}
