'use client';

import React, { useEffect, useState } from 'react';
import Link from 'next/link';
import type { AdminSession, SalesforceConnectionSettings, ShellSummary } from '@/types/governance';
import { OrgStatus } from '@/components/views/OrgStatus';
import { Num } from '@/components/ui/primitives';
import { matchRoute, NAV_SECTIONS, VIEWS, viewHref, type ViewId } from './routes';
import { sessionTimeLeft } from './freshness';

const ICONS: Record<ViewId, React.ReactNode> = {
  dashboard: (
    <>
      <rect x="3" y="3" width="7" height="9" rx="1.5" />
      <rect x="14" y="3" width="7" height="5" rx="1.5" />
      <rect x="14" y="12" width="7" height="9" rx="1.5" />
      <rect x="3" y="16" width="7" height="5" rx="1.5" />
    </>
  ),
  org: <path d="M17.5 19a4.5 4.5 0 0 0 .5-8.97A6 6 0 0 0 6.2 8.5 4 4 0 0 0 6 16.5" />,
  'access-groups': <path d="M12 3l8 4v5c0 5-3.5 8.5-8 9-4.5-.5-8-4-8-9V7l8-4z" />,
  simulator: <path d="M9 3h6M10 3v6l-5 9a2 2 0 0 0 1.7 3h10.6a2 2 0 0 0 1.7-3l-5-9V3" />,
  'logs-mcp': <path d="M3 12h4l3-7 4 14 3-7h4" />,
  'logs-admin': <path d="M9 12h6M9 16h6M7 4h10a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2z" />,
  settings: (
    <>
      <rect x="4" y="11" width="16" height="9" rx="2" />
      <path d="M8 11V7a4 4 0 0 1 8 0v4" />
    </>
  ),
};

/** The count beside a sidebar item, from /summary (neutral: a count, not a status). */
function badgeFor(id: ViewId, summary: ShellSummary | null): { value: number; title: string } | null {
  if (!summary) return null;
  switch (id) {
    case 'org': {
      const missing = summary.missingInOrg.profiles + summary.missingInOrg.objects + summary.missingInOrg.fields;
      return missing > 0 ? { value: missing, title: `${missing} tracked item(s) no longer in the org` } : null;
    }
    case 'access-groups':
      return { value: summary.counts.groups, title: `${summary.counts.groups} access group(s)` };
    case 'logs-mcp':
      return summary.badges.mcpDeniedOrError24h > 0
        ? { value: summary.badges.mcpDeniedOrError24h, title: 'Denied or failed MCP calls in the last 24 h' }
        : null;
    case 'logs-admin':
      return summary.badges.adminFailedOrDenied24h > 0
        ? { value: summary.badges.adminFailedOrDenied24h, title: 'Failed or denied admin actions in the last 24 h' }
        : null;
    default:
      return null;
  }
}

function SessionChip({ expiresAt }: { expiresAt: string | null }) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const iv = window.setInterval(() => setNow(Date.now()), 30_000);
    return () => window.clearInterval(iv);
  }, []);
  const left = sessionTimeLeft(expiresAt, now);
  if (!left) return null;
  return <span className="session-chip num">{left}</span>;
}

export function Sidebar({
  pathname,
  summary,
  sfSettings,
  session,
  onLink,
  onSignOut,
  onClose,
}: {
  pathname: string;
  summary: ShellSummary | null;
  sfSettings: SalesforceConnectionSettings | null;
  session: AdminSession & { expiresAt: string | null };
  onLink: (e: React.MouseEvent<HTMLAnchorElement>, href: string) => void;
  onSignOut: () => void;
  onClose: () => void;
}) {
  const active = matchRoute(pathname)?.route.view;
  const displayUser = session.displayName || session.name || session.username;
  const initials = displayUser
    .split(' ')
    .map((s) => s[0])
    .join('')
    .slice(0, 2)
    .toUpperCase();
  const okta = String(session.authMethod).toLowerCase().includes('okta');

  return (
    <aside className="sb" aria-label="Sidebar">
      <div className="brand">
        <div className="brand-mark" aria-hidden="true">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
            <path d="M12 2L3 7v10l9 5 9-5V7l-9-5z" />
            <path d="M12 8v8M8 10l4 2 4-2" />
          </svg>
        </div>
        <div className="brand-txt">
          <div className="brand-t">Salesforce MCP</div>
          <div className="brand-s">admin portal</div>
        </div>
        <button type="button" className="btn gh sm sb-close" onClick={onClose} aria-label="Close navigation">
          ✕
        </button>
      </div>

      <nav className="nav" aria-label="Primary">
        {NAV_SECTIONS.map((section) => (
          <div className="nav-sec" key={section.id}>
            {section.label && <div className="nav-h">{section.label}</div>}
            {VIEWS.filter((v) => v.section === section.id).map((v) => {
              const href = viewHref(v.id);
              const on = active === v.id;
              const badge = badgeFor(v.id, summary);
              return (
                <Link
                  key={v.id}
                  href={href}
                  className={`nav-it${on ? ' on' : ''}`}
                  aria-current={on ? 'page' : undefined}
                  title={v.label}
                  onClick={(e) => onLink(e, href)}
                >
                  <span>
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" aria-hidden="true">
                      {ICONS[v.id]}
                    </svg>
                    <span className="nav-lbl">{v.label}</span>
                  </span>
                  {v.id === 'org' && (
                    <OrgStatus
                      variant="dot"
                      status={sfSettings?.connectionStatus}
                      orgId={sfSettings?.connectedOrgId}
                    />
                  )}
                  {badge && (
                    <span className="ct" title={badge.title} aria-label={badge.title}>
                      <Num value={badge.value} />
                    </span>
                  )}
                </Link>
              );
            })}
          </div>
        ))}
      </nav>

      <div className="sb-ft">
        <div className="u-row">
          <div className="av" aria-hidden="true">
            {initials}
          </div>
          <div className="u-meta">
            <div className="u-name">{displayUser}</div>
            <div className="u-role">
              <span>{okta ? 'Okta SSO' : 'Password'}</span>
              {/* Roles are not enforced yet, so every portal administrator has full access. */}
              <span>· Full admin</span>
            </div>
            <SessionChip expiresAt={session.expiresAt} />
          </div>
        </div>
        <button type="button" className="btn sm sb-signout" onClick={onSignOut} title="Sign out">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" aria-hidden="true">
            <path d="M15 4h3a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-3M10 17l-5-5 5-5M5 12h11" />
          </svg>
          <span className="nav-lbl">Sign out</span>
        </button>
      </div>
    </aside>
  );
}
