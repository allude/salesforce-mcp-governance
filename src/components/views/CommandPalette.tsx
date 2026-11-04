'use client';

import React, { useState, useEffect, useMemo } from 'react';
import type {
  SalesforceProfile,
  SalesforceObjectConfig,
  AccessGroup,
} from '@/types/governance';
import { grantsAccess, readableGrants } from '@/rbac/groupGrants';
import type { FlyoutState } from './FlyoutDrawer';
import { newAccessGroupDraft } from './accessGroupDraft';

interface CommandPaletteProps {
  open: boolean;
  onClose: () => void;
  onNavigateView: (view: string) => void;
  onOpenFlyout: (flyout: FlyoutState) => void;
  /** Absent in production, where the server refuses sample data. */
  onSeedEnterpriseMatrix?: () => void;
  onToggleTheme: () => void;
  theme: 'dark' | 'light';
  profiles: SalesforceProfile[];
  objects: SalesforceObjectConfig[];
  groups: AccessGroup[];
}

export function CommandPalette({
  open,
  onClose,
  onNavigateView,
  onOpenFlyout,
  onSeedEnterpriseMatrix,
  onToggleTheme,
  theme,
  profiles,
  objects,
  groups,
}: CommandPaletteProps) {
  const [query, setQuery] = useState('');
  const [activeIndex, setActiveIndex] = useState(0);

  useEffect(() => {
    if (open) {
      setQuery('');
      setActiveIndex(0);
    }
  }, [open]);

  const items = useMemo(() => {
    const q = query.trim().toLowerCase();
    const list: Array<{
      id: string;
      section: string;
      label: string;
      meta: string;
      action: () => void;
    }> = [
      {
        id: 'nav-dashboard',
        section: 'Navigation',
        label: 'Go to Dashboard',
        meta: 'Overview · KPIs · Needs attention',
        action: () => onNavigateView('dashboard'),
      },
      {
        id: 'nav-profiles',
        section: 'Navigation',
        label: 'Go to Salesforce · Profiles',
        meta: `${profiles.length} profiles`,
        action: () => onNavigateView('profiles'),
      },
      {
        id: 'nav-objects',
        section: 'Navigation',
        label: 'Go to Salesforce · Objects',
        meta: `${objects.length} SObjects`,
        action: () => onNavigateView('objects'),
      },
      {
        id: 'nav-sf-conn',
        section: 'Navigation',
        label: 'Go to Salesforce · Org Connection (JWT)',
        meta: 'OAuth 2.0 JWT Bearer',
        action: () => onNavigateView('sf-connection'),
      },
      {
        id: 'nav-groups',
        section: 'Navigation',
        label: 'Go to Access Matrix · Groups',
        meta: `${groups.length} groups`,
        action: () => onNavigateView('groups'),
      },
      {
        id: 'nav-matrix',
        section: 'Navigation',
        label: 'Go to Access Matrix · Profile ↔ Group',
        meta: 'RBAC grid',
        action: () => onNavigateView('matrix'),
      },
      {
        id: 'nav-traffic',
        section: 'Navigation',
        label: 'Go to Logs · MCP Traffic',
        meta: 'PII-redacted telemetry',
        action: () => onNavigateView('traffic'),
      },
      {
        id: 'nav-audit',
        section: 'Navigation',
        label: 'Go to Logs · Portal Audit',
        meta: 'Admin governance log',
        action: () => onNavigateView('audit'),
      },
      {
        id: 'nav-auth',
        section: 'Navigation',
        label: 'Go to Portal Auth & Okta SSO',
        meta: 'Administrators & OIDC',
        action: () => onNavigateView('auth-settings'),
      },
      {
        id: 'act-sim',
        section: 'Quick Actions',
        label: 'Open Live MCP Policy Simulator',
        meta: 'Test RBAC policies',
        action: () => onOpenFlyout({ type: 'simulator' }),
      },
      {
        id: 'act-new-group',
        section: 'Quick Actions',
        label: 'Create New Access Group',
        meta: 'Configure actions & R·C·U·D',
        action: () =>
          onOpenFlyout({
            type: 'group',
            data: newAccessGroupDraft(),
          }),
      },
      {
        id: 'act-import-csv',
        section: 'Quick Actions',
        label: 'Import Salesforce Profiles CSV',
        meta: 'ProfileId,ProfileName',
        action: () => onOpenFlyout({ type: 'import' }),
      },
      {
        id: 'act-sync-sfdx',
        section: 'Quick Actions',
        label: 'Sync Salesforce SObjects (SFDX / Org Pull)',
        meta: 'XML folder or describeGlobal',
        action: () => onOpenFlyout({ type: 'sync' }),
      },
      ...(onSeedEnterpriseMatrix
        ? [
            {
              id: 'act-seed',
              section: 'Quick Actions',
              label: 'Load Reference Enterprise Governance Matrix',
              meta: '5 standard groups + profile mappings',
              action: () => onSeedEnterpriseMatrix(),
            },
          ]
        : []),
      {
        id: 'act-theme',
        section: 'Quick Actions',
        label: `Switch to ${theme === 'dark' ? 'Daylight (Light)' : 'Obsidian (Dark)'} Theme`,
        meta: 'Appearance',
        action: () => onToggleTheme(),
      },
    ];

    for (const g of groups) {
      list.push({
        id: `grp-${g.id}`,
        section: 'Access Groups',
        label: g.name,
        meta: `${g.allowedActions.length} actions · ${readableGrants(g.objectPermissions).filter(grantsAccess).length} objects`,
        action: () => onOpenFlyout({ type: 'group', data: g }),
      });
    }

    for (const o of objects.slice(0, 30)) {
      list.push({
        id: `obj-${o.objectName}`,
        section: 'Salesforce Objects',
        label: `${o.objectName} (${o.label})`,
        meta: `${o.enabled ? 'Enabled' : 'Disabled'} · ${o.fields.length} fields`,
        action: () => onOpenFlyout({ type: 'object', data: o }),
      });
    }

    for (const p of profiles.slice(0, 30)) {
      list.push({
        id: `prof-${p.id}`,
        section: 'Salesforce Profiles',
        label: p.name,
        meta: p.id,
        action: () => onOpenFlyout({ type: 'profile', data: p }),
      });
    }

    if (!q) return list.slice(0, 24);
    return list
      .filter(
        (it) =>
          it.label.toLowerCase().includes(q) ||
          it.meta.toLowerCase().includes(q) ||
          it.section.toLowerCase().includes(q)
      )
      .slice(0, 24);
  }, [
    query,
    profiles,
    objects,
    groups,
    theme,
    onNavigateView,
    onOpenFlyout,
    onSeedEnterpriseMatrix,
    onToggleTheme,
  ]);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        onClose();
      } else if (e.key === 'ArrowDown') {
        e.preventDefault();
        setActiveIndex((i) => (items.length ? (i + 1) % items.length : 0));
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        setActiveIndex((i) =>
          items.length ? (i - 1 + items.length) % items.length : 0
        );
      } else if (e.key === 'Enter' && items[activeIndex]) {
        e.preventDefault();
        items[activeIndex].action();
        onClose();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, items, activeIndex, onClose]);

  if (!open) return null;

  return (
    <div className="cmdk-scrim" onClick={onClose}>
      <div className="cmdk-box" onClick={(e) => e.stopPropagation()}>
        <div className="cmdk-inp-wrap">
          <svg
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
          >
            <circle cx="11" cy="11" r="7" />
            <path d="M20 20l-3.5-3.5" />
          </svg>
          <input
            autoFocus
            className="cmdk-inp"
            placeholder="Jump to view, profile, SObject, access group, or run command…"
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setActiveIndex(0);
            }}
          />
          <span className="kbd">ESC</span>
        </div>
        <div className="cmdk-list">
          {items.length === 0 ? (
            <div className="empty">No matching views, entities, or commands.</div>
          ) : (
            items.map((it, idx) => {
              const showSec =
                idx === 0 || items[idx - 1].section !== it.section;
              return (
                <React.Fragment key={it.id}>
                  {showSec && <div className="cmdk-sec">{it.section}</div>}
                  <button
                    type="button"
                    className={`cmdk-item ${idx === activeIndex ? 'active' : ''}`}
                    onMouseEnter={() => setActiveIndex(idx)}
                    onClick={() => {
                      it.action();
                      onClose();
                    }}
                  >
                    <span style={{ fontWeight: 500 }}>{it.label}</span>
                    <span className="mono" style={{ color: 'var(--t3)' }}>
                      {it.meta}
                    </span>
                  </button>
                </React.Fragment>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
}
