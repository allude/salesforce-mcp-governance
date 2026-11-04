'use client';

import React, { useState, useEffect, useMemo } from 'react';
import type { SalesforceProfile, SalesforceObjectConfig, AccessGroup, SearchHit } from '@/types/governance';
import { isKnownMcpAction } from '@/groups/groupGrants';
import { grantsAccess, readableGrants } from '@/rbac/groupGrants';
import { VIEWS, VIEW_TABS, ROUTES, type DrawerRef, type RouteId, type ViewParams } from '@/components/shell/routes';
import { useModalDialog } from './useModalDialog';
import { filterPaletteItems, type PaletteItem } from './paletteFilter';

interface CommandPaletteProps {
  open: boolean;
  onClose: () => void;
  /** Goes to a route from the route map (guarded by the shell against losing a draft). */
  onNavigate: (route: RouteId, params?: ViewParams) => void;
  /** Opens a drawer on the current view (guarded by the shell). */
  onOpenDrawer: (ref: DrawerRef) => void;
  onNewGroup: () => void;
  /** Absent in production, where the server refuses sample data. */
  onSeedEnterpriseMatrix?: () => void;
  onToggleTheme: () => void;
  theme: 'dark' | 'light';
  profiles: SalesforceProfile[];
  objects: SalesforceObjectConfig[];
  groups: AccessGroup[];
  /** GET /api/admin/search: identifiers beyond the loaded lists (fields, log event ids). */
  searchIdentifiers?: (q: string, signal: AbortSignal) => Promise<SearchHit[]>;
}

const HIT_SECTION: Record<SearchHit['kind'], string> = {
  profile: 'Salesforce Profiles',
  object: 'Salesforce Objects',
  field: 'Fields',
  group: 'Access Groups',
  tool: 'MCP tools',
  mcp_event: 'MCP log events',
  admin_event: 'Admin audit events',
};

export function CommandPalette({
  open,
  onClose,
  onNavigate,
  onOpenDrawer,
  onNewGroup,
  onSeedEnterpriseMatrix,
  onToggleTheme,
  theme,
  profiles,
  objects,
  groups,
  searchIdentifiers,
}: CommandPaletteProps) {
  const [query, setQuery] = useState('');
  const [activeIndex, setActiveIndex] = useState(0);
  const [hits, setHits] = useState<SearchHit[]>([]);
  // A dialog like the others: Escape closes the palette alone (never the drawer under it), Tab stays
  // in, and focus goes back to whatever opened it.
  const modal = useModalDialog<HTMLDivElement, HTMLInputElement>(open, onClose);
  const listId = React.useId();

  useEffect(() => {
    if (open) {
      setQuery('');
      setActiveIndex(0);
      setHits([]);
    }
  }, [open]);

  // Identifiers the loaded lists do not hold, from the server; debounced, the stale request aborted.
  useEffect(() => {
    const q = query.trim();
    if (!open || !searchIdentifiers || q.length < 2) {
      setHits([]);
      return;
    }
    const controller = new AbortController();
    const timer = setTimeout(() => {
      searchIdentifiers(q, controller.signal)
        .then((found) => {
          if (!controller.signal.aborted) setHits(found);
        })
        .catch(() => {
          // The palette still lists the local matches.
        });
    }, 200);
    return () => {
      clearTimeout(timer);
      controller.abort();
    };
  }, [open, query, searchIdentifiers]);

  const items = useMemo(() => {
    const list: PaletteItem[] = [];
    for (const view of VIEWS) {
      const tabs = VIEW_TABS[view.id] ?? [view.home];
      for (const route of tabs) {
        const tabbed = tabs.length > 1;
        list.push({
          id: `nav-${route}`,
          section: 'Navigation',
          label: tabbed ? `${view.label} · ${ROUTES[route].title}` : view.label,
          meta: ROUTES[route].path,
          action: () => onNavigate(route),
        });
      }
    }
    list.push({
      id: 'act-new-group',
      section: 'Quick Actions',
      label: 'Create New Access Group',
      meta: 'Configure actions & R·C·U·D',
      action: onNewGroup,
    });
    if (onSeedEnterpriseMatrix) {
      list.push({
        id: 'act-seed',
        section: 'Quick Actions',
        label: 'Load Reference Enterprise Governance Matrix',
        meta: '5 standard groups + profile mappings',
        action: onSeedEnterpriseMatrix,
      });
    }
    list.push({
      id: 'act-theme',
      section: 'Quick Actions',
      label: `Switch to ${theme === 'dark' ? 'Light' : 'Dark'} theme`,
      meta: 'Appearance',
      action: onToggleTheme,
    });

    const seen = new Set<string>();
    for (const g of groups) {
      seen.add(`group:${g.id}`);
      list.push({
        id: `grp-${g.id}`,
        section: 'Access Groups',
        label: g.name,
        // Counted as the Profile ↔ Group matrix counts them: only this server's tools.
        meta: `${(g.allowedActions || []).filter(isKnownMcpAction).length} actions · ${readableGrants(g.objectPermissions).filter(grantsAccess).length} objects`,
        action: () => onOpenDrawer({ type: 'group', id: g.id }),
      });
    }
    for (const o of objects) {
      seen.add(`object:${o.objectName}`);
      list.push({
        id: `obj-${o.objectName}`,
        section: 'Salesforce Objects',
        label: `${o.objectName} (${o.label})`,
        meta: `${o.enabled ? 'Enabled' : 'Disabled'} · ${o.fields.length} fields`,
        action: () => onOpenDrawer({ type: 'object', id: o.objectName }),
      });
    }
    for (const p of profiles) {
      seen.add(`profile:${p.id}`);
      list.push({
        id: `prof-${p.id}`,
        section: 'Salesforce Profiles',
        label: p.name,
        meta: p.id,
        action: () => onOpenDrawer({ type: 'profile', id: p.id }),
      });
    }
    for (const hit of hits) {
      if (seen.has(`${hit.kind}:${hit.id}`)) continue;
      const action = (): void => {
        switch (hit.kind) {
          case 'profile':
            return onOpenDrawer({ type: 'profile', id: hit.id });
          case 'object':
            return onOpenDrawer({ type: 'object', id: hit.id });
          case 'field':
            return onOpenDrawer({ type: 'object', id: hit.id.split('.')[0] });
          case 'group':
            return onOpenDrawer({ type: 'group', id: hit.id });
          case 'tool':
            return onNavigate('simulator', { tool: hit.id });
          case 'mcp_event':
            return onNavigate('logs-mcp', { drawer: `mcp:${hit.id}` });
          case 'admin_event':
            return onNavigate('logs-admin', { drawer: `audit:${hit.id}` });
        }
      };
      list.push({ id: `hit-${hit.kind}-${hit.id}`, section: HIT_SECTION[hit.kind], label: hit.id, meta: hit.label, action });
    }
    return filterPaletteItems(list, query);
  }, [query, hits, profiles, objects, groups, theme, onNavigate, onOpenDrawer, onNewGroup, onSeedEnterpriseMatrix, onToggleTheme]);

  if (!open) return null;

  // The palette closes first and hands focus back, then the command runs (it may open a drawer or a
  // confirm of its own).
  const run = (item: PaletteItem) => {
    modal.close();
    item.action();
  };

  const onListKey = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setActiveIndex((i) => (items.length ? (i + 1) % items.length : 0));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setActiveIndex((i) => (items.length ? (i - 1 + items.length) % items.length : 0));
    } else if (e.key === 'Enter' && items[activeIndex]) {
      e.preventDefault();
      run(items[activeIndex]);
    }
  };

  const activeId = items[activeIndex] ? `${listId}-${activeIndex}` : undefined;

  return (
    <div className="cmdk-scrim" onClick={modal.close}>
      <div
        ref={modal.dialogRef}
        className="cmdk-box"
        role="dialog"
        aria-modal="true"
        aria-label="Command palette"
        tabIndex={-1}
        onClick={(e) => e.stopPropagation()}
        onKeyDown={onListKey}
      >
        <div className="cmdk-inp-wrap">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
            <circle cx="11" cy="11" r="7" />
            <path d="M20 20l-3.5-3.5" />
          </svg>
          <input
            ref={modal.initialFocusRef}
            className="cmdk-inp"
            role="combobox"
            aria-expanded="true"
            aria-controls={listId}
            aria-activedescendant={activeId}
            aria-label="Search views, Profiles, SObjects, fields, groups and log events"
            placeholder="Jump to a view, Profile, SObject, field, access group or log event…"
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setActiveIndex(0);
            }}
          />
          <span className="kbd">ESC</span>
        </div>
        <div className="cmdk-list" id={listId} role="listbox" aria-label="Results">
          {items.length === 0 ? (
            <div className="empty">No matching views, entities, or commands.</div>
          ) : (
            items.map((it, idx) => {
              const showSec = idx === 0 || items[idx - 1].section !== it.section;
              return (
                <React.Fragment key={it.id}>
                  {showSec && (
                    <div className="cmdk-sec" role="presentation">
                      {it.section}
                    </div>
                  )}
                  <button
                    type="button"
                    id={`${listId}-${idx}`}
                    role="option"
                    aria-selected={idx === activeIndex}
                    tabIndex={-1}
                    className={`cmdk-item ${idx === activeIndex ? 'active' : ''}`}
                    onMouseEnter={() => setActiveIndex(idx)}
                    onClick={() => run(it)}
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
