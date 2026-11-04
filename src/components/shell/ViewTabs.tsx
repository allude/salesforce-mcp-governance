'use client';

import React from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { Num } from '@/components/ui/primitives';
import { usePortal } from './PortalShell';
import { buildHref, matchRoute, ROUTES, VIEW_TABS, type RouteId, type ViewId } from './routes';

/** A view's tab strip (Org, Access Groups, Settings), with counts from /summary. */
export function ViewTabs({ view }: { view: ViewId }) {
  const pathname = usePathname();
  const { summary, data } = usePortal();
  const tabs = VIEW_TABS[view] ?? [];
  const current = matchRoute(pathname)?.route.id;
  const count = (id: RouteId): React.ReactNode => {
    const c = summary?.counts;
    switch (id) {
      case 'org-profiles':
        return <Num value={c?.profiles ?? data.profiles.length} />;
      case 'org-objects':
        return (
          <>
            <Num value={c?.enabledObjects ?? data.objects.filter((o) => o.enabled).length} />/
            <Num value={c?.objects ?? data.objects.length} />
          </>
        );
      case 'access-groups':
        return <Num value={c?.groups ?? data.groups.length} />;
      case 'access-matrix':
        return (
          <>
            <Num value={c?.mappedProfiles} />/<Num value={c?.profiles ?? data.profiles.length} />
          </>
        );
      default:
        return null;
    }
  };
  return <ViewTabStrip tabs={tabs} current={current} count={count} />;
}

function ViewTabStrip({
  tabs,
  current,
  count,
}: {
  tabs: readonly RouteId[];
  current: RouteId | undefined;
  count: (id: RouteId) => React.ReactNode;
}) {
  const { navigate } = usePortal();
  return (
    <nav className="vtabs" aria-label="Sections">
      {tabs.map((id) => {
        const on = current === id || (id === 'access-groups' && current === 'access-group');
        const href = buildHref(id);
        const c = count(id);
        return (
          <Link
            key={id}
            href={href}
            className={`vtab${on ? ' on' : ''}`}
            aria-current={on ? 'page' : undefined}
            onClick={(e) => {
              if (e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
              e.preventDefault();
              navigate(id);
            }}
          >
            {ROUTES[id].title}
            {c !== null && <span className="ct">{c}</span>}
          </Link>
        );
      })}
    </nav>
  );
}
