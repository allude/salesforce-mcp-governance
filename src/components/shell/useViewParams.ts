'use client';

import { useCallback, useEffect, useMemo } from 'react';
import { usePathname, useSearchParams } from 'next/navigation';
import { buildHref, matchRoute, parseViewParams, ROUTES, type RouteId, type ViewParams } from './routes';

/**
 * A page's searchParams, read through the route map: unknown keys and invalid values are dropped and
 * the address bar is rewritten to the canonical form (replaceState, so Back is not cluttered). `set`
 * merges a change and pushes it, so Back steps through filter changes and a reload or a shared link
 * shows the same view. Must sit under a Suspense boundary (the segment's loading.tsx).
 */
export function useViewParams(id: RouteId) {
  const searchParams = useSearchParams();
  const pathname = usePathname();
  const route = ROUTES[id];
  const parsed = useMemo(
    () => parseViewParams(route, new URLSearchParams(searchParams.toString())),
    [route, searchParams]
  );
  const pathParams = useMemo(() => matchRoute(pathname)?.pathParams ?? {}, [pathname]);

  useEffect(() => {
    if (!parsed.changed) return;
    if (matchRoute(pathname)?.route.id !== id) return;
    window.history.replaceState(null, '', `${pathname}${parsed.search}`);
  }, [parsed, pathname, id]);

  const set = useCallback(
    (patch: ViewParams, mode: 'push' | 'replace' = 'push') => {
      const next = { ...parsed.values, ...patch };
      for (const [k, v] of Object.entries(patch)) if (v === '') delete next[k];
      const href = buildHref(id, next, pathParams);
      if (href === `${window.location.pathname}${window.location.search}`) return;
      if (mode === 'push') window.history.pushState(null, '', href);
      else window.history.replaceState(null, '', href);
    },
    [id, parsed.values, pathParams]
  );

  return { values: parsed.values, pathParams, set };
}
