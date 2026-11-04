import { Suspense } from 'react';
import { PortalShell } from '@/components/shell/PortalShell';
import { ViewSkeleton } from '@/components/shell/ViewSkeleton';

/**
 * Every signed-in page. The shell (sidebar, header, drawer, palette, drafts) lives here, so moving
 * between views keeps it mounted. It reads useSearchParams (the open drawer), hence the Suspense.
 */
export default function PortalLayout({ children }: { children: React.ReactNode }) {
  return (
    <Suspense fallback={<ViewSkeleton />}>
      <PortalShell>{children}</PortalShell>
    </Suspense>
  );
}
