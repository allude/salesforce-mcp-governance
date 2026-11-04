import React from 'react';

/** The loading state every (portal) segment shows (loading.tsx) and the shell shows until data arrives. */
export function ViewSkeleton({ label = 'Loading…' }: { label?: string }) {
  return (
    <div className="skel" role="status" aria-live="polite" aria-busy="true">
      <span className="sr-only">{label}</span>
      <div className="skel-h" />
      <div className="skel-row">
        <div className="skel-card" />
        <div className="skel-card" />
        <div className="skel-card" />
      </div>
      <div className="skel-tbl" />
    </div>
  );
}
