'use client';

import React from 'react';
import type { SalesforceConnectionSettings } from '@/types/governance';
import { statusToneClass } from '@/components/ui/statusTone';
import { cn } from '@/components/ui/primitives';
import { connectionStatusBadge } from './orgConnectionState';

type Status = SalesforceConnectionSettings['connectionStatus'];

/**
 * The org's connection state, one component for the header, the sidebar and the dashboard so they
 * always agree: emerald Connected (with the Org ID in mono), amber Error or Not Verified, slate Not
 * Connected. `simulated` adds the neutral, dashed "Mock org" chip (never the amber of Degraded).
 */
export function OrgStatus({
  status,
  orgId,
  simulated = false,
  variant = 'inline',
  className,
}: {
  status: Status | undefined;
  orgId?: string;
  simulated?: boolean;
  /** 'dot' is the dot alone (sidebar), with the label as its accessible name. */
  variant?: 'inline' | 'dot';
  className?: string;
}) {
  const badge = connectionStatusBadge(status ?? 'disconnected', orgId || '');
  const tone = statusToneClass(badge.tone);
  const name = `Salesforce org: ${badge.label}${simulated ? ' (mock org)' : ''}`;
  if (variant === 'dot') {
    return <span className={cn('dot', tone || 'off', className)} role="img" aria-label={name} title={name} />;
  }
  return (
    <span className={cn('org-status', className)} title={name}>
      <span className={cn('dot', tone || 'off')} aria-hidden="true" />
      <span>
        {status === 'connected' ? (
          <>
            Connected <code className="mono">{orgId || 'Active'}</code>
          </>
        ) : (
          badge.label
        )}
      </span>
      {simulated && <span className="tag marker">Mock org</span>}
    </span>
  );
}
