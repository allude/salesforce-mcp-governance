/**
 * The one mapping from a runtime status to its colour, for every place the portal shows one: the MCP
 * traffic table, drawer, chart and KPIs, the admin audit Result, the org connection badge and the
 * header's freshness chip. Emerald means allowed or healthy, rose denied, amber an error or a degraded
 * state; anything else is neutral slate. Nothing else in src may map a status to a colour.
 */
export type StatusTone = 'allowed' | 'denied' | 'error' | 'neutral';

const TONES: Record<string, StatusTone> = {
  // MCP call outcomes (CopilotMcpLogRecord.status) and admin audit results (PortalAuditResult).
  ALLOWED: 'allowed',
  SUCCESS: 'allowed',
  DENIED: 'denied',
  ERROR: 'error',
  FAILED: 'error',
  // Org connection (SalesforceConnectionSettings.connectionStatus).
  CONNECTED: 'allowed',
  NOT_VERIFIED: 'error',
  // Shell freshness (Live / Degraded); Paused and Disconnected stay neutral.
  LIVE: 'allowed',
  DEGRADED: 'error',
};

export function statusTone(status: string | null | undefined): StatusTone {
  if (typeof status !== 'string') return 'neutral';
  return TONES[status.trim().toUpperCase().replace(/[\s-]+/g, '_')] ?? 'neutral';
}

/** The class suffix the status tokens use (`.tag.st-denied`, `.dot.st-error`, `.b-seg.st-allowed`). */
export function statusToneClass(tone: StatusTone): string {
  return tone === 'neutral' ? '' : `st-${tone}`;
}
