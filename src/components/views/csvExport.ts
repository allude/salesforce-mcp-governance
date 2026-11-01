import type {
  CopilotMcpLogEntry,
  PortalAdminLogEntry,
  SalesforceProfile,
} from '@/types/governance';

/**
 * One field of an exported CSV. Log values can be attacker-controlled (a failed login stores the
 * submitted username), and spreadsheets evaluate a leading formula character even inside quotes,
 * so the quote prefix is needed as well as the quoting.
 */
export function csvCell(value: string | number | boolean | null | undefined): string {
  const text = value === null || value === undefined ? '' : String(value);
  const neutralised = /^[=+\-@\t\r\n]/.test(text) ? `'${text}` : text;
  return `"${neutralised.replace(/"/g, '""')}"`;
}

export function buildCsv(
  headers: string[],
  rows: Array<Array<string | number | boolean | null | undefined>>
): string {
  return [headers, ...rows].map((row) => row.map(csvCell).join(',')).join('\n');
}

export function trafficLogCsv(rows: CopilotMcpLogEntry[]): string {
  return buildCsv(
    ['Id', 'Timestamp', 'User', 'ProfileId', 'ProfileName', 'Tool', 'TargetObject', 'Status', 'LatencyMs', 'Simulated'],
    rows.map((r) => [
      r.id,
      r.timestamp,
      r.sfUsername,
      r.profileId,
      r.profileName,
      r.toolName,
      r.targetObject,
      r.status,
      r.latencyMs,
      r.simulated ? 'true' : 'false',
    ])
  );
}

export function portalAuditCsv(rows: PortalAdminLogEntry[]): string {
  return buildCsv(
    ['Id', 'Timestamp', 'AdminUsername', 'AuthMethod', 'Action', 'Target', 'Details', 'IpAddress'],
    rows.map((r) => [r.id, r.timestamp, r.adminUsername, r.authMethod, r.action, r.target, r.details, r.ipAddress])
  );
}

export function profilesCsv(profiles: SalesforceProfile[]): string {
  return buildCsv(
    ['ProfileId', 'ProfileName', 'UpdatedAt'],
    profiles.map((p) => [p.id, p.name, p.updatedAt])
  );
}
