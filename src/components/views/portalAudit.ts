import { auditResultFromAction, type PortalAuditResult } from '@/security/auditResult';
import { statusTone, type StatusTone } from '@/components/ui/statusTone';

/** The Result shown for a Portal Admin log row: its stored result, or the action-name rule for a row without one. */
export function portalAuditResult(record: { action: string; result?: PortalAuditResult }): {
  label: PortalAuditResult;
  tone: StatusTone;
} {
  const label = record.result ?? auditResultFromAction(record.action);
  // SUCCESS emerald, DENIED rose, FAILED amber: the colours MCP calls use for the same outcomes.
  return { label, tone: statusTone(label) };
}
