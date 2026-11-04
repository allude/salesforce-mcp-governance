import { auditResultFromAction, type PortalAuditResult } from '@/security/auditResult';

/** The Result shown for a Portal Admin log row: its stored result, or the action-name rule for a row without one. */
export function portalAuditResult(record: { action: string; result?: PortalAuditResult }): {
  label: PortalAuditResult;
  tone: 'ok' | 'err';
} {
  const label = record.result ?? auditResultFromAction(record.action);
  return { label, tone: label === 'SUCCESS' ? 'ok' : 'err' };
}
