/** Portal Admin log rows have no result column: failures are recorded under their own action names. */
export function portalAuditResult(action: string): { label: string; tone: 'ok' | 'err' } {
  if (/_FAILED$/.test(action)) return { label: 'FAILED', tone: 'err' };
  if (/_DENIED$/.test(action)) return { label: 'DENIED', tone: 'err' };
  return { label: 'SUCCESS', tone: 'ok' };
}
