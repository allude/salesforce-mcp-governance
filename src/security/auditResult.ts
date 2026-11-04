// Shared by the store and the portal, so it must not import server-only modules.

/** What a Portal Admin log row records as the outcome of the action it describes. */
export const PORTAL_AUDIT_RESULTS = ['SUCCESS', 'FAILED', 'DENIED'] as const;

export type PortalAuditResult = (typeof PORTAL_AUDIT_RESULTS)[number];

/**
 * The result of a row written without one. Failures and refusals have always been logged under their
 * own action names (LOGIN_FAILED, OKTA_LOGIN_DENIED), so the name's suffix decides.
 */
export function auditResultFromAction(action: string): PortalAuditResult {
  if (/_FAILED$/.test(action)) return 'FAILED';
  if (/_DENIED$/.test(action)) return 'DENIED';
  return 'SUCCESS';
}
