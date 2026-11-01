/** The fake host a simulated connection reports. No real Salesforce token may ever be sent to it. */
export const SIMULATED_ORG_INSTANCE_URL = 'https://enterprise-org.my.salesforce.com';

/** The Org ID a simulated connection reports when no expected Org ID is set. */
export const SIMULATED_ORG_ID = '00D8b000002MCPORG';

/** The hosts instance_url holds before anyone has chosen one: the seed values, which only route logins. */
const GENERIC_LOGIN_HOSTS = new Set(['login.salesforce.com', 'test.salesforce.com']);

/**
 * Whether instance_url (MCP's token host) still waits for a real value: blank, a generic login host, or
 * the simulated host. Anything else, even a value that cannot be parsed, counts as the admin's choice.
 */
export function isUninitialisedMcpTokenHost(instanceUrl: string): boolean {
  const value = instanceUrl.trim();
  if (!value) return true;
  try {
    const { hostname } = new URL(value);
    return GENERIC_LOGIN_HOSTS.has(hostname) || hostname === new URL(SIMULATED_ORG_INSTANCE_URL).hostname;
  } catch {
    return false;
  }
}
