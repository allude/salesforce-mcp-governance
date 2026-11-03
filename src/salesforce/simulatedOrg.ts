/** The fake host a simulated connection reports. No real Salesforce token may ever be sent to it. */
export const SIMULATED_ORG_INSTANCE_URL = 'https://enterprise-org.my.salesforce.com';

/** The Org ID a simulated connection reports when no expected Org ID is set. */
export const SIMULATED_ORG_ID = '00D8b000002MCPORG';

/** The hosts instance_url holds before anyone has chosen one: the seed values, which only route logins. */
const GENERIC_LOGIN_HOSTS = new Set(['login.salesforce.com', 'test.salesforce.com']);

/** A URL's host as DNS compares it: URL parsing lowercases it and drops the port, and a trailing dot names the same host. */
function comparableHostname(url: string): string | null {
  try {
    return new URL(url.trim()).hostname.replace(/\.+$/, '');
  } catch {
    return null;
  }
}

const SIMULATED_ORG_HOSTNAME = comparableHostname(SIMULATED_ORG_INSTANCE_URL);

/**
 * Whether a URL points at the simulated host, however it is written: any case, port, path or trailing
 * dot. An exact string match let `https://enterprise-org.my.salesforce.com:8443` through every guard.
 */
export function isSimulatedOrgHost(url: string): boolean {
  return comparableHostname(url) === SIMULATED_ORG_HOSTNAME;
}

/** Refuses the simulated host anywhere a real token or JWT assertion would be sent. */
export function assertNotSimulatedOrgHost(url: string, role: string): void {
  if (isSimulatedOrgHost(url)) {
    throw new Error(`The simulated org host cannot be used as the ${role}.`);
  }
}

/**
 * Whether instance_url (MCP's token host) still waits for a real value: blank, a generic login host, or
 * the simulated host. Anything else, even a value that cannot be parsed, counts as the admin's choice.
 */
export function isUninitialisedMcpTokenHost(instanceUrl: string): boolean {
  if (!instanceUrl.trim()) return true;
  const hostname = comparableHostname(instanceUrl);
  return hostname !== null && (GENERIC_LOGIN_HOSTS.has(hostname) || hostname === SIMULATED_ORG_HOSTNAME);
}
