import type { SalesforceConnectionSettings } from '@/types/governance';

/** What the Org Connection header badge shows for each connection status. */
export function connectionStatusBadge(
  status: SalesforceConnectionSettings['connectionStatus'],
  connectedOrgId: string
): { label: string; variant: 'emerald' | 'amber' | 'rose' | 'slate' } {
  switch (status) {
    case 'connected':
      return { label: `Connected (${connectedOrgId || 'Active'})`, variant: 'emerald' };
    case 'not_verified':
      return { label: 'Not Verified', variant: 'amber' };
    case 'error':
      return { label: 'Connection Error', variant: 'rose' };
    default:
      return { label: 'Not Connected', variant: 'slate' };
  }
}

/**
 * Replacing a key breaks the org connection until the new certificate reaches Salesforce, so with a
 * key already stored the click only opens a confirmation. A first key has nothing to break.
 */
export function generateCertClick(hasPrivateKey: boolean): 'confirm' | 'generate' {
  return hasPrivateKey ? 'confirm' : 'generate';
}

/** Past the window of a double-click, whose second click lands wherever the dialog has just appeared. */
const DIALOG_ARMING_MS = 500;

/** Whether a click on the open dialog can be deliberate, so the click that opened it cannot answer it. */
export function dialogClickCounts(openedAt: number, now: number): boolean {
  return now - openedAt >= DIALOG_ARMING_MS;
}

export const REPLACE_KEY_WARNING =
  'This replaces the stored private key. Salesforce will reject the connection until you upload the new certificate to the Connected App and connect again.';

export const KEY_REPLACED_NOTICE =
  'Generated a new private key & certificate. Upload the new certificate to the Connected App, then Connect & Verify.';

export const KEY_GENERATED_NOTICE = 'Generated 2048-bit RSA Private Key & X.509 Certificate (.crt)';

function hostnameOf(url: string): string {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return '';
  }
}

function isSandboxLoginHost(host: string): boolean {
  return (
    host === 'test.salesforce.com' ||
    host.endsWith('.sandbox.my.salesforce.com') ||
    host.endsWith('.sandbox.lightning.force.com')
  );
}

/** A connection that logs in through a sandbox while MCP verifies user tokens at production login. */
export function mcpTokenHostWarning(
  settings: Pick<SalesforceConnectionSettings, 'connectionStatus' | 'loginUrl' | 'instanceUrl'>
): string | null {
  if (settings.connectionStatus !== 'connected') return null;
  if (!isSandboxLoginHost(hostnameOf(settings.loginUrl))) return null;
  if (hostnameOf(settings.instanceUrl) !== 'login.salesforce.com') return null;
  return 'This connection logs in through a sandbox, but MCP verifies user tokens at login.salesforce.com, so sandbox users may be refused. Set the MCP token host to the sandbox My Domain URL, or Connect & Verify again to use the connected host.';
}
