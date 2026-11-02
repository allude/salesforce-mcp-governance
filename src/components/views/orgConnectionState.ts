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
 * Whether the Simulated connection mode is offered. The server refuses it in production, so it shows
 * there only when already stored, to keep that state visible until the admin moves to a live org.
 */
export function showSimulatedConnectionOption(
  devToolsEnabled: boolean,
  storedAuthMode: SalesforceConnectionSettings['authMode']
): boolean {
  return devToolsEnabled || storedAuthMode === 'simulated';
}

type StoredKeyState = Pick<SalesforceConnectionSettings, 'hasPrivateKey' | 'privateKeyUndecryptable'>;

/** A key is stored, whether or not this server can currently decrypt it. */
export function storedKeyExists(settings: StoredKeyState): boolean {
  return settings.hasPrivateKey || settings.privateKeyUndecryptable;
}

/** Which confirmation a replacement needs. An undecryptable key has its own: it could still be recovered. */
export type ReplaceKeyConfirmation = 'replace' | 'destroy-undecryptable';

/**
 * Replacing a key breaks the org connection until the new certificate reaches Salesforce, so with a
 * key already stored the click only opens a confirmation. A first key has nothing to break.
 */
export function generateCertClick(settings: StoredKeyState): ReplaceKeyConfirmation | 'generate' {
  if (settings.privateKeyUndecryptable) return 'destroy-undecryptable';
  return settings.hasPrivateKey ? 'replace' : 'generate';
}

/**
 * Confirms the undecryptable key only when the admin was shown that warning. Settings that went stale
 * must not confirm a destruction nobody saw, so the server refuses those and the portal refreshes.
 */
export function generateCertRequestBody(commonName: string, confirmed: ReplaceKeyConfirmation | null) {
  return confirmed === 'destroy-undecryptable'
    ? { commonName, confirmReplaceUndecryptableKey: true }
    : { commonName };
}

/** The key badge in Step 1. Reads "unreadable", since "no key" would hide that one could be recovered. */
export function privateKeyBadge(settings: StoredKeyState): { label: string; variant: 'emerald' | 'amber' | 'rose' } {
  if (settings.privateKeyUndecryptable) return { label: 'Stored Key Cannot Be Decrypted', variant: 'rose' };
  return settings.hasPrivateKey
    ? { label: 'Private Key Stored (AES-256)', variant: 'emerald' }
    : { label: 'No Key Configured', variant: 'amber' };
}

/** Past the window of a double-click, whose second click lands wherever the dialog has just appeared. */
const DIALOG_ARMING_MS = 500;

/** Whether a click on the open dialog can be deliberate, so the click that opened it cannot answer it. */
export function dialogClickCounts(openedAt: number, now: number): boolean {
  return now - openedAt >= DIALOG_ARMING_MS;
}

export const REPLACE_KEY_WARNING =
  'This replaces the stored private key. Salesforce will reject the connection until you upload the new certificate to the Connected App and connect again.';

export const UNDECRYPTABLE_KEY_WARNING =
  'The stored private key cannot be decrypted with the current APP_SECRET_KEY, so this server cannot sign with it. Restoring the previous APP_SECRET_KEY could recover the key. Generating a new key destroys it for good, and so does saving a pasted one.';

/** What the confirmation says and asks for each kind of replacement. */
export function replaceKeyDialog(confirmation: ReplaceKeyConfirmation): {
  title: string;
  warnings: string[];
  confirmLabel: string;
} {
  return confirmation === 'destroy-undecryptable'
    ? {
        title: 'Destroy the undecryptable private key?',
        warnings: [UNDECRYPTABLE_KEY_WARNING, REPLACE_KEY_WARNING],
        confirmLabel: 'Destroy it and generate',
      }
    : {
        title: 'Replace the stored private key?',
        warnings: [REPLACE_KEY_WARNING],
        confirmLabel: 'Replace the key',
      };
}

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
  settings: Pick<SalesforceConnectionSettings, 'connectionStatus' | 'authMode' | 'loginUrl' | 'instanceUrl'>
): string | null {
  if (settings.connectionStatus !== 'connected') return null;
  // A simulated connect never writes the instance URL, so its advice to reconnect could not clear this.
  if (settings.authMode === 'simulated') return null;
  if (!isSandboxLoginHost(hostnameOf(settings.loginUrl))) return null;
  if (hostnameOf(settings.instanceUrl) !== 'login.salesforce.com') return null;
  return 'This connection logs in through a sandbox, but MCP verifies user tokens at login.salesforce.com, so sandbox users may be refused. Set the MCP token host to the sandbox My Domain URL, or Connect & Verify again to use the connected host.';
}
