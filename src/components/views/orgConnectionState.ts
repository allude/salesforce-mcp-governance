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
 * key already stored the first click only arms the button. A first key has nothing to break.
 */
export function generateCertClick(hasPrivateKey: boolean, armed: boolean): 'arm' | 'generate' {
  return hasPrivateKey && !armed ? 'arm' : 'generate';
}

/** The generate button's label, for its own wording when no key is stored or nothing is armed. */
export function generateCertLabel(hasPrivateKey: boolean, armed: boolean, idleLabel: string): string {
  return hasPrivateKey && armed ? 'Click again to replace the key' : idleLabel;
}

export const REPLACE_KEY_WARNING =
  'This replaces the stored private key. Salesforce will reject the connection until you upload the new certificate to the Connected App and connect again.';

export const KEY_REPLACED_NOTICE =
  'Generated a new private key & certificate. Upload the new certificate to the Connected App, then Connect & Verify.';

export const KEY_GENERATED_NOTICE = 'Generated 2048-bit RSA Private Key & X.509 Certificate (.crt)';
