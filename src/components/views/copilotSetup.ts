import { isSimulatedOrgHost, isUninitialisedMcpTokenHost } from '@/salesforce/simulatedOrg';
import type {
  AccessGroup,
  NavViewId,
  ProfileGroupMapping,
  SalesforceObject,
} from '@/types/governance';
import { mcpActivityStatus } from './mcpActivity';

/** What the server grants and Copilot Studio should ask for; refresh_token keeps users signed in. */
export const DEFAULT_COPILOT_SCOPES = 'api refresh_token openid profile email';

/** The fields of /.well-known/oauth-protected-resource (RFC 9728) this page reads. */
export interface ProtectedResourceMetadata {
  resource?: unknown;
  authorization_servers?: unknown;
  scopes_supported?: unknown;
}

export interface CopilotConnectorValues {
  /** Copilot Studio's "Server URL". */
  serverUrl: string;
  /** Where users sign in, and where MCP verifies their tokens. */
  salesforceBase: string;
  authorizationUrl: string;
  tokenUrl: string;
  refreshUrl: string;
  scopes: string;
}

function withoutTrailingSlash(url: string): string {
  return url.trim().replace(/\/+$/, '');
}

function nonEmptyStrings(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((v): v is string => typeof v === 'string' && v.trim() !== '')
    : [];
}

/**
 * The values to paste into Copilot Studio, read from the metadata the server publishes to MCP
 * clients, so the page states what Copilot will be told. The fallback covers a failed fetch.
 */
export function copilotConnectorValues(
  metadata: ProtectedResourceMetadata | null,
  fallback: { origin: string; instanceUrl: string }
): CopilotConnectorValues {
  const serverUrl =
    typeof metadata?.resource === 'string' && metadata.resource.trim()
      ? metadata.resource.trim()
      : `${withoutTrailingSlash(fallback.origin)}/mcp`;
  const salesforceBase = withoutTrailingSlash(
    nonEmptyStrings(metadata?.authorization_servers)[0] ||
      fallback.instanceUrl ||
      'https://login.salesforce.com'
  );
  const scopes = nonEmptyStrings(metadata?.scopes_supported);
  const tokenUrl = `${salesforceBase}/services/oauth2/token`;
  return {
    serverUrl,
    salesforceBase,
    authorizationUrl: `${salesforceBase}/services/oauth2/authorize`,
    tokenUrl,
    refreshUrl: tokenUrl,
    scopes: scopes.length ? scopes.join(' ') : DEFAULT_COPILOT_SCOPES,
  };
}

/**
 * The tenant data policy pattern that matches the custom connector Copilot Studio creates for the
 * server, so admins can classify it before the connector exists.
 */
export function customConnectorPattern(serverUrl: string): string {
  try {
    return `${new URL(serverUrl).origin}/*`;
  } catch {
    return 'https://<your-mcp-host>/*';
  }
}

export type ReadinessTone = 'ok' | 'warn' | 'err' | 'off';

export interface ReadinessCheck {
  id: 'server-url' | 'salesforce-host' | 'profiles' | 'objects' | 'first-call';
  label: string;
  tone: ReadinessTone;
  detail: string;
  fix?: { view: NavViewId; label: string };
}

function hostnameOf(url: string): string | null {
  try {
    return new URL(url).hostname.toLowerCase().replace(/\.+$/, '');
  } catch {
    return null;
  }
}

/** Hosts only this machine or its network can reach, which Microsoft's cloud cannot. */
export function isPrivateHost(host: string): boolean {
  const bare = host.replace(/^\[|\]$/g, '');
  if (bare === 'localhost' || bare.endsWith('.localhost')) return true;
  if (bare.endsWith('.local') || bare.endsWith('.internal') || bare.endsWith('.lan')) return true;
  if (bare.includes(':')) {
    return bare === '::1' || bare === '::' || /^f[cd]/.test(bare) || bare.startsWith('fe80:');
  }
  const ipv4 = bare.match(/^(\d{1,3})\.(\d{1,3})\.\d{1,3}\.\d{1,3}$/);
  if (!ipv4) return !bare.includes('.');
  const [a, b] = [Number(ipv4[1]), Number(ipv4[2])];
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 100 && b >= 64 && b <= 127)
  );
}

/** Copilot Studio calls the server from Microsoft's cloud, so it needs a public HTTPS URL. */
export function serverUrlReadiness(serverUrl: string): ReadinessCheck {
  const label = 'Public HTTPS endpoint';
  const host = hostnameOf(serverUrl);
  if (host === null) {
    return { id: 'server-url', label, tone: 'err', detail: `${serverUrl} is not a valid URL. Check BASE_URL.` };
  }
  if (isPrivateHost(host)) {
    return {
      id: 'server-url',
      label,
      tone: 'err',
      detail: `Copilot Studio runs in Microsoft's cloud and cannot reach ${host}. Publish the portal on a public HTTPS host (or a tunnel) and set BASE_URL to it.`,
    };
  }
  if (!serverUrl.toLowerCase().startsWith('https://')) {
    return {
      id: 'server-url',
      label,
      tone: 'err',
      detail: 'Copilot Studio only connects to HTTPS servers. Serve the portal over HTTPS and set BASE_URL to the https:// URL.',
    };
  }
  return { id: 'server-url', label, tone: 'ok', detail: `Copilot Studio will call ${serverUrl}.` };
}

/** The Salesforce host the sign-in URLs point at, which is also where MCP verifies each user's token. */
export function salesforceHostReadiness(salesforceBase: string): ReadinessCheck {
  const label = 'Salesforce sign-in host';
  const fix = { view: 'settings-salesforce' as const, label: 'Set MCP token host' };
  const host = hostnameOf(salesforceBase) ?? salesforceBase;
  if (isSimulatedOrgHost(salesforceBase)) {
    return {
      id: 'salesforce-host',
      label,
      tone: 'err',
      detail: `${host} is the simulated org, which no real user can sign in to. Set the MCP token host to your org's My Domain URL.`,
      fix,
    };
  }
  if (isUninitialisedMcpTokenHost(salesforceBase)) {
    return {
      id: 'salesforce-host',
      label,
      tone: 'warn',
      detail: `Users would sign in at the generic ${host}. Set the MCP token host to your org's My Domain URL (https://<domain>.my.salesforce.com) so sign-in and token checks go to your org; sandboxes need it.`,
      fix,
    };
  }
  return {
    id: 'salesforce-host',
    label,
    tone: 'ok',
    detail: `Users sign in at ${host}, and MCP verifies their tokens there.`,
  };
}

/** Users whose Profile reaches no group with tools get an empty tool list in Copilot. */
export function profileAccessReadiness(
  groups: Pick<AccessGroup, 'id' | 'allowedActions'>[],
  mappings: ProfileGroupMapping[]
): ReadinessCheck {
  const label = 'Profiles granted tools';
  const toolGroups = new Set(groups.filter((g) => g.allowedActions.length > 0).map((g) => g.id));
  const granted = mappings.filter((m) => m.groupIds.some((id) => toolGroups.has(id))).length;
  if (granted === 0) {
    return {
      id: 'profiles',
      label,
      tone: 'err',
      detail: 'No Salesforce Profile is mapped to a group that grants tools, so every Copilot user would see no tools.',
      fix: { view: 'matrix-profile-groups', label: 'Map Profiles to groups' },
    };
  }
  return {
    id: 'profiles',
    label,
    tone: 'ok',
    detail: `${granted} ${granted === 1 ? 'Profile reaches' : 'Profiles reach'} a group that grants tools. Users with any other Profile see none.`,
  };
}

export function objectReadiness(objects: Pick<SalesforceObject, 'enabled'>[]): ReadinessCheck {
  const label = 'Objects enabled';
  const enabled = objects.filter((o) => o.enabled).length;
  if (enabled === 0) {
    return {
      id: 'objects',
      label,
      tone: 'warn',
      detail: 'No Salesforce object is enabled, so the tools have nothing to read or change.',
      fix: { view: 'sf-objects', label: 'Enable objects' },
    };
  }
  return {
    id: 'objects',
    label,
    tone: 'ok',
    detail: `${enabled} ${enabled === 1 ? 'object is' : 'objects are'} enabled for MCP.`,
  };
}

/**
 * Whether a signed-in user has reached the server yet. Any MCP client counts: the log does not say
 * which client called. `now` should be on the server's clock.
 */
export function firstCallReadiness(lastMcpCallAt: string | null | undefined, now: number): ReadinessCheck {
  const label = 'Verified MCP call received';
  const fix = { view: 'logs-copilot' as const, label: 'Open MCP traffic' };
  if (!lastMcpCallAt) {
    return {
      id: 'first-call',
      label,
      tone: 'off',
      detail: 'No signed-in user has called the server yet. Test the agent (step 8) and the call shows up here.',
      fix,
    };
  }
  return { id: 'first-call', label, tone: 'ok', detail: `${mcpActivityStatus(lastMcpCallAt, now).label}.`, fix };
}
