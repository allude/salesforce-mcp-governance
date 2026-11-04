'use client';

import React, { useEffect, useMemo, useState } from 'react';
import { Check, Copy, ExternalLink } from 'lucide-react';
import type {
  AccessGroup,
  NavViewId,
  ProfileGroupMapping,
  SalesforceConnectionSettings,
  SalesforceObject,
} from '@/types/governance';
import {
  copilotConnectorValues,
  customConnectorPattern,
  firstCallReadiness,
  objectReadiness,
  profileAccessReadiness,
  salesforceHostReadiness,
  serverUrlReadiness,
  type ProtectedResourceMetadata,
} from './copilotSetup';

const SERVER_NAME = 'Salesforce CRM';
const SERVER_DESCRIPTION =
  "Lists, describes, queries (SOQL), reads, creates, updates and deletes the Salesforce records the signed-in user's Profile allows.";
const SALESFORCE_APP_NAME = 'Microsoft Copilot MCP Connector';
const REDIRECT_PLACEHOLDER = 'https://global.consent.azure-apim.net/redirect';

function Ext({ href, children }: { href: string; children: React.ReactNode }) {
  return (
    <a className="ext" href={href} target="_blank" rel="noopener noreferrer">
      {children}
      <ExternalLink aria-hidden="true" />
    </a>
  );
}

function CopyButton({
  value,
  label,
  onShowToast,
  iconOnly = false,
}: {
  value: string;
  label: string;
  onShowToast: (msg: string, isError?: boolean) => void;
  iconOnly?: boolean;
}) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      className={iconOnly ? 'btn gh sm' : 'btn sm'}
      aria-label={`Copy ${label}`}
      title={`Copy ${label}`}
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(value);
          setCopied(true);
          setTimeout(() => setCopied(false), 1500);
          onShowToast(`Copied ${label}`);
        } catch {
          onShowToast('The browser blocked the clipboard. Select the value and copy it.', true);
        }
      }}
    >
      {copied ? <Check /> : <Copy />}
      {!iconOnly && (copied ? 'Copied' : 'Copy')}
    </button>
  );
}

function CopyField({
  label,
  value,
  hint,
  onShowToast,
}: {
  label: string;
  value: string;
  hint?: React.ReactNode;
  onShowToast: (msg: string, isError?: boolean) => void;
}) {
  return (
    <div className="fld">
      <label>{label}</label>
      <div className="copy-row">
        <input
          className="inp mono"
          readOnly
          value={value}
          aria-label={label}
          onFocus={(e) => e.currentTarget.select()}
        />
        <CopyButton value={value} label={label} onShowToast={onShowToast} />
      </div>
      {hint && <div className="hint">{hint}</div>}
    </div>
  );
}

function WizardRow({
  label,
  value,
  plain = false,
  onShowToast,
}: {
  label: string;
  value: string;
  /** Prose rather than an identifier, so not set in monospace. */
  plain?: boolean;
  onShowToast: (msg: string, isError?: boolean) => void;
}) {
  return (
    <>
      <dt>{label}</dt>
      <dd className="cp">
        <span className={plain ? undefined : 'mono'}>{value}</span>
        <CopyButton value={value} label={label} iconOnly onShowToast={onShowToast} />
      </dd>
    </>
  );
}

function Step({
  n,
  where,
  title,
  children,
}: {
  n: number;
  where: string;
  title: string;
  children: React.ReactNode;
}) {
  return (
    <li className="step" id={`copilot-step-${n}`}>
      <div className="step-n" aria-hidden="true">
        {n}
      </div>
      <div className="step-b">
        <div className="step-h">
          <h3>
            <span className="sr-only">Step {n}: </span>
            {title}
          </h3>
          <span className="tag">{where}</span>
        </div>
        {children}
      </div>
    </li>
  );
}

export function CopilotConnectorView({
  sfSettings,
  groups,
  mappings,
  objects,
  lastMcpCallAt,
  serverNow,
  onShowToast,
  onNavigate,
}: {
  sfSettings: SalesforceConnectionSettings | null;
  groups: AccessGroup[];
  mappings: ProfileGroupMapping[];
  objects: SalesforceObject[];
  /** undefined until the server has answered, null when it has seen no verified call. */
  lastMcpCallAt: string | null | undefined;
  /** Now on the server's clock, which stamps the calls. */
  serverNow: number;
  onShowToast: (msg: string, isError?: boolean) => void;
  onNavigate: (view: NavViewId) => void;
}) {
  // The values come from the metadata MCP clients read, so the page says what Copilot is told.
  const [metadata, setMetadata] = useState<ProtectedResourceMetadata | null>(null);
  const [metadataFailed, setMetadataFailed] = useState(false);
  const instanceUrl = sfSettings?.instanceUrl || '';

  useEffect(() => {
    let cancelled = false;
    fetch('/.well-known/oauth-protected-resource', { cache: 'no-store' })
      .then((res) => (res.ok ? res.json() : Promise.reject(new Error(String(res.status)))))
      .then((body) => {
        if (cancelled) return;
        setMetadata(body);
        setMetadataFailed(false);
      })
      .catch(() => {
        if (!cancelled) setMetadataFailed(true);
      });
    return () => {
      cancelled = true;
    };
    // The authorization server follows the MCP token host, so a change there is refetched.
  }, [instanceUrl]);

  const values = useMemo(
    () =>
      copilotConnectorValues(metadata, {
        origin: typeof window === 'undefined' ? '' : window.location.origin,
        instanceUrl,
      }),
    [metadata, instanceUrl]
  );

  const checks = [
    serverUrlReadiness(values.serverUrl),
    salesforceHostReadiness(values.salesforceBase),
    profileAccessReadiness(groups, mappings),
    objectReadiness(objects),
    firstCallReadiness(lastMcpCallAt, serverNow),
  ];
  const blocking = checks.filter((c) => c.tone === 'err').length;

  return (
    <div className="copilot">
      <div className="ph">
        <div className="ph-l">
          <h1>Microsoft Copilot connector</h1>
          <p>
            Add this server to a Copilot Studio agent as an MCP tool, then publish the agent to
            Microsoft Teams and Microsoft 365 Copilot. Each user signs in with their own Salesforce
            account, and this portal decides which tools, objects and fields they get.
          </p>
        </div>
        <div className="ph-act">
          <a
            className="btn pri"
            href="https://copilotstudio.microsoft.com"
            target="_blank"
            rel="noopener noreferrer"
          >
            Open Copilot Studio
            <ExternalLink aria-hidden="true" />
          </a>
          <a
            className="btn"
            href="https://learn.microsoft.com/en-us/microsoft-copilot-studio/mcp-add-existing-server-to-agent"
            target="_blank"
            rel="noopener noreferrer"
          >
            Microsoft docs
            <ExternalLink aria-hidden="true" />
          </a>
        </div>
      </div>

      <div className="g2">
        <div className="card">
          <div className="card-h">
            <div>
              <div className="card-t">Values for Copilot Studio</div>
              <div className="card-s">
                Paste these into the MCP wizard in step 4. They come from this server&apos;s OAuth
                metadata, so they match what Copilot reads.
              </div>
            </div>
          </div>
          <div className="card-b">
            {metadataFailed && (
              <p className="note warn" role="status">
                The OAuth metadata at <span className="mono">/.well-known/oauth-protected-resource</span>{' '}
                could not be read, so these values come from this browser&apos;s address and the MCP
                token host. Check that the MCP backend is running.
              </p>
            )}
            <CopyField
              label="Server URL"
              value={values.serverUrl}
              hint="BASE_URL followed by /mcp. Microsoft's cloud calls it, so it must be public HTTPS."
              onShowToast={onShowToast}
            />
            <CopyField
              label="Authorization URL"
              value={values.authorizationUrl}
              onShowToast={onShowToast}
            />
            <CopyField
              label="Token URL template"
              value={values.tokenUrl}
              onShowToast={onShowToast}
            />
            <CopyField label="Refresh URL" value={values.refreshUrl} onShowToast={onShowToast} />
            <CopyField
              label="Scopes"
              value={values.scopes}
              hint="refresh_token keeps users signed in; without it they sign in again every time the access token expires."
              onShowToast={onShowToast}
            />
            <p className="card-s" style={{ margin: 0 }}>
              The Client ID and Client secret are the Consumer Key and Consumer Secret of the
              Salesforce app you create in step 3. This portal never sees them.
            </p>
          </div>
        </div>

        <div className="card">
          <div className="card-h">
            <div>
              <div className="card-t">Readiness</div>
              <div className="card-s">What this portal can check for you</div>
            </div>
            <span className={`tag ${blocking ? 'err' : 'ok'}`}>
              {blocking ? `${blocking} to fix` : 'Ready'}
            </span>
          </div>
          <ul className="chk-list readiness">
            {checks.map((check) => (
              <li className="chk-row" key={check.id}>
                <div className="readiness-row">
                  <span className={`dot ${check.tone}`} aria-hidden="true" />
                  <div>
                    <div className="readiness-t">
                      {check.label}
                      <span className="sr-only">
                        {check.tone === 'ok'
                          ? ' (done)'
                          : check.tone === 'off'
                          ? ' (waiting)'
                          : check.tone === 'warn'
                          ? ' (check)'
                          : ' (to fix)'}
                      </span>
                    </div>
                    <div className="readiness-d">{check.detail}</div>
                  </div>
                </div>
                {check.fix && (
                  <button
                    type="button"
                    className="btn sm"
                    onClick={() => onNavigate(check.fix!.view)}
                  >
                    {check.fix.label}
                  </button>
                )}
              </li>
            ))}
          </ul>
        </div>
      </div>

      <div className="card">
        <div className="card-h">
          <div>
            <div className="card-t">Step by step</div>
            <div className="card-s">
              About 30 minutes. You need admin rights in Salesforce and maker rights in a Copilot
              Studio environment.
            </div>
          </div>
        </div>
        <ol className="steps">
          <Step n={1} where="Before you start" title="Check licences and environment settings">
            <ul>
              <li>
                A Copilot Studio licence (a user licence with Copilot Credits, or pay-as-you-go) in a
                Power Platform environment where you can create agents. A trial cannot publish, and a
                Microsoft 365 Copilot licence alone does not cover these agents. Tool calls use
                Copilot Credits.{' '}
                <Ext href="https://learn.microsoft.com/en-us/microsoft-copilot-studio/billing-licensing">
                  Licensing
                </Ext>
              </li>
              <li>
                Build the agent in Copilot Studio&apos;s <strong>classic experience</strong> (on the
                home page, <strong>… → Open classic experience</strong>). Microsoft documents manual
                OAuth for MCP only there, and an agent cannot move between experiences later.{' '}
                <Ext href="https://learn.microsoft.com/en-us/microsoft-copilot-studio/agents-experience/switch-experiences">
                  Switch experiences
                </Ext>
              </li>
              <li>
                <strong>Generative orchestration</strong> on for the agent (agent{' '}
                <strong>Settings → Generative AI → Orchestration</strong>: Yes, the default). Only
                generative orchestration calls MCP tools.{' '}
                <Ext href="https://learn.microsoft.com/en-us/microsoft-copilot-studio/advanced-generative-actions">
                  Generative orchestration
                </Ext>
              </li>
              <li>
                A data policy that lets the agent use a custom connector: Copilot Studio creates one
                for the MCP server. Classify it (or a tenant pattern such as{' '}
                <span className="mono">{customConnectorPattern(values.serverUrl)}</span>) as{' '}
                <strong>Business</strong>, the same group as the Teams and Microsoft 365 channel.{' '}
                <Ext href="https://admin.powerplatform.microsoft.com/security/dataprotection/dlp">
                  Power Platform admin center
                </Ext>{' '}
                ·{' '}
                <Ext href="https://learn.microsoft.com/en-us/microsoft-copilot-studio/admin-data-loss-prevention">
                  Data policies for Copilot Studio
                </Ext>
              </li>
              <li>
                In Salesforce, an admin who can create External Client Apps, and users whose
                Profiles you will map in step 7.
              </li>
            </ul>
          </Step>

          <Step n={2} where="Your hosting" title="Publish this server on a public HTTPS URL">
            <p>
              Copilot Studio calls the MCP server from Microsoft&apos;s cloud, so{' '}
              <span className="mono">localhost</span> and private addresses do not work. The portal
              proxies <span className="mono">/mcp</span> to the backend, so publish the portal
              (port 3000) and set <span className="mono">BASE_URL</span> to its public origin.
            </p>
            <ul>
              <li>
                <strong>Production:</strong> deploy behind HTTPS (Azure Container Apps, App
                Service, or any host), set{' '}
                <span className="mono">BASE_URL=https://mcp.yourcompany.com</span>, and restart.
              </li>
              <li>
                <strong>Trying it out:</strong> run a tunnel to port 3000, put its URL in{' '}
                <span className="mono">.env</span> as <span className="mono">BASE_URL</span>, and
                restart <span className="mono">npm run dev</span>.
              </li>
            </ul>
            <pre className="code">{`npx cloudflared tunnel --url http://localhost:3000
# or
ngrok http 3000`}</pre>
            <p>
              To check it from outside, this should answer <span className="mono">401</span> with a{' '}
              <span className="mono">WWW-Authenticate</span> header:
            </p>
            <div className="copy-row">
              <pre className="code">{`curl -i -X POST ${values.serverUrl}`}</pre>
              <CopyButton
                value={`curl -i -X POST ${values.serverUrl}`}
                label="curl command"
                onShowToast={onShowToast}
              />
            </div>
          </Step>

          <Step n={3} where="Salesforce Setup" title="Create the Salesforce External Client App">
            <ol>
              <li>
                In Setup, search Quick Find for <strong>External Client App Manager</strong> and click{' '}
                <strong>New External Client App</strong>.{' '}
                <Ext href="https://help.salesforce.com/s/articleView?id=xcloud.create_a_local_external_client_app.htm&type=5">
                  Salesforce Help
                </Ext>
              </li>
              <li>
                Name it <span className="mono">{SALESFORCE_APP_NAME}</span>, add a contact email, and
                leave <strong>Distribution State</strong> on <strong>Local</strong>.
              </li>
              <li>
                Open <strong>API (Enable OAuth Settings)</strong> and tick{' '}
                <strong>Enable OAuth</strong>. For <strong>Callback URL</strong>, enter{' '}
                <span className="mono">{REDIRECT_PLACEHOLDER}</span> for now: Copilot Studio gives
                you the real one in step 4.
              </li>
              <li>
                Under <strong>OAuth Scopes</strong>, add:
                <ul>
                  <li>Manage user data via APIs (api)</li>
                  <li>Perform requests at any time (refresh_token, offline_access)</li>
                  <li>Access unique user identifiers (openid)</li>
                  <li>Access the identity URL service (id, profile, email, address, phone)</li>
                </ul>
              </li>
              <li>
                Leave the <strong>Flow Enablement</strong> options off: Copilot Studio uses the
                standard authorization code (web server) flow. Under <strong>Security</strong>, keep{' '}
                <strong>Require secret for Web Server Flow</strong> and{' '}
                <strong>Require secret for Refresh Token Flow</strong> ticked, and untick{' '}
                <strong>Require Proof Key for Code Exchange (PKCE)</strong>. Copilot Studio&apos;s
                manual OAuth sends the client secret but no PKCE challenge, so Salesforce would
                refuse the sign-in.
              </li>
              <li>
                Click <strong>Create</strong>. On the <strong>Policies</strong> tab, click{' '}
                <strong>Edit</strong> and under <strong>OAuth Policies</strong> set:
                <ul>
                  <li>
                    <strong>Permitted Users</strong>: <em>All users may self-authorize</em> lets
                    anyone sign in and approve; <em>Admin approved users are pre-authorized</em>{' '}
                    limits it to the Profiles or permission sets you add.
                  </li>
                  <li>
                    <strong>IP Relaxation</strong>: <em>Relax IP restrictions</em> if your Profiles
                    have Login IP Ranges. The token exchange runs from Microsoft&apos;s network.
                  </li>
                  <li>
                    <strong>Refresh Token Policy</strong>: how long users stay signed in. Leave
                    refresh token rotation off until you have tested it with Copilot.
                  </li>
                </ul>
              </li>
              <li>
                On the <strong>Settings</strong> tab, under <strong>OAuth Settings</strong>, click{' '}
                <strong>Consumer Key and Secret</strong>, verify with the emailed code, and copy
                both. They are the Client ID and Client secret for step 4.
              </li>
            </ol>
            <p className="card-s">
              Since Spring &apos;26 Salesforce restricts creating new Connected Apps. An existing
              Connected App still works with the same OAuth settings; its key and secret are under{' '}
              <strong>Manage Consumer Details</strong>.{' '}
              <Ext href="https://developer.salesforce.com/docs/platform/api-rest/guide/intro-oauth-and-connected-apps.html">
                Connected Apps and External Client Apps
              </Ext>
            </p>
          </Step>

          <Step n={4} where="Copilot Studio" title="Add the MCP server to your agent">
            <ol>
              <li>
                Open <Ext href="https://copilotstudio.microsoft.com">Copilot Studio</Ext>, pick your
                environment at the top right, and open the agent (or create one in the classic
                experience).
              </li>
              <li>
                On the agent&apos;s <strong>Tools</strong> page, select{' '}
                <strong>Add a tool → New tool → Model Context Protocol</strong> (some tenants skip
                the <strong>New tool</strong> step).
              </li>
              <li>
                Fill in the MCP wizard:
                <dl className="kv wizard">
                  <WizardRow label="Server name" value={SERVER_NAME} onShowToast={onShowToast} />
                  <WizardRow
                    label="Server description"
                    value={SERVER_DESCRIPTION}
                    plain
                    onShowToast={onShowToast}
                  />
                  <WizardRow label="Server URL" value={values.serverUrl} onShowToast={onShowToast} />
                  <dt>Authentication</dt>
                  <dd>
                    <strong>OAuth 2.0</strong>, type <strong>Manual</strong>
                  </dd>
                  <dt>Client ID</dt>
                  <dd>Consumer Key from step 3</dd>
                  <dt>Client secret</dt>
                  <dd>Consumer Secret from step 3</dd>
                  <WizardRow
                    label="Authorization URL"
                    value={values.authorizationUrl}
                    onShowToast={onShowToast}
                  />
                  <WizardRow label="Token URL template" value={values.tokenUrl} onShowToast={onShowToast} />
                  <WizardRow label="Refresh URL" value={values.refreshUrl} onShowToast={onShowToast} />
                  <WizardRow label="Scopes" value={values.scopes} onShowToast={onShowToast} />
                </dl>
                The description matters: generative orchestration reads it to decide when to call
                Salesforce. Use <strong>Manual</strong>: the other OAuth types need Dynamic Client
                Registration, which Salesforce does not offer here.
              </li>
              <li>
                Click <strong>Create</strong>. Copilot Studio shows a callback{' '}
                <strong>Redirect URL</strong>, usually{' '}
                <span className="mono">https://global.consent.azure-apim.net/redirect/…</span> with a
                suffix unique to this connector. Copy all of it, and leave the wizard open.
              </li>
            </ol>
            <p className="card-s">
              <Ext href="https://learn.microsoft.com/en-us/microsoft-copilot-studio/mcp-add-existing-server-to-agent">
                Connect your agent to an existing MCP server
              </Ext>{' '}
              ·{' '}
              <Ext href="https://learn.microsoft.com/en-us/microsoft-copilot-studio/agent-extend-action-mcp">
                MCP in Copilot Studio
              </Ext>
            </p>
          </Step>

          <Step n={5} where="Salesforce Setup" title="Paste the redirect URL into the Salesforce app">
            <ol>
              <li>
                In <strong>External Client App Manager</strong>, open{' '}
                <span className="mono">{SALESFORCE_APP_NAME}</span>, go to the{' '}
                <strong>Settings</strong> tab and click <strong>Edit</strong>.
              </li>
              <li>
                Under <strong>OAuth Settings</strong>, replace the placeholder{' '}
                <strong>Callback URL</strong> with the Redirect URL from step 4, exactly as Copilot
                showed it, and save.
              </li>
              <li>
                Salesforce says changes to an External Client App can take up to 30 minutes to apply.
                Until then, sign-in may fail with <span className="mono">redirect_uri_mismatch</span>.
              </li>
            </ol>
          </Step>

          <Step n={6} where="Copilot Studio" title="Connect, and make each user sign in as themselves">
            <ol>
              <li>
                Back in the wizard, select <strong>Next</strong>. In the <strong>Add tool</strong>{' '}
                dialog, choose <strong>Create a new connection</strong>, sign in to Salesforce, and
                select <strong>Add to agent</strong>.
              </li>
              <li>
                Open the tool from the agent&apos;s <strong>Tools</strong> page. Under{' '}
                <strong>Details → Additional details</strong>, keep <strong>Credentials to use</strong>{' '}
                on <strong>End user credentials</strong> (newer pages call it user authentication).
                With maker-provided credentials every user would act as you, with your
                Profile&apos;s access.
              </li>
              <li>
                Keep the agent&apos;s own sign-in on <strong>Authenticate with Microsoft</strong>{' '}
                (agent <strong>Settings → Security → Authentication</strong>). With{' '}
                <strong>No authentication</strong>, tools cannot use each user&apos;s credentials.
              </li>
              <li>
                The tool&apos;s <strong>Tools</strong> section lists what <em>your</em> Profile
                allows, with a toggle for each. Turn off any the agent should never call (for
                example <span className="mono">delete_record</span>). Each user still gets only what
                their own Profile allows; anything else is denied and logged.
              </li>
            </ol>
            <p className="card-s">
              <Ext href="https://learn.microsoft.com/en-us/microsoft-copilot-studio/mcp-add-components-to-agent">
                Manage the server&apos;s tools
              </Ext>{' '}
              ·{' '}
              <Ext href="https://learn.microsoft.com/en-us/microsoft-copilot-studio/configure-enduser-authentication">
                End-user authentication
              </Ext>
            </p>
          </Step>

          <Step n={7} where="This portal" title="Give users' Profiles access">
            <p>
              The server identifies each caller by their Salesforce Profile. A Profile that is not
              registered and mapped to a group with tools sees no tools at all.
            </p>
            <div className="step-act">
              <button type="button" className="btn sm" onClick={() => onNavigate('sf-profiles')}>
                Profiles
              </button>
              <button type="button" className="btn sm" onClick={() => onNavigate('matrix-groups')}>
                Groups
              </button>
              <button
                type="button"
                className="btn sm"
                onClick={() => onNavigate('matrix-profile-groups')}
              >
                Profile ↔ Group
              </button>
              <button type="button" className="btn sm" onClick={() => onNavigate('sf-objects')}>
                Objects
              </button>
            </div>
          </Step>

          <Step n={8} where="Copilot Studio" title="Test the agent">
            <ol>
              <li>
                Select <strong>Test</strong> to open <strong>Test your agent</strong>, and ask
                something like <em>&ldquo;Show my open opportunities in Salesforce&rdquo;</em>.
              </li>
              <li>
                The agent shows a connection card. Select <strong>Connect</strong>, sign in to
                Salesforce, and select <strong>Allow</strong>; the tool call then retries. The
                activity map shows which tools ran, and <strong>… → Manage connections</strong>{' '}
                resets the test chat&apos;s sign-in.
              </li>
              <li>
                Check <strong>MCP traffic</strong> here: each call shows the verified user, their
                Profile, and whether it was allowed or denied.
              </li>
            </ol>
            <div className="step-act">
              <button type="button" className="btn sm" onClick={() => onNavigate('logs-copilot')}>
                Open MCP traffic
              </button>
            </div>
          </Step>

          <Step n={9} where="Copilot Studio · Microsoft 365 admin" title="Publish to Teams and Microsoft 365 Copilot">
            <ol>
              <li>
                Select <strong>Publish</strong> and confirm. Publish again after every change.
              </li>
              <li>
                Go to <strong>Channels</strong>, select <strong>Teams and Microsoft 365 Copilot</strong>,
                keep <strong>Make agent available in Microsoft 365 Copilot</strong> ticked, and select{' '}
                <strong>Add channel</strong>.{' '}
                <Ext href="https://learn.microsoft.com/en-us/microsoft-copilot-studio/publication-add-bot-to-microsoft-teams">
                  Publish to Teams and Microsoft 365 Copilot
                </Ext>
              </li>
              <li>
                Under <strong>Availability options</strong>, copy a link, show it to your teammates
                and the users you shared the agent with, or select{' '}
                <strong>Show to everyone in my org</strong> to submit it to the org catalog.
              </li>
              <li>
                An admin approves an org catalog submission in the{' '}
                <Ext href="https://admin.microsoft.com/#/agents/all">Microsoft 365 admin center</Ext>{' '}
                (<strong>Agents → All agents → Requests</strong>) or the{' '}
                <Ext href="https://admin.teams.microsoft.com/policies/manage-apps">
                  Teams admin center
                </Ext>{' '}
                (<strong>Teams apps → Manage apps</strong>).{' '}
                <Ext href="https://learn.microsoft.com/en-us/microsoft-agent-365/admin/agent-requests">
                  Agent requests
                </Ext>
              </li>
              <li>
                If users cannot install it, check that Microsoft 365 admin center{' '}
                <strong>Agents → Settings</strong> allows agents built by your organization, and that
                Teams allows custom apps.{' '}
                <Ext href="https://learn.microsoft.com/en-us/troubleshoot/power-platform/copilot-studio/authoring/prevent-agent-install">
                  Why an agent will not install
                </Ext>
              </li>
              <li>
                Each user signs in to Salesforce the first time the agent calls a tool for them. In
                Microsoft 365 Copilot that is <strong>Open Connection Manager → Connect</strong>,
                then <strong>Retry</strong>.
              </li>
            </ol>
          </Step>
        </ol>
      </div>

      <div className="card" style={{ marginTop: 12 }}>
        <div className="card-h">
          <div className="card-t">If something goes wrong</div>
        </div>
        <div className="tbl-wrap">
          <table className="tbl">
            <thead>
              <tr>
                <th>What you see</th>
                <th>Likely cause</th>
                <th>Fix</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>Copilot Studio cannot reach or list the server</td>
                <td>BASE_URL is not public HTTPS, or the tunnel stopped.</td>
                <td>Run the curl check in step 2 from outside your network.</td>
              </tr>
              <tr>
                <td>
                  Salesforce says <span className="mono">redirect_uri_mismatch</span>
                </td>
                <td>
                  The Callback URL does not match Copilot&apos;s Redirect URL exactly, or Salesforce
                  has not applied it yet.
                </td>
                <td>Repeat step 5, then wait up to 30 minutes.</td>
              </tr>
              <tr>
                <td>
                  Salesforce says <span className="mono">invalid_request</span> about a code
                  challenge
                </td>
                <td>The Salesforce app requires PKCE.</td>
                <td>Untick Require PKCE in step 3.</td>
              </tr>
              <tr>
                <td>Users are blocked before the consent screen</td>
                <td>
                  Permitted Users is set to admin approved, and their Profile or permission set is
                  not on the app.
                </td>
                <td>Add them on the app&apos;s Policies tab, or allow self-authorization.</td>
              </tr>
              <tr>
                <td>The agent says it has no Salesforce tools, or every call is denied</td>
                <td>The user&apos;s Profile is not mapped to a group that grants tools.</td>
                <td>
                  <button
                    type="button"
                    className="btn sm"
                    onClick={() => onNavigate('matrix-profile-groups')}
                  >
                    Map Profiles to groups
                  </button>
                </td>
              </tr>
              <tr>
                <td>
                  MCP traffic shows <span className="mono">Unverified Token</span>
                </td>
                <td>
                  The token comes from a different org or host than the MCP token host, or the Org
                  ID lock refused it.
                </td>
                <td>
                  <button
                    type="button"
                    className="btn sm"
                    onClick={() => onNavigate('settings-salesforce')}
                  >
                    Check Org Connection
                  </button>
                </td>
              </tr>
              <tr>
                <td>Users have to sign in again every few hours</td>
                <td>
                  The <span className="mono">refresh_token</span> scope is missing, the Refresh
                  Token Policy expires tokens early, or refresh token rotation is on.
                </td>
                <td>
                  Add the scope on both sides (steps 3 and 4) and review the policy. Some tenants
                  report manual OAuth asking again when the access token expires.
                </td>
              </tr>
              <tr>
                <td>The agent cannot use the tool, or a data policy error appears</td>
                <td>A data policy puts the MCP custom connector in a different group from the channel.</td>
                <td>Classify the connector as Business (step 1).</td>
              </tr>
              <tr>
                <td>You need to change the Client ID or secret later</td>
                <td>Copilot Studio does not reopen the OAuth settings.</td>
                <td>
                  Edit the custom connector&apos;s <strong>Security</strong> tab in Power Apps, and
                  enter the secret again each time you save.
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
