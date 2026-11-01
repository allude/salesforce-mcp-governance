'use client';

import React, { useEffect, useState, useRef } from 'react';
import {
  KeyRound,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  Download,
  Copy,
  Upload,
  RefreshCw,
  BookOpen,
  PlugZap,
  Lock,
  ArrowRight,
  Terminal,
  FileKey,
  Check,
  Unplug,
} from 'lucide-react';
import {
  SalesforceConnectionSettings,
  NavViewId,
} from '@/types/governance';
import { Card, Badge, Switch } from '@/components/ui/primitives';
import {
  connectionStatusBadge,
  generateCertClick,
  generateCertLabel,
  KEY_GENERATED_NOTICE,
  KEY_REPLACED_NOTICE,
  mcpTokenHostWarning,
  REPLACE_KEY_WARNING,
} from './orgConnectionState';

export function SalesforceOrgConnectionView({
  sfSettings,
  apiFetch,
  onRefresh,
  onShowToast,
  onNavigate,
}: {
  sfSettings: SalesforceConnectionSettings;
  apiFetch: <T = any>(url: string, options?: RequestInit) => Promise<T>;
  onRefresh: () => Promise<void>;
  onShowToast: (msg: string, isError?: boolean) => void;
  onNavigate: (view: NavViewId) => void;
}) {
  const [activeTab, setActiveTab] = useState<'connect' | 'guide'>('connect');

  // Connection form state
  const [authMode, setAuthMode] = useState<'jwt_bearer' | 'simulated'>(
    sfSettings.authMode || 'jwt_bearer'
  );
  const [loginUrl, setLoginUrl] = useState(
    sfSettings.loginUrl || 'https://login.salesforce.com'
  );
  const [clientId, setClientId] = useState(sfSettings.clientId || '');
  const [username, setUsername] = useState(sfSettings.username || '');
  const [apiVersion, setApiVersion] = useState(
    sfSettings.apiVersion || 'v62.0'
  );
  const [expectedOrgId, setExpectedOrgId] = useState(
    sfSettings.expectedOrgId || ''
  );
  const [enforceOrgIdLock, setEnforceOrgIdLock] = useState(
    Boolean(sfSettings.enforceOrgIdLock)
  );

  // MCP token host, saved on its own: Connect ignores it, and the main form must not resend a stale value.
  const [mcpTokenHost, setMcpTokenHost] = useState(sfSettings.instanceUrl || '');
  const [mcpTokenHostError, setMcpTokenHostError] = useState('');
  const [savingMcpTokenHost, setSavingMcpTokenHost] = useState(false);

  // Private key & certificate state
  const [showCustomKeyInput, setShowCustomKeyInput] = useState(false);
  const [privateKeyInput, setPrivateKeyInput] = useState('');
  const [certificatePem, setCertificatePem] = useState(
    sfSettings.certificatePem || ''
  );
  const [generatingCert, setGeneratingCert] = useState(false);
  const [confirmReplaceKey, setConfirmReplaceKey] = useState(false);
  const [connecting, setConnecting] = useState(false);
  const [saving, setSaving] = useState(false);
  const [copiedCert, setCopiedCert] = useState(false);

  const keyFileInputRef = useRef<HTMLInputElement | null>(null);
  const certFileInputRef = useRef<HTMLInputElement | null>(null);

  const isConnected = sfSettings.connectionStatus === 'connected';
  const tokenHostWarning = mcpTokenHostWarning(sfSettings);
  const statusBadge = connectionStatusBadge(
    sfSettings.connectionStatus,
    sfSettings.connectedOrgId
  );

  // A click armed on one tab must not count for the other tab's button.
  useEffect(() => {
    setConfirmReplaceKey(false);
  }, [activeTab]);

  // A connect may initialise the host, so the input follows what the server holds.
  useEffect(() => {
    setMcpTokenHost(sfSettings.instanceUrl || '');
    setMcpTokenHostError('');
  }, [sfSettings.instanceUrl]);

  const handleGenerateCertBundle = async () => {
    if (generateCertClick(sfSettings.hasPrivateKey, confirmReplaceKey) === 'arm') {
      setConfirmReplaceKey(true);
      return;
    }
    const replacingKey = sfSettings.hasPrivateKey;
    setConfirmReplaceKey(false);
    setGeneratingCert(true);
    try {
      const res = await apiFetch<{
        sfSettings: SalesforceConnectionSettings;
        certificatePem: string;
        fingerprintSha256: string;
      }>('/api/admin/sf-settings/generate-cert', {
        method: 'POST',
        body: JSON.stringify({
          commonName: 'Salesforce MCP Metadata Sync',
        }),
      });
      setCertificatePem(res.certificatePem);
      setPrivateKeyInput('');
      await onRefresh();
      onShowToast(replacingKey ? KEY_REPLACED_NOTICE : KEY_GENERATED_NOTICE);
    } catch (err: any) {
      onShowToast(err.message, true);
    } finally {
      setGeneratingCert(false);
    }
  };

  const handleDownloadCertificateCrt = () => {
    const pem = certificatePem || sfSettings.certificatePem;
    if (!pem) {
      onShowToast('Generate or upload a certificate first.', true);
      return;
    }
    const blob = new Blob([pem], { type: 'application/x-x509-ca-cert' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'salesforce-mcp-jwt.crt';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    onShowToast('Downloaded salesforce-mcp-jwt.crt');
  };

  const handleCopyCertificatePem = async () => {
    const pem = certificatePem || sfSettings.certificatePem;
    if (!pem) return;
    await navigator.clipboard.writeText(pem);
    setCopiedCert(true);
    setTimeout(() => setCopiedCert(false), 2000);
    onShowToast('Copied X.509 Certificate PEM to clipboard');
  };

  const handlePrivateKeyFileUpload = async (
    e: React.ChangeEvent<HTMLInputElement>
  ) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const text = await file.text();
    setPrivateKeyInput(text);
    e.target.value = '';
    onShowToast(`Loaded private key from ${file.name}`);
  };

  const handleCertFileUpload = async (
    e: React.ChangeEvent<HTMLInputElement>
  ) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const text = await file.text();
    setCertificatePem(text);
    e.target.value = '';
    onShowToast(`Loaded certificate from ${file.name}`);
  };

  const buildPayload = () => ({
    authMode,
    loginUrl: loginUrl.trim(),
    clientId: clientId.trim(),
    username: username.trim(),
    apiVersion: apiVersion.trim() || 'v62.0',
    expectedOrgId: expectedOrgId.trim(),
    enforceOrgIdLock,
    ...(privateKeyInput.trim()
      ? { privateKeyPem: privateKeyInput.trim() }
      : {}),
    ...(certificatePem.trim() ? { certificatePem: certificatePem.trim() } : {}),
  });

  const handleSaveSettingsOnly = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    try {
      const res = await apiFetch<{ sfSettings: SalesforceConnectionSettings }>(
        '/api/admin/sf-settings',
        {
          method: 'PUT',
          body: JSON.stringify(buildPayload()),
        }
      );
      setPrivateKeyInput('');
      await onRefresh();
      onShowToast(
        res.sfSettings.connectionStatus === 'not_verified'
          ? 'Saved. The connection is not verified until you Connect & Verify again.'
          : 'Saved Salesforce Org connection settings'
      );
    } catch (err: any) {
      onShowToast(err.message, true);
    } finally {
      setSaving(false);
    }
  };

  const handleSaveMcpTokenHost = async (e: React.FormEvent) => {
    e.preventDefault();
    setMcpTokenHostError('');
    setSavingMcpTokenHost(true);
    try {
      const res = await apiFetch<{ sfSettings: SalesforceConnectionSettings }>(
        '/api/admin/sf-settings',
        {
          method: 'PUT',
          body: JSON.stringify({ instanceUrl: mcpTokenHost.trim() }),
        }
      );
      // The server keeps only the origin, which may not change the stored value.
      setMcpTokenHost(res.sfSettings.instanceUrl);
      await onRefresh();
      onShowToast('Saved MCP token host');
    } catch (err: any) {
      setMcpTokenHostError(err.message);
    } finally {
      setSavingMcpTokenHost(false);
    }
  };

  const handleConnectAndVerify = async () => {
    setConnecting(true);
    try {
      const res = await apiFetch<{
        connected: boolean;
        sfSettings: SalesforceConnectionSettings;
      }>('/api/admin/sf-settings/connect', {
        method: 'POST',
        body: JSON.stringify(buildPayload()),
      });
      setPrivateKeyInput('');
      await onRefresh();
      onShowToast(
        `Connected to Salesforce Org (${res.sfSettings.connectedOrgId})`
      );
    } catch (err: any) {
      await onRefresh();
      onShowToast(err.message, true);
    } finally {
      setConnecting(false);
    }
  };

  const handleDisconnect = async () => {
    try {
      await apiFetch('/api/admin/sf-settings/disconnect', {
        method: 'POST',
      });
      await onRefresh();
      onShowToast('Disconnected from Salesforce Org');
    } catch (err: any) {
      onShowToast(err.message, true);
    }
  };

  return (
    <div className="space-y-5">
      {/* Top Header & Sub-Navigation Tabs */}
      <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-center">
        <div>
          <div className="flex items-center gap-2.5">
            <h2 className="text-base font-bold text-slate-900">
              Connect to Salesforce Org (JWT Metadata Sync)
            </h2>
            <Badge variant={statusBadge.variant}>{statusBadge.label}</Badge>
          </div>
          <p className="mt-0.5 text-xs text-slate-500">
            Configure an External Connected App with X.509 JWT Certificate authentication to automatically pull Salesforce Profiles, Objects, and Fields without requiring customer record data access.
          </p>
        </div>

        {/* Sub-Tabs */}
        <div className="inline-flex rounded-xl border border-slate-200 bg-white p-1 shadow-2xs">
          <button
            type="button"
            onClick={() => setActiveTab('connect')}
            className={`inline-flex items-center gap-1.5 rounded-lg px-3.5 py-1.5 text-xs font-bold transition ${
              activeTab === 'connect'
                ? 'bg-indigo-600 text-white'
                : 'text-slate-600 hover:bg-slate-50 hover:text-slate-900'
            }`}
          >
            <PlugZap className="h-3.5 w-3.5" />
            <span>1. Connection &amp; JWT Credentials</span>
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('guide')}
            className={`inline-flex items-center gap-1.5 rounded-lg px-3.5 py-1.5 text-xs font-bold transition ${
              activeTab === 'guide'
                ? 'bg-indigo-600 text-white'
                : 'text-slate-600 hover:bg-slate-50 hover:text-slate-900'
            }`}
          >
            <BookOpen className="h-3.5 w-3.5" />
            <span>2. Setup Guide &amp; Required Permissions</span>
          </button>
        </div>
      </div>

      {/* Live Connection Status Banner */}
      {isConnected && (
        <Card className="border-emerald-200 bg-emerald-50/60 p-4">
          <div className="flex flex-col justify-between gap-3 sm:flex-row sm:items-center">
            <div className="flex items-start gap-3">
              <div className="mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-emerald-600 text-white">
                <CheckCircle2 className="h-4 w-4" />
              </div>
              <div className="text-xs">
                <div className="font-bold text-emerald-950">
                  Connected to Salesforce Org via{' '}
                  {sfSettings.authMode === 'simulated'
                    ? 'JWT Bearer (Simulated Org Mode)'
                    : 'External Connected App (JWT Bearer)'}
                </div>
                <div className="mt-0.5 flex flex-wrap items-center gap-x-4 gap-y-1 font-mono text-[11px] text-emerald-800">
                  <span>Org ID: {sfSettings.connectedOrgId}</span>
                  <span>Instance: {sfSettings.syncInstanceUrl}</span>
                  <span>MCP token host: {sfSettings.instanceUrl}</span>
                  <span>User: {sfSettings.connectedUser}</span>
                  {sfSettings.lastConnectedAt && (
                    <span>
                      Verified:{' '}
                      {new Date(sfSettings.lastConnectedAt).toLocaleString()}
                    </span>
                  )}
                </div>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={() => onNavigate('sf-profiles')}
                className="inline-flex items-center gap-1.5 rounded-lg bg-white px-3 py-1.5 text-xs font-semibold text-emerald-900 shadow-2xs ring-1 ring-emerald-300 transition hover:bg-emerald-100/50"
              >
                <span>Pull Profiles</span>
                <ArrowRight className="h-3.5 w-3.5" />
              </button>
              <button
                type="button"
                onClick={() => onNavigate('sf-objects')}
                className="inline-flex items-center gap-1.5 rounded-lg bg-emerald-700 px-3 py-1.5 text-xs font-semibold text-white shadow-2xs transition hover:bg-emerald-800"
              >
                <span>Pull Objects &amp; Fields</span>
                <ArrowRight className="h-3.5 w-3.5" />
              </button>
              <button
                type="button"
                onClick={handleDisconnect}
                className="inline-flex items-center gap-1 rounded-lg border border-emerald-300 bg-white px-2.5 py-1.5 text-xs font-semibold text-slate-600 hover:bg-rose-50 hover:text-rose-600"
                title="Disconnect Org"
              >
                <Unplug className="h-3.5 w-3.5" />
                <span>Disconnect</span>
              </button>
            </div>
          </div>
        </Card>
      )}

      {!isConnected && (
        <p className="font-mono text-[11px] text-slate-600">
          MCP token host: {sfSettings.instanceUrl}
        </p>
      )}

      {tokenHostWarning && (
        <Card className="border-amber-200 bg-amber-50/70 p-4">
          <div className="flex items-start gap-2.5 text-xs text-amber-900">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-600" />
            <div>
              <div className="font-bold">Check the MCP Token Host</div>
              <div className="mt-0.5 text-[11px]">{tokenHostWarning}</div>
            </div>
          </div>
        </Card>
      )}

      {sfSettings.connectionStatus === 'not_verified' && (
        <Card className="border-amber-200 bg-amber-50/70 p-4">
          <div className="flex items-start gap-2.5 text-xs text-amber-900">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-600" />
            <div>
              <div className="font-bold">Connection Not Verified</div>
              <div className="mt-0.5 text-[11px]">
                The key or connection settings changed after the last connection. Pulling from the org is off until you Connect &amp; Verify. If the key changed, upload the new certificate to the Connected App first.
              </div>
            </div>
          </div>
        </Card>
      )}

      {sfSettings.connectionStatus === 'error' && sfSettings.lastError && (
        <Card className="border-rose-200 bg-rose-50/70 p-4">
          <div className="flex items-start gap-2.5 text-xs text-rose-800">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-rose-600" />
            <div>
              <div className="font-bold">Last Connection Attempt Failed</div>
              <div className="mt-0.5 font-mono text-[11px]">
                {sfSettings.lastError}
              </div>
            </div>
          </div>
        </Card>
      )}

      {/* ===================================================================
          TAB 1: CONNECTION & JWT CREDENTIALS
         =================================================================== */}
      {activeTab === 'connect' && (
        <div className="grid grid-cols-1 gap-5 lg:grid-cols-12">
          {/* Left Column: X.509 Certificate & RSA Private Key Management */}
          <Card className="p-5 lg:col-span-5">
            <div className="flex items-center justify-between border-b border-slate-100 pb-3">
              <div className="flex items-center gap-2">
                <FileKey className="h-4 w-4 text-indigo-600" />
                <h3 className="text-sm font-bold text-slate-900">
                  Step 1: X.509 Certificate &amp; Private Key
                </h3>
              </div>
              <Badge variant={sfSettings.hasPrivateKey ? 'emerald' : 'amber'}>
                {sfSettings.hasPrivateKey
                  ? 'Private Key Stored (AES-256)'
                  : 'No Key Configured'}
              </Badge>
            </div>

            <p className="mt-2.5 text-xs text-slate-600">
              Salesforce JWT Bearer authentication requires an{' '}
              <strong>X.509 digital certificate (`.crt`)</strong> uploaded to
              your Salesforce Connected App and the matching{' '}
              <strong>RSA Private Key</strong> stored on this MCP server to sign
              JWT assertions (`RS256`).
            </p>

            {/* Option A: One-Click Generate in Portal */}
            <div className="mt-4 rounded-xl border border-indigo-100 bg-indigo-50/50 p-3.5">
              <div className="text-xs font-bold text-indigo-950">
                Recommended: Generate Keypair &amp; Certificate Here
              </div>
              <p className="mt-0.5 text-[11px] text-indigo-800">
                Generates a 2048-bit RSA Private Key (encrypted at rest in SQLite) and a self-signed X.509 `.crt` certificate you can download and upload directly to Salesforce.
              </p>

              <div className="mt-3 flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  disabled={generatingCert}
                  onClick={handleGenerateCertBundle}
                  onBlur={() => setConfirmReplaceKey(false)}
                  className="inline-flex items-center gap-1.5 rounded-lg bg-indigo-600 px-3 py-1.5 text-xs font-semibold text-white shadow-2xs transition hover:bg-indigo-700 disabled:opacity-50"
                >
                  <RefreshCw
                    className={`h-3.5 w-3.5 ${
                      generatingCert ? 'animate-spin' : ''
                    }`}
                  />
                  <span>
                    {generateCertLabel(
                      sfSettings.hasPrivateKey,
                      confirmReplaceKey,
                      sfSettings.hasPrivateKey
                        ? 'Regenerate Certificate & Key'
                        : 'Generate X.509 Certificate & Key'
                    )}
                  </span>
                </button>

                {(certificatePem || sfSettings.certificatePem) && (
                  <>
                    <button
                      type="button"
                      onClick={handleDownloadCertificateCrt}
                      className="inline-flex items-center gap-1.5 rounded-lg border border-indigo-200 bg-white px-3 py-1.5 text-xs font-semibold text-indigo-700 hover:bg-indigo-50"
                    >
                      <Download className="h-3.5 w-3.5" />
                      <span>Download `.crt` for Salesforce</span>
                    </button>

                    <button
                      type="button"
                      onClick={handleCopyCertificatePem}
                      className="inline-flex items-center gap-1 rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-xs font-semibold text-slate-700 hover:bg-slate-50"
                    >
                      {copiedCert ? (
                        <Check className="h-3.5 w-3.5 text-emerald-600" />
                      ) : (
                        <Copy className="h-3.5 w-3.5" />
                      )}
                      <span>{copiedCert ? 'Copied' : 'Copy PEM'}</span>
                    </button>
                  </>
                )}
              </div>

              {confirmReplaceKey && (
                <p role="alert" className="mt-2 text-[11px] font-semibold text-amber-800">
                  {REPLACE_KEY_WARNING}
                </p>
              )}

              {sfSettings.certFingerprint && (
                <div className="mt-3 rounded-lg bg-white/90 px-3 py-2 font-mono text-[10px] text-slate-600 ring-1 ring-indigo-100">
                  <div className="font-bold text-slate-700">
                    Active Certificate SHA-256 Fingerprint:
                  </div>
                  <div className="mt-0.5 break-all text-indigo-700">
                    {sfSettings.certFingerprint}
                  </div>
                </div>
              )}
            </div>

            {/* Option B: Upload or Paste Existing PEM Private Key */}
            <div className="mt-4 border-t border-slate-100 pt-3.5">
              <button
                type="button"
                onClick={() => setShowCustomKeyInput(!showCustomKeyInput)}
                className="flex w-full items-center justify-between text-left text-xs font-semibold text-slate-700 hover:text-indigo-600"
              >
                <span>
                  Or upload / paste your own existing RSA Private Key (`.key` / `.pem`)
                </span>
                <span className="font-mono text-[11px] text-indigo-600">
                  {showCustomKeyInput ? 'Hide ▲' : 'Expand ▼'}
                </span>
              </button>

              {showCustomKeyInput && (
                <div className="mt-3 space-y-3">
                  <div>
                    <div className="flex items-center justify-between">
                      <label className="block text-xs font-semibold text-slate-700">
                        RSA Private Key PEM (`-----BEGIN PRIVATE KEY-----`)
                      </label>
                      <input
                        ref={keyFileInputRef}
                        type="file"
                        accept=".key,.pem,text/plain"
                        onChange={handlePrivateKeyFileUpload}
                        className="hidden"
                      />
                      <button
                        type="button"
                        onClick={() => keyFileInputRef.current?.click()}
                        className="inline-flex items-center gap-1 text-[11px] font-semibold text-indigo-600 hover:underline"
                      >
                        <Upload className="h-3 w-3" />
                        <span>Upload `.key` / `.pem`</span>
                      </button>
                    </div>
                    <textarea
                      rows={4}
                      value={privateKeyInput}
                      onChange={(e) => setPrivateKeyInput(e.target.value)}
                      placeholder={
                        sfSettings.hasPrivateKey
                          ? '•••••••• (Encrypted Private Key is already saved. Paste a new PEM here to replace it.)'
                          : '-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQE...\n-----END PRIVATE KEY-----'
                      }
                      className="mt-1 w-full rounded-lg border border-slate-200 bg-slate-50 p-2.5 font-mono text-[11px] text-slate-900 focus:border-indigo-500 focus:bg-white focus:outline-none"
                    />
                  </div>

                  <div>
                    <div className="flex items-center justify-between">
                      <label className="block text-xs font-semibold text-slate-700">
                        Public Certificate PEM (Optional — for downloading `.crt`)
                      </label>
                      <input
                        ref={certFileInputRef}
                        type="file"
                        accept=".crt,.cer,.pem,text/plain"
                        onChange={handleCertFileUpload}
                        className="hidden"
                      />
                      <button
                        type="button"
                        onClick={() => certFileInputRef.current?.click()}
                        className="inline-flex items-center gap-1 text-[11px] font-semibold text-indigo-600 hover:underline"
                      >
                        <Upload className="h-3 w-3" />
                        <span>Upload `.crt`</span>
                      </button>
                    </div>
                    <textarea
                      rows={3}
                      value={certificatePem}
                      onChange={(e) => setCertificatePem(e.target.value)}
                      placeholder="-----BEGIN CERTIFICATE-----..."
                      className="mt-1 w-full rounded-lg border border-slate-200 bg-slate-50 p-2.5 font-mono text-[11px] text-slate-900 focus:border-indigo-500 focus:bg-white focus:outline-none"
                    />
                  </div>
                </div>
              )}
            </div>
          </Card>

          {/* Right Column: Connected App & Integration User Form */}
          <Card className="p-5 lg:col-span-7">
            <form onSubmit={handleSaveSettingsOnly} className="space-y-4">
              <div className="flex items-center justify-between border-b border-slate-100 pb-3">
                <div className="flex items-center gap-2">
                  <KeyRound className="h-4 w-4 text-indigo-600" />
                  <div>
                    <h3 className="text-sm font-bold text-slate-900">
                      Step 2: Connected App &amp; Salesforce Org Credentials
                    </h3>
                    <p className="text-[11px] text-slate-500">
                      Enter the Consumer Key (`Client ID`) and Integration Username from your Salesforce External Connected App.
                    </p>
                  </div>
                </div>

                <button
                  type="button"
                  onClick={() => setActiveTab('guide')}
                  className="text-xs font-semibold text-indigo-600 hover:underline"
                >
                  View Setup Guide →
                </button>
              </div>

              {/* Connection Mode Selector */}
              <div>
                <label className="block text-xs font-semibold text-slate-700">
                  Connection Mode
                </label>
                <div className="mt-1.5 grid grid-cols-1 gap-2.5 sm:grid-cols-2">
                  <button
                    type="button"
                    onClick={() => setAuthMode('jwt_bearer')}
                    className={`flex flex-col items-start rounded-xl border p-3 text-left text-xs transition ${
                      authMode === 'jwt_bearer'
                        ? 'border-indigo-300 bg-indigo-50/60 ring-1 ring-indigo-300'
                        : 'border-slate-200 bg-white hover:bg-slate-50'
                    }`}
                  >
                    <span className="font-bold text-slate-900">
                      Live Salesforce Org (JWT Bearer)
                    </span>
                    <span className="mt-0.5 text-[11px] text-slate-500">
                      Authenticates against `login.salesforce.com`, `test.salesforce.com`, or your My Domain URL.
                    </span>
                  </button>

                  <button
                    type="button"
                    onClick={() => {
                      setAuthMode('simulated');
                      if (!clientId)
                        setClientId('3MVG9_EXTERNAL_CONNECTED_APP_JWT');
                      if (!username)
                        setUsername(
                          'mcp-metadata-sync@enterprise.my.salesforce.com'
                        );
                    }}
                    className={`flex flex-col items-start rounded-xl border p-3 text-left text-xs transition ${
                      authMode === 'simulated'
                        ? 'border-indigo-300 bg-indigo-50/60 ring-1 ring-indigo-300'
                        : 'border-slate-200 bg-white hover:bg-slate-50'
                    }`}
                  >
                    <span className="font-bold text-slate-900">
                      Simulated Salesforce Org (Local Testing)
                    </span>
                    <span className="mt-0.5 text-[11px] text-slate-500">
                      Verifies your RSA JWT signature locally &amp; connects to a built-in mock org to test pulling &amp; removal diffs.
                    </span>
                  </button>
                </div>
              </div>

              {/* Environment / Login URL & API Version */}
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
                <div className="sm:col-span-2">
                  <label className="block text-xs font-semibold text-slate-700">
                    Salesforce Login / My Domain URL (`aud` claim)
                  </label>
                  <div className="mt-1 flex gap-1.5">
                    <input
                      type="text"
                      required
                      value={loginUrl}
                      onChange={(e) => setLoginUrl(e.target.value)}
                      placeholder="https://login.salesforce.com"
                      className="w-full rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5 font-mono text-xs text-slate-900 focus:border-indigo-500 focus:bg-white focus:outline-none"
                    />
                  </div>
                  <div className="mt-1 flex gap-2 text-[10px]">
                    <button
                      type="button"
                      onClick={() => setLoginUrl('https://login.salesforce.com')}
                      className="font-semibold text-indigo-600 hover:underline"
                    >
                      Production (`login.salesforce.com`)
                    </button>
                    <span className="text-slate-300">•</span>
                    <button
                      type="button"
                      onClick={() => setLoginUrl('https://test.salesforce.com')}
                      className="font-semibold text-indigo-600 hover:underline"
                    >
                      Sandbox (`test.salesforce.com`)
                    </button>
                  </div>
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-700">
                    REST API Version
                  </label>
                  <input
                    type="text"
                    value={apiVersion}
                    onChange={(e) => setApiVersion(e.target.value)}
                    placeholder="v62.0"
                    className="mt-1 w-full rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5 font-mono text-xs text-slate-900 focus:border-indigo-500 focus:bg-white focus:outline-none"
                  />
                </div>
              </div>

              {/* Consumer Key (Client ID) & Integration Username */}
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                <div>
                  <label className="block text-xs font-semibold text-slate-700">
                    Connected App Consumer Key / Client ID (`iss` claim)
                  </label>
                  <input
                    type="text"
                    required={authMode === 'jwt_bearer'}
                    value={clientId}
                    onChange={(e) => setClientId(e.target.value)}
                    placeholder="3MVG9..."
                    className="mt-1 w-full rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5 font-mono text-xs text-slate-900 focus:border-indigo-500 focus:bg-white focus:outline-none"
                  />
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-700">
                    Salesforce Integration Username (`sub` claim)
                  </label>
                  <input
                    type="text"
                    required={authMode === 'jwt_bearer'}
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    placeholder="mcp-metadata-sync@yourcompany.com"
                    className="mt-1 w-full rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5 font-mono text-xs text-slate-900 focus:border-indigo-500 focus:bg-white focus:outline-none"
                  />
                </div>
              </div>

              {/* Optional Org ID Lock */}
              <div className="rounded-xl border border-slate-200/80 bg-slate-50/50 p-3">
                <div className="flex items-center justify-between">
                  <div>
                    <div className="flex items-center gap-1.5 text-xs font-bold text-slate-800">
                      <Lock className="h-3.5 w-3.5 text-indigo-600" />
                      <span>Enforce Salesforce Org ID Lock (Optional)</span>
                    </div>
                    <p className="text-[11px] text-slate-500">
                      If enabled, rejects connections unless the Salesforce `organization_id` matches the Expected Org ID below.
                    </p>
                  </div>
                  <Switch
                    checked={enforceOrgIdLock}
                    onCheckedChange={setEnforceOrgIdLock}
                  />
                </div>

                {enforceOrgIdLock && (
                  <div className="mt-2.5">
                    <input
                      type="text"
                      value={expectedOrgId}
                      onChange={(e) => setExpectedOrgId(e.target.value)}
                      placeholder="Expected 15 or 18-char Salesforce Org ID (e.g. 00D8b000002MCPORG)"
                      className="w-full rounded-lg border border-slate-200 bg-white px-3 py-1.5 font-mono text-xs text-slate-900 focus:border-indigo-500 focus:outline-none"
                    />
                  </div>
                )}
              </div>

              {/* Action Buttons */}
              <div className="flex flex-wrap items-center justify-between gap-3 border-t border-slate-100 pt-3">
                <button
                  type="submit"
                  disabled={saving}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3.5 py-2 text-xs font-semibold text-slate-700 hover:bg-slate-50 disabled:opacity-50"
                >
                  <span>{saving ? 'Saving...' : 'Save Draft Settings'}</span>
                </button>

                <button
                  type="button"
                  disabled={connecting}
                  onClick={handleConnectAndVerify}
                  className="inline-flex items-center gap-2 rounded-lg bg-indigo-600 px-4 py-2 text-xs font-bold text-white shadow-xs transition hover:bg-indigo-700 disabled:opacity-50"
                >
                  <PlugZap className="h-4 w-4" />
                  <span>
                    {connecting
                      ? 'Verifying JWT Handshake...'
                      : 'Connect & Verify Salesforce Org'}
                  </span>
                </button>
              </div>
            </form>

            {/* MCP Token Host: a separate form, so Enter here cannot submit the connection settings */}
            <form
              onSubmit={handleSaveMcpTokenHost}
              className="mt-4 border-t border-slate-100 pt-4"
            >
              <label
                htmlFor="mcp-token-host"
                className="block text-xs font-semibold text-slate-700"
              >
                MCP token host
              </label>
              <p className="text-[11px] text-slate-500">
                Where MCP verifies users&apos; Salesforce tokens, and the authorization server it advertises to clients. A successful live connect replaces this only while it is `login.salesforce.com` or `test.salesforce.com`, so set your My Domain URL to keep it fixed.
              </p>
              <div className="mt-1 flex gap-2">
                <input
                  id="mcp-token-host"
                  type="text"
                  value={mcpTokenHost}
                  onChange={(e) => {
                    setMcpTokenHost(e.target.value);
                    setMcpTokenHostError('');
                  }}
                  placeholder="https://yourcompany.my.salesforce.com"
                  aria-invalid={Boolean(mcpTokenHostError)}
                  aria-describedby={mcpTokenHostError ? 'mcp-token-host-error' : undefined}
                  className="w-full rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5 font-mono text-xs text-slate-900 focus:border-indigo-500 focus:bg-white focus:outline-none"
                />
                <button
                  type="submit"
                  disabled={savingMcpTokenHost}
                  className="shrink-0 rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-semibold text-slate-700 hover:bg-slate-50 disabled:opacity-50"
                >
                  {savingMcpTokenHost ? 'Saving...' : 'Save Host'}
                </button>
              </div>
              {mcpTokenHostError && (
                <p
                  id="mcp-token-host-error"
                  role="alert"
                  className="mt-1 text-[11px] font-semibold text-rose-700"
                >
                  {mcpTokenHostError}
                </p>
              )}
            </form>
          </Card>
        </div>
      )}

      {/* ===================================================================
          TAB 2: SETUP GUIDE — EXTERNAL CONNECTED APP WITH JWT & PERMISSIONS
         =================================================================== */}
      {activeTab === 'guide' && (
        <div className="space-y-5">
          {/* Zero Record Data Architectural Callout */}
          <Card className="border-indigo-200 bg-indigo-50/50 p-5">
            <div className="flex items-start gap-3">
              <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-indigo-600 text-white">
                <ShieldCheck className="h-5 w-5" />
              </div>
              <div className="space-y-1 text-xs">
                <h3 className="text-sm font-bold text-indigo-950">
                  Zero-Trust Principle: Metadata-Only Access (No Customer Record Data Needed)
                </h3>
                <p className="text-indigo-900 leading-relaxed">
                  This Salesforce connection is used <strong>exclusively by the Admin Control Plane</strong> to pull{' '}
                  <strong>Profile Metadata</strong> (`SELECT Id, Name, UserType FROM Profile`) and{' '}
                  <strong>Object &amp; Field Schema Definitions</strong> (`EntityDefinition`, `FieldDefinition`, and `SObject Describe`).
                  It <strong>never</strong> queries or mutates business records (`Account`, `Contact`, `Opportunity`, `Case`, etc.).
                  When users invoke MCP tools from Microsoft Copilot at runtime, the MCP Server executes requests using each caller&apos;s own scoped token—never this metadata sync connection.
                </p>
              </div>
            </div>
          </Card>

          <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
            {/* Step 1 & Step 2 */}
            <Card className="p-5 space-y-4">
              <div>
                <Badge variant="indigo">Step 1</Badge>
                <h3 className="mt-1.5 text-sm font-bold text-slate-900">
                  Generate Your X.509 Certificate (`.crt`)
                </h3>
                <p className="mt-1 text-xs text-slate-600">
                  The OAuth 2.0 JWT Bearer flow uses an asymmetric RSA 2048-bit keypair. You upload the public certificate (`salesforce-mcp-jwt.crt`) to Salesforce, while this server signs short-lived JWT assertions with the private key.
                </p>
                <div className="mt-3 flex flex-wrap gap-2">
                  <button
                    type="button"
                    disabled={generatingCert}
                    onClick={handleGenerateCertBundle}
                    onBlur={() => setConfirmReplaceKey(false)}
                    className="inline-flex items-center gap-1.5 rounded-lg bg-indigo-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-indigo-700 disabled:opacity-50"
                  >
                    <FileKey className="h-3.5 w-3.5" />
                    <span>
                      {generateCertLabel(
                        sfSettings.hasPrivateKey,
                        confirmReplaceKey,
                        sfSettings.hasPrivateKey
                          ? 'Regenerate Cert & Key'
                          : '1-Click Generate Cert & Key'
                      )}
                    </span>
                  </button>
                  {(certificatePem || sfSettings.certificatePem) && (
                    <button
                      type="button"
                      onClick={handleDownloadCertificateCrt}
                      className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-semibold text-slate-700 hover:bg-slate-50"
                    >
                      <Download className="h-3.5 w-3.5 text-indigo-600" />
                      <span>Download `salesforce-mcp-jwt.crt`</span>
                    </button>
                  )}
                </div>
                {confirmReplaceKey && (
                  <p role="alert" className="mt-2 text-[11px] font-semibold text-amber-800">
                    {REPLACE_KEY_WARNING}
                  </p>
                )}
                <div className="mt-3 rounded-lg bg-slate-900 p-3 font-mono text-[11px] text-slate-200">
                  <div className="text-slate-400">
                    # Optional: If generating via OpenSSL CLI instead:
                  </div>
                  <div>
                    openssl req -x509 -sha256 -nodes -days 730 -newkey rsa:2048 \
                  </div>
                  <div>
                    &nbsp;&nbsp;-keyout server.key -out salesforce-mcp-jwt.crt
                  </div>
                </div>
              </div>

              <div className="border-t border-slate-100 pt-4">
                <Badge variant="indigo">Step 2</Badge>
                <h3 className="mt-1.5 text-sm font-bold text-slate-900">
                  Create the External Connected App in Salesforce
                </h3>
                <ol className="mt-2 list-decimal space-y-2 pl-4 text-xs text-slate-700">
                  <li>
                    In Salesforce Setup, navigate to{' '}
                    <strong>App Manager &gt; New Connected App</strong> (or{' '}
                    <strong>External Client App Manager</strong>).
                  </li>
                  <li>
                    Name it <code className="font-mono font-semibold">Salesforce MCP Metadata Sync</code> and check{' '}
                    <strong>Enable OAuth Settings</strong>.
                  </li>
                  <li>
                    Set <strong>Callback URL</strong> to{' '}
                    <code className="rounded bg-slate-100 px-1.5 py-0.5 font-mono">
                      http://localhost:1717/OauthRedirect
                    </code>{' '}
                    (required by Salesforce UI, though unused by headless JWT flow).
                  </li>
                  <li>
                    Check <strong>Use digital signatures</strong> and upload the{' '}
                    <code className="font-mono font-semibold">salesforce-mcp-jwt.crt</code> file from Step 1.
                  </li>
                  <li>
                    Under <strong>Selected OAuth Scopes</strong>, add only:
                    <ul className="mt-1 list-disc pl-5 font-mono text-[11px] text-indigo-900">
                      <li>Manage user data via APIs (api)</li>
                      <li>Perform requests at any time (refresh_token, offline_access)</li>
                    </ul>
                  </li>
                  <li>
                    Save the Connected App, then click{' '}
                    <strong>Manage &gt; Edit Policies</strong>:
                    <ul className="mt-1 list-disc pl-5 text-[11px] text-slate-600">
                      <li>
                        Set <strong>Permitted Users</strong> to{' '}
                        <strong className="text-slate-900">
                          Admin approved users are pre-authorized
                        </strong>
                        .
                      </li>
                    </ul>
                  </li>
                </ol>
              </div>
            </Card>

            {/* Step 3 & Step 4: Least-Privilege Metadata Permissions */}
            <Card className="p-5 space-y-4">
              <div>
                <Badge variant="emerald">Step 3 • Least Privilege</Badge>
                <h3 className="mt-1.5 text-sm font-bold text-slate-900">
                  Configure Permission Set (Metadata Only — Zero Record Access)
                </h3>
                <p className="mt-1 text-xs text-slate-600">
                  Create a dedicated Integration User (recommended license:{' '}
                  <strong>Salesforce Integration</strong> with profile{' '}
                  <code className="font-mono">Salesforce API Only System Integrations</code>) and assign a Permission Set named{' '}
                  <code className="font-mono font-semibold">MCP_Metadata_Schema_Reader</code> with the following exact settings:
                </p>

                <div className="mt-3 overflow-hidden rounded-xl border border-slate-200">
                  <table className="w-full border-collapse text-left text-xs">
                    <thead>
                      <tr className="border-b border-slate-200 bg-slate-50 text-[10px] font-bold tracking-wider text-slate-500 uppercase">
                        <th className="py-2 pr-2 pl-3">Permission Setting</th>
                        <th className="px-2 py-2">Required Value</th>
                        <th className="py-2 pr-3 pl-2">Why It Is Needed</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100 text-[11px]">
                      <tr>
                        <td className="py-2 pr-2 pl-3 font-mono font-bold text-slate-900">
                          API Enabled
                        </td>
                        <td className="px-2 py-2">
                          <Badge variant="emerald">Enabled (ON)</Badge>
                        </td>
                        <td className="py-2 pr-3 pl-2 text-slate-600">
                          Allows calling Salesforce REST &amp; Tooling APIs.
                        </td>
                      </tr>
                      <tr>
                        <td className="py-2 pr-2 pl-3 font-mono font-bold text-slate-900">
                          View Setup and Configuration
                        </td>
                        <td className="px-2 py-2">
                          <Badge variant="emerald">Enabled (ON)</Badge>
                        </td>
                        <td className="py-2 pr-3 pl-2 text-slate-600">
                          Allows querying <code className="font-mono">Profile</code>,{' '}
                          <code className="font-mono">EntityDefinition</code>, and{' '}
                          <code className="font-mono">FieldDefinition</code> metadata without record access.
                        </td>
                      </tr>
                      <tr className="bg-slate-50/60">
                        <td className="py-2 pr-2 pl-3 font-mono font-bold text-slate-900">
                          Object CRUD (Read / Create / Edit / Delete)
                        </td>
                        <td className="px-2 py-2">
                          <Badge variant="slate">None (ALL OFF)</Badge>
                        </td>
                        <td className="py-2 pr-3 pl-2 text-slate-600">
                          <strong>Not required.</strong> Our sync engine falls back to Tooling <code className="font-mono">EntityDefinition</code> &amp; <code className="font-mono">FieldDefinition</code> so 0 CRM records are visible.
                        </td>
                      </tr>
                      <tr className="bg-slate-50/60">
                        <td className="py-2 pr-2 pl-3 font-mono font-bold text-slate-900">
                          View All / Modify All Data
                        </td>
                        <td className="px-2 py-2">
                          <Badge variant="rose">Disabled (OFF)</Badge>
                        </td>
                        <td className="py-2 pr-3 pl-2 text-slate-600">
                          Never grant <code className="font-mono">View All Data</code> or <code className="font-mono">Modify All Data</code> to the metadata sync user.
                        </td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              </div>

              <div className="border-t border-slate-100 pt-4">
                <Badge variant="indigo">Step 4</Badge>
                <h3 className="mt-1.5 text-sm font-bold text-slate-900">
                  Pre-Authorize &amp; Pull Metadata Automatically
                </h3>
                <ol className="mt-2 list-decimal space-y-1.5 pl-4 text-xs text-slate-700">
                  <li>
                    On the Connected App&apos;s <strong>Manage</strong> page, scroll to{' '}
                    <strong>Permission Sets</strong> (or <strong>Profiles</strong>) and add{' '}
                    <code className="font-mono font-semibold">MCP_Metadata_Schema_Reader</code>.
                  </li>
                  <li>
                    Copy the Connected App&apos;s <strong>Consumer Key</strong> (`Client ID`) and paste it into Tab 1 along with the Integration Username.
                  </li>
                  <li>
                    Click <strong>Connect &amp; Verify Salesforce Org</strong>, then visit{' '}
                    <button
                      type="button"
                      onClick={() => onNavigate('sf-profiles')}
                      className="font-semibold text-indigo-600 underline"
                    >
                      Salesforce &gt; Profiles
                    </button>{' '}
                    and{' '}
                    <button
                      type="button"
                      onClick={() => onNavigate('sf-objects')}
                      className="font-semibold text-indigo-600 underline"
                    >
                      Salesforce &gt; Objects
                    </button>{' '}
                    to pull metadata and reconcile any removed fields, objects, or profiles.
                  </li>
                </ol>
              </div>
            </Card>
          </div>
        </div>
      )}
    </div>
  );
}
