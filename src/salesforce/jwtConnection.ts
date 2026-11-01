import crypto from 'node:crypto';
import { config } from '../config.js';
import { validateSalesforceInstanceUrl, escapeSoqlString } from './client.js';

export interface GeneratedCertBundle {
  privateKeyPem: string;
  certificatePem: string;
  fingerprintSha256: string;
  subject: string;
  validFrom: string;
  validTo: string;
}

/**
 * ASN.1 DER encoding helpers for generating a standard self-signed X.509 v3 certificate
 * using pure Node.js `node:crypto` without external OpenSSL CLI dependencies.
 */
function encodeDerLength(len: number): Buffer {
  if (len < 128) return Buffer.from([len]);
  const bytes: number[] = [];
  let temp = len;
  while (temp > 0) {
    bytes.unshift(temp & 0xff);
    temp >>= 8;
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function derTag(tag: number, content: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag]), encodeDerLength(content.length), content]);
}

function derSequence(items: Buffer[]): Buffer {
  return derTag(0x30, Buffer.concat(items));
}

function derSet(items: Buffer[]): Buffer {
  return derTag(0x31, Buffer.concat(items));
}

function derInteger(buf: Buffer): Buffer {
  // Ensure positive integer in two's complement DER
  const needsLeadingZero = buf.length > 0 && (buf[0] & 0x80) !== 0;
  const content = needsLeadingZero ? Buffer.concat([Buffer.from([0x00]), buf]) : buf;
  return derTag(0x02, content);
}

function derBitString(buf: Buffer): Buffer {
  // 0x00 unused bits prefix
  return derTag(0x03, Buffer.concat([Buffer.from([0x00]), buf]));
}

function derOid(oidNums: number[]): Buffer {
  const bytes: number[] = [40 * oidNums[0] + oidNums[1]];
  for (let i = 2; i < oidNums.length; i++) {
    let val = oidNums[i];
    if (val === 0) {
      bytes.push(0);
      continue;
    }
    const sub: number[] = [];
    while (val > 0) {
      sub.unshift(val & 0x7f);
      val >>= 7;
    }
    for (let j = 0; j < sub.length - 1; j++) {
      sub[j] |= 0x80;
    }
    bytes.push(...sub);
  }
  return derTag(0x06, Buffer.from(bytes));
}

function derUtf8String(str: string): Buffer {
  return derTag(0x0c, Buffer.from(str, 'utf8'));
}

function derPrintableString(str: string): Buffer {
  return derTag(0x13, Buffer.from(str, 'ascii'));
}

function derUtcTime(date: Date): Buffer {
  const yy = String(date.getUTCFullYear() % 100).padStart(2, '0');
  const mm = String(date.getUTCMonth() + 1).padStart(2, '0');
  const dd = String(date.getUTCDate()).padStart(2, '0');
  const hh = String(date.getUTCHours()).padStart(2, '0');
  const min = String(date.getUTCMinutes()).padStart(2, '0');
  const ss = String(date.getUTCSeconds()).padStart(2, '0');
  return derTag(0x17, Buffer.from(`${yy}${mm}${dd}${hh}${min}${ss}Z`, 'ascii'));
}

function buildX509Name(commonName: string, orgName: string): Buffer {
  // Country = US (2.5.4.6), Org = orgName (2.5.4.10), CN = commonName (2.5.4.3)
  const rdnCountry = derSet([
    derSequence([derOid([2, 5, 4, 6]), derPrintableString('US')]),
  ]);
  const rdnOrg = derSet([
    derSequence([derOid([2, 5, 4, 10]), derUtf8String(orgName)]),
  ]);
  const rdnCn = derSet([
    derSequence([derOid([2, 5, 4, 3]), derUtf8String(commonName)]),
  ]);
  return derSequence([rdnCountry, rdnOrg, rdnCn]);
}

/**
 * Generates a 2048-bit RSA Private Key and a self-signed X.509 Certificate (`.crt` PEM)
 * suitable for uploading to a Salesforce Connected App / External Client App ("Use digital signatures").
 */
export function generateSelfSignedCertificateBundle(
  commonName = 'Salesforce MCP Metadata Sync',
  orgName = 'Salesforce MCP Governance Server',
  validDays = 730
): GeneratedCertBundle {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
  });

  const spkiDer = publicKey.export({ type: 'spki', format: 'der' }) as Buffer;
  const privateKeyPem = privateKey.export({
    type: 'pkcs8',
    format: 'pem',
  }) as string;

  const now = new Date();
  const notBefore = new Date(now.getTime() - 5 * 60 * 1000);
  const notAfter = new Date(now.getTime() + validDays * 24 * 60 * 60 * 1000);

  // Version v3 ([0] EXPLICIT INTEGER 2)
  const versionExplicit = derTag(0xa0, derInteger(Buffer.from([0x02])));
  const serialNumber = derInteger(crypto.randomBytes(12));

  // sha256WithRSAEncryption (1.2.840.113549.1.1.11) + NULL
  const sha256WithRsaAlgId = derSequence([
    derOid([1, 2, 840, 113549, 1, 1, 11]),
    Buffer.from([0x05, 0x00]),
  ]);

  const nameDer = buildX509Name(commonName, orgName);
  const validityDer = derSequence([derUtcTime(notBefore), derUtcTime(notAfter)]);

  const tbsCertificate = derSequence([
    versionExplicit,
    serialNumber,
    sha256WithRsaAlgId,
    nameDer,
    validityDer,
    nameDer,
    spkiDer,
  ]);

  const signature = crypto.sign('RSA-SHA256', tbsCertificate, privateKey);
  const certDer = derSequence([
    tbsCertificate,
    sha256WithRsaAlgId,
    derBitString(signature),
  ]);

  const b64Lines = certDer.toString('base64').match(/.{1,64}/g) || [];
  const certificatePem = `-----BEGIN CERTIFICATE-----\n${b64Lines.join('\n')}\n-----END CERTIFICATE-----\n`;

  // Verify with Node's native X509Certificate parser
  const parsedX509 = new crypto.X509Certificate(certificatePem);

  return {
    privateKeyPem,
    certificatePem,
    fingerprintSha256: parsedX509.fingerprint256,
    subject: parsedX509.subject.replace(/\n/g, ', '),
    validFrom: notBefore.toISOString(),
    validTo: notAfter.toISOString(),
  };
}

/**
 * Inspects an uploaded/pasted Certificate PEM or derives a public certificate info summary.
 */
export function inspectCertificatePem(certificatePem: string): {
  fingerprintSha256: string;
  subject: string;
  validTo: string;
} | null {
  try {
    if (!certificatePem || !certificatePem.includes('BEGIN CERTIFICATE')) {
      return null;
    }
    const x509 = new crypto.X509Certificate(certificatePem);
    return {
      fingerprintSha256: x509.fingerprint256,
      subject: x509.subject.replace(/\n/g, ', '),
      validTo: x509.validTo,
    };
  } catch {
    return null;
  }
}

/**
 * Validates that a PEM string is a valid RSA Private Key and returns a clean PEM.
 */
export function validatePrivateKeyPem(privateKeyPem: string): string {
  const trimmed = privateKeyPem.trim();
  try {
    const keyObj = crypto.createPrivateKey(trimmed);
    return keyObj.export({ type: 'pkcs8', format: 'pem' }) as string;
  } catch (err: any) {
    throw new Error(
      `Invalid RSA Private Key PEM: ${err.message || 'Could not parse private key'}`
    );
  }
}

/**
 * Creates a signed OAuth 2.0 JWT Bearer assertion (`RS256`) for Salesforce Connected App authentication.
 */
export function createSalesforceJwtAssertion(params: {
  clientId: string;
  username: string;
  loginUrl: string;
  privateKeyPem: string;
}): string {
  const cleanAud = validateSalesforceInstanceUrl(params.loginUrl);
  const nowSec = Math.floor(Date.now() / 1000);

  const header = {
    alg: 'RS256',
    typ: 'JWT',
  };
  const payload = {
    iss: params.clientId.trim(),
    sub: params.username.trim(),
    aud: cleanAud,
    exp: nowSec + 180,
  };

  const encodedHeader = Buffer.from(JSON.stringify(header), 'utf8').toString('base64url');
  const encodedPayload = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  const signingInput = `${encodedHeader}.${encodedPayload}`;

  const keyObj = crypto.createPrivateKey(params.privateKeyPem);
  const signature = crypto
    .sign('RSA-SHA256', Buffer.from(signingInput, 'utf8'), keyObj)
    .toString('base64url');

  return `${signingInput}.${signature}`;
}

export interface SalesforceOrgTokenSession {
  accessToken: string;
  instanceUrl: string;
  orgId: string;
  username: string;
  apiVersion: string;
  authMode: 'jwt_bearer' | 'simulated';
}

export interface SimulatedOrgState {
  profiles: Array<{ Id: string; Name: string; UserType: string }>;
  objects: Array<{
    objectName: string;
    label: string;
    isCustom: boolean;
    fields: Array<{
      fieldName: string;
      label: string;
      fieldType: string;
      isCustom: boolean;
      required: boolean;
    }>;
  }>;
}

const DEFAULT_SIMULATED_ORG: SimulatedOrgState = {
  profiles: [
    { Id: '00e8b000000SysAdmA', Name: 'System Administrator', UserType: 'Standard' },
    { Id: '00e8b000001SalesRp', Name: 'Enterprise Sales Representative', UserType: 'Standard' },
    { Id: '00e8b000002SuppAgt', Name: 'Customer Support Specialist', UserType: 'Standard' },
    { Id: '00e8b000003RevOpsA', Name: 'Revenue Operations Analyst', UserType: 'Standard' },
    { Id: '00e8b000004ApiIntg', Name: 'Salesforce API Only System Integrations', UserType: 'Standard' },
  ],
  objects: [
    {
      objectName: 'Account',
      label: 'Account',
      isCustom: false,
      fields: [
        { fieldName: 'Id', label: 'Account ID', fieldType: 'Id', isCustom: false, required: true },
        { fieldName: 'Name', label: 'Account Name', fieldType: 'Text', isCustom: false, required: true },
        { fieldName: 'Type', label: 'Account Type', fieldType: 'Picklist', isCustom: false, required: false },
        { fieldName: 'Industry', label: 'Industry', fieldType: 'Picklist', isCustom: false, required: false },
        { fieldName: 'AnnualRevenue', label: 'Annual Revenue', fieldType: 'Currency', isCustom: false, required: false },
        { fieldName: 'BillingCountry', label: 'Billing Country', fieldType: 'Text', isCustom: false, required: false },
        { fieldName: 'Customer_Tier__c', label: 'Customer Tier', fieldType: 'Picklist', isCustom: true, required: false },
        { fieldName: 'OwnerId', label: 'Owner ID', fieldType: 'Reference', isCustom: false, required: true },
      ],
    },
    {
      objectName: 'Opportunity',
      label: 'Opportunity',
      isCustom: false,
      fields: [
        { fieldName: 'Id', label: 'Opportunity ID', fieldType: 'Id', isCustom: false, required: true },
        { fieldName: 'Name', label: 'Opportunity Name', fieldType: 'Text', isCustom: false, required: true },
        { fieldName: 'AccountId', label: 'Account ID', fieldType: 'Reference', isCustom: false, required: false },
        { fieldName: 'StageName', label: 'Stage', fieldType: 'Picklist', isCustom: false, required: true },
        { fieldName: 'Amount', label: 'Amount', fieldType: 'Currency', isCustom: false, required: false },
        { fieldName: 'CloseDate', label: 'Close Date', fieldType: 'Date', isCustom: false, required: true },
        { fieldName: 'NextStep', label: 'Next Step', fieldType: 'Text', isCustom: false, required: false },
        { fieldName: 'ARR_Impact__c', label: 'ARR Impact', fieldType: 'Currency', isCustom: true, required: false },
        { fieldName: 'OwnerId', label: 'Owner ID', fieldType: 'Reference', isCustom: false, required: true },
      ],
    },
    {
      objectName: 'Contact',
      label: 'Contact',
      isCustom: false,
      fields: [
        { fieldName: 'Id', label: 'Contact ID', fieldType: 'Id', isCustom: false, required: true },
        { fieldName: 'Name', label: 'Full Name', fieldType: 'Text', isCustom: false, required: true },
        { fieldName: 'FirstName', label: 'First Name', fieldType: 'Text', isCustom: false, required: false },
        { fieldName: 'LastName', label: 'Last Name', fieldType: 'Text', isCustom: false, required: true },
        { fieldName: 'Email', label: 'Email', fieldType: 'Email', isCustom: false, required: false },
        { fieldName: 'Title', label: 'Title', fieldType: 'Text', isCustom: false, required: false },
        { fieldName: 'AccountId', label: 'Account ID', fieldType: 'Reference', isCustom: false, required: false },
      ],
    },
    {
      objectName: 'Case',
      label: 'Case',
      isCustom: false,
      fields: [
        { fieldName: 'Id', label: 'Case ID', fieldType: 'Id', isCustom: false, required: true },
        { fieldName: 'CaseNumber', label: 'Case Number', fieldType: 'AutoNumber', isCustom: false, required: true },
        { fieldName: 'Subject', label: 'Subject', fieldType: 'Text', isCustom: false, required: false },
        { fieldName: 'Status', label: 'Status', fieldType: 'Picklist', isCustom: false, required: true },
        { fieldName: 'Priority', label: 'Priority', fieldType: 'Picklist', isCustom: false, required: false },
        { fieldName: 'Origin', label: 'Case Origin', fieldType: 'Picklist', isCustom: false, required: false },
        { fieldName: 'SLA_Escalated__c', label: 'SLA Escalated', fieldType: 'Boolean', isCustom: true, required: false },
        { fieldName: 'AccountId', label: 'Account ID', fieldType: 'Reference', isCustom: false, required: false },
      ],
    },
    {
      objectName: 'Change_Request__c',
      label: 'Change Request',
      isCustom: true,
      fields: [
        { fieldName: 'Id', label: 'Record ID', fieldType: 'Id', isCustom: false, required: true },
        { fieldName: 'Name', label: 'Change Request Number', fieldType: 'Text', isCustom: false, required: true },
        { fieldName: 'Risk_Level__c', label: 'Risk Level', fieldType: 'Picklist', isCustom: true, required: false },
        { fieldName: 'Approval_Status__c', label: 'Approval Status', fieldType: 'Picklist', isCustom: true, required: false },
        { fieldName: 'Deployment_Window__c', label: 'Deployment Window', fieldType: 'DateTime', isCustom: true, required: false },
        { fieldName: 'OwnerId', label: 'Owner ID', fieldType: 'Reference', isCustom: false, required: true },
      ],
    },
  ],
};

/**
 * Authenticates against a Salesforce Org using OAuth 2.0 JWT Bearer Flow
 * (or Simulated Org mode when configured for local testing).
 */
export async function connectToSalesforceOrgViaJwt(settings: {
  authMode: 'jwt_bearer' | 'simulated';
  loginUrl: string;
  clientId: string;
  username: string;
  privateKeyPem: string;
  apiVersion: string;
  expectedOrgId?: string;
  enforceOrgIdLock?: boolean;
}): Promise<SalesforceOrgTokenSession> {
  const apiVersion = settings.apiVersion || config.salesforce.apiVersion || 'v62.0';

  if (settings.authMode === 'simulated') {
    if (config.isProd) {
      throw new Error('Simulated Salesforce connections are not available in production.');
    }
    if (!settings.privateKeyPem) {
      throw new Error(
        'Please generate or provide an X.509 Certificate & RSA Private Key first so the JWT signature can be verified.'
      );
    }
    // Verify we can actually sign a valid JWT assertion with the configured private key
    createSalesforceJwtAssertion({
      clientId: settings.clientId || '3MVG9_SIMULATED_CONNECTED_APP_KEY',
      username: settings.username || 'mcp-metadata-sync@enterprise.my.salesforce.com',
      loginUrl: settings.loginUrl || 'https://login.salesforce.com',
      privateKeyPem: settings.privateKeyPem,
    });

    const simOrgId = settings.expectedOrgId?.trim() || '00D8b000002MCPORG';
    return {
      accessToken: 'sf_jwt_sim_token',
      instanceUrl:
        settings.loginUrl && !settings.loginUrl.includes('login.salesforce.com')
          ? validateSalesforceInstanceUrl(settings.loginUrl)
          : 'https://enterprise-org.my.salesforce.com',
      orgId: simOrgId,
      username: settings.username?.trim() || 'mcp-metadata-sync@enterprise.my.salesforce.com',
      apiVersion,
      authMode: 'simulated',
    };
  }

  if (!settings.clientId?.trim()) {
    throw new Error('Connected App Consumer Key (Client ID) is required.');
  }
  if (!settings.username?.trim()) {
    throw new Error('Salesforce Integration Username is required.');
  }
  if (!settings.privateKeyPem?.trim()) {
    throw new Error('RSA Private Key PEM is required to sign the JWT assertion.');
  }

  const cleanLoginUrl = validateSalesforceInstanceUrl(
    settings.loginUrl || 'https://login.salesforce.com'
  );
  const assertion = createSalesforceJwtAssertion({
    clientId: settings.clientId,
    username: settings.username,
    loginUrl: cleanLoginUrl,
    privateKeyPem: settings.privateKeyPem,
  });

  const body = new URLSearchParams({
    grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
    assertion,
  });

  const tokenRes = await fetch(`${cleanLoginUrl}/services/oauth2/token`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'application/json',
    },
    body: body.toString(),
  });

  const tokenText = await tokenRes.text();
  let tokenData: any = {};
  try {
    tokenData = tokenText ? JSON.parse(tokenText) : {};
  } catch {
    tokenData = { error_description: tokenText };
  }

  if (!tokenRes.ok || !tokenData.access_token) {
    const errCode = tokenData.error || `HTTP_${tokenRes.status}`;
    const errDesc =
      tokenData.error_description ||
      tokenData.message ||
      'Salesforce JWT Bearer token exchange failed.';
    throw new Error(`[${errCode}] ${errDesc}`);
  }

  const instanceUrl = validateSalesforceInstanceUrl(
    tokenData.instance_url || cleanLoginUrl
  );
  const accessToken: string = tokenData.access_token;

  // Extract Org ID from id URL (`https://login.salesforce.com/id/00D.../005...`) or userinfo
  let orgId = '';
  if (typeof tokenData.id === 'string') {
    const parts = tokenData.id.split('/').filter(Boolean);
    const idIdx = parts.indexOf('id');
    if (idIdx >= 0 && parts[idIdx + 1]) {
      orgId = parts[idIdx + 1];
    }
  }

  if (!orgId) {
    try {
      const uRes = await fetch(`${instanceUrl}/services/oauth2/userinfo`, {
        headers: { Authorization: `Bearer ${accessToken}`, Accept: 'application/json' },
      });
      if (uRes.ok) {
        const uData = (await uRes.json()) as any;
        orgId = uData.organization_id || '';
      }
    } catch {
      // Ignore if userinfo scope not enabled
    }
  }

  if (
    settings.enforceOrgIdLock &&
    settings.expectedOrgId?.trim() &&
    orgId &&
    !orgId.startsWith(settings.expectedOrgId.trim().slice(0, 15))
  ) {
    throw new Error(
      `Org ID Lock Mismatch: Connected Org '${orgId}' does not match expected Org ID '${settings.expectedOrgId}'.`
    );
  }

  return {
    accessToken,
    instanceUrl,
    orgId: orgId || settings.expectedOrgId || 'Connected',
    username: settings.username.trim(),
    apiVersion,
    authMode: 'jwt_bearer',
  };
}

/**
 * Fetches all Salesforce Profiles (`Id, Name, UserType`) using the JWT connection.
 * Requires only `View Setup and Configuration` (`SELECT Id, Name, UserType FROM Profile`).
 */
export async function fetchProfilesFromOrgSession(
  session: SalesforceOrgTokenSession
): Promise<Array<{ id: string; name: string; userType: string }>> {
  if (session.authMode === 'simulated') {
    return DEFAULT_SIMULATED_ORG.profiles.map((p) => ({
      id: p.Id,
      name: p.Name,
      userType: p.UserType,
    }));
  }

  const soql = 'SELECT Id, Name, UserType FROM Profile ORDER BY Name ASC';
  const res = await fetch(
    `${session.instanceUrl}/services/data/${session.apiVersion}/query?q=${encodeURIComponent(soql)}`,
    {
      headers: {
        Authorization: `Bearer ${session.accessToken}`,
        Accept: 'application/json',
      },
    }
  );

  if (!res.ok) {
    const errText = await res.text();
    throw new Error(
      `Failed to query Salesforce Profiles (${res.status}). Ensure the Integration User has 'View Setup and Configuration': ${errText}`
    );
  }

  const data = (await res.json()) as any;
  const records = Array.isArray(data.records) ? data.records : [];
  return records.map((r: any) => ({
    id: String(r.Id),
    name: String(r.Name),
    userType: String(r.UserType || 'Standard'),
  }));
}

export interface OrgObjectSummary {
  objectName: string;
  label: string;
  isCustom: boolean;
  category: 'custom' | 'standard_crm' | 'system';
}

const MAJOR_CRM_OBJECTS = new Set([
  'Account',
  'Contact',
  'Opportunity',
  'Lead',
  'Case',
  'Task',
  'Event',
  'Campaign',
  'Contract',
  'Order',
  'Product2',
  'Pricebook2',
  'Quote',
  'Asset',
  'Solution',
  'User',
]);

const IGNORED_SYSTEM_SUFFIXES = [
  'History',
  'Share',
  'Feed',
  'ChangeEvent',
  'Tag',
];

/**
 * Lists available Objects in the connected Salesforce Org so the admin can browse/select
 * which objects to pull or refresh tracked objects.
 * Supports both `/sobjects` Describe Global and Tooling/SOQL `EntityDefinition` fallback
 * (which works even when the user has 0 Object CRUD permissions and only `View Setup and Configuration`).
 */
export async function fetchOrgObjectsCatalog(
  session: SalesforceOrgTokenSession
): Promise<OrgObjectSummary[]> {
  if (session.authMode === 'simulated') {
    return DEFAULT_SIMULATED_ORG.objects.map((o) => ({
      objectName: o.objectName,
      label: o.label,
      isCustom: o.isCustom,
      category: o.isCustom ? 'custom' : 'standard_crm',
    }));
  }

  const catalogMap = new Map<string, OrgObjectSummary>();

  // 1. Try EntityDefinition query first (returns metadata for objects visible via View Setup & Configuration even without Object CRUD!)
  try {
    const soql =
      'SELECT QualifiedApiName, Label, IsCustomSetting, IsQueryable FROM EntityDefinition WHERE IsQueryable = true AND IsCustomSetting = false ORDER BY QualifiedApiName ASC LIMIT 2000';
    const edRes = await fetch(
      `${session.instanceUrl}/services/data/${session.apiVersion}/tooling/query?q=${encodeURIComponent(soql)}`,
      {
        headers: {
          Authorization: `Bearer ${session.accessToken}`,
          Accept: 'application/json',
        },
      }
    );
    if (edRes.ok) {
      const edData = (await edRes.json()) as any;
      for (const r of edData.records || []) {
        const name = String(r.QualifiedApiName || '');
        if (!name || IGNORED_SYSTEM_SUFFIXES.some((s) => name.endsWith(s))) continue;
        const isCustom = name.endsWith('__c') || name.endsWith('__mdt');
        const category: OrgObjectSummary['category'] = isCustom
          ? 'custom'
          : MAJOR_CRM_OBJECTS.has(name)
          ? 'standard_crm'
          : 'system';
        catalogMap.set(name, {
          objectName: name,
          label: String(r.Label || name),
          isCustom,
          category,
        });
      }
    }
  } catch {
    // Fall back to /sobjects below
  }

  // 2. Also merge `/services/data/vXX.X/sobjects` global describe
  const res = await fetch(
    `${session.instanceUrl}/services/data/${session.apiVersion}/sobjects`,
    {
      headers: {
        Authorization: `Bearer ${session.accessToken}`,
        Accept: 'application/json',
      },
    }
  );

  if (res.ok) {
    const data = (await res.json()) as any;
    for (const s of data.sobjects || []) {
      const name = String(s.name || '');
      if (!name || IGNORED_SYSTEM_SUFFIXES.some((suf) => name.endsWith(suf))) continue;
      const isCustom = Boolean(s.custom) || name.endsWith('__c');
      const category: OrgObjectSummary['category'] = isCustom
        ? 'custom'
        : MAJOR_CRM_OBJECTS.has(name)
        ? 'standard_crm'
        : 'system';
      if (!catalogMap.has(name)) {
        catalogMap.set(name, {
          objectName: name,
          label: String(s.label || name),
          isCustom,
          category,
        });
      }
    }
  } else if (catalogMap.size === 0) {
    const errText = await res.text();
    throw new Error(`Failed to fetch Objects catalog from Salesforce (${res.status}): ${errText}`);
  }

  return Array.from(catalogMap.values()).sort((a, b) =>
    a.objectName.localeCompare(b.objectName)
  );
}

export interface PulledOrgObjectMetadata {
  objectName: string;
  label: string;
  isCustom: boolean;
  existsInOrg: boolean;
  fields: Array<{
    fieldName: string;
    label: string;
    fieldType: string;
    isCustom: boolean;
    required: boolean;
  }>;
}

function normalizeSfFieldType(rawType: string): string {
  const t = (rawType || 'string').toLowerCase();
  if (t === 'id') return 'Id';
  if (t === 'string' || t === 'textarea') return 'Text';
  if (t === 'picklist' || t === 'multipicklist') return 'Picklist';
  if (t === 'currency') return 'Currency';
  if (t === 'boolean') return 'Boolean';
  if (t === 'date') return 'Date';
  if (t === 'datetime') return 'DateTime';
  if (t === 'reference') return 'Reference';
  if (t === 'double' || t === 'int' || t === 'percent') return 'Number';
  if (t === 'email') return 'Email';
  if (t === 'phone') return 'Phone';
  if (t === 'url') return 'Url';
  return rawType.charAt(0).toUpperCase() + rawType.slice(1);
}

/**
 * Fetches detailed Object & Field metadata for a list of object API names.
 * Uses Tooling API `FieldDefinition` + REST `/sobjects/{Name}/describe` so it works
 * even when the Integration User has `View Setup and Configuration` with 0 Object CRUD permissions.
 */
export async function fetchObjectsMetadataFromOrgSession(
  session: SalesforceOrgTokenSession,
  objectNames: string[]
): Promise<PulledOrgObjectMetadata[]> {
  const cleanNames = Array.from(
    new Set(objectNames.map((n) => n.trim()).filter(Boolean))
  );

  if (session.authMode === 'simulated') {
    return cleanNames.map((reqName) => {
      const found = DEFAULT_SIMULATED_ORG.objects.find(
        (o) => o.objectName.toLowerCase() === reqName.toLowerCase()
      );
      if (!found) {
        return {
          objectName: reqName,
          label: reqName,
          isCustom: reqName.endsWith('__c'),
          existsInOrg: false,
          fields: [],
        };
      }
      return {
        objectName: found.objectName,
        label: found.label,
        isCustom: found.isCustom,
        existsInOrg: true,
        fields: found.fields.map((f) => ({ ...f })),
      };
    });
  }

  const results: PulledOrgObjectMetadata[] = [];

  for (const objName of cleanNames) {
    // 1. Try standard SObject Describe first
    const descRes = await fetch(
      `${session.instanceUrl}/services/data/${session.apiVersion}/sobjects/${encodeURIComponent(objName)}/describe`,
      {
        headers: {
          Authorization: `Bearer ${session.accessToken}`,
          Accept: 'application/json',
        },
      }
    );

    if (descRes.ok) {
      const desc = (await descRes.json()) as any;
      const fields = Array.isArray(desc.fields)
        ? desc.fields.map((f: any) => ({
            fieldName: String(f.name),
            label: String(f.label || f.name),
            fieldType: normalizeSfFieldType(String(f.type || 'Text')),
            isCustom: Boolean(f.custom) || String(f.name).endsWith('__c'),
            required:
              String(f.name) === 'Id' ||
              (!f.nillable && !f.defaultedOnCreate && Boolean(f.createable)),
          }))
        : [];
      results.push({
        objectName: String(desc.name || objName),
        label: String(desc.label || objName),
        isCustom: Boolean(desc.custom) || objName.endsWith('__c'),
        existsInOrg: true,
        fields,
      });
      continue;
    }

    // 2. Fallback: Query Tooling API EntityDefinition + FieldDefinition
    // (Works with `View Setup and Configuration` even when the Integration User has 0 CRUD on the object!)
    const edSoql = `SELECT QualifiedApiName, Label, IsCustomSetting FROM EntityDefinition WHERE QualifiedApiName = '${escapeSoqlString(objName)}' LIMIT 1`;
    const edRes = await fetch(
      `${session.instanceUrl}/services/data/${session.apiVersion}/tooling/query?q=${encodeURIComponent(edSoql)}`,
      {
        headers: {
          Authorization: `Bearer ${session.accessToken}`,
          Accept: 'application/json',
        },
      }
    );

    if (edRes.ok) {
      const edData = (await edRes.json()) as any;
      const edRecord = edData.records?.[0];
      if (edRecord) {
        const fdSoql = `SELECT QualifiedApiName, Label, DataType, IsNameField FROM FieldDefinition WHERE EntityDefinition.QualifiedApiName = '${escapeSoqlString(objName)}' ORDER BY QualifiedApiName ASC`;
        const fdRes = await fetch(
          `${session.instanceUrl}/services/data/${session.apiVersion}/tooling/query?q=${encodeURIComponent(fdSoql)}`,
          {
            headers: {
              Authorization: `Bearer ${session.accessToken}`,
              Accept: 'application/json',
            },
          }
        );
        const fdData = fdRes.ok ? ((await fdRes.json()) as any) : { records: [] };
        const fields = (fdData.records || []).map((f: any) => {
          const fn = String(f.QualifiedApiName);
          return {
            fieldName: fn,
            label: String(f.Label || fn),
            fieldType: normalizeSfFieldType(String(f.DataType || 'Text')),
            isCustom: fn.endsWith('__c'),
            required: fn === 'Id' || Boolean(f.IsNameField),
          };
        });

        results.push({
          objectName: String(edRecord.QualifiedApiName || objName),
          label: String(edRecord.Label || objName),
          isCustom: String(edRecord.QualifiedApiName || objName).endsWith('__c'),
          existsInOrg: true,
          fields,
        });
        continue;
      }
    }

    // Object was not found in Salesforce Org (deleted or removed)
    results.push({
      objectName: objName,
      label: objName,
      isCustom: objName.endsWith('__c'),
      existsInOrg: false,
      fields: [],
    });
  }

  return results;
}
