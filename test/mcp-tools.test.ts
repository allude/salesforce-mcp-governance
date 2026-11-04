import './helpers/env.js';
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { store } from '../src/db/store.js';
import { createSimulatorToken } from '../src/salesforce/client.js';
import type {
  CopilotMcpLogRecord,
  SalesforceConnectionSettings,
  SalesforceObject,
} from '../src/types/governance.js';
import {
  installSalesforceMock,
  type RecordedSalesforceCall,
  type SalesforceMock,
} from './helpers/salesforceMock.js';
import { mcpRequest, startTestServer, toolResultPayload, type TestServer } from './helpers/server.js';

// End-to-end tools/call behaviour through the real HTTP /mcp endpoint. Salesforce is faked at the
// fetch boundary (test/helpers/salesforceMock.ts). Every case checks three things: the MCP response,
// the single audit row it wrote, and exactly what was (or was not) sent to Salesforce.

// ---------------------------------------------------------------------------------------------
// Fixture: unique ids / names per run, because every test file shares one database
// ---------------------------------------------------------------------------------------------
const RUN = crypto.randomBytes(4).toString('hex');
/** An 18-character Salesforce-style id with the given 3-character key prefix. */
const sfId = (prefix: string) => `${prefix}${crypto.randomBytes(6).toString('hex').toUpperCase()}AAA`;

const API = '/services/data/v62.0';
const ORG_ID = sfId('00D');
const RECORD_ID = sfId('001');
const MOCK_QUERY_RECORDS = [
  { attributes: { type: 'Account' }, Id: '001000000000001AAA', Name: 'Private Customer Record' },
];

interface Caller {
  token: string;
  userId: string;
  username: string;
  profileId: string;
  profileName: string;
  instanceUrl: string;
}

const FULL: Caller = {
  token: `tok_mcp_tools_full_${RUN}`,
  userId: sfId('005'),
  username: `full.rep.${RUN}@acme.example.com`,
  profileId: sfId('00e'),
  profileName: `MCP Tools Full Access ${RUN}`,
  instanceUrl: `https://acme-${RUN}.my.salesforce.com`,
};

const READ_ONLY: Caller = {
  token: `tok_mcp_tools_readonly_${RUN}`,
  userId: sfId('005'),
  username: `readonly.rep.${RUN}@acme.example.com`,
  profileId: sfId('00e'),
  profileName: `MCP Tools Read Only ${RUN}`,
  instanceUrl: `https://acme-${RUN}.my.salesforce.com`,
};

const ALL_TOOLS = [
  'list_enabled_objects',
  'describe_object',
  'soql_query',
  'get_record',
  'create_record',
  'update_record',
  'delete_record',
];
/** Listed in the full group on purpose: unknown actions must never be exposed or callable. */
const UNKNOWN_ACTION_IN_GROUP = 'export_all_data';

const FULL_GROUP = { id: `grp_mcp_tools_full_${RUN}`, name: `MCP Tools Full ${RUN}` };
const READ_ONLY_GROUP = { id: `grp_mcp_tools_ro_${RUN}`, name: `MCP Tools Read Only ${RUN}` };

/** Enabled globally, but granted to none of this file's groups. */
const UNSHARED_OBJECT = `Mcp_Unshared_${RUN}__c`;
/** Enabled globally; the full group grants it read-only. */
const READ_ONLY_OBJECT = `Mcp_ReadOnly_${RUN}__c`;
/** Disabled globally, although the full group grants it with full CRUD. */
const DISABLED_OBJECT = `Mcp_Disabled_${RUN}__c`;

const ACCOUNT_FIELDS = ['Id', 'Name', 'Industry', 'AnnualRevenue', 'SSN__c'];

/** Structural contract of each tool's inputSchema (property types, required arguments). */
const EXPECTED_INPUT_SCHEMAS: Record<string, { type: string; required: string[]; properties: Record<string, string> }> = {
  list_enabled_objects: { type: 'object', required: [], properties: {} },
  describe_object: { type: 'object', required: ['objectName'], properties: { objectName: 'string' } },
  soql_query: {
    type: 'object',
    required: ['objectName'],
    properties: { objectName: 'string', fields: 'array<string>', whereClause: 'string', limit: 'number' },
  },
  get_record: {
    type: 'object',
    required: ['objectName', 'recordId'],
    properties: { objectName: 'string', recordId: 'string', fields: 'array<string>' },
  },
  create_record: {
    type: 'object',
    required: ['fields', 'objectName'],
    properties: { objectName: 'string', fields: 'object' },
  },
  update_record: {
    type: 'object',
    required: ['fields', 'objectName', 'recordId'],
    properties: { objectName: 'string', recordId: 'string', fields: 'object' },
  },
  delete_record: {
    type: 'object',
    required: ['objectName', 'recordId'],
    properties: { objectName: 'string', recordId: 'string' },
  },
};

// /mcp is rate limited per client IP and the limiter is shared by every test file running in this
// process. Identify this file as its own client (the app trusts X-Forwarded-For from loopback, as it
// does for the local portal proxy) so other files' traffic cannot push these tests into a 429.
const CLIENT_HEADERS = { 'X-Forwarded-For': `198.51.100.${crypto.randomInt(1, 255)}` };

let sf: SalesforceMock;
let server: TestServer;

// ---------------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------------
type AuditStatus = 'ALLOWED' | 'DENIED' | 'ERROR';

interface ToolCallOutcome {
  isError: boolean;
  /** Parsed JSON text content of the tool result. */
  payload: any;
  /** The text content exactly as the caller received it. */
  text: string;
  /** Audit rows written while this call ran (all users, oldest first). */
  auditRows: CopilotMcpLogRecord[];
  /** Salesforce requests made for this call, excluding the token-verification lookups. */
  salesforceCalls: RecordedSalesforceCall[];
}

const describeCall = (c: RecordedSalesforceCall) => `${c.method} ${c.url.pathname}${c.url.search}`;

/** userinfo + the User/Profile lookup made while verifying a Bearer token (cached for 2 minutes). */
function isIdentityLookup(call: RecordedSalesforceCall): boolean {
  return (
    call.url.pathname === '/services/oauth2/userinfo' ||
    /\bFROM User WHERE Id =/i.test(call.url.searchParams.get('q') ?? '')
  );
}

function newestAuditRowId(): string | undefined {
  return store.getCopilotMcpLogs(1)[0]?.id;
}

/** Audit rows written after the row `markerId` (or all rows when there was none), oldest first. */
function auditRowsSince(markerId: string | undefined): CopilotMcpLogRecord[] {
  const recent = store.getCopilotMcpLogs(1000); // newest first
  const end = markerId === undefined ? recent.length : recent.findIndex((r) => r.id === markerId);
  assert.ok(end >= 0, 'the audit marker row is no longer among the newest 1000 rows');
  return recent.slice(0, end).reverse();
}

async function callTool(caller: Caller, name: string, args?: Record<string, unknown>): Promise<ToolCallOutcome> {
  const marker = newestAuditRowId();
  const sfCallsBefore = sf.calls.length;
  const strayCallsBefore = sf.nonSalesforceCalls.length;

  const res = await mcpRequest(
    server.baseUrl,
    caller.token,
    'tools/call',
    args === undefined ? { name } : { name, arguments: args },
    CLIENT_HEADERS
  );

  assert.equal(res.status, 200, `tools/call ${name} answered HTTP ${res.status}: ${JSON.stringify(res.body)}`);
  assert.ok(res.body?.result, `tools/call ${name} must return a JSON-RPC result, got ${JSON.stringify(res.body)}`);
  assert.deepEqual(
    sf.nonSalesforceCalls.slice(strayCallsBefore).map(describeCall),
    [],
    'no request may leave for a non-Salesforce host'
  );
  // Invariant for every tools/call in this file: exactly one audit row, whatever the outcome.
  const auditRows = auditRowsSince(marker);
  assert.equal(
    auditRows.length,
    1,
    `tools/call ${name} must write exactly one audit row, got ${JSON.stringify(auditRows.map((r) => [r.toolName, r.status]))}`
  );

  return {
    isError: res.body.result.isError === true,
    payload: toolResultPayload(res.body),
    text: res.body.result.content?.[0]?.text ?? '',
    auditRows,
    salesforceCalls: sf.calls.slice(sfCallsBefore).filter((c) => !isIdentityLookup(c)),
  };
}

async function listTools(caller: Caller): Promise<{ tools: any[]; salesforceCalls: RecordedSalesforceCall[] }> {
  const sfCallsBefore = sf.calls.length;
  const res = await mcpRequest(server.baseUrl, caller.token, 'tools/list', {}, CLIENT_HEADERS);
  assert.equal(res.status, 200, JSON.stringify(res.body));
  assert.ok(Array.isArray(res.body?.result?.tools), JSON.stringify(res.body));
  return {
    tools: res.body.result.tools,
    salesforceCalls: sf.calls.slice(sfCallsBefore).filter((c) => !isIdentityLookup(c)),
  };
}

/** Asserts the call wrote exactly one audit row describing it, and returns that row. */
function expectAuditRow(
  outcome: ToolCallOutcome,
  caller: Caller,
  toolName: string,
  status: AuditStatus,
  targetObject: string
): CopilotMcpLogRecord {
  assert.equal(
    outcome.auditRows.length,
    1,
    `each tools/call must write exactly one audit row, got ${JSON.stringify(outcome.auditRows.map((r) => [r.toolName, r.status]))}`
  );
  const [row] = outcome.auditRows;
  assert.equal(row.toolName, toolName, 'audit toolName');
  assert.equal(row.status, status, 'audit status');
  assert.equal(row.sfUsername, caller.username, 'audit sfUsername comes from the verified Salesforce userinfo');
  assert.equal(row.profileId, caller.profileId, 'audit profileId');
  assert.equal(row.profileName, caller.profileName, 'audit profileName');
  assert.equal(row.targetObject, targetObject, 'audit targetObject');
  return row;
}

function expectNothingSentToSalesforce(outcome: ToolCallOutcome): void {
  assert.deepEqual(outcome.salesforceCalls.map(describeCall), [], 'nothing may be sent to Salesforce');
}

/** Asserts exactly one Salesforce request was made, to the caller's own instance with the caller's own token. */
function expectSingleSalesforceCall(outcome: ToolCallOutcome, caller: Caller): RecordedSalesforceCall {
  assert.equal(
    outcome.salesforceCalls.length,
    1,
    `expected exactly one Salesforce call, got ${JSON.stringify(outcome.salesforceCalls.map(describeCall))}`
  );
  const [call] = outcome.salesforceCalls;
  assert.equal(call.url.origin, caller.instanceUrl, "the call goes to the caller's own Salesforce instance");
  assert.equal(call.authorization, `Bearer ${caller.token}`, "the call is made with the caller's own token");
  return call;
}

/** The decoded SOQL of a GET /query call. */
function soqlOf(call: RecordedSalesforceCall): string {
  assert.equal(call.method, 'GET');
  assert.equal(call.url.pathname, `${API}/query`);
  return call.url.searchParams.get('q') ?? '';
}

function expectAccessDenied(outcome: ToolCallOutcome, toolName: string, reason: RegExp): void {
  assert.equal(outcome.isError, true, `expected a tool error, got ${JSON.stringify(outcome.payload)}`);
  assert.equal(outcome.payload?.error, 'ACCESS_DENIED');
  assert.equal(outcome.payload?.tool, toolName);
  assert.match(String(outcome.payload?.reason), reason);
}

function schemaShape(schema: any): { type: string; required: string[]; properties: Record<string, string> } {
  const properties: Record<string, string> = {};
  for (const [name, prop] of Object.entries<any>(schema?.properties ?? {})) {
    properties[name] = prop?.type === 'array' ? `array<${prop?.items?.type}>` : String(prop?.type);
  }
  return { type: schema?.type, required: [...(schema?.required ?? [])].sort(), properties };
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

/**
 * Runs `run` while Salesforce requests matching `matches` fail with `fault()`. The Salesforce mock still
 * receives (and records) the request first, so tests can assert what was sent.
 */
async function withSalesforceFault<T>(
  matches: (url: URL, method: string) => boolean,
  fault: () => Promise<Response>,
  run: () => Promise<T>
): Promise<T> {
  const mockedFetch = globalThis.fetch;
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url);
    const method = (init?.method ?? (input instanceof Request ? input.method : 'GET')).toUpperCase();
    if (!matches(url, method)) return mockedFetch(input, init);
    await mockedFetch(input, init);
    return fault();
  }) as typeof fetch;
  try {
    return await run();
  } finally {
    globalThis.fetch = mockedFetch;
  }
}

// ---------------------------------------------------------------------------------------------
// Seeding / cleanup (shared database: pin what these tests depend on, restore it afterwards)
// ---------------------------------------------------------------------------------------------
let savedSettings: SalesforceConnectionSettings | undefined;
let accountBefore: SalesforceObject | undefined;

function seedGovernance(): void {
  store.updateSalesforceSettings({
    instanceUrl: 'https://login.salesforce.com',
    apiVersion: 'v62.0',
    enforceOrgIdLock: false,
  });

  store.upsertObjectWithFields({
    objectName: 'Account',
    label: 'Account',
    enabled: true,
    fields: [
      { fieldName: 'Id', label: 'Record ID', fieldType: 'Id', required: true },
      { fieldName: 'Name', label: 'Account Name', fieldType: 'Text' },
      { fieldName: 'Industry', label: 'Industry', fieldType: 'Picklist' },
      { fieldName: 'AnnualRevenue', label: 'Annual Revenue', fieldType: 'Currency' },
      { fieldName: 'SSN__c', label: 'Social Security Number', fieldType: 'Text', isCustom: true, enabled: false },
    ],
  });
  // An upsert keeps the enabled flag of fields that already exist, so set every flag explicitly.
  store.toggleObject('Account', true);
  for (const field of ACCOUNT_FIELDS) {
    store.toggleObjectField('Account', field, field !== 'SSN__c');
  }

  store.upsertObjectWithFields({ objectName: UNSHARED_OBJECT, enabled: true });
  store.upsertObjectWithFields({ objectName: READ_ONLY_OBJECT, enabled: true });
  store.upsertObjectWithFields({ objectName: DISABLED_OBJECT, enabled: false });

  store.upsertProfile(FULL.profileId, FULL.profileName);
  store.upsertProfile(READ_ONLY.profileId, READ_ONLY.profileName);

  store.createGroup({
    id: FULL_GROUP.id,
    name: FULL_GROUP.name,
    description: 'mcp-tools.test.ts: every tool, full CRUD on Account',
    allowedActions: [...ALL_TOOLS, UNKNOWN_ACTION_IN_GROUP],
    objectPermissions: [
      {
        objectName: 'Account',
        canRead: true,
        canCreate: true,
        canUpdate: true,
        canDelete: true,
        // SSN__c is granted here on purpose: the global field switch must still win.
        allowedFields: ['Id', 'Name', 'Industry', 'SSN__c'],
      },
      {
        objectName: READ_ONLY_OBJECT,
        canRead: true,
        canCreate: false,
        canUpdate: false,
        canDelete: false,
        allowedFields: ['Id', 'Name'],
      },
      {
        objectName: DISABLED_OBJECT,
        canRead: true,
        canCreate: true,
        canUpdate: true,
        canDelete: true,
        allowedFields: ['Id', 'Name'],
      },
    ],
  });
  store.createGroup({
    id: READ_ONLY_GROUP.id,
    name: READ_ONLY_GROUP.name,
    description: 'mcp-tools.test.ts: read-only Account access',
    allowedActions: ['soql_query', 'describe_object'],
    objectPermissions: [
      {
        objectName: 'Account',
        canRead: true,
        canCreate: false,
        canUpdate: false,
        canDelete: false,
        allowedFields: ['Id', 'Name'],
      },
    ],
  });

  store.setProfileGroups(FULL.profileId, [FULL_GROUP.id]);
  store.setProfileGroups(READ_ONLY.profileId, [READ_ONLY_GROUP.id]);
}

function removeSeededGovernance(): void {
  store.deleteGroup(FULL_GROUP.id);
  store.deleteGroup(READ_ONLY_GROUP.id);
  store.deleteProfile(FULL.profileId);
  store.deleteProfile(READ_ONLY.profileId);
  for (const objectName of [UNSHARED_OBJECT, READ_ONLY_OBJECT, DISABLED_OBJECT]) {
    store.deleteObject(objectName);
  }

  if (!accountBefore) {
    store.deleteObject('Account');
  } else {
    store.toggleObject('Account', accountBefore.enabled);
    const enabledBefore = new Map(accountBefore.fields.map((f) => [f.fieldName, f.enabled]));
    for (const field of ACCOUNT_FIELDS) {
      // Fields this file created go back to the default a fresh upsert would give them.
      store.toggleObjectField('Account', field, enabledBefore.get(field) ?? true);
    }
  }

  if (savedSettings) {
    store.updateSalesforceSettings({
      instanceUrl: savedSettings.instanceUrl,
      apiVersion: savedSettings.apiVersion,
      enforceOrgIdLock: savedSettings.enforceOrgIdLock,
      expectedOrgId: savedSettings.expectedOrgId,
    });
  }
}

// ---------------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------------
describe('MCP tools/call end-to-end through HTTP /mcp with a mocked Salesforce org', () => {
  before(async () => {
    savedSettings = store.getSalesforceSettings();
    accountBefore = store.getObjects().find((o) => o.objectName === 'Account');
    seedGovernance();

    sf = installSalesforceMock();
    for (const caller of [FULL, READ_ONLY]) {
      sf.addUser(caller.token, {
        userId: caller.userId,
        organizationId: ORG_ID,
        username: caller.username,
        profileId: caller.profileId,
        profileName: caller.profileName,
        instanceUrl: caller.instanceUrl,
      });
    }
    server = await startTestServer();
  });

  after(async () => {
    try {
      await server?.close();
    } finally {
      sf?.restore();
      removeSeededGovernance();
    }
  });

  // 1. tools/list -----------------------------------------------------------------------------
  describe('tools/list', () => {
    test('lists exactly the seven granted tools with their input schemas, never the unknown action the group also names', async () => {
      const { tools, salesforceCalls } = await listTools(FULL);

      assert.deepEqual(tools.map((t) => t.name).sort(), [...ALL_TOOLS].sort());
      for (const tool of tools) {
        assert.equal(typeof tool.description, 'string', `${tool.name} has a description`);
        assert.ok(tool.description.length > 0, `${tool.name} has a non-empty description`);
        assert.deepEqual(schemaShape(tool.inputSchema), EXPECTED_INPUT_SCHEMAS[tool.name], `${tool.name} inputSchema`);
      }
      assert.deepEqual(salesforceCalls.map(describeCall), [], 'tools/list is answered from the policy');
    });

    test('the read-only profile sees only soql_query and describe_object', async () => {
      const { tools, salesforceCalls } = await listTools(READ_ONLY);

      assert.deepEqual(tools.map((t) => t.name).sort(), ['describe_object', 'soql_query']);
      for (const tool of tools) {
        assert.deepEqual(schemaShape(tool.inputSchema), EXPECTED_INPUT_SCHEMAS[tool.name], `${tool.name} inputSchema`);
      }
      assert.deepEqual(salesforceCalls.map(describeCall), [], 'tools/list is answered from the policy');
    });
  });

  // Discovery tools (answered from the policy) ---------------------------------------------------
  describe('discovery tools', () => {
    test('describe_object returns the effective CRUD flags and allowed fields without calling Salesforce', async () => {
      const outcome = await callTool(FULL, 'describe_object', { objectName: 'Account' });

      assert.equal(outcome.isError, false, JSON.stringify(outcome.payload));
      assert.deepEqual(outcome.payload, {
        objectName: 'Account',
        permissions: { canRead: true, canCreate: true, canUpdate: true, canDelete: true },
        // The group also lists SSN__c, but it is disabled globally.
        allowedFields: ['Id', 'Name', 'Industry'],
        activeOrgFields: ['Id', 'Name', 'Industry'],
      });
      expectAuditRow(outcome, FULL, 'describe_object', 'ALLOWED', 'Account');
      expectNothingSentToSalesforce(outcome);
    });

    test('list_enabled_objects lists only globally enabled objects the groups grant, without calling Salesforce', async () => {
      const outcome = await callTool(FULL, 'list_enabled_objects', {});

      assert.equal(outcome.isError, false, JSON.stringify(outcome.payload));
      assert.equal(outcome.payload.profileId, FULL.profileId);
      assert.equal(outcome.payload.profileName, FULL.profileName);
      assert.deepEqual(outcome.payload.assignedGroups, [FULL_GROUP.name]);
      const objects = [...outcome.payload.objects].sort((a, b) => (a.objectName < b.objectName ? -1 : 1));
      assert.deepEqual(objects, [
        { objectName: 'Account', canRead: true, canCreate: true, canUpdate: true, canDelete: true, allowedFieldCount: 3 },
        {
          objectName: READ_ONLY_OBJECT,
          canRead: true,
          canCreate: false,
          canUpdate: false,
          canDelete: false,
          allowedFieldCount: 2,
        },
      ]);
      expectAuditRow(outcome, FULL, 'list_enabled_objects', 'ALLOWED', '*');
      expectNothingSentToSalesforce(outcome);
    });
  });

  // 2. soql_query on allowed fields ------------------------------------------------------------
  describe('soql_query on allowed fields', () => {
    test('is ALLOWED and sends SELECT Id, Name FROM Account LIMIT 50 with the caller token, returning the records', async () => {
      const outcome = await callTool(FULL, 'soql_query', { objectName: 'Account', fields: ['Id', 'Name'] });

      assert.equal(outcome.isError, false, JSON.stringify(outcome.payload));
      assert.deepEqual(outcome.payload, {
        objectName: 'Account',
        fieldsQueried: ['Id', 'Name'],
        totalSize: 1,
        records: MOCK_QUERY_RECORDS,
      });
      const row = expectAuditRow(outcome, FULL, 'soql_query', 'ALLOWED', 'Account');
      assert.deepEqual(row.matchedGroups, [FULL_GROUP.name]);
      const call = expectSingleSalesforceCall(outcome, FULL);
      assert.equal(soqlOf(call), 'SELECT Id, Name FROM Account LIMIT 50');
    });

    test('caps a requested limit of 500 at 200', async () => {
      const outcome = await callTool(FULL, 'soql_query', { objectName: 'Account', fields: ['Id', 'Name'], limit: 500 });

      assert.equal(outcome.isError, false, JSON.stringify(outcome.payload));
      expectAuditRow(outcome, FULL, 'soql_query', 'ALLOWED', 'Account');
      assert.equal(soqlOf(expectSingleSalesforceCall(outcome, FULL)), 'SELECT Id, Name FROM Account LIMIT 200');
    });

    test('falls back to LIMIT 50 for a non-numeric or negative limit', async () => {
      for (const limit of ['abc', -5]) {
        const outcome = await callTool(FULL, 'soql_query', { objectName: 'Account', fields: ['Id', 'Name'], limit });

        assert.equal(outcome.isError, false, `limit ${JSON.stringify(limit)}: ${JSON.stringify(outcome.payload)}`);
        expectAuditRow(outcome, FULL, 'soql_query', 'ALLOWED', 'Account');
        assert.equal(
          soqlOf(expectSingleSalesforceCall(outcome, FULL)),
          'SELECT Id, Name FROM Account LIMIT 50',
          `limit ${JSON.stringify(limit)}`
        );
      }
    });

    test('without fields selects exactly the effective allowed fields (the globally disabled SSN__c is left out)', async () => {
      const outcome = await callTool(FULL, 'soql_query', { objectName: 'Account' });

      assert.equal(outcome.isError, false, JSON.stringify(outcome.payload));
      assert.deepEqual(outcome.payload.fieldsQueried, ['Id', 'Name', 'Industry']);
      expectAuditRow(outcome, FULL, 'soql_query', 'ALLOWED', 'Account');
      assert.equal(soqlOf(expectSingleSalesforceCall(outcome, FULL)), 'SELECT Id, Name, Industry FROM Account LIMIT 50');
    });

    test('matches the object name case-insensitively and queries the canonical API name', async () => {
      const outcome = await callTool(FULL, 'soql_query', { objectName: 'account', fields: ['id', 'name'] });

      assert.equal(outcome.isError, false, JSON.stringify(outcome.payload));
      expectAuditRow(outcome, FULL, 'soql_query', 'ALLOWED', 'account');
      const soql = soqlOf(expectSingleSalesforceCall(outcome, FULL));
      assert.match(soql, /^SELECT id, name FROM Account LIMIT 50$/i);
      assert.ok(soql.includes(' FROM Account '), `canonical object name in: ${soql}`);
    });

    test('the audit row keeps the query shape but never the returned record values', async () => {
      const outcome = await callTool(FULL, 'soql_query', { objectName: 'Account', fields: ['Id', 'Name'] });

      assert.deepEqual(outcome.payload.records, MOCK_QUERY_RECORDS, 'the caller does receive the records');
      const row = expectAuditRow(outcome, FULL, 'soql_query', 'ALLOWED', 'Account');
      for (const stored of [row.sanitizedRequestPayload, row.sanitizedResponseSummary]) {
        assert.ok(!stored.includes('Private Customer Record'), `audit row leaked a record value: ${stored}`);
        assert.ok(!stored.includes('001000000000001AAA'), `audit row leaked a returned record id: ${stored}`);
      }
      const request = JSON.parse(row.sanitizedRequestPayload);
      assert.equal(request.objectName, 'Account');
      assert.deepEqual(request.fields, ['Id', 'Name']);
      assert.equal(JSON.parse(row.sanitizedResponseSummary).records, '[REDACTED 1 RECORDS]');
    });
  });

  // 3. soql_query on fields outside the allowlist ---------------------------------------------------
  describe('soql_query on fields outside the allowlist', () => {
    test('a field the group does not grant (AnnualRevenue) is ACCESS_DENIED, logged DENIED, and no query is sent', async () => {
      const outcome = await callTool(FULL, 'soql_query', { objectName: 'Account', fields: ['Id', 'AnnualRevenue'] });

      expectAccessDenied(outcome, 'soql_query', /AnnualRevenue/);
      expectAuditRow(outcome, FULL, 'soql_query', 'DENIED', 'Account');
      expectNothingSentToSalesforce(outcome);
    });

    test('a globally disabled field (SSN__c) is ACCESS_DENIED even though the group lists it, and no query is sent', async () => {
      const outcome = await callTool(FULL, 'soql_query', { objectName: 'Account', fields: ['Id', 'SSN__c'] });

      expectAccessDenied(outcome, 'soql_query', /SSN__c/);
      expectAuditRow(outcome, FULL, 'soql_query', 'DENIED', 'Account');
      expectNothingSentToSalesforce(outcome);
    });
  });

  // 4. soql_query whereClause ---------------------------------------------------------------
  describe('soql_query whereClause', () => {
    test('a filter on an allowed field is passed through to Salesforce', async () => {
      const outcome = await callTool(FULL, 'soql_query', {
        objectName: 'Account',
        fields: ['Id', 'Name'],
        whereClause: "Industry = 'Quantum Banking 7731'",
      });

      assert.equal(outcome.isError, false, JSON.stringify(outcome.payload));
      expectAuditRow(outcome, FULL, 'soql_query', 'ALLOWED', 'Account');
      assert.equal(
        soqlOf(expectSingleSalesforceCall(outcome, FULL)),
        "SELECT Id, Name FROM Account WHERE Industry = 'Quantum Banking 7731' LIMIT 50"
      );
    });

    test('the stored audit payload redacts the filter values', async () => {
      const outcome = await callTool(FULL, 'soql_query', {
        objectName: 'Account',
        fields: ['Id', 'Name'],
        whereClause: "Industry = 'Quantum Banking 7731' AND Name LIKE 'Jane Q Customer%'",
      });

      assert.equal(outcome.isError, false, JSON.stringify(outcome.payload));
      const row = expectAuditRow(outcome, FULL, 'soql_query', 'ALLOWED', 'Account');
      for (const stored of [row.sanitizedRequestPayload, row.sanitizedResponseSummary]) {
        assert.ok(!stored.includes('Quantum Banking 7731'), `audit row leaked a filter value: ${stored}`);
        assert.ok(!stored.includes('Jane Q Customer'), `audit row leaked a filter value: ${stored}`);
      }
      const request = JSON.parse(row.sanitizedRequestPayload);
      assert.equal(request.objectName, 'Account');
      assert.ok(Object.hasOwn(request, 'whereClause'), 'the audit row still records that a filter was used');
    });

    test('a filter on a disallowed field is DENIED and nothing is sent', async () => {
      const outcome = await callTool(FULL, 'soql_query', {
        objectName: 'Account',
        fields: ['Id', 'Name'],
        whereClause: 'AnnualRevenue > 5000000',
      });

      expectAccessDenied(outcome, 'soql_query', /AnnualRevenue/);
      const row = expectAuditRow(outcome, FULL, 'soql_query', 'DENIED', 'Account');
      assert.ok(!row.sanitizedRequestPayload.includes('5000000'), `audit row leaked a filter value: ${row.sanitizedRequestPayload}`);
      expectNothingSentToSalesforce(outcome);
    });

    test('a filter probing the globally disabled SSN__c is DENIED and nothing is sent', async () => {
      const outcome = await callTool(FULL, 'soql_query', {
        objectName: 'Account',
        fields: ['Id'],
        whereClause: "SSN__c = '123-45-6789'",
      });

      expectAccessDenied(outcome, 'soql_query', /SSN__c/);
      const row = expectAuditRow(outcome, FULL, 'soql_query', 'DENIED', 'Account');
      assert.ok(!row.sanitizedRequestPayload.includes('123-45-6789'), `audit row leaked a filter value: ${row.sanitizedRequestPayload}`);
      expectNothingSentToSalesforce(outcome);
    });

    test('a filter containing a subquery is DENIED and nothing is sent', async () => {
      const outcome = await callTool(FULL, 'soql_query', {
        objectName: 'Account',
        fields: ['Id', 'Name'],
        whereClause: "Id IN (SELECT AccountId FROM Contact WHERE Email = 'victim@example.com')",
      });

      expectAccessDenied(outcome, 'soql_query', /SELECT/);
      const row = expectAuditRow(outcome, FULL, 'soql_query', 'DENIED', 'Account');
      assert.ok(
        !row.sanitizedRequestPayload.includes('victim@example.com'),
        `audit row leaked a filter value: ${row.sanitizedRequestPayload}`
      );
      expectNothingSentToSalesforce(outcome);
    });
  });

  // 5. get_record ------------------------------------------------------------------------------
  describe('get_record', () => {
    test(`is ALLOWED and GETs ${API}/sobjects/Account/<id>?fields=Id,Name,Industry`, async () => {
      const outcome = await callTool(FULL, 'get_record', { objectName: 'Account', recordId: RECORD_ID });

      assert.equal(outcome.isError, false, JSON.stringify(outcome.payload));
      assert.deepEqual(outcome.payload, {
        objectName: 'Account',
        recordId: RECORD_ID,
        fieldsReturned: ['Id', 'Name', 'Industry'],
        record: { attributes: { type: 'Account' }, Id: RECORD_ID, Name: 'Private Customer Record' },
      });
      expectAuditRow(outcome, FULL, 'get_record', 'ALLOWED', 'Account');
      const call = expectSingleSalesforceCall(outcome, FULL);
      assert.equal(call.method, 'GET');
      assert.equal(call.url.pathname, `${API}/sobjects/Account/${RECORD_ID}`);
      assert.deepEqual([...call.url.searchParams.entries()], [['fields', 'Id,Name,Industry']]);
    });

    test('the audit row does not store the returned field values', async () => {
      const outcome = await callTool(FULL, 'get_record', { objectName: 'Account', recordId: RECORD_ID, fields: ['Id', 'Name'] });

      assert.equal(outcome.payload.record.Name, 'Private Customer Record', 'the caller does receive the record');
      const row = expectAuditRow(outcome, FULL, 'get_record', 'ALLOWED', 'Account');
      assert.ok(
        !row.sanitizedResponseSummary.includes('Private Customer Record'),
        `audit row leaked a record value: ${row.sanitizedResponseSummary}`
      );
    });

    test("rejects malformed record ids ('../../limits', 'abc') before anything is sent", async () => {
      for (const recordId of ['../../limits', 'abc']) {
        const outcome = await callTool(FULL, 'get_record', { objectName: 'Account', recordId });

        assert.equal(outcome.isError, true, `recordId ${recordId}: ${JSON.stringify(outcome.payload)}`);
        assert.match(String(outcome.payload?.error), /recordId/);
        // Refused arguments are logged DENIED: the call was refused, nothing failed.
        expectAuditRow(outcome, FULL, 'get_record', 'DENIED', 'Account');
        expectNothingSentToSalesforce(outcome);
      }
    });

    test('asking for a disallowed field is DENIED and nothing is sent', async () => {
      const outcome = await callTool(FULL, 'get_record', {
        objectName: 'Account',
        recordId: RECORD_ID,
        fields: ['Id', 'AnnualRevenue'],
      });

      expectAccessDenied(outcome, 'get_record', /AnnualRevenue/);
      expectAuditRow(outcome, FULL, 'get_record', 'DENIED', 'Account');
      expectNothingSentToSalesforce(outcome);
    });
  });

  // 6. create_record ---------------------------------------------------------------------------
  describe('create_record', () => {
    test('POSTs exactly the given body to /sobjects/Account and returns the new record id', async () => {
      const fields = { Name: 'Acme Secret Holdings', Industry: 'Banking' };
      const outcome = await callTool(FULL, 'create_record', { objectName: 'Account', fields });

      assert.equal(outcome.isError, false, JSON.stringify(outcome.payload));
      assert.deepEqual(outcome.payload, {
        status: 'SUCCESS',
        tool: 'create_record',
        objectName: 'Account',
        recordId: '001000000000NEWAAA',
        fieldNames: ['Name', 'Industry'],
      });
      expectAuditRow(outcome, FULL, 'create_record', 'ALLOWED', 'Account');
      const call = expectSingleSalesforceCall(outcome, FULL);
      assert.equal(call.method, 'POST');
      assert.equal(call.url.pathname, `${API}/sobjects/Account`);
      assert.equal(call.url.search, '');
      assert.deepEqual(call.body, fields);
    });

    test('with a disallowed field is DENIED and nothing is sent', async () => {
      const outcome = await callTool(FULL, 'create_record', {
        objectName: 'Account',
        fields: { Name: 'Acme Secret Holdings', AnnualRevenue: 1000000 },
      });

      expectAccessDenied(outcome, 'create_record', /AnnualRevenue/);
      expectAuditRow(outcome, FULL, 'create_record', 'DENIED', 'Account');
      expectNothingSentToSalesforce(outcome);
    });

    test('without field values (missing, empty, or an array) is rejected before anything is sent', async () => {
      const variants: Array<[string, Record<string, unknown>]> = [
        ['missing', { objectName: 'Account' }],
        ['empty object', { objectName: 'Account', fields: {} }],
        ['array', { objectName: 'Account', fields: ['Name', 'Industry'] }],
      ];
      for (const [label, args] of variants) {
        const outcome = await callTool(FULL, 'create_record', args);

        assert.equal(outcome.isError, true, `${label}: ${JSON.stringify(outcome.payload)}`);
        assert.match(String(outcome.payload?.error), /fields/, label);
        expectAuditRow(outcome, FULL, 'create_record', 'DENIED', 'Account');
        expectNothingSentToSalesforce(outcome);
      }
    });

    test('a rejected call whose fields arrive as an array of records keeps those values out of the audit log', async () => {
      const outcome = await callTool(FULL, 'create_record', {
        objectName: 'Account',
        fields: [{ Name: 'Jane Array-Wrapped Doe', Industry: 'Banking' }],
      });

      assert.equal(outcome.isError, true, JSON.stringify(outcome.payload));
      expectNothingSentToSalesforce(outcome);
      const row = expectAuditRow(outcome, FULL, 'create_record', 'DENIED', 'Account');
      assert.ok(
        !row.sanitizedRequestPayload.includes('Jane Array-Wrapped Doe'),
        `audit row stored a submitted record value: ${row.sanitizedRequestPayload}`
      );
    });
  });

  // 7. update_record / delete_record -------------------------------------------------------------
  describe('update_record and delete_record', () => {
    test('update_record PATCHes /sobjects/Account/<id> with exactly the given fields', async () => {
      const fields = { Industry: 'Energy', Name: 'Acme Renamed Holdings' };
      const outcome = await callTool(FULL, 'update_record', { objectName: 'Account', recordId: RECORD_ID, fields });

      assert.equal(outcome.isError, false, JSON.stringify(outcome.payload));
      assert.deepEqual(outcome.payload, {
        status: 'SUCCESS',
        tool: 'update_record',
        objectName: 'Account',
        recordId: RECORD_ID,
        fieldNames: ['Industry', 'Name'],
      });
      expectAuditRow(outcome, FULL, 'update_record', 'ALLOWED', 'Account');
      const call = expectSingleSalesforceCall(outcome, FULL);
      assert.equal(call.method, 'PATCH');
      assert.equal(call.url.pathname, `${API}/sobjects/Account/${RECORD_ID}`);
      assert.equal(call.url.search, '');
      assert.deepEqual(call.body, fields);
    });

    test('delete_record DELETEs /sobjects/Account/<id> without a body', async () => {
      const outcome = await callTool(FULL, 'delete_record', { objectName: 'Account', recordId: RECORD_ID });

      assert.equal(outcome.isError, false, JSON.stringify(outcome.payload));
      assert.deepEqual(outcome.payload, {
        status: 'SUCCESS',
        tool: 'delete_record',
        objectName: 'Account',
        recordId: RECORD_ID,
      });
      expectAuditRow(outcome, FULL, 'delete_record', 'ALLOWED', 'Account');
      const call = expectSingleSalesforceCall(outcome, FULL);
      assert.equal(call.method, 'DELETE');
      assert.equal(call.url.pathname, `${API}/sobjects/Account/${RECORD_ID}`);
      assert.equal(call.url.search, '');
      assert.equal(call.body, undefined);
    });

    test('the write audit rows keep the field names but never the written values', async () => {
      const created = await callTool(FULL, 'create_record', {
        objectName: 'Account',
        fields: { Name: 'Acme Confidential Create', Industry: 'Biotech Secret' },
      });
      const updated = await callTool(FULL, 'update_record', {
        objectName: 'Account',
        recordId: RECORD_ID,
        fields: { Name: 'Acme Confidential Update' },
      });

      const createRow = expectAuditRow(created, FULL, 'create_record', 'ALLOWED', 'Account');
      const updateRow = expectAuditRow(updated, FULL, 'update_record', 'ALLOWED', 'Account');
      for (const stored of [createRow.sanitizedRequestPayload, updateRow.sanitizedRequestPayload]) {
        for (const value of ['Acme Confidential Create', 'Biotech Secret', 'Acme Confidential Update']) {
          assert.ok(!stored.includes(value), `audit row stored the written value '${value}': ${stored}`);
        }
      }
      assert.deepEqual(Object.keys(JSON.parse(createRow.sanitizedRequestPayload).fields), ['Name', 'Industry']);
      assert.deepEqual(Object.keys(JSON.parse(updateRow.sanitizedRequestPayload).fields), ['Name']);
    });

    test('a written field name that is not an API name is stored by its length in the payload, as in the decision', async () => {
      const typed = 'jane.doe@example.com 555-12-3456';
      const outcome = await callTool(FULL, 'create_record', {
        objectName: 'Account',
        fields: { [typed]: 'x', Name: 'Doe' },
      });

      expectAccessDenied(outcome, 'create_record', /are not permitted/);
      const row = expectAuditRow(outcome, FULL, 'create_record', 'DENIED', 'Account');
      expectNothingSentToSalesforce(outcome);
      assert.deepEqual(row.decision?.steps.at(-1)?.fieldNames, ['<invalid:len=32>']);
      assert.deepEqual(JSON.parse(row.sanitizedRequestPayload), {
        objectName: 'Account',
        fields: { '<invalid:len=32>': '<REDACTED:string>', Name: '<REDACTED:string>' },
      });
      for (const stored of [row.sanitizedRequestPayload, row.sanitizedResponseSummary, JSON.stringify(row.decision)]) {
        assert.ok(!stored.includes('jane.doe') && !stored.includes('555-12'), `audit row stored the typed field name: ${stored}`);
      }
    });

    test('update_record with a disallowed field is DENIED and nothing is sent', async () => {
      const outcome = await callTool(FULL, 'update_record', {
        objectName: 'Account',
        recordId: RECORD_ID,
        fields: { AnnualRevenue: 1 },
      });

      expectAccessDenied(outcome, 'update_record', /AnnualRevenue/);
      expectAuditRow(outcome, FULL, 'update_record', 'DENIED', 'Account');
      expectNothingSentToSalesforce(outcome);
    });

    test('update_record and delete_record reject a path-traversal record id before anything is sent', async () => {
      const calls: Array<[string, Record<string, unknown>]> = [
        ['update_record', { objectName: 'Account', recordId: '../../limits', fields: { Name: 'x' } }],
        ['delete_record', { objectName: 'Account', recordId: '../../limits' }],
      ];
      for (const [tool, args] of calls) {
        const outcome = await callTool(FULL, tool, args);

        assert.equal(outcome.isError, true, `${tool}: ${JSON.stringify(outcome.payload)}`);
        assert.match(String(outcome.payload?.error), /recordId/, tool);
        expectAuditRow(outcome, FULL, tool, 'DENIED', 'Account');
        expectNothingSentToSalesforce(outcome);
      }
    });
  });

  // 8. Profile / object policy ------------------------------------------------------------------
  describe('profile and object policy', () => {
    test('the read-only profile is DENIED create_record, update_record and delete_record, and nothing is sent', async () => {
      const calls: Array<[string, Record<string, unknown>]> = [
        ['create_record', { objectName: 'Account', fields: { Name: 'Not Allowed Co' } }],
        ['update_record', { objectName: 'Account', recordId: RECORD_ID, fields: { Name: 'Not Allowed Co' } }],
        ['delete_record', { objectName: 'Account', recordId: RECORD_ID }],
      ];
      for (const [tool, args] of calls) {
        const outcome = await callTool(READ_ONLY, tool, args);

        expectAccessDenied(outcome, tool, /not granted by any Group/);
        assert.equal(outcome.payload.profileId, READ_ONLY.profileId);
        assert.equal(outcome.payload.profileName, READ_ONLY.profileName);
        expectAuditRow(outcome, READ_ONLY, tool, 'DENIED', 'Account');
        expectNothingSentToSalesforce(outcome);
      }
    });

    test('the read-only profile can still run soql_query on Account', async () => {
      const outcome = await callTool(READ_ONLY, 'soql_query', { objectName: 'Account', fields: ['Id', 'Name'] });

      assert.equal(outcome.isError, false, JSON.stringify(outcome.payload));
      expectAuditRow(outcome, READ_ONLY, 'soql_query', 'ALLOWED', 'Account');
      assert.equal(soqlOf(expectSingleSalesforceCall(outcome, READ_ONLY)), 'SELECT Id, Name FROM Account LIMIT 50');
    });

    test('a tool call on an object the caller is not granted is DENIED and nothing is sent', async () => {
      const calls: Array<[Caller, string, Record<string, unknown>]> = [
        [READ_ONLY, 'soql_query', { objectName: UNSHARED_OBJECT, fields: ['Id'] }],
        [FULL, 'get_record', { objectName: UNSHARED_OBJECT, recordId: RECORD_ID }],
      ];
      for (const [caller, tool, args] of calls) {
        const outcome = await callTool(caller, tool, args);

        expectAccessDenied(outcome, tool, /not permitted by Groups/);
        expectAuditRow(outcome, caller, tool, 'DENIED', UNSHARED_OBJECT);
        expectNothingSentToSalesforce(outcome);
      }
    });

    test('a tool call on a globally disabled object is DENIED even though the group grants it', async () => {
      const outcome = await callTool(FULL, 'soql_query', { objectName: DISABLED_OBJECT, fields: ['Id'] });

      expectAccessDenied(outcome, 'soql_query', /disabled/);
      expectAuditRow(outcome, FULL, 'soql_query', 'DENIED', DISABLED_OBJECT);
      expectNothingSentToSalesforce(outcome);
    });

    test('write tools are DENIED on an object the group grants read-only, and nothing is sent', async () => {
      const calls: Array<[string, Record<string, unknown>, RegExp]> = [
        ['create_record', { objectName: READ_ONLY_OBJECT, fields: { Name: 'x' } }, /Create access/],
        ['update_record', { objectName: READ_ONLY_OBJECT, recordId: RECORD_ID, fields: { Name: 'x' } }, /Update access/],
        ['delete_record', { objectName: READ_ONLY_OBJECT, recordId: RECORD_ID }, /Delete access/],
      ];
      for (const [tool, args, reason] of calls) {
        const outcome = await callTool(FULL, tool, args);

        expectAccessDenied(outcome, tool, reason);
        expectAuditRow(outcome, FULL, tool, 'DENIED', READ_ONLY_OBJECT);
        expectNothingSentToSalesforce(outcome);
      }
    });
  });

  // 9. Missing objectName / unknown tools / one audit row per call ------------------------------------
  describe('malformed calls and audit accounting', () => {
    test('soql_query and create_record without objectName are DENIED and nothing is sent', async () => {
      const calls: Array<[string, Record<string, unknown>]> = [
        ['soql_query', { fields: ['Id', 'Name'] }],
        ['create_record', { fields: { Name: 'Nameless Object Co' } }],
      ];
      for (const [tool, args] of calls) {
        const outcome = await callTool(FULL, tool, args);

        expectAccessDenied(outcome, tool, /requires an objectName/);
        expectAuditRow(outcome, FULL, tool, 'DENIED', '*');
        expectNothingSentToSalesforce(outcome);
      }
    });

    test('an unknown tool name is DENIED, even one the group lists, and nothing is sent', async () => {
      for (const tool of [UNKNOWN_ACTION_IN_GROUP, 'drop_all_tables']) {
        const outcome = await callTool(FULL, tool, { objectName: 'Account' });

        expectAccessDenied(outcome, tool, /Unknown MCP tool/);
        // The caller's text is not a catalog tool, so the audit row stores only its length.
        expectAuditRow(outcome, FULL, `<invalid:len=${tool.length}>`, 'DENIED', 'Account');
        expectNothingSentToSalesforce(outcome);
      }
    });

    test('an objectName that is not an API name is DENIED and the audit row stores only its length', async () => {
      // 'ACCT-99812' looks like a structural token, so only the API-name check keeps it out of the payload.
      for (const objectName of ['ACCT-99812', "Account WHERE Email = 'jane.doe@acme.example'"]) {
        const outcome = await callTool(FULL, 'soql_query', { objectName, fields: ['Id'] });
        const stored = `<invalid:len=${objectName.length}>`;

        expectAccessDenied(outcome, 'soql_query', /not permitted by Groups/);
        const row = expectAuditRow(outcome, FULL, 'soql_query', 'DENIED', stored);
        assert.deepEqual(JSON.parse(row.sanitizedRequestPayload), { objectName: stored, fields: ['Id'] });
        assert.deepEqual(JSON.parse(row.sanitizedResponseSummary), {
          error: '<REDACTED:string>',
          reason: '<REDACTED:string>',
        });
        expectNothingSentToSalesforce(outcome);
      }
    });

    test('every tools/call writes exactly one audit row, whatever its outcome', async () => {
      const calls: Array<[Caller, string, Record<string, unknown> | undefined, AuditStatus]> = [
        [FULL, 'soql_query', { objectName: 'Account', fields: ['Id'] }, 'ALLOWED'],
        [FULL, 'list_enabled_objects', undefined, 'ALLOWED'],
        [FULL, 'get_record', { objectName: 'Account', recordId: 'abc' }, 'DENIED'],
        [FULL, 'soql_query', { objectName: 'Account', fields: ['SSN__c'] }, 'DENIED'],
        [FULL, 'create_record', { fields: { Name: 'x' } }, 'DENIED'],
        [READ_ONLY, 'delete_record', { objectName: 'Account', recordId: RECORD_ID }, 'DENIED'],
        [READ_ONLY, 'not_a_real_tool', {}, 'DENIED'],
      ];
      const marker = newestAuditRowId();

      for (const [caller, tool, args] of calls) {
        await callTool(caller, tool, args);
      }

      assert.deepEqual(
        auditRowsSince(marker).map((r) => [r.sfUsername, r.toolName, r.status]),
        calls.map(([caller, tool, , status]) => [
          caller.username,
          ALL_TOOLS.includes(tool) ? tool : `<invalid:len=${tool.length}>`,
          status,
        ])
      );
    });
  });

  // Caller-facing payloads: every refusal is decided by evaluatePolicy before any Salesforce call, and
  // the caller still gets the exact text it got when the field, WHERE and argument checks ran in the
  // handlers. Only the log status of a malformed argument changed, from ERROR to DENIED.
  describe('refusal payloads are byte-identical to the earlier handlers', () => {
    const exactly = (body: Record<string, unknown>) => JSON.stringify(body, null, 2);
    const fullNotGranted = (tool: string) =>
      `MCP Action '${tool}' is not granted by any Group assigned to Profile '${READ_ONLY.profileName}' (Groups: ${READ_ONLY_GROUP.name}).`;
    const cases: Array<{
      path: string;
      caller: Caller;
      tool: string;
      args: Record<string, unknown>;
      text: string;
      status: AuditStatus;
      target: string;
    }> = [
      {
        path: 'pre-execution denial (tool not granted)',
        caller: READ_ONLY,
        tool: 'delete_record',
        args: { objectName: 'Account', recordId: RECORD_ID },
        text: exactly({
          error: 'ACCESS_DENIED',
          tool: 'delete_record',
          targetObject: 'Account',
          profileId: READ_ONLY.profileId,
          profileName: READ_ONLY.profileName,
          reason: fullNotGranted('delete_record'),
        }),
        status: 'DENIED',
        target: 'Account',
      },
      {
        path: 'pre-execution denial (object not granted)',
        caller: FULL,
        tool: 'get_record',
        // The record id is malformed too: access is decided first, as it always was.
        args: { objectName: UNSHARED_OBJECT, recordId: 'abc' },
        text: exactly({
          error: 'ACCESS_DENIED',
          tool: 'get_record',
          targetObject: UNSHARED_OBJECT,
          profileId: FULL.profileId,
          profileName: FULL.profileName,
          reason: `Object '${UNSHARED_OBJECT}' is either disabled in Salesforce > Objects or not permitted by Groups [${FULL_GROUP.name}].`,
        }),
        status: 'DENIED',
        target: UNSHARED_OBJECT,
      },
      {
        path: 'pre-execution denial (missing objectName)',
        caller: FULL,
        tool: 'soql_query',
        args: { fields: ['Id'] },
        text: exactly({
          error: 'ACCESS_DENIED',
          tool: 'soql_query',
          targetObject: '*',
          profileId: FULL.profileId,
          profileName: FULL.profileName,
          reason: "MCP Action 'soql_query' requires an objectName argument.",
        }),
        status: 'DENIED',
        target: '*',
      },
      {
        path: 'field denial',
        caller: FULL,
        tool: 'soql_query',
        args: { objectName: 'account', fields: ['Id', 'AnnualRevenue', 'SSN__c'] },
        text: exactly({
          error: 'ACCESS_DENIED',
          tool: 'soql_query',
          targetObject: 'account',
          reason: `Fields [AnnualRevenue, SSN__c] on Account are not permitted for Profile '${FULL.profileName}'.`,
        }),
        status: 'DENIED',
        target: 'account',
      },
      {
        path: 'field denial (written fields)',
        caller: FULL,
        tool: 'update_record',
        args: { objectName: 'Account', recordId: RECORD_ID, fields: { AnnualRevenue: 1 } },
        text: exactly({
          error: 'ACCESS_DENIED',
          tool: 'update_record',
          targetObject: 'Account',
          reason: `Fields [AnnualRevenue] on Account are not permitted for Profile '${FULL.profileName}'.`,
        }),
        status: 'DENIED',
        target: 'Account',
      },
      {
        path: 'WHERE denial',
        caller: FULL,
        tool: 'soql_query',
        args: { objectName: 'Account', fields: ['Id'], whereClause: 'AnnualRevenue > 5000000' },
        text: exactly({
          error: 'ACCESS_DENIED',
          tool: 'soql_query',
          targetObject: 'Account',
          reason: "whereClause references 'AnnualRevenue', which is not an allowed field for this Profile.",
        }),
        status: 'DENIED',
        target: 'Account',
      },
      {
        path: 'guard syntax error (unbalanced parentheses)',
        caller: FULL,
        tool: 'soql_query',
        args: { objectName: 'Account', fields: ['Id'], whereClause: "(Name = 'Acme'" },
        text: exactly({ error: 'whereClause has unbalanced parentheses.' }),
        status: 'DENIED',
        target: 'Account',
      },
      {
        path: 'guard syntax error (unsupported character)',
        caller: FULL,
        tool: 'soql_query',
        args: { objectName: 'Account', whereClause: "Name = 'Acme'; DELETE" },
        text: exactly({ error: 'whereClause contains an unsupported character at position 14.' }),
        status: 'DENIED',
        target: 'Account',
      },
      {
        path: 'argument error (record id)',
        caller: FULL,
        tool: 'delete_record',
        args: { objectName: 'Account', recordId: '../../limits' },
        text: exactly({ error: 'recordId must be a 15 or 18-character Salesforce Record ID.' }),
        status: 'DENIED',
        target: 'Account',
      },
      {
        path: 'argument error (field values)',
        caller: FULL,
        tool: 'update_record',
        args: { objectName: 'Account', recordId: RECORD_ID, fields: [] },
        text: exactly({ error: 'fields must be an object of field names to values.' }),
        status: 'DENIED',
        target: 'Account',
      },
      {
        path: 'pre-execution denial (objectName not an API name)',
        caller: FULL,
        tool: 'soql_query',
        args: { objectName: 'ACCT-99812', fields: ['Id'] },
        text: exactly({
          error: 'ACCESS_DENIED',
          tool: 'soql_query',
          targetObject: 'ACCT-99812',
          profileId: FULL.profileId,
          profileName: FULL.profileName,
          reason: `Object 'ACCT-99812' is either disabled in Salesforce > Objects or not permitted by Groups [${FULL_GROUP.name}].`,
        }),
        status: 'DENIED',
        target: '<invalid:len=10>',
      },
      {
        path: 'pre-execution denial (objectName not text)',
        caller: FULL,
        tool: 'describe_object',
        args: { objectName: 42 },
        text: exactly({
          error: 'ACCESS_DENIED',
          tool: 'describe_object',
          targetObject: '42',
          profileId: FULL.profileId,
          profileName: FULL.profileName,
          reason: `Object '42' is either disabled in Salesforce > Objects or not permitted by Groups [${FULL_GROUP.name}].`,
        }),
        status: 'DENIED',
        target: '<invalid:len=2>',
      },
      {
        // String() of an object whose toString is not a function throws; the handler's text for it stays.
        path: 'argument error (a selected field that cannot be read as text)',
        caller: FULL,
        tool: 'soql_query',
        args: { objectName: 'Account', fields: ['Id', { toString: 1 }] },
        text: exactly({ error: 'Cannot convert object to primitive value' }),
        status: 'DENIED',
        target: 'Account',
      },
      {
        path: 'argument error (a returned field that cannot be read as text)',
        caller: FULL,
        tool: 'get_record',
        args: { objectName: 'Account', recordId: RECORD_ID, fields: [{ toString: 1, valueOf: 1 }] },
        text: exactly({ error: 'Cannot convert object to primitive value' }),
        status: 'DENIED',
        target: 'Account',
      },
      ...(['describe_object', 'soql_query'] as const).map((tool) => ({
        // The same objectName: read before the decision, it once threw out of the handler unlogged.
        path: `pre-execution denial (an objectName that cannot be read as text, ${tool})`,
        caller: FULL,
        tool,
        args: { objectName: { toString: 1 } },
        text: exactly({
          error: 'ACCESS_DENIED',
          tool,
          targetObject: '*',
          profileId: FULL.profileId,
          profileName: FULL.profileName,
          reason: 'Cannot convert object to primitive value',
        }),
        status: 'DENIED' as const,
        target: '*',
      })),
    ];

    for (const c of cases) {
      test(`${c.path}: the caller-facing text and isError are unchanged, logged ${c.status}`, async () => {
        const outcome = await callTool(c.caller, c.tool, c.args);

        assert.equal(outcome.isError, true);
        assert.equal(outcome.text, c.text);
        const row = expectAuditRow(outcome, c.caller, c.tool, c.status, c.target);
        assert.deepEqual(row.matchedGroups, [c.caller === FULL ? FULL_GROUP.name : READ_ONLY_GROUP.name]);
        expectNothingSentToSalesforce(outcome);
      });
    }

    test('an Object stored under a name that is not an API name: the handler\'s text, logged ERROR as a policy fault', async (t) => {
      // Saved before Object names were validated; the store refuses one now, so the read is faked.
      const legacy = 'Legacy Object';
      const objects = store.getObjects();
      const groups = store.getGroups();
      const field = (fieldName: string) => ({
        objectName: legacy,
        fieldName,
        label: fieldName,
        fieldType: 'Text',
        isCustom: false,
        required: false,
        enabled: true,
        missingInOrg: false,
      });
      t.mock.method(store, 'getObjects', () => [
        ...objects,
        {
          objectName: legacy,
          label: legacy,
          isCustom: true,
          enabled: true,
          sourcePath: '',
          fieldCount: 2,
          enabledFieldCount: 2,
          fields: [field('Id'), field('Name')],
          updatedAt: '',
        },
      ]);
      t.mock.method(store, 'getGroups', () =>
        groups.map((g) =>
          g.id === FULL_GROUP.id
            ? {
                ...g,
                objectPermissions: [
                  ...g.objectPermissions,
                  { objectName: legacy, canRead: true, canCreate: false, canUpdate: false, canDelete: false, allowedFields: ['Name'] },
                ],
              }
            : g
        )
      );

      const outcome = await callTool(FULL, 'soql_query', { objectName: 'legacy object', fields: ['Name'] });

      assert.equal(outcome.isError, true);
      assert.equal(outcome.text, exactly({ error: "Object 'Legacy Object' is not a valid Salesforce API name." }));
      expectAuditRow(outcome, FULL, 'soql_query', 'ERROR', '<invalid:len=13>');
      expectNothingSentToSalesforce(outcome);
    });

    test('list_enabled_objects ignores an objectName, even one of an Object the caller is not granted', async () => {
      for (const objectName of [UNSHARED_OBJECT, DISABLED_OBJECT]) {
        const outcome = await callTool(FULL, 'list_enabled_objects', { objectName });

        assert.equal(outcome.isError, false, JSON.stringify(outcome.payload));
        assert.deepEqual(outcome.payload.assignedGroups, [FULL_GROUP.name]);
        expectAuditRow(outcome, FULL, 'list_enabled_objects', 'ALLOWED', objectName);
        expectNothingSentToSalesforce(outcome);
      }
    });
  });

  // 10. Salesforce API failures --------------------------------------------------------------------
  describe('Salesforce API failures', () => {
    test('a Salesforce 404 for get_record is returned as a tool error and logged as ERROR', async () => {
      const missingId = sfId('001');
      const outcome = await withSalesforceFault(
        (url) => url.pathname === `${API}/sobjects/Account/${missingId}`,
        async () => jsonResponse(404, [{ errorCode: 'NOT_FOUND', message: 'The requested resource does not exist' }]),
        () => callTool(FULL, 'get_record', { objectName: 'Account', recordId: missingId })
      );

      assert.equal(outcome.isError, true, JSON.stringify(outcome.payload));
      assert.match(String(outcome.payload?.error), /NOT_FOUND/);
      assert.equal(outcome.payload?.record, undefined);
      expectAuditRow(outcome, FULL, 'get_record', 'ERROR', 'Account');
      const call = expectSingleSalesforceCall(outcome, FULL);
      assert.equal(call.url.pathname, `${API}/sobjects/Account/${missingId}`);
    });

    test('an expired Salesforce session (HTTP 401) on update_record is returned as a tool error and logged as ERROR', async () => {
      const outcome = await withSalesforceFault(
        (url, method) => method === 'PATCH' && url.pathname === `${API}/sobjects/Account/${RECORD_ID}`,
        async () => jsonResponse(401, [{ errorCode: 'INVALID_SESSION_ID', message: 'Session expired or invalid' }]),
        () => callTool(FULL, 'update_record', { objectName: 'Account', recordId: RECORD_ID, fields: { Industry: 'Energy' } })
      );

      assert.equal(outcome.isError, true, JSON.stringify(outcome.payload));
      assert.match(String(outcome.payload?.error), /INVALID_SESSION_ID/);
      expectAuditRow(outcome, FULL, 'update_record', 'ERROR', 'Account');
      assert.equal(expectSingleSalesforceCall(outcome, FULL).method, 'PATCH');
    });

    test('a network failure reaching Salesforce on create_record is returned as a tool error and logged as ERROR', async () => {
      const outcome = await withSalesforceFault(
        (url, method) => method === 'POST' && url.pathname === `${API}/sobjects/Account`,
        async () => {
          throw new TypeError('fetch failed');
        },
        () => callTool(FULL, 'create_record', { objectName: 'Account', fields: { Name: 'Unreachable Org Co' } })
      );

      assert.equal(outcome.isError, true, JSON.stringify(outcome.payload));
      assert.match(String(outcome.payload?.error), /fetch failed/);
      expectAuditRow(outcome, FULL, 'create_record', 'ERROR', 'Account');
      assert.equal(expectSingleSalesforceCall(outcome, FULL).method, 'POST');
    });

    test('after a Salesforce 500 the server keeps answering: the next tools/call succeeds and /healthz is ok', async () => {
      const failed = await withSalesforceFault(
        (url) => url.pathname === `${API}/query` && !/\bFROM User\b/i.test(url.searchParams.get('q') ?? ''),
        async () => new Response('<html><body>Internal Server Error</body></html>', { status: 500, headers: { 'Content-Type': 'text/html' } }),
        () => callTool(FULL, 'soql_query', { objectName: 'Account', fields: ['Id', 'Name'] })
      );
      assert.equal(failed.isError, true, JSON.stringify(failed.payload));
      assert.match(String(failed.payload?.error), /500/);
      expectAuditRow(failed, FULL, 'soql_query', 'ERROR', 'Account');

      const next = await callTool(FULL, 'soql_query', { objectName: 'Account', fields: ['Id', 'Name'] });
      assert.equal(next.isError, false, JSON.stringify(next.payload));
      assert.deepEqual(next.payload.records, MOCK_QUERY_RECORDS);
      expectAuditRow(next, FULL, 'soql_query', 'ALLOWED', 'Account');

      const health = await fetch(`${server.baseUrl}/healthz`);
      assert.equal(health.status, 200);
      assert.equal(((await health.json()) as { status: string }).status, 'ok');
    });
  });

  // 11. The decision, identity and timing each row records ---------------------------------------
  describe('the decision each tools/call row records', () => {
    /** The identity and timing columns every verified tools/call row has. */
    function expectDecided(row: CopilotMcpLogRecord, caller: Caller, group: { id: string }) {
      assert.equal(row.kind, 'real');
      assert.deepEqual(row.assignedGroupIds, [group.id]);
      assert.equal(row.policyRevision, store.getPolicyRevision());
      assert.equal(row.decision?.policyRevision, row.policyRevision);
      assert.deepEqual(
        [row.callerProfileId, row.matchedProfileId, row.matchMethod, row.decision?.matchMethod],
        [caller.profileId, caller.profileId, 'id', 'id']
      );
      assert.equal(row.decisionStage, row.decision?.stage);
      assert.equal(row.decisionCode, row.decision?.code);
      assert.deepEqual(row.decidingGroupIds, row.decision?.decidingGroupIds);
      assert.ok(Number.isInteger(row.verificationMs) && row.verificationMs! >= 1, `verificationMs ${row.verificationMs}`);
      assert.ok(Number.isInteger(row.totalMs) && row.totalMs! >= row.verificationMs!, `totalMs ${row.totalMs} >= ${row.verificationMs}`);
      assert.equal(row.latencyMs, row.totalMs, 'latency_ms is the total');
    }

    test('an allowed call that succeeds: ALLOWED at the last stage, decided by the granting group, names but no values', async () => {
      const outcome = await callTool(FULL, 'soql_query', {
        objectName: 'account',
        fields: ['id', 'Name'],
        whereClause: "Industry = 'Energy-Secret-Value'",
      });

      assert.equal(outcome.isError, false, JSON.stringify(outcome.payload));
      // target_object keeps what the caller sent; the decision keeps the catalog's spelling.
      const row = expectAuditRow(outcome, FULL, 'soql_query', 'ALLOWED', 'account');
      expectDecided(row, FULL, FULL_GROUP);
      assert.deepEqual([row.decision?.outcome, row.decisionCode, row.decisionStage], ['allowed', 'ALLOWED', 'input']);
      assert.deepEqual(row.decidingGroupIds, [FULL_GROUP.id]);
      const named = Object.fromEntries(row.decision!.steps.map((step) => [step.stage, [step.objectName, step.fieldNames]]));
      assert.deepEqual(named.fields, ['Account', ['Id', 'Name']], 'the catalog spelling, not the caller\'s');
      assert.deepEqual(named.where, ['Account', ['Industry']]);
      assert.ok(!JSON.stringify(row.decision).includes('Energy-Secret-Value'));
    });

    test('a refused field: DENIED at fields, FIELD_NOT_PERMITTED, no deciding group, text that is not a name stored by its length', async () => {
      const outcome = await callTool(FULL, 'soql_query', { objectName: 'Account', fields: ['Id', 'AnnualRevenue', 'jane.doe@acme.example'] });

      const row = expectAuditRow(outcome, FULL, 'soql_query', 'DENIED', 'Account');
      expectDecided(row, FULL, FULL_GROUP);
      assert.deepEqual([row.decision?.outcome, row.decisionCode, row.decisionStage], ['denied', 'FIELD_NOT_PERMITTED', 'fields']);
      assert.deepEqual(row.decidingGroupIds, []);
      assert.deepEqual(row.decision?.steps.at(-1), {
        stage: 'fields',
        result: 'fail',
        grantingGroupIds: [],
        objectName: 'Account',
        fieldNames: ['AnnualRevenue', '<invalid:len=21>'],
      });
      assert.ok(!JSON.stringify(row).includes('jane.doe'), 'the address is in no column');
    });

    test('a tool the profile is not granted: DENIED at tool_grant, under the read-only group', async () => {
      const outcome = await callTool(READ_ONLY, 'create_record', { objectName: 'Account', fields: { Name: 'Nope' } });

      const row = expectAuditRow(outcome, READ_ONLY, 'create_record', 'DENIED', 'Account');
      expectDecided(row, READ_ONLY, READ_ONLY_GROUP);
      assert.deepEqual([row.decisionCode, row.decisionStage, row.decidingGroupIds], ['TOOL_NOT_GRANTED', 'tool_grant', []]);
    });

    test('invalid arguments: DENIED at input, INPUT_INVALID', async () => {
      const outcome = await callTool(FULL, 'get_record', { objectName: 'Account', recordId: '../../limits' });

      const row = expectAuditRow(outcome, FULL, 'get_record', 'DENIED', 'Account');
      expectDecided(row, FULL, FULL_GROUP);
      assert.deepEqual([row.decision?.outcome, row.decisionCode, row.decisionStage], ['invalid', 'INPUT_INVALID', 'input']);
      assert.ok(!JSON.stringify(row.decision).includes('limits'));
    });

    test('an allowed call Salesforce fails: ERROR, but the decision is still ALLOWED by the granting group', async () => {
      const missingId = sfId('001');
      const outcome = await withSalesforceFault(
        (url) => url.pathname === `${API}/sobjects/Account/${missingId}`,
        async () => jsonResponse(404, [{ errorCode: 'NOT_FOUND', message: 'The requested resource does not exist' }]),
        () => callTool(FULL, 'get_record', { objectName: 'Account', recordId: missingId })
      );

      const row = expectAuditRow(outcome, FULL, 'get_record', 'ERROR', 'Account');
      expectDecided(row, FULL, FULL_GROUP);
      assert.deepEqual([row.decision?.outcome, row.decisionCode, row.decidingGroupIds], ['allowed', 'ALLOWED', [FULL_GROUP.id]]);
    });

    test('a policy change shows in the next row\'s revision', async () => {
      const before = (await callTool(FULL, 'describe_object', { objectName: 'Account' })).auditRows[0];
      // Off and on again: two policy changes that leave the policy as it was.
      store.toggleObjectField('Account', 'Industry', false);
      store.toggleObjectField('Account', 'Industry', true);
      const after = (await callTool(FULL, 'describe_object', { objectName: 'Account' })).auditRows[0];

      assert.ok(after.policyRevision! > before.policyRevision!, `${after.policyRevision} > ${before.policyRevision}`);
      assert.equal(after.policyRevision, store.getPolicyRevision());
    });

    test('a slow token check shows in verificationMs and totalMs: the row is timed from receipt', async () => {
      const delayMs = 150;
      const slow: Caller = { ...FULL, token: `tok_mcp_tools_slow_${RUN}`, username: `slow.rep.${RUN}@acme.example.com` };
      sf.addUser(slow.token, {
        userId: sfId('005'),
        organizationId: ORG_ID,
        username: slow.username,
        profileId: slow.profileId,
        profileName: slow.profileName,
        instanceUrl: slow.instanceUrl,
      });
      const mockedFetch = globalThis.fetch;
      globalThis.fetch = (async (input: any, init?: any) => {
        const url = new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url);
        if (url.pathname === '/services/oauth2/userinfo') await new Promise((resolve) => setTimeout(resolve, delayMs));
        return mockedFetch(input, init);
      }) as typeof fetch;
      let outcome: ToolCallOutcome;
      try {
        outcome = await callTool(slow, 'list_enabled_objects', {});
      } finally {
        globalThis.fetch = mockedFetch;
      }

      const row = expectAuditRow(outcome, slow, 'list_enabled_objects', 'ALLOWED', '*');
      expectDecided(row, slow, FULL_GROUP);
      assert.ok(row.verificationMs! >= delayMs, `verificationMs ${row.verificationMs} includes the ${delayMs} ms wait`);
      assert.ok(row.totalMs! >= delayMs, `totalMs ${row.totalMs} includes it too`);
    });

    test('access revoked while Salesforce answers: the row still names the group, Object and Profile the call was decided on', async () => {
      const group = { id: `grp_mcp_tools_revoked_${RUN}`, name: `MCP Tools Revoked ${RUN}` };
      const objectName = `Mcp_Revoked_${RUN}__c`;
      const recordId = sfId('a00');
      const caller: Caller = {
        ...FULL,
        token: `tok_mcp_tools_revoked_${RUN}`,
        userId: sfId('005'),
        username: `revoked.rep.${RUN}@acme.example.com`,
        profileId: sfId('00e'),
        profileName: `MCP Tools Revoked ${RUN}`,
      };
      store.upsertObjectWithFields({ objectName, enabled: true, fields: [{ fieldName: 'Id' }, { fieldName: 'Name' }] });
      store.upsertProfile(caller.profileId, caller.profileName);
      store.createGroup({
        id: group.id,
        name: group.name,
        description: 'mcp-tools.test.ts: deleted while its call runs',
        allowedActions: ['update_record'],
        objectPermissions: [{ objectName, canRead: true, canCreate: false, canUpdate: true, canDelete: false, allowedFields: ['Id', 'Name'] }],
      });
      store.setProfileGroups(caller.profileId, [group.id]);
      sf.addUser(caller.token, {
        userId: caller.userId,
        organizationId: ORG_ID,
        username: caller.username,
        profileId: caller.profileId,
        profileName: caller.profileName,
        instanceUrl: caller.instanceUrl,
      });

      // An admin deletes the group, the Object and the Profile after the PATCH has left, before Salesforce answers.
      const revoke = () => [store.deleteGroup(group.id), store.deleteObject(objectName), store.deleteProfile(caller.profileId)];
      const mockedFetch = globalThis.fetch;
      let revoked: boolean[] = [];
      globalThis.fetch = (async (input: any, init?: any) => {
        const url = new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url);
        if (init?.method === 'PATCH' && url.pathname === `${API}/sobjects/${objectName}/${recordId}`) revoked = revoke();
        return mockedFetch(input, init);
      }) as typeof fetch;
      let outcome: ToolCallOutcome;
      try {
        outcome = await callTool(caller, 'update_record', { objectName, recordId, fields: { Name: 'Renamed' } });
      } finally {
        globalThis.fetch = mockedFetch;
        revoke();
      }

      assert.deepEqual(revoked, [true, true, true], 'all three were deleted while the call ran');
      const row = expectAuditRow(outcome, caller, 'update_record', 'ALLOWED', objectName);
      assert.deepEqual([row.assignedGroupIds, row.decidingGroupIds], [[group.id], [group.id]]);
      assert.deepEqual(row.decision?.decidingGroupIds, [group.id]);
      assert.deepEqual(row.decision?.steps.find((step) => step.stage === 'fields'), {
        stage: 'fields',
        result: 'pass',
        grantingGroupIds: [group.id],
        objectName,
        fieldNames: ['Name'],
      });
      assert.deepEqual([row.matchedProfileId, row.matchMethod], [caller.profileId, 'id']);
      assert.ok(!JSON.stringify(row.decision).includes('<invalid'), JSON.stringify(row.decision));
    });

    test('a Profile registered under an id that is not a Salesforce id: matched by name, the row keeps that id', async () => {
      const registeredId = `SALES_OPS_${RUN}`;
      const caller: Caller = {
        ...FULL,
        token: `tok_mcp_tools_by_name_${RUN}`,
        userId: sfId('005'),
        username: `by.name.rep.${RUN}@acme.example.com`,
        profileId: sfId('00e'),
        profileName: `MCP Tools Sales Ops ${RUN}`,
      };
      // The CSV import stores any id, as POST /profiles/import-csv does.
      store.importProfilesFromCsvRows([{ id: registeredId, name: caller.profileName }]);
      store.setProfileGroups(registeredId, [READ_ONLY_GROUP.id]);
      sf.addUser(caller.token, {
        userId: caller.userId,
        organizationId: ORG_ID,
        username: caller.username,
        profileId: caller.profileId,
        profileName: caller.profileName,
        instanceUrl: caller.instanceUrl,
      });
      let outcome: ToolCallOutcome;
      try {
        outcome = await callTool(caller, 'describe_object', { objectName: 'Account' });
      } finally {
        store.deleteProfile(registeredId);
      }

      const [row] = outcome.auditRows;
      assert.deepEqual([row.status, row.decisionCode, row.decidingGroupIds], ['ALLOWED', 'ALLOWED', [READ_ONLY_GROUP.id]]);
      assert.deepEqual([row.callerProfileId, row.matchedProfileId, row.matchMethod], [caller.profileId, registeredId, 'name']);
    });

    test('a simulator token\'s row is kind simulated, with the same decision columns', async () => {
      const token = createSimulatorToken({ profileId: FULL.profileId, profileName: FULL.profileName });
      const marker = newestAuditRowId();

      const res = await mcpRequest(server.baseUrl, token, 'tools/call', { name: 'soql_query', arguments: { objectName: 'Account', fields: ['Id'] } }, CLIENT_HEADERS);

      assert.equal(res.status, 200, JSON.stringify(res.body));
      const rows = auditRowsSince(marker);
      assert.equal(rows.length, 1);
      const [row] = rows;
      assert.deepEqual([row.kind, row.status, row.decisionCode, row.decidingGroupIds], ['simulated', 'ALLOWED', 'ALLOWED', [FULL_GROUP.id]]);
      assert.equal(row.policyRevision, store.getPolicyRevision());
      assert.deepEqual([row.callerProfileId, row.matchedProfileId, row.matchMethod], [FULL.profileId, FULL.profileId, 'id']);
      assert.ok(row.verificationMs! >= 1 && row.totalMs! >= row.verificationMs!);
    });
  });
});
