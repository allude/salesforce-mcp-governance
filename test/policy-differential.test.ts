import './helpers/env.js';
// Differential tests against the code evaluatePolicy replaced, on generated policies (groups,
// mappings, Objects, flag combinations, case variants, disabled Objects and fields, fields missing in
// the org, malformed entries):
// 1. evaluateMcpToolCall, now a thin wrapper over evaluatePolicy's tool and Object stages, against
//    the engine it replaced (test/helpers/legacyPolicyEngine.ts, an unchanged copy), for every caller,
//    tool and target.
// 2. The tools/call handler, whose field, WHERE and argument checks moved into evaluatePolicy, against
//    the handler it replaced (test/helpers/legacyMcpServer.ts, an unchanged copy), on generated
//    arguments: the caller gets the same text, Salesforce gets the same requests, and the log row is
//    the same.
// The accepted differences, each asserted where it shows: a tool outside the object-scoped set ignores
// objectName, so it gets what the old code gave it with no object; a malformed argument is logged
// DENIED where it was logged ERROR, since the call was refused (owner decision D12); and an objectName
// that cannot be read as text, on which the old handler threw out unlogged, is decided and logged.
import { test, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import type { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { store } from '../src/db/store.js';
import {
  evaluateMcpToolCall,
  evaluatePolicy,
  loadPolicySnapshot,
  resolveEffectiveProfilePermissions,
  type PolicyDecisionCode,
  type PolicyEvaluationResult,
  type PolicyStage,
} from '../src/rbac/policyEngine.js';
import { createUserScopedMcpServer } from '../src/mcp/server.js';
import { targetObjectArgument } from '../src/mcp/toolArguments.js';
import { evaluateMcpToolCall as legacyEvaluateMcpToolCall } from './helpers/legacyPolicyEngine.js';
import { createUserScopedMcpServer as createLegacyMcpServer } from './helpers/legacyMcpServer.js';
import { installSalesforceMock } from './helpers/salesforceMock.js';
import type { VerifiedSalesforceUser } from '../src/salesforce/client.js';
import { AVAILABLE_MCP_ACTIONS, type CopilotMcpLogRecord } from '../src/types/governance.js';

const ALL_ACTIONS: string[] = AVAILABLE_MCP_ACTIONS.map((a) => a.id);
const OBJECT_SCOPED_TOOLS = new Set(ALL_ACTIONS.filter((id) => id !== 'list_enabled_objects'));
const TOOLS = [...ALL_ACTIONS, 'execute_apex', 'SOQL_QUERY'];

const STAGE_OF_CODE: Record<Exclude<PolicyDecisionCode, 'ALLOWED' | 'INTERNAL_ERROR' | 'ROW_FILTER'>, PolicyStage> = {
  TOOL_UNKNOWN: 'tool',
  PROFILE_UNREGISTERED: 'identity',
  NO_GROUPS: 'groups',
  TOOL_NOT_GRANTED: 'tool_grant',
  OBJECT_NOT_GRANTED: 'object',
  OBJECT_BLOCKED: 'object',
  CRUD_MISSING: 'crud',
  FIELD_NOT_PERMITTED: 'fields',
  WHERE_FIELD_NOT_PERMITTED: 'where',
  INPUT_INVALID: 'input',
};

/** mulberry32: a small seeded generator, so a failing world can be rebuilt from its seed. */
function seededRandom(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let x = Math.imul(state ^ (state >>> 15), 1 | state);
    x = (x + Math.imul(x ^ (x >>> 7), 61 | x)) ^ x;
    return ((x ^ (x >>> 14)) >>> 0) / 4294967296;
  };
}

const ID_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

/** Salesforce's 18-character form of a 15-character id. */
function to18(id15: string): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ012345';
  let suffix = '';
  for (let chunk = 0; chunk < 3; chunk++) {
    let bits = 0;
    for (let i = 0; i < 5; i++) {
      const c = id15[chunk * 5 + i];
      if (c >= 'A' && c <= 'Z') bits |= 1 << i;
    }
    suffix += alphabet[bits];
  }
  return id15 + suffix;
}

function caller(profileId: string, profileName: string): VerifiedSalesforceUser {
  return {
    userId: '005000000000001AAA',
    organizationId: '00D000000000001AAA',
    username: 'differential.caller@example.com',
    email: 'differential.caller@example.com',
    displayName: 'Differential Caller',
    profileId,
    profileName,
    instanceUrl: 'https://acme.my.salesforce.com',
    accessToken: 'differential-test-token',
  };
}

interface World {
  callers: Array<{ label: string; user: VerifiedSalesforceUser }>;
  targets: Array<string | undefined>;
  /** The catalog's Objects, and one that entries grant but the catalog never lists. */
  catalog: string[];
  ghost: string;
  fieldPool: string[];
}

/** Seeds one generated policy into the store (removed when the test ends) and returns what to call it with. */
function buildWorld(t: TestContext, seed: number): World {
  const random = seededRandom(seed);
  const chance = (p: number) => random() < p;
  const pick = <T>(values: readonly T[]): T => values[Math.floor(random() * values.length)];
  const subset = <T>(values: readonly T[], p: number): T[] => values.filter(() => chance(p));
  const caseVariant = (name: string) => pick([name, name, name.toLowerCase(), name.toUpperCase()]);
  const sfId15 = (prefix: string) =>
    `${prefix}${Array.from({ length: 12 }, () => ID_CHARS[Math.floor(random() * ID_CHARS.length)]).join('')}`;
  const tag = `${seed}x${Math.floor(random() * 1e9).toString(36)}`;

  const profileIds: string[] = [];
  const objectNames: string[] = [];
  t.after(() => {
    for (const id of profileIds) store.deleteProfile(id);
    // Every generated world's groups go before any Object, so an Object's delete has no grant left to revoke.
    for (const group of store.getGroups()) {
      if (group.id.startsWith('grp_diff_')) store.deleteGroup(group.id);
    }
    for (const name of objectNames) store.deleteObject(name);
  });

  // Objects: some enabled, some not; Id, Name and the rest each enabled or disabled per Object, and
  // some kept after a sync found them missing in the org. That flag has a generator of its own, so the
  // rest of the world is what it was before the flag was generated.
  const missingInOrg = seededRandom(seed ^ 0x5eed);
  const fieldPool = ['Id', 'Name', 'Amount__c', 'Secret__c', 'Phone'];
  const catalog = ['Alpha', 'Bravo', 'Charlie', 'Delta'].map((base) => {
    const objectName = `Diff${base}_${tag}__c`;
    const fields = subset(fieldPool, 0.8);
    store.upsertObjectWithFields({
      objectName,
      enabled: chance(0.75),
      fields: fields.map((fieldName) => ({
        fieldName,
        enabled: chance(fieldName === 'Id' ? 0.8 : 0.65),
        missingInOrg: fieldName !== 'Id' && missingInOrg() < 0.2,
      })),
    });
    objectNames.push(objectName);
    return objectName;
  });
  const ghost = `DiffGhost_${tag}__c`; // granted by entries, never in the catalog

  const flagValue = (): unknown => {
    const r = random();
    if (r < 0.45) return true;
    if (r < 0.8) return false;
    if (r < 0.96) return undefined;
    return 'true'; // malformed: the entry is skipped whole
  };
  const entry = (): unknown => {
    if (chance(0.04)) return pick([null, 'free text', [catalog[0]]]);
    const fields = subset([...fieldPool, 'Ghost__c', ''], 0.35).map(caseVariant);
    return {
      objectName: caseVariant(pick([...catalog, ghost])),
      canRead: flagValue(),
      canCreate: flagValue(),
      canUpdate: flagValue(),
      canDelete: flagValue(),
      allowedFields: chance(0.04) ? pick(['Name', [7]]) : fields,
    };
  };

  const groups = Array.from({ length: 6 }, (_, i) =>
    store.createGroup({
      id: `grp_diff_${tag}_${i}`,
      // A random leading letter, so the groups' (name) order differs from their creation order.
      name: `${pick(['A', 'K', 'Q', 'Z'])} Diff ${tag} ${i}`,
      allowedActions: subset([...TOOLS, ''], 0.4),
      objectPermissions: Array.from({ length: Math.floor(random() * 4) }, entry) as never,
    })
  );

  const profiles = Array.from({ length: 5 }, (_, i) => {
    const id15 = sfId15('00e');
    const id = chance(0.5) ? id15 : to18(id15);
    const name = `Diff Profile ${tag} ${i}`;
    store.upsertProfile(id, name);
    profileIds.push(id);
    // One Profile in five keeps no groups at all.
    store.setProfileGroups(id, i === 4 ? [] : subset(groups, 0.45).map((g) => g.id));
    return { id15, id, name };
  });

  const strangerId = to18(sfId15('00e'));
  const callers: World['callers'] = [
    { label: 'unregistered', user: caller(strangerId, `Nobody ${tag}`) },
    { label: 'empty identity', user: caller('', '') },
    { label: 'empty id, registered name', user: caller('', profiles[0].name) },
  ];
  profiles.forEach((p, i) => {
    const otherForm = p.id.length === 15 ? to18(p.id15) : p.id15;
    callers.push(
      { label: `profile ${i}`, user: caller(p.id, p.name) },
      { label: `profile ${i}, other id form and name`, user: caller(otherForm, `Renamed ${tag}`) },
      { label: `profile ${i} by name`, user: caller(strangerId, p.name.toUpperCase()) },
      { label: `profile ${i} by id, profile ${(i + 1) % 5}'s name`, user: caller(p.id, profiles[(i + 1) % 5].name) }
    );
  });

  const targets: World['targets'] = [
    undefined,
    '',
    '*',
    ...catalog.flatMap((name) => [name, name.toLowerCase(), name.toUpperCase()]),
    ghost,
    'ACCT-99812',
    "Account WHERE Email = 'x'",
  ];
  return { callers, targets, catalog, ghost, fieldPool };
}

/** The generated targets that are not Salesforce API names. */
const NOT_API_NAMES = new Set(['ACCT-99812', "Account WHERE Email = 'x'"]);

/** The fields the old engine returned, which the new one must return alike. */
function legacyView(result: Omit<PolicyEvaluationResult, 'decision'>) {
  return {
    permitted: result.permitted,
    reason: result.reason,
    allowedFields: result.allowedFields,
    objectName: result.objectName,
    matchedGroups: result.matchedGroups,
    skippedGroupEntries: result.skippedGroupEntries,
  };
}

/** The decision's own invariants: its outcome, steps, code and deciding groups agree with each other. */
function assertCoherentDecision(result: PolicyEvaluationResult, tool: string, label: string): void {
  const { decision } = result;
  assert.equal(decision.outcome === 'allowed', result.permitted, `${label}: outcome matches permitted`);
  assert.equal(decision.reason, result.reason, label);
  assert.ok(decision.steps.slice(0, -1).every((s) => s.result === 'pass'), `${label}: only the last step can fail`);
  const assigned = new Set(decision.assignedGroups.map((g) => g.id));
  if (decision.outcome === 'allowed') {
    assert.equal(decision.code, 'ALLOWED', label);
    assert.ok(decision.steps.every((s) => s.result === 'pass'), label);
    const stages = ['tool', 'identity', 'groups', 'tool_grant', ...(OBJECT_SCOPED_TOOLS.has(tool) ? ['object', 'crud'] : [])];
    assert.deepEqual(decision.steps.map((s) => s.stage), stages, `${label}: the tool and Object stages, nothing more`);
    assert.ok(decision.decidingGroupIds.length > 0, `${label}: some group decided it`);
    assert.ok(decision.decidingGroupIds.every((id) => assigned.has(id)), `${label}: deciding groups are assigned`);
  } else {
    const failed = decision.steps.at(-1);
    assert.equal(failed?.result, 'fail', `${label}: a refusal ends on a failed step`);
    assert.equal(failed?.stage, STAGE_OF_CODE[decision.code as keyof typeof STAGE_OF_CODE], `${label}: ${decision.code} fails at its stage`);
    assert.equal(decision.outcome, decision.code === 'INPUT_INVALID' ? 'invalid' : 'denied', label);
    assert.deepEqual(decision.decidingGroupIds, [], label);
  }
  for (const step of decision.steps) {
    assert.ok(step.grantingGroupIds.every((id) => assigned.has(id)), `${label}: ${step.stage} groups are assigned`);
    assert.equal(step.ruleId, null, label);
  }
}

test('evaluateMcpToolCall agrees with the engine it replaced on generated policies', (t) => {
  t.mock.method(console, 'warn', () => {}); // malformed entries are reported once each; not under test here
  const codesSeen = new Set<string>();
  let calls = 0;
  let objectNameIgnored = 0;
  let notApiNameRefused = 0;

  for (const seed of [1, 2, 3]) {
    const world = buildWorld(t, seed);
    for (const { label, user } of world.callers) {
      for (const tool of TOOLS) {
        for (const target of world.targets) {
          const call = `seed ${seed}, ${label}: ${tool}(${JSON.stringify(target)})`;
          const actual = evaluateMcpToolCall(user, tool, target);
          const asBefore = legacyEvaluateMcpToolCall(user, tool, target);
          let expected = asBefore;
          if (!OBJECT_SCOPED_TOOLS.has(tool)) {
            // The documented difference: objectName is ignored, so the old answer without one applies.
            expected = legacyEvaluateMcpToolCall(user, tool, undefined);
            if (JSON.stringify(legacyView(asBefore)) !== JSON.stringify(legacyView(expected))) {
              objectNameIgnored++;
              assert.equal(tool, 'list_enabled_objects', `${call}: only list_enabled_objects can differ`);
              assert.ok(target && target !== '*', `${call}: only when an object is named`);
              // The old engine checked that object: it denied the call on it, or resolved it.
              assert.ok(
                asBefore.permitted
                  ? asBefore.objectName !== undefined
                  : /^Object '.*' is either disabled/.test(asBefore.reason),
                `${call}: the old engine checked the object: ${JSON.stringify(legacyView(asBefore))}`
              );
            }
          }
          assert.deepEqual(legacyView(actual), legacyView(expected), call);
          assertCoherentDecision(actual, tool, call);
          if (
            OBJECT_SCOPED_TOOLS.has(tool) &&
            NOT_API_NAMES.has(String(target)) &&
            actual.decision.steps.some((s) => s.stage === 'tool_grant' && s.result === 'pass')
          ) {
            // Denied as before, with the same reason, but as the malformed argument it is.
            assert.equal(actual.decision.code, 'INPUT_INVALID', `${call}: not an API name`);
            notApiNameRefused++;
          }
          codesSeen.add(actual.decision.code);
          calls++;
        }
      }
    }
  }

  // Controls: the generated policies reach every code the tool and Object stages can give, and the
  // documented difference was exercised rather than vacuously absent.
  assert.deepEqual(
    [...codesSeen].sort(),
    [
      'ALLOWED',
      'CRUD_MISSING',
      'INPUT_INVALID',
      'NO_GROUPS',
      'OBJECT_BLOCKED',
      'OBJECT_NOT_GRANTED',
      'PROFILE_UNREGISTERED',
      'TOOL_NOT_GRANTED',
      'TOOL_UNKNOWN',
    ]
  );
  assert.ok(objectNameIgnored > 0, 'some list_enabled_objects call with an objectName was denied before');
  assert.ok(notApiNameRefused > 0, 'some objectName that is not an API name reached the Object stage');
  assert.ok(calls > 10_000, `${calls} calls compared`);
});

test('the documented difference: list_enabled_objects is no longer denied on the objectName it ignores', (t) => {
  const tag = Math.floor(Math.random() * 1e9).toString(36);
  const granted = `DiffListGranted_${tag}__c`;
  const unshared = `DiffListUnshared_${tag}__c`;
  const profileId = to18(`00eDiffList${tag.padEnd(4, 'x').slice(0, 4)}`);
  store.upsertObjectWithFields({ objectName: granted, enabled: true, fields: [{ fieldName: 'Id' }] });
  store.upsertObjectWithFields({ objectName: unshared, enabled: true, fields: [{ fieldName: 'Id' }] });
  const group = store.createGroup({
    id: `grp_diff_list_${tag}`,
    name: `Diff List ${tag}`,
    allowedActions: ['list_enabled_objects'],
    objectPermissions: [{ objectName: granted, canRead: true, canCreate: false, canUpdate: false, canDelete: false, allowedFields: ['Id'] }],
  });
  store.upsertProfile(profileId, `Diff List Profile ${tag}`);
  store.setProfileGroups(profileId, [group.id]);
  t.after(() => {
    store.deleteProfile(profileId);
    store.deleteGroup(group.id);
    store.deleteObject(granted);
    store.deleteObject(unshared);
  });
  const user = caller(profileId, `Diff List Profile ${tag}`);

  const before = legacyEvaluateMcpToolCall(user, 'list_enabled_objects', unshared);
  assert.equal(before.permitted, false);
  assert.match(before.reason, /not permitted by Groups/);
  // The old engine even resolved a granted object for it, and returned its fields.
  assert.equal(legacyEvaluateMcpToolCall(user, 'list_enabled_objects', granted).objectName, granted);

  for (const target of [unshared, granted]) {
    const now = evaluateMcpToolCall(user, 'list_enabled_objects', target);
    assert.deepEqual(legacyView(now), legacyView(legacyEvaluateMcpToolCall(user, 'list_enabled_objects', undefined)));
    assert.equal(now.permitted, true);
    assert.equal(now.objectName, undefined);
    assert.deepEqual(now.allowedFields, []);
  }
});

// ---------------------------------------------------------------------------
// 2. The tools/call handler: the checks that moved from the handlers into evaluatePolicy
// ---------------------------------------------------------------------------

type LogRow = Parameters<typeof store.recordCopilotMcpLog>[0];

/** What one tools/call did, as far as anyone outside the handler can tell. */
interface ToolCallEffect {
  /** The tool result's text and isError, or the JSON-RPC error when the handler threw. */
  result: { isError: boolean; text: string } | { rpcError: string };
  /** The Salesforce requests it made: method, path with query, body. */
  salesforce: string[];
  /** The log rows it wrote, without their latency and what the legacy handler could not record. */
  logRows: Array<Omit<LogRow, LoggedSince>>;
  /** The decision each row recorded; the legacy handler recorded none. */
  loggedDecisions: Array<LogRow['decision']>;
}

/** The timing and decision a row records now: the legacy handler wrote none of them. */
type LoggedSince = 'latencyMs' | 'totalMs' | 'verificationMs' | 'decision';

const DIFFERENTIAL_TOKEN = 'differential-test-token';

async function connectClient(t: TestContext, server: Server): Promise<Client> {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const client = new Client({ name: 'policy-differential', version: '1.0.0' });
  await client.connect(clientTransport);
  t.after(() => client.close());
  return client;
}

/** An Object and the fields a caller may use on it, to aim the generated arguments at what is granted. */
interface AimedObject {
  objectName: string;
  allowedFields: string[];
}

/** The CRUD flag each object-scoped tool needs, as the handlers' tools have always needed it. */
const CRUD_OF_TOOL = {
  describe_object: 'canRead',
  soql_query: 'canRead',
  get_record: 'canRead',
  create_record: 'canCreate',
  update_record: 'canUpdate',
  delete_record: 'canDelete',
} as const;

/**
 * The caller's arguments as the wire carries them: JSON, so no undefined and no functions. Aimed at a
 * granted Object, they mostly name it and its allowed fields, so that the calls get past the access
 * stages to the argument checks and to Salesforce.
 */
function generatedArguments(world: World, random: () => number, aimed?: AimedObject): Record<string, unknown> | undefined {
  const chance = (p: number) => random() < p;
  const pick = <T>(values: readonly T[]): T => values[Math.floor(random() * values.length)];
  const caseVariant = (name: string) => pick([name, name, name.toLowerCase(), name.toUpperCase()]);
  // An object whose toString is not a function: String() of it throws.
  const unreadable = () => ({ toString: 1 });
  const usualField = () =>
    caseVariant(aimed && aimed.allowedFields.length > 0 && chance(0.8) ? pick(aimed.allowedFields) : pick([...world.fieldPool, 'Ghost__c']));
  const fieldName = (): unknown =>
    chance(0.9) ? usualField() : pick(['', 'Owner.Name', 'Name, Secret__c', 7, null, unreadable()]);
  const fieldList = () => Array.from({ length: Math.floor(random() * 4) }, fieldName);

  if (chance(0.03)) return undefined;
  const r = random();
  const objectName =
    aimed && r < 0.85
      ? caseVariant(aimed.objectName)
      : r < 0.06
        ? undefined
        : r < 0.1
          ? pick(['', '*'])
          : r < 0.78
            ? caseVariant(pick(world.catalog))
            : r < 0.85
              ? world.ghost
              : pick<unknown>(['ACCT-99812', "Account WHERE Email = 'x'", ` ${world.catalog[1]}`, 42, [world.catalog[0]], unreadable()]);
  const fieldsValue = (): unknown => {
    const kind = random();
    if (kind < 0.1) return undefined;
    if (kind < 0.5) return chance(0.1) ? [...fieldList(), unreadable()] : fieldList();
    if (kind < 0.9) {
      const names = fieldList().filter((f): f is string => typeof f === 'string');
      return Object.fromEntries((names.length > 0 ? names : [usualField()]).map((f) => [f, pick(['x', 1, null])]));
    }
    return pick<unknown>([[], {}, 'Name', null, { Name: unreadable() }]);
  };
  const whereClause = (): unknown => {
    if (chance(0.3)) return undefined;
    if (chance(0.35)) {
      const terms = Array.from({ length: 1 + Math.floor(random() * 3) }, () => `${usualField()} ${pick(['!= null', "= 'x'", '> 5', "LIKE 'A%'"])}`);
      return pick([terms.join(' AND '), `(${terms.join(' OR ')})`, `NOT ${terms[0]}`]);
    }
    return pick<unknown>([
      '',
      '   ',
      "Name = 'x'",
      "name != null AND ID != null",
      "Amount__c > 5 AND (Phone = null OR Name LIKE 'A%')",
      "Secret__c = 'x'",
      "Ghost__c = 'x' AND (",
      "(Name = 'x'",
      "Name = 'x')",
      "Name = 'x'; DELETE",
      "Name = 'x' -- c",
      'Id IN (SELECT AccountId FROM Contact)',
      'CreatedDate = LAST_N_DAYS:30',
      'Name = :bind',
      `Name = '${'a'.repeat(2000)}'`,
      42,
    ]);
  };
  const args = {
    objectName,
    fields: fieldsValue(),
    recordId: pick<unknown>([
      '001000000000001AAA',
      '001000000000001AAA',
      '001000000000001',
      ' 001000000000001AAA ',
      undefined,
      'abc',
      '../../limits',
      '001000000000001AAA/../x',
      42,
    ]),
    whereClause: whereClause(),
    limit: pick<unknown>([undefined, 5, 500, 'abc', -1]),
  };
  return JSON.parse(JSON.stringify(args));
}

test('tools/call refuses, answers and calls Salesforce as the handlers it replaced did, on generated arguments', async (t) => {
  t.mock.method(console, 'warn', () => {}); // malformed entries are reported once each; not under test here
  const sf = installSalesforceMock();
  t.after(() => sf.restore());
  sf.addUser(DIFFERENTIAL_TOKEN, {
    userId: '005000000000001AAA',
    organizationId: '00D000000000001AAA',
    username: 'differential.caller@example.com',
    profileId: '00e000000000001AAA',
    profileName: 'Differential',
    instanceUrl: 'https://acme.my.salesforce.com',
  });
  const logRows: LogRow[] = [];
  t.mock.method(store, 'recordCopilotMcpLog', (row: LogRow) => {
    logRows.push(row);
    return undefined as unknown as CopilotMcpLogRecord;
  });

  async function callTool(client: Client, name: string, args: Record<string, unknown> | undefined): Promise<ToolCallEffect> {
    const sfBefore = sf.calls.length;
    const logBefore = logRows.length;
    let result: ToolCallEffect['result'];
    try {
      const res = await client.callTool(args === undefined ? { name } : { name, arguments: args });
      const content = res.content as Array<{ type: string; text?: string }>;
      result = { isError: res.isError === true, text: content[0]?.text ?? '' };
    } catch (err) {
      result = { rpcError: (err as Error).message };
    }
    return {
      result,
      salesforce: sf.calls
        .slice(sfBefore)
        .map((c) => `${c.method} ${c.url.pathname}${c.url.search} ${JSON.stringify(c.body ?? null)}`),
      logRows: logRows
        .slice(logBefore)
        .map(
          ({
            latencyMs: _latencyMs,
            totalMs: _totalMs,
            verificationMs: _verificationMs,
            decision: _decision,
            policySnapshot: _policySnapshot,
            ...row
          }) => row
        ),
      loggedDecisions: logRows.slice(logBefore).map((row) => row.decision),
    };
  }

  const codesSeen = new Set<string>();
  const toolsReachingSalesforce = new Set<string>();
  let calls = 0;
  let statusMoved = 0;
  let objectNameIgnored = 0;
  let threw = 0;
  let ignoredMissingFields = 0;
  let unreadableArgument = 0;

  for (const seed of [4, 5, 6]) {
    const world = buildWorld(t, seed);
    const random = seededRandom(seed * 7919);
    const pick = <T>(values: readonly T[]): T => values[Math.floor(random() * values.length)];
    const clients = await Promise.all(
      world.callers.map(async ({ label, user }) => ({
        label,
        user,
        legacy: await connectClient(t, createLegacyMcpServer(user)),
        current: await connectClient(t, createUserScopedMcpServer(user)),
      }))
    );

    for (let i = 0; i < 1500; i++) {
      const { label, user, legacy, current } = pick(clients);
      let tool = pick(TOOLS);
      // Most calls are aimed at a tool and Object the caller is granted, the rest at anything.
      let aimed: AimedObject | undefined;
      if (random() < 0.6) {
        const effective = resolveEffectiveProfilePermissions(user.profileId, user.profileName);
        const granted = Array.from(effective.objectPermissions.values()).flatMap((o) =>
          Object.entries(CRUD_OF_TOOL)
            .filter(([id, flag]) => effective.allowedActions.has(id) && o[flag])
            .map(([id]) => ({ tool: id, objectName: o.objectName, allowedFields: Array.from(o.allowedFields) }))
        );
        if (granted.length > 0) {
          const target = pick(granted);
          tool = target.tool;
          aimed = target;
        }
      }
      const args = generatedArguments(world, random, aimed);
      const call = `seed ${seed}, ${label}: ${tool}(${JSON.stringify(args)?.slice(0, 300)})`;

      const before = await callTool(legacy, tool, args);
      const now = await callTool(current, tool, args);
      const decision = evaluatePolicy(user, tool, args ?? {}, loadPolicySnapshot());
      codesSeen.add(decision.code);
      calls++;

      // Every row records the decision the call was made on; the legacy rows compare without it.
      assert.deepEqual(now.loggedDecisions, now.logRows.map(() => decision), call);
      const nowEffect = { result: now.result, salesforce: now.salesforce, logRows: now.logRows };
      let expected: Omit<ToolCallEffect, 'loggedDecisions'> = before;
      if ('rpcError' in before.result) {
        // String() of the objectName threw before any check in the old handler, so the call got a
        // JSON-RPC error and no row. Now it is decided as a call without an objectName would be, refused
        // where that one is refused for the missing objectName with the reason the read gave instead,
        // and logged once with the arguments sent.
        threw++;
        assert.match(before.result.rpcError, /Cannot convert object to primitive value/, call);
        assert.deepEqual([before.salesforce, before.logRows], [[], []], call);
        assert.ok(args?.objectName !== undefined, `${call}: only an objectName can throw so`);
        const { objectName: _unreadable, ...withoutObject } = args;
        const asBefore = await callTool(legacy, tool, withoutObject);
        const missing = JSON.stringify(`MCP Action '${tool}' requires an objectName argument.`);
        const withReadError = (text: string) => text.replace(missing, JSON.stringify(decision.reason));
        expected = {
          ...asBefore,
          result: 'text' in asBefore.result ? { ...asBefore.result, text: withReadError(asBefore.result.text) } : asBefore.result,
          logRows: asBefore.logRows.map((row) => ({
            ...row,
            rawRequestPayload: args,
            rawResponseSummary: JSON.parse(withReadError(JSON.stringify(row.rawResponseSummary))),
          })),
        };
        assert.equal(expected.logRows.length, 1, `${call}: logged once`);
      } else if (
        !OBJECT_SCOPED_TOOLS.has(tool) &&
        args?.objectName !== undefined &&
        JSON.stringify(legacyView(legacyEvaluateMcpToolCall(user, tool, targetObjectArgument(args)))) !==
          JSON.stringify(legacyView(legacyEvaluateMcpToolCall(user, tool, undefined)))
      ) {
        // The documented difference: objectName is ignored, so the old answer without one applies,
        // logged under the objectName sent as before.
        assert.equal(tool, 'list_enabled_objects', `${call}: only list_enabled_objects can differ`);
        const { objectName: _ignored, ...withoutObject } = args;
        const asBefore = await callTool(legacy, tool, withoutObject);
        expected = {
          ...asBefore,
          logRows: asBefore.logRows.map((row) => ({ ...row, targetObject: before.logRows[0].targetObject, rawRequestPayload: args })),
        };
        if (JSON.stringify(before.result) !== JSON.stringify(now.result)) {
          objectNameIgnored++;
          assert.match(
            'text' in before.result ? before.result.text : '',
            /is either disabled in Salesforce > Objects/,
            `${call}: the old handler refused the call on its object`
          );
        }
      } else if (before.logRows[0]?.status === 'ERROR' && now.logRows[0]?.status === 'DENIED') {
        // The other documented difference: a malformed argument is a refusal now, logged DENIED.
        statusMoved++;
        assert.deepEqual(before.salesforce, [], `${call}: the old handler refused it before calling Salesforce`);
        assert.equal(decision.code, 'INPUT_INVALID', `${call}: refused as invalid input`);
        expected = { ...before, logRows: before.logRows.map((row) => ({ ...row, status: 'DENIED' as const })) };
      }
      assert.deepEqual(nowEffect, { result: expected.result, salesforce: expected.salesforce, logRows: expected.logRows }, call);

      if (now.salesforce.length > 0) toolsReachingSalesforce.add(tool);
      if (decision.code === 'INPUT_INVALID' && decision.reason === 'Cannot convert object to primitive value') unreadableArgument++;
      if ('text' in now.result && now.result.text.includes('"ignoredMissingFields"')) ignoredMissingFields++;
    }
  }

  // Controls: the generated arguments reach every stage that moved out of the handlers, both
  // documented differences, and every tool that calls Salesforce.
  for (const code of ['ALLOWED', 'FIELD_NOT_PERMITTED', 'WHERE_FIELD_NOT_PERMITTED', 'INPUT_INVALID', 'CRUD_MISSING']) {
    assert.ok(codesSeen.has(code), `some call was decided ${code}: ${[...codesSeen].join(', ')}`);
  }
  assert.deepEqual(
    [...toolsReachingSalesforce].sort(),
    ['create_record', 'delete_record', 'get_record', 'soql_query', 'update_record'],
    'every tool that calls Salesforce did, and nothing else did'
  );
  assert.ok(statusMoved > 0, 'some malformed argument moved from ERROR to DENIED');
  assert.ok(objectNameIgnored > 0, 'some list_enabled_objects call with an objectName was denied before');
  assert.ok(threw > 0, 'some objectName could not be read as text');
  assert.ok(unreadableArgument > 0, 'some selected field could not be read as text');
  assert.ok(ignoredMissingFields > 0, 'some call left out a field missing in the org');
  assert.ok(calls >= 4500, `${calls} calls compared`);
});
