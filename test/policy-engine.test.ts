import './helpers/env.js';
// Pure unit tests for the RBAC policy engine (src/rbac/policyEngine.ts), the Salesforce id
// comparison it relies on (salesforceIdsMatch in src/salesforce/client.ts) and the soql_query
// whereClause guard (src/mcp/soqlGuard.ts). Policy data is seeded through the real store; every
// test uses its own uniquely named objects, groups and Profiles and removes them afterwards.
import { test, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { store } from '../src/db/store.js';
import {
  PolicyViolationError,
  decisionLogStatus,
  evaluateMcpToolCall,
  evaluatePolicy,
  evaluateToolAccess,
  getVisibleToolsForUser,
  loadPolicySnapshot,
  resolveEffectiveProfilePermissions,
  type PolicyDecision,
  type PolicyDecisionCode,
  type PolicyEvaluationResult,
  type PolicyOutcome,
  type PolicyOverrides,
  type PolicySnapshot,
  type PolicyStage,
} from '../src/rbac/policyEngine.js';
import { mergeGrants } from '../src/rbac/groupGrants.js';
import { assertSafeSoqlWhereClause, checkSoqlWhereClause } from '../src/mcp/soqlGuard.js';
import { salesforceIdsMatch, type VerifiedSalesforceUser } from '../src/salesforce/client.js';
import {
  AVAILABLE_MCP_ACTIONS,
  type AccessGroup,
  type GroupObjectPermission,
  type SalesforceObject,
} from '../src/types/governance.js';

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const ALL_ACTIONS: string[] = AVAILABLE_MCP_ACTIONS.map((a) => a.id);
const OBJECT_SCOPED_TOOLS = [
  'describe_object',
  'soql_query',
  'get_record',
  'create_record',
  'update_record',
  'delete_record',
];
const FULL_CRUD = { canRead: true, canCreate: true, canUpdate: true, canDelete: true };

type CrudFlags = Partial<Pick<GroupObjectPermission, 'canRead' | 'canCreate' | 'canUpdate' | 'canDelete'>>;

/** One object entry of a group; every CRUD flag not given is false. */
function grant(objectName: string, flags: CrudFlags, allowedFields: string[]): GroupObjectPermission {
  return {
    objectName,
    canRead: false,
    canCreate: false,
    canUpdate: false,
    canDelete: false,
    ...flags,
    allowedFields,
  };
}

const ID_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

/** Random 15-character Salesforce id. Character 3 is always the letter 'Q', so its case can be flipped. */
function randomSfId15(keyPrefix: string): string {
  const tail = Array.from(crypto.randomBytes(11), (b) => ID_CHARS[b % ID_CHARS.length]).join('');
  return `${keyPrefix}Q${tail}`;
}

/** Salesforce's 18-character form: each 5-char chunk's uppercase positions encoded as one suffix char. */
function to18(id15: string): string {
  assert.equal(id15.length, 15, `to18 needs a 15-character id, got ${id15}`);
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

/** The same 15-character id with the letter at `index` in the other case. */
function withFlippedCase(id15: string, index = 3): string {
  const c = id15[index];
  const flipped = c === c.toUpperCase() ? c.toLowerCase() : c.toUpperCase();
  assert.notEqual(flipped, c, `character ${index} of ${id15} is not a letter`);
  return id15.slice(0, index) + flipped + id15.slice(index + 1);
}

/** The same 15-character id with a different last character. */
function withDifferentLastChar(id15: string): string {
  return id15.slice(0, 14) + (id15[14] === '7' ? '8' : '7');
}

function caller(profileId: string, profileName: string): VerifiedSalesforceUser {
  const n = crypto.randomBytes(4).toString('hex');
  return {
    userId: to18(randomSfId15('005')),
    organizationId: to18(randomSfId15('00D')),
    username: `caller.${n}@example.com`,
    email: `caller.${n}@example.com`,
    displayName: `Policy Test Caller ${n}`,
    profileId,
    profileName,
    instanceUrl: 'https://acme.my.salesforce.com',
    accessToken: `test-access-token-${n}`,
  };
}

interface SeededProfile {
  id: string;
  name: string;
}

/** Seeds policy rows with names unique to one test and deletes them when the test ends. */
class PolicyFixture {
  readonly tag = crypto.randomBytes(4).toString('hex');
  private readonly profileIds: string[] = [];
  private readonly groupIds: string[] = [];
  private readonly objectNames: string[] = [];

  constructor(t: TestContext) {
    t.after(() => {
      for (const id of this.profileIds) store.deleteProfile(id);
      for (const id of this.groupIds) store.deleteGroup(id);
      for (const name of this.objectNames) store.deleteObject(name);
    });
  }

  /** Registers `<base>_<tag>__c` with the given fields (`false` = disabled globally). */
  object(baseName: string, fields: Record<string, boolean>, opts: { enabled?: boolean } = {}): string {
    const objectName = `${baseName}_${this.tag}__c`;
    const enabled = opts.enabled ?? true;
    store.upsertObjectWithFields({
      objectName,
      enabled,
      fields: Object.entries(fields).map(([fieldName, fieldEnabled]) => ({ fieldName, enabled: fieldEnabled })),
    });
    this.objectNames.push(objectName);

    const saved = store.getObjects().find((o) => o.objectName === objectName);
    assert.ok(saved, `seeded object ${objectName}`);
    assert.equal(saved.enabled, enabled, `seeded object ${objectName} enabled flag`);
    for (const [fieldName, fieldEnabled] of Object.entries(fields)) {
      assert.equal(
        saved.fields.find((f) => f.fieldName === fieldName)?.enabled,
        fieldEnabled,
        `seeded field ${objectName}.${fieldName} enabled flag`
      );
    }
    return objectName;
  }

  group(baseName: string, allowedActions: string[], objectPermissions: GroupObjectPermission[] = []): AccessGroup {
    const group = store.createGroup({
      id: `grp_policy_test_${this.tag}_${this.groupIds.length + 1}`,
      name: `${baseName} ${this.tag}`,
      allowedActions,
      objectPermissions,
    });
    this.groupIds.push(group.id);
    return group;
  }

  /** Registers a Profile (18-character id by default) mapped to `groups`. */
  profile(baseName: string, groups: AccessGroup[], id = to18(randomSfId15('00e'))): SeededProfile {
    const name = `${baseName} ${this.tag}`;
    store.upsertProfile(id, name);
    store.setProfileGroups(
      id,
      groups.map((g) => g.id)
    );
    this.profileIds.push(id);
    return { id, name };
  }

  callerFor(profile: SeededProfile): VerifiedSalesforceUser {
    return caller(profile.id, profile.name);
  }

  /** A caller whose Profile id and name are both unknown to the store. */
  unregisteredCaller(): VerifiedSalesforceUser {
    return caller(to18(randomSfId15('00e')), `Unregistered Profile ${this.tag}`);
  }
}

function describeCall(toolName: string, targetObject: string | undefined): string {
  return `${toolName}(${targetObject === undefined ? '<no object>' : JSON.stringify(targetObject)})`;
}

/** The code, failing stage and (when not 'denied') outcome a refused decision must carry. */
interface ExpectedRefusal {
  code: PolicyDecisionCode;
  stage: PolicyStage;
  outcome?: PolicyOutcome;
}

/**
 * Asserts the decision was refused with this code at this stage: every earlier step passed, nothing
 * after the failing step was recorded, and no group decided it.
 */
function assertRefusal(decision: PolicyDecision, expected: ExpectedRefusal, label: string): void {
  const outcome = expected.outcome ?? (expected.code === 'INPUT_INVALID' ? 'invalid' : 'denied');
  const trace = JSON.stringify(decision.steps.map((s) => `${s.stage}:${s.result}`));
  assert.equal(decision.outcome, outcome, `${label} outcome (${decision.code}: ${decision.reason})`);
  assert.equal(decision.code, expected.code, `${label} code (${decision.reason})`);
  assert.equal(decision.steps.at(-1)?.stage, expected.stage, `${label} failing stage, trace ${trace}`);
  assert.equal(decision.steps.at(-1)?.result, 'fail', `${label} the last step fails, trace ${trace}`);
  assert.ok(decision.steps.slice(0, -1).every((s) => s.result === 'pass'), `${label} earlier steps pass, trace ${trace}`);
  assert.deepEqual(decision.decidingGroupIds, [], `${label} a refusal has no deciding groups`);
  assert.deepEqual(decision.steps.at(-1)?.grantingGroupIds, [], `${label} a failed step granted nothing`);
  assert.equal(decision.objectName, null, `${label} a refusal resolves no object`);
  assert.deepEqual(decision.allowedFields, [], `${label} a refusal exposes no fields`);
}

/** Asserts an allowed decision: every step passed and its deciding groups are among the assigned ones. */
function assertAllowedDecision(decision: PolicyDecision, label: string): void {
  assert.equal(decision.outcome, 'allowed', `${label} must be allowed, got ${decision.code}: ${decision.reason}`);
  assert.equal(decision.code, 'ALLOWED', label);
  assert.ok(decision.steps.every((s) => s.result === 'pass'), `${label} every step passes`);
  const assigned = decision.assignedGroups.map((g) => g.id);
  assert.ok(decision.decidingGroupIds.length > 0, `${label} some group decided it`);
  assert.ok(decision.decidingGroupIds.every((id) => assigned.includes(id)), `${label} deciding groups are assigned`);
}

/** Asserts a denial with a matching reason, code and stage, no fields or object leaked, and the same result twice. */
function assertDenied(
  user: VerifiedSalesforceUser,
  toolName: string,
  targetObject: string | undefined,
  reason: RegExp,
  expected: ExpectedRefusal
): PolicyEvaluationResult {
  const call = describeCall(toolName, targetObject);
  const first = evaluateMcpToolCall(user, toolName, targetObject);
  assert.equal(first.permitted, false, `${call} must be denied, got ${JSON.stringify(first)}`);
  assert.equal(typeof first.reason, 'string', `${call} denial carries a reason`);
  assert.match(first.reason, reason, `${call} denial reason`);
  assert.deepEqual(first.allowedFields, [], `${call} denial must not expose fields`);
  assert.equal(first.objectName, undefined, `${call} denial must not resolve an object`);
  assertRefusal(first.decision, expected, call);
  assert.equal(first.decision.reason, first.reason, `${call} the decision carries the same reason`);
  assert.deepEqual(evaluateMcpToolCall(user, toolName, targetObject), first, `${call} denial must be deterministic`);
  return first;
}

function assertPermitted(
  user: VerifiedSalesforceUser,
  toolName: string,
  targetObject?: string
): PolicyEvaluationResult {
  const result = evaluateMcpToolCall(user, toolName, targetObject);
  assert.equal(
    result.permitted,
    true,
    `${describeCall(toolName, targetObject)} must be permitted, got ${JSON.stringify(result)}`
  );
  assertAllowedDecision(result.decision, describeCall(toolName, targetObject));
  return result;
}

/** evaluatePolicy with the call's arguments, on a snapshot read now. */
function decide(
  user: VerifiedSalesforceUser,
  toolName: string,
  args: Record<string, unknown>,
  overrides?: PolicyOverrides
): PolicyDecision {
  return evaluatePolicy(user, toolName, args, loadPolicySnapshot(), overrides);
}

/** The steps as `stage:result[groups]`, for comparing whole traces. */
function trace(decision: PolicyDecision): string[] {
  return decision.steps.map((s) => `${s.stage}:${s.result}[${s.grantingGroupIds.join(',')}]`);
}

const sorted = (values: readonly string[]) => [...values].sort();

// ---------------------------------------------------------------------------
// 1. getVisibleToolsForUser
// ---------------------------------------------------------------------------

test("getVisibleToolsForUser: exposes exactly the union of the Profile's groups' actions, in AVAILABLE_MCP_ACTIONS order", (t) => {
  const fx = new PolicyFixture(t);
  const groupA = fx.group('Visible A', ['soql_query', 'list_enabled_objects']);
  const groupB = fx.group('Visible B', ['delete_record', 'describe_object', 'soql_query']);
  fx.group('Visible Unmapped', ['get_record', 'create_record', 'update_record']); // not mapped to the Profile
  const profile = fx.profile('Visible Profile', [groupA, groupB]);

  const visible = getVisibleToolsForUser(fx.callerFor(profile));

  assert.deepEqual(
    visible.map((a) => a.id),
    ['list_enabled_objects', 'describe_object', 'soql_query', 'delete_record']
  );
  for (const tool of visible) {
    assert.deepEqual(tool, AVAILABLE_MCP_ACTIONS.find((a) => a.id === tool.id), `${tool.id} is the catalog entry`);
  }
});

test('getVisibleToolsForUser: never exposes an unknown action string stored in a group', (t) => {
  const fx = new PolicyFixture(t);
  const group = fx.group('Unknown Actions', [
    'execute_apex',
    'get_record',
    'GET_RECORD',
    'soql_query ',
    '*',
    '__proto__',
    'constructor',
    '',
  ]);
  const profile = fx.profile('Unknown Actions Profile', [group]);

  const visible = getVisibleToolsForUser(fx.callerFor(profile)).map((a) => a.id);

  assert.deepEqual(visible, ['get_record']);
});

test('getVisibleToolsForUser: exposes nothing to a caller whose Profile is not registered', (t) => {
  const fx = new PolicyFixture(t);
  fx.profile('Registered Everything', [fx.group('Everything', ALL_ACTIONS)]);

  assert.deepEqual(getVisibleToolsForUser(fx.unregisteredCaller()), []);
  assert.deepEqual(getVisibleToolsForUser(caller('', '')), [], 'an empty Profile id and name match nothing');
});

test('getVisibleToolsForUser: exposes nothing to a registered Profile with no groups', (t) => {
  const fx = new PolicyFixture(t);
  fx.group('Everything Unmapped', ALL_ACTIONS);
  const profile = fx.profile('Groupless', []);

  assert.deepEqual(getVisibleToolsForUser(fx.callerFor(profile)), []);
});

// ---------------------------------------------------------------------------
// 2. evaluateMcpToolCall denials
// ---------------------------------------------------------------------------

test('evaluateMcpToolCall: denies a caller whose Profile is not registered', (t) => {
  const fx = new PolicyFixture(t);
  const obj = fx.object('Unreg', { Id: true, Name: true });
  fx.profile('Registered Everything', [
    fx.group('Everything', ALL_ACTIONS, [grant(obj, FULL_CRUD, ['Id', 'Name'])]),
  ]);
  const stranger = fx.unregisteredCaller();

  for (const tool of ALL_ACTIONS) {
    const target = tool === 'list_enabled_objects' ? undefined : obj;
    const result = assertDenied(stranger, tool, target, /not registered/i, {
      code: 'PROFILE_UNREGISTERED',
      stage: 'identity',
    });
    assert.deepEqual(result.matchedGroups, []);
    assert.ok(result.reason.includes(stranger.profileId), `reason names the caller's Profile id: ${result.reason}`);
  }
});

test('evaluateMcpToolCall: denies a registered Profile that has no groups', (t) => {
  const fx = new PolicyFixture(t);
  const obj = fx.object('NoGroups', { Id: true, Name: true });
  fx.group('Everything Unmapped', ALL_ACTIONS, [grant(obj, FULL_CRUD, ['Id', 'Name'])]);
  const user = fx.callerFor(fx.profile('Groupless', []));

  for (const tool of ALL_ACTIONS) {
    const target = tool === 'list_enabled_objects' ? undefined : obj;
    const result = assertDenied(user, tool, target, /no Groups/i, { code: 'NO_GROUPS', stage: 'groups' });
    assert.deepEqual(result.matchedGroups, []);
  }
});

test("evaluateMcpToolCall: denies a known tool that none of the Profile's groups grant", (t) => {
  const fx = new PolicyFixture(t);
  const obj = fx.object('NotGranted', { Id: true, Name: true });
  // Full CRUD on the object but only two actions: CRUD flags alone must not unlock other tools.
  const readers = fx.group('Readers', ['soql_query', 'get_record'], [grant(obj, FULL_CRUD, ['Id', 'Name'])]);
  const user = fx.callerFor(fx.profile('Readers Profile', [readers]));

  assertPermitted(user, 'soql_query', obj);
  for (const tool of ['list_enabled_objects', 'describe_object', 'create_record', 'update_record', 'delete_record']) {
    const target = tool === 'list_enabled_objects' ? undefined : obj;
    const result = assertDenied(user, tool, target, /not granted/i, { code: 'TOOL_NOT_GRANTED', stage: 'tool_grant' });
    assert.ok(result.reason.includes(tool), `reason names the tool: ${result.reason}`);
  }
});

test('evaluateMcpToolCall: denies an unknown tool name even when a group lists it', (t) => {
  const fx = new PolicyFixture(t);
  const obj = fx.object('UnknownTool', { Id: true, Name: true });
  const unknownTools = ['execute_apex', 'run_anonymous_apex', 'SOQL_QUERY', '__proto__', 'constructor'];
  const group = fx.group('Lists Unknown Tools', [...ALL_ACTIONS, ...unknownTools], [
    grant(obj, FULL_CRUD, ['Id', 'Name']),
  ]);
  const user = fx.callerFor(fx.profile('Unknown Tools Profile', [group]));

  for (const tool of unknownTools) {
    assertDenied(user, tool, obj, /unknown/i, { code: 'TOOL_UNKNOWN', stage: 'tool' });
    assertDenied(user, tool, undefined, /unknown/i, { code: 'TOOL_UNKNOWN', stage: 'tool' });
  }
});

test("evaluateMcpToolCall: denies object-scoped tools called with no object or with '*'", (t) => {
  const fx = new PolicyFixture(t);
  const obj = fx.object('NoTarget', { Id: true, Name: true });
  const group = fx.group('Everything', ALL_ACTIONS, [grant(obj, FULL_CRUD, ['Id', 'Name'])]);
  const user = fx.callerFor(fx.profile('No Target Profile', [group]));

  for (const tool of OBJECT_SCOPED_TOOLS) {
    assertPermitted(user, tool, obj); // control: the same call naming the object is allowed
    for (const target of [undefined, '', '*']) {
      assertDenied(user, tool, target, /requires an objectName/i, { code: 'INPUT_INVALID', stage: 'input' });
    }
  }
});

test("evaluateMcpToolCall: denies an object that none of the Profile's groups grant", (t) => {
  const fx = new PolicyFixture(t);
  const granted = fx.object('Granted', { Id: true, Name: true });
  const other = fx.object('Other', { Id: true, Name: true }); // enabled globally, granted only to an unmapped group
  const group = fx.group('Granted Only', ALL_ACTIONS, [grant(granted, FULL_CRUD, ['Id', 'Name'])]);
  fx.group('Other Unmapped', ALL_ACTIONS, [grant(other, FULL_CRUD, ['Id', 'Name'])]);
  const user = fx.callerFor(fx.profile('Granted Profile', [group]));

  assertPermitted(user, 'soql_query', granted);
  for (const tool of OBJECT_SCOPED_TOOLS) {
    assertDenied(user, tool, other, /not permitted/i, { code: 'OBJECT_NOT_GRANTED', stage: 'object' });
    assertDenied(user, tool, `Missing_${fx.tag}__c`, /not permitted/i, { code: 'OBJECT_NOT_GRANTED', stage: 'object' });
  }
});

test('evaluateMcpToolCall: denies every object-scoped tool on an object whose group entry sets no CRUD flag', (t) => {
  const fx = new PolicyFixture(t);
  const obj = fx.object('NoFlags', { Id: true, Name: true });
  const group = fx.group('No Flags', ALL_ACTIONS, [grant(obj, {}, ['Id', 'Name'])]);
  const user = fx.callerFor(fx.profile('No Flags Profile', [group]));

  for (const tool of OBJECT_SCOPED_TOOLS) {
    assertDenied(user, tool, obj, /not permitted/i, { code: 'OBJECT_NOT_GRANTED', stage: 'object' });
  }
});

test('evaluateMcpToolCall: denies every object-scoped tool on an object disabled globally in Salesforce > Objects', (t) => {
  const fx = new PolicyFixture(t);
  const toggled = fx.object('Toggled', { Id: true, Name: true });
  const seededDisabled = fx.object('SeededOff', { Id: true, Name: true }, { enabled: false });
  const group = fx.group('Everything', ALL_ACTIONS, [
    grant(toggled, FULL_CRUD, ['Id', 'Name']),
    grant(seededDisabled, FULL_CRUD, ['Id', 'Name']),
  ]);
  const user = fx.callerFor(fx.profile('Disabled Profile', [group]));
  for (const tool of OBJECT_SCOPED_TOOLS) {
    assertPermitted(user, tool, toggled); // control: allowed while the object is enabled
  }

  store.toggleObject(toggled, false);

  for (const tool of OBJECT_SCOPED_TOOLS) {
    // Granted, but switched off in Salesforce > Objects: blocked, not "not granted".
    assertDenied(user, tool, toggled, /disabled/i, { code: 'OBJECT_BLOCKED', stage: 'object' });
    assertDenied(user, tool, seededDisabled, /disabled/i, { code: 'OBJECT_BLOCKED', stage: 'object' });
  }
});

test('evaluateMcpToolCall: denies read tools (describe_object, soql_query, get_record) without canRead', (t) => {
  const fx = new PolicyFixture(t);
  const obj = fx.object('NoRead', { Id: true, Name: true });
  const group = fx.group('Writers', ALL_ACTIONS, [
    grant(obj, { canCreate: true, canUpdate: true, canDelete: true }, ['Id', 'Name']),
  ]);
  const user = fx.callerFor(fx.profile('Writers Profile', [group]));

  assertPermitted(user, 'create_record', obj); // control: the object itself is granted
  for (const tool of ['describe_object', 'soql_query', 'get_record']) {
    assertDenied(user, tool, obj, /read access/i, { code: 'CRUD_MISSING', stage: 'crud' });
  }
});

test('evaluateMcpToolCall: denies create_record without canCreate', (t) => {
  const fx = new PolicyFixture(t);
  const obj = fx.object('NoCreate', { Id: true, Name: true });
  const group = fx.group('No Create', ALL_ACTIONS, [
    grant(obj, { canRead: true, canUpdate: true, canDelete: true }, ['Id', 'Name']),
  ]);
  const user = fx.callerFor(fx.profile('No Create Profile', [group]));

  assertPermitted(user, 'update_record', obj); // control
  assertDenied(user, 'create_record', obj, /create access/i, { code: 'CRUD_MISSING', stage: 'crud' });
});

test('evaluateMcpToolCall: denies update_record without canUpdate', (t) => {
  const fx = new PolicyFixture(t);
  const obj = fx.object('NoUpdate', { Id: true, Name: true });
  const group = fx.group('No Update', ALL_ACTIONS, [
    grant(obj, { canRead: true, canCreate: true, canDelete: true }, ['Id', 'Name']),
  ]);
  const user = fx.callerFor(fx.profile('No Update Profile', [group]));

  assertPermitted(user, 'create_record', obj); // control
  assertDenied(user, 'update_record', obj, /update access/i, { code: 'CRUD_MISSING', stage: 'crud' });
});

test('evaluateMcpToolCall: denies delete_record without canDelete', (t) => {
  const fx = new PolicyFixture(t);
  const obj = fx.object('NoDelete', { Id: true, Name: true });
  const group = fx.group('No Delete', ALL_ACTIONS, [
    grant(obj, { canRead: true, canCreate: true, canUpdate: true }, ['Id', 'Name']),
  ]);
  const user = fx.callerFor(fx.profile('No Delete Profile', [group]));

  assertPermitted(user, 'update_record', obj); // control
  assertDenied(user, 'delete_record', obj, /delete access/i, { code: 'CRUD_MISSING', stage: 'crud' });
});

// ---------------------------------------------------------------------------
// 3. evaluateMcpToolCall permits
// ---------------------------------------------------------------------------

test('evaluateMcpToolCall: permits a granted tool on a granted object and lists the matched group', (t) => {
  const fx = new PolicyFixture(t);
  const obj = fx.object('Permit', { Id: true, Name: true });
  const group = fx.group('Permit Readers', ['soql_query'], [grant(obj, { canRead: true }, ['Id', 'Name'])]);
  const user = fx.callerFor(fx.profile('Permit Profile', [group]));

  const result = assertPermitted(user, 'soql_query', obj);

  assert.deepEqual(result.matchedGroups, [group.name]);
  assert.equal(result.objectName, obj);
  assert.deepEqual(sorted(result.allowedFields), ['Id', 'Name']);
  assert.ok(result.reason.length > 0, 'a permit also carries a reason');
  // Without the call's arguments the wrapper checks the tool and the Object only.
  assert.deepEqual(trace(result.decision), [
    'tool:pass[]',
    'identity:pass[]',
    'groups:pass[]',
    `tool_grant:pass[${group.id}]`,
    `object:pass[${group.id}]`,
    `crud:pass[${group.id}]`,
  ]);
  assert.deepEqual(result.decision.decidingGroupIds, [group.id]);
  assert.equal(result.decision.objectName, obj);
});

test("evaluateMcpToolCall: allowedFields is the groups' allowedFields intersected with the globally enabled fields", (t) => {
  const fx = new PolicyFixture(t);
  const obj = fx.object('Intersect', {
    Id: true,
    Name: true,
    Amount__c: true,
    Stage__c: true, // enabled globally, but no group grants it
    Secret__c: false, // granted by both groups, but disabled globally
  });
  const one = fx.group('Intersect One', ['soql_query'], [
    grant(obj, { canRead: true }, ['Id', 'Name', 'Secret__c', 'Ghost__c']), // Ghost__c is not a field of the object
  ]);
  const two = fx.group('Intersect Two', ['soql_query'], [grant(obj, { canRead: true }, ['Amount__c', 'Secret__c'])]);
  const user = fx.callerFor(fx.profile('Intersect Profile', [one, two]));

  const result = assertPermitted(user, 'soql_query', obj);

  assert.deepEqual(sorted(result.allowedFields), ['Amount__c', 'Id', 'Name']);
});

test('evaluateMcpToolCall: a field disabled globally never appears in allowedFields, for any tool', (t) => {
  const fx = new PolicyFixture(t);
  const obj = fx.object('FieldOff', { Id: true, Name: true, Salary__c: true });
  const one = fx.group('FieldOff One', ALL_ACTIONS, [grant(obj, FULL_CRUD, ['Id', 'Name', 'Salary__c'])]);
  const two = fx.group('FieldOff Two', ALL_ACTIONS, [grant(obj, { canRead: true }, ['Salary__c'])]);
  const user = fx.callerFor(fx.profile('FieldOff Profile', [one, two]));
  assert.ok(
    assertPermitted(user, 'soql_query', obj).allowedFields.includes('Salary__c'),
    'control: Salary__c is allowed while it is enabled'
  );

  store.toggleObjectField(obj, 'Salary__c', false);

  for (const tool of OBJECT_SCOPED_TOOLS) {
    const result = assertPermitted(user, tool, obj);
    assert.deepEqual(sorted(result.allowedFields), ['Id', 'Name'], `${tool} allowedFields`);
  }
});

test("evaluateMcpToolCall: unions CRUD flags and allowed fields across the Profile's groups", (t) => {
  const fx = new PolicyFixture(t);
  const obj = fx.object('Union', { Id: true, Name: true, Subject__c: true, Priority__c: true });
  const readers = fx.group('Union Readers', ['soql_query', 'get_record'], [
    grant(obj, { canRead: true }, ['Id', 'Name']),
  ]);
  const writers = fx.group('Union Writers', ['create_record', 'update_record'], [
    grant(obj, { canCreate: true, canUpdate: true }, ['Subject__c']),
  ]);
  const deleters = fx.group('Union Deleters', ['delete_record'], [grant(obj, { canDelete: true }, [])]);
  const user = fx.callerFor(fx.profile('Union Profile', [readers, writers, deleters]));
  const expectedGroups = sorted([readers.name, writers.name, deleters.name]);

  for (const tool of ['soql_query', 'get_record', 'create_record', 'update_record', 'delete_record']) {
    const result = assertPermitted(user, tool, obj);
    assert.deepEqual(sorted(result.matchedGroups), expectedGroups, `${tool} matchedGroups`);
    assert.deepEqual(sorted(result.allowedFields), ['Id', 'Name', 'Subject__c'], `${tool} allowedFields`);
    assert.equal(result.objectName, obj, `${tool} objectName`);
  }
});

test('evaluateMcpToolCall: combines a tool granted by one group with object access granted by another', (t) => {
  const fx = new PolicyFixture(t);
  const obj = fx.object('Cross', { Id: true, Name: true });
  const toolsOnly = fx.group('Cross Tools', ['get_record', 'delete_record'], []);
  const accessOnly = fx.group('Cross Access', [], [grant(obj, { canRead: true, canDelete: true }, ['Name'])]);
  const user = fx.callerFor(fx.profile('Cross Profile', [toolsOnly, accessOnly]));

  const read = assertPermitted(user, 'get_record', obj);
  assert.deepEqual(read.allowedFields, ['Name']);
  assertPermitted(user, 'delete_record', obj);

  // Still allowed, and the trace shows which group gave what: the tool from one, the Object, the
  // operation and the field from the other.
  const decision = decide(user, 'get_record', { objectName: obj, recordId: to18(randomSfId15('a01')), fields: ['Name'] });
  assertAllowedDecision(decision, 'get_record with arguments');
  assert.deepEqual(trace(decision), [
    'tool:pass[]',
    'identity:pass[]',
    'groups:pass[]',
    `tool_grant:pass[${toolsOnly.id}]`,
    `object:pass[${accessOnly.id}]`,
    `crud:pass[${accessOnly.id}]`,
    `fields:pass[${accessOnly.id}]`,
    'input:pass[]',
  ]);
  assert.deepEqual(decision.steps.find((s) => s.stage === 'fields')?.fieldNames, ['Name']);
  assert.deepEqual(sorted(decision.decidingGroupIds), sorted([toolsOnly.id, accessOnly.id]));
  assert.deepEqual(sorted(read.decision.decidingGroupIds), sorted([toolsOnly.id, accessOnly.id]));
});

test('evaluatePolicy: per-step groups follow each capability, the per-entry Id fallback included, and unrelated groups do not decide', (t) => {
  const fx = new PolicyFixture(t);
  const obj = fx.object('Provenance', { Id: true, Name: true, Phone: true });
  const other = fx.object('ProvenanceOther', { Id: true, Name: true });
  const named = fx.group('A Provenance Named', ['soql_query'], [grant(obj, { canRead: true }, ['Name'])]);
  // Lists no field, so it gives Id (the per-entry fallback), and grants no tool.
  const fieldless = fx.group('B Provenance Fieldless', [], [grant(obj, { canRead: true, canUpdate: true }, [])]);
  const phone = fx.group('C Provenance Phone', ['update_record'], [grant(obj, { canUpdate: true }, ['phone'])]);
  const unrelated = fx.group('D Provenance Unrelated', ['soql_query'], [grant(other, FULL_CRUD, ['Id', 'Name'])]);
  const user = fx.callerFor(fx.profile('Provenance Profile', [named, fieldless, phone, unrelated]));

  const byId = decide(user, 'soql_query', { objectName: obj, fields: ['Id'] });
  assertAllowedDecision(byId, 'soql_query Id');
  assert.deepEqual(trace(byId), [
    'tool:pass[]',
    'identity:pass[]',
    'groups:pass[]',
    `tool_grant:pass[${named.id},${unrelated.id}]`,
    `object:pass[${named.id},${fieldless.id},${phone.id}]`,
    `crud:pass[${named.id},${fieldless.id}]`,
    `fields:pass[${fieldless.id}]`,
    'where:pass[]',
    'input:pass[]',
  ]);
  assert.deepEqual(byId.decidingGroupIds, [named.id, fieldless.id, phone.id, unrelated.id]);

  const byName = decide(user, 'soql_query', { objectName: obj.toUpperCase(), fields: ['NAME'], whereClause: "name != null AND ID != null" });
  assertAllowedDecision(byName, 'soql_query Name');
  assert.deepEqual(byName.steps.find((s) => s.stage === 'fields')?.grantingGroupIds, [named.id]);
  const where = byName.steps.find((s) => s.stage === 'where');
  assert.deepEqual(where?.fieldNames, ['name', 'ID']);
  assert.deepEqual(where?.grantingGroupIds, [named.id, fieldless.id]);
  assert.equal(byName.objectName, obj, 'the catalog spelling');
  assert.ok(byName.steps.slice(4).every((s) => s.objectName === obj), 'the object-scoped steps name the Object');

  // The write: the tool from C, Update from B and C, Phone (granted as 'phone') from C only.
  const write = decide(user, 'update_record', { objectName: obj, recordId: to18(randomSfId15('a01')), fields: { Phone: '1' } });
  assertAllowedDecision(write, 'update_record Phone');
  assert.deepEqual(trace(write).slice(3), [
    `tool_grant:pass[${phone.id}]`,
    `object:pass[${named.id},${fieldless.id},${phone.id}]`,
    `crud:pass[${fieldless.id},${phone.id}]`,
    `fields:pass[${phone.id}]`,
    'input:pass[]',
  ]);
  assert.deepEqual(write.decidingGroupIds, [named.id, fieldless.id, phone.id], 'D grants another tool and Object only');
});

test("evaluateMcpToolCall: allowedFields do not depend on the alphabetical order of the Profile's group names", (t) => {
  const fx = new PolicyFixture(t);
  const obj = fx.object('Order', { Id: true, Name: true, Secret__c: true });
  // The same two group definitions behind two Profiles; only which group's name sorts first differs.
  // One group's entry lists Secret__c without setting any CRUD flag, the other grants Read on Id and Name.
  const noGrantFirst = fx.profile('Order NoGrant First', [
    fx.group('A Order NoGrant', ['soql_query'], [grant(obj, {}, ['Secret__c'])]),
    fx.group('B Order Reader', ['soql_query'], [grant(obj, { canRead: true }, ['Id', 'Name'])]),
  ]);
  const readerFirst = fx.profile('Order Reader First', [
    fx.group('A Order Reader', ['soql_query'], [grant(obj, { canRead: true }, ['Id', 'Name'])]),
    fx.group('B Order NoGrant', ['soql_query'], [grant(obj, {}, ['Secret__c'])]),
  ]);

  const whenNoGrantSortsFirst = assertPermitted(fx.callerFor(noGrantFirst), 'soql_query', obj);
  const whenReaderSortsFirst = assertPermitted(fx.callerFor(readerFirst), 'soql_query', obj);

  assert.deepEqual(
    sorted(whenReaderSortsFirst.allowedFields),
    sorted(whenNoGrantSortsFirst.allowedFields),
    'identical group definitions must yield identical allowedFields whatever the groups are named'
  );
});

test('evaluateMcpToolCall: an entry with no enabled fields adds Id whichever group name sorts first', (t) => {
  const fx = new PolicyFixture(t);
  const obj = fx.object('IdSwap', { Id: true, Name: true, Secret__c: false });
  // Each form of "no resolvable fields": none listed, only a globally disabled field, only a field the object lacks.
  for (const noFields of [[], ['Secret__c'], ['Ghost__c']]) {
    const label = JSON.stringify(noFields);
    const fieldlessFirst = fx.profile(`IdSwap Fieldless First ${label}`, [
      fx.group(`A IdSwap Fieldless ${label}`, ['soql_query'], [grant(obj, { canRead: true }, noFields)]),
      fx.group(`B IdSwap Name ${label}`, ['soql_query'], [grant(obj, { canRead: true }, ['Name'])]),
    ]);
    const nameFirst = fx.profile(`IdSwap Name First ${label}`, [
      fx.group(`A IdSwap Name ${label}`, ['soql_query'], [grant(obj, { canRead: true }, ['Name'])]),
      fx.group(`B IdSwap Fieldless ${label}`, ['soql_query'], [grant(obj, { canRead: true }, noFields)]),
    ]);

    for (const profile of [fieldlessFirst, nameFirst]) {
      assert.deepEqual(
        sorted(assertPermitted(fx.callerFor(profile), 'soql_query', obj).allowedFields),
        ['Id', 'Name'],
        profile.name
      );
    }
  }
});

test('evaluateMcpToolCall: a Delete-only entry with no fields adds no Id, in either group order', (t) => {
  const fx = new PolicyFixture(t);
  const obj = fx.object('IdDeleteOnly', { Id: true, Name: true });
  // delete_record reads no field, so Delete-only access must not make Id readable through soql_query or get_record.
  const deleteFirst = fx.profile('IdDeleteOnly Delete First', [
    fx.group('A IdDeleteOnly Delete', ['soql_query'], [grant(obj, { canDelete: true }, [])]),
    fx.group('B IdDeleteOnly Name', ['soql_query'], [grant(obj, { canRead: true }, ['Name'])]),
  ]);
  const nameFirst = fx.profile('IdDeleteOnly Name First', [
    fx.group('A IdDeleteOnly Name', ['soql_query'], [grant(obj, { canRead: true }, ['Name'])]),
    fx.group('B IdDeleteOnly Delete', ['soql_query'], [grant(obj, { canDelete: true }, [])]),
  ]);

  for (const profile of [deleteFirst, nameFirst]) {
    assert.deepEqual(sorted(assertPermitted(fx.callerFor(profile), 'soql_query', obj).allowedFields), ['Name'], profile.name);
  }
});

test('resolveEffectiveProfilePermissions: the Id fallback keeps every field the merged-set rule gave, in every group order', (t) => {
  const fx = new PolicyFixture(t);
  const enabledFields = ['Id', 'Name'];
  const obj = fx.object('IdSuperset', { Id: true, Name: true, Secret__c: false });
  const entries: Record<string, GroupObjectPermission> = {
    ReadNone: grant(obj, { canRead: true }, []),
    ReadName: grant(obj, { canRead: true }, ['Name']),
    UpdateDisabled: grant(obj, { canUpdate: true }, ['Secret__c']),
    DeleteNone: grant(obj, { canDelete: true }, []),
  };

  // The rule before the fix: Id was added only while the fields merged so far were still empty.
  const mergedSetRule = (order: GroupObjectPermission[]): string[] => {
    const fields = new Set<string>();
    let readCreateOrUpdate = false;
    for (const entry of order) {
      readCreateOrUpdate ||= entry.canRead || entry.canCreate || entry.canUpdate;
      for (const f of entry.allowedFields) if (enabledFields.includes(f)) fields.add(f);
      if (fields.size === 0 && readCreateOrUpdate) fields.add('Id');
    }
    return sorted([...fields]);
  };

  // Every non-empty selection of the entries, in every order.
  const orders: string[][] = [];
  const arrange = (prefix: string[], rest: string[]) => {
    if (prefix.length > 0) orders.push(prefix);
    rest.forEach((key, i) => arrange([...prefix, key], [...rest.slice(0, i), ...rest.slice(i + 1)]));
  };
  arrange([], Object.keys(entries));

  const resultBySet = new Map<string, string[]>();
  let ordersThatGainId = 0;
  for (const order of orders) {
    // A leading letter per position makes the groups' name order follow `order`.
    const groups = order.map((key, i) =>
      fx.group(`${String.fromCharCode(65 + i)} IdSuperset ${order.join(' ')} ${key}`, [], [entries[key]])
    );
    const profile = fx.profile(`IdSuperset ${order.join(' ')}`, groups);
    const effective = resolveEffectiveProfilePermissions(profile.id, profile.name);
    const result = sorted([...(effective.objectPermissions.get(obj)?.allowedFields ?? [])]);
    const before = mergedSetRule(order.map((key) => entries[key]));

    for (const field of before) {
      assert.ok(result.includes(field), `${order.join(' > ')}: keeps ${field} (before: ${before}, now: ${result})`);
    }
    if (result.length > before.length) ordersThatGainId++;

    const setKey = sorted(order).join(' ');
    const sameSet = resultBySet.get(setKey);
    if (sameSet) {
      assert.deepEqual(result, sameSet, `${order.join(' > ')}: same allowedFields as any other order of ${setKey}`);
    } else {
      resultBySet.set(setKey, result);
    }
  }
  assert.ok(ordersThatGainId > 0, 'control: some orders gain Id that the merged-set rule left out');
});

test('evaluateMcpToolCall: matches the object name case-insensitively and returns the canonical API name', (t) => {
  const fx = new PolicyFixture(t);
  const obj = fx.object('Invoice', { Id: true, Name: true, Total__c: true }); // canonical: Invoice_<tag>__c
  const group = fx.group('Invoice Team', ['soql_query', 'update_record'], [
    grant(obj.toLowerCase(), { canRead: true, canUpdate: true }, ['Name', 'Total__c']),
  ]);
  const user = fx.callerFor(fx.profile('Invoice Profile', [group]));

  for (const target of [obj.toUpperCase(), obj.toLowerCase(), obj]) {
    for (const tool of ['soql_query', 'update_record']) {
      const result = assertPermitted(user, tool, target);
      assert.equal(result.objectName, obj, `${describeCall(tool, target)} objectName`);
      assert.deepEqual(sorted(result.allowedFields), ['Name', 'Total__c']);
    }
  }
});

// Groups saved by an older version hold their grants as they were sent. The engine must neither grant
// on a value that only looks like a flag nor throw on an entry it cannot read.
test("evaluateMcpToolCall: a flag grants only when it is exactly true; an entry with any other value is skipped whole", (t) => {
  const fx = new PolicyFixture(t);
  const obj = fx.object('StrictFlags', { Id: true, Name: true });
  const group = fx.group('Strict Flags', OBJECT_SCOPED_TOOLS, [
    { ...grant(obj, { canDelete: true }, ['Id', 'Name']), canRead: 'false' } as never,
  ]);
  const user = fx.callerFor(fx.profile('Strict Flags Profile', [group]));

  const notGranted = { code: 'OBJECT_NOT_GRANTED', stage: 'object' } as const;
  for (const tool of OBJECT_SCOPED_TOOLS) assertDenied(user, tool, obj, /either disabled .* or not permitted/, notGranted);
  const denied = assertDenied(user, 'soql_query', obj, /not permitted/, notGranted);
  assert.deepEqual(denied.decision.skippedGroupEntries, denied.skippedGroupEntries, 'the decision carries them too');
  assert.deepEqual(denied.skippedGroupEntries, [
    { groupId: group.id, index: 0, reason: 'canRead is not true or false' },
  ]);
});

test('resolveEffectiveProfilePermissions: skips each malformed stored entry, records why, and keeps the others', (t) => {
  const warnings: string[] = [];
  t.mock.method(console, 'warn', (message: string) => warnings.push(message));
  const fx = new PolicyFixture(t);
  const obj = fx.object('Malformed', { Id: true, Name: true, Secret__c: true });
  const secret = `secret-${fx.tag}`;
  const malformed = [
    null,
    `free text ${secret}`,
    [obj],
    { objectName: 7, canRead: true },
    { ...grant(obj, { canRead: true }, ['Secret__c']), canUpdate: secret },
    { ...grant(obj, { canRead: true }, []), allowedFields: secret },
    { ...grant(obj, { canRead: true }, []), allowedFields: ['Secret__c', 7] },
  ];
  const group = fx.group('Malformed', ['soql_query'], [...malformed, grant(obj, { canRead: true }, ['Name'])] as never);
  const profile = fx.profile('Malformed Profile', [group]);

  const effective = resolveEffectiveProfilePermissions(profile.id);
  assert.deepEqual(sorted([...(effective.objectPermissions.get(obj)?.allowedFields ?? [])]), ['Name']);
  assert.deepEqual(effective.skippedGroupEntries, [
    { groupId: group.id, index: 0, reason: 'the entry is not an object' },
    { groupId: group.id, index: 1, reason: 'the entry is not an object' },
    { groupId: group.id, index: 2, reason: 'the entry is not an object' },
    { groupId: group.id, index: 3, reason: 'objectName is not text' },
    { groupId: group.id, index: 4, reason: 'canUpdate is not true or false' },
    { groupId: group.id, index: 5, reason: 'allowedFields is not a list of field names' },
    { groupId: group.id, index: 6, reason: 'allowedFields is not a list of field names' },
  ]);
  const permitted = assertPermitted(fx.callerFor(profile), 'soql_query', obj);
  assert.deepEqual(permitted.allowedFields, ['Name']);
  assert.equal(permitted.skippedGroupEntries?.length, 7);

  // Told once per entry and reason, by key only: evaluating again warns no more, and no value is logged.
  resolveEffectiveProfilePermissions(profile.id);
  assert.equal(warnings.length, 7);
  for (const warning of warnings) {
    assert.match(warning, new RegExp(`Access Group ${group.id}: object entry \\d is skipped`));
    assert.ok(!warning.includes(secret), warning);
  }
});

// POST /groups, the group editor and the upgrade migration merge a group's entries for one Object.
test('mergeGrants: a merged entry gives what its entries gave one by one, including the Id fallback of each', (t) => {
  const fx = new PolicyFixture(t);
  const obj = fx.object('MergeId', { Id: true, Name: true, Phone: false });
  const catalogFields = (objectName: string) => store.getObjectFieldNames(store.resolveObjectName(objectName)) ?? [];
  let n = 0;
  const effectiveFields = (entries: GroupObjectPermission[]) => {
    n++;
    const group = fx.group(`Merge Id ${n}`, ['soql_query'], entries);
    const profile = fx.profile(`Merge Id ${n}`, [group]);
    return sorted([...(resolveEffectiveProfilePermissions(profile.id).objectPermissions.get(obj)?.allowedFields ?? [])]);
  };

  const sameAccess: Array<[string, GroupObjectPermission[]]> = [
    ['an entry with no field', [grant(obj.toLowerCase(), { canRead: true }, []), grant(obj, { canUpdate: true }, ['Name'])]],
    ['an entry with only unknown fields', [grant(obj, { canCreate: true }, ['Gone__c']), grant(obj.toUpperCase(), { canRead: true }, ['name'])]],
    ['an entry that only deletes, which has no fallback', [grant(obj, { canDelete: true }, []), grant(obj, { canRead: true }, ['Name'])]],
    ['an entry that grants nothing', [grant(obj, {}, []), grant(obj, { canRead: true }, ['Name'])]],
  ];
  for (const [label, entries] of sameAccess) {
    const merged = mergeGrants(entries, catalogFields);
    assert.equal(merged.length, 1, label);
    assert.deepEqual(effectiveFields(merged), effectiveFields(entries), label);
  }
  assert.deepEqual(mergeGrants(sameAccess[0][1], catalogFields)[0].allowedFields, ['Name', 'Id']);

  // An entry whose fields all exist but are disabled falls back to Id only while they stay disabled,
  // so no stored list gives the same in both states: the merged entry keeps the narrower one.
  const disabledOnly = [grant(obj, { canRead: true }, ['Phone']), grant(obj, { canRead: true }, ['Name'])];
  assert.deepEqual(effectiveFields(disabledOnly), ['Id', 'Name']);
  assert.deepEqual(effectiveFields(mergeGrants(disabledOnly, catalogFields)), ['Name']);
});

test('evaluateMcpToolCall: a well-formed group adds no skippedGroupEntries property', (t) => {
  const fx = new PolicyFixture(t);
  const obj = fx.object('WellFormed', { Id: true });
  const group = fx.group('Well Formed', ['soql_query'], [grant(obj, { canRead: true }, ['Id'])]);
  const result = assertPermitted(fx.callerFor(fx.profile('Well Formed Profile', [group])), 'soql_query', obj);
  assert.equal('skippedGroupEntries' in result, false);
});

test('evaluateMcpToolCall: permits list_enabled_objects without an object', (t) => {
  const fx = new PolicyFixture(t);
  const group = fx.group('Discovery', ['list_enabled_objects']);
  const user = fx.callerFor(fx.profile('Discovery Profile', [group]));

  for (const target of [undefined, '*']) {
    const result = assertPermitted(user, 'list_enabled_objects', target);
    assert.deepEqual(result.matchedGroups, [group.name]);
    assert.deepEqual(result.allowedFields, []);
    assert.equal(result.objectName, undefined);
  }
});

// ---------------------------------------------------------------------------
// 4. Profile resolution and salesforceIdsMatch
// ---------------------------------------------------------------------------

test('profile resolution: a Profile registered with a 15-character id matches a caller presenting the 18-character form', (t) => {
  const fx = new PolicyFixture(t);
  const obj = fx.object('Res15', { Id: true, Name: true });
  const group = fx.group('Res15 Readers', ['soql_query'], [grant(obj, { canRead: true }, ['Name'])]);
  const id15 = randomSfId15('00e');
  fx.profile('Res15 Profile', [group], id15);
  // The caller reports a Profile name that is not registered, so only the id can match.
  const user = caller(to18(id15), `Caller Side Name ${fx.tag}`);

  assert.deepEqual(getVisibleToolsForUser(user).map((a) => a.id), ['soql_query']);
  assert.deepEqual(assertPermitted(user, 'soql_query', obj).matchedGroups, [group.name]);
});

test('profile resolution: a Profile registered with an 18-character id matches a caller presenting the 15-character form', (t) => {
  const fx = new PolicyFixture(t);
  const obj = fx.object('Res18', { Id: true, Name: true });
  const group = fx.group('Res18 Readers', ['soql_query'], [grant(obj, { canRead: true }, ['Name'])]);
  const id15 = randomSfId15('00e');
  fx.profile('Res18 Profile', [group], to18(id15));
  const user = caller(id15, `Caller Side Name ${fx.tag}`);

  assert.deepEqual(getVisibleToolsForUser(user).map((a) => a.id), ['soql_query']);
  assert.deepEqual(assertPermitted(user, 'soql_query', obj).matchedGroups, [group.name]);
});

test('profile resolution: a caller whose ProfileId has a different 15-character prefix is not matched', (t) => {
  const fx = new PolicyFixture(t);
  const obj = fx.object('ResDiff', { Id: true, Name: true });
  const group = fx.group('ResDiff Everything', ALL_ACTIONS, [grant(obj, FULL_CRUD, ['Name'])]);
  const id15 = randomSfId15('00e');
  fx.profile('ResDiff Profile', [group], id15);
  const lookalikes = [
    to18(withDifferentLastChar(id15)), // one character differs
    withDifferentLastChar(id15),
    to18(withFlippedCase(id15)), // differs only in letter case: 15-character ids are case-sensitive
    withFlippedCase(id15),
    withFlippedCase(id15) + to18(id15).slice(15), // case-flipped id carrying the original checksum suffix
  ];

  for (const profileId of lookalikes) {
    const user = caller(profileId, `Lookalike ${fx.tag}`);
    assert.deepEqual(getVisibleToolsForUser(user), [], `${profileId} must see no tools`);
    assertDenied(user, 'soql_query', obj, /not registered/i, { code: 'PROFILE_UNREGISTERED', stage: 'identity' });
  }
});

test("profile resolution: an id match wins over another registered Profile that has the caller's Profile name", (t) => {
  const fx = new PolicyFixture(t);
  const obj = fx.object('Precedence', { Id: true, Name: true });
  const admins = fx.group('Precedence Admins', ALL_ACTIONS, [grant(obj, FULL_CRUD, ['Id', 'Name'])]);
  const readers = fx.group('Precedence Readers', ['soql_query'], [grant(obj, { canRead: true }, ['Name'])]);
  const adminProfile = fx.profile('Precedence Admin', [admins]);
  const readerProfile = fx.profile('Precedence Reader', [readers]);
  // ProfileId is the reader Profile's, while the reported Profile name is the admin Profile's.
  const user = caller(readerProfile.id, adminProfile.name);

  assert.deepEqual(getVisibleToolsForUser(user).map((a) => a.id), ['soql_query']);
  assert.deepEqual(assertPermitted(user, 'soql_query', obj).matchedGroups, [readers.name]);
  assertDenied(user, 'delete_record', obj, /not granted/i, { code: 'TOOL_NOT_GRANTED', stage: 'tool_grant' });
});

test('salesforceIdsMatch: treats the 15- and 18-character forms of an id as equal', () => {
  const id15 = '00e5g000001AbCd';
  const id18 = to18(id15);
  assert.equal(id18, '00e5g000001AbCdAAK');

  assert.equal(salesforceIdsMatch(id15, id18), true);
  assert.equal(salesforceIdsMatch(id18, id15), true);
  assert.equal(salesforceIdsMatch(id15, id15), true);
  assert.equal(salesforceIdsMatch(id18, id18), true);
  // Salesforce's documented example pair (also checks this file's to18 helper)
  assert.equal(to18('001A0000006Vm9r'), '001A0000006Vm9rIAC');
  assert.equal(salesforceIdsMatch('001A0000006Vm9r', '001A0000006Vm9rIAC'), true);
});

test('salesforceIdsMatch: is case-sensitive on the 15-character part', () => {
  const id15 = '00e5g000001AbCd';
  const otherCase = '00e5g000001abcd';

  assert.equal(salesforceIdsMatch(id15, otherCase), false);
  assert.equal(salesforceIdsMatch(to18(id15), to18(otherCase)), false);
  assert.equal(salesforceIdsMatch(id15, to18(otherCase)), false);
  assert.equal(salesforceIdsMatch(to18(id15), otherCase), false);
  assert.equal(salesforceIdsMatch(to18(id15), otherCase + to18(id15).slice(15)), false);
});

test('salesforceIdsMatch: ignores the case of the 3-character checksum suffix', () => {
  const id18 = to18('00e5g000001AbCd'); // ...AAK
  const lowerSuffix = id18.slice(0, 15) + id18.slice(15).toLowerCase();

  assert.equal(salesforceIdsMatch(id18, lowerSuffix), true);
  assert.equal(salesforceIdsMatch(lowerSuffix, '00e5g000001AbCd'), true);
});

test('salesforceIdsMatch: does not match ids with a different 15-character prefix', () => {
  const a = '00e5g000001AbCd';
  const b = '00e5g000001AbCe';

  assert.equal(salesforceIdsMatch(a, b), false);
  assert.equal(salesforceIdsMatch(to18(a), to18(b)), false); // both end in AAK
  assert.equal(salesforceIdsMatch(a, to18(b)), false);
  assert.equal(salesforceIdsMatch(to18(a), b), false);
});

test('salesforceIdsMatch: does not match an id against an empty, truncated, over-long or non-alphanumeric value', () => {
  const id15 = '00e5g000001AbCd';

  assert.equal(salesforceIdsMatch('', ''), false);
  assert.equal(salesforceIdsMatch('   ', '   '), false);
  assert.equal(salesforceIdsMatch(id15, ''), false);
  assert.equal(salesforceIdsMatch('', id15), false);
  assert.equal(salesforceIdsMatch(id15.slice(0, 14), id15), false); // 14 characters
  assert.equal(salesforceIdsMatch(id15, `${id15}A`), false); // 16 characters
  assert.equal(salesforceIdsMatch(id15, `${id15}AA`), false); // 17 characters
  assert.equal(salesforceIdsMatch(id15, `${id15}AAKX`), false); // 19 characters
  assert.equal(salesforceIdsMatch(id15, `${id15}!!!`), false); // non-alphanumeric suffix
});

// ---------------------------------------------------------------------------
// 5. assertSafeSoqlWhereClause
// ---------------------------------------------------------------------------

const WHERE_FIELDS = ['Name', 'Amount__c', 'CloseDate', 'CreatedDate', 'Stage__c', 'Phone', 'IsActive__c'];

function assertAccepted(whereClause: string, allowedFields: string[] = WHERE_FIELDS): void {
  try {
    assertSafeSoqlWhereClause(whereClause, allowedFields);
  } catch (err) {
    assert.fail(`expected ${JSON.stringify(whereClause)} to be accepted, but it threw: ${(err as Error).message}`);
  }
}

function assertRejected(whereClause: string, allowedFields: string[] = WHERE_FIELDS): Error {
  let thrown: unknown;
  try {
    assertSafeSoqlWhereClause(whereClause, allowedFields);
  } catch (err) {
    thrown = err;
  }
  assert.ok(thrown instanceof Error, `expected ${JSON.stringify(whereClause)} to be rejected with an Error`);
  return thrown;
}

test('assertSafeSoqlWhereClause: accepts allowed fields compared with string literals, including escaped quotes', () => {
  assertAccepted("Name = 'Acme'");
  assertAccepted("Name = 'O\\'Brien'");
  assertAccepted("Name != ''");
  assertAccepted("Name = 'back\\\\slash'");
  assertAccepted("Name = 'It\\'s \\'quoted\\''");
});

test('assertSafeSoqlWhereClause: accepts numbers and negative numbers', () => {
  assertAccepted('Amount__c > 1000');
  assertAccepted('Amount__c >= 10.5');
  assertAccepted('Amount__c > -5');
  assertAccepted('Amount__c <> -0.25');
  assertAccepted('Amount__c<-1000.75');
});

test('assertSafeSoqlWhereClause: accepts dates and datetimes', () => {
  assertAccepted('CloseDate = 2024-01-15');
  assertAccepted('CloseDate >= 2024-01-01 AND CloseDate <= 2024-12-31');
  assertAccepted('CreatedDate > 2024-01-15T10:30:00Z');
  assertAccepted('CreatedDate < 2024-01-15T10:30:00+05:30');
  assertAccepted('CreatedDate >= 2024-01-15T10:30:00-08:00');
});

test('assertSafeSoqlWhereClause: accepts date literals such as TODAY and LAST_N_DAYS:30', () => {
  assertAccepted('CloseDate = TODAY');
  assertAccepted('CreatedDate = LAST_N_DAYS:30');
  assertAccepted('CloseDate < next_n_months:6');
  assertAccepted('CreatedDate > N_DAYS_AGO:7');
  assertAccepted('CloseDate = THIS_FISCAL_QUARTER OR CloseDate = YESTERDAY');
});

test('assertSafeSoqlWhereClause: accepts AND / OR / NOT and nested parentheses', () => {
  assertAccepted("Name = 'a' AND Amount__c > 1 OR NOT Stage__c = 'Lost'");
  assertAccepted("NOT (Name = 'a')");
  assertAccepted("name = 'a' and (amount__c > 1 or not stage__c = 'Lost')");
  assertAccepted(
    "((Name = 'a' OR Name = 'b') AND (Amount__c > 5 OR (Stage__c = 'Won' AND (IsActive__c = TRUE))))"
  );
});

test('assertSafeSoqlWhereClause: accepts LIKE and IN (...)', () => {
  assertAccepted("Name LIKE 'Acme%'");
  assertAccepted("NOT Name LIKE '%test\\_%'");
  assertAccepted("Stage__c IN ('Won', 'Lost')");
  assertAccepted("Stage__c NOT IN ('Won')");
  assertAccepted('Amount__c IN (1, 2, -3)');
  assertAccepted('CloseDate IN (2024-01-15, 2024-02-15)');
});

test('assertSafeSoqlWhereClause: accepts NULL, TRUE and FALSE', () => {
  assertAccepted('Phone = NULL');
  assertAccepted('Phone != null');
  assertAccepted('IsActive__c = TRUE');
  assertAccepted('IsActive__c = false');
});

test('assertSafeSoqlWhereClause: matches allowed field names case-insensitively', () => {
  assertAccepted("name = 'x'", ['Name']);
  assertAccepted("NAME LIKE 'a%'", ['Name']);
  assertAccepted('amount__C > 5 AND AMOUNT__C < 10', ['Amount__c']);
  assertAccepted("stage__c = 'Won'", ['STAGE__C']);
});

test('assertSafeSoqlWhereClause: rejects a disallowed field with a PolicyViolationError', () => {
  const allowed = ['Name', 'Amount__c'];
  for (const whereClause of [
    "Secret__c = 'x'",
    "Name = 'x' AND Secret__c = 'y'",
    "(Name = 'x' OR NOT secret__c != null)",
    'Amount__c > 5 OR AnnualRevenue > 5',
    "Names = 'x'",
    "Name__c = 'x'",
  ]) {
    const err = assertRejected(whereClause, allowed);
    assert.ok(
      err instanceof PolicyViolationError,
      `${JSON.stringify(whereClause)} must throw PolicyViolationError, got ${err.name}: ${err.message}`
    );
  }
});

test('assertSafeSoqlWhereClause: rejects a semi-join subquery', () => {
  const allowed = ['Name', 'AccountId'];
  assertRejected('Id IN (SELECT AccountId FROM Contact)', allowed);
  assertRejected('Id NOT IN (SELECT AccountId FROM Contact)', allowed);
  assertRejected('Name IN (select Name from Account)', allowed);
});

test('assertSafeSoqlWhereClause: rejects relationship traversal, even when each path segment is an allowed name', () => {
  const allowed = ['Name', 'Owner', 'Email'];
  assertRejected("Owner.Email = 'x'", allowed);
  assertRejected("Name = 'x' AND Owner.Email != null", allowed);
  assertRejected("Account__r.Name = 'x'", allowed);
});

test('assertSafeSoqlWhereClause: rejects bind variables', () => {
  const allowed = ['Name', 'foo', 'names'];
  assertRejected('Name = :foo', allowed);
  assertRejected('Name=:foo', allowed);
  assertRejected('Name IN :names', allowed);
  assertRejected('Name = :1', allowed);
});

test('assertSafeSoqlWhereClause: rejects semicolons', () => {
  assertRejected("Name = 'x'; DELETE FROM Account");
  assertRejected("Name = 'x';");
  assertRejected("Name = 'x' ; Name = 'y'");
});

test('assertSafeSoqlWhereClause: rejects comment markers', () => {
  assertRejected("Name = 'x' -- trailing comment");
  assertRejected("Name = 'x' --");
  assertRejected("Name = 'x' /* block */");
  assertRejected("/**/Name = 'x'");
  assertRejected("Name = 'x' // line comment");
});

test('assertSafeSoqlWhereClause: rejects double quotes', () => {
  assertRejected('Name = "x"');
  assertRejected(`Name = 'x' OR Name = "y"`);
  assertRejected(`"Name" = 'x'`);
});

test('assertSafeSoqlWhereClause: rejects unbalanced parentheses', () => {
  assertRejected("(Name = 'x'");
  assertRejected("Name = 'x')");
  assertRejected("((Name = 'x')");
  assertRejected("(Name = 'x'))");
  assertRejected(")Name = 'x'(");
});

test('assertSafeSoqlWhereClause: rejects an unterminated string literal', () => {
  assertRejected("Name = 'abc");
  assertRejected("Name = 'abc\\'"); // the closing quote is escaped
  assertRejected("Name = '");
  assertRejected("Name = 'a' OR Name = 'b");
});

test('assertSafeSoqlWhereClause: rejects a string literal containing a newline', () => {
  assertRejected("Name = 'line one\nline two'");
  assertRejected("Name = 'a\rb'");
  assertRejected("Name = 'a\r\nb'");
  assertRejected("Name = 'a\\\nb'"); // backslash followed by a raw newline
});

test('assertSafeSoqlWhereClause: rejects a clause longer than 2000 characters', () => {
  const clauseOfLength = (length: number) => `Name = '${'a'.repeat(length - 9)}'`;
  assert.equal(clauseOfLength(2000).length, 2000);
  assert.equal(clauseOfLength(2001).length, 2001);

  assertAccepted(clauseOfLength(2000)); // control: the limit itself is allowed
  assertRejected(clauseOfLength(2001));
  assertRejected(`${"Name = 'x' OR ".repeat(200)}Name = 'x'`);
});

test('checkSoqlWhereClause: reports the first problem in reading order, and the fields an accepted clause uses', () => {
  const allowed = ['Name', 'Amount__c'];
  assert.deepEqual(checkSoqlWhereClause("name = 'a' AND (NAME != 'b' OR amount__c > 1) AND Id != null", allowed), {
    ok: true,
    fieldNames: ['name', 'amount__c', 'Id'],
  });
  assert.deepEqual(checkSoqlWhereClause("Secret__c = 'x' AND (", allowed), {
    ok: false,
    problem: 'field',
    fieldName: 'Secret__c',
    message: "whereClause references 'Secret__c', which is not an allowed field for this Profile.",
  });
  assert.deepEqual(checkSoqlWhereClause("Name = 'x'; Secret__c = 'y'", allowed), {
    ok: false,
    problem: 'malformed',
    message: 'whereClause contains an unsupported character at position 11.',
  });
  assert.deepEqual(checkSoqlWhereClause("(Name = 'x'", allowed), {
    ok: false,
    problem: 'malformed',
    message: 'whereClause has unbalanced parentheses.',
  });
});

// ---------------------------------------------------------------------------
// 6. evaluatePolicy: the decision with the call's arguments
// ---------------------------------------------------------------------------

const RECORD_ID = to18(randomSfId15('a01'));

/** One Profile with read and write access to one Object, for the argument checks. */
function argumentFixture(t: TestContext) {
  const fx = new PolicyFixture(t);
  const obj = fx.object('Args', { Id: true, Name: true, Amount__c: true, Secret__c: false });
  const group = fx.group('Args Everything', ALL_ACTIONS, [grant(obj, FULL_CRUD, ['Id', 'Name', 'Amount__c', 'Secret__c'])]);
  const profile = fx.profile('Args Profile', [group]);
  return { fx, obj, group, profile, user: fx.callerFor(profile) };
}

test('evaluatePolicy: a requested or written field outside the allowlist is FIELD_NOT_PERMITTED at the fields stage', (t) => {
  const { obj, profile, user } = argumentFixture(t);
  const calls: Array<[string, Record<string, unknown>, string[]]> = [
    ['soql_query', { objectName: obj, fields: ['Name', 'Secret__c'] }, ['Secret__c']],
    ['get_record', { objectName: obj, recordId: RECORD_ID, fields: ['Ghost__c', 'id'] }, ['Ghost__c']],
    ['create_record', { objectName: obj, fields: { Name: 'x', Secret__c: 'y', Other__c: 1 } }, ['Secret__c', 'Other__c']],
    ['update_record', { objectName: obj, recordId: RECORD_ID, fields: { secret__C: 'y' } }, ['secret__C']],
  ];
  for (const [tool, args, denied] of calls) {
    const decision = decide(user, tool, args);
    assertRefusal(decision, { code: 'FIELD_NOT_PERMITTED', stage: 'fields' }, tool);
    assert.equal(
      decision.reason,
      `Fields [${denied.join(', ')}] on ${obj} are not permitted for Profile '${profile.name}'.`,
      `${tool} reason`
    );
    assert.deepEqual(decision.steps.at(-1)?.fieldNames, denied, `${tool} names the refused fields`);
    assert.equal(decision.steps.at(-1)?.objectName, obj);
    assert.equal(decisionLogStatus(decision), 'DENIED');
  }
});

test('evaluatePolicy: a WHERE clause naming a field outside the allowlist is WHERE_FIELD_NOT_PERMITTED at the where stage', (t) => {
  const { obj, user } = argumentFixture(t);
  for (const [whereClause, field] of [
    ["Secret__c = 'x'", 'Secret__c'],
    ["Name = 'x' OR (Owner__c != null)", 'Owner__c'],
    ['Id IN (SELECT AccountId FROM Contact)', 'SELECT'],
  ]) {
    const decision = decide(user, 'soql_query', { objectName: obj, fields: ['Name'], whereClause });
    assertRefusal(decision, { code: 'WHERE_FIELD_NOT_PERMITTED', stage: 'where' }, whereClause);
    assert.equal(decision.reason, `whereClause references '${field}', which is not an allowed field for this Profile.`);
    assert.deepEqual(decision.steps.at(-1)?.fieldNames, [field]);
    assert.equal(decision.steps.at(-2)?.stage, 'fields', 'the field names were checked first');
  }
});

test('evaluatePolicy: malformed arguments are invalid (INPUT_INVALID at the input stage), logged DENIED, with the handlers\' messages', (t) => {
  const { obj, user } = argumentFixture(t);
  const cases: Array<[string, Record<string, unknown>, string]> = [
    ['soql_query', { objectName: obj, whereClause: "(Name = 'x'" }, 'whereClause has unbalanced parentheses.'],
    ['soql_query', { objectName: obj, whereClause: "Name = 'x')" }, 'whereClause has unbalanced parentheses.'],
    ['soql_query', { objectName: obj, whereClause: "Name = 'x' -- c" }, 'whereClause contains an unsupported character at position 12.'],
    ['soql_query', { objectName: obj, whereClause: `Name = '${'a'.repeat(2000)}'` }, 'whereClause is longer than 2000 characters.'],
    ['get_record', { objectName: obj, recordId: 'abc' }, 'recordId must be a 15 or 18-character Salesforce Record ID.'],
    ['get_record', { objectName: obj }, 'recordId must be a 15 or 18-character Salesforce Record ID.'],
    ['update_record', { objectName: obj, recordId: '../../limits', fields: { Name: 'x' } }, 'recordId must be a 15 or 18-character Salesforce Record ID.'],
    ['delete_record', { objectName: obj, recordId: 42 }, 'recordId must be a 15 or 18-character Salesforce Record ID.'],
    ['create_record', { objectName: obj }, 'fields must be an object of field names to values.'],
    ['create_record', { objectName: obj, fields: {} }, 'fields must be an object of field names to values.'],
    ['update_record', { objectName: obj, recordId: RECORD_ID, fields: ['Name'] }, 'fields must be an object of field names to values.'],
  ];
  for (const [tool, args, message] of cases) {
    const decision = decide(user, tool, args);
    assertRefusal(decision, { code: 'INPUT_INVALID', stage: 'input', outcome: 'invalid' }, `${tool} ${JSON.stringify(args).slice(0, 80)}`);
    assert.equal(decision.reason, message);
    assert.equal(decisionLogStatus(decision), 'DENIED', 'invalid arguments are logged as DENIED, not ERROR');
  }

  // A missing objectName is refused before the Object is looked up.
  const missing = decide(user, 'soql_query', { fields: ['Name'] });
  assertRefusal(missing, { code: 'INPUT_INVALID', stage: 'input' }, 'missing objectName');
  assert.deepEqual(missing.steps.map((s) => s.stage), ['tool', 'identity', 'groups', 'tool_grant', 'input']);
  assert.equal(missing.reason, "MCP Action 'soql_query' requires an objectName argument.");
});

test('evaluatePolicy: an objectName that is not an API name is invalid at the input stage, with the reason an ungranted Object gets', (t) => {
  const { fx, obj, group, user } = argumentFixture(t);
  const notGranted = (name: string) =>
    `Object '${name}' is either disabled in Salesforce > Objects or not permitted by Groups [${group.name}].`;
  const cases: Array<[unknown, string]> = [
    ['ACCT-99812', 'ACCT-99812'],
    ["Account WHERE Name != null", "Account WHERE Name != null"],
    [` ${obj}`, ` ${obj}`],
    [`${obj}.Owner`, `${obj}.Owner`],
    [5, '5'],
    // Not text at all, even when it reads as an API name.
    [true, 'true'],
    [['Nothing__c'], 'Nothing__c'],
  ];
  for (const [objectName, asText] of cases) {
    const label = `objectName ${JSON.stringify(objectName)}`;
    const decision = decide(user, 'soql_query', { objectName, fields: ['Name'] });
    assertRefusal(decision, { code: 'INPUT_INVALID', stage: 'input' }, label);
    assert.deepEqual(decision.steps.map((s) => s.stage), ['tool', 'identity', 'groups', 'tool_grant', 'input'], label);
    assert.equal(decision.steps.at(-1)?.objectName, asText, label);
    assert.equal(decision.reason, notGranted(asText), `${label}: the caller is told what an ungranted Object gets`);
    assert.equal(decisionLogStatus(decision), 'DENIED', label);
  }
  // The wrapper (no arguments but the Object) classifies a text one the same way, with the same reason.
  for (const target of ['ACCT-99812', "Account WHERE Email = 'x'"]) {
    assertDenied(user, 'soql_query', target, /not permitted by Groups/, { code: 'INPUT_INVALID', stage: 'input' });
  }
  // A valid API name that names no granted Object is still a permission denial.
  assertRefusal(
    decide(user, 'soql_query', { objectName: `Nothing_${fx.tag}__c` }),
    { code: 'OBJECT_NOT_GRANTED', stage: 'object' },
    'an API name nothing grants'
  );
});

test('evaluatePolicy: an argument that cannot be read as text is invalid with the reader\'s message, never an error decision', (t) => {
  const errors: unknown[] = [];
  t.mock.method(console, 'error', (...args: unknown[]) => errors.push(args));
  const { obj, user } = argumentFixture(t);
  // JSON can carry an object whose toString is not a function; String() of it throws a TypeError.
  const unreadable = { toString: 1 };
  for (const tool of ['soql_query', 'get_record']) {
    const decision = decide(user, tool, { objectName: obj, recordId: RECORD_ID, fields: ['Name', unreadable] });
    assertRefusal(decision, { code: 'INPUT_INVALID', stage: 'input', outcome: 'invalid' }, tool);
    assert.equal(decision.reason, 'Cannot convert object to primitive value', tool);
    assert.equal(decision.steps.at(-2)?.stage, 'crud', `${tool}: read after access was decided`);
    assert.equal(decisionLogStatus(decision), 'DENIED', tool);
  }
  // The objectName is read before the Object is looked up.
  const objectName = decide(user, 'soql_query', { objectName: unreadable });
  assertRefusal(objectName, { code: 'INPUT_INVALID', stage: 'input' }, 'objectName');
  assert.equal(objectName.reason, 'Cannot convert object to primitive value');
  assert.deepEqual(errors, [], 'a caller\'s malformed input is not reported as an engine failure');
});

test('evaluatePolicy: checks run in the order the handlers ran them, so a call with two problems reports the same one as before', (t) => {
  const { fx, obj, user } = argumentFixture(t);
  const ungranted = fx.object('ArgsUngranted', { Id: true });
  const cases: Array<[string, Record<string, unknown>, PolicyDecisionCode, PolicyStage]> = [
    // Access before arguments: an unauthorized caller learns nothing about its arguments.
    ['get_record', { objectName: ungranted, recordId: 'abc' }, 'OBJECT_NOT_GRANTED', 'object'],
    ['create_record', { objectName: ungranted, fields: [] }, 'OBJECT_NOT_GRANTED', 'object'],
    // The record id before the field names, as get_record and update_record read them.
    ['get_record', { objectName: obj, recordId: 'abc', fields: ['Secret__c'] }, 'INPUT_INVALID', 'input'],
    ['update_record', { objectName: obj, recordId: 'abc', fields: { Secret__c: 1 } }, 'INPUT_INVALID', 'input'],
    // The selected fields before the WHERE clause, and the WHERE clause in reading order.
    ['soql_query', { objectName: obj, fields: ['Secret__c'], whereClause: "(Name = 'x'" }, 'FIELD_NOT_PERMITTED', 'fields'],
    ['soql_query', { objectName: obj, whereClause: "Secret__c = 'x' AND (" }, 'WHERE_FIELD_NOT_PERMITTED', 'where'],
    ['soql_query', { objectName: obj, whereClause: "Name = 'x'; Secret__c = 'y'" }, 'INPUT_INVALID', 'input'],
  ];
  for (const [tool, args, code, stage] of cases) {
    assertRefusal(decide(user, tool, args), { code, stage }, `${tool} ${JSON.stringify(args)}`);
  }
});

test('evaluatePolicy: allowed calls with arguments record the argument stages and keep the wrapper\'s result', (t) => {
  const { obj, group, user } = argumentFixture(t);
  const cases: Array<[string, Record<string, unknown>, PolicyStage[]]> = [
    ['describe_object', { objectName: obj.toLowerCase() }, []],
    ['soql_query', { objectName: obj, fields: ['Id', 'name'], whereClause: "Amount__c > 5", limit: 'abc' }, ['fields', 'where']],
    // A fields value that is not a list selects every allowed field, as soql_query always did.
    ['soql_query', { objectName: obj, fields: { Name: 'x' } }, ['fields', 'where']],
    ['get_record', { objectName: obj, recordId: ` ${RECORD_ID} ` }, ['fields']],
    ['create_record', { objectName: obj, fields: { Name: 'x' } }, ['fields']],
    ['update_record', { objectName: obj, recordId: RECORD_ID, fields: { Amount__c: 1 } }, ['fields']],
    ['delete_record', { objectName: obj, recordId: RECORD_ID }, []],
    ['list_enabled_objects', {}, []],
  ];
  for (const [tool, args, argumentStages] of cases) {
    const decision = decide(user, tool, args);
    assertAllowedDecision(decision, tool);
    const accessStages = tool === 'list_enabled_objects'
      ? ['tool', 'identity', 'groups', 'tool_grant']
      : ['tool', 'identity', 'groups', 'tool_grant', 'object', 'crud'];
    // The last step, an 'input' pass, says the arguments were checked and all passed.
    assert.deepEqual(decision.steps.map((s) => s.stage), [...accessStages, ...argumentStages, 'input'], tool);
    assert.deepEqual(decision.steps.at(-1), {
      stage: 'input',
      result: 'pass',
      grantingGroupIds: [],
      objectName: tool === 'list_enabled_objects' ? null : obj,
      fieldNames: [],
      ruleId: null,
    }, tool);
    assert.deepEqual(decision.decidingGroupIds, [group.id], tool);

    const wrapper = evaluateMcpToolCall(user, tool, typeof args.objectName === 'string' ? args.objectName : undefined);
    assert.equal(decision.reason, wrapper.reason, tool);
    assert.equal(decision.objectName, wrapper.objectName ?? null, tool);
    assert.deepEqual(decision.allowedFields, wrapper.allowedFields, tool);
    // The wrapper checked no argument, and its trace says so: no 'input' step.
    assert.deepEqual(wrapper.decision.steps.map((s) => s.stage), accessStages, `${tool} wrapper`);
    assert.notDeepEqual(wrapper.decision.steps, decision.steps, `${tool}: a check without the arguments looks different`);
  }
  const selectAll = decide(user, 'soql_query', { objectName: obj, fields: { Name: 'x' } });
  assert.deepEqual(selectAll.steps.find((s) => s.stage === 'fields')?.fieldNames, ['Id', 'Name', 'Amount__c']);
});

test('evaluatePolicy: list_enabled_objects ignores objectName, so no Object it names can deny it', (t) => {
  const fx = new PolicyFixture(t);
  const granted = fx.object('ListGranted', { Id: true });
  const disabled = fx.object('ListDisabled', { Id: true }, { enabled: false });
  const unshared = fx.object('ListUnshared', { Id: true });
  const group = fx.group('List Readers', ['list_enabled_objects'], [
    grant(granted, { canRead: true }, ['Id']),
    grant(disabled, { canRead: true }, ['Id']),
  ]);
  const user = fx.callerFor(fx.profile('List Profile', [group]));

  for (const objectName of [granted, disabled, unshared, `Missing_${fx.tag}__c`, "Account WHERE x = 'y'", 7]) {
    const decision = decide(user, 'list_enabled_objects', { objectName });
    assertAllowedDecision(decision, `list_enabled_objects(${objectName})`);
    assert.deepEqual(decision.steps.map((s) => s.stage), ['tool', 'identity', 'groups', 'tool_grant', 'input']);
    assert.equal(decision.steps.at(-1)?.objectName, null, 'the ignored objectName is not recorded');
    assert.equal(decision.objectName, null);
    assert.deepEqual(decision.allowedFields, []);
    if (typeof objectName === 'string') {
      const wrapper = assertPermitted(user, 'list_enabled_objects', objectName);
      assert.deepEqual(wrapper.allowedFields, []);
      assert.equal(wrapper.objectName, undefined);
    }
  }
});

test('evaluatePolicy: identity records how the Profile was matched', (t) => {
  const fx = new PolicyFixture(t);
  const group = fx.group('Identity Readers', ['list_enabled_objects']);
  const id15 = randomSfId15('00e');
  const profile = fx.profile('Identity Profile', [group], id15);

  const byId = decide(caller(to18(id15), 'Some Other Name'), 'list_enabled_objects', {});
  assert.deepEqual(byId.identity, { callerProfileId: to18(id15), matchedProfileId: id15, matchMethod: 'id' });

  const strangerId = to18(randomSfId15('00e'));
  // Registered under a Salesforce id, so never matched by name: every org has a Profile by that name.
  const sameName = decide(caller(strangerId, profile.name.toUpperCase()), 'list_enabled_objects', {});
  assertRefusal(sameName, { code: 'PROFILE_UNREGISTERED', stage: 'identity' }, 'name of a Profile registered by id');
  assert.deepEqual(sameName.identity, { callerProfileId: strangerId, matchedProfileId: null, matchMethod: 'none' });

  // Registered under an id that is not a Salesforce id: it has no id to match, so its name stands in.
  const namedOnly = fx.profile('Named Only', [group], `NAMED_ONLY_${fx.tag}`);
  const byName = decide(caller(strangerId, namedOnly.name.toUpperCase()), 'list_enabled_objects', {});
  assertAllowedDecision(byName, 'name fallback');
  assert.deepEqual(byName.identity, { callerProfileId: strangerId, matchedProfileId: namedOnly.id, matchMethod: 'name' });

  const none = decide(caller(strangerId, `Nobody ${fx.tag}`), 'list_enabled_objects', {});
  assertRefusal(none, { code: 'PROFILE_UNREGISTERED', stage: 'identity' }, 'no match');
  assert.deepEqual(none.identity, { callerProfileId: strangerId, matchedProfileId: null, matchMethod: 'none' });
  assert.deepEqual(none.assignedGroups, []);
});

test('evaluatePolicy: the decision carries the policy revision of its snapshot', (t) => {
  const fx = new PolicyFixture(t);
  const user = fx.callerFor(fx.profile('Revision Profile', [fx.group('Revision Readers', ['list_enabled_objects'])]));
  const snapshot = loadPolicySnapshot();
  assert.equal(snapshot.policyRevision, store.getPolicyRevision());
  assert.equal(evaluatePolicy(user, 'list_enabled_objects', {}, snapshot).policyRevision, snapshot.policyRevision);

  fx.object('RevisionBump', { Id: true }); // a policy change
  assert.equal(evaluatePolicy(user, 'list_enabled_objects', {}, snapshot).policyRevision, snapshot.policyRevision);
  assert.ok(decide(user, 'list_enabled_objects', {}).policyRevision > snapshot.policyRevision);
});

test('evaluatePolicy: overrides.assignedGroupIds replaces the mapped groups for one evaluation', (t) => {
  const fx = new PolicyFixture(t);
  const obj = fx.object('WhatIf', { Id: true, Name: true });
  const readers = fx.group('WhatIf Readers', ['soql_query'], [grant(obj, { canRead: true }, ['Name'])]);
  const deleters = fx.group('WhatIf Deleters', ['delete_record'], [grant(obj, { canDelete: true }, [])]);
  const profile = fx.profile('WhatIf Profile', [readers]);
  const user = fx.callerFor(profile);
  const remove = { objectName: obj, recordId: RECORD_ID };

  assertRefusal(decide(user, 'delete_record', remove), { code: 'TOOL_NOT_GRANTED', stage: 'tool_grant' }, 'as stored');

  const whatIf = decide(user, 'delete_record', remove, { assignedGroupIds: [deleters.id, `grp_unknown_${fx.tag}`] });
  assertAllowedDecision(whatIf, 'what-if');
  assert.deepEqual(whatIf.assignedGroups, [{ id: deleters.id, name: deleters.name }], 'unknown ids grant nothing');
  assert.deepEqual(whatIf.decidingGroupIds, [deleters.id]);
  assertRefusal(
    decide(user, 'soql_query', { objectName: obj }, { assignedGroupIds: [deleters.id] }),
    { code: 'TOOL_NOT_GRANTED', stage: 'tool_grant' },
    'the mapped group no longer applies'
  );

  assertRefusal(decide(user, 'soql_query', { objectName: obj }, { assignedGroupIds: [] }), { code: 'NO_GROUPS', stage: 'groups' }, 'no groups');
  assertRefusal(
    decide(fx.unregisteredCaller(), 'delete_record', remove, { assignedGroupIds: [deleters.id] }),
    { code: 'PROFILE_UNREGISTERED', stage: 'identity' },
    'an override does not register a Profile'
  );

  // Nothing was stored: the Profile still has only its mapped group.
  assert.deepEqual(store.getProfileGroupIds(profile.id), [readers.id]);
  assertAllowedDecision(decide(user, 'soql_query', { objectName: obj }), 'as stored again');
});

/** A policy that exists only in memory: one Profile, one group reading Name on one Object. */
function syntheticSnapshot(objectName: string): { snapshot: PolicySnapshot; user: VerifiedSalesforceUser; groupId: string } {
  const profileId = to18(randomSfId15('00e'));
  const field = (fieldName: string) => ({
    objectName,
    fieldName,
    label: fieldName,
    fieldType: 'Text',
    isCustom: false,
    required: false,
    enabled: true,
    missingInOrg: false,
  });
  const object: SalesforceObject = {
    objectName,
    label: objectName,
    isCustom: true,
    enabled: true,
    sourcePath: '',
    fieldCount: 2,
    enabledFieldCount: 2,
    fields: [field('Id'), field('Name')],
    updatedAt: '',
  };
  const group: AccessGroup = {
    id: `grp_synthetic_${crypto.randomBytes(4).toString('hex')}`,
    name: 'Synthetic Readers',
    description: '',
    allowedActions: ['soql_query'],
    objectPermissions: [grant(objectName, { canRead: true }, ['Name'])],
    version: 1,
    updatedAt: '',
  };
  return {
    snapshot: {
      policyRevision: 41,
      profiles: [{ id: profileId, name: 'Synthetic Profile', updatedAt: '' }],
      groups: [group],
      mappings: [{ profileId, groupIds: [group.id] }],
      objects: [object],
    },
    user: caller(profileId, 'Synthetic Profile'),
    groupId: group.id,
  };
}

test('evaluatePolicy: is pure, deciding from the snapshot alone without reading the store', (t) => {
  const { snapshot, user, groupId } = syntheticSnapshot('Synthetic__c');
  for (const method of ['getPolicyRevision', 'getProfiles', 'getGroups', 'getProfileGroupMappings', 'getObjects'] as const) {
    t.mock.method(store, method, () => {
      throw new Error(`evaluatePolicy read store.${method}()`);
    });
  }

  const decision = evaluatePolicy(user, 'soql_query', { objectName: 'synthetic__C', fields: ['Name'] }, snapshot);
  assertAllowedDecision(decision, 'synthetic');
  assert.equal(decision.objectName, 'Synthetic__c');
  assert.equal(decision.policyRevision, 41);
  assert.deepEqual(decision.decidingGroupIds, [groupId]);
  assert.deepEqual(
    resolveEffectiveProfilePermissions(user.profileId, user.profileName, snapshot).assignedGroups.map((g) => g.id),
    [groupId]
  );
});

test('evaluatePolicy: an Object stored under a name that is not an API name is a policy fault, an error decision', (t) => {
  const errors: unknown[] = [];
  t.mock.method(console, 'error', (...args: unknown[]) => errors.push(args));
  // Saved before names were validated; the catalog no longer accepts one, so only a snapshot holds it.
  // The name is the stored policy's, not the caller's (who may spell it in any case), so it is not
  // the caller's invalid input: it is logged as ERROR, as the handler's check logged it.
  const { snapshot, user } = syntheticSnapshot('Legacy Object');
  const decision = evaluatePolicy(user, 'soql_query', { objectName: 'legacy object', fields: ['Name'] }, snapshot);
  assert.equal(decision.outcome, 'error');
  assert.equal(decision.code, 'INTERNAL_ERROR');
  assert.equal(decision.reason, "Object 'Legacy Object' is not a valid Salesforce API name.", 'the text the handler gave');
  assert.equal(decisionLogStatus(decision), 'ERROR');
  // Access was decided first; evaluation stopped after it, with no step failed.
  assert.deepEqual(decision.steps.map((s) => `${s.stage}:${s.result}`), [
    'tool:pass',
    'identity:pass',
    'groups:pass',
    'tool_grant:pass',
    'object:pass',
    'crud:pass',
  ]);
  assert.deepEqual(decision.decidingGroupIds, []);
  assert.equal(decision.objectName, null);
  assert.deepEqual(decision.allowedFields, []);
  assert.deepEqual(errors, [], 'a stored name is reported by the decision, not as an exception');
  // Without the arguments (the wrapper, the simulator without a sample payload) the handler's check
  // is not made, as before.
  assert.equal(
    evaluateToolAccess(user, 'soql_query', 'legacy object', snapshot).outcome,
    'allowed'
  );
});

test('evaluatePolicy: an exception inside the evaluation is an error decision that allows nothing', (t) => {
  const errors: unknown[] = [];
  t.mock.method(console, 'error', (...args: unknown[]) => errors.push(args));
  const { snapshot, user } = syntheticSnapshot('Broken__c');
  const broken = { ...snapshot, objects: [{ ...snapshot.objects[0], fields: [null] }] } as unknown as PolicySnapshot;

  const decision = evaluatePolicy(user, 'soql_query', { objectName: 'Broken__c' }, broken);
  assert.equal(decision.outcome, 'error');
  assert.equal(decision.code, 'INTERNAL_ERROR');
  assert.equal(decision.reason, 'The access policy could not be evaluated, so the call is refused.');
  assert.deepEqual(decision.decidingGroupIds, []);
  assert.deepEqual(decision.allowedFields, []);
  assert.equal(decision.objectName, null);
  assert.equal(decision.policyRevision, 41);
  assert.equal(decisionLogStatus(decision), 'ERROR');
  assert.equal(errors.length, 1, 'the failure is logged for the operator');

  const unreadable = evaluatePolicy(user, 'soql_query', {}, null as unknown as PolicySnapshot);
  assert.equal(unreadable.outcome, 'error');
  assert.equal(unreadable.policyRevision, 0);
});

test('resolveEffectiveProfilePermissions: the same result from the store as from a snapshot of it', (t) => {
  const fx = new PolicyFixture(t);
  const obj = fx.object('SameMerge', { Id: true, Name: true, Phone: false });
  const profile = fx.profile('SameMerge Profile', [
    fx.group('SameMerge A', ['soql_query'], [grant(obj, { canRead: true }, ['Name', 'Phone'])]),
    fx.group('SameMerge B', ['get_record'], [grant(obj.toUpperCase(), { canUpdate: true }, [])]),
  ]);
  assert.deepEqual(
    resolveEffectiveProfilePermissions(profile.id, profile.name, loadPolicySnapshot()),
    resolveEffectiveProfilePermissions(profile.id, profile.name)
  );
});
