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
  evaluateMcpToolCall,
  getVisibleToolsForUser,
  type PolicyEvaluationResult,
} from '../src/rbac/policyEngine.js';
import { assertSafeSoqlWhereClause } from '../src/mcp/soqlGuard.js';
import { salesforceIdsMatch, type VerifiedSalesforceUser } from '../src/salesforce/client.js';
import {
  AVAILABLE_MCP_ACTIONS,
  type AccessGroup,
  type GroupObjectPermission,
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
    const group = store.upsertGroup({
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

/** Asserts a denial with a matching reason, no fields or object leaked, and the same result twice. */
function assertDenied(
  user: VerifiedSalesforceUser,
  toolName: string,
  targetObject: string | undefined,
  reason: RegExp
): PolicyEvaluationResult {
  const call = describeCall(toolName, targetObject);
  const first = evaluateMcpToolCall(user, toolName, targetObject);
  assert.equal(first.permitted, false, `${call} must be denied, got ${JSON.stringify(first)}`);
  assert.equal(typeof first.reason, 'string', `${call} denial carries a reason`);
  assert.match(first.reason, reason, `${call} denial reason`);
  assert.deepEqual(first.allowedFields, [], `${call} denial must not expose fields`);
  assert.equal(first.objectName, undefined, `${call} denial must not resolve an object`);
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
  return result;
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
    const result = assertDenied(stranger, tool, target, /not registered/i);
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
    const result = assertDenied(user, tool, target, /no Groups/i);
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
    const result = assertDenied(user, tool, target, /not granted/i);
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
    assertDenied(user, tool, obj, /unknown/i);
    assertDenied(user, tool, undefined, /unknown/i);
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
      assertDenied(user, tool, target, /requires an objectName/i);
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
    assertDenied(user, tool, other, /not permitted/i);
    assertDenied(user, tool, `Missing_${fx.tag}__c`, /not permitted/i);
  }
});

test('evaluateMcpToolCall: denies every object-scoped tool on an object whose group entry sets no CRUD flag', (t) => {
  const fx = new PolicyFixture(t);
  const obj = fx.object('NoFlags', { Id: true, Name: true });
  const group = fx.group('No Flags', ALL_ACTIONS, [grant(obj, {}, ['Id', 'Name'])]);
  const user = fx.callerFor(fx.profile('No Flags Profile', [group]));

  for (const tool of OBJECT_SCOPED_TOOLS) {
    assertDenied(user, tool, obj, /not permitted/i);
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
    assertDenied(user, tool, toggled, /disabled/i);
    assertDenied(user, tool, seededDisabled, /disabled/i);
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
    assertDenied(user, tool, obj, /read access/i);
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
  assertDenied(user, 'create_record', obj, /create access/i);
});

test('evaluateMcpToolCall: denies update_record without canUpdate', (t) => {
  const fx = new PolicyFixture(t);
  const obj = fx.object('NoUpdate', { Id: true, Name: true });
  const group = fx.group('No Update', ALL_ACTIONS, [
    grant(obj, { canRead: true, canCreate: true, canDelete: true }, ['Id', 'Name']),
  ]);
  const user = fx.callerFor(fx.profile('No Update Profile', [group]));

  assertPermitted(user, 'create_record', obj); // control
  assertDenied(user, 'update_record', obj, /update access/i);
});

test('evaluateMcpToolCall: denies delete_record without canDelete', (t) => {
  const fx = new PolicyFixture(t);
  const obj = fx.object('NoDelete', { Id: true, Name: true });
  const group = fx.group('No Delete', ALL_ACTIONS, [
    grant(obj, { canRead: true, canCreate: true, canUpdate: true }, ['Id', 'Name']),
  ]);
  const user = fx.callerFor(fx.profile('No Delete Profile', [group]));

  assertPermitted(user, 'update_record', obj); // control
  assertDenied(user, 'delete_record', obj, /delete access/i);
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

  assert.deepEqual(assertPermitted(user, 'get_record', obj).allowedFields, ['Name']);
  assertPermitted(user, 'delete_record', obj);
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
    assertDenied(user, 'soql_query', obj, /not registered/i);
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
  assertDenied(user, 'delete_record', obj, /not granted/i);
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
