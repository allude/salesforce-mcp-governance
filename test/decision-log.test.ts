import './helpers/env.js';
// Unit tests for decisionLogColumns (src/rbac/decisionLog.ts): what the MCP log keeps of a decision.
// Decisions come from evaluatePolicy on a hand-built snapshot, or are written out by hand where the
// engine cannot give one, and the catalog is an in-memory one. Nothing here reads the store.
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import {
  decisionLogColumns,
  MAX_LOGGED_NAMES,
  policySnapshotCatalog,
  tokenRejectedDecision,
  UPSTREAM_UNAVAILABLE_DECISION,
  type DecisionLogCatalog,
} from '../src/rbac/decisionLog.js';
import {
  evaluatePolicy,
  POLICY_DECISION_CODES,
  POLICY_STAGES,
  type PolicyDecision,
  type PolicySnapshot,
  type PolicyStage,
} from '../src/rbac/policyEngine.js';
import { MALFORMED_GRANT_REASONS, malformedGrantReason } from '../src/rbac/groupGrants.js';
import type { SalesforceObject } from '../src/types/governance.js';

const PROFILE_ID = '00e5g000001D8pRAAU';
const SUBJECT = { profileId: PROFILE_ID, profileName: 'Support', username: 'rep@acme.example.com' };
const GROUP = { id: 'grp_support', name: 'Support' };
const OTHER_GROUP = { id: 'grp_billing', name: 'Billing' };

function catalogObject(objectName: string, fields: Array<[string, boolean?]>, enabled = true): SalesforceObject {
  return {
    objectName,
    label: objectName,
    isCustom: false,
    enabled,
    sourcePath: '',
    fieldCount: fields.length,
    enabledFieldCount: fields.filter(([, on = true]) => on).length,
    fields: fields.map(([fieldName, on = true]) => ({
      objectName,
      fieldName,
      label: fieldName,
      fieldType: 'Text',
      isCustom: false,
      required: false,
      enabled: on,
      missingInOrg: false,
    })),
    updatedAt: '',
  };
}

const OBJECTS = [
  catalogObject('Case', [['Id'], ['Subject'], ['Status'], ['SSN__c', false]]),
  catalogObject('Account', [['Id'], ['Name']]),
];

function snapshot(overrides: Partial<PolicySnapshot> = {}): PolicySnapshot {
  return {
    policyRevision: 42,
    profiles: [{ id: PROFILE_ID, name: 'Support', updatedAt: '' }],
    groups: [
      {
        id: GROUP.id,
        name: GROUP.name,
        description: '',
        allowedActions: ['soql_query', 'get_record', 'update_record', 'describe_object'],
        objectPermissions: [
          { objectName: 'Case', canRead: true, canCreate: false, canUpdate: true, canDelete: false, allowedFields: ['Id', 'Subject', 'Status'] },
        ],
        version: 1,
        updatedAt: '',
      },
    ],
    mappings: [{ profileId: PROFILE_ID, groupIds: [GROUP.id] }],
    objects: OBJECTS,
    ...overrides,
  } as PolicySnapshot;
}

/** A catalog in memory: Objects and fields as `objects` holds them, and these group and Profile ids. */
function catalog(
  objects = OBJECTS,
  groupIds = [GROUP.id, OTHER_GROUP.id],
  profileIds = [PROFILE_ID]
): DecisionLogCatalog & { lookups: string[] } {
  const lookups: string[] = [];
  return {
    lookups,
    objectName(name) {
      lookups.push(`object:${name}`);
      return (
        objects.find((o) => o.objectName === name)?.objectName ??
        objects.find((o) => o.objectName.toLowerCase() === name.toLowerCase())?.objectName ??
        null
      );
    },
    fieldNames(objectName) {
      lookups.push(`fields:${objectName}`);
      return objects.find((o) => o.objectName === objectName)?.fields.map((f) => f.fieldName) ?? [];
    },
    hasGroup(groupId) {
      lookups.push(`group:${groupId}`);
      return groupIds.includes(groupId);
    },
    hasProfile(profileId) {
      lookups.push(`profile:${profileId}`);
      return profileIds.includes(profileId);
    },
  };
}

const decide = (tool: string, args: Record<string, unknown>, snap = snapshot()) => evaluatePolicy(SUBJECT, tool, args, snap);

const step = (stage: PolicyStage, objectName: string | null, fieldNames: string[], result: 'pass' | 'fail' = 'pass') => ({
  stage,
  result,
  objectName,
  fieldNames,
});

describe('decisionLogColumns', () => {
  test('an allowed call keeps every stage, its granting groups, and the Object and fields in the catalog spelling', () => {
    const decision = decide('soql_query', { objectName: 'case', fields: ['id', 'SUBJECT'], whereClause: "status = 'Open'" });
    assert.equal(decision.outcome, 'allowed');

    const columns = decisionLogColumns(decision, catalog());

    assert.deepEqual(columns.decision, {
      outcome: 'allowed',
      code: 'ALLOWED',
      stage: 'input',
      steps: [
        { stage: 'tool', result: 'pass', grantingGroupIds: [], objectName: null, fieldNames: [] },
        { stage: 'identity', result: 'pass', grantingGroupIds: [], objectName: null, fieldNames: [] },
        { stage: 'groups', result: 'pass', grantingGroupIds: [], objectName: null, fieldNames: [] },
        { stage: 'tool_grant', result: 'pass', grantingGroupIds: [GROUP.id], objectName: null, fieldNames: [] },
        { stage: 'object', result: 'pass', grantingGroupIds: [GROUP.id], objectName: 'Case', fieldNames: [] },
        { stage: 'crud', result: 'pass', grantingGroupIds: [GROUP.id], objectName: 'Case', fieldNames: [] },
        { stage: 'fields', result: 'pass', grantingGroupIds: [GROUP.id], objectName: 'Case', fieldNames: ['Id', 'Subject'] },
        { stage: 'where', result: 'pass', grantingGroupIds: [GROUP.id], objectName: 'Case', fieldNames: ['Status'] },
        { stage: 'input', result: 'pass', grantingGroupIds: [], objectName: 'Case', fieldNames: [] },
      ],
      decidingGroupIds: [GROUP.id],
      matchMethod: 'id',
      policyRevision: 42,
    });
    assert.deepEqual(
      { ...columns, decision: undefined },
      {
        decision: undefined,
        stage: 'input',
        code: 'ALLOWED',
        assignedGroupIds: [GROUP.id],
        decidingGroupIds: [GROUP.id],
        policyRevision: 42,
        callerProfileId: PROFILE_ID,
        matchedProfileId: PROFILE_ID,
        matchMethod: 'id',
      }
    );
  });

  test('a refusal keeps the failing stage and the names it refused, and never the reason or a value', () => {
    const secret = 'jane.doe@acme.example';
    const cases: Array<[string, Record<string, unknown>, string, string]> = [
      ['soql_query', { objectName: 'Case', fields: ['Id', 'SSN__c', secret] }, 'fields', 'FIELD_NOT_PERMITTED'],
      ['soql_query', { objectName: 'Case', fields: ['Id'], whereClause: `SSN__c = '${secret}'` }, 'where', 'WHERE_FIELD_NOT_PERMITTED'],
      ['soql_query', { objectName: 'Case', fields: ['Id'], whereClause: `(Subject = '${secret}'` }, 'input', 'INPUT_INVALID'],
      ['get_record', { objectName: 'Case', recordId: secret }, 'input', 'INPUT_INVALID'],
      ['update_record', { objectName: 'Case', recordId: '500000000000001AAA', fields: { Subject: secret, Ghost__c: 1 } }, 'fields', 'FIELD_NOT_PERMITTED'],
      ['soql_query', { objectName: secret }, 'input', 'INPUT_INVALID'],
      ['soql_query', { objectName: 'Account' }, 'object', 'OBJECT_NOT_GRANTED'],
    ];
    for (const [tool, args, stage, code] of cases) {
      const decision = decide(tool, args);
      const columns = decisionLogColumns(decision, catalog());
      const stored = JSON.stringify(columns);

      assert.equal(columns.decision.code, code, `${tool} ${JSON.stringify(args)}`);
      assert.equal(columns.stage, stage);
      assert.equal(columns.decision.stage, stage);
      assert.equal(columns.decision.steps.at(-1)?.result, 'fail');
      assert.deepEqual(columns.decidingGroupIds, []);
      assert.ok(!stored.includes(secret), `no value is stored: ${stored}`);
      assert.ok(!stored.includes(decision.reason), 'the reason text is not stored');
      assert.ok(!('reason' in columns.decision) && !('allowedFields' in columns.decision));
    }

    const fields = decisionLogColumns(decide('soql_query', { objectName: 'Case', fields: ['Id', 'SSN__c', secret] }), catalog());
    assert.deepEqual(fields.decision.steps.at(-1), {
      stage: 'fields',
      result: 'fail',
      grantingGroupIds: [],
      objectName: 'Case',
      // SSN__c is a catalog field (disabled, so refused) and stays; the e-mail address is not a name.
      fieldNames: ['SSN__c', `<invalid:len=${secret.length}>`],
    });
    const notAnObject = decisionLogColumns(decide('soql_query', { objectName: secret }), catalog());
    assert.equal(notAnObject.decision.steps.at(-1)?.objectName, `<invalid:len=${secret.length}>`);
  });

  test('a name the catalog does not hold is stored by its length, even when it looks like an API name', () => {
    const decision: PolicyDecision = {
      ...decide('soql_query', { objectName: 'Case', fields: ['Id'] }),
      steps: [
        { ...step('object', 'Opportunity', []), grantingGroupIds: [], ruleId: null },
        { ...step('fields', 'Case', ['Subject', 'Ghost__c', 'Owner.Name', '']), grantingGroupIds: [GROUP.id, 'grp_gone'], ruleId: null },
        { ...step('fields', 'Ghost_Object__c', ['Subject']), grantingGroupIds: [], ruleId: null },
      ],
      decidingGroupIds: [GROUP.id, 'grp_gone'],
      assignedGroups: [GROUP, { id: 'grp_gone', name: 'Gone' }],
    };

    const columns = decisionLogColumns(decision, catalog());

    assert.deepEqual(columns.decision.steps, [
      { stage: 'object', result: 'pass', grantingGroupIds: [], objectName: '<invalid:len=11>', fieldNames: [] },
      {
        stage: 'fields',
        result: 'pass',
        grantingGroupIds: [GROUP.id, '<invalid:len=8>'],
        objectName: 'Case',
        fieldNames: ['Subject', '<invalid:len=8>', '<invalid:len=10>', '<invalid:len=0>'],
      },
      // A field is checked against its own Object, so none of an unknown Object's fields is kept.
      { stage: 'fields', result: 'pass', grantingGroupIds: [], objectName: '<invalid:len=15>', fieldNames: ['<invalid:len=7>'] },
    ]);
    assert.deepEqual(columns.decidingGroupIds, [GROUP.id, '<invalid:len=8>']);
    assert.deepEqual(columns.decision.decidingGroupIds, columns.decidingGroupIds);
    assert.deepEqual(columns.assignedGroupIds, [GROUP.id, '<invalid:len=8>']);
  });

  test('each list of field names keeps at most 200 and counts the rest, and the catalog is asked once per name', () => {
    const many = Array.from({ length: MAX_LOGGED_NAMES + 50 }, (_, i) => (i % 2 === 0 ? 'Subject' : `Extra_${i}__c`));
    const decision = decide('soql_query', { objectName: 'Case', fields: many });
    const lookups = catalog();

    const failed = decisionLogColumns(decision, lookups).decision.steps.at(-1)!;

    // Of the 250 names, the 125 Extra_ ones are refused, so the failed step lists 125 and drops none.
    assert.equal(failed.fieldNames.length, 125);
    assert.equal(failed.fieldNamesDropped, undefined);

    const allowedMany = Array.from({ length: MAX_LOGGED_NAMES + 50 }, () => 'Subject');
    const passed = decisionLogColumns(decide('soql_query', { objectName: 'Case', fields: allowedMany }), lookups).decision.steps.find(
      (s) => s.stage === 'fields'
    )!;
    assert.equal(passed.fieldNames.length, MAX_LOGGED_NAMES);
    assert.equal(passed.fieldNamesDropped, 50);
    assert.equal(lookups.lookups.filter((l) => l === 'fields:Case').length, 2, 'one field lookup per Object per decision');
  });

  test('a refusal of more than 200 fields keeps 200 and counts the rest', () => {
    const refused = Array.from({ length: MAX_LOGGED_NAMES + 7 }, (_, i) => `Extra_${i}__c`);
    const failed = decisionLogColumns(decide('soql_query', { objectName: 'Case', fields: refused }), catalog()).decision.steps.at(-1)!;
    assert.equal(failed.fieldNames.length, MAX_LOGGED_NAMES);
    assert.equal(failed.fieldNamesDropped, 7);
  });

  test('skipped entries keep the group, the position and a fixed reason only', () => {
    const groups = snapshot().groups;
    const snap = snapshot({
      groups: [
        {
          ...groups[0],
          objectPermissions: [{ objectName: 7, canRead: true }, ...groups[0].objectPermissions, { objectName: 'Case', canRead: 'yes' }] as never,
        },
      ],
    });
    const decision = decide('soql_query', { objectName: 'Case', fields: ['Id'] }, snap);
    assert.equal(decision.skippedGroupEntries?.length, 2);

    const columns = decisionLogColumns(decision, catalog());
    assert.deepEqual(columns.decision.skippedEntries, [
      { groupId: GROUP.id, index: 0, reason: 'objectName is not text' },
      { groupId: GROUP.id, index: 2, reason: 'canRead is not true or false' },
    ]);

    const leaked = "canRead is 'jane.doe@acme.example'";
    const tampered: PolicyDecision = {
      ...decision,
      skippedGroupEntries: [
        { groupId: GROUP.id, index: 1, reason: leaked },
        ...Array.from({ length: MAX_LOGGED_NAMES + 3 }, (_, index) => ({ groupId: 'grp_gone', index, reason: 'objectName is not text' })),
      ],
    };
    const capped = decisionLogColumns(tampered, catalog()).decision;
    assert.deepEqual(capped.skippedEntries?.[0], { groupId: GROUP.id, index: 1, reason: `<invalid:len=${leaked.length}>` });
    assert.deepEqual(capped.skippedEntries?.[1], { groupId: '<invalid:len=8>', index: 0, reason: 'objectName is not text' });
    assert.equal(capped.skippedEntries?.length, MAX_LOGGED_NAMES);
    assert.equal(capped.skippedEntriesDropped, 4);
  });

  test('every reason malformedGrantReason gives is one the log keeps', () => {
    const malformed = [null, [], 'x', { objectName: 1 }, { objectName: 'A', allowedFields: 'Id' }, { objectName: 'A', allowedFields: [1] }];
    for (const flag of ['canRead', 'canCreate', 'canUpdate', 'canDelete']) malformed.push({ objectName: 'A', [flag]: 'true' } as never);
    const reasons = new Set(malformed.map((entry) => malformedGrantReason(entry)));
    assert.deepEqual([...reasons].sort(), [...MALFORMED_GRANT_REASONS].sort());
  });

  test('the caller\'s Profile id is kept only in the form of a Salesforce id, and the matched one only when the registry has it', () => {
    // PROFILE_ID is a Salesforce id, so another id with its name is not matched: the caller's id is kept, no match.
    const byName = evaluatePolicy({ ...SUBJECT, profileId: '00e000000000ZZZ' }, 'soql_query', { objectName: 'Case' }, snapshot());
    assert.equal(byName.identity.matchMethod, 'none');
    assert.deepEqual(
      (({ callerProfileId, matchedProfileId, matchMethod }) => ({ callerProfileId, matchedProfileId, matchMethod }))(
        decisionLogColumns(byName, catalog())
      ),
      { callerProfileId: '00e000000000ZZZ', matchedProfileId: '', matchMethod: 'none' }
    );

    for (const [profileId, stored] of [
      ['', ''],
      ['jane.doe@acme.example', '<invalid:len=21>'],
    ]) {
      const unknown = evaluatePolicy({ ...SUBJECT, profileId, profileName: 'Unregistered' }, 'soql_query', { objectName: 'Case' }, snapshot());
      const columns = decisionLogColumns(unknown, catalog());
      assert.equal(columns.decision.code, 'PROFILE_UNREGISTERED');
      assert.deepEqual([columns.callerProfileId, columns.matchedProfileId, columns.matchMethod], [stored, '', 'none']);
    }

    // The engine matches an id with spaces around it, but the log keeps only the id as Salesforce writes one.
    const padded = evaluatePolicy({ ...SUBJECT, profileId: ` ${PROFILE_ID}` }, 'soql_query', { objectName: 'Case' }, snapshot());
    const columns = decisionLogColumns(padded, catalog());
    assert.deepEqual([columns.callerProfileId, columns.matchedProfileId], ['<invalid:len=19>', PROFILE_ID]);
  });

  test('a registered Profile whose id is not in the form of a Salesforce id is kept as the registry holds it', () => {
    // The CSV import and older rows can register any id. The matched id is the registry's, not the caller's.
    const salesOps = { id: 'SALES_OPS', name: 'Sales Ops', updatedAt: '' };
    const snap = snapshot({ profiles: [salesOps], mappings: [{ profileId: salesOps.id, groupIds: [GROUP.id] }] });
    const lookups = catalog(OBJECTS, [GROUP.id], [salesOps.id]);

    const byName = evaluatePolicy({ ...SUBJECT, profileName: 'Sales Ops' }, 'soql_query', { objectName: 'Case' }, snap);
    assert.deepEqual([byName.outcome, byName.identity.matchMethod], ['allowed', 'name']);
    const named = decisionLogColumns(byName, lookups);
    assert.deepEqual([named.callerProfileId, named.matchedProfileId, named.matchMethod], [PROFILE_ID, 'SALES_OPS', 'name']);

    // Simulated under that id: matched by id, while the caller's id, not one Salesforce could give, is not kept.
    const byId = evaluatePolicy({ ...SUBJECT, profileId: salesOps.id }, 'soql_query', { objectName: 'Case' }, snap);
    const simulated = decisionLogColumns(byId, lookups);
    assert.deepEqual([simulated.callerProfileId, simulated.matchedProfileId, simulated.matchMethod], ['<invalid:len=9>', 'SALES_OPS', 'id']);

    // An id the registry does not have is stored by its length, as an unknown group id is.
    const forged: PolicyDecision = { ...byName, identity: { ...byName.identity, matchedProfileId: 'jane.doe@acme.example' } };
    assert.equal(decisionLogColumns(forged, lookups).matchedProfileId, '<invalid:len=21>');
    assert.ok(lookups.lookups.includes('profile:SALES_OPS'));
  });

  test('an error decision keeps the steps it passed and the stage evaluation stopped at', () => {
    const decision = evaluatePolicy(SUBJECT, 'soql_query', { objectName: 'Case' }, { ...snapshot(), groups: null } as never);
    assert.equal(decision.code, 'INTERNAL_ERROR');
    const columns = decisionLogColumns(decision, catalog());
    assert.deepEqual([columns.decision.outcome, columns.code, columns.stage, columns.decision.steps], ['error', 'INTERNAL_ERROR', '', []]);
    assert.equal(columns.policyRevision, 42);
  });

  test('a refused token and an outage are one failed step at auth or upstream, with no policy revision', () => {
    for (const [decision, outcome, stage, code] of [
      [tokenRejectedDecision('TOKEN_INVALID'), 'denied', 'auth', 'TOKEN_INVALID'],
      [tokenRejectedDecision('ORG_LOCK_VIOLATION'), 'denied', 'auth', 'ORG_LOCK_VIOLATION'],
      [tokenRejectedDecision('INSTANCE_NOT_ALLOWED'), 'denied', 'auth', 'INSTANCE_NOT_ALLOWED'],
      [UPSTREAM_UNAVAILABLE_DECISION, 'error', 'upstream', 'UPSTREAM_UNAVAILABLE'],
    ] as const) {
      const lookups = catalog();
      assert.deepEqual(decisionLogColumns(decision, lookups), {
        decision: {
          outcome,
          code,
          stage,
          steps: [{ stage, result: 'fail', grantingGroupIds: [], objectName: null, fieldNames: [] }],
          decidingGroupIds: [],
          matchMethod: 'none',
          policyRevision: null,
        },
        stage,
        code,
        assignedGroupIds: [],
        decidingGroupIds: [],
        policyRevision: null,
        callerProfileId: '',
        matchedProfileId: '',
        matchMethod: 'none',
      });
      assert.deepEqual(lookups.lookups, [], 'nothing is looked up for a request no policy was read for');
    }
  });

  test('every stage and code the engine can give is stored as itself, and anything else is not', () => {
    const base = decide('soql_query', { objectName: 'Case', fields: ['Id'] });
    for (const stage of POLICY_STAGES) {
      const columns = decisionLogColumns({ ...base, steps: [{ ...base.steps[0], stage }] }, catalog());
      assert.equal(columns.stage, stage);
    }
    for (const code of POLICY_DECISION_CODES) {
      assert.equal(decisionLogColumns({ ...base, code }, catalog()).code, code);
    }
    const forged = { ...base, code: 'Owner.Email', steps: [{ ...base.steps[0], stage: 'jane@acme' }] } as never as PolicyDecision;
    const columns = decisionLogColumns(forged, catalog());
    assert.deepEqual([columns.code, columns.stage], ['<invalid:len=11>', '<invalid:len=9>']);
  });
});

describe('policySnapshotCatalog', () => {
  test('a decision is checked against the snapshot it was made from, so a later change cannot unname it', () => {
    const snap = snapshot();
    const decision = decide('update_record', { objectName: 'case', recordId: '500000000000001AAA', fields: { subject: 'x' } }, snap);
    assert.equal(decision.outcome, 'allowed');

    const columns = decisionLogColumns(decision, policySnapshotCatalog(snap));
    assert.deepEqual(columns, decisionLogColumns(decision, catalog()), 'the same columns as the catalog the snapshot was read from');
    assert.deepEqual([columns.assignedGroupIds, columns.decidingGroupIds, columns.matchedProfileId], [[GROUP.id], [GROUP.id], PROFILE_ID]);
    assert.deepEqual(
      columns.decision.steps.find((s) => s.stage === 'fields'),
      { stage: 'fields', result: 'pass', grantingGroupIds: [GROUP.id], objectName: 'Case', fieldNames: ['Subject'] }
    );

    // Read after the group, the Profile and the Object were deleted, the policy holds none of them.
    const later = snapshot({ profiles: [], groups: [], mappings: [], objects: [catalogObject('Account', [['Id']])] });
    const afterwards = decisionLogColumns(decision, policySnapshotCatalog(later));
    assert.deepEqual(
      [afterwards.decidingGroupIds, afterwards.matchedProfileId, afterwards.decision.steps.find((s) => s.stage === 'fields')?.objectName],
      [['<invalid:len=11>'], '<invalid:len=18>', '<invalid:len=4>']
    );
  });

  test('an Object is found as the store finds one: its own spelling, else the first in name order that differs only by case', () => {
    const lookups = policySnapshotCatalog(
      snapshot({ objects: [catalogObject('case', [['id']]), catalogObject('Case', [['Id'], ['Subject']]), catalogObject('CASE', [['ID']])] })
    );
    assert.deepEqual(
      ['Case', 'case', 'CASE', 'cAsE', 'Account', 'Case '].map((name) => lookups.objectName(name)),
      ['Case', 'case', 'CASE', 'CASE', null, null]
    );
    assert.deepEqual(lookups.fieldNames('Case'), ['Id', 'Subject']);
    assert.deepEqual(lookups.fieldNames('cAsE'), [], 'fields are read for the stored spelling only');
    assert.deepEqual([lookups.hasGroup(GROUP.id), lookups.hasGroup(OTHER_GROUP.id)], [true, false]);
    assert.deepEqual([lookups.hasProfile(PROFILE_ID), lookups.hasProfile(PROFILE_ID.slice(0, 15))], [true, false]);
  });
});
