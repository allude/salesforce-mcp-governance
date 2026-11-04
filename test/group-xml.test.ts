import './helpers/env.js';
// The Access Group XML format (export, import and the editor's XML view), what makes a grant not
// available or broken, the change lines history records, and the drawer's draft helpers.
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import type { AccessGroup, GroupObjectPermission, SalesforceObject } from '../src/types/governance.js';
import { accessGroupToXml, parseAccessGroupXml, type AccessGroupDocument } from '../src/groups/groupXml.js';
import {
  describeGroupChanges,
  groupAvailabilityIssues,
  normalizeMcpActions,
  normalizeObjectPermissions,
} from '../src/groups/groupGrants.js';
import {
  importTargetFor,
  nameForImportedCopy,
  removeEntryField,
  restoreHeldField,
  restoreHeldObject,
  setAvailableFields,
} from '../src/components/views/accessGroupDraft.js';

const perm = (objectName: string, extra: Partial<GroupObjectPermission> = {}): GroupObjectPermission => ({
  objectName,
  canRead: true,
  canCreate: false,
  canUpdate: false,
  canDelete: false,
  allowedFields: ['Id'],
  ...extra,
});

const catalogObject = (
  objectName: string,
  fields: Array<{ fieldName: string; enabled?: boolean; missingInOrg?: boolean }>,
  extra: Partial<SalesforceObject> = {}
): SalesforceObject => ({
  objectName,
  label: objectName,
  isCustom: objectName.endsWith('__c'),
  enabled: true,
  sourcePath: 'manual',
  fieldCount: fields.length,
  enabledFieldCount: fields.filter((f) => f.enabled !== false).length,
  fields: fields.map((f) => ({
    objectName,
    fieldName: f.fieldName,
    label: f.fieldName,
    fieldType: 'Text',
    isCustom: f.fieldName.endsWith('__c'),
    required: false,
    enabled: f.enabled !== false,
    missingInOrg: f.missingInOrg,
  })),
  updatedAt: '2026-11-01T00:00:00.000Z',
  ...extra,
});

const sample: AccessGroupDocument = {
  id: 'grp_sales_1',
  name: 'Sales <Read> & "Write"',
  description: "Pipeline access for AE's",
  allowedActions: ['soql_query', 'query_records'],
  objectPermissions: [
    perm('Account', { canUpdate: true, allowedFields: ['Id', 'Name'], removedFields: [{ fieldName: 'Secret__c', at: '2026-11-02T10:00:00.000Z', by: 'alice@acme.example' }] }),
    perm('Salary__c', { removed: { at: '2026-11-01T09:00:00.000Z', by: 'bob@acme.example' } }),
    perm('Empty__c', { allowedFields: [] }),
  ],
};

const parsedOk = (xml: string) => {
  const result = parseAccessGroupXml(xml);
  assert.ok(result.ok, JSON.stringify(result));
  return result.group;
};

const parseError = (xml: string) => {
  const result = parseAccessGroupXml(xml);
  assert.equal(result.ok, false, 'expected the XML to be rejected');
  return result as { ok: false; error: string; line?: number };
};

const wrap = (body: string) => `<?xml version="1.0"?>\n<AccessGroup version="1">\n  <name>G</name>\n${body}\n</AccessGroup>`;

describe('XML export and import', () => {
  test('a group survives the round trip, held entries, unknown tools and special characters included', () => {
    assert.deepEqual(parsedOk(accessGroupToXml(sample)), sample);
  });

  test('with the catalog, each line naming something not available says why, and reading ignores it', () => {
    const xml = accessGroupToXml(sample, { objects: [catalogObject('Account', [{ fieldName: 'Id' }, { fieldName: 'Name' }])] });
    assert.match(xml, /<action>query_records<\/action> <!-- NOT AVAILABLE: Not an MCP tool on this server/);
    assert.match(xml, /<object name="Salary__c"[^>]*> <!-- NOT AVAILABLE: Deleted from Salesforce > Objects by bob@acme.example on 2026-11-01/);
    assert.match(xml, /<object name="Empty__c"[^>]*\/> <!-- NOT AVAILABLE: Not in Salesforce > Objects/);
    assert.match(xml, /Secret__c<\/field> <!-- NOT AVAILABLE: Deleted from Salesforce > Objects by alice@acme.example/);
    assert.doesNotMatch(xml, /<field>Name<\/field> <!--/);
    assert.deepEqual(parsedOk(xml), sample);
  });

  test('a minimal file is a group with nothing granted', () => {
    assert.deepEqual(parsedOk('<AccessGroup><name> Minimal </name></AccessGroup>'), {
      name: 'Minimal',
      description: '',
      allowedActions: [],
      objectPermissions: [],
    });
  });

  test('omitted access flags are false, and true/false are read in any case', () => {
    const group = parsedOk(wrap('<objects><object name="Case" read="TRUE" delete="False"><field>Id</field></object></objects>'));
    assert.deepEqual(group.objectPermissions, [perm('Case')]);
  });

  test('CDATA, numeric entities and comments are read', () => {
    const group = parsedOk(wrap('<description><![CDATA[a < b]]> &#38; &#x263A;</description><!-- note -->'));
    assert.equal(group.description, 'a < b & ☺');
  });

  test('a field held in a file and granted in it stays held', () => {
    const group = parsedOk(wrap('<objects><object name="Case"><field>Id</field><field removedAt="x">id</field></object></objects>'));
    assert.deepEqual(group.objectPermissions[0].allowedFields, []);
    assert.deepEqual(group.objectPermissions[0].removedFields, [{ fieldName: 'id', at: 'x', by: '' }]);
  });

  const rejected: Array<[string, string, RegExp, number?]> = [
    ['a misspelled element', wrap('  <objets/>'), /<objets> is not allowed in <AccessGroup>/, 4],
    ['a misspelled attribute', wrap('<objects>\n<object name="Case" reed="true"/>\n</objects>'), /unknown attribute reed/, 5],
    ['a flag that is not true or false', wrap('<objects><object name="Case" read="yes"/></objects>'), /must be "true" or "false"/],
    ['an object listed twice', wrap('<objects>\n<object name="Case"/>\n<object name="CASE"/>\n</objects>'), /CASE is already listed on line 5/, 6],
    ['an object name that is not an API name', wrap('<objects><object name="Case; DELETE"/></objects>'), /not a valid Salesforce object API name/],
    ['a field name that is not an API name', wrap('<objects><object name="Case"><field>Id, Name</field></object></objects>'), /not a valid Salesforce field API name/],
    ['an action ID that is not an ID', wrap('<mcpActions><action>drop table</action></mcpActions>'), /not a valid MCP action ID/],
    ['another root element', '<CustomObject><label>X</label></CustomObject>', /root element must be <AccessGroup>/],
    ['a DOCTYPE', '<!DOCTYPE x [<!ENTITY a "b">]><AccessGroup><name>G</name></AccessGroup>', /DOCTYPE/],
    ['an unclosed element', '<AccessGroup>\n<name>G</name>\n<objects>\n</AccessGroup>', /Expected <\/objects> \(opened on line 3\)/, 4],
    ['a group without a name', '<AccessGroup><description>x</description></AccessGroup>', /needs a <name>/],
    ['another format version', '<AccessGroup version="2"><name>G</name></AccessGroup>', /version 1, not 2/],
    ['a bare ampersand', wrap('<description>R & D</description>'), /must start an entity/],
    ['text where elements belong', wrap('<objects>Case</objects>'), /holds elements, not text/],
    ['two groups in one file', '<AccessGroup><name>A</name></AccessGroup><AccessGroup><name>B</name></AccessGroup>', /only one <AccessGroup>/],
    ['an empty file', '   ', /no XML elements/],
  ];
  for (const [what, xml, message, line] of rejected) {
    test(`rejects ${what}`, () => {
      const result = parseError(xml);
      assert.match(result.error, message);
      if (line !== undefined) assert.equal(result.line, line);
    });
  }
});

describe('what is not available, and what is broken', () => {
  const objects = [
    catalogObject('Account', [{ fieldName: 'Id' }, { fieldName: 'Name', enabled: false }, { fieldName: 'Phone', missingInOrg: true }]),
    catalogObject('Case', [{ fieldName: 'Id' }], { enabled: false }),
    catalogObject('Lead', [{ fieldName: 'Id' }], { missingInOrg: true }),
    catalogObject('Salary__c', [{ fieldName: 'Id' }]),
  ];
  const reasons = (group: Pick<AccessGroup, 'allowedActions' | 'objectPermissions'>) =>
    groupAvailabilityIssues(group, objects).map((i) => [i.kind, i.objectName ? `${i.objectName}:${i.name}` : i.name, i.reason, i.status]);

  test('names each item with its reason, and only the org-missing ones as broken', () => {
    assert.deepEqual(
      reasons({
        allowedActions: ['soql_query', 'query_records'],
        objectPermissions: [
          perm('account', { allowedFields: ['Id', 'Name', 'Phone', 'Fax'], removedFields: [{ fieldName: 'Secret__c', at: '', by: '' }] }),
          perm('Case'),
          perm('Lead'),
          perm('Ghost__c'),
          perm('Salary__c', { removed: { at: '2026-11-01T00:00:00.000Z', by: 'bob' } }),
        ],
      }),
      [
        ['action', 'query_records', 'unknown_action', 'unavailable'],
        ['field', 'account:Name', 'field_disabled', 'unavailable'],
        ['field', 'account:Phone', 'field_missing_in_org', 'broken'],
        ['field', 'account:Fax', 'field_not_in_catalog', 'unavailable'],
        ['field', 'account:Secret__c', 'field_deleted', 'unavailable'],
        ['object', 'Case:Case', 'object_disabled', 'unavailable'],
        ['object', 'Lead:Lead', 'object_missing_in_org', 'broken'],
        ['object', 'Ghost__c:Ghost__c', 'object_not_in_catalog', 'unavailable'],
        ['object', 'Salary__c:Salary__c', 'object_deleted', 'unavailable'],
      ]
    );
  });

  test('a deleted object that was imported again is still not available, and says it is back', () => {
    const [issue] = groupAvailabilityIssues(
      { allowedActions: [], objectPermissions: [perm('Salary__c', { removed: { at: '2026-11-01T00:00:00.000Z', by: 'bob' } })] },
      objects
    );
    assert.match(issue.message, /by bob on 2026-11-01\. It grants nothing until an admin restores it, although the object is back/);
  });

  test('a group of available grants has no issues', () => {
    assert.deepEqual(reasons({ allowedActions: ['soql_query'], objectPermissions: [perm('Account')] }), []);
  });
});

describe('the shape a saved group must have', () => {
  test('action IDs: strings of the right shape, each once; unknown tools kept', () => {
    assert.deepEqual(normalizeMcpActions([' soql_query', 'soql_query', 'future_tool']), { ok: true, value: ['soql_query', 'future_tool'] });
    assert.equal(normalizeMcpActions(['ok', 5]).ok, false);
    assert.equal(normalizeMcpActions('soql_query').ok, false);
  });

  test('object entries: only true grants, fields once, held fields win over granted ones', () => {
    const result = normalizeObjectPermissions([
      { objectName: ' Account ', canRead: 'true', canCreate: true, allowedFields: ['Id', 'ID', 'Name'], removedFields: [{ fieldName: 'name', at: 1 }] },
    ]);
    assert.deepEqual(result, {
      ok: true,
      value: [
        {
          objectName: 'Account',
          canRead: false,
          canCreate: true,
          canUpdate: false,
          canDelete: false,
          allowedFields: ['Id'],
          removedFields: [{ fieldName: 'name', at: '', by: '' }],
        },
      ],
    });
  });

  test('a removal marker in any form keeps the entry held', () => {
    const result = normalizeObjectPermissions([{ objectName: 'Account', canRead: true, removed: true }]);
    assert.ok(result.ok && result.value[0].removed);
  });

  test('rejects duplicate objects and names that are not API names', () => {
    assert.match((normalizeObjectPermissions([perm('Case'), perm('case')]) as { error: string }).error, /listed more than once/);
    assert.match((normalizeObjectPermissions([perm('Case Detail')]) as { error: string }).error, /not a valid Salesforce object API name/);
    assert.match((normalizeObjectPermissions([perm('Case', { allowedFields: ['a.b'] })]) as { error: string }).error, /field API name/);
  });
});

describe('change lines for history', () => {
  const before = {
    name: 'Sales',
    description: 'Old',
    allowedActions: ['soql_query', 'get_record'],
    objectPermissions: [
      perm('Account', { allowedFields: ['Id', 'Name'] }),
      perm('Case'),
      perm('Lead', { removed: { at: '', by: 'x' } }),
      perm('Contact', { allowedFields: ['Id'], removedFields: [{ fieldName: 'Email', at: '', by: '' }] }),
    ],
  };

  test('a creation lists what the group was created with', () => {
    assert.deepEqual(describeGroupChanges(null, { ...before, objectPermissions: [before.objectPermissions[0], before.objectPermissions[2]] }), [
      'MCP actions: soql_query, get_record.',
      'Account (R) with fields Id, Name.',
      'Lead (R) with fields Id; the object is held as deleted from Salesforce > Objects.',
    ]);
  });

  test('an edit lists each change', () => {
    const after = {
      name: 'Sales RW',
      description: 'New',
      allowedActions: ['soql_query', 'update_record'],
      objectPermissions: [
        perm('Account', { canUpdate: true, allowedFields: ['Id', 'Phone'] }),
        perm('Lead'),
        perm('Contact', { allowedFields: ['Id', 'Email'] }),
        perm('Opportunity'),
      ],
    };
    assert.deepEqual(describeGroupChanges(before, after), [
      'Renamed from "Sales" to "Sales RW".',
      'Description changed from "Old" to "New".',
      'Added MCP actions: update_record.',
      'Removed MCP actions: get_record.',
      'Account access changed from R to R·U.',
      'Account fields added: Phone.',
      'Account fields removed: Name.',
      'Lead restored: it grants again while the object is in Salesforce > Objects.',
      'Contact fields restored: Email.',
      'Added Opportunity (R) with fields Id.',
      'Removed Case (R) from the group.',
    ]);
  });

  test('nothing granted changed means no lines', () => {
    assert.deepEqual(describeGroupChanges(before, structuredClone(before)), []);
  });
});

describe('the drawer draft', () => {
  const groups: AccessGroup[] = [
    { id: 'grp_a', name: 'Sales Read', description: '', allowedActions: [], objectPermissions: [], updatedAt: '' },
    { id: 'grp_b', name: 'Sales Read (imported)', description: '', allowedActions: [], objectPermissions: [], updatedAt: '' },
  ];

  test('an import updates the group it came from, else the one with its name, else a new one', () => {
    assert.deepEqual(importTargetFor(groups, { ...sample, id: 'grp_b', name: 'Anything' }), { group: groups[1], matchedBy: 'id' });
    assert.deepEqual(importTargetFor(groups, { ...sample, id: 'grp_elsewhere', name: ' sales read ' }), { group: groups[0], matchedBy: 'name' });
    assert.equal(importTargetFor(groups, { ...sample, id: undefined, name: 'Brand new' }), null);
  });

  test('saving an import as new picks a free name', () => {
    assert.equal(nameForImportedCopy(groups, 'Sales Read'), 'Sales Read (imported 2)');
    assert.equal(nameForImportedCopy(groups, 'Other'), 'Other');
  });

  const draft = { name: 'D', description: '', allowedActions: [], objectPermissions: sample.objectPermissions };

  test('restoring a held object clears its marker; restoring a held field grants it again', () => {
    assert.equal(restoreHeldObject(draft, 'salary__c').objectPermissions[1].removed, undefined);
    const account = restoreHeldField(draft, 'Account', 'secret__c').objectPermissions[0];
    assert.deepEqual(account.allowedFields, ['Id', 'Name', 'secret__c']);
    assert.equal(account.removedFields, undefined);
  });

  test('a held field can be removed outright', () => {
    const account = removeEntryField(draft, 'Account', 'Secret__c').objectPermissions[0];
    assert.deepEqual(account.allowedFields, ['Id', 'Name']);
    assert.equal(account.removedFields, undefined);
  });

  test('All and None change only fields that are available, keeping the rest for review', () => {
    const object = catalogObject('Account', [{ fieldName: 'Id' }, { fieldName: 'Name', enabled: false }, { fieldName: 'Phone' }]);
    const withGone = { ...draft, objectPermissions: [perm('Account', { allowedFields: ['Name', 'Gone__c', 'Id'] })] };
    assert.deepEqual(setAvailableFields(withGone, object, false).objectPermissions[0].allowedFields, ['Name', 'Gone__c']);
    assert.deepEqual(setAvailableFields(withGone, object, true).objectPermissions[0].allowedFields, ['Name', 'Gone__c', 'Id', 'Phone']);
  });
});
