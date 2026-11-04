import './helpers/env.js';
// Pure unit tests for how grants held as deleted from Salesforce > Objects are read: an entry held as
// deleted (`removed`) and the fields an entry holds (`removedFields`) grant nothing, no merge folds them
// into live grants, a save that restores one is detected, and the audit diff shows it.
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import {
  effectiveGrants,
  isHeldGrant,
  mergeGrants,
  readableGrants,
  restoresHeldGrant,
} from '../src/rbac/groupGrants.js';
import { groupAuditFields, groupUpdateDiff } from '../src/routes/groupAuditDiff.js';
import { describeGroupChanges, groupAvailabilityIssues } from '../src/groups/groupGrants.js';
import { accessGroupToXml, parseAccessGroupXml } from '../src/groups/groupXml.js';
import { groupDraftContent } from '../src/components/views/accessGroupDraft.js';
import type { AccessGroup, GroupObjectPermission, SalesforceObject } from '../src/types/governance.js';

const REMOVAL = { at: '2026-10-02T00:00:00.000Z', by: 'admin' };
const heldField = (fieldName: string) => ({ fieldName, ...REMOVAL });
const grant = (objectName: string, more: Partial<GroupObjectPermission> = {}): GroupObjectPermission => ({
  objectName,
  canRead: true,
  canCreate: false,
  canUpdate: false,
  canDelete: false,
  allowedFields: ['Id'],
  ...more,
});
const groupWith = (objectPermissions: unknown[]): AccessGroup =>
  ({
    id: 'grp_held',
    name: 'Held',
    description: '',
    allowedActions: ['soql_query'],
    objectPermissions,
    version: 1,
    updatedAt: '2026-10-02T00:00:00.000Z',
  }) as AccessGroup;

describe('isHeldGrant', () => {
  test('any marker but false, null or undefined holds an entry', () => {
    for (const removed of [REMOVAL, true, 'yes', 1, {}, []]) {
      assert.equal(isHeldGrant({ objectName: 'Account', removed }), true, JSON.stringify(removed));
    }
    for (const removed of [false, null, undefined, 0, '']) {
      assert.equal(isHeldGrant({ objectName: 'Account', removed }), false, JSON.stringify(removed));
    }
    for (const entry of [null, undefined, 'Account', 7, { objectName: 'Account' }]) {
      assert.equal(isHeldGrant(entry), false, JSON.stringify(entry));
    }
  });
});

describe('restoresHeldGrant', () => {
  const stored = [
    { ...grant('Account', { canUpdate: true }), removed: REMOVAL },
    grant('Contact', { allowedFields: ['Id', 'Email'], removedFields: [heldField('Phone')] }),
  ];

  test('a live entry for an Object held as deleted restores it, in any spelling', () => {
    assert.equal(restoresHeldGrant(stored, [grant('account')]), true);
    assert.equal(restoresHeldGrant(stored, [grant('ACCOUNT', { canRead: false, allowedFields: [] })]), true);
  });

  test('a live entry granting a held field again restores it, in any spelling', () => {
    assert.equal(restoresHeldGrant(stored, [grant('contact', { allowedFields: ['Id', 'phone'] })]), true);
  });

  test('keeping, removing or still holding what is held restores nothing', () => {
    assert.equal(restoresHeldGrant(stored, stored as GroupObjectPermission[]), false);
    assert.equal(restoresHeldGrant(stored, []), false);
    assert.equal(restoresHeldGrant(stored, [grant('Lead')]), false);
    assert.equal(restoresHeldGrant(stored, [grant('Contact', { allowedFields: ['Id', 'Email'] })]), false);
    assert.equal(restoresHeldGrant(stored, [{ ...grant('Account'), removed: REMOVAL }]), false);
  });

  test('an entry the policy engine cannot read holds nothing to restore', () => {
    const unreadable = [
      { objectName: 7, canRead: true, removed: REMOVAL },
      { objectName: 'Lead', canRead: 'true', removed: REMOVAL },
      { objectName: 'Case', canRead: true, allowedFields: 'Subject', removedFields: [heldField('Subject')] },
    ];
    assert.equal(restoresHeldGrant(unreadable, [grant('Lead'), grant('Case', { allowedFields: ['Subject'] })]), false);
  });

  test('a held field that is not a field name matches nothing', () => {
    const odd = [grant('Contact', { removedFields: [null, { fieldName: 7 }, 'Phone'] as never })];
    assert.equal(restoresHeldGrant(odd, [grant('Contact', { allowedFields: ['Phone', '7'] })]), false);
  });
});

describe('readers of stored grants', () => {
  const entries = [
    { ...grant('Account', { canUpdate: true, allowedFields: ['Id', 'Name'] }), removed: REMOVAL },
    grant('Contact', { removedFields: [heldField('Phone')] }),
  ];

  test('a field an entry lists both as granted and as held is read as held', () => {
    const both = grant('Contact', { allowedFields: ['Id', 'Phone'], removedFields: [heldField('phone')] });
    assert.deepEqual(readableGrants([both])[0].allowedFields, ['Id']);
  });

  test('readableGrants and effectiveGrants leave held entries out and keep held fields ungranted', () => {
    assert.deepEqual(
      readableGrants(entries).map((g) => [g.objectName, g.allowedFields]),
      [['Contact', ['Id']]]
    );
    const objects = [
      { objectName: 'Account', enabled: true },
      { objectName: 'Contact', enabled: true },
    ];
    assert.deepEqual(
      effectiveGrants(entries, objects).map((g) => g.objectName),
      ['Contact']
    );
  });
});

describe('mergeGrants with held fields', () => {
  const fields = () => ['Id', 'Name', 'Phone', 'Email'];

  test('the merged entry holds every field its entries hold, once, and grants none of them', () => {
    const [merged] = mergeGrants(
      [
        grant('Contact', { allowedFields: ['Name', 'Phone'], removedFields: [heldField('Email')] }),
        grant('Contact', { canUpdate: true, allowedFields: ['Email'], removedFields: [heldField('phone'), heldField('EMAIL')] }),
      ],
      fields
    );
    assert.deepEqual(merged, {
      objectName: 'Contact',
      canRead: true,
      canCreate: false,
      canUpdate: true,
      canDelete: false,
      allowedFields: ['Name'],
      removedFields: [heldField('Email'), heldField('phone')],
    });
  });

  test('a merged entry with nothing held has no removedFields', () => {
    const [merged] = mergeGrants([grant('Contact', { allowedFields: ['Name'] }), grant('contact', { allowedFields: ['Phone'] })], fields);
    assert.equal('removedFields' in merged, false);
    assert.deepEqual(merged.allowedFields, ['Name', 'Phone']);
  });

  test('held field entries that are not field names are dropped', () => {
    const [merged] = mergeGrants(
      [
        grant('Contact', { allowedFields: ['Name'], removedFields: [null, { fieldName: 7 }] as never }),
        grant('Contact', { allowedFields: ['Phone'] }),
      ],
      fields
    );
    assert.equal('removedFields' in merged, false);
  });
});

describe('audit diff of held grants', () => {
  test('an entry held as deleted and the fields an entry holds are marked', () => {
    const audited = groupAuditFields(
      groupWith([
        { ...grant('Account'), removed: REMOVAL },
        grant('Contact', { removedFields: [heldField('Phone'), heldField('jane@example.com')] }),
      ])
    );
    assert.deepEqual(audited.objectPermissions, [
      { ...grant('Account'), held: true },
      { ...grant('Contact'), heldFields: ['Phone', '<invalid:len=16>'] },
    ]);
  });

  test('restoring a held entry or a held field shows in the diff', () => {
    const held = groupWith([{ ...grant('Account'), removed: REMOVAL }, grant('Contact', { removedFields: [heldField('Phone')] })]);
    const restored = groupWith([grant('Account'), grant('Contact', { allowedFields: ['Id', 'Phone'] })]);
    assert.deepEqual(groupUpdateDiff(held, restored), {
      before: {
        objectPermissions: [
          { ...grant('Account'), held: true },
          { ...grant('Contact'), heldFields: ['Phone'] },
        ],
      },
      after: { objectPermissions: [grant('Account'), grant('Contact', { allowedFields: ['Id', 'Phone'] })] },
    });
  });
});

describe('a group as stored, as the portal and history read it', () => {
  // As older releases or a hand edit can leave a group: entries the policy engine skips, an entry with
  // no field list, held fields in other shapes, and an action ID that is not text.
  const stored = {
    name: 'Legacy',
    description: '',
    allowedActions: ['soql_query', 7, null] as unknown as string[],
    objectPermissions: [
      null,
      { objectName: 7, canRead: true },
      { objectName: 'Lead', canRead: 'true', allowedFields: ['Id'] },
      { objectName: 'Account', canRead: true },
      { objectName: 'Contact', canRead: true, allowedFields: ['Id'], removedFields: [null, 'Phone', { fieldName: 5 }, heldField('Email')] },
      { objectName: 'Case', canRead: true, allowedFields: ['Id'], removed: true },
    ] as unknown as GroupObjectPermission[],
  };
  const objects = ['Account', 'Contact', 'Case', 'Lead'].map((objectName) => ({
    objectName,
    label: objectName,
    isCustom: false,
    enabled: true,
    sourcePath: '',
    fieldCount: 2,
    enabledFieldCount: 2,
    fields: ['Id', 'Email'].map((fieldName) => ({ objectName, fieldName, label: fieldName, fieldType: 'Text', isCustom: false, required: false, enabled: true })),
    updatedAt: '',
  })) as SalesforceObject[];

  test('availability issues and change lines read what the engine reads, and do not fail on the rest', () => {
    assert.deepEqual(
      groupAvailabilityIssues(stored, objects).map((issue) => [issue.objectName, issue.name, issue.reason]),
      [
        ['Contact', 'Email', 'field_deleted'],
        ['Case', 'Case', 'object_deleted'],
      ]
    );
    const draft = groupDraftContent(stored, objects);
    // The drawer's pending changes: what saving the drawer's draft over the stored group changes.
    assert.deepEqual(describeGroupChanges(stored, { ...draft, name: 'Legacy', description: '' }), []);
    assert.deepEqual(describeGroupChanges(stored, { ...draft, objectPermissions: [] }), [
      'Removed Account (R) from the group.',
      'Removed Contact (R) from the group.',
      'Removed Case (R) from the group.',
    ]);
  });

  test('a held marker whose date or admin is not text reads as none', () => {
    const odd = { at: 5, by: 7 } as never;
    assert.deepEqual(
      groupAvailabilityIssues(
        {
          allowedActions: [],
          objectPermissions: [
            { ...grant('Account'), removed: odd },
            grant('Contact', { removedFields: [{ fieldName: 'Phone', ...(odd as object) }] as never }),
          ],
        },
        objects
      ).map((issue) => [issue.objectName, issue.name, issue.message]),
      [
        ['Account', 'Account', 'Deleted from Salesforce > Objects. It grants nothing until an admin restores it, although the object is back in Salesforce > Objects.'],
        ['Contact', 'Phone', 'Deleted from Salesforce > Objects. It grants nothing until an admin restores it.'],
      ]
    );
  });

  test('a history version reads like a stored group, so its XML can be shown, downloaded and loaded back', () => {
    const version = groupDraftContent(stored, objects);
    assert.deepEqual(version.dropped, { actions: ['7', 'null'], grants: ['entry 1', 'entry 2', 'entry 3'] });
    assert.deepEqual(version.allowedActions, ['soql_query']);
    assert.deepEqual(version.objectPermissions, [
      grant('Account', { allowedFields: [] }),
      grant('Contact', { removedFields: [heldField('Email')] }),
      { ...grant('Case'), removed: { at: '', by: '' } },
    ]);
    const { dropped: _dropped, ...content } = version;
    const parsed = parseAccessGroupXml(accessGroupToXml(content, { objects }));
    assert.ok(parsed.ok, JSON.stringify(parsed));
    assert.deepEqual(parsed.group.objectPermissions.map((p) => [p.objectName, p.allowedFields, Boolean(p.removed), p.removedFields?.map((f) => f.fieldName) ?? []]), [
      ['Account', [], false, []],
      ['Contact', ['Id'], false, ['Email']],
      ['Case', ['Id'], true, []],
    ]);
  });
});
