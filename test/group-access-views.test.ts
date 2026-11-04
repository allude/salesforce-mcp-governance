import './helpers/env.js';
// The portal's summaries of stored Access Groups must read their grants as the policy engine does: a
// flag grants only when it is exactly true, and an entry the engine skips as malformed (a group saved
// by an older version) grants nothing, so no view shows access that /mcp does not give. Rendered to
// markup to exercise the real views.
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { FlyoutDrawer } from '../src/components/views/FlyoutDrawer.js';
import { AccessGroupsView, ProfileGroupMatrixView } from '../src/components/views/AccessMatrixViews.js';
import { SalesforceObjectsView, SalesforceProfilesView } from '../src/components/views/SalesforceViews.js';
import { CommandPalette } from '../src/components/views/CommandPalette.js';
import { effectiveGrants, readableGrants } from '../src/rbac/groupGrants.js';
import type { AccessGroup, SalesforceObject, SalesforceProfile } from '../src/types/governance.js';

const catalogObject = (objectName: string, fieldNames: string[]): SalesforceObject => ({
  objectName,
  label: objectName,
  isCustom: false,
  enabled: true,
  sourcePath: 'org',
  fieldCount: fieldNames.length,
  enabledFieldCount: fieldNames.length,
  fields: fieldNames.map((fieldName) => ({
    objectName,
    fieldName,
    label: fieldName,
    fieldType: 'Text',
    isCustom: false,
    required: false,
    enabled: true,
  })),
  updatedAt: '2026-10-01T00:00:00.000Z',
});

const objects = [catalogObject('Account', ['Id', 'Name']), catalogObject('Contact', ['Id'])];

// Account is granted only by entries the engine skips; Contact by a well-formed one.
const legacy: AccessGroup = {
  id: 'grp-legacy',
  name: 'Legacy Grants',
  description: '',
  allowedActions: ['soql_query'],
  objectPermissions: [
    { objectName: 'Account', canRead: true, canDelete: 'no', allowedFields: ['Name'] },
    { objectName: 'Account', canRead: 'true', allowedFields: ['Id'] },
    { objectName: 'Account', canUpdate: 1 },
  ] as never,
  version: 1,
  updatedAt: '2026-10-01T00:00:00.000Z',
};
const readers: AccessGroup = {
  id: 'grp-readers',
  name: 'Contact Readers',
  description: '',
  allowedActions: ['soql_query'],
  objectPermissions: [
    { objectName: 'Contact', canRead: true, canCreate: false, canUpdate: false, canDelete: false, allowedFields: ['Id'] },
  ],
  version: 1,
  updatedAt: '2026-10-01T00:00:00.000Z',
};
const groups = [legacy, readers];
const profile: SalesforceProfile = { id: '00e000000000001', name: 'Legacy Profile', updatedAt: '2026-10-01T00:00:00.000Z' };
const profiles = [profile];
const mappings = [{ profileId: profile.id, groupIds: [legacy.id, readers.id] }];

const noop = async () => {};

function renderDrawer(
  flyout: { type: 'profile' | 'object'; data: unknown },
  policy: { groups: AccessGroup[]; mappings: typeof mappings } = { groups, mappings }
): string {
  return renderToStaticMarkup(
    createElement(FlyoutDrawer, {
      flyout,
      onClose: () => {},
      onOpenFlyout: () => {},
      onNavigateView: () => {},
      profiles,
      objects,
      groups: policy.groups,
      mappings: policy.mappings,
      sfSettings: null,
      onUpsertProfile: noop,
      onDeleteProfile: noop,
      onImportCsv: noop,
      onToggleProfileGroup: noop,
      onToggleObject: noop,
      onToggleField: noop,
      onBulkToggleFields: noop,
      onSyncSfdxPath: noop,
      onSyncUploadedFiles: noop,
      onSaveGroup: noop,
      onDeleteGroup: noop,
      devToolsEnabled: true,
      onTestMcpCall: noop,
      onRefreshWorkspace: async () => null,
      notify: () => {},
    })
  );
}

/** The table row of `html` that holds `text`. */
function rowWith(html: string, text: string): string {
  const at = html.indexOf(text);
  assert.ok(at >= 0, `no "${text}" in the markup`);
  return html.slice(html.lastIndexOf('<tr', at), html.indexOf('</tr>', at));
}

describe('portal summaries of stored groups', () => {
  test('readableGrants leaves out the entries the engine skips and reads each flag as the engine does', () => {
    assert.deepEqual(readableGrants([...legacy.objectPermissions, null, 'text', { objectName: '' }, ...readers.objectPermissions]), [
      readers.objectPermissions[0],
    ]);
    assert.deepEqual(readableGrants([{ objectName: 'Account', canRead: true }]), [
      { objectName: 'Account', canRead: true, canCreate: false, canUpdate: false, canDelete: false, allowedFields: [] },
    ]);
    assert.deepEqual(readableGrants(undefined), []);
  });

  test("the Profile drawer's effective access lists only what the engine grants", () => {
    const html = renderDrawer({ type: 'profile', data: profile });
    assert.ok(html.includes('Object access (1)'), html);
    assert.ok(html.includes('<span class="mono">Contact</span>'));
    assert.ok(!html.includes('<span class="mono">Account</span>'));
  });

  test("an Object drawer's 'Used by groups' lists only the groups that grant something on it", () => {
    assert.ok(renderDrawer({ type: 'object', data: objects[0] }).includes('Used by groups (0)'));
    assert.ok(renderDrawer({ type: 'object', data: objects[1] }).includes('Used by groups (1)'));
  });

  test('the Access Groups table shows no Object for a group whose only entries are skipped', () => {
    const html = renderToStaticMarkup(
      createElement(AccessGroupsView, { groups, objects, profiles, mappings, onOpenFlyout: () => {} })
    );
    assert.ok(rowWith(html, 'Legacy Grants').includes('No objects configured'));
    assert.ok(!rowWith(html, 'Contact Readers').includes('No objects configured'));
  });

  test('the Profile and Group matrix counts only the Objects the engine grants', () => {
    const html = renderToStaticMarkup(
      createElement(ProfileGroupMatrixView, {
        profiles,
        groups,
        objects,
        mappings,
        onToggleProfileGroup: noop,
        onOpenFlyout: () => {},
      })
    );
    assert.ok(rowWith(html, profile.id).includes('1 actions · 1 objects'), rowWith(html, profile.id));
    // Each group's column header counts the Objects it grants.
    assert.ok(html.includes('1 actions · 0 objects'), html);
  });

  test('Salesforce > Profiles and Salesforce > Objects count only what the engine grants', () => {
    const profilesHtml = renderToStaticMarkup(
      createElement(SalesforceProfilesView, {
        profiles,
        groups,
        objects,
        mappings,
        sfSettings: null,
        onOpenFlyout: () => {},
        onPreviewPullProfilesFromOrg: async () => ({}) as never,
        onApplyPullProfilesFromOrg: noop,
        onNavigateToOrgConnection: () => {},
      })
    );
    assert.ok(rowWith(profilesHtml, profile.id).includes('1 actions · 1 objects'));

    const objectsHtml = renderToStaticMarkup(
      createElement(SalesforceObjectsView, {
        objects,
        groups,
        sfSettings: null,
        onToggleObject: noop,
        onBulkToggleAllObjects: noop,
        onOpenFlyout: () => {},
        onFetchOrgObjectCatalog: async () => [],
        onPreviewPullObjectsFromOrg: async () => ({}) as never,
        onApplyPullObjectsFromOrg: noop,
        onNavigateToOrgConnection: () => {},
      })
    );
    assert.ok(!rowWith(objectsHtml, '>Account<').includes('1 group'));
    assert.ok(rowWith(objectsHtml, '>Contact<').includes('1 group'));
  });

  test("a Profile's access leaves out grants on Objects missing from Salesforce > Objects, and matches names in any case", () => {
    // Quote__c was never imported, so /mcp denies it; 'account' and 'ACCOUNT' are Account.
    const uncatalogued: AccessGroup = {
      id: 'grp-uncatalogued',
      name: 'Uncatalogued Grants',
      description: '',
      allowedActions: ['soql_query'],
      objectPermissions: [
        { objectName: 'Quote__c', canRead: true, canCreate: false, canUpdate: false, canDelete: false, allowedFields: ['Id'] },
        { objectName: 'account', canRead: true, canCreate: false, canUpdate: false, canDelete: false, allowedFields: ['Name'] },
        { objectName: 'ACCOUNT', canRead: false, canCreate: false, canUpdate: true, canDelete: false, allowedFields: ['Name'] },
      ],
      version: 1,
      updatedAt: '2026-10-01T00:00:00.000Z',
    };
    const policy = { groups: [uncatalogued], mappings: [{ profileId: profile.id, groupIds: [uncatalogued.id] }] };

    const drawer = renderDrawer({ type: 'profile', data: profile }, policy);
    assert.ok(drawer.includes('Object access (1)'), drawer);
    assert.ok(drawer.includes('<span class="mono">Account</span>'), drawer);
    assert.ok(!drawer.includes('Quote__c') && !drawer.includes('<span class="mono">account</span>'), drawer);

    const matrix = renderToStaticMarkup(
      createElement(ProfileGroupMatrixView, { profiles, objects, ...policy, onToggleProfileGroup: noop, onOpenFlyout: () => {} })
    );
    assert.ok(rowWith(matrix, profile.id).includes('1 actions · 1 objects'), rowWith(matrix, profile.id));

    const profilesHtml = renderToStaticMarkup(
      createElement(SalesforceProfilesView, {
        profiles,
        objects,
        ...policy,
        sfSettings: null,
        onOpenFlyout: () => {},
        onPreviewPullProfilesFromOrg: async () => ({}) as never,
        onApplyPullProfilesFromOrg: noop,
        onNavigateToOrgConnection: () => {},
      })
    );
    assert.ok(rowWith(profilesHtml, profile.id).includes('1 actions · 1 objects'), rowWith(profilesHtml, profile.id));
  });

  test('effectiveGrants reads a group as the policy engine does, catalog row and spelling included', () => {
    const catalog = [
      { objectName: 'Account', enabled: true },
      { objectName: 'Lead', enabled: false },
      // Two rows for one Object, as an older version could store them: the last enabled one counts.
      { objectName: 'Opportunity', enabled: true },
      { objectName: 'opportunity', enabled: true },
    ];
    const grant = (objectName: string, flags: Record<string, boolean> = { canRead: true }) => ({ objectName, ...flags, allowedFields: [] });
    assert.deepEqual(
      effectiveGrants(
        [grant('ACCOUNT'), grant('Lead'), grant('Ghost__c'), grant('OPPORTUNITY'), grant('Account', {}), { objectName: 'Account', canRead: 'true' }],
        catalog
      ).map((g) => g.objectName),
      ['Account', 'opportunity']
    );
    assert.deepEqual(effectiveGrants(undefined, catalog), []);
  });

  test('the command palette counts the Objects each group grants', () => {
    const html = renderToStaticMarkup(
      createElement(CommandPalette, {
        open: true,
        onClose: () => {},
        onNavigateView: () => {},
        onOpenFlyout: () => {},
        onToggleTheme: () => {},
        theme: 'dark',
        profiles,
        objects,
        groups,
      })
    );
    assert.ok(html.includes('1 actions · 0 objects'), html);
    assert.ok(html.includes('1 actions · 1 objects'));
  });
});
