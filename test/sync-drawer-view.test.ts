import './helpers/env.js';
// The server refuses the server-folder import in production, so the Sync drawer must not offer it
// there. devToolsEnabled is the overview's production flag. Rendered to markup to exercise the real drawer.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { FlyoutDrawer } from '../src/components/views/FlyoutDrawer.js';

const noop = async () => {};

function renderSyncDrawer(devToolsEnabled: boolean): string {
  return renderToStaticMarkup(
    createElement(FlyoutDrawer, {
      flyout: { type: 'sync' },
      onClose: () => {},
      onOpenFlyout: () => {},
      onNavigateView: () => {},
      profiles: [],
      objects: [],
      groups: [],
      mappings: [],
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
      devToolsEnabled,
      onTestMcpCall: noop,
      onRefreshWorkspace: async () => null,
      onLoadGroupHistory: async () => [],
      notify: () => {},
    })
  );
}

test('outside production the Sync drawer offers the server-folder import as step 2', () => {
  const html = renderSyncDrawer(true);
  assert.ok(html.includes('2. Sync from local server path'));
  assert.ok(html.includes('3. Pull from connected Salesforce org'));
  assert.ok(html.includes('Local server path'));
});

test('in production the Sync drawer leaves the server-folder import out and renumbers the org pull', () => {
  const html = renderSyncDrawer(false);
  assert.ok(!html.includes('server path'), 'no server-folder section or subtitle entry');
  assert.ok(!html.includes('import-local-folder'));
  assert.ok(html.includes('2. Pull from connected Salesforce org'));
});
