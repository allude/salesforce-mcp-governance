import './helpers/env.js';
// The key replacement and sample matrix dialogs are aria-modal: keys pressed while one is open must
// never move focus to the page behind, Escape must close it wherever focus is, and focus goes back
// only to a control that can still take it.
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { MODAL_FOCUSABLE_SELECTOR, canReturnFocusTo, modalKeyAction } from '../src/components/views/modalFocus.js';

// Both dialogs hold Cancel then Confirm.
const CANCEL = 0;
const CONFIRM = 1;

describe('modalKeyAction', () => {
  test('Tab from Confirm wraps to Cancel instead of leaving the dialog', () => {
    assert.deepEqual(modalKeyAction('Tab', false, 2, CONFIRM), { kind: 'focus', index: CANCEL });
  });

  test('Shift+Tab from Cancel wraps to Confirm instead of leaving the dialog', () => {
    assert.deepEqual(modalKeyAction('Tab', true, 2, CANCEL), { kind: 'focus', index: CONFIRM });
  });

  test('Tab and Shift+Tab move between the buttons in order', () => {
    assert.deepEqual(modalKeyAction('Tab', false, 2, CANCEL), { kind: 'focus', index: CONFIRM });
    assert.deepEqual(modalKeyAction('Tab', true, 2, CONFIRM), { kind: 'focus', index: CANCEL });
    assert.deepEqual(modalKeyAction('Tab', false, 3, 1), { kind: 'focus', index: 2 });
  });

  test('from outside the dialog, after a click dropped focus to body, Tab re-enters at the matching end', () => {
    assert.deepEqual(modalKeyAction('Tab', false, 2, -1), { kind: 'focus', index: CANCEL });
    assert.deepEqual(modalKeyAction('Tab', true, 2, -1), { kind: 'focus', index: CONFIRM });
  });

  test('with one control, Tab keeps focus on it; with none, on the dialog box', () => {
    assert.deepEqual(modalKeyAction('Tab', false, 1, 0), { kind: 'focus', index: 0 });
    assert.deepEqual(modalKeyAction('Tab', true, 1, 0), { kind: 'focus', index: 0 });
    assert.deepEqual(modalKeyAction('Tab', false, 0, -1), { kind: 'focus', index: -1 });
  });

  test('Escape closes whether focus is inside the dialog or not', () => {
    for (const active of [CANCEL, CONFIRM, -1]) {
      assert.deepEqual(modalKeyAction('Escape', false, 2, active), { kind: 'close' });
    }
  });

  test('other keys are left to the focused control, so Enter still answers the dialog', () => {
    for (const key of ['Enter', ' ', 'a', 'ArrowDown']) {
      assert.equal(modalKeyAction(key, false, 2, CANCEL), null, key);
    }
  });
});

describe('canReturnFocusTo', () => {
  test('returns focus to the opener while it is on the page and enabled', () => {
    assert.equal(canReturnFocusTo({ isConnected: true }), true);
    assert.equal(canReturnFocusTo({ isConnected: true, disabled: false }), true);
  });

  test('skips an opener that is gone, disabled, or unknown', () => {
    assert.equal(canReturnFocusTo({ isConnected: false }), false);
    assert.equal(canReturnFocusTo({ isConnected: true, disabled: true }), false);
    assert.equal(canReturnFocusTo(null), false);
    assert.equal(canReturnFocusTo(undefined), false);
  });
});

describe('MODAL_FOCUSABLE_SELECTOR', () => {
  test('leaves out disabled controls and elements taken out of the tab order', () => {
    assert.match(MODAL_FOCUSABLE_SELECTOR, /button:not\(\[disabled\]\)/);
    assert.match(MODAL_FOCUSABLE_SELECTOR, /\[tabindex\]:not\(\[tabindex="-1"\]\)/);
  });
});

describe('the confirmation dialogs', () => {
  const sources = {
    'key replacement': '../src/components/views/SalesforceOrgConnectionView.tsx',
    'sample matrix': '../src/app/page.tsx',
  };

  for (const [name, file] of Object.entries(sources)) {
    test(`the ${name} dialog uses the shared modal focus handling`, () => {
      const source = fs.readFileSync(new URL(file, import.meta.url), 'utf8');
      const dialog = source.slice(source.indexOf('role="alertdialog"') - 400);
      assert.match(source, /useModalDialog\(/);
      assert.match(dialog, /ref=\{\w+\.dialogRef\}/);
      assert.match(dialog, /ref=\{\w+\.initialFocusRef\}/);
      // Focus and Escape come from the helper; autoFocus and a box-level Escape handler did neither.
      assert.doesNotMatch(dialog.slice(0, 3000), /autoFocus|onKeyDown/);
    });
  }

  test('the key replacement dialog keeps its arming delay on the scrim and on Confirm', () => {
    const source = fs.readFileSync(new URL(sources['key replacement'], import.meta.url), 'utf8');
    assert.equal(source.match(/dialogClickCounts\(replaceKeyConfirmOpenedAt\.current, Date\.now\(\)\)/g)?.length, 2);
  });
});
