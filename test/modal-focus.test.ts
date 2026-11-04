import './helpers/env.js';
// The key replacement and sample matrix dialogs are aria-modal: keys pressed while one is open must
// never move focus to the page behind, Escape must close it wherever focus is, and focus goes back
// only to a control that can still take it.
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {
  MODAL_FOCUSABLE_SELECTOR,
  canReturnFocusTo,
  modalFocusinAction,
  modalKeyAction,
} from '../src/components/views/modalFocus.js';
import { isCommandPaletteShortcut } from '../src/components/views/shortcuts.js';

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

describe('page-wide shortcuts while a dialog is open', () => {
  // Cmd+K used to fall through to the page's window listener: the command palette opened behind the
  // dialog, took focus out of it, ran commands on Enter, and stayed open after Escape closed the
  // dialog first.
  test('Cmd+K and Ctrl+K are blocked from the page wherever focus is', () => {
    for (const active of [CANCEL, CONFIRM, -1]) {
      assert.deepEqual(modalKeyAction('k', false, 2, active, { metaKey: true }), { kind: 'block' }, `meta ${active}`);
      assert.deepEqual(modalKeyAction('k', false, 2, active, { ctrlKey: true }), { kind: 'block' }, `ctrl ${active}`);
    }
  });

  test('the chord is blocked with Shift held too, as the page listener would still open the palette', () => {
    assert.deepEqual(modalKeyAction('K', true, 2, CANCEL, { metaKey: true }), { kind: 'block' });
    assert.deepEqual(modalKeyAction('K', true, 2, CANCEL, { ctrlKey: true }), { kind: 'block' });
  });

  test('a dialog with no controls still blocks the chord', () => {
    assert.deepEqual(modalKeyAction('k', false, 0, -1, { metaKey: true }), { kind: 'block' });
  });

  test('a plain k, and other Cmd/Ctrl chords, are left to the focused control and the browser', () => {
    assert.equal(modalKeyAction('k', false, 2, CANCEL), null);
    assert.equal(modalKeyAction('k', false, 2, CANCEL, { metaKey: false, ctrlKey: false }), null);
    assert.equal(modalKeyAction('c', false, 2, CANCEL, { metaKey: true }), null);
    assert.equal(modalKeyAction('Enter', false, 2, CONFIRM, { ctrlKey: true }), null);
  });

  test('Escape and Tab keep their meaning with Ctrl held', () => {
    assert.deepEqual(modalKeyAction('Escape', false, 2, CANCEL, { ctrlKey: true }), { kind: 'close' });
    assert.deepEqual(modalKeyAction('Tab', false, 2, CONFIRM, { ctrlKey: true }), { kind: 'focus', index: CANCEL });
  });

  test('the dialog blocks exactly what opens the command palette', () => {
    const chords = [
      { key: 'k', metaKey: true },
      { key: 'k', ctrlKey: true },
      { key: 'K', metaKey: true },
      { key: 'k' },
      { key: 'j', metaKey: true },
      { key: 'Escape', ctrlKey: true },
    ];
    for (const chord of chords) {
      const blocked = modalKeyAction(chord.key, false, 2, CANCEL, chord)?.kind === 'block';
      assert.equal(blocked, isCommandPaletteShortcut(chord), JSON.stringify(chord));
    }
  });

  test('the shell and the dialog share one test for the palette shortcut', () => {
    const page = fs.readFileSync(new URL('../src/components/shell/PortalShell.tsx', import.meta.url), 'utf8');
    const hook = fs.readFileSync(new URL('../src/components/views/useModalDialog.ts', import.meta.url), 'utf8');
    assert.match(page, /if \(isCommandPaletteShortcut\(e\)( && !anyModalOpen\(\))?\)/);
    assert.doesNotMatch(page, /e\.key\.toLowerCase\(\) === 'k'/);
    // The hook must pass the modifiers, or the chord reaches modalKeyAction as a plain k.
    assert.match(hook, /metaKey: e\.metaKey, ctrlKey: e\.ctrlKey/);
  });
});

describe('isCommandPaletteShortcut', () => {
  test('Cmd+K on macOS and Ctrl+K elsewhere, in either case', () => {
    assert.equal(isCommandPaletteShortcut({ key: 'k', metaKey: true }), true);
    assert.equal(isCommandPaletteShortcut({ key: 'k', ctrlKey: true }), true);
    assert.equal(isCommandPaletteShortcut({ key: 'K', ctrlKey: true }), true);
  });

  test('a k typed without Cmd or Ctrl, or another key with them, is not the shortcut', () => {
    assert.equal(isCommandPaletteShortcut({ key: 'k' }), false);
    assert.equal(isCommandPaletteShortcut({ key: 'k', metaKey: false, ctrlKey: false }), false);
    assert.equal(isCommandPaletteShortcut({ key: 'l', metaKey: true }), false);
    assert.equal(isCommandPaletteShortcut({ key: 'Escape', ctrlKey: true }), false);
  });
});

describe('modalFocusinAction', () => {
  test('focus arriving behind the open dialog is pulled back in', () => {
    assert.equal(modalFocusinAction(false, false), 'reclaim');
  });

  test('focus moving between the dialog controls is tracked, not fought', () => {
    assert.equal(modalFocusinAction(true, false), 'track');
  });

  test('focus handed back to the opener on close is let out of the dialog', () => {
    assert.equal(modalFocusinAction(false, true), 'allow');
    assert.equal(modalFocusinAction(true, true), 'allow');
  });

  test('the hook guards focusin and lets the opener take focus back on close', () => {
    const hook = fs.readFileSync(new URL('../src/components/views/useModalDialog.ts', import.meta.url), 'utf8');
    assert.match(hook, /addEventListener\('focusin', onFocusIn, true\)/);
    assert.match(hook, /removeEventListener\('focusin', onFocusIn, true\)/);
    assert.match(hook, /releasingRef\.current = true;\s*try \{\s*opener\.focus\(\);/);
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

  test('the shared Dialog and Drawer primitives use the modal focus handling', () => {
    const source = fs.readFileSync(new URL('../src/components/ui/primitives.tsx', import.meta.url), 'utf8');
    for (const name of ['Dialog', 'Drawer']) {
      const start = source.indexOf(`export function ${name}(`);
      assert.ok(start > 0, name);
      const body = source.slice(start, source.indexOf('\nexport function', start + 10));
      assert.match(body, /useModalDialog(<[^>]*>)?\(open, onClose\)/, name);
      assert.match(body, /ref=\{modal\.dialogRef\}/, name);
      assert.match(body, /aria-modal="true"/, name);
      assert.doesNotMatch(body, /autoFocus|onKeyDown/, name);
    }
    const dialog = source.slice(source.indexOf('export function Dialog('));
    assert.match(dialog.slice(0, 3000), /initialFocusRef: initialFocus === 'box' \? \{ current: null \} : modal\.initialFocusRef/);
  });

  test('the sample matrix confirmation is an alertdialog on the shared Dialog, focus on Cancel', () => {
    const source = fs.readFileSync(new URL('../src/components/shell/PortalShell.tsx', import.meta.url), 'utf8');
    const at = source.indexOf('title="Load the sample enterprise matrix?"');
    assert.ok(at > 0);
    const dialog = source.slice(source.lastIndexOf('<Dialog', at), at + 900);
    assert.match(dialog, /role="alertdialog"/);
    assert.match(dialog, /<button ref=\{initialFocusRef\} type="button" className="btn" onClick=\{close\}>\s*Cancel/);
  });

  test('the drawer and the command palette are modal layers too', () => {
    const fly = fs.readFileSync(new URL('../src/components/views/FlyoutDrawer.tsx', import.meta.url), 'utf8');
    assert.match(fly, /<Drawer\b/);
    // Escape reaches the drawer only through the shared stack, never a window listener of its own.
    assert.doesNotMatch(fly, /addEventListener\('keydown'/);
    const palette = fs.readFileSync(new URL('../src/components/views/CommandPalette.tsx', import.meta.url), 'utf8');
    assert.match(palette, /useModalDialog<HTMLDivElement, HTMLInputElement>\(open, onClose\)/);
  });

  test('the key replacement dialog keeps its arming delay on the scrim and on Confirm', () => {
    const source = fs.readFileSync(new URL(sources['key replacement'], import.meta.url), 'utf8');
    assert.equal(source.match(/dialogClickCounts\(replaceKeyConfirmOpenedAt\.current, Date\.now\(\)\)/g)?.length, 2);
  });
});
