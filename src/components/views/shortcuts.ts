export interface ShortcutKeyEvent {
  key: string;
  metaKey?: boolean;
  ctrlKey?: boolean;
}

/**
 * Cmd+K on macOS, Ctrl+K elsewhere: toggles the command palette. The page listener and the modal
 * dialogs (which keep the chord from reaching that listener) share this test so they cannot drift.
 */
export function isCommandPaletteShortcut(e: ShortcutKeyEvent): boolean {
  return Boolean(e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k';
}
