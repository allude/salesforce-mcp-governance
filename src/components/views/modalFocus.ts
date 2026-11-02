import { isCommandPaletteShortcut } from './shortcuts';

/** What a confirmation dialog can move focus to, in the order Tab visits them. */
export const MODAL_FOCUSABLE_SELECTOR = [
  'button:not([disabled])',
  'a[href]',
  'input:not([disabled]):not([type="hidden"])',
  'select:not([disabled])',
  'textarea:not([disabled])',
  '[tabindex]:not([tabindex="-1"])',
].join(', ');

export type ModalKeyAction =
  | { kind: 'close' }
  /** `index` is into the dialog's focusable elements, or -1 for the dialog box when it has none. */
  | { kind: 'focus'; index: number }
  /** A page-wide shortcut (the command palette's Cmd/Ctrl+K), kept from the page behind the dialog. */
  | { kind: 'block' }
  | null;

export interface ModalKeyModifiers {
  metaKey?: boolean;
  ctrlKey?: boolean;
}

/**
 * What a key pressed anywhere on the page does while a modal dialog is open. Tab always moves focus
 * by hand and wraps, so it can never reach the page behind; from outside the dialog (focus dropped
 * to body after a click on its text) it re-enters at the matching end. `activeIndex` is -1 when the
 * focused element is not one of the dialog's `focusableCount` elements.
 *
 * Page-wide shortcuts are blocked: the command palette would take focus out of the dialog, run its
 * commands behind it, and stay open after Escape closed the dialog underneath. A new window-level
 * shortcut must be blocked here as well.
 */
export function modalKeyAction(
  key: string,
  shiftKey: boolean,
  focusableCount: number,
  activeIndex: number,
  modifiers: ModalKeyModifiers = {}
): ModalKeyAction {
  if (isCommandPaletteShortcut({ key, ...modifiers })) return { kind: 'block' };
  if (key === 'Escape') return { kind: 'close' };
  if (key !== 'Tab') return null;
  if (focusableCount <= 0) return { kind: 'focus', index: -1 };
  if (activeIndex < 0 || activeIndex >= focusableCount) {
    return { kind: 'focus', index: shiftKey ? focusableCount - 1 : 0 };
  }
  const step = shiftKey ? -1 : 1;
  return { kind: 'focus', index: (activeIndex + step + focusableCount) % focusableCount };
}

export type ModalFocusinAction = 'track' | 'reclaim' | 'allow';

/**
 * What focus arriving somewhere does while a modal dialog is open: inside the dialog it is tracked,
 * so a reclaim can go back to the same control; outside it (a script's focus(), an autoFocus input
 * mounting behind the dialog) it is pulled back in, except while the dialog itself is handing focus
 * back to its opener on the way out.
 */
export function modalFocusinAction(targetInDialog: boolean, releasing: boolean): ModalFocusinAction {
  if (releasing) return 'allow';
  return targetInDialog ? 'track' : 'reclaim';
}

export interface FocusReturnCandidate {
  isConnected: boolean;
  disabled?: boolean;
}

/**
 * Whether focus can go back to the control that opened the dialog. One removed from the page, or
 * disabled by the action just confirmed, would drop focus to body and leave the user at the top.
 */
export function canReturnFocusTo(el: FocusReturnCandidate | null | undefined): boolean {
  return Boolean(el && el.isConnected && !el.disabled);
}
