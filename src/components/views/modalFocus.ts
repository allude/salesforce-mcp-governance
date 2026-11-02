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
  | null;

/**
 * What a key pressed anywhere on the page does while a modal dialog is open. Tab always moves focus
 * by hand and wraps, so it can never reach the page behind; from outside the dialog (focus dropped
 * to body after a click on its text) it re-enters at the matching end. `activeIndex` is -1 when the
 * focused element is not one of the dialog's `focusableCount` elements.
 */
export function modalKeyAction(
  key: string,
  shiftKey: boolean,
  focusableCount: number,
  activeIndex: number
): ModalKeyAction {
  if (key === 'Escape') return { kind: 'close' };
  if (key !== 'Tab') return null;
  if (focusableCount <= 0) return { kind: 'focus', index: -1 };
  if (activeIndex < 0 || activeIndex >= focusableCount) {
    return { kind: 'focus', index: shiftKey ? focusableCount - 1 : 0 };
  }
  const step = shiftKey ? -1 : 1;
  return { kind: 'focus', index: (activeIndex + step + focusableCount) % focusableCount };
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
