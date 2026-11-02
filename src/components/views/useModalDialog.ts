'use client';

import { useCallback, useLayoutEffect, useRef } from 'react';
import { MODAL_FOCUSABLE_SELECTOR, canReturnFocusTo, modalKeyAction } from './modalFocus';

/**
 * Focus handling for an aria-modal confirmation dialog: focus starts on `initialFocusRef` (Cancel),
 * Tab and Shift+Tab stay inside `dialogRef`, Escape closes from anywhere on the page, and focus goes
 * back to the control that opened it. Answer the dialog through `close`, which hands focus back
 * before the caller's action can disable or remove that control.
 */
export function useModalDialog(open: boolean, onClose: () => void) {
  const dialogRef = useRef<HTMLDivElement | null>(null);
  const initialFocusRef = useRef<HTMLButtonElement | null>(null);
  const openerRef = useRef<HTMLElement | null>(null);
  const onCloseRef = useRef(onClose);

  useLayoutEffect(() => {
    onCloseRef.current = onClose;
  });

  const returnFocus = useCallback(() => {
    const opener = openerRef.current;
    openerRef.current = null;
    if (opener && canReturnFocusTo(opener)) opener.focus();
  }, []);

  const close = useCallback(() => {
    returnFocus();
    onCloseRef.current();
  }, [returnFocus]);

  useLayoutEffect(() => {
    if (!open) return;
    const box = dialogRef.current;
    const active = document.activeElement;
    openerRef.current = active instanceof HTMLElement && active !== document.body ? active : null;
    (initialFocusRef.current ?? box)?.focus();

    // Capture phase on document, so Escape still works after a click dropped focus to body, and
    // listeners behind the dialog (such as the drawer's Escape) never see these keys.
    const onKey = (e: KeyboardEvent) => {
      if (!box) return;
      const focusables = Array.from(box.querySelectorAll<HTMLElement>(MODAL_FOCUSABLE_SELECTOR));
      const current = document.activeElement;
      const action = modalKeyAction(
        e.key,
        e.shiftKey,
        focusables.length,
        current instanceof HTMLElement ? focusables.indexOf(current) : -1
      );
      if (!action) return;
      e.preventDefault();
      e.stopPropagation();
      if (action.kind === 'close') close();
      else (action.index < 0 ? box : focusables[action.index]).focus();
    };
    document.addEventListener('keydown', onKey, true);
    return () => {
      document.removeEventListener('keydown', onKey, true);
      // Closed without `close` (or unmounted): only reclaim focus the dialog was holding.
      const now = document.activeElement;
      if (!now || now === document.body || box?.contains(now)) returnFocus();
      else openerRef.current = null;
    };
  }, [open, close, returnFocus]);

  return { dialogRef, initialFocusRef, close };
}
