'use client';

import { useCallback, useLayoutEffect, useRef } from 'react';
import {
  MODAL_FOCUSABLE_SELECTOR,
  canReturnFocusTo,
  modalFocusinAction,
  modalKeyAction,
} from './modalFocus';

/** The open modal layers (dialogs, the drawer, the palette), oldest first. */
const openModalLayers: symbol[] = [];

/** Whether any modal layer is open: page-level shortcuts stand down while one is. */
export function anyModalOpen(): boolean {
  return openModalLayers.length > 0;
}

/**
 * Focus handling for an aria-modal confirmation dialog: focus starts on `initialFocusRef` (Cancel),
 * Tab and Shift+Tab stay inside `dialogRef`, Escape closes from anywhere on the page, page-wide
 * shortcuts such as Cmd/Ctrl+K never reach the page behind, focus moved outside by script is pulled
 * back in, and focus goes back to the control that opened it. Answer the dialog through `close`,
 * which hands focus back before the caller's action can disable or remove that control.
 */
export function useModalDialog<
  TDialog extends HTMLElement = HTMLDivElement,
  TInitial extends HTMLElement = HTMLButtonElement,
>(open: boolean, onClose: () => void) {
  const dialogRef = useRef<TDialog | null>(null);
  const initialFocusRef = useRef<TInitial | null>(null);
  const openerRef = useRef<HTMLElement | null>(null);
  const onCloseRef = useRef(onClose);
  // Set while focus goes back to the opener, so the focusin guard lets it leave the dialog.
  const releasingRef = useRef(false);

  useLayoutEffect(() => {
    onCloseRef.current = onClose;
  });

  const returnFocus = useCallback(() => {
    const opener = openerRef.current;
    openerRef.current = null;
    if (!opener || !canReturnFocusTo(opener)) return;
    releasingRef.current = true;
    try {
      opener.focus();
    } finally {
      releasingRef.current = false;
    }
  }, []);

  const close = useCallback(() => {
    returnFocus();
    onCloseRef.current();
  }, [returnFocus]);

  useLayoutEffect(() => {
    if (!open) return;
    // Only the topmost open dialog answers keys and guards focus: a confirm opened over the drawer, or
    // the palette over it, closes alone on Escape instead of taking the drawer with it.
    const layer = Symbol('modal');
    openModalLayers.push(layer);
    const isTopmost = () => openModalLayers[openModalLayers.length - 1] === layer;
    const box = dialogRef.current;
    const active = document.activeElement;
    openerRef.current = active instanceof HTMLElement && active !== document.body ? active : null;
    (initialFocusRef.current ?? box)?.focus();
    const initiallyFocused = document.activeElement;
    let lastInside: HTMLElement | null =
      box && initiallyFocused instanceof HTMLElement && box.contains(initiallyFocused) ? initiallyFocused : null;

    // Capture phase on document, so Escape still works after a click dropped focus to body, and
    // listeners behind the dialog (such as the drawer's Escape and the page's Cmd/Ctrl+K on window)
    // never see these keys.
    const onKey = (e: KeyboardEvent) => {
      if (!box || !isTopmost()) return;
      const focusables = Array.from(box.querySelectorAll<HTMLElement>(MODAL_FOCUSABLE_SELECTOR));
      const current = document.activeElement;
      const action = modalKeyAction(
        e.key,
        e.shiftKey,
        focusables.length,
        current instanceof HTMLElement ? focusables.indexOf(current) : -1,
        { metaKey: e.metaKey, ctrlKey: e.ctrlKey }
      );
      if (!action) return;
      e.preventDefault();
      e.stopPropagation();
      if (action.kind === 'close') close();
      else if (action.kind === 'focus') (action.index < 0 ? box : focusables[action.index]).focus();
    };

    // Whatever still moves focus behind the dialog (a script's focus(), an autoFocus control
    // mounting) is undone: focus returns to the control in the dialog that last held it.
    const onFocusIn = (e: FocusEvent) => {
      if (!box || !isTopmost()) return;
      const target = e.target;
      const inDialog = target instanceof Node && box.contains(target);
      const action = modalFocusinAction(inDialog, releasingRef.current);
      if (action === 'track') {
        if (target instanceof HTMLElement) lastInside = target;
      } else if (action === 'reclaim') {
        // A control disabled since it was focused cannot take focus; fall back to Cancel, then the box.
        for (const el of [lastInside, initialFocusRef.current, box]) {
          if (!el || !box.contains(el)) continue;
          el.focus();
          if (document.activeElement === el) break;
        }
      }
    };
    document.addEventListener('keydown', onKey, true);
    document.addEventListener('focusin', onFocusIn, true);
    return () => {
      openModalLayers.splice(openModalLayers.indexOf(layer), 1);
      document.removeEventListener('keydown', onKey, true);
      document.removeEventListener('focusin', onFocusIn, true);
      // Closed without `close` (or unmounted): only reclaim focus the dialog was holding.
      const now = document.activeElement;
      if (!now || now === document.body || box?.contains(now)) returnFocus();
      else openerRef.current = null;
    };
  }, [open, close, returnFocus]);

  return { dialogRef, initialFocusRef, close };
}
