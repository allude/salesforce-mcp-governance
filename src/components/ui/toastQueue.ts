/**
 * The toast queue behind ToastRegion, as pure functions so its rules are unit-tested without a DOM:
 * newest last, at most MAX_TOASTS shown (the oldest non-error goes first), errors stay until dismissed,
 * others time out.
 */
export type ToastKind = 'success' | 'info' | 'error';

export interface ToastItem {
  id: number;
  kind: ToastKind;
  message: string;
  /** An Undo for an action that can be reversed safely (untrack an SObject, for example). */
  undo?: { label?: string; run: () => void };
  /** Milliseconds before it goes by itself; null for errors, which stay until dismissed. */
  durationMs: number | null;
}

export const MAX_TOASTS = 4;
export const TOAST_DURATION_MS = { success: 4_000, info: 4_000, withUndo: 8_000 } as const;

export function toastDuration(kind: ToastKind, hasUndo: boolean): number | null {
  if (kind === 'error') return null;
  return hasUndo ? TOAST_DURATION_MS.withUndo : TOAST_DURATION_MS[kind];
}

export function pushToast(queue: readonly ToastItem[], toast: ToastItem): ToastItem[] {
  // The same message twice in a row (a failing poll) refreshes the toast instead of stacking copies.
  const rest = queue.filter((t) => !(t.message === toast.message && t.kind === toast.kind));
  const next = [...rest, toast];
  while (next.length > MAX_TOASTS) {
    const oldestTransient = next.findIndex((t) => t.kind !== 'error');
    next.splice(oldestTransient === -1 ? 0 : oldestTransient, 1);
  }
  return next;
}

export function dismissToast(queue: readonly ToastItem[], id: number): ToastItem[] {
  return queue.filter((t) => t.id !== id);
}
