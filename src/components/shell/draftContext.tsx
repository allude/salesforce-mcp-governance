'use client';

import React, { createContext, useCallback, useContext, useEffect, useLayoutEffect, useMemo, useReducer, useRef } from 'react';
import { EMPTY_DRAFTS, draftReducer, type DraftEntry, type DraftScope, type DraftState } from './policyDraft';

/**
 * The PolicyDraft context: the shell's store of unsaved work (rules in policyDraft.ts). It lives in the
 * (portal) layout, so moving between views never loses a draft. Editors register what they hold with
 * useDraftRegistration; the shell reads the state for the Unsaved Changes bars and its guards.
 */
export interface DraftHandlers {
  /** Throws the draft away (back to what the server holds). */
  discard: () => void;
  /** Takes the admin to where the draft can be reviewed and applied. */
  review?: () => void;
}

interface DraftActions {
  set: (entry: DraftEntry, handlers: DraftHandlers) => void;
  clear: (key: string) => void;
  /** Discards the drafts named (all when omitted), calling each editor's own discard. */
  discard: (keys?: readonly string[]) => void;
  /** Calls review on the first draft in a scope. */
  review: (scope: DraftScope) => void;
  /** The current state, for event handlers that must not wait for a render. */
  read: () => DraftState;
}

const DraftStateContext = createContext<DraftState>(EMPTY_DRAFTS);
const DraftActionsContext = createContext<DraftActions | null>(null);

export function DraftProvider({ children }: { children: React.ReactNode }) {
  const [state, dispatchState] = useReducer(draftReducer, EMPTY_DRAFTS);
  // A mirror updated as each action is dispatched, so a guard that runs right after a clear (Save,
  // then close) reads the new state instead of the last render's.
  const stateRef = useRef<DraftState>(EMPTY_DRAFTS);
  const dispatch = useCallback((action: Parameters<typeof draftReducer>[1]) => {
    stateRef.current = draftReducer(stateRef.current, action);
    dispatchState(action);
  }, []);
  const handlers = useRef(new Map<string, DraftHandlers>());

  const set = useCallback((entry: DraftEntry, h: DraftHandlers) => {
    handlers.current.set(entry.key, h);
    dispatch({ type: 'set', entry });
  }, [dispatch]);
  const clear = useCallback((key: string) => {
    handlers.current.delete(key);
    dispatch({ type: 'clear', key });
  }, []);
  const discard = useCallback((keys?: readonly string[]) => {
    const targets = keys ?? Object.keys(stateRef.current);
    for (const key of targets) {
      const h = handlers.current.get(key);
      handlers.current.delete(key);
      dispatch({ type: 'clear', key });
      h?.discard();
    }
  }, []);
  const review = useCallback((scope: DraftScope) => {
    const entry = Object.values(stateRef.current).find((e) => e.scope === scope);
    if (entry) handlers.current.get(entry.key)?.review?.();
  }, []);
  const read = useCallback(() => stateRef.current, []);
  const actions = useMemo<DraftActions>(() => ({ set, clear, discard, review, read }), [set, clear, discard, review, read]);

  return (
    <DraftActionsContext.Provider value={actions}>
      <DraftStateContext.Provider value={state}>{children}</DraftStateContext.Provider>
    </DraftActionsContext.Provider>
  );
}

export function useDraftState(): DraftState {
  return useContext(DraftStateContext);
}

/** Null outside the portal shell (a view rendered on its own, as the unit tests do). */
export function useDraftActions(): DraftActions | null {
  return useContext(DraftActionsContext);
}

/**
 * Registers an editor's unsaved changes: `entry` null or with count 0 means nothing unsaved. The
 * registration follows the entry's key and is removed when the editor unmounts. A no-op outside the
 * shell.
 */
export function useDraftRegistration(entry: DraftEntry | null, handlers: DraftHandlers): void {
  const actions = useDraftActions();
  const handlersRef = useRef(handlers);
  useLayoutEffect(() => {
    handlersRef.current = handlers;
  });
  const key = entry?.key ?? null;
  const count = entry && entry.count > 0 ? entry.count : 0;
  const label = entry?.label ?? '';
  const scope = entry?.scope ?? 'policy';

  useEffect(() => {
    if (!actions || !key) return;
    if (count === 0) {
      actions.clear(key);
      return;
    }
    actions.set(
      { key, count, label, scope },
      { discard: () => handlersRef.current.discard(), review: () => handlersRef.current.review?.() }
    );
  }, [actions, key, count, label, scope]);

  useEffect(() => {
    if (!actions || !key) return;
    return () => actions.clear(key);
  }, [actions, key]);
}
