/**
 * The shell's draft store, as a pure reducer so its rules are unit-tested without a DOM. Editors
 * register what they hold unsaved: the policy (Access Groups & Matrix Builder: group definitions and
 * mappings) and the two forms (Org connection, Okta / security). Each bar counts only its own scope.
 * The shell asks before anything would throw a draft away: drawer close, Escape, a scrim click, the
 * palette replacing the drawer, navigation, Sign out, and reload (beforeunload).
 */
export type DraftScope = 'policy' | 'connection' | 'security';

export interface DraftEntry {
  key: string;
  scope: DraftScope;
  /** What holds the change, for the confirm dialog ("Group Sales Read-Only"). */
  label: string;
  /** How many changes it holds (> 0; an entry with none is removed). */
  count: number;
}

export type DraftState = Readonly<Record<string, DraftEntry>>;

export type DraftAction =
  | { type: 'set'; entry: DraftEntry }
  | { type: 'clear'; key: string }
  | { type: 'clear-scope'; scope: DraftScope }
  | { type: 'clear-all' };

export const EMPTY_DRAFTS: DraftState = Object.freeze({});

export function draftReducer(state: DraftState, action: DraftAction): DraftState {
  switch (action.type) {
    case 'set': {
      const { entry } = action;
      if (entry.count <= 0) return draftReducer(state, { type: 'clear', key: entry.key });
      const current = state[entry.key];
      if (current && current.count === entry.count && current.label === entry.label && current.scope === entry.scope) {
        return state;
      }
      return { ...state, [entry.key]: entry };
    }
    case 'clear': {
      if (!(action.key in state)) return state;
      const { [action.key]: _removed, ...rest } = state;
      return rest;
    }
    case 'clear-scope': {
      const rest = Object.fromEntries(Object.entries(state).filter(([, e]) => e.scope !== action.scope));
      return Object.keys(rest).length === Object.keys(state).length ? state : rest;
    }
    case 'clear-all':
      return Object.keys(state).length ? EMPTY_DRAFTS : state;
  }
}

export function draftCount(state: DraftState, scope?: DraftScope): number {
  return Object.values(state)
    .filter((e) => scope === undefined || e.scope === scope)
    .reduce((n, e) => n + e.count, 0);
}

export function isDirty(state: DraftState, scope?: DraftScope): boolean {
  return draftCount(state, scope) > 0;
}

/** The bars shown, top to bottom: a form bar sits above the policy bar, each with its own count. */
export function draftBars(state: DraftState): Array<{ scope: DraftScope; count: number; title: string }> {
  const titles: Record<DraftScope, (n: number) => string> = {
    connection: (n) => `Unsaved connection changes (${n})`,
    security: (n) => `Unsaved security changes (${n})`,
    policy: (n) => `Unsaved Policy Changes (${n})`,
  };
  return (['connection', 'security', 'policy'] as const)
    .map((scope) => ({ scope, count: draftCount(state, scope), title: titles[scope](draftCount(state, scope)) }))
    .filter((bar) => bar.count > 0);
}

/**
 * Whether an action has to ask first. `affects` names the draft keys the action would throw away; with
 * none given, every draft counts (navigation, Sign out, reload).
 */
export function needsDiscardConfirm(state: DraftState, affects?: readonly string[]): boolean {
  const entries = Object.values(state);
  return affects === undefined ? entries.length > 0 : entries.some((e) => affects.includes(e.key));
}

/** The confirm dialog's list: what would be lost. */
export function discardSummary(state: DraftState, affects?: readonly string[]): string[] {
  return Object.values(state)
    .filter((e) => affects === undefined || affects.includes(e.key))
    .map((e) => `${e.label} (${e.count} change${e.count === 1 ? '' : 's'})`);
}
