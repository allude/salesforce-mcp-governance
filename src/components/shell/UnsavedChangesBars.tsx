'use client';

import React from 'react';
import { useDraftState } from './draftContext';
import { draftBars, type DraftScope } from './policyDraft';

/**
 * One bar per kind of unsaved work, form bars above the policy bar: "Unsaved Policy Changes (3) ·
 * Review · Discard". Review takes the admin back to the editor holding the draft.
 */
export function UnsavedChangesBars({
  onReview,
  onDiscard,
}: {
  onReview: (scope: DraftScope) => void;
  onDiscard: (keys: string[]) => void;
}) {
  const state = useDraftState();
  const bars = draftBars(state);
  if (bars.length === 0) return null;
  return (
    <div className="draft-bars" role="region" aria-label="Unsaved changes">
      {bars.map((bar) => (
        <div key={bar.scope} className={`draft-bar draft-${bar.scope}`}>
          <span className="dot st-error" aria-hidden="true" />
          <span className="draft-t">{bar.title}</span>
          <span className="draft-items">
            {Object.values(state)
              .filter((e) => e.scope === bar.scope)
              .map((e) => e.label)
              .join(' · ')}
          </span>
          <button type="button" className="btn sm" onClick={() => onReview(bar.scope)}>
            Review
          </button>
          <button
            type="button"
            className="btn gh sm"
            onClick={() =>
              onDiscard(
                Object.values(state)
                  .filter((e) => e.scope === bar.scope)
                  .map((e) => e.key)
              )
            }
          >
            Discard
          </button>
        </div>
      ))}
    </div>
  );
}
