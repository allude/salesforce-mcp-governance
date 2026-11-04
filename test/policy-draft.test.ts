import './helpers/env.js';
// The shell's draft store (src/components/shell/policyDraft.ts): which drafts exist, the bars, and
// when an action has to ask before throwing one away.
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import {
  EMPTY_DRAFTS,
  discardSummary,
  draftBars,
  draftCount,
  draftReducer,
  isDirty,
  needsDiscardConfirm,
  type DraftEntry,
} from '../src/components/shell/policyDraft.js';
import { changedFieldCount } from '../src/components/shell/formDraft.js';

const group: DraftEntry = { key: 'group:grp_sales', scope: 'policy', label: 'Group Sales', count: 3 };
const conn: DraftEntry = { key: 'form:connection', scope: 'connection', label: 'Org connection', count: 1 };

describe('draft store', () => {
  test('set, update, clear; a count of 0 removes the entry; no-op changes keep the same state', () => {
    let s = draftReducer(EMPTY_DRAFTS, { type: 'set', entry: group });
    assert.equal(draftCount(s), 3);
    assert.equal(draftReducer(s, { type: 'set', entry: { ...group } }), s);
    s = draftReducer(s, { type: 'set', entry: { ...group, count: 0 } });
    assert.deepEqual(s, {});
    assert.equal(isDirty(s), false);
    s = draftReducer(draftReducer(s, { type: 'set', entry: group }), { type: 'set', entry: conn });
    assert.equal(draftReducer(s, { type: 'clear', key: 'nope' }), s);
    assert.deepEqual(Object.keys(draftReducer(s, { type: 'clear-scope', scope: 'policy' })), ['form:connection']);
    assert.equal(draftReducer(s, { type: 'clear-all' }), EMPTY_DRAFTS);
  });

  test('bars: form bars above the policy bar, each counting its own scope', () => {
    let s = draftReducer(EMPTY_DRAFTS, { type: 'set', entry: group });
    s = draftReducer(s, { type: 'set', entry: conn });
    assert.deepEqual(
      draftBars(s).map((b) => b.title),
      ['Unsaved connection changes (1)', 'Unsaved Policy Changes (3)']
    );
  });

  test('an action asks only when it would throw away a draft it affects', () => {
    let s = draftReducer(EMPTY_DRAFTS, { type: 'set', entry: group });
    assert.equal(needsDiscardConfirm(s), true, 'reload, Sign out');
    assert.equal(needsDiscardConfirm(s, ['form:connection']), false, 'navigation keeps a group draft');
    s = draftReducer(s, { type: 'set', entry: conn });
    assert.equal(needsDiscardConfirm(s, ['form:connection']), true);
    assert.deepEqual(discardSummary(s, ['form:connection']), ['Org connection (1 change)']);
    assert.equal(needsDiscardConfirm(EMPTY_DRAFTS), false);
  });

  test('a form counts the fields that differ from what is saved', () => {
    const saved = { a: '1', b: true, c: 'x' };
    assert.equal(changedFieldCount({ ...saved }, saved, ['a', 'b', 'c']), 0);
    assert.equal(changedFieldCount({ a: '2', b: false, c: 'x' }, saved, ['a', 'b', 'c']), 2);
    assert.equal(changedFieldCount({ a: '2', b: false, c: 'x' }, saved, ['c']), 0);
  });
});
