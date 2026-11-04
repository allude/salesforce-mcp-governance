import './helpers/env.js';
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { MAX_TOASTS, dismissToast, pushToast, toastDuration, type ToastItem } from '../src/components/ui/toastQueue.js';

const toast = (id: number, kind: ToastItem['kind'] = 'success', message = `m${id}`): ToastItem => ({
  id,
  kind,
  message,
  durationMs: toastDuration(kind, false),
});

describe('toast queue', () => {
  test('errors stay until dismissed; others time out, longer when they offer Undo', () => {
    assert.equal(toastDuration('error', false), null);
    assert.ok((toastDuration('success', false) ?? 0) > 0);
    assert.ok((toastDuration('success', true) ?? 0) > (toastDuration('success', false) ?? 0));
  });

  test('stacks newest last, capped, dropping the oldest non-error first', () => {
    let q: ToastItem[] = [toast(1, 'error')];
    for (let i = 2; i <= MAX_TOASTS + 2; i++) q = pushToast(q, toast(i));
    assert.equal(q.length, MAX_TOASTS);
    assert.equal(q[0].id, 1, 'the error survives');
    assert.equal(q[q.length - 1].id, MAX_TOASTS + 2);
  });

  test('a repeated message replaces its earlier copy', () => {
    const q = pushToast(pushToast([], toast(1, 'error', 'Backend unreachable')), toast(2, 'error', 'Backend unreachable'));
    assert.deepEqual(q.map((t) => t.id), [2]);
  });

  test('dismiss removes only that toast', () => {
    assert.deepEqual(dismissToast([toast(1), toast(2)], 1).map((t) => t.id), [2]);
  });
});
