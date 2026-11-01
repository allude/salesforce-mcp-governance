// The sample matrix is refused in production and replaces mappings elsewhere, so the portal must
// neither offer it in production nor run it on the first click.
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { ENTERPRISE_MATRIX_WARNING, enterpriseMatrixAction } from '../src/components/views/enterpriseMatrix.js';

describe('enterpriseMatrixAction', () => {
  test('is not offered when dev tools are off, as in production', () => {
    assert.equal(enterpriseMatrixAction(false, () => {}), undefined);
  });

  test('outside production, the click only asks for confirmation', () => {
    let asked = 0;
    const action = enterpriseMatrixAction(true, () => {
      asked += 1;
    });
    assert.ok(action);
    action();
    assert.equal(asked, 1);
  });

  test('the warning says existing mappings are replaced', () => {
    assert.match(ENTERPRISE_MATRIX_WARNING, /mappings replaced/);
  });
});
