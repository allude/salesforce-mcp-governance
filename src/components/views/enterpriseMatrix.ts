export const ENTERPRISE_MATRIX_WARNING =
  'This creates 5 sample Access Groups and sample Profiles. Any Profile whose name matches a sample Profile has its group mappings replaced, which can change what it is allowed to do.';

/**
 * The action the portal offers, or undefined where the server refuses it. Views show the action only
 * when they are given one, and it only asks for confirmation: running is a separate step.
 */
export function enterpriseMatrixAction(
  devToolsEnabled: boolean,
  askToConfirm: () => void
): (() => void) | undefined {
  return devToolsEnabled ? askToConfirm : undefined;
}
