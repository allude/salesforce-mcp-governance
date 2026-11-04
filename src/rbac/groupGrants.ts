// The object entries ("grants") of an Access Group, as the policy engine, POST /groups, the store's
// canonicalization and the portal's group editor read them. Pure, so the portal can import it too.
import type { GroupObjectPermission } from '../types/governance.js';

export const GRANT_FLAGS = ['canRead', 'canCreate', 'canUpdate', 'canDelete'] as const;

const NOT_AN_OBJECT = 'the entry is not an object';
const OBJECT_NAME_NOT_TEXT = 'objectName is not text';
const flagNotBoolean = (flag: (typeof GRANT_FLAGS)[number]) => `${flag} is not true or false`;
const FIELDS_NOT_NAMES = 'allowedFields is not a list of field names';

/**
 * Every reason malformedGrantReason gives. The MCP log stores a skipped entry's reason only when it is
 * one of these, so no other text can reach it.
 */
export const MALFORMED_GRANT_REASONS: readonly string[] = [
  NOT_AN_OBJECT,
  OBJECT_NAME_NOT_TEXT,
  ...GRANT_FLAGS.map(flagNotBoolean),
  FIELDS_NOT_NAMES,
];

/**
 * Why a stored entry cannot be read as a grant, or null when it can. Such an entry is skipped whole
 * by the policy engine: it grants nothing, whatever part of it looks usable. The reason names a key
 * only, never a value.
 */
export function malformedGrantReason(entry: unknown): string | null {
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return NOT_AN_OBJECT;
  const grant = entry as Record<string, unknown>;
  if (typeof grant.objectName !== 'string') return OBJECT_NAME_NOT_TEXT;
  for (const flag of GRANT_FLAGS) {
    if (grant[flag] !== undefined && typeof grant[flag] !== 'boolean') return flagNotBoolean(flag);
  }
  if (
    grant.allowedFields !== undefined &&
    !(Array.isArray(grant.allowedFields) && grant.allowedFields.every((field) => typeof field === 'string'))
  ) {
    return FIELDS_NOT_NAMES;
  }
  return null;
}

/** A flag grants only when it is exactly true. */
export function grantsAccess(grant: Pick<GroupObjectPermission, (typeof GRANT_FLAGS)[number]>): boolean {
  return GRANT_FLAGS.some((flag) => grant[flag] === true);
}

/**
 * A stored group's entries as the policy engine reads them, for the portal's summaries of stored
 * groups: the entries it skips (see malformedGrantReason) and those naming no Object are left out,
 * and each flag is true only when it is stored as exactly true. So no summary shows access that /mcp
 * does not give.
 */
export function readableGrants(entries: readonly unknown[] | undefined): GroupObjectPermission[] {
  if (!Array.isArray(entries)) return [];
  return entries.flatMap((entry) => {
    if (malformedGrantReason(entry) !== null) return [];
    const grant = entry as Partial<GroupObjectPermission> & { objectName: string };
    if (!grant.objectName) return [];
    return [
      {
        objectName: grant.objectName,
        canRead: grant.canRead === true,
        canCreate: grant.canCreate === true,
        canUpdate: grant.canUpdate === true,
        canDelete: grant.canDelete === true,
        allowedFields: grant.allowedFields ?? [],
      },
    ];
  });
}

/**
 * Finds a name's stored spelling in `names`: the same spelling if it is there, else the first that
 * differs only by case. Salesforce API names are case-insensitive.
 */
export function spellingLookup(names: readonly string[]): (name: string) => string | null {
  const exact = new Set(names);
  const byLowerCase = new Map<string, string>();
  for (const name of names) {
    if (!byLowerCase.has(name.toLowerCase())) byLowerCase.set(name.toLowerCase(), name);
  }
  return (name) => (exact.has(name) ? name : byLowerCase.get(name.toLowerCase()) ?? null);
}

/** The names once each, ignoring case, in the spelling and order they first appear. */
export function uniqueIgnoringCase(names: readonly string[]): string[] {
  const seen = new Set<string>();
  return names.filter((name) => {
    const key = name.toLowerCase();
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/**
 * Merges the entries of one group that name the same Object, in any case, into one at the place of
 * the first: its flags are OR-ed and its fields are the union of the fields of the entries that grant
 * something. An entry that grants nothing adds no fields, because the policy engine reads it as
 * nothing at all. An entry with no other entry for its Object is returned as it is.
 *
 * The engine gives an entry that grants Read, Create or Update but names none of the Object's fields
 * the Object's Id instead, entry by entry, and in a union the other entries' fields would hide that.
 * So when such an entry is merged, the merged entry lists Id too, as `catalogFields` (the Object's
 * field names in Salesforce > Objects) spells it. The merged entry then gives what its entries gave,
 * with one exception no stored list can avoid: an entry whose fields all exist but are disabled gives
 * Id only until one of them is enabled, and merged it gives no Id for them, so it can only grant less.
 */
export function mergeGrants(
  grants: readonly GroupObjectPermission[],
  catalogFields: (objectName: string) => readonly string[]
): GroupObjectPermission[] {
  const byObject = new Map<string, GroupObjectPermission[]>();
  for (const grant of grants) {
    const key = grant.objectName.toLowerCase();
    byObject.set(key, [...(byObject.get(key) ?? []), grant]);
  }
  return Array.from(byObject.values(), (same) => {
    if (same.length === 1) return same[0];
    const granting = same.filter(grantsAccess);
    const catalogField = spellingLookup(catalogFields(same[0].objectName));
    const idField = catalogField('Id');
    const fallsBackToId = granting.some(
      (grant) =>
        (grant.canRead === true || grant.canCreate === true || grant.canUpdate === true) &&
        !(grant.allowedFields ?? []).some((field) => catalogField(field) !== null)
    );
    return {
      objectName: same[0].objectName,
      canRead: same.some((grant) => grant.canRead === true),
      canCreate: same.some((grant) => grant.canCreate === true),
      canUpdate: same.some((grant) => grant.canUpdate === true),
      canDelete: same.some((grant) => grant.canDelete === true),
      allowedFields: uniqueIgnoringCase([
        ...(granting.length > 0 ? granting : same).flatMap((grant) => grant.allowedFields ?? []),
        ...(fallsBackToId && idField ? [idField] : []),
      ]),
    };
  });
}
