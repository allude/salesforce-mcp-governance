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

/**
 * Whether a stored entry is held: its Object was deleted from Salesforce > Objects, so it stays on the
 * group for admins to see, restore or remove, and grants nothing, even once the Object is imported
 * again, until an admin restores it. Any value but false, null or undefined holds it, as it does for
 * the release that added holding, so an entry is never read as live because its marker is odd.
 */
export function isHeldGrant(entry: unknown): boolean {
  return Boolean(entry && typeof entry === 'object' && (entry as { removed?: unknown }).removed);
}

/**
 * The fields an entry holds as deleted from Salesforce > Objects (`removedFields`), lower-cased. Held
 * fields grant nothing, even once they are back in the catalog, until an admin restores them. A held
 * field that names no field (an older release or a hand edit) is skipped.
 */
export function heldFieldNames(entry: Pick<GroupObjectPermission, 'removedFields'>): Set<string> {
  const held: unknown[] = Array.isArray(entry.removedFields) ? entry.removedFields : [];
  return new Set(
    held.flatMap((field) =>
      field && typeof field === 'object' && typeof (field as { fieldName?: unknown }).fieldName === 'string'
        ? [(field as { fieldName: string }).fieldName.toLowerCase()]
        : []
    )
  );
}

/**
 * Whether saving `next` over a group's `stored` entries restores something held: an entry held as
 * deleted from Salesforce > Objects that `next` lists live for its Object, or a held field (in
 * `removedFields`) that a live entry of `next` grants again. Entries the policy engine cannot read are
 * skipped, as they hold nothing it reads.
 */
export function restoresHeldGrant(stored: readonly unknown[], next: readonly GroupObjectPermission[]): boolean {
  const liveNext = new Map<string, GroupObjectPermission>();
  for (const grant of next) {
    if (!isHeldGrant(grant)) liveNext.set(grant.objectName.toLowerCase(), grant);
  }
  return stored.some((entry) => {
    if (malformedGrantReason(entry) !== null) return false;
    const grant = entry as GroupObjectPermission;
    const live = liveNext.get(grant.objectName.toLowerCase());
    if (!live) return false;
    if (isHeldGrant(grant)) return true;
    const granted = new Set((live.allowedFields ?? []).map((field) => field.toLowerCase()));
    return (Array.isArray(grant.removedFields) ? grant.removedFields : []).some(
      (held) => held && typeof held.fieldName === 'string' && granted.has(held.fieldName.toLowerCase())
    );
  });
}

/** A flag grants only when it is exactly true. */
export function grantsAccess(grant: Pick<GroupObjectPermission, (typeof GRANT_FLAGS)[number]>): boolean {
  return GRANT_FLAGS.some((flag) => grant[flag] === true);
}

/**
 * A stored group's entries as the policy engine reads them, for the portal's summaries of stored
 * groups: the entries it skips (see malformedGrantReason), held ones (isHeldGrant) and those naming
 * no Object are left out, each flag is true only when it is stored as exactly true, and a field the
 * entry holds (heldFieldNames) is not listed as granted. So no summary shows access that /mcp does not give.
 */
export function readableGrants(entries: readonly unknown[] | undefined): GroupObjectPermission[] {
  if (!Array.isArray(entries)) return [];
  return entries.flatMap((entry) => {
    if (malformedGrantReason(entry) !== null || isHeldGrant(entry)) return [];
    const grant = entry as Partial<GroupObjectPermission> & { objectName: string };
    if (!grant.objectName) return [];
    const held = heldFieldNames(grant);
    return [
      {
        objectName: grant.objectName,
        canRead: grant.canRead === true,
        canCreate: grant.canCreate === true,
        canUpdate: grant.canUpdate === true,
        canDelete: grant.canDelete === true,
        allowedFields: (grant.allowedFields ?? []).filter((field) => !held.has(field.toLowerCase())),
      },
    ];
  });
}

/**
 * The Salesforce > Objects row a grant's Object resolves to, by lower-case name: enabled rows only and,
 * of several for one Object (a database from an older version can hold 'Account' and 'account'), the
 * last in `objects` order. The policy engine resolves grants with this, and so do the portal's
 * summaries of a Profile's access (effectiveGrants), so the two cannot disagree.
 */
export function enabledObjectsByLowerName<T extends { objectName: string; enabled: boolean }>(
  objects: readonly T[]
): Map<string, T> {
  const byName = new Map<string, T>();
  for (const object of objects) {
    if (object.enabled) byName.set(object.objectName.toLowerCase(), object);
  }
  return byName;
}

/**
 * A stored group's grants that give access on /mcp, for the portal's summaries of a Profile's access:
 * the readable entries (readableGrants) that grant a flag and whose Object is enabled in Salesforce >
 * Objects (enabledObjectsByLowerName), each named as the catalog spells its Object. An entry for an
 * Object that is missing from the catalog, or disabled there, gives nothing on /mcp and is left out.
 */
export function effectiveGrants(
  entries: readonly unknown[] | undefined,
  objects: readonly { objectName: string; enabled: boolean }[]
): GroupObjectPermission[] {
  const enabled = enabledObjectsByLowerName(objects);
  return readableGrants(entries).flatMap((grant) => {
    const object = enabled.get(grant.objectName.toLowerCase());
    return object && grantsAccess(grant) ? [{ ...grant, objectName: object.objectName }] : [];
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
 * The merged entry holds every field its entries hold (`removedFields`), and a field one entry grants
 * and another holds stays held. Callers never pass a held entry (isHeldGrant) with others for its
 * Object: merged, it would grant what it holds.
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
    const removedFields: NonNullable<GroupObjectPermission['removedFields']> = [];
    for (const held of same.flatMap((grant) => (Array.isArray(grant.removedFields) ? grant.removedFields : []))) {
      if (!held || typeof held !== 'object' || typeof held.fieldName !== 'string') continue;
      if (removedFields.some((f) => f.fieldName.toLowerCase() === held.fieldName.toLowerCase())) continue;
      removedFields.push(held);
    }
    const isHeld = (field: string) => removedFields.some((f) => f.fieldName.toLowerCase() === field.toLowerCase());
    return {
      objectName: same[0].objectName,
      canRead: same.some((grant) => grant.canRead === true),
      canCreate: same.some((grant) => grant.canCreate === true),
      canUpdate: same.some((grant) => grant.canUpdate === true),
      canDelete: same.some((grant) => grant.canDelete === true),
      allowedFields: uniqueIgnoringCase([
        ...(granting.length > 0 ? granting : same).flatMap((grant) => grant.allowedFields ?? []),
        ...(fallsBackToId && idField ? [idField] : []),
      ]).filter((field) => !isHeld(field)),
      ...(removedFields.length > 0 ? { removedFields } : {}),
    };
  });
}
