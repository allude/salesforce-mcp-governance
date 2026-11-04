import { store } from '../db/store.js';
import { SALESFORCE_API_NAME_PATTERN } from '../db/importers.js';
import { MCP_ACTION_ID_PATTERN } from '../groups/groupGrants.js';
import { GRANT_FLAGS, isHeldGrant, mergeGrants, spellingLookup, uniqueIgnoringCase } from '../rbac/groupGrants.js';
import {
  ACCESS_GROUP_DESCRIPTION_MAX_LENGTH,
  ACCESS_GROUP_EDIT_SOURCES,
  ACCESS_GROUP_NAME_MAX_LENGTH,
  type AccessGroupChangeSource,
  type CatalogRemoval,
  type GroupObjectPermission,
} from '../types/governance.js';
import type { PayloadResult } from './orgSyncPayload.js';

// POST /groups stores what passes here and nothing else, in the shape the policy engine reads: every
// flag a boolean, every name an API name, and other keys dropped. A name this server does not have
// (an Object or field not in Salesforce > Objects, an MCP action it has no tool for) is kept and the
// portal shows it as not available: it grants nothing while the server lacks it, and a group imported
// from another server, or one whose Object was deleted, keeps what it names for an admin to review.

export interface GroupSaveRequest {
  /** The group to update; undefined creates one. */
  id: string | undefined;
  /** The version the client loaded, when it sent one. */
  expectedVersion: number | undefined;
  name: string;
  description: string;
  allowedActions: string[];
  /**
   * The grants as sent. The route checks them with parseGroupObjectPermissions only after the version
   * check, because a stale draft is a 409 whatever it holds, never a 400.
   */
  objectPermissions: unknown;
  /** Which editor (or import) the save came from, for the group's history. */
  source: AccessGroupChangeSource;
  /** The file an import came from, or the version a restore loaded; '' otherwise. */
  sourceDetail: string;
}

/** The detail an edit's history keeps: the file an import came from, or the version a restore loaded. */
export const MAX_SOURCE_DETAIL = 300;
const MAX_REMOVAL_TEXT = 200;

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

/** A name the admin typed, as an error message may show it: trimmed, quoted and cut at 80 characters. */
const typedName = (name: string) => JSON.stringify(name.trim().slice(0, 80));

const fail = (error: string): { ok: false; error: string } => ({ ok: false, error });

/** When and by whom something held was deleted, as text only, each part capped. */
function removalOf(raw: unknown): CatalogRemoval {
  const source = isRecord(raw) ? raw : {};
  const text = (value: unknown) => (typeof value === 'string' ? value.trim().slice(0, MAX_REMOVAL_TEXT) : '');
  return { at: text(source.at), by: text(source.by) };
}

/**
 * Checks a group's object grants and returns them as stored: each Object and field under the catalog's
 * spelling when Salesforce > Objects has it (and as typed when it does not), every flag a boolean,
 * other keys dropped, and the entries for one Object (in any case) merged into one (see mergeGrants).
 * An entry held as deleted (`removed`) and its held fields (`removedFields`) are kept as held: a field
 * both granted and held stays held, the safer of the two readings. A held entry is never merged, since
 * merged into a live entry it would grant what it holds, so an Object it shares with another entry is
 * refused. The error names the entry and the key, and of what was sent only the name typed.
 */
export function parseGroupObjectPermissions(raw: unknown): PayloadResult<GroupObjectPermission[]> {
  if (raw === undefined || raw === null) return { ok: true, value: [] };
  if (!Array.isArray(raw)) return fail('objectPermissions must be an array.');

  const grants: GroupObjectPermission[] = [];
  for (const [index, entry] of raw.entries()) {
    const at = `objectPermissions[${index}]`;
    if (!isRecord(entry)) return fail(`${at} must be an object.`);
    if (typeof entry.objectName !== 'string' || !entry.objectName.trim()) {
      return fail(`${at}.objectName must be the API name of an Object.`);
    }
    const typedObject = entry.objectName.trim();
    if (!SALESFORCE_API_NAME_PATTERN.test(typedObject)) {
      return fail(`${at}.objectName: ${typedName(typedObject)} is not a valid Salesforce object API name.`);
    }
    for (const flag of GRANT_FLAGS) {
      if (entry[flag] !== undefined && typeof entry[flag] !== 'boolean') {
        return fail(`${at}.${flag} must be true or false.`);
      }
    }
    const sentFields = entry.allowedFields ?? [];
    if (!Array.isArray(sentFields)) return fail(`${at}.allowedFields must be an array of field API names.`);
    const sentHeld = entry.removedFields ?? [];
    if (!Array.isArray(sentHeld)) return fail(`${at}.removedFields must be an array of held fields.`);

    const objectName = store.resolveObjectName(typedObject);
    const catalogFields = store.getObjectFieldNames(objectName);
    const catalogSpelling = catalogFields ? spellingLookup(catalogFields) : () => null;
    const fieldName = (typed: string) => catalogSpelling(typed) ?? typed;

    const removedFields: Array<CatalogRemoval & { fieldName: string }> = [];
    for (const [heldIndex, held] of sentHeld.entries()) {
      const heldAt = `${at}.removedFields[${heldIndex}]`;
      if (!isRecord(held) || typeof held.fieldName !== 'string' || !held.fieldName.trim()) {
        return fail(`${heldAt}.fieldName must be a field API name.`);
      }
      const typedField = held.fieldName.trim();
      if (!SALESFORCE_API_NAME_PATTERN.test(typedField)) {
        return fail(`${heldAt}.fieldName: ${typedName(typedField)} is not a valid Salesforce field API name.`);
      }
      if (removedFields.some((f) => f.fieldName.toLowerCase() === typedField.toLowerCase())) continue;
      removedFields.push({ fieldName: typedField, ...removalOf(held) });
    }
    const heldNames = new Set(removedFields.map((f) => f.fieldName.toLowerCase()));

    const allowedFields: string[] = [];
    for (const [fieldIndex, field] of sentFields.entries()) {
      const fieldAt = `${at}.allowedFields[${fieldIndex}]`;
      if (typeof field !== 'string' || !field.trim()) return fail(`${fieldAt} must be a field API name.`);
      const typedField = field.trim();
      if (!SALESFORCE_API_NAME_PATTERN.test(typedField)) {
        return fail(`${fieldAt}: ${typedName(typedField)} is not a valid Salesforce field API name.`);
      }
      if (!heldNames.has(typedField.toLowerCase())) allowedFields.push(fieldName(typedField));
    }

    const grant: GroupObjectPermission = {
      objectName,
      canRead: entry.canRead === true,
      canCreate: entry.canCreate === true,
      canUpdate: entry.canUpdate === true,
      canDelete: entry.canDelete === true,
      allowedFields: uniqueIgnoringCase(allowedFields),
    };
    if (isHeldGrant(entry)) grant.removed = removalOf(entry.removed);
    if (removedFields.length > 0) grant.removedFields = removedFields;
    grants.push(grant);
  }

  const entriesByObject = new Map<string, GroupObjectPermission[]>();
  for (const grant of grants) {
    const key = grant.objectName.toLowerCase();
    entriesByObject.set(key, [...(entriesByObject.get(key) ?? []), grant]);
  }
  for (const same of entriesByObject.values()) {
    if (same.length > 1 && same.some(isHeldGrant)) {
      return fail(
        `Object ${same[0].objectName} is listed more than once, and one of its entries is held as deleted. Restore or remove the held entry first.`
      );
    }
  }
  return { ok: true, value: mergeGrants(grants, (objectName) => store.getObjectFieldNames(objectName) ?? []) };
}

/**
 * Reads a POST /groups body, all but its grants (see GroupSaveRequest). Names and descriptions are
 * trimmed and capped, MCP action IDs trimmed and listed once, and an unknown `source` reads as the
 * visual editor. `expectedVersion` may be left out, for clients from before versions; the portal
 * always sends it on an update.
 */
export function parseGroupSaveRequest(body: Record<string, unknown>): PayloadResult<GroupSaveRequest> {
  const { id, expectedVersion, name, description, allowedActions, objectPermissions, source, sourceDetail } = body;

  if (typeof name !== 'string' || !name.trim()) return fail('Group name is required.');
  if (name.trim().length > ACCESS_GROUP_NAME_MAX_LENGTH) {
    return fail(`The group name must be at most ${ACCESS_GROUP_NAME_MAX_LENGTH} characters.`);
  }
  if (description !== undefined && description !== null && typeof description !== 'string') {
    return fail('The description must be text.');
  }
  const trimmedDescription = (description ?? '').trim();
  if (trimmedDescription.length > ACCESS_GROUP_DESCRIPTION_MAX_LENGTH) {
    return fail(`The description must be at most ${ACCESS_GROUP_DESCRIPTION_MAX_LENGTH} characters.`);
  }
  if (id !== undefined && id !== null && typeof id !== 'string') return fail('id must be the id of an Access Group.');
  if (
    expectedVersion !== undefined &&
    expectedVersion !== null &&
    !(Number.isSafeInteger(expectedVersion) && (expectedVersion as number) >= 1)
  ) {
    return fail('expectedVersion must be the version of the group as it was loaded.');
  }

  // An ID this server has no tool for is kept and shown as not available: tools/list offers and
  // tools/call runs only this server's own tools, so it grants nothing. One that is no ID is refused.
  if (allowedActions !== undefined && allowedActions !== null && !Array.isArray(allowedActions)) {
    return fail('allowedActions must be a list of MCP action IDs.');
  }
  const actions: string[] = [];
  for (const [index, raw] of ((allowedActions as unknown[] | null | undefined) ?? []).entries()) {
    if (typeof raw !== 'string' || !raw.trim()) return fail(`allowedActions[${index}] must be an MCP action ID.`);
    const actionId = raw.trim();
    if (!MCP_ACTION_ID_PATTERN.test(actionId)) {
      return fail(`allowedActions[${index}]: ${typedName(actionId)} is not a valid MCP action ID.`);
    }
    if (!actions.includes(actionId)) actions.push(actionId);
  }

  return {
    ok: true,
    value: {
      id: typeof id === 'string' && id.trim() ? id.trim() : undefined,
      expectedVersion: typeof expectedVersion === 'number' ? expectedVersion : undefined,
      name: name.trim(),
      description: trimmedDescription,
      allowedActions: actions,
      objectPermissions,
      source: (ACCESS_GROUP_EDIT_SOURCES as readonly unknown[]).includes(source) ? (source as AccessGroupChangeSource) : 'editor',
      sourceDetail: typeof sourceDetail === 'string' ? sourceDetail.trim().slice(0, MAX_SOURCE_DETAIL) : '',
    },
  };
}
