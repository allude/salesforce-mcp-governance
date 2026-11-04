import { store } from '../db/store.js';
import { GRANT_FLAGS, mergeGrants, spellingLookup, uniqueIgnoringCase } from '../rbac/groupGrants.js';
import {
  ACCESS_GROUP_DESCRIPTION_MAX_LENGTH,
  ACCESS_GROUP_NAME_MAX_LENGTH,
  AVAILABLE_MCP_ACTIONS,
  unknownMcpActionIds,
  type GroupObjectPermission,
} from '../types/governance.js';
import type { PayloadResult } from './orgSyncPayload.js';

// POST /groups stores what passes here and nothing else: the policy engine reads a stored group as
// it is, so a grant it cannot use must be refused before it is saved, not skipped at /mcp later.

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
   * check, because a stale draft can hold an Object or field deleted since: that is a 409, not a 400.
   */
  objectPermissions: unknown;
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

/** A name the admin typed, as an error message may show it: trimmed, quoted and cut at 80 characters. */
const typedName = (name: string) => JSON.stringify(name.trim().slice(0, 80));

const fail = (error: string): { ok: false; error: string } => ({ ok: false, error });

/**
 * Checks a group's object grants against Salesforce > Objects and returns them as stored: each Object
 * and field under the catalog's spelling, every flag a boolean, other keys dropped, and the entries
 * for one Object (in any case) merged into one (see mergeGrants). An Object that is disabled globally
 * is accepted. The error names the entry and the key, and of what was sent only the name typed.
 */
export function parseGroupObjectPermissions(raw: unknown): PayloadResult<GroupObjectPermission[]> {
  if (raw === undefined) return { ok: true, value: [] };
  if (!Array.isArray(raw)) return fail('objectPermissions must be an array.');

  const grants: GroupObjectPermission[] = [];
  for (const [index, entry] of raw.entries()) {
    const at = `objectPermissions[${index}]`;
    if (!isRecord(entry)) return fail(`${at} must be an object.`);
    if (typeof entry.objectName !== 'string' || !entry.objectName.trim()) {
      return fail(`${at}.objectName must be the API name of an Object.`);
    }
    for (const flag of GRANT_FLAGS) {
      if (entry[flag] !== undefined && typeof entry[flag] !== 'boolean') {
        return fail(`${at}.${flag} must be true or false.`);
      }
    }
    const sentFields = entry.allowedFields === undefined ? [] : entry.allowedFields;
    if (!Array.isArray(sentFields)) return fail(`${at}.allowedFields must be an array of field API names.`);

    const objectName = store.resolveObjectName(entry.objectName);
    const fieldNames = store.getObjectFieldNames(objectName);
    if (!fieldNames) {
      return fail(`${at}.objectName: Salesforce > Objects has no Object named ${typedName(entry.objectName)}.`);
    }
    const fieldSpelling = spellingLookup(fieldNames);
    const allowedFields: string[] = [];
    for (const [fieldIndex, field] of sentFields.entries()) {
      const fieldAt = `${at}.allowedFields[${fieldIndex}]`;
      if (typeof field !== 'string' || !field.trim()) return fail(`${fieldAt} must be a field API name.`);
      const fieldName = fieldSpelling(field.trim());
      if (!fieldName) return fail(`${fieldAt}: Object "${objectName}" has no field named ${typedName(field)}.`);
      allowedFields.push(fieldName);
    }

    grants.push({
      objectName,
      canRead: entry.canRead === true,
      canCreate: entry.canCreate === true,
      canUpdate: entry.canUpdate === true,
      canDelete: entry.canDelete === true,
      allowedFields: uniqueIgnoringCase(allowedFields),
    });
  }
  return { ok: true, value: mergeGrants(grants, (objectName) => store.getObjectFieldNames(objectName) ?? []) };
}

/**
 * Reads a POST /groups body, all but its grants (see GroupSaveRequest). Names and descriptions are
 * trimmed and capped. `expectedVersion` may be left out, for clients from before versions; the portal
 * always sends it on an update.
 */
export function parseGroupSaveRequest(body: Record<string, unknown>): PayloadResult<GroupSaveRequest> {
  const { id, expectedVersion, name, description, allowedActions, objectPermissions } = body;

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

  // An unknown ID grants nothing at /mcp, so storing one would only look like a working grant.
  const actions = Array.isArray(allowedActions) ? allowedActions : [];
  const unknownActions = unknownMcpActionIds(actions);
  if (unknownActions.length > 0) {
    return fail(
      `Unknown MCP action IDs: ${unknownActions.join(', ')}. Valid IDs: ${AVAILABLE_MCP_ACTIONS.map((a) => a.id).join(', ')}.`
    );
  }

  return {
    ok: true,
    value: {
      id: typeof id === 'string' && id.trim() ? id.trim() : undefined,
      expectedVersion: typeof expectedVersion === 'number' ? expectedVersion : undefined,
      name: name.trim(),
      description: trimmedDescription,
      allowedActions: actions as string[],
      objectPermissions,
    },
  };
}
