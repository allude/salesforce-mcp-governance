/**
 * What an Access Group grants, checked the same way by the server, the portal's group editor and
 * XML import: the shape a stored group must have, which of its grants are not available on this
 * server (and why), and the changes between two versions of a group, as history records them.
 */
import { AVAILABLE_MCP_ACTIONS } from '../types/governance.ts';
import type {
  AccessGroupSnapshot,
  CatalogRemoval,
  GroupObjectPermission,
  SalesforceObject,
} from '../types/governance.ts';
import { SALESFORCE_API_NAME_PATTERN } from '../db/importers.ts';
import { malformedGrantReason } from '../rbac/groupGrants.ts';

/**
 * What an MCP action ID may look like. A group may name an ID this server has no tool for (an XML
 * file from a newer server, a tool since removed): it is kept and shown as not available.
 */
export const MCP_ACTION_ID_PATTERN = /^[A-Za-z][A-Za-z0-9_.:-]{0,99}$/;

export function isKnownMcpAction(id: string): boolean {
  return AVAILABLE_MCP_ACTIONS.some((action) => action.id === id);
}

export type GrantResult<T> = { ok: true; value: T } | { ok: false; error: string };

const MAX_REMOVAL_TEXT = 200;

/** A group's MCP action IDs: strings of the right shape, each once. Unknown tools are kept. */
export function normalizeMcpActions(input: unknown): GrantResult<string[]> {
  if (input === undefined || input === null) return { ok: true, value: [] };
  if (!Array.isArray(input)) return { ok: false, error: 'allowedActions must be a list of MCP action IDs.' };
  const ids: string[] = [];
  for (const raw of input) {
    if (typeof raw !== 'string') return { ok: false, error: `${JSON.stringify(raw)} is not an MCP action ID.` };
    const id = raw.trim();
    if (!MCP_ACTION_ID_PATTERN.test(id)) return { ok: false, error: `'${raw}' is not a valid MCP action ID.` };
    if (!ids.includes(id)) ids.push(id);
  }
  return { ok: true, value: ids };
}

function normalizeRemoval(raw: unknown): CatalogRemoval {
  const source = raw && typeof raw === 'object' ? (raw as Record<string, unknown>) : {};
  const text = (value: unknown) => (typeof value === 'string' ? value.trim().slice(0, MAX_REMOVAL_TEXT) : '');
  return { at: text(source.at), by: text(source.by) };
}

/**
 * A group's object entries in the stored shape. Names must be Salesforce API names, an object may be
 * listed once, and a field once per object (both case-insensitively, as Salesforce compares them).
 * Only `true` grants a CRUD flag. A field both granted and held as deleted stays held: being deleted
 * is the safer of the two readings.
 */
export function normalizeObjectPermissions(input: unknown): GrantResult<GroupObjectPermission[]> {
  if (input === undefined || input === null) return { ok: true, value: [] };
  if (!Array.isArray(input)) return { ok: false, error: 'objectPermissions must be a list of object entries.' };
  const entries: GroupObjectPermission[] = [];
  const seen = new Set<string>();
  for (const raw of input) {
    if (!raw || typeof raw !== 'object') return { ok: false, error: 'Each object entry must be an object.' };
    const entry = raw as Record<string, unknown>;
    const objectName = typeof entry.objectName === 'string' ? entry.objectName.trim() : '';
    if (!SALESFORCE_API_NAME_PATTERN.test(objectName)) {
      return { ok: false, error: `'${String(entry.objectName ?? '')}' is not a valid Salesforce object API name.` };
    }
    const key = objectName.toLowerCase();
    if (seen.has(key)) return { ok: false, error: `Object ${objectName} is listed more than once.` };
    seen.add(key);

    const removedFields: Array<CatalogRemoval & { fieldName: string }> = [];
    if (entry.removedFields !== undefined && entry.removedFields !== null) {
      if (!Array.isArray(entry.removedFields)) {
        return { ok: false, error: `removedFields of ${objectName} must be a list.` };
      }
      for (const held of entry.removedFields) {
        const fieldName = held && typeof held === 'object' ? String((held as Record<string, unknown>).fieldName ?? '').trim() : '';
        if (!SALESFORCE_API_NAME_PATTERN.test(fieldName)) {
          return { ok: false, error: `'${fieldName}' on ${objectName} is not a valid Salesforce field API name.` };
        }
        if (removedFields.some((f) => f.fieldName.toLowerCase() === fieldName.toLowerCase())) continue;
        removedFields.push({ fieldName, ...normalizeRemoval(held) });
      }
    }

    const allowedFields: string[] = [];
    if (entry.allowedFields !== undefined && entry.allowedFields !== null && !Array.isArray(entry.allowedFields)) {
      return { ok: false, error: `allowedFields of ${objectName} must be a list of field API names.` };
    }
    for (const rawField of (entry.allowedFields as unknown[]) || []) {
      const fieldName = typeof rawField === 'string' ? rawField.trim() : '';
      if (!SALESFORCE_API_NAME_PATTERN.test(fieldName)) {
        return { ok: false, error: `'${String(rawField)}' on ${objectName} is not a valid Salesforce field API name.` };
      }
      const lower = fieldName.toLowerCase();
      if (allowedFields.some((f) => f.toLowerCase() === lower)) continue;
      if (removedFields.some((f) => f.fieldName.toLowerCase() === lower)) continue;
      allowedFields.push(fieldName);
    }

    const normalized: GroupObjectPermission = {
      objectName,
      canRead: entry.canRead === true,
      canCreate: entry.canCreate === true,
      canUpdate: entry.canUpdate === true,
      canDelete: entry.canDelete === true,
      allowedFields,
    };
    if (entry.removed) normalized.removed = normalizeRemoval(entry.removed);
    if (removedFields.length > 0) normalized.removedFields = removedFields;
    entries.push(normalized);
  }
  return { ok: true, value: entries };
}

// ============================================================================
// Availability: what in a group cannot work on this server, and why
// ============================================================================

export type GroupIssueReason =
  | 'unknown_action'
  | 'object_deleted'
  | 'object_not_in_catalog'
  | 'object_disabled'
  | 'object_missing_in_org'
  | 'field_deleted'
  | 'field_not_in_catalog'
  | 'field_disabled'
  | 'field_missing_in_org';

export interface GroupAvailabilityIssue {
  kind: 'action' | 'object' | 'field';
  /** The object an object or field issue is on; '' for an action. */
  objectName: string;
  /** The action ID, object name or field name. */
  name: string;
  reason: GroupIssueReason;
  /**
   * `unavailable`: the grant does nothing on this server. `broken`: it is in force, but Salesforce no
   * longer has what it names, so calls using it fail.
   */
  status: 'unavailable' | 'broken';
  message: string;
}

function removalClause(removal: CatalogRemoval): string {
  const by = removal.by ? ` by ${removal.by}` : '';
  const on = removal.at && !Number.isNaN(Date.parse(removal.at)) ? ` on ${removal.at.slice(0, 10)}` : '';
  return `${by}${on}`;
}

/** When and by whom something held was deleted, as text, whatever form the stored marker has. */
function removalText(raw: unknown): CatalogRemoval {
  const source = raw && typeof raw === 'object' ? (raw as Record<string, unknown>) : {};
  const text = (value: unknown) => (typeof value === 'string' ? value : '');
  return { at: text(source.at), by: text(source.by) };
}

/**
 * A group as stored, as the readers here take it (availability issues, history lines, XML of a history
 * version): the MCP action IDs that are text, and the entries the policy engine can read (see
 * malformedGrantReason), held ones included, each with a field list, only the held fields that name a
 * field, and when and by whom each was held as text. An older release could store entries the engine
 * skips, an entry with no field list, or held markers in another shape. They grant nothing, so they are
 * left out (or read as text), and no reader fails on them.
 */
export function describableGroup<T extends Pick<AccessGroupSnapshot, 'allowedActions' | 'objectPermissions'>>(group: T): T {
  const actions: unknown[] = Array.isArray(group.allowedActions) ? group.allowedActions : [];
  const entries: unknown[] = Array.isArray(group.objectPermissions) ? group.objectPermissions : [];
  return {
    ...group,
    allowedActions: actions.filter((id): id is string => typeof id === 'string'),
    objectPermissions: entries.flatMap((entry) => {
      if (malformedGrantReason(entry) !== null) return [];
      const perm = entry as GroupObjectPermission;
      const removedFields = (Array.isArray(perm.removedFields) ? (perm.removedFields as unknown[]) : []).flatMap((held) =>
        held && typeof held === 'object' && typeof (held as { fieldName?: unknown }).fieldName === 'string'
          ? [{ fieldName: (held as { fieldName: string }).fieldName, ...removalText(held) }]
          : []
      );
      const { removed, removedFields: _stored, ...rest } = perm;
      return [
        {
          ...rest,
          allowedFields: perm.allowedFields ?? [],
          ...(removed ? { removed: removalText(removed) } : {}),
          ...(removedFields.length > 0 ? { removedFields } : {}),
        },
      ];
    }),
  };
}

/** The catalog row for a name, matched as Salesforce matches API names. An exact spelling wins. */
function findByName<T>(rows: readonly T[], name: string, nameOf: (row: T) => string): T | undefined {
  return rows.find((row) => nameOf(row) === name) || rows.find((row) => nameOf(row).toLowerCase() === name.toLowerCase());
}

/**
 * Everything in a group that grants nothing on this server, or names something Salesforce no longer
 * has, in the group's own order. An object that is not available is reported once, not per field.
 * The group may be one as stored (see describableGroup).
 */
export function groupAvailabilityIssues(
  stored: Pick<AccessGroupSnapshot, 'allowedActions' | 'objectPermissions'>,
  objects: readonly SalesforceObject[]
): GroupAvailabilityIssue[] {
  const group = describableGroup(stored);
  const issues: GroupAvailabilityIssue[] = [];
  for (const id of group.allowedActions || []) {
    if (isKnownMcpAction(id)) continue;
    issues.push({
      kind: 'action',
      objectName: '',
      name: id,
      reason: 'unknown_action',
      status: 'unavailable',
      message: 'Not an MCP tool on this server, so it grants nothing.',
    });
  }

  for (const perm of group.objectPermissions || []) {
    const catalogObject = findByName(objects, perm.objectName, (o) => o.objectName);
    const objectIssue = (reason: GroupIssueReason, status: GroupAvailabilityIssue['status'], message: string) =>
      issues.push({ kind: 'object', objectName: perm.objectName, name: perm.objectName, reason, status, message });

    if (perm.removed) {
      objectIssue(
        'object_deleted',
        'unavailable',
        `Deleted from Salesforce > Objects${removalClause(perm.removed)}. It grants nothing until an admin restores it${
          catalogObject ? ', although the object is back in Salesforce > Objects' : ''
        }.`
      );
      continue;
    }
    if (!catalogObject) {
      objectIssue('object_not_in_catalog', 'unavailable', 'Not in Salesforce > Objects, so it grants nothing. Import or sync the object to use it.');
      continue;
    }
    if (!catalogObject.enabled) {
      objectIssue('object_disabled', 'unavailable', 'Disabled in Salesforce > Objects, so it grants nothing until it is enabled.');
      continue;
    }
    if (catalogObject.missingInOrg) {
      objectIssue('object_missing_in_org', 'broken', 'Missing from the Salesforce org (flagged by org sync). Still granted, but calls to it fail.');
    }

    const fieldIssue = (name: string, reason: GroupIssueReason, status: GroupAvailabilityIssue['status'], message: string) =>
      issues.push({ kind: 'field', objectName: perm.objectName, name, reason, status, message });
    for (const fieldName of perm.allowedFields || []) {
      const catalogField = findByName(catalogObject.fields, fieldName, (f) => f.fieldName);
      if (!catalogField) {
        fieldIssue(fieldName, 'field_not_in_catalog', 'unavailable', `Not a field of ${catalogObject.objectName} in Salesforce > Objects, so it grants nothing.`);
      } else if (!catalogField.enabled) {
        fieldIssue(fieldName, 'field_disabled', 'unavailable', 'Disabled in Salesforce > Objects, so it grants nothing until it is enabled.');
      } else if (catalogField.missingInOrg) {
        fieldIssue(fieldName, 'field_missing_in_org', 'broken', 'Missing from the Salesforce org (flagged by org sync). Still granted, but queries using it fail.');
      }
    }
    for (const held of perm.removedFields || []) {
      const isBack = Boolean(findByName(catalogObject.fields, held.fieldName, (f) => f.fieldName));
      fieldIssue(
        held.fieldName,
        'field_deleted',
        'unavailable',
        `Deleted from Salesforce > Objects${removalClause(held)}. It grants nothing until an admin restores it${
          isBack ? ', although the field is back in Salesforce > Objects' : ''
        }.`
      );
    }
  }
  return issues;
}

// ============================================================================
// Changes between two versions of a group, one line each, for history
// ============================================================================

const CRUD_LETTERS: Array<[keyof GroupObjectPermission, string]> = [
  ['canRead', 'R'],
  ['canCreate', 'C'],
  ['canUpdate', 'U'],
  ['canDelete', 'D'],
];

export function crudLetters(perm: GroupObjectPermission): string {
  const letters = CRUD_LETTERS.filter(([key]) => perm[key] === true).map(([, letter]) => letter);
  return letters.length > 0 ? letters.join('·') : 'no access';
}

function quoted(text: string): string {
  const clean = text.replace(/\s+/g, ' ').trim();
  return `"${clean.length > 80 ? `${clean.slice(0, 77)}…` : clean}"`;
}

const list = (names: string[]) => names.join(', ');
const lowerSet = (names: string[]) => new Set(names.map((n) => n.toLowerCase()));
const heldNames = (perm: GroupObjectPermission) => (perm.removedFields || []).map((f) => f.fieldName);

function describeNewObject(perm: GroupObjectPermission): string {
  const fields = perm.allowedFields.length > 0 ? ` with fields ${list(perm.allowedFields)}` : ' with no fields';
  const held = heldNames(perm);
  return (
    `${perm.objectName} (${crudLetters(perm)})${fields}` +
    (held.length > 0 ? `; held as deleted: ${list(held)}` : '') +
    (perm.removed ? '; the object is held as deleted from Salesforce > Objects' : '')
  );
}

function describeObjectChanges(before: GroupObjectPermission, after: GroupObjectPermission): string[] {
  const name = after.objectName;
  const lines: string[] = [];
  if (before.objectName !== after.objectName) lines.push(`${before.objectName} is now spelled ${after.objectName}.`);
  if (!before.removed && after.removed) lines.push(`${name} held as deleted from Salesforce > Objects: it grants nothing until restored.`);
  if (before.removed && !after.removed) lines.push(`${name} restored: it grants again while the object is in Salesforce > Objects.`);
  if (crudLetters(before) !== crudLetters(after)) lines.push(`${name} access changed from ${crudLetters(before)} to ${crudLetters(after)}.`);

  const allowedBefore = lowerSet(before.allowedFields);
  const allowedAfter = lowerSet(after.allowedFields);
  const heldBefore = lowerSet(heldNames(before));
  const heldAfter = lowerSet(heldNames(after));
  const added: string[] = [];
  const restored: string[] = [];
  const removed: string[] = [];
  const held: string[] = [];
  for (const field of after.allowedFields) {
    if (allowedBefore.has(field.toLowerCase())) continue;
    (heldBefore.has(field.toLowerCase()) ? restored : added).push(field);
  }
  for (const field of before.allowedFields) {
    if (allowedAfter.has(field.toLowerCase())) continue;
    (heldAfter.has(field.toLowerCase()) ? held : removed).push(field);
  }
  for (const field of heldNames(after)) {
    if (!heldBefore.has(field.toLowerCase()) && !allowedBefore.has(field.toLowerCase())) held.push(field);
  }
  for (const field of heldNames(before)) {
    if (!heldAfter.has(field.toLowerCase()) && !allowedAfter.has(field.toLowerCase())) removed.push(field);
  }
  if (added.length > 0) lines.push(`${name} fields added: ${list(added)}.`);
  if (restored.length > 0) lines.push(`${name} fields restored: ${list(restored)}.`);
  if (removed.length > 0) lines.push(`${name} fields removed: ${list(removed)}.`);
  if (held.length > 0) lines.push(`${name} fields held as deleted from Salesforce > Objects: ${list(held)}.`);
  return lines;
}

/**
 * The changes from `before` to `after`, one line each. With no `before`, the group was created and
 * every line describes what it was created with. Empty when nothing that grants access changed.
 * Either group may be one as stored (see describableGroup).
 */
export function describeGroupChanges(storedBefore: AccessGroupSnapshot | null, storedAfter: AccessGroupSnapshot): string[] {
  const before = storedBefore && describableGroup(storedBefore);
  const after = describableGroup(storedAfter);
  if (!before) {
    return [
      after.allowedActions.length > 0 ? `MCP actions: ${list(after.allowedActions)}.` : 'No MCP actions.',
      ...(after.objectPermissions.length > 0
        ? after.objectPermissions.map((perm) => `${describeNewObject(perm)}.`)
        : ['No objects.']),
    ];
  }

  const lines: string[] = [];
  if (before.name !== after.name) lines.push(`Renamed from ${quoted(before.name)} to ${quoted(after.name)}.`);
  if (before.description !== after.description) {
    lines.push(`Description changed from ${quoted(before.description || '(none)')} to ${quoted(after.description || '(none)')}.`);
  }

  const addedActions = after.allowedActions.filter((id) => !before.allowedActions.includes(id));
  const removedActions = before.allowedActions.filter((id) => !after.allowedActions.includes(id));
  if (addedActions.length > 0) lines.push(`Added MCP actions: ${list(addedActions)}.`);
  if (removedActions.length > 0) lines.push(`Removed MCP actions: ${list(removedActions)}.`);

  const beforeByName = new Map(before.objectPermissions.map((p) => [p.objectName.toLowerCase(), p]));
  const afterByName = new Map(after.objectPermissions.map((p) => [p.objectName.toLowerCase(), p]));
  for (const perm of after.objectPermissions) {
    const previous = beforeByName.get(perm.objectName.toLowerCase());
    if (!previous) lines.push(`Added ${describeNewObject(perm)}.`);
    else lines.push(...describeObjectChanges(previous, perm));
  }
  for (const perm of before.objectPermissions) {
    if (!afterByName.has(perm.objectName.toLowerCase())) lines.push(`Removed ${perm.objectName} (${crudLetters(perm)}) from the group.`);
  }
  return lines;
}
