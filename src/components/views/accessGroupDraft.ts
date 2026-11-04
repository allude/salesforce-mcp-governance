import { AVAILABLE_MCP_ACTIONS } from '@/types/governance';
import type {
  AccessGroup,
  AccessGroupChangeSource,
  CatalogRemoval,
  GroupObjectPermission,
  McpActionId,
  McpActionType,
  SalesforceObject,
} from '@/types/governance';
import { SALESFORCE_API_NAME_PATTERN } from '@/db/importers';
import type { AccessGroupDocument } from '@/groups/groupXml';
import { MCP_ACTION_ID_PATTERN } from '@/groups/groupGrants';
import {
  isHeldGrant,
  malformedGrantReason,
  mergeGrants,
  spellingLookup,
  uniqueIgnoringCase,
} from '@/rbac/groupGrants';

/** What a new group starts with: discovery and read tools, never anything that writes. */
export const DEFAULT_NEW_GROUP_ACTIONS: readonly McpActionId[] = [
  'list_enabled_objects',
  'describe_object',
  'soql_query',
  'get_record',
];

export function newAccessGroupDraft() {
  return {
    name: 'New Access Group',
    description: 'Describe what this group allows…',
    allowedActions: [...DEFAULT_NEW_GROUP_ACTIONS] as McpActionType[],
    objectPermissions: [],
  };
}

/**
 * The stored group behind a drawer, or null for a draft that has not been saved. Delete and profile
 * assignment need a real group ID, so they must not fall back to the draft's data.
 */
export function savedAccessGroup(
  groups: readonly AccessGroup[],
  id: string | undefined
): AccessGroup | null {
  return (id && groups.find((group) => group.id === id)) || null;
}

/**
 * Separates the IDs a group may name that are not tools on this server. The drawer has no switch for
 * those, so it lists them apart, as not available, for the admin to keep or remove.
 */
export function splitMcpActions(allowedActions: readonly McpActionType[]): {
  known: McpActionType[];
  unknown: McpActionType[];
} {
  const isKnown = (id: McpActionType) => AVAILABLE_MCP_ACTIONS.some((a) => a.id === id);
  return {
    known: allowedActions.filter(isKnown),
    unknown: allowedActions.filter((id) => !isKnown(id)),
  };
}

/**
 * The MCP action IDs a stored group's drawer starts from: each once, trimmed, as POST /groups stores
 * them. An ID this server has no tool for is kept (the drawer shows it as not available). Only what
 * POST /groups would refuse, a value that is not an MCP action ID (see MCP_ACTION_ID_PATTERN), is left
 * out and named in `dropped`: it grants nothing, and the admin is told that saving removes it.
 */
export function groupDraftActions(allowedActions: readonly unknown[]): {
  actions: McpActionType[];
  dropped: string[];
} {
  const actions: McpActionType[] = [];
  const dropped: string[] = [];
  for (const raw of allowedActions) {
    const id = typeof raw === 'string' ? raw.trim() : '';
    if (!MCP_ACTION_ID_PATTERN.test(id)) dropped.push(JSON.stringify(raw) ?? String(raw));
    else if (!actions.includes(id)) actions.push(id);
  }
  return { actions, dropped };
}

/** When and by whom something held was deleted, as text, whatever form the stored marker has. */
function removalOf(raw: unknown): CatalogRemoval {
  const source = raw && typeof raw === 'object' ? (raw as Record<string, unknown>) : {};
  const text = (value: unknown) => (typeof value === 'string' ? value : '');
  return { at: text(source.at), by: text(source.by) };
}

/**
 * The grants a stored group's drawer starts from, in the form POST /groups stores them, so the drawer
 * shows every entry the group has and saving it unedited changes nothing:
 * - Each Object and granted field is under the catalog's spelling when Salesforce > Objects has it,
 *   and as stored when it does not. Such an Object or field is kept, and the drawer shows it as not
 *   available.
 * - A held entry (`removed`: its Object was deleted from Salesforce > Objects) and held fields
 *   (`removedFields`) are kept as held. A held entry is never merged with another entry, since merged
 *   it would grant what it holds, and a field both granted and held stays held, as the server keeps it.
 * - The live entries for one Object (in any case) are merged into one, at the place of the first (see
 *   mergeGrants).
 * Only what POST /groups would refuse is left out and named in `dropped`: an entry the policy engine
 * cannot read (see malformedGrantReason) or one naming no Object, as `entry N`, and an Object or field
 * whose name is not a Salesforce API name, by that name. It grants nothing today, so the admin can
 * still save the group and is told that saving removes it. A blank field name and a held field naming
 * no field are left out too, unnamed: they name nothing, and grant or hold nothing.
 */
export function groupDraftGrants(
  objectPermissions: readonly unknown[],
  objects: readonly SalesforceObject[]
): { grants: GroupObjectPermission[]; dropped: string[] } {
  const objectSpelling = spellingLookup(objects.map((o) => o.objectName));
  const catalogFields = (objectName: string) =>
    objects.find((o) => o.objectName === objectName)?.fields.map((f) => f.fieldName) ?? [];
  const dropped: string[] = [];
  const grants: GroupObjectPermission[] = [];
  // The live entries of each Object, merged at the place of the first once all are read.
  const live = new Map<string, { index: number; entries: GroupObjectPermission[] }>();
  objectPermissions.forEach((entry, index) => {
    if (malformedGrantReason(entry) !== null || !(entry as GroupObjectPermission).objectName.trim()) {
      dropped.push(`entry ${index + 1}`);
      return;
    }
    const grant = entry as GroupObjectPermission;
    const typedObject = grant.objectName.trim();
    if (!SALESFORCE_API_NAME_PATTERN.test(typedObject)) {
      dropped.push(grant.objectName);
      return;
    }
    const objectName = objectSpelling(typedObject) ?? typedObject;
    const fieldSpelling = spellingLookup(catalogFields(objectName));
    // A field name POST /groups would refuse names no field, so it grants and holds nothing.
    const fieldName = (raw: string): string | null => {
      const typed = raw.trim();
      if (!typed) return null;
      if (SALESFORCE_API_NAME_PATTERN.test(typed)) return typed;
      dropped.push(`${objectName}.${raw}`);
      return null;
    };

    const removedFields: NonNullable<GroupObjectPermission['removedFields']> = [];
    for (const held of Array.isArray(grant.removedFields) ? grant.removedFields : []) {
      if (!held || typeof held !== 'object' || typeof held.fieldName !== 'string') continue;
      const typed = fieldName(held.fieldName);
      if (!typed || removedFields.some((f) => f.fieldName.toLowerCase() === typed.toLowerCase())) continue;
      removedFields.push({ fieldName: typed, ...removalOf(held) });
    }
    const heldNames = new Set(removedFields.map((f) => f.fieldName.toLowerCase()));
    const allowedFields = uniqueIgnoringCase(
      (grant.allowedFields ?? []).flatMap((field) => {
        const typed = fieldName(field);
        return typed ? [fieldSpelling(typed) ?? typed] : [];
      })
    ).filter((field) => !heldNames.has(field.toLowerCase()));

    const draft: GroupObjectPermission = {
      objectName,
      canRead: grant.canRead === true,
      canCreate: grant.canCreate === true,
      canUpdate: grant.canUpdate === true,
      canDelete: grant.canDelete === true,
      allowedFields,
      ...(isHeldGrant(grant) ? { removed: removalOf(grant.removed) } : {}),
      ...(removedFields.length > 0 ? { removedFields } : {}),
    };
    if (draft.removed) {
      grants.push(draft);
      return;
    }
    const key = objectName.toLowerCase();
    const slot = live.get(key);
    if (slot) {
      slot.entries.push(draft);
    } else {
      live.set(key, { index: grants.length, entries: [draft] });
      grants.push(draft);
    }
  });
  for (const { index, entries } of live.values()) {
    if (entries.length > 1) grants[index] = mergeGrants(entries, catalogFields)[0];
  }
  return { grants, dropped };
}

/**
 * A stored group, or a version of one from its history, in the form the drawer edits, loads and
 * exports it: its action IDs through groupDraftActions and its grants through groupDraftGrants. A
 * history version is kept as the group was stored, so an entry an older release stored that POST
 * /groups would refuse is left out here, and named in `dropped`.
 */
export function groupDraftContent(
  group: { name?: unknown; description?: unknown; allowedActions?: unknown; objectPermissions?: unknown },
  objects: readonly SalesforceObject[]
): {
  name: string;
  description: string;
  allowedActions: McpActionType[];
  objectPermissions: GroupObjectPermission[];
  dropped: { actions: string[]; grants: string[] };
} {
  const text = (value: unknown) => (typeof value === 'string' ? value : '');
  const actions = groupDraftActions(Array.isArray(group.allowedActions) ? group.allowedActions : []);
  const grants = groupDraftGrants(Array.isArray(group.objectPermissions) ? group.objectPermissions : [], objects);
  return {
    name: text(group.name),
    description: text(group.description),
    allowedActions: actions.actions,
    objectPermissions: grants.grants,
    dropped: { actions: actions.dropped, grants: grants.dropped },
  };
}

/** The groups and Objects of one read of the workspace (GET /api/admin/overview). */
export interface WorkspaceSnapshot {
  groups: AccessGroup[];
  objects: SalesforceObject[];
}

/**
 * What "Reload group" rebuilds the drawer's draft from after a save was refused (409): the group and
 * the Objects of one fresh read of the workspace, which agree with each other. Not the refused save's
 * group with the page's own Objects: those can be older than the group, so the drawer would show a
 * grant on an Object or field added since as not available, under the spelling it was stored in.
 */
export function reloadedGroup(
  conflict: AccessGroup,
  workspace: WorkspaceSnapshot | null
): { group: AccessGroup; objects: SalesforceObject[] } | { error: string } {
  if (!workspace) return { error: `Access Group "${conflict.name}" could not be reloaded. Try again.` };
  const group = workspace.groups.find((g) => g.id === conflict.id);
  if (!group) return { error: `Access Group "${conflict.name}" was deleted elsewhere, so there is nothing to reload.` };
  return { group, objects: workspace.objects };
}

/**
 * The group as the server has it now, when a save was refused because the group changed since the
 * drawer loaded it (409 with the current group); null for any other failure.
 */
export function staleGroupFromError(err: unknown): AccessGroup | null {
  const { status, body } = (err ?? {}) as { status?: unknown; body?: { group?: AccessGroup } };
  return status === 409 && body?.group && typeof body.group.version === 'number' ? body.group : null;
}

/** A group as the drawer edits it: a stored group, a new one, or one read from an XML file. */
export interface AccessGroupDraft {
  id?: string;
  /**
   * The version of the stored group the draft was loaded from (undefined for a new group). Saving
   * sends it as expectedVersion, whichever view or source the draft came from, so a group changed
   * elsewhere since is refused (409) instead of overwritten.
   */
  version?: number;
  name: string;
  description: string;
  allowedActions: McpActionType[];
  objectPermissions: GroupObjectPermission[];
}

/** Where a draft came from, when not from the switches: recorded as the source of its save. */
export interface AccessGroupDraftOrigin {
  source: 'xml_import' | 'version_restore';
  /** The file name, or which version was loaded. */
  detail: string;
}

export function draftSaveSource(
  origin: AccessGroupDraftOrigin | null,
  editedAsXml: boolean
): { source: AccessGroupChangeSource; sourceDetail: string } {
  if (origin) return { source: origin.source, sourceDetail: origin.detail };
  return { source: editedAsXml ? 'xml_editor' : 'editor', sourceDetail: '' };
}

/**
 * The stored group an imported file updates: the one it was exported from (same id), or else the one
 * with its name. Null when the file describes a new group.
 */
export function importTargetFor(
  groups: readonly AccessGroup[],
  doc: AccessGroupDocument
): { group: AccessGroup; matchedBy: 'id' | 'name' } | null {
  const byId = doc.id ? groups.find((g) => g.id === doc.id) : undefined;
  if (byId) return { group: byId, matchedBy: 'id' };
  const name = doc.name.trim().toLowerCase();
  const byName = groups.find((g) => g.name.trim().toLowerCase() === name);
  return byName ? { group: byName, matchedBy: 'name' } : null;
}

/** A name for saving an import as a new group, as group names must be unique. */
export function nameForImportedCopy(groups: readonly AccessGroup[], name: string): string {
  const taken = new Set(groups.map((g) => g.name.trim().toLowerCase()));
  const base = name.trim();
  if (!taken.has(base.toLowerCase())) return base;
  for (let n = 1; ; n++) {
    const candidate = n === 1 ? `${base} (imported)` : `${base} (imported ${n})`;
    if (!taken.has(candidate.toLowerCase())) return candidate;
  }
}

export function groupXmlFileName(name: string): string {
  const slug = name
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '');
  return `access-group-${slug || 'unnamed'}.xml`;
}

export function downloadTextFile(text: string, fileName: string, type = 'application/xml;charset=utf-8') {
  const blob = new Blob([text], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = fileName;
  a.click();
  URL.revokeObjectURL(url);
}

const sameName = (a: string, b: string) => a.toLowerCase() === b.toLowerCase();

function mapEntry(
  draft: AccessGroupDraft,
  objectName: string,
  change: (perm: GroupObjectPermission) => GroupObjectPermission
): AccessGroupDraft {
  return {
    ...draft,
    objectPermissions: draft.objectPermissions.map((p) => (sameName(p.objectName, objectName) ? change(p) : p)),
  };
}

/** Lets an entry held after its object was deleted grant again (once the object is in Salesforce > Objects). */
export function restoreHeldObject(draft: AccessGroupDraft, objectName: string): AccessGroupDraft {
  return mapEntry(draft, objectName, ({ removed: _removed, ...rest }) => rest);
}

/** Moves a field held after its deletion back into the granted fields. */
export function restoreHeldField(draft: AccessGroupDraft, objectName: string, fieldName: string): AccessGroupDraft {
  return mapEntry(draft, objectName, (perm) => {
    const held = (perm.removedFields || []).filter((f) => !sameName(f.fieldName, fieldName));
    const { removedFields: _held, ...rest } = perm;
    return {
      ...rest,
      allowedFields: perm.allowedFields.some((f) => sameName(f, fieldName))
        ? perm.allowedFields
        : [...perm.allowedFields, fieldName],
      ...(held.length > 0 ? { removedFields: held } : {}),
    };
  });
}

export function removeObjectEntry(draft: AccessGroupDraft, objectName: string): AccessGroupDraft {
  return { ...draft, objectPermissions: draft.objectPermissions.filter((p) => !sameName(p.objectName, objectName)) };
}

/** Drops a field from an entry, whether it is granted or held as deleted. */
export function removeEntryField(draft: AccessGroupDraft, objectName: string, fieldName: string): AccessGroupDraft {
  return mapEntry(draft, objectName, (perm) => {
    const held = (perm.removedFields || []).filter((f) => !sameName(f.fieldName, fieldName));
    const { removedFields: _held, ...rest } = perm;
    return {
      ...rest,
      allowedFields: perm.allowedFields.filter((f) => !sameName(f, fieldName)),
      ...(held.length > 0 ? { removedFields: held } : {}),
    };
  });
}

/**
 * Sets an entry's granted fields to every enabled field of the object (`all`) or none, keeping the
 * fields that are not available: those are only dropped one by one, so an admin sees each go.
 */
export function setAvailableFields(
  draft: AccessGroupDraft,
  object: SalesforceObject,
  all: boolean
): AccessGroupDraft {
  const enabled = object.fields.filter((f) => f.enabled).map((f) => f.fieldName);
  const enabledLower = new Set(enabled.map((f) => f.toLowerCase()));
  return mapEntry(draft, object.objectName, (perm) => ({
    ...perm,
    allowedFields: [...perm.allowedFields.filter((f) => !enabledLower.has(f.toLowerCase())), ...(all ? enabled : [])],
  }));
}
