import { AVAILABLE_MCP_ACTIONS } from '@/types/governance';
import type {
  AccessGroup,
  AccessGroupChangeSource,
  GroupObjectPermission,
  McpActionId,
  McpActionType,
  SalesforceObject,
} from '@/types/governance';
import type { AccessGroupDocument } from '@/groups/groupXml';

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

/** A group as the drawer edits it: a stored group, a new one, or one read from an XML file. */
export interface AccessGroupDraft {
  id?: string;
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
