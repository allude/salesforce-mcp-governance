import { AVAILABLE_MCP_ACTIONS } from '@/types/governance';
import type {
  AccessGroup,
  GroupObjectPermission,
  McpActionId,
  McpActionType,
  SalesforceObject,
} from '@/types/governance';
import { malformedGrantReason, mergeGrants, spellingLookup, uniqueIgnoringCase } from '@/rbac/groupGrants';

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
 * Separates the IDs a stored group may name that are not real tools. The drawer has no switch for
 * those, so without this the admin could neither see them nor save past the server's rejection.
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
 * The grants a stored group's drawer starts from, in the form POST /groups accepts: each Object and
 * field under the catalog's spelling and the entries for one Object merged, so the drawer shows every
 * grant the group has. What the server would refuse grants nothing today (an entry the policy engine
 * skips, an Object or field not in Salesforce > Objects); it is left out and named in `dropped`, so the
 * admin can still save the group and is told that saving removes it.
 */
export function groupDraftGrants(
  objectPermissions: readonly unknown[],
  objects: readonly SalesforceObject[]
): { grants: GroupObjectPermission[]; dropped: string[] } {
  const objectSpelling = spellingLookup(objects.map((o) => o.objectName));
  const dropped: string[] = [];
  const grants: GroupObjectPermission[] = [];
  objectPermissions.forEach((entry, index) => {
    if (malformedGrantReason(entry) !== null) {
      dropped.push(`entry ${index + 1}`);
      return;
    }
    const grant = entry as GroupObjectPermission;
    const objectName = grant.objectName ? objectSpelling(grant.objectName) : null;
    if (!objectName) {
      dropped.push(grant.objectName || `entry ${index + 1}`);
      return;
    }
    const fieldSpelling = spellingLookup(
      objects.find((o) => o.objectName === objectName)?.fields.map((f) => f.fieldName) ?? []
    );
    const allowedFields: string[] = [];
    for (const field of grant.allowedFields ?? []) {
      const fieldName = fieldSpelling(field);
      if (fieldName) allowedFields.push(fieldName);
      else dropped.push(`${objectName}.${field}`);
    }
    grants.push({
      objectName,
      canRead: grant.canRead === true,
      canCreate: grant.canCreate === true,
      canUpdate: grant.canUpdate === true,
      canDelete: grant.canDelete === true,
      allowedFields: uniqueIgnoringCase(allowedFields),
    });
  });
  const catalogFields = (objectName: string) =>
    objects.find((o) => o.objectName === objectName)?.fields.map((f) => f.fieldName) ?? [];
  return { grants: mergeGrants(grants, catalogFields), dropped };
}

/** The groups and Objects of one read of the workspace (GET /api/admin/overview). */
export interface WorkspaceSnapshot {
  groups: AccessGroup[];
  objects: SalesforceObject[];
}

/**
 * What "Reload group" rebuilds the drawer's draft from after a save was refused (409): the group and
 * the Objects of one fresh read of the workspace, which agree with each other. Not the refused save's
 * group with the page's own Objects: those can be older than the group, so groupDraftGrants would drop
 * a grant on an Object or field added since, and saving the draft would revoke it.
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
