import { AVAILABLE_MCP_ACTIONS } from '@/types/governance';
import type { AccessGroup, McpActionId, McpActionType } from '@/types/governance';

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
