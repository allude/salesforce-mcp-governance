import { store } from '../db/store.js';
import { VerifiedSalesforceUser, salesforceIdsMatch } from '../salesforce/client.js';
import { AVAILABLE_MCP_ACTIONS, GroupObjectPermission } from '../types/governance.js';

/** Thrown when a permitted tool call asks for fields or filters outside the caller's allowlist. */
export class PolicyViolationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PolicyViolationError';
  }
}

export interface EffectiveProfilePermissions {
  profileFound: boolean;
  profileId: string;
  profileName: string;
  assignedGroups: Array<{ id: string; name: string }>;
  allowedActions: Set<string>;
  objectPermissions: Map<
    string,
    {
      objectName: string;
      canRead: boolean;
      canCreate: boolean;
      canUpdate: boolean;
      canDelete: boolean;
      allowedFields: Set<string>;
      missingInOrgFields: Set<string>;
    }
  >;
}

/**
 * Resolves the effective permissions for a Salesforce Profile by combining all Groups
 * mapped to that Profile in `profile_group_memberships`, intersected with globally enabled
 * Objects and Fields in `sf_objects` / `sf_object_fields`.
 */
export function resolveEffectiveProfilePermissions(
  profileId: string,
  profileNameHint?: string
): EffectiveProfilePermissions {
  const profiles = store.getProfiles();
  const matchedProfile =
    profiles.find((p) => salesforceIdsMatch(p.id, profileId)) ||
    (profileNameHint
      ? profiles.find((p) => p.name.toLowerCase() === profileNameHint.toLowerCase())
      : undefined);

  if (!matchedProfile) {
    return {
      profileFound: false,
      profileId,
      profileName: profileNameHint || profileId,
      assignedGroups: [],
      allowedActions: new Set(),
      objectPermissions: new Map(),
    };
  }

  const mappings = store.getProfileGroupMappings();
  const profileMapping = mappings.find((m) => m.profileId === matchedProfile.id);
  const groupIds = new Set(profileMapping?.groupIds || []);

  const allGroups = store.getGroups();
  const assignedGroups = allGroups.filter((g) => groupIds.has(g.id));

  const enabledObjectsMap = new Map(
    store
      .getObjects()
      .filter((o) => o.enabled)
      .map((o) => {
        const canonicalFieldMap = new Map<string, string>();
        const missingInOrgFields = new Set<string>();
        for (const f of o.fields) {
          if (f.enabled) {
            canonicalFieldMap.set(f.fieldName.toLowerCase(), f.fieldName);
            if (f.missingInOrg) {
              missingInOrgFields.add(f.fieldName);
            }
          }
        }
        return [
          o.objectName.toLowerCase(),
          {
            objectName: o.objectName,
            canonicalFieldMap,
            missingInOrgFields,
          },
        ];
      })
  );

  const allowedActions = new Set<string>();
  const objectPermissions = new Map<
    string,
    {
      objectName: string;
      canRead: boolean;
      canCreate: boolean;
      canUpdate: boolean;
      canDelete: boolean;
      allowedFields: Set<string>;
      missingInOrgFields: Set<string>;
    }
  >();

  for (const grp of assignedGroups) {
    if (!Array.isArray(grp.allowedActions)) continue;
    for (const act of grp.allowedActions) {
      allowedActions.add(act);
    }

    if (!Array.isArray(grp.objectPermissions)) continue;
    for (const objPerm of grp.objectPermissions) {
      if (!objPerm || !objPerm.objectName) continue;
      // An entry that grants no CRUD access grants nothing, including its field list. Without this,
      // its fields would be merged only when another group had already granted the object, so the
      // result would depend on the groups' (alphabetical) processing order.
      if (!(objPerm.canRead || objPerm.canCreate || objPerm.canUpdate || objPerm.canDelete)) continue;

      const globalObj = enabledObjectsMap.get(objPerm.objectName.toLowerCase());
      if (!globalObj) continue; // Object is disabled or removed in Salesforce -> Objects

      const existing = objectPermissions.get(globalObj.objectName) || {
        objectName: globalObj.objectName,
        canRead: false,
        canCreate: false,
        canUpdate: false,
        canDelete: false,
        allowedFields: new Set<string>(),
        missingInOrgFields: globalObj.missingInOrgFields,
      };

      existing.canRead = existing.canRead || Boolean(objPerm.canRead);
      existing.canCreate = existing.canCreate || Boolean(objPerm.canCreate);
      existing.canUpdate = existing.canUpdate || Boolean(objPerm.canUpdate);
      existing.canDelete = existing.canDelete || Boolean(objPerm.canDelete);

      for (const f of objPerm.allowedFields || []) {
        if (!f) continue;
        const canonical = globalObj.canonicalFieldMap.get(f.toLowerCase());
        if (canonical) {
          existing.allowedFields.add(canonical);
        }
      }

      // Ensure that if all configured fields were removed/disabled, Id remains safe as fallback when enabled
      if (
        existing.allowedFields.size === 0 &&
        (existing.canRead || existing.canCreate || existing.canUpdate) &&
        globalObj.canonicalFieldMap.has('id')
      ) {
        existing.allowedFields.add(globalObj.canonicalFieldMap.get('id')!);
      }

      if (
        existing.canRead ||
        existing.canCreate ||
        existing.canUpdate ||
        existing.canDelete
      ) {
        objectPermissions.set(globalObj.objectName, existing);
      }
    }
  }

  return {
    profileFound: true,
    profileId: matchedProfile.id,
    profileName: matchedProfile.name,
    assignedGroups: assignedGroups.map((g) => ({ id: g.id, name: g.name })),
    allowedActions,
    objectPermissions,
  };
}

export interface PolicyEvaluationResult {
  permitted: boolean;
  reason: string;
  matchedGroups: string[];
  allowedFields: string[];
  /** Canonical API name of the permitted target object (set when an object-scoped call is permitted). */
  objectName?: string;
}

// Tools that operate on one Salesforce object and must name it via `objectName`.
const OBJECT_SCOPED_TOOLS = new Set([
  'describe_object',
  'soql_query',
  'get_record',
  'create_record',
  'update_record',
  'delete_record',
]);

export function evaluateMcpToolCall(
  user: VerifiedSalesforceUser,
  toolName: string,
  targetObject?: string
): PolicyEvaluationResult {
  const effective = resolveEffectiveProfilePermissions(
    user.profileId,
    user.profileName
  );
  const groupNames = effective.assignedGroups.map((g) => g.name);

  if (!AVAILABLE_MCP_ACTIONS.some((a) => a.id === toolName)) {
    return {
      permitted: false,
      reason: `Unknown MCP tool '${toolName}'.`,
      matchedGroups: groupNames,
      allowedFields: [],
    };
  }

  if (!effective.profileFound) {
    return {
      permitted: false,
      reason: user.profileId
        ? `Profile '${user.profileId}' (${user.profileName}) is not registered in Salesforce > Profiles.`
        : "The caller's Salesforce Profile could not be determined (the User/Profile lookup failed), so no MCP action is permitted.",
      matchedGroups: [],
      allowedFields: [],
    };
  }

  if (effective.assignedGroups.length === 0) {
    return {
      permitted: false,
      reason: `Profile '${effective.profileName}' (${effective.profileId}) has no Groups assigned in the Profile Group Matrix.`,
      matchedGroups: [],
      allowedFields: [],
    };
  }

  if (!effective.allowedActions.has(toolName)) {
    return {
      permitted: false,
      reason: `MCP Action '${toolName}' is not granted by any Group assigned to Profile '${effective.profileName}' (Groups: ${groupNames.join(', ')}).`,
      matchedGroups: groupNames,
      allowedFields: [],
    };
  }

  const hasTargetObject = Boolean(targetObject && targetObject !== '*');
  if (OBJECT_SCOPED_TOOLS.has(toolName) && !hasTargetObject) {
    return {
      permitted: false,
      reason: `MCP Action '${toolName}' requires an objectName argument.`,
      matchedGroups: groupNames,
      allowedFields: [],
    };
  }

  if (targetObject && hasTargetObject) {
    const objPerm = Array.from(effective.objectPermissions.values()).find(
      (o) => o.objectName.toLowerCase() === targetObject.toLowerCase()
    );
    if (!objPerm) {
      return {
        permitted: false,
        reason: `Object '${targetObject}' is either disabled in Salesforce > Objects or not permitted by Groups [${groupNames.join(', ')}].`,
        matchedGroups: groupNames,
        allowedFields: [],
      };
    }

    if (
      (toolName === 'soql_query' ||
        toolName === 'get_record' ||
        toolName === 'describe_object') &&
      !objPerm.canRead
    ) {
      return {
        permitted: false,
        reason: `Read access to '${targetObject}' is not granted in Groups [${groupNames.join(', ')}].`,
        matchedGroups: groupNames,
        allowedFields: [],
      };
    }

    if (toolName === 'create_record' && !objPerm.canCreate) {
      return {
        permitted: false,
        reason: `Create access to '${targetObject}' is not granted in Groups [${groupNames.join(', ')}].`,
        matchedGroups: groupNames,
        allowedFields: [],
      };
    }

    if (toolName === 'update_record' && !objPerm.canUpdate) {
      return {
        permitted: false,
        reason: `Update access to '${targetObject}' is not granted in Groups [${groupNames.join(', ')}].`,
        matchedGroups: groupNames,
        allowedFields: [],
      };
    }

    if (toolName === 'delete_record' && !objPerm.canDelete) {
      return {
        permitted: false,
        reason: `Delete access to '${targetObject}' is not granted in Groups [${groupNames.join(', ')}].`,
        matchedGroups: groupNames,
        allowedFields: [],
      };
    }

    return {
      permitted: true,
      reason: `Permitted via Groups [${groupNames.join(', ')}]`,
      matchedGroups: groupNames,
      allowedFields: Array.from(objPerm.allowedFields),
      objectName: objPerm.objectName,
    };
  }

  return {
    permitted: true,
    reason: `Permitted via Groups [${groupNames.join(', ')}]`,
    matchedGroups: groupNames,
    allowedFields: [],
  };
}

export function getVisibleToolsForUser(user: VerifiedSalesforceUser) {
  const effective = resolveEffectiveProfilePermissions(
    user.profileId,
    user.profileName
  );
  return AVAILABLE_MCP_ACTIONS.filter((a) => effective.allowedActions.has(a.id));
}
