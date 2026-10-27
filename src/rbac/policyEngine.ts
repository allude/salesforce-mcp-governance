import { store } from '../db/store.js';
import { VerifiedSalesforceUser } from '../salesforce/client.js';
import { AVAILABLE_MCP_ACTIONS, GroupObjectPermission } from '../types/governance.js';

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
    profiles.find((p) => p.id === profileId) ||
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
      .map((o) => [
        o.objectName.toLowerCase(),
        {
          objectName: o.objectName,
          enabledFields: new Set(
            o.fields.filter((f) => f.enabled).map((f) => f.fieldName)
          ),
        },
      ])
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
    }
  >();

  for (const grp of assignedGroups) {
    for (const act of grp.allowedActions) {
      allowedActions.add(act);
    }

    for (const objPerm of grp.objectPermissions) {
      const globalObj = enabledObjectsMap.get(objPerm.objectName.toLowerCase());
      if (!globalObj) continue; // Object is disabled in Salesforce -> Objects

      const existing = objectPermissions.get(globalObj.objectName) || {
        objectName: globalObj.objectName,
        canRead: false,
        canCreate: false,
        canUpdate: false,
        canDelete: false,
        allowedFields: new Set<string>(),
      };

      existing.canRead = existing.canRead || objPerm.canRead;
      existing.canCreate = existing.canCreate || objPerm.canCreate;
      existing.canUpdate = existing.canUpdate || objPerm.canUpdate;
      existing.canDelete = existing.canDelete || objPerm.canDelete;

      for (const f of objPerm.allowedFields) {
        if (globalObj.enabledFields.has(f)) {
          existing.allowedFields.add(f);
        }
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
}

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

  if (!effective.profileFound) {
    return {
      permitted: false,
      reason: `Profile '${user.profileId}' (${user.profileName}) is not registered in Salesforce > Profiles.`,
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

  if (targetObject && targetObject !== '*') {
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
