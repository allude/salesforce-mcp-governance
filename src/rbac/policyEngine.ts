import { store } from '../db/store.js';
import type { VerifiedSalesforceUser } from '../salesforce/client.js';
import { salesforceIdsMatch } from '../salesforce/ids.js';
import { checkSoqlWhereClause, type WhereClauseCheck } from '../mcp/soqlGuard.js';
import {
  API_NAME_PATTERN,
  FIELD_VALUES_MESSAGE,
  RECORD_ID_MESSAGE,
  fieldValuesArgument,
  recordIdArgument,
  selectedFieldNames,
  targetObjectArgument,
  whereClauseArgument,
  type ToolArguments,
} from '../mcp/toolArguments.js';
import {
  AVAILABLE_MCP_ACTIONS,
  type AccessGroup,
  type GroupObjectPermission,
  type McpActionId,
  type ProfileGroupMapping,
  type SalesforceObject,
  type SalesforceProfile,
} from '../types/governance.js';
import { enabledObjectsByLowerName, GRANT_FLAGS, grantsAccess, malformedGrantReason } from './groupGrants.js';

export { PolicyViolationError } from './policyViolation.js';

/** A stored object entry of a group that the engine skipped whole, because it cannot be read as a grant. */
export interface SkippedGroupEntry {
  groupId: string;
  /** The entry's position in the group's objectPermissions. */
  index: number;
  /** Which key is wrong, never its value, e.g. 'canRead is not true or false'. */
  reason: string;
}

const warnedSkippedEntries = new Set<string>();

/** Tells the operator once per group, entry and reason. The log names the key, never the stored value. */
function warnSkippedEntry({ groupId, index, reason }: SkippedGroupEntry): void {
  const key = `${groupId}\u0000${index}\u0000${reason}`;
  if (warnedSkippedEntries.has(key)) return;
  warnedSkippedEntries.add(key);
  console.warn(
    `[policy] Access Group ${groupId}: object entry ${index} is skipped and grants nothing (${reason}). Open the group in the portal and save it to remove the entry.`
  );
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
  /** Present only when a stored entry of an assigned group was skipped (see SkippedGroupEntry). */
  skippedGroupEntries?: SkippedGroupEntry[];
}

// ---------------------------------------------------------------------------
// Policy snapshot: everything a decision is made from, read once per call
// ---------------------------------------------------------------------------

/** The policy as stored: what evaluatePolicy decides from. It reads nothing else. */
export interface PolicySnapshot {
  /** store.getPolicyRevision() when the snapshot was read. */
  policyRevision: number;
  /** Salesforce > Profiles. */
  profiles: SalesforceProfile[];
  /** The Access Groups. */
  groups: AccessGroup[];
  /** The Profile -> Group mappings. */
  mappings: ProfileGroupMapping[];
  /** Salesforce > Objects, with each Object's and field's enabled flag and missing-in-org flags. */
  objects: SalesforceObject[];
}

/** Reads the policy from the store. Callers read it once per call and decide everything from it. */
export function loadPolicySnapshot(): PolicySnapshot {
  // Read in one synchronous run, so no change lands between the revision and the rows it counts.
  return {
    policyRevision: store.getPolicyRevision(),
    profiles: store.getProfiles(),
    groups: store.getGroups(),
    mappings: store.getProfileGroupMappings(),
    objects: store.getObjects(),
  };
}

// ---------------------------------------------------------------------------
// The merge: a Profile's groups combined, with which group granted what
// ---------------------------------------------------------------------------

export type ProfileMatchMethod = 'id' | 'name' | 'none';

type GrantFlag = (typeof GRANT_FLAGS)[number];

/** Which assigned groups granted an Object, each CRUD operation on it, and each of its fields. */
interface ObjectProvenance {
  /** The groups with an entry that grants the Object. */
  groupIds: Set<string>;
  flags: Record<GrantFlag, Set<string>>;
  /** Keyed by the field's catalog spelling, the Id fallback included. */
  fields: Map<string, Set<string>>;
}

interface MergedPolicy {
  effective: EffectiveProfilePermissions;
  matchedProfileId: string | null;
  matchMethod: ProfileMatchMethod;
  /** Tool id -> the groups granting it. */
  toolGrants: Map<string, Set<string>>;
  /** Keyed by the Object's catalog spelling, as effective.objectPermissions is. */
  objectGrants: Map<string, ObjectProvenance>;
  /** Lower-cased names of the Objects an assigned group's entry grants, enabled globally or not. */
  entryGrantedObjects: Set<string>;
}

function addGrant<K>(map: Map<K, Set<string>>, key: K, groupId: string): void {
  const groupIds = map.get(key) ?? new Set<string>();
  groupIds.add(groupId);
  map.set(key, groupIds);
}

/**
 * Combines all Groups mapped to the Profile (or, with overrides.assignedGroupIds, those groups
 * instead), intersected with the Objects and Fields enabled globally. resolveEffectiveProfilePermissions
 * and evaluatePolicy both read this one merge, so they can never disagree.
 */
function mergeAssignedGroups(
  snapshot: PolicySnapshot,
  profileId: string,
  profileNameHint: string | undefined,
  overrides?: PolicyOverrides
): MergedPolicy {
  const profiles = snapshot.profiles;
  const matchedById = profiles.find((p) => salesforceIdsMatch(p.id, profileId));
  const matchedProfile =
    matchedById ||
    (profileNameHint
      ? profiles.find((p) => p.name.toLowerCase() === profileNameHint.toLowerCase())
      : undefined);

  const toolGrants = new Map<string, Set<string>>();
  const objectGrants = new Map<string, ObjectProvenance>();
  const entryGrantedObjects = new Set<string>();

  if (!matchedProfile) {
    return {
      effective: {
        profileFound: false,
        profileId,
        profileName: profileNameHint || profileId,
        assignedGroups: [],
        allowedActions: new Set(),
        objectPermissions: new Map(),
      },
      matchedProfileId: null,
      matchMethod: 'none',
      toolGrants,
      objectGrants,
      entryGrantedObjects,
    };
  }

  const profileMapping = snapshot.mappings.find((m) => m.profileId === matchedProfile.id);
  const groupIds = new Set(overrides?.assignedGroupIds ?? profileMapping?.groupIds ?? []);

  const assignedGroups = snapshot.groups.filter((g) => groupIds.has(g.id));

  const enabledObjectsMap = new Map(
    Array.from(enabledObjectsByLowerName(snapshot.objects), ([lowerName, o]) => {
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
        lowerName,
        {
          objectName: o.objectName,
          canonicalFieldMap,
          missingInOrgFields,
        },
      ] as const;
    })
  );

  const allowedActions = new Set<string>();
  const objectPermissions: EffectiveProfilePermissions['objectPermissions'] = new Map();

  const skippedGroupEntries: SkippedGroupEntry[] = [];

  for (const grp of assignedGroups) {
    if (!Array.isArray(grp.allowedActions)) continue;
    for (const act of grp.allowedActions) {
      allowedActions.add(act);
      addGrant(toolGrants, act, grp.id);
    }

    if (!Array.isArray(grp.objectPermissions)) continue;
    for (const [index, entry] of (grp.objectPermissions as unknown[]).entries()) {
      // POST /groups stores only well-formed entries, but an older version stored them as sent. One
      // this cannot read is skipped whole (fail closed), never half-applied and never thrown on.
      const reason = malformedGrantReason(entry);
      if (reason) {
        const skipped = { groupId: grp.id, index, reason };
        skippedGroupEntries.push(skipped);
        warnSkippedEntry(skipped);
        continue;
      }
      const objPerm = entry as GroupObjectPermission;
      if (!objPerm.objectName) continue;
      // An entry that grants no CRUD access grants nothing, including its field list. Without this,
      // its fields would be merged only when another group had already granted the object, so the
      // result would depend on the groups' (alphabetical) processing order. A flag grants only when
      // it is exactly true.
      if (!grantsAccess(objPerm)) continue;
      entryGrantedObjects.add(objPerm.objectName.toLowerCase());

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
      const provenance = objectGrants.get(globalObj.objectName) || {
        groupIds: new Set<string>(),
        flags: { canRead: new Set(), canCreate: new Set(), canUpdate: new Set(), canDelete: new Set() },
        fields: new Map<string, Set<string>>(),
      };
      objectGrants.set(globalObj.objectName, provenance);
      provenance.groupIds.add(grp.id);

      existing.canRead = existing.canRead || objPerm.canRead === true;
      existing.canCreate = existing.canCreate || objPerm.canCreate === true;
      existing.canUpdate = existing.canUpdate || objPerm.canUpdate === true;
      existing.canDelete = existing.canDelete || objPerm.canDelete === true;
      for (const flag of GRANT_FLAGS) {
        if (objPerm[flag] === true) provenance.flags[flag].add(grp.id);
      }

      let resolvedAnyField = false;
      for (const f of objPerm.allowedFields || []) {
        if (!f) continue;
        const canonical = globalObj.canonicalFieldMap.get(f.toLowerCase());
        if (canonical) {
          existing.allowedFields.add(canonical);
          addGrant(provenance.fields, canonical, grp.id);
          resolvedAnyField = true;
        }
      }

      // An entry whose configured fields were all removed/disabled still grants Id when Id is enabled.
      // This is decided per entry, not on the fields merged so far, so that it never depends on the
      // groups' (alphabetical) processing order.
      if (
        !resolvedAnyField &&
        (objPerm.canRead === true || objPerm.canCreate === true || objPerm.canUpdate === true) &&
        globalObj.canonicalFieldMap.has('id')
      ) {
        const idField = globalObj.canonicalFieldMap.get('id')!;
        existing.allowedFields.add(idField);
        addGrant(provenance.fields, idField, grp.id);
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
    effective: {
      profileFound: true,
      profileId: matchedProfile.id,
      profileName: matchedProfile.name,
      assignedGroups: assignedGroups.map((g) => ({ id: g.id, name: g.name })),
      allowedActions,
      objectPermissions,
      ...(skippedGroupEntries.length > 0 ? { skippedGroupEntries } : {}),
    },
    matchedProfileId: matchedProfile.id,
    matchMethod: matchedById ? 'id' : 'name',
    toolGrants,
    objectGrants,
    entryGrantedObjects,
  };
}

/**
 * Resolves the effective permissions for a Salesforce Profile by combining all Groups
 * mapped to that Profile in `profile_group_memberships`, intersected with globally enabled
 * Objects and Fields in `sf_objects` / `sf_object_fields`. Pass the call's snapshot to decide from
 * the same policy as its decision; without one, the policy is read from the store.
 */
export function resolveEffectiveProfilePermissions(
  profileId: string,
  profileNameHint?: string,
  snapshot: PolicySnapshot = loadPolicySnapshot()
): EffectiveProfilePermissions {
  return mergeAssignedGroups(snapshot, profileId, profileNameHint).effective;
}

// ---------------------------------------------------------------------------
// The decision
// ---------------------------------------------------------------------------

export type PolicyOutcome = 'allowed' | 'denied' | 'invalid' | 'error';

export const POLICY_DECISION_CODES = [
  'ALLOWED',
  'TOOL_UNKNOWN',
  'PROFILE_UNREGISTERED',
  'NO_GROUPS',
  'TOOL_NOT_GRANTED',
  'OBJECT_NOT_GRANTED',
  'OBJECT_BLOCKED',
  'CRUD_MISSING',
  'FIELD_NOT_PERMITTED',
  'WHERE_FIELD_NOT_PERMITTED',
  /** Reserved for row filters (Step 3); no decision carries it yet. */
  'ROW_FILTER',
  'INPUT_INVALID',
  'INTERNAL_ERROR',
] as const;
export type PolicyDecisionCode = (typeof POLICY_DECISION_CODES)[number];

/**
 * The stages in the order they run. 'input' is not a place of its own: an argument is checked where
 * the tool handlers always checked it (a missing objectName before 'object', one that is not an API
 * name in 'object', the record id, the field values and the field names after 'crud', the WHERE
 * syntax inside 'where'), and a failed check is recorded there as a failed 'input' step. When every
 * check passes, evaluatePolicy records one 'input' pass last; evaluateToolAccess, which checks no
 * argument, records none.
 */
export const POLICY_STAGES = [
  'tool',
  'identity',
  'groups',
  'tool_grant',
  'object',
  'crud',
  'fields',
  'where',
  'input',
] as const;
export type PolicyStage = (typeof POLICY_STAGES)[number];

export interface PolicyStep {
  stage: PolicyStage;
  result: 'pass' | 'fail';
  /**
   * The assigned groups that grant what the step checked, in assignedGroups order: the tool
   * (tool_grant), the Object (object), the operation (crud), the fields named (fields, where). [] for
   * the other stages and for a failed step, which nothing granted.
   */
  grantingGroupIds: string[];
  /** The Object the step is about: its catalog spelling once found, as the caller named it before. */
  objectName: string | null;
  /** The field names involved: those requested on a pass, those refused on a fail. */
  fieldNames: string[];
  /** The row-filter rule that decided the step (Step 3); null for now. */
  ruleId: string | null;
}

export interface PolicyDecision {
  outcome: PolicyOutcome;
  code: PolicyDecisionCode;
  /** The reason the caller is given. */
  reason: string;
  /** The Object's catalog spelling, for an allowed call of an object-scoped tool; otherwise null. */
  objectName: string | null;
  /** The caller's allowed fields on that Object, for an allowed object-scoped call; otherwise []. */
  allowedFields: string[];
  /** One step per stage reached, in order; nothing after the step that failed. */
  steps: PolicyStep[];
  /** Every group assigned to the caller's Profile (or given as overrides), in name order. */
  assignedGroups: Array<{ id: string; name: string }>;
  /** For an allowed call, the groups that granted it (tool_grant, object, crud, fields); otherwise []. */
  decidingGroupIds: string[];
  identity: {
    callerProfileId: string;
    matchedProfileId: string | null;
    matchMethod: ProfileMatchMethod;
  };
  policyRevision: number;
  /** Present only when a stored entry of the caller's groups was skipped. */
  skippedGroupEntries?: SkippedGroupEntry[];
}

/** The verified caller, as token verification gives it. */
export type PolicySubject = Pick<VerifiedSalesforceUser, 'profileId' | 'profileName' | 'username'>;

/** What-if changes to the stored policy for one evaluation (the simulator). */
export interface PolicyOverrides {
  /** Evaluate with these groups instead of those mapped to the Profile. Unknown ids grant nothing. */
  assignedGroupIds?: string[];
}

const INTERNAL_ERROR_REASON = 'The access policy could not be evaluated, so the call is refused.';

// Every catalog tool but list_enabled_objects works on one Salesforce object, named by `objectName`,
// and needs one CRUD flag on it. A tool added to the catalog must be placed here or the build fails.
const OBJECT_TOOL_CRUD: Record<Exclude<McpActionId, 'list_enabled_objects'>, { flag: GrantFlag; label: string }> = {
  describe_object: { flag: 'canRead', label: 'Read' },
  soql_query: { flag: 'canRead', label: 'Read' },
  get_record: { flag: 'canRead', label: 'Read' },
  create_record: { flag: 'canCreate', label: 'Create' },
  update_record: { flag: 'canUpdate', label: 'Update' },
  delete_record: { flag: 'canDelete', label: 'Delete' },
};

function objectToolCrud(toolName: string): { flag: GrantFlag; label: string } | undefined {
  return Object.hasOwn(OBJECT_TOOL_CRUD, toolName)
    ? OBJECT_TOOL_CRUD[toolName as keyof typeof OBJECT_TOOL_CRUD]
    : undefined;
}

const DECIDING_STAGES = new Set<PolicyStage>(['tool_grant', 'object', 'crud', 'fields']);

/**
 * Reads one of the caller's arguments. A value JSON allows can still make reading it throw: String() of
 * an object whose toString is not a function. That is malformed input, not an engine failure, so its
 * message is returned for an invalid decision; it is the text the handler that read it gave before.
 */
function readArgument<T>(reader: () => T): { ok: true; value: T } | { ok: false; message: string } {
  try {
    return { ok: true, value: reader() };
  } catch (err) {
    return { ok: false, message: err instanceof Error ? err.message : 'The arguments could not be read.' };
  }
}

/**
 * Decides a tools/call from the snapshot alone: every stage from the tool to the WHERE clause, with
 * the call's arguments. Pure: it reads nothing from the store, and it never throws. A failure inside
 * the evaluation itself is an 'error' decision, which allows nothing.
 */
export function evaluatePolicy(
  subject: PolicySubject,
  toolName: string,
  args: ToolArguments,
  snapshot: PolicySnapshot,
  overrides?: PolicyOverrides
): PolicyDecision {
  return runPipeline(subject, toolName, args, snapshot, overrides, true);
}

/**
 * evaluatePolicy for the tool and the Object only (stages tool to crud), for a check made without
 * the call's arguments: evaluateMcpToolCall, and the simulator without a sample payload. An allowed
 * decision here says nothing about fields, filters or argument shapes.
 */
export function evaluateToolAccess(
  subject: PolicySubject,
  toolName: string,
  targetObject: string | undefined,
  snapshot: PolicySnapshot,
  overrides?: PolicyOverrides
): PolicyDecision {
  const args = targetObject === undefined ? {} : { objectName: targetObject };
  return runPipeline(subject, toolName, args, snapshot, overrides, false);
}

function runPipeline(
  subject: PolicySubject,
  toolName: string,
  args: ToolArguments,
  snapshot: PolicySnapshot,
  overrides: PolicyOverrides | undefined,
  checkArguments: boolean
): PolicyDecision {
  const steps: PolicyStep[] = [];
  let merged: MergedPolicy | undefined;
  try {
    merged = mergeAssignedGroups(snapshot, subject.profileId, subject.profileName, overrides);
    return decide(merged, subject, toolName, args, snapshot.policyRevision, steps, checkArguments);
  } catch (err) {
    // Fail closed. The error is the engine's own (bad snapshot data or a bug), never the caller's input.
    console.error('[policy] Policy evaluation failed, so the call is refused:', err);
    const skipped = merged?.effective.skippedGroupEntries;
    return {
      outcome: 'error',
      code: 'INTERNAL_ERROR',
      reason: INTERNAL_ERROR_REASON,
      objectName: null,
      allowedFields: [],
      steps,
      assignedGroups: merged?.effective.assignedGroups ?? [],
      decidingGroupIds: [],
      identity: {
        callerProfileId: typeof subject?.profileId === 'string' ? subject.profileId : '',
        matchedProfileId: merged?.matchedProfileId ?? null,
        matchMethod: merged?.matchMethod ?? 'none',
      },
      policyRevision: typeof snapshot?.policyRevision === 'number' ? snapshot.policyRevision : 0,
      ...(skipped ? { skippedGroupEntries: skipped } : {}),
    };
  }
}

function decide(
  merged: MergedPolicy,
  subject: PolicySubject,
  toolName: string,
  args: ToolArguments,
  policyRevision: number,
  steps: PolicyStep[],
  checkArguments: boolean
): PolicyDecision {
  const { effective } = merged;
  const assignedGroups = effective.assignedGroups;
  const groupNames = assignedGroups.map((g) => g.name);
  const inAssignedOrder = (groupIds: Iterable<string>): string[] => {
    const wanted = new Set(groupIds);
    return assignedGroups.filter((g) => wanted.has(g.id)).map((g) => g.id);
  };

  const record = (
    stage: PolicyStage,
    result: PolicyStep['result'],
    detail: { grantingGroupIds?: Iterable<string>; objectName?: string; fieldNames?: string[] } = {}
  ): void => {
    steps.push({
      stage,
      result,
      grantingGroupIds: result === 'pass' && detail.grantingGroupIds ? inAssignedOrder(detail.grantingGroupIds) : [],
      objectName: detail.objectName ?? null,
      fieldNames: detail.fieldNames ?? [],
      ruleId: null,
    });
  };

  const decision = (
    outcome: PolicyOutcome,
    code: PolicyDecisionCode,
    reason: string,
    resolved?: { objectName: string; allowedFields: string[] }
  ): PolicyDecision => ({
    outcome,
    code,
    reason,
    objectName: resolved?.objectName ?? null,
    allowedFields: resolved?.allowedFields ?? [],
    steps,
    assignedGroups,
    decidingGroupIds:
      outcome === 'allowed'
        ? inAssignedOrder(
            steps.filter((s) => s.result === 'pass' && DECIDING_STAGES.has(s.stage)).flatMap((s) => s.grantingGroupIds)
          )
        : [],
    identity: {
      callerProfileId: subject.profileId,
      matchedProfileId: merged.matchedProfileId,
      matchMethod: merged.matchMethod,
    },
    policyRevision,
    ...(effective.skippedGroupEntries ? { skippedGroupEntries: effective.skippedGroupEntries } : {}),
  });

  const refuse = (
    stage: PolicyStage,
    code: PolicyDecisionCode,
    reason: string,
    detail?: { objectName?: string; fieldNames?: string[] }
  ): PolicyDecision => {
    record(stage, 'fail', detail);
    return decision(code === 'INPUT_INVALID' ? 'invalid' : 'denied', code, reason);
  };

  // With the arguments, an allowed call ends on an 'input' pass: every argument check the tool needs
  // passed. Without them there is none, so a decision always says whether its arguments were checked.
  const allowed = (resolved?: { objectName: string; allowedFields: string[] }) => {
    if (checkArguments) record('input', 'pass', { objectName: resolved?.objectName });
    return decision('allowed', 'ALLOWED', `Permitted via Groups [${groupNames.join(', ')}]`, resolved);
  };

  // tool
  if (!AVAILABLE_MCP_ACTIONS.some((a) => a.id === toolName)) {
    return refuse('tool', 'TOOL_UNKNOWN', `Unknown MCP tool '${toolName}'.`);
  }
  record('tool', 'pass');

  // identity
  if (!effective.profileFound) {
    return refuse(
      'identity',
      'PROFILE_UNREGISTERED',
      subject.profileId
        ? `Profile '${subject.profileId}' (${subject.profileName}) is not registered in Salesforce > Profiles.`
        : "The caller's Salesforce Profile could not be determined (the User/Profile lookup failed), so no MCP action is permitted."
    );
  }
  record('identity', 'pass');

  // groups
  if (assignedGroups.length === 0) {
    return refuse(
      'groups',
      'NO_GROUPS',
      `Profile '${effective.profileName}' (${effective.profileId}) has no Groups assigned in the Profile Group Matrix.`
    );
  }
  record('groups', 'pass');

  // tool_grant
  if (!effective.allowedActions.has(toolName)) {
    return refuse(
      'tool_grant',
      'TOOL_NOT_GRANTED',
      `MCP Action '${toolName}' is not granted by any Group assigned to Profile '${effective.profileName}' (Groups: ${groupNames.join(', ')}).`
    );
  }
  record('tool_grant', 'pass', { grantingGroupIds: merged.toolGrants.get(toolName) ?? [] });

  // A tool outside the object-scoped set has no Object to check: an objectName sent with it is ignored.
  const crud = objectToolCrud(toolName);
  if (!crud) return allowed();

  // object
  const target = readArgument(() => targetObjectArgument(args));
  if (!target.ok) return refuse('input', 'INPUT_INVALID', target.message);
  const targetObject = target.value;
  if (!targetObject || targetObject === '*') {
    return refuse('input', 'INPUT_INVALID', `MCP Action '${toolName}' requires an objectName argument.`);
  }
  const objPerm = Array.from(effective.objectPermissions.values()).find(
    (o) => o.objectName.toLowerCase() === targetObject.toLowerCase()
  );
  if (!objPerm) {
    // An objectName that is not text, or not an API name, is a malformed argument rather than an
    // Object; granted by an entry but not enabled in Salesforce > Objects (disabled there, or not
    // listed) is blocked; anything else is not granted. Each way the caller is told the same, as before.
    const reason = `Object '${targetObject}' is either disabled in Salesforce > Objects or not permitted by Groups [${groupNames.join(', ')}].`;
    if (typeof args.objectName !== 'string' || !API_NAME_PATTERN.test(targetObject)) {
      return refuse('input', 'INPUT_INVALID', reason, { objectName: targetObject });
    }
    return refuse(
      'object',
      merged.entryGrantedObjects.has(targetObject.toLowerCase()) ? 'OBJECT_BLOCKED' : 'OBJECT_NOT_GRANTED',
      reason,
      { objectName: targetObject }
    );
  }
  const objectName = objPerm.objectName;
  const provenance = merged.objectGrants.get(objectName);
  record('object', 'pass', { objectName, grantingGroupIds: provenance?.groupIds ?? [] });

  // crud
  if (!objPerm[crud.flag]) {
    return refuse(
      'crud',
      'CRUD_MISSING',
      `${crud.label} access to '${targetObject}' is not granted in Groups [${groupNames.join(', ')}].`,
      { objectName }
    );
  }
  record('crud', 'pass', { objectName, grantingGroupIds: provenance?.flags[crud.flag] ?? [] });

  const allowedFields = Array.from(objPerm.allowedFields);
  const resolved = { objectName, allowedFields };
  if (!checkArguments) return allowed(resolved);

  // What the tool handlers checked, in their order: the Object's API name, the record id, the field
  // values, the field names, then the WHERE clause.
  //
  // The Object's name here is the catalog's, not the caller's (who may spell it in any case). One stored
  // before names were validated is a fault in the policy, so an error decision that allows nothing,
  // with the text the handler gave for it. Evaluation stops there, so no step fails.
  if (!API_NAME_PATTERN.test(objectName)) {
    return decision('error', 'INTERNAL_ERROR', `Object '${objectName}' is not a valid Salesforce API name.`);
  }
  const invalid = (message: string) => refuse('input', 'INPUT_INVALID', message, { objectName });
  if (toolName === 'describe_object') return allowed(resolved);

  if (
    (toolName === 'get_record' || toolName === 'update_record' || toolName === 'delete_record') &&
    recordIdArgument(args) === null
  ) {
    return invalid(RECORD_ID_MESSAGE);
  }
  if (toolName === 'delete_record') return allowed(resolved);

  let requestedFields: string[];
  if (toolName === 'create_record' || toolName === 'update_record') {
    const fieldValues = fieldValuesArgument(args);
    if (!fieldValues) return invalid(FIELD_VALUES_MESSAGE);
    requestedFields = Object.keys(fieldValues);
  } else {
    const selected = readArgument(() => selectedFieldNames(args, allowedFields));
    if (!selected.ok) return invalid(selected.message);
    requestedFields = selected.value;
  }

  // fields: every name must be in the allowlist, case-insensitively. Names stored before API-name
  // validation existed are re-checked, since they go into SOQL and URLs.
  const fieldGrants = new Map(
    Array.from(provenance?.fields ?? [], ([field, groupIds]) => [field.toLowerCase(), groupIds] as const)
  );
  const grantsOf = (fieldNames: string[]) => fieldNames.flatMap((f) => Array.from(fieldGrants.get(f.toLowerCase()) ?? []));
  const permitted = new Set(
    allowedFields.filter((f) => API_NAME_PATTERN.test(f)).map((f) => f.toLowerCase())
  );
  const disallowed = requestedFields.filter((f) => !permitted.has(f.toLowerCase()));
  if (disallowed.length > 0) {
    return refuse(
      'fields',
      'FIELD_NOT_PERMITTED',
      `Fields [${disallowed.join(', ')}] on ${objectName} are not permitted for Profile '${effective.profileName}'.`,
      { objectName, fieldNames: disallowed }
    );
  }
  record('fields', 'pass', { objectName, fieldNames: requestedFields, grantingGroupIds: grantsOf(requestedFields) });

  // where
  if (toolName === 'soql_query') {
    const whereClause = whereClauseArgument(args);
    const check: WhereClauseCheck = whereClause
      ? checkSoqlWhereClause(whereClause, allowedFields)
      : { ok: true, fieldNames: [] };
    if (!check.ok) {
      // A clause that cannot be read is a malformed argument; one naming a field is a denial.
      return check.problem === 'malformed'
        ? invalid(check.message)
        : refuse('where', 'WHERE_FIELD_NOT_PERMITTED', check.message, { objectName, fieldNames: [check.fieldName] });
    }
    record('where', 'pass', { objectName, fieldNames: check.fieldNames, grantingGroupIds: grantsOf(check.fieldNames) });
  }

  return allowed(resolved);
}

/** The log status of a refused or allowed decision: invalid arguments are DENIED, not ERROR. */
export function decisionLogStatus(decision: PolicyDecision): 'ALLOWED' | 'DENIED' | 'ERROR' {
  if (decision.outcome === 'allowed') return 'ALLOWED';
  return decision.outcome === 'error' ? 'ERROR' : 'DENIED';
}

// ---------------------------------------------------------------------------
// The earlier result shape
// ---------------------------------------------------------------------------

export interface PolicyEvaluationResult {
  permitted: boolean;
  reason: string;
  matchedGroups: string[];
  allowedFields: string[];
  /** Canonical API name of the permitted target object (set when an object-scoped call is permitted). */
  objectName?: string;
  /** Present only when a stored entry of the caller's groups was skipped while resolving their access. */
  skippedGroupEntries?: SkippedGroupEntry[];
  /** The decision these fields are read from. */
  decision: PolicyDecision;
}

/** A decision in the shape evaluateMcpToolCall has always returned; matchedGroups lists every assigned group. */
export function policyEvaluationResult(decision: PolicyDecision): PolicyEvaluationResult {
  const permitted = decision.outcome === 'allowed';
  return {
    permitted,
    reason: decision.reason,
    matchedGroups: decision.assignedGroups.map((g) => g.name),
    allowedFields: permitted ? decision.allowedFields : [],
    ...(permitted && decision.objectName ? { objectName: decision.objectName } : {}),
    ...(decision.skippedGroupEntries ? { skippedGroupEntries: decision.skippedGroupEntries } : {}),
    decision,
  };
}

/** The tool and Object check (evaluateToolAccess) on the stored policy, in the earlier result shape. */
export function evaluateMcpToolCall(
  user: VerifiedSalesforceUser,
  toolName: string,
  targetObject?: string
): PolicyEvaluationResult {
  return policyEvaluationResult(evaluateToolAccess(user, toolName, targetObject, loadPolicySnapshot()));
}

export function getVisibleToolsForUser(user: VerifiedSalesforceUser) {
  const effective = resolveEffectiveProfilePermissions(
    user.profileId,
    user.profileName
  );
  return AVAILABLE_MCP_ACTIONS.filter((a) => effective.allowedActions.has(a.id));
}
