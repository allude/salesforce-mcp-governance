// What the MCP log keeps of a decision: decision_json and the columns beside it. Names, ids, codes and
// counts only, never a reason and never a value. A decision's steps echo what the caller sent (the
// objectName, field names, a WHERE identifier), so a name is kept only when it is a Salesforce API name
// that the synced catalog holds, in the catalog's spelling, a group id only when a group has it, and the
// matched Profile id only when the registry has it. Anything else is stored by its length
// (`<invalid:len=N>`), as the tool_name and target_object columns store refused text. The catalog is
// the policy snapshot the decision was made from (policySnapshotCatalog), so a group or Object deleted
// while the call ran is still named in its row. Pure: the catalog is passed in, and nothing here reads
// the store.
import { SALESFORCE_API_NAME_PATTERN } from '../db/importers.js';
import { isSalesforceId } from '../salesforce/ids.js';
import type { TokenRejectionCode } from '../salesforce/client.js';
import type { McpLogDecision, McpLogDecisionStep, McpLogMatchMethod } from '../types/governance.js';
import { MALFORMED_GRANT_REASONS, spellingLookup } from './groupGrants.js';
import type {
  PolicyDecision,
  PolicyDecisionCode,
  PolicyOutcome,
  PolicySnapshot,
  PolicyStage,
  PolicyStep,
  ProfileMatchMethod,
} from './policyEngine.js';

/**
 * A request refused before any policy was read: its bearer token did not verify ('auth'), or Salesforce
 * gave no verdict on it ('upstream').
 */
export type GatewayDecision =
  | { outcome: 'denied'; stage: 'auth'; code: TokenRejectionCode }
  | { outcome: 'error'; stage: 'upstream'; code: 'UPSTREAM_UNAVAILABLE' };

/** The decision logged for a token that failed verification. */
export function tokenRejectedDecision(code: TokenRejectionCode): GatewayDecision {
  return { outcome: 'denied', stage: 'auth', code };
}

/** The decision logged when Salesforce could not verify a token (SalesforceUnavailableError). */
export const UPSTREAM_UNAVAILABLE_DECISION: GatewayDecision = {
  outcome: 'error',
  stage: 'upstream',
  code: 'UPSTREAM_UNAVAILABLE',
};

// The words a stored decision may hold. Each list is a Record over the engine's own type, so the
// compiler refuses one that leaves out a stage or code the engine can give, or names one it cannot.
const LOGGED_OUTCOMES: Record<PolicyOutcome, true> = { allowed: true, denied: true, invalid: true, error: true };
const LOGGED_STAGES: Record<PolicyStage | GatewayDecision['stage'], true> = {
  tool: true,
  identity: true,
  groups: true,
  tool_grant: true,
  object: true,
  crud: true,
  fields: true,
  where: true,
  input: true,
  auth: true,
  upstream: true,
};
const LOGGED_CODES: Record<PolicyDecisionCode | GatewayDecision['code'], true> = {
  ALLOWED: true,
  TOOL_UNKNOWN: true,
  PROFILE_UNREGISTERED: true,
  NO_GROUPS: true,
  TOOL_NOT_GRANTED: true,
  OBJECT_NOT_GRANTED: true,
  OBJECT_BLOCKED: true,
  CRUD_MISSING: true,
  FIELD_NOT_PERMITTED: true,
  WHERE_FIELD_NOT_PERMITTED: true,
  ROW_FILTER: true,
  INPUT_INVALID: true,
  INTERNAL_ERROR: true,
  TOKEN_INVALID: true,
  ORG_LOCK_VIOLATION: true,
  INSTANCE_NOT_ALLOWED: true,
  UPSTREAM_UNAVAILABLE: true,
};
const LOGGED_MATCH_METHODS: Record<ProfileMatchMethod, true> = { id: true, name: true, none: true };

/** The most field names one step keeps, and skipped entries one decision keeps; the rest are counted. */
export const MAX_LOGGED_NAMES = 200;

/** The synced catalog a logged decision's names are checked against. */
export interface DecisionLogCatalog {
  /** The catalog's spelling of the Object `name` names, matched ignoring case (sf_objects), or null. */
  objectName(name: string): string | null;
  /** The fields sf_object_fields holds for the Object stored under exactly `objectName`. */
  fieldNames(objectName: string): readonly string[];
  /** Whether an Access Group has this id. */
  hasGroup(groupId: string): boolean;
  /** Whether Salesforce > Profiles (sf_profiles) has a Profile under exactly this id. */
  hasProfile(profileId: string): boolean;
}

/**
 * The catalog of the policy snapshot a decision was made from: its Objects and their fields (every one,
 * enabled or not, as sf_objects and sf_object_fields held them), its groups and its Profiles. An Object
 * is found as store.resolveObjectName finds one, without trimming: under its own spelling, else the first
 * in name order that differs only by case. Every id a decision holds comes from its snapshot, so checking
 * against the snapshot keeps the names of a group, Object or Profile deleted while the call ran, and
 * still refuses whatever the caller wrote that the catalog did not hold. Without a snapshot, nothing is
 * held, so every name would be stored by its length; a refused token or an outage looks nothing up.
 */
export function policySnapshotCatalog(
  snapshot: Pick<PolicySnapshot, 'objects' | 'groups' | 'profiles'> | undefined
): DecisionLogCatalog {
  const objects = snapshot?.objects ?? [];
  // Built on first use: most decisions name one Object, and a refusal at the tool stage names none.
  let objectSpelling: ((name: string) => string | null) | undefined;
  let groupIds: Set<string> | undefined;
  let profileIds: Set<string> | undefined;
  return {
    objectName(name) {
      objectSpelling ??= spellingLookup(objects.map((o) => o.objectName).sort());
      return objectSpelling(name);
    },
    fieldNames(objectName) {
      return objects.find((o) => o.objectName === objectName)?.fields.map((f) => f.fieldName) ?? [];
    },
    hasGroup(groupId) {
      groupIds ??= new Set((snapshot?.groups ?? []).map((g) => g.id));
      return groupIds.has(groupId);
    },
    hasProfile(profileId) {
      profileIds ??= new Set((snapshot?.profiles ?? []).map((p) => p.id));
      return profileIds.has(profileId);
    },
  };
}

/** What a log row stores of its decision, column by column. */
export interface DecisionLogColumns {
  decision: McpLogDecision;
  /** decision.stage and decision.code, also kept in columns of their own. */
  stage: string;
  code: string;
  assignedGroupIds: string[];
  decidingGroupIds: string[];
  /** null when no policy was read. */
  policyRevision: number | null;
  /** '' when there is none: no verified caller, or a caller whose Profile lookup failed. */
  callerProfileId: string;
  /** The registered Profile's id as the registry holds it, whatever its form; '' when none matched. */
  matchedProfileId: string;
  matchMethod: McpLogMatchMethod;
}

/** Text that may not be stored, stored by its length only. */
function invalid(value: unknown): string {
  return `<invalid:len=${typeof value === 'string' ? value.length : 0}>`;
}

/** A word from one of the fixed lists above, or `<invalid:len=N>`. */
function word(vocabulary: Record<string, true>, value: unknown): string {
  return typeof value === 'string' && Object.hasOwn(vocabulary, value) ? value : invalid(value);
}

/** The caller's Salesforce Profile id as it was given, or `<invalid:len=N>`; '' stays '' (none). */
function callerProfileId(id: unknown): string {
  if (id === '' || id === null || id === undefined) return '';
  return typeof id === 'string' && id === id.trim() && isSalesforceId(id) ? id : invalid(id);
}

/** Takes at most MAX_LOGGED_NAMES items and says how many it left out. */
function capped<T>(items: readonly T[]): { kept: T[]; dropped: number } {
  return { kept: items.slice(0, MAX_LOGGED_NAMES), dropped: Math.max(0, items.length - MAX_LOGGED_NAMES) };
}

/** The catalog's lookups for one decision, each made once. */
function checkedNames(catalog: DecisionLogCatalog) {
  const objects = new Map<string, string | null>();
  const fields = new Map<string, (name: string) => string | null>();
  const groups = new Map<string, boolean>();
  const profiles = new Map<string, boolean>();
  return {
    /** The catalog spelling of an Object name, or null when it is not one the catalog holds. */
    object(name: unknown): string | null {
      if (typeof name !== 'string' || !SALESFORCE_API_NAME_PATTERN.test(name)) return null;
      if (!objects.has(name)) objects.set(name, catalog.objectName(name));
      return objects.get(name) ?? null;
    },
    /** A field name of a catalog Object in the catalog's spelling, or `<invalid:len=N>`. */
    field(catalogObject: string | null, name: unknown): string {
      if (catalogObject === null || typeof name !== 'string' || !SALESFORCE_API_NAME_PATTERN.test(name)) {
        return invalid(name);
      }
      let lookup = fields.get(catalogObject);
      if (!lookup) {
        lookup = spellingLookup(catalog.fieldNames(catalogObject));
        fields.set(catalogObject, lookup);
      }
      return lookup(name) ?? invalid(name);
    },
    /** A group id a group has, or `<invalid:len=N>`. */
    group(id: unknown): string {
      if (typeof id !== 'string') return invalid(id);
      if (!groups.has(id)) groups.set(id, catalog.hasGroup(id));
      return groups.get(id) ? id : invalid(id);
    },
    /**
     * The id of a registered Profile, or `<invalid:len=N>`; none stays ''. The registry, not the caller,
     * wrote it, and it may hold ids of any form (the CSV import, rows from before the id check).
     */
    profile(id: unknown): string {
      if (id === '' || id === null || id === undefined) return '';
      if (typeof id !== 'string') return invalid(id);
      if (!profiles.has(id)) profiles.set(id, catalog.hasProfile(id));
      return profiles.get(id) ? id : invalid(id);
    },
  };
}

type CheckedNames = ReturnType<typeof checkedNames>;

function loggedStep(step: PolicyStep, names: CheckedNames): McpLogDecisionStep {
  const catalogObject = step.objectName === null ? null : names.object(step.objectName);
  const fieldNames = capped(Array.isArray(step.fieldNames) ? step.fieldNames : []);
  return {
    stage: word(LOGGED_STAGES, step.stage),
    result: step.result === 'pass' ? 'pass' : 'fail',
    grantingGroupIds: (step.grantingGroupIds ?? []).map(names.group),
    objectName: step.objectName === null ? null : catalogObject ?? invalid(step.objectName),
    fieldNames: fieldNames.kept.map((name) => names.field(catalogObject, name)),
    ...(fieldNames.dropped > 0 ? { fieldNamesDropped: fieldNames.dropped } : {}),
  };
}

function gatewayColumns(decision: GatewayDecision): DecisionLogColumns {
  const stage = word(LOGGED_STAGES, decision.stage);
  const code = word(LOGGED_CODES, decision.code);
  return {
    decision: {
      outcome: decision.outcome === 'denied' ? 'denied' : 'error',
      code,
      stage,
      steps: [{ stage, result: 'fail', grantingGroupIds: [], objectName: null, fieldNames: [] }],
      decidingGroupIds: [],
      matchMethod: 'none',
      policyRevision: null,
    },
    stage,
    code,
    assignedGroupIds: [],
    decidingGroupIds: [],
    policyRevision: null,
    callerProfileId: '',
    matchedProfileId: '',
    matchMethod: 'none',
  };
}

/**
 * What a log row stores of `decision`. Every step keeps its stage, result, granting groups, Object and
 * fields; the decision keeps its outcome, code, final stage, deciding groups, how the Profile matched,
 * the policy revision and the skipped entries' group, position and fixed reason. The reason text, the
 * allowed fields and the arguments are never kept. A refused token or an outage (a GatewayDecision) has
 * one failed step of its own stage and no policy revision.
 */
export function decisionLogColumns(
  decision: PolicyDecision | GatewayDecision,
  catalog: DecisionLogCatalog
): DecisionLogColumns {
  if (!('steps' in decision)) return gatewayColumns(decision);

  const names = checkedNames(catalog);
  const steps = decision.steps.map((step) => loggedStep(step, names));
  const stage = steps.length > 0 ? steps[steps.length - 1].stage : '';
  const code = word(LOGGED_CODES, decision.code);
  const decidingGroupIds = decision.decidingGroupIds.map(names.group);
  const matchMethod = Object.hasOwn(LOGGED_MATCH_METHODS, decision.identity.matchMethod)
    ? decision.identity.matchMethod
    : 'none';
  const policyRevision = Number.isSafeInteger(decision.policyRevision) ? decision.policyRevision : null;
  const skipped = decision.skippedGroupEntries ? capped(decision.skippedGroupEntries) : null;

  return {
    decision: {
      outcome: Object.hasOwn(LOGGED_OUTCOMES, decision.outcome) ? decision.outcome : 'error',
      code,
      stage,
      steps,
      decidingGroupIds,
      matchMethod,
      policyRevision,
      ...(skipped
        ? {
            skippedEntries: skipped.kept.map((entry) => ({
              groupId: names.group(entry.groupId),
              index: Number.isSafeInteger(entry.index) && entry.index >= 0 ? entry.index : -1,
              reason: MALFORMED_GRANT_REASONS.includes(entry.reason) ? entry.reason : invalid(entry.reason),
            })),
          }
        : {}),
      ...(skipped && skipped.dropped > 0 ? { skippedEntriesDropped: skipped.dropped } : {}),
    },
    stage,
    code,
    assignedGroupIds: decision.assignedGroups.map((group) => names.group(group.id)),
    decidingGroupIds,
    policyRevision,
    callerProfileId: callerProfileId(decision.identity.callerProfileId),
    matchedProfileId: names.profile(decision.identity.matchedProfileId),
    matchMethod,
  };
}
