// What a Portal Admin log row records of an Access Group. A diff holds names, ids and flags only.
// POST /groups now stores only checked grants, but a group saved by an older version holds its grants
// as they were sent, so each grant is rebuilt here from the keys a grant has, as the policy engine
// reads it. Anything else stored with it never reaches the log.
import { SALESFORCE_API_NAME_PATTERN } from '../db/importers.js';
import { malformedGrantReason } from '../rbac/groupGrants.js';
import { AVAILABLE_MCP_ACTIONS, type AccessGroup } from '../types/governance.js';

/** The longest group name or description a diff keeps. A longer one is cut, and the diff lists it under truncated. */
export const GROUP_AUDIT_TEXT_LIMIT = 1_000;

const KNOWN_ACTION_IDS = new Set<string>(AVAILABLE_MCP_ACTIONS.map((action) => action.id));

interface AuditedGrant {
  objectName: string;
  canRead: boolean;
  canCreate: boolean;
  canUpdate: boolean;
  canDelete: boolean;
  allowedFields: string[];
}

interface AuditedGroup {
  name: string;
  description: string;
  allowedActions: string[];
  objectPermissions: AuditedGrant[];
  truncated?: Array<'name' | 'description'>;
}

// Text that is not a Salesforce API name matches no catalog Object or Field, so it grants nothing. Like
// the Copilot MCP log, it is recorded by its length only.
const auditedName = (value: string) =>
  SALESFORCE_API_NAME_PATTERN.test(value) ? value : `<invalid:len=${value.length}>`;

/**
 * A grant as the policy engine reads it, or null for an entry that grants nothing whatever it holds:
 * one the engine skips as malformed, or one that names no object.
 */
function auditedGrant(entry: unknown): AuditedGrant | null {
  if (malformedGrantReason(entry) !== null) return null;
  const grant = entry as Record<string, unknown> & { objectName: string; allowedFields?: string[] };
  if (!grant.objectName) return null;
  return {
    objectName: auditedName(grant.objectName),
    // A flag grants only when it is exactly true; an absent one is false.
    canRead: grant.canRead === true,
    canCreate: grant.canCreate === true,
    canUpdate: grant.canUpdate === true,
    canDelete: grant.canDelete === true,
    allowedFields: (grant.allowedFields ?? []).map(auditedName),
  };
}

/** What an Access Group's audit diff records of it: enough to rebuild the group, and nothing else. */
export function groupAuditFields(group: AccessGroup): AuditedGroup {
  const truncated: Array<'name' | 'description'> = [];
  const text = (key: 'name' | 'description') => {
    const value = String(group[key] ?? '');
    if (value.length <= GROUP_AUDIT_TEXT_LIMIT) return value;
    truncated.push(key);
    return value.slice(0, GROUP_AUDIT_TEXT_LIMIT);
  };
  const fields: AuditedGroup = {
    name: text('name'),
    description: text('description'),
    allowedActions: (Array.isArray(group.allowedActions) ? group.allowedActions : []).map((id) =>
      KNOWN_ACTION_IDS.has(id) ? id : `<invalid:len=${String(id).length}>`
    ),
    objectPermissions: (Array.isArray(group.objectPermissions) ? group.objectPermissions : [])
      .map(auditedGrant)
      .filter((grant): grant is AuditedGrant => grant !== null),
  };
  return truncated.length > 0 ? { ...fields, truncated } : fields;
}

/** The grants of `grants` that `others` does not hold as they are, matched one for one. */
function grantsNotIn(grants: AuditedGrant[], others: AuditedGrant[]): AuditedGrant[] {
  const unmatched = new Map<string, number>();
  for (const grant of others) {
    const key = JSON.stringify(grant);
    unmatched.set(key, (unmatched.get(key) ?? 0) + 1);
  }
  return grants.filter((grant) => {
    const key = JSON.stringify(grant);
    const count = unmatched.get(key) ?? 0;
    if (count === 0) return true;
    unmatched.set(key, count - 1);
    return false;
  });
}

/**
 * UPDATE_GROUP's diff: each side holds only what changed. A field is listed when its value changed,
 * and of the grants only those the other side does not hold as they are: removed or changed ones in
 * before, added or changed ones in after. Taking before's grants out of the old group and putting
 * after's in gives the saved one. An unchanged save is { before: {}, after: {} }.
 */
export function groupUpdateDiff(previous: AccessGroup, saved: AccessGroup) {
  const [old, now] = [groupAuditFields(previous), groupAuditFields(saved)];
  const before: Partial<AuditedGroup> = {};
  const after: Partial<AuditedGroup> = {};

  // Compared on the stored values, so a change past the cut of a long description still shows.
  if (previous.name !== saved.name) [before.name, after.name] = [old.name, now.name];
  if (previous.description !== saved.description) {
    [before.description, after.description] = [old.description, now.description];
  }
  if (JSON.stringify(previous.allowedActions) !== JSON.stringify(saved.allowedActions)) {
    [before.allowedActions, after.allowedActions] = [old.allowedActions, now.allowedActions];
  }
  const removed = grantsNotIn(old.objectPermissions, now.objectPermissions);
  const added = grantsNotIn(now.objectPermissions, old.objectPermissions);
  if (removed.length > 0 || added.length > 0) {
    before.objectPermissions = removed;
    after.objectPermissions = added;
  }

  const cut = (fields: AuditedGroup, side: Partial<AuditedGroup>) =>
    (fields.truncated ?? []).filter((key) => key in side);
  const [beforeCut, afterCut] = [cut(old, before), cut(now, after)];
  return {
    before: beforeCut.length > 0 ? { ...before, truncated: beforeCut } : before,
    after: afterCut.length > 0 ? { ...after, truncated: afterCut } : after,
  };
}
