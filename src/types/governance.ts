import type { PortalAuditResult } from '../security/auditResult.js';

export type NavViewId =
  | 'dashboard'
  | 'sf-profiles'
  | 'sf-objects'
  | 'matrix-groups'
  | 'matrix-profile-groups'
  | 'logs-copilot'
  | 'logs-portal'
  | 'settings-auth'
  | 'settings-salesforce'
  | 'connect-copilot';

export const AVAILABLE_MCP_ACTIONS = [
  {
    id: 'list_enabled_objects',
    label: 'List Allowed Objects',
    category: 'Discovery',
    description: 'Lists Salesforce objects the user is permitted to access via their Profile Groups.',
  },
  {
    id: 'describe_object',
    label: 'Describe Object & Allowed Fields',
    category: 'Discovery',
    description: 'Returns allowed fields and metadata for an enabled Salesforce object.',
  },
  {
    id: 'soql_query',
    label: 'Run Scoped SOQL Query',
    category: 'Read',
    description: 'Executes a read-only SOQL query restricted to permitted objects and fields.',
  },
  {
    id: 'get_record',
    label: 'Get Record by ID',
    category: 'Read',
    description: 'Fetches a single Salesforce record filtered to allowed fields.',
  },
  {
    id: 'create_record',
    label: 'Create Record',
    category: 'Write',
    description: 'Creates a new record on an object where group grants Create access.',
  },
  {
    id: 'update_record',
    label: 'Update Record',
    category: 'Write',
    description: 'Updates permitted fields on an existing record where group grants Update access.',
  },
  {
    id: 'delete_record',
    label: 'Delete Record',
    category: 'Delete',
    description: 'Deletes a record on an object where group grants Delete access.',
  },
] as const;

export type McpActionId = (typeof AVAILABLE_MCP_ACTIONS)[number]['id'];

/** The values in `ids` that name no MCP tool, as text. A group granting one of them would grant nothing. */
export function unknownMcpActionIds(ids: readonly unknown[]): string[] {
  return ids
    .filter((id) => !AVAILABLE_MCP_ACTIONS.some((action) => action.id === id))
    .map((id) => String(id));
}

export type McpActionType = string;
export type RemovalResolutionAction = 'KEEP_FLAGGED' | 'DELETE';

export interface AdminSession {
  username: string;
  name: string;
  displayName?: string;
  role?: string;
  authMethod: string;
  groups?: string[];
}

export interface OrgObjectCatalogEntry {
  objectName: string;
  label: string;
  isCustom: boolean;
  custom?: boolean;
  queryable?: boolean;
  alreadyInStore?: boolean;
}

export interface SalesforceProfile {
  id: string; // 15 or 18-char Salesforce Profile ID (00e...)
  name: string;
  missingInOrg?: boolean;
  updatedAt: string;
}

export interface SalesforceObjectField {
  objectName: string;
  fieldName: string;
  label: string;
  fieldType: string;
  isCustom: boolean;
  required: boolean;
  enabled: boolean;
  missingInOrg?: boolean;
}

export interface SalesforceObject {
  objectName: string;
  label: string;
  isCustom: boolean;
  enabled: boolean;
  sourcePath: string;
  fieldCount: number;
  enabledFieldCount: number;
  fields: SalesforceObjectField[];
  missingInOrg?: boolean;
  updatedAt: string;
}

/** When something was deleted from Salesforce > Objects, and the admin who deleted it. */
export interface CatalogRemoval {
  at: string;
  by: string;
}

export interface GroupObjectPermission {
  objectName: string;
  canRead: boolean;
  canCreate: boolean;
  canUpdate: boolean;
  canDelete: boolean;
  allowedFields: string[]; // Field API names from SalesforceObjectField
  /**
   * Set when the object was deleted from Salesforce > Objects. The entry stays on the group so admins
   * can see what it granted, and it grants nothing, even after the object is imported again, until an
   * admin restores it.
   */
  removed?: CatalogRemoval;
  /** Granted fields deleted from Salesforce > Objects, kept the same way: they grant nothing until restored. */
  removedFields?: Array<CatalogRemoval & { fieldName: string }>;
}

/** The longest Access Group name and description POST /groups accepts, after trimming. */
export const ACCESS_GROUP_NAME_MAX_LENGTH = 80;
export const ACCESS_GROUP_DESCRIPTION_MAX_LENGTH = 500;

export interface AccessGroup {
  id: string;
  name: string;
  description: string;
  allowedActions: string[]; // McpActionId[], plus any ID this server has no tool for (kept and shown as not available)
  objectPermissions: GroupObjectPermission[];
  /** 1 when created, +1 on every saved change. POST /groups refuses an update built from another version. */
  version: number;
  updatedAt: string;
}

/** What a group grants, without its identity: what history keeps and an XML file holds. */
export type AccessGroupSnapshot = Pick<AccessGroup, 'name' | 'description' | 'allowedActions' | 'objectPermissions'>;

/** Where a change to a group came from. */
export type AccessGroupChangeSource =
  | 'editor' // the drawer's switches
  | 'xml_editor' // the drawer's XML view
  | 'xml_import' // an imported XML file
  | 'version_restore' // a version loaded from the group's history
  | 'objects' // Salesforce > Objects (delete, enable, disable)
  | 'org_sync' // Object sync from the Salesforce org
  | 'sample_data';

export const ACCESS_GROUP_EDIT_SOURCES = ['editor', 'xml_editor', 'xml_import', 'version_restore'] as const;

export interface AccessGroupHistoryEntry {
  id: string;
  groupId: string;
  /** The group's name when this happened. */
  groupName: string;
  timestamp: string;
  adminUsername: string;
  authMethod: string;
  /** `catalog`: something the group grants changed in Salesforce > Objects, not the group itself. */
  kind: 'created' | 'updated' | 'deleted' | 'catalog';
  source: AccessGroupChangeSource;
  /** The file an import came from, or which version a restore loaded. '' otherwise. */
  sourceDetail: string;
  /** One line per change, for people to read. */
  changes: string[];
  /** The group after the change; for a deletion, the group as it was. */
  snapshot: AccessGroupSnapshot;
}

export interface ProfileGroupMapping {
  profileId: string;
  groupIds: string[];
}

/** What an MCP log row records: a verified caller's call, a policy simulation, or a refused token. */
export type McpLogKind = 'real' | 'simulated' | 'rejected';

/** How the caller's Profile was matched to a registered one; '' on a row from before it was recorded. */
export type McpLogMatchMethod = '' | 'id' | 'name' | 'none';

/**
 * One stage of a logged decision. It holds names and ids only: an Object or field name the synced
 * catalog does not hold, and a group id no group has, are stored as `<invalid:len=N>`.
 */
export interface McpLogDecisionStep {
  stage: string;
  result: 'pass' | 'fail';
  grantingGroupIds: string[];
  /** The Object's catalog spelling; null when the step names none. */
  objectName: string | null;
  /** In the catalog's spelling, at most 200; fieldNamesDropped counts the rest. */
  fieldNames: string[];
  fieldNamesDropped?: number;
}

/**
 * A row's decision (decision_json): what decided the call, never why in words and never a value.
 * Stages are the policy engine's, or 'auth' (the token) and 'upstream' (Salesforce gave no verdict on
 * it) for a request refused before any policy was read.
 */
export interface McpLogDecision {
  outcome: 'allowed' | 'denied' | 'invalid' | 'error';
  code: string;
  /** The stage of the last step: the one that failed, or the last that passed for an allowed call. */
  stage: string;
  steps: McpLogDecisionStep[];
  decidingGroupIds: string[];
  matchMethod: 'id' | 'name' | 'none';
  /** null when no policy was read (a refused token or an outage). */
  policyRevision: number | null;
  /** Stored group entries the engine skipped as malformed, at most 200; skippedEntriesDropped counts the rest. */
  skippedEntries?: Array<{ groupId: string; index: number; reason: string }>;
  skippedEntriesDropped?: number;
}

export interface CopilotMcpLogRecord {
  id: string;
  timestamp: string;
  sfUsername: string;
  profileId: string;
  profileName: string;
  matchedGroups: string[];
  toolName: string;
  targetObject: string;
  status: 'ALLOWED' | 'DENIED' | 'ERROR';
  latencyMs: number; // total_ms on rows that have it, so it runs from request receipt
  sanitizedRequestPayload: string; // JSON with PII / record values stripped
  sanitizedResponseSummary: string; // JSON with record values stripped
  simulated?: true; // Present only on rows from the policy simulator, never on real traffic
  seq?: number; // Write order (the seq column), set by every reader; the paging cursor
  // The decision and timing part of the row. The Admin API always sends these; they are optional so
  // that the portal can still show a row from a server that predates them. On a row written before
  // they existed, every one but kind is not recorded: '' for text, [] for lists, null otherwise.
  kind?: McpLogKind;
  decision?: McpLogDecision | null;
  decisionStage?: string; // decision.stage, kept in a column of its own
  decisionCode?: string; // decision.code, likewise
  assignedGroupIds?: string[]; // The groups assigned to the caller's Profile when the call was decided
  decidingGroupIds?: string[]; // For an allowed call, the groups that granted it
  policyRevision?: number | null; // The policy revision the call was decided on
  callerProfileId?: string; // The verified caller's Profile id ('' when there is none, or no caller)
  matchedProfileId?: string; // The registered Profile the decision matched ('' when none)
  matchMethod?: McpLogMatchMethod;
  verificationMs?: number | null; // How long verifying the bearer token took
  totalMs?: number | null; // From request receipt to the row
}

/**
 * Dashboard figures for recent verified MCP calls, read from the whole log on the server. Simulator
 * runs and rejected tokens are left out: neither is a Copilot user calling a tool.
 */
export interface McpActivityFigures {
  windowHours: number;
  /** Where the window ends: the server's clock when it answered. */
  asOf: string;
  verifiedCalls: number;
  activeUsers: number;
  activeProfiles: number;
  p95LatencyMs: number;
  avgLatencyMs: number;
  /** Most calls first, at most 6. */
  topTools: Array<{ toolName: string; calls: number }>;
  /** Most calls first, at most 5, each with the Profile of the user's latest call. */
  topUsers: Array<{ username: string; profileName: string; calls: number }>;
}

/** Real calls (simulator runs left out) counted per outcome in one fixed slice of time. */
export interface McpTrafficSlice {
  /** Epoch ms where the slice starts; slices are aligned to multiples of their size. */
  start: number;
  ok: number;
  warn: number;
  err: number;
}

export type McpTrafficRange = '1h' | '24h' | '7d';

/**
 * For each dashboard chart range, the counts of every logged call in its window, in slices small
 * enough for the browser to place against its own reading of the server clock. Oldest first, with
 * empty slices left out.
 */
export type McpTrafficSeries = Record<McpTrafficRange, { sliceMs: number; slices: McpTrafficSlice[] }>;

export interface PortalAdminLogRecord {
  id: string;
  timestamp: string;
  adminUsername: string;
  authMethod: 'password' | 'okta_sso';
  action: string;
  target: string;
  details: string;
  ipAddress: string;
  // The structured part of the row. The Admin API always sends these; they are optional so that the
  // portal can still show a row from a server that predates them (the Result then follows the action name).
  // A row written before these columns existed has '' for targetType, targetId and correlationId and a
  // null diff: not recorded. Its result follows the action name.
  result?: PortalAuditResult;
  targetType?: string; // e.g. 'group', 'profile', 'settings'; '' when the action has no single target
  targetId?: string; // The stable id of that target (a group id, a Profile id, a settings section); '' when none
  diff?: Record<string, unknown> | null; // Names, ids and flags of what changed, never a secret; null when not recorded
  correlationId?: string; // Shared by every row written while handling one Admin API request; '' is not an id
  seq?: number; // Write order (the seq column) on rows from the Admin API log lists; the paging cursor
}

export interface OktaSsoSettings {
  enabled: boolean;
  oktaDomain: string;
  issuer: string;
  clientId: string;
  hasClientSecret: boolean;
  redirectUri: string;
  adminGroup: string;
  updatedAt: string;
}

export interface SalesforceConnectionSettings {
  enabled: boolean;
  authMode: 'jwt_bearer' | 'simulated';
  loginUrl: string;
  clientId: string;
  username: string;
  /** A key connect can sign with. False for one that cannot be decrypted: see privateKeyUndecryptable. */
  hasPrivateKey: boolean;
  /** A key is stored but the current APP_SECRET_KEY cannot decrypt it. Restoring that secret could recover it. */
  privateKeyUndecryptable: boolean;
  certificatePem: string;
  certFingerprint: string;
  /** `not_verified`: the settings changed after the last connect or failed attempt, so neither result holds. */
  connectionStatus: 'connected' | 'disconnected' | 'error' | 'not_verified';
  lastConnectedAt: string | null;
  lastError: string;
  connectedOrgId: string;
  connectedUser: string;
  expectedOrgId: string;
  /** Where MCP verifies user tokens and the authorization server it advertises. Not the sync connection's. */
  instanceUrl: string;
  /** The instance the metadata sync connection last verified against. For display; '' when not connected. */
  syncInstanceUrl: string;
  apiVersion: string;
  enforceOrgIdLock: boolean;
  sfdxObjectsFolderPath: string;
  updatedAt: string;
}

export interface ProfileSyncDiffPreview {
  orgId: string;
  instanceUrl: string;
  added: Array<{ id: string; name: string; userType: string }>;
  updated: Array<{
    id: string;
    name: string;
    previousName: string;
    /** The stored ID, when the sync replaces it with the org's 18-character form. */
    previousId?: string;
    unchanged: boolean;
  }>;
  removedFromOrg: Array<{
    id: string;
    name: string;
    mappedGroupNames: string[];
  }>;
  /** Org Profiles stored as more than one local row, as older versions could leave them. */
  duplicates: ProfileSyncDuplicate[];
}

export interface ProfileSyncDuplicate {
  id: string;
  name: string;
  /** Listed in resolution order: the first is the row whose groups are in force today. */
  rows: Array<{ id: string; name: string; groupNames: string[] }>;
  /** 'merge' collapses the rows into one. 'conflict' leaves them untouched for an admin to resolve. */
  outcome: 'merge' | 'conflict';
  /** The groups the merged row keeps. Empty for a conflict, where nothing changes. */
  resultGroupNames: string[];
  /** Groups a merge puts in force that are not today. Empty for a conflict. */
  grantedGroupNames: string[];
}

export interface ObjectSyncDiffPreview {
  orgId: string;
  instanceUrl: string;
  upsertedObjects: Array<{
    objectName: string;
    label: string;
    isCustom: boolean;
    isNewObject: boolean;
    totalOrgFields: number;
    addedFields: Array<{
      fieldName: string;
      label: string;
      fieldType: string;
      isCustom: boolean;
      required: boolean;
    }>;
    updatedFieldsCount: number;
    removedFieldsFromOrg: Array<{
      objectName: string;
      fieldName: string;
      label: string;
      fieldType: string;
      enabled: boolean;
      referencedInGroups: string[];
    }>;
    /** Every local spelling this sync updates, when an older version left more than one. */
    caseVariants: string[];
  }>;
  removedObjectsFromOrg: Array<{
    objectName: string;
    label: string;
    fieldCount: number;
    referencedInGroups: string[];
  }>;
}

export interface PortalUserSummary {
  username: string;
  displayName: string;
  role: string;
  createdAt: string;
  lastLoginAt: string | null;
}

export interface PortalOverviewPayload {
  stats: {
    totalMcpRequests: number;
    allowedMcpRequests: number;
    deniedMcpRequests: number;
    erroredMcpRequests: number;
    totalProfiles: number;
    totalObjects: number;
    enabledObjects: number;
    totalGroups: number;
  };
  profiles: SalesforceProfile[];
  objects: SalesforceObject[];
  groups: AccessGroup[];
  profileGroupMappings: ProfileGroupMapping[];
  /**
   * The policy revision these lists are at: 1 on a new database and one more for every committed change
   * to Profiles, Objects, fields, Access Groups or their mappings. It never goes down.
   */
  policyRevision: number;
  /** The server's clock when it answered, for placing log rows from a browser with a different clock. */
  serverTime: string;
  copilotLogs: CopilotMcpLogRecord[];
  /** Read from the whole log, unlike copilotLogs, which holds only the latest rows of each kind. */
  mcpActivity: McpActivityFigures;
  /** The dashboard chart's counts, also read from the whole log. */
  mcpTraffic: McpTrafficSeries;
  portalLogs: PortalAdminLogRecord[];
  /** The most rows of each kind the two log lists hold. */
  logCaps: {
    copilotLogs: { calls: number; simulated: number; rejected: number };
    portalLogs: { events: number; simulations: number };
  };
  oktaSettings: OktaSsoSettings;
  sfSettings: SalesforceConnectionSettings;
  portalUsers: PortalUserSummary[];
}

export type SalesforceObjectConfig = SalesforceObject;
export type CopilotMcpLogEntry = CopilotMcpLogRecord;
export type PortalAdminLogEntry = PortalAdminLogRecord;
export type OktaConfig = OktaSsoSettings;
export type PortalUser = PortalUserSummary;
export type OrgProfilesPullPreview = ProfileSyncDiffPreview;
export type OrgObjectsSyncPreview = ObjectSyncDiffPreview;

