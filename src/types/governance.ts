export type NavViewId =
  | 'dashboard'
  | 'sf-profiles'
  | 'sf-objects'
  | 'matrix-groups'
  | 'matrix-profile-groups'
  | 'logs-copilot'
  | 'logs-portal'
  | 'settings-auth'
  | 'settings-salesforce';

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

export interface GroupObjectPermission {
  objectName: string;
  canRead: boolean;
  canCreate: boolean;
  canUpdate: boolean;
  canDelete: boolean;
  allowedFields: string[]; // Field API names from SalesforceObjectField
}

export interface AccessGroup {
  id: string;
  name: string;
  description: string;
  allowedActions: string[]; // McpActionId[]
  objectPermissions: GroupObjectPermission[];
  updatedAt: string;
}

export interface ProfileGroupMapping {
  profileId: string;
  groupIds: string[];
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
  latencyMs: number;
  sanitizedRequestPayload: string; // JSON with PII / record values stripped
  sanitizedResponseSummary: string; // JSON with record values stripped
}

export interface PortalAdminLogRecord {
  id: string;
  timestamp: string;
  adminUsername: string;
  authMethod: 'password' | 'okta_sso';
  action: string;
  target: string;
  details: string;
  ipAddress: string;
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
  hasPrivateKey: boolean;
  certificatePem: string;
  certFingerprint: string;
  connectionStatus: 'connected' | 'disconnected' | 'error';
  lastConnectedAt: string | null;
  lastError: string;
  connectedOrgId: string;
  connectedUser: string;
  expectedOrgId: string;
  instanceUrl: string;
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
  copilotLogs: CopilotMcpLogRecord[];
  portalLogs: PortalAdminLogRecord[];
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

