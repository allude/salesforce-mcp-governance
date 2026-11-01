export type NavViewId =
  | 'dashboard'
  | 'sf-profiles'
  | 'sf-objects'
  | 'matrix-groups'
  | 'matrix-profile-groups'
  | 'logs-copilot'
  | 'logs-portal'
  | 'settings-auth';

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

export interface SalesforceProfile {
  id: string; // 15 or 18-char Salesforce Profile ID (00e...)
  name: string;
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
  expectedOrgId: string;
  instanceUrl: string;
  apiVersion: string;
  enforceOrgIdLock: boolean;
  sfdxObjectsFolderPath: string;
  updatedAt: string;
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
