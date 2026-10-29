import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import {
  VerifiedSalesforceUser,
  salesforceRestRequest,
} from '../salesforce/client.js';
import { assertSafeSoqlWhereClause } from './soqlGuard.js';
import { SALESFORCE_API_NAME_PATTERN } from '../db/importers.js';
import {
  PolicyViolationError,
  evaluateMcpToolCall,
  getVisibleToolsForUser,
  resolveEffectiveProfilePermissions,
} from '../rbac/policyEngine.js';
import { store } from '../db/store.js';

const TOOL_INPUT_SCHEMAS: Record<string, object> = {
  list_enabled_objects: {
    type: 'object',
    properties: {},
  },
  describe_object: {
    type: 'object',
    properties: {
      objectName: {
        type: 'string',
        description: 'Salesforce Object API Name (e.g., Account, Case)',
      },
    },
    required: ['objectName'],
  },
  soql_query: {
    type: 'object',
    properties: {
      objectName: {
        type: 'string',
        description: 'Primary Salesforce Object API Name being queried',
      },
      fields: {
        type: 'array',
        items: { type: 'string' },
        description: 'Fields to select (must be allowed by the user Group)',
      },
      whereClause: {
        type: 'string',
        description:
          "Optional WHERE filter expression using only allowed fields, literals and operators (no subqueries), e.g. StageName = 'Closed Won' AND Amount > 1000",
      },
      limit: {
        type: 'number',
        description: 'Maximum rows to return (default 50)',
      },
    },
    required: ['objectName'],
  },
  get_record: {
    type: 'object',
    properties: {
      objectName: { type: 'string', description: 'Salesforce Object API Name' },
      recordId: { type: 'string', description: '15 or 18-character Record ID' },
      fields: {
        type: 'array',
        items: { type: 'string' },
        description: 'Fields to return (defaults to every field allowed for your Profile)',
      },
    },
    required: ['objectName', 'recordId'],
  },
  create_record: {
    type: 'object',
    properties: {
      objectName: { type: 'string', description: 'Salesforce Object API Name' },
      fields: {
        type: 'object',
        description: 'Key-value map of allowed fields and values to create',
      },
    },
    required: ['objectName', 'fields'],
  },
  update_record: {
    type: 'object',
    properties: {
      objectName: { type: 'string', description: 'Salesforce Object API Name' },
      recordId: { type: 'string', description: '15 or 18-character Record ID' },
      fields: {
        type: 'object',
        description: 'Key-value map of allowed fields and values to update',
      },
    },
    required: ['objectName', 'recordId', 'fields'],
  },
  delete_record: {
    type: 'object',
    properties: {
      objectName: { type: 'string', description: 'Salesforce Object API Name' },
      recordId: { type: 'string', description: '15 or 18-character Record ID' },
    },
    required: ['objectName', 'recordId'],
  },
};

const RECORD_ID_PATTERN = /^[a-zA-Z0-9]{15}(?:[a-zA-Z0-9]{3})?$/;
const API_NAME_PATTERN = SALESFORCE_API_NAME_PATTERN;

function requireRecordId(args: Record<string, any>): string {
  const recordId = typeof args.recordId === 'string' ? args.recordId.trim() : '';
  if (!RECORD_ID_PATTERN.test(recordId)) {
    throw new Error('recordId must be a 15 or 18-character Salesforce Record ID.');
  }
  return recordId;
}

/** Field names must all be in the Profile's allowlist (case-insensitive). */
function assertFieldsAllowed(
  fieldNames: string[],
  allowedFields: string[],
  objectName: string,
  profileName: string
): void {
  // Names stored before API-name validation existed are re-checked, since they go into SOQL/URLs.
  const permittedSet = new Set(
    allowedFields.filter((f) => API_NAME_PATTERN.test(f)).map((f) => f.toLowerCase())
  );
  const disallowed = fieldNames.filter((f) => !permittedSet.has(f.toLowerCase()));
  if (disallowed.length > 0) {
    throw new PolicyViolationError(
      `Fields [${disallowed.join(', ')}] on ${objectName} are not permitted for Profile '${profileName}'.`
    );
  }
}

function requireFieldValues(args: Record<string, any>): Record<string, unknown> {
  const fields = args.fields;
  if (!fields || typeof fields !== 'object' || Array.isArray(fields) || Object.keys(fields).length === 0) {
    throw new Error('fields must be an object of field names to values.');
  }
  return fields as Record<string, unknown>;
}

export function createUserScopedMcpServer(user: VerifiedSalesforceUser): Server {
  const server = new Server(
    {
      name: 'salesforce-governance-mcp-server',
      version: '3.0.0',
    },
    {
      capabilities: {
        tools: {},
      },
    }
  );

  // 1. tools/list — Only expose tools granted to the caller's Profile via its assigned Groups
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    const visible = getVisibleToolsForUser(user);
    return {
      tools: visible.map((t) => ({
        name: t.id,
        description: t.description,
        inputSchema: TOOL_INPUT_SCHEMAS[t.id] || {
          type: 'object',
          properties: {},
        },
      })),
    };
  });

  // 2. tools/call — Enforce Profile -> Group -> Object/Field permissions and log with stripped PII
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const startTime = Date.now();
    const toolName = request.params.name;
    const args = (request.params.arguments || {}) as Record<string, any>;
    const targetObject = args.objectName ? String(args.objectName) : '*';

    const evaluation = evaluateMcpToolCall(user, toolName, targetObject);
    if (!evaluation.permitted) {
      const latencyMs = Math.max(1, Date.now() - startTime);
      store.recordCopilotMcpLog({
        sfUsername: user.username,
        profileId: user.profileId,
        profileName: user.profileName,
        matchedGroups: evaluation.matchedGroups,
        toolName,
        targetObject,
        status: 'DENIED',
        latencyMs,
        rawRequestPayload: args,
        rawResponseSummary: {
          error: 'ACCESS_DENIED',
          reason: evaluation.reason,
        },
      });

      return {
        isError: true,
        content: [
          {
            type: 'text',
            text: JSON.stringify(
              {
                error: 'ACCESS_DENIED',
                tool: toolName,
                targetObject,
                profileId: user.profileId,
                profileName: user.profileName,
                reason: evaluation.reason,
              },
              null,
              2
            ),
          },
        ],
      };
    }

    try {
      const effective = resolveEffectiveProfilePermissions(
        user.profileId,
        user.profileName
      );
      let responsePayload: Record<string, unknown> = {};

      if (toolName === 'list_enabled_objects') {
        const objects = Array.from(effective.objectPermissions.values()).map(
          (o) => ({
            objectName: o.objectName,
            canRead: o.canRead,
            canCreate: o.canCreate,
            canUpdate: o.canUpdate,
            canDelete: o.canDelete,
            allowedFieldCount: o.allowedFields.size,
          })
        );
        responsePayload = {
          profileId: effective.profileId,
          profileName: effective.profileName,
          assignedGroups: effective.assignedGroups.map((g) => g.name),
          objects,
        };
      } else {
        // Every other tool is object-scoped; the policy engine returned the canonical object name.
        const objectName = evaluation.objectName || targetObject;
        if (!API_NAME_PATTERN.test(objectName)) {
          throw new Error(`Object '${objectName}' is not a valid Salesforce API name.`);
        }

        if (toolName === 'describe_object') {
          const objPerm = effective.objectPermissions.get(objectName);
          responsePayload = {
            objectName,
            permissions: {
              canRead: objPerm?.canRead || false,
              canCreate: objPerm?.canCreate || false,
              canUpdate: objPerm?.canUpdate || false,
              canDelete: objPerm?.canDelete || false,
            },
            allowedFields: evaluation.allowedFields,
          };
        } else if (toolName === 'soql_query') {
          const requestedFields: string[] = Array.isArray(args.fields)
            ? args.fields.map(String)
            : evaluation.allowedFields.filter((f) => API_NAME_PATTERN.test(f));
          assertFieldsAllowed(requestedFields, evaluation.allowedFields, objectName, effective.profileName);

          const whereClause =
            typeof args.whereClause === 'string' && args.whereClause.trim()
              ? args.whereClause.trim()
              : '';
          if (whereClause) {
            assertSafeSoqlWhereClause(whereClause, evaluation.allowedFields);
          }

          const selectFields =
            requestedFields.length > 0 ? requestedFields.join(', ') : 'Id';
          const requestedLimit = Math.floor(Number(args.limit));
          const limit = Number.isFinite(requestedLimit) && requestedLimit > 0 ? Math.min(requestedLimit, 200) : 50;
          const soql = `SELECT ${selectFields} FROM ${objectName}${
            whereClause ? ` WHERE ${whereClause}` : ''
          } LIMIT ${limit}`;

          const sfRes = await salesforceRestRequest(
            user,
            'GET',
            `/query?q=${encodeURIComponent(soql)}`
          );
          responsePayload = {
            objectName,
            fieldsQueried: requestedFields,
            totalSize: (sfRes as any)?.totalSize ?? 0,
            records: (sfRes as any)?.records ?? [],
          };
        } else if (toolName === 'get_record') {
          const recordId = requireRecordId(args);
          const requestedFields: string[] = Array.isArray(args.fields)
            ? args.fields.map(String)
            : evaluation.allowedFields.filter((f) => API_NAME_PATTERN.test(f));
          assertFieldsAllowed(requestedFields, evaluation.allowedFields, objectName, effective.profileName);
          const fieldList = requestedFields.length > 0 ? requestedFields : ['Id'];

          const record = await salesforceRestRequest(
            user,
            'GET',
            `/sobjects/${objectName}/${recordId}?fields=${encodeURIComponent(fieldList.join(','))}`
          );
          responsePayload = {
            objectName,
            recordId,
            fieldsReturned: fieldList,
            record,
          };
        } else if (toolName === 'create_record') {
          const fieldValues = requireFieldValues(args);
          assertFieldsAllowed(Object.keys(fieldValues), evaluation.allowedFields, objectName, effective.profileName);

          const sfRes = await salesforceRestRequest<{ id?: string; success?: boolean; errors?: unknown[] }>(
            user,
            'POST',
            `/sobjects/${objectName}`,
            fieldValues
          );
          responsePayload = {
            status: 'SUCCESS',
            tool: toolName,
            objectName,
            recordId: sfRes?.id,
            fieldNames: Object.keys(fieldValues),
          };
        } else if (toolName === 'update_record') {
          const recordId = requireRecordId(args);
          const fieldValues = requireFieldValues(args);
          assertFieldsAllowed(Object.keys(fieldValues), evaluation.allowedFields, objectName, effective.profileName);

          await salesforceRestRequest(user, 'PATCH', `/sobjects/${objectName}/${recordId}`, fieldValues);
          responsePayload = {
            status: 'SUCCESS',
            tool: toolName,
            objectName,
            recordId,
            fieldNames: Object.keys(fieldValues),
          };
        } else if (toolName === 'delete_record') {
          const recordId = requireRecordId(args);
          await salesforceRestRequest(user, 'DELETE', `/sobjects/${objectName}/${recordId}`);
          responsePayload = {
            status: 'SUCCESS',
            tool: toolName,
            objectName,
            recordId,
          };
        }
      }

      const latencyMs = Math.max(1, Date.now() - startTime);
      store.recordCopilotMcpLog({
        sfUsername: user.username,
        profileId: effective.profileId,
        profileName: effective.profileName,
        matchedGroups: evaluation.matchedGroups,
        toolName,
        targetObject,
        status: 'ALLOWED',
        latencyMs,
        rawRequestPayload: args,
        rawResponseSummary: responsePayload,
      });

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(responsePayload, null, 2),
          },
        ],
      };
    } catch (err: any) {
      const latencyMs = Math.max(1, Date.now() - startTime);
      const denied = err instanceof PolicyViolationError;
      store.recordCopilotMcpLog({
        sfUsername: user.username,
        profileId: user.profileId,
        profileName: user.profileName,
        matchedGroups: evaluation.matchedGroups,
        toolName,
        targetObject,
        status: denied ? 'DENIED' : 'ERROR',
        latencyMs,
        rawRequestPayload: args,
        rawResponseSummary: denied
          ? { error: 'ACCESS_DENIED', reason: err.message }
          : { error: err.message || 'Execution error' },
      });

      return {
        isError: true,
        content: [
          {
            type: 'text',
            text: JSON.stringify(
              denied
                ? { error: 'ACCESS_DENIED', tool: toolName, targetObject, reason: err.message }
                : { error: err.message },
              null,
              2
            ),
          },
        ],
      };
    }
  });

  return server;
}
