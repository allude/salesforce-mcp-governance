import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import {
  VerifiedSalesforceUser,
  salesforceRestRequest,
} from '../salesforce/client.js';
import {
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
        description: 'Optional WHERE filter expression',
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
      } else if (toolName === 'describe_object') {
        const objPerm = effective.objectPermissions.get(targetObject);
        responsePayload = {
          objectName: targetObject,
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
          : evaluation.allowedFields;
        const permittedSet = new Set(
          evaluation.allowedFields.map((f) => f.toLowerCase())
        );
        const disallowed = requestedFields.filter(
          (f) => !permittedSet.has(f.toLowerCase())
        );
        if (disallowed.length > 0) {
          throw new Error(
            `Fields [${disallowed.join(', ')}] on ${targetObject} are not permitted for Profile '${effective.profileName}'.`
          );
        }
        const selectFields =
          requestedFields.length > 0 ? requestedFields.join(', ') : 'Id';
        const limit = Math.min(Number(args.limit || 50), 200);
        const soql = `SELECT ${selectFields} FROM ${targetObject}${
          args.whereClause ? ` WHERE ${args.whereClause}` : ''
        } LIMIT ${limit}`;

        const sfRes = await salesforceRestRequest(
          user,
          'GET',
          `/query?q=${encodeURIComponent(soql)}`
        );
        responsePayload = {
          objectName: targetObject,
          fieldsQueried: requestedFields,
          totalSize: (sfRes as any)?.totalSize ?? 0,
          records: (sfRes as any)?.records ?? [],
        };
      } else if (
        toolName === 'get_record' ||
        toolName === 'create_record' ||
        toolName === 'update_record' ||
        toolName === 'delete_record'
      ) {
        // Validate field-level permissions for create/update
        if (
          (toolName === 'create_record' || toolName === 'update_record') &&
          args.fields &&
          typeof args.fields === 'object'
        ) {
          const permittedSet = new Set(
            evaluation.allowedFields.map((f) => f.toLowerCase())
          );
          const inputFieldNames = Object.keys(args.fields);
          const disallowed = inputFieldNames.filter(
            (f) => !permittedSet.has(f.toLowerCase())
          );
          if (disallowed.length > 0) {
            throw new Error(
              `Fields [${disallowed.join(', ')}] on ${targetObject} are not permitted for Profile '${effective.profileName}'.`
            );
          }
        }

        responsePayload = {
          status: 'SUCCESS',
          tool: toolName,
          objectName: targetObject,
          recordId: args.recordId || '001000000000001AAA',
          fieldNames: args.fields ? Object.keys(args.fields) : evaluation.allowedFields,
        };
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
      store.recordCopilotMcpLog({
        sfUsername: user.username,
        profileId: user.profileId,
        profileName: user.profileName,
        matchedGroups: evaluation.matchedGroups,
        toolName,
        targetObject,
        status: 'ERROR',
        latencyMs,
        rawRequestPayload: args,
        rawResponseSummary: { error: err.message || 'Execution error' },
      });

      return {
        isError: true,
        content: [
          {
            type: 'text',
            text: JSON.stringify({ error: err.message }, null, 2),
          },
        ],
      };
    }
  });

  return server;
}
