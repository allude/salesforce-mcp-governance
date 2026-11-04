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
  API_NAME_PATTERN,
  FIELD_VALUES_MESSAGE,
  RECORD_ID_MESSAGE,
  fieldValuesArgument,
  recordIdArgument,
  selectedFieldNames,
  targetObjectArgument,
  whereClauseArgument,
} from './toolArguments.js';
import {
  decisionLogStatus,
  evaluatePolicy,
  getVisibleToolsForUser,
  loadPolicySnapshot,
  resolveEffectiveProfilePermissions,
  type PolicyDecision,
} from '../rbac/policyEngine.js';
import { store } from '../db/store.js';
import type { McpActionId } from '../types/governance.js';

// Keyed by McpActionId: a tool added to the catalog without a schema here does not compile.
export const TOOL_INPUT_SCHEMAS: Record<McpActionId, object> = {
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

// evaluatePolicy has refused a call whose record id or field values these would refuse. They still
// throw rather than pass an unchecked value into a URL or a request body.
function requireRecordId(args: Record<string, any>): string {
  const recordId = recordIdArgument(args);
  if (recordId === null) throw new Error(RECORD_ID_MESSAGE);
  return recordId;
}

function requireFieldValues(args: Record<string, any>): Record<string, unknown> {
  const fields = fieldValuesArgument(args);
  if (fields === null) throw new Error(FIELD_VALUES_MESSAGE);
  return fields;
}

/**
 * What the caller is told about a refused call, and the log row's summary of it. A refused tool or
 * Object (anything decided before the CRUD check passed, a missing or malformed objectName included)
 * names the Profile; a refused field or WHERE filter does not; a malformed argument, or a policy that
 * could not be evaluated, is a plain error.
 */
function refusalPayload(
  decision: PolicyDecision,
  toolName: string,
  targetObject: string,
  user: VerifiedSalesforceUser
): { body: Record<string, unknown>; summary: Record<string, unknown> } {
  const { code, reason } = decision;
  if (code === 'FIELD_NOT_PERMITTED' || code === 'WHERE_FIELD_NOT_PERMITTED') {
    return {
      body: { error: 'ACCESS_DENIED', tool: toolName, targetObject, reason },
      summary: { error: 'ACCESS_DENIED', reason },
    };
  }
  const passedCrud = decision.steps.some((s) => s.stage === 'crud' && s.result === 'pass');
  if (decision.outcome === 'error' || (code === 'INPUT_INVALID' && passedCrud)) {
    return { body: { error: reason }, summary: { error: reason } };
  }
  return {
    body: {
      error: 'ACCESS_DENIED',
      tool: toolName,
      targetObject,
      profileId: user.profileId,
      profileName: user.profileName,
      reason,
    },
    summary: { error: 'ACCESS_DENIED', reason },
  };
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
    const targetObject = targetObjectArgument(args);

    // One snapshot per call: the decision and the handler below act on the same policy.
    const snapshot = loadPolicySnapshot();
    const decision = evaluatePolicy(user, toolName, args, snapshot);
    const matchedGroups = decision.assignedGroups.map((g) => g.name);
    if (decision.outcome !== 'allowed') {
      const latencyMs = Math.max(1, Date.now() - startTime);
      const refusal = refusalPayload(decision, toolName, targetObject, user);
      store.recordCopilotMcpLog({
        sfUsername: user.username,
        simulated: user.simulated,
        profileId: user.profileId,
        profileName: user.profileName,
        matchedGroups,
        toolName,
        targetObject,
        status: decisionLogStatus(decision),
        latencyMs,
        rawRequestPayload: args,
        rawResponseSummary: refusal.summary,
      });

      return {
        isError: true,
        content: [
          {
            type: 'text',
            text: JSON.stringify(refusal.body, null, 2),
          },
        ],
      };
    }

    try {
      const effective = resolveEffectiveProfilePermissions(
        user.profileId,
        user.profileName,
        snapshot
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
        // Every other tool is object-scoped. evaluatePolicy returned the canonical object name and
        // checked it, the record id, the field names and the WHERE clause; this check stays so that no
        // unchecked name can reach SOQL or a REST path.
        const objectName = decision.objectName || targetObject;
        if (!API_NAME_PATTERN.test(objectName)) {
          throw new Error(`Object '${objectName}' is not a valid Salesforce API name.`);
        }

        // Fields an admin kept after a sync removed them from the org. They stay in policy, but
        // sending them to Salesforce would fail the whole call, so they are left out and reported.
        const objPerm = effective.objectPermissions.get(objectName);
        const missingInOrg = new Set(
          Array.from(objPerm?.missingInOrgFields || []).map((f) => f.toLowerCase())
        );
        const isMissingInOrg = (field: string) => missingInOrg.has(field.toLowerCase());
        const withIgnoredFields = (ignored: string[]) =>
          ignored.length > 0 ? { ignoredMissingFields: ignored } : {};

        if (toolName === 'describe_object') {
          responsePayload = {
            objectName,
            permissions: {
              canRead: objPerm?.canRead || false,
              canCreate: objPerm?.canCreate || false,
              canUpdate: objPerm?.canUpdate || false,
              canDelete: objPerm?.canDelete || false,
            },
            allowedFields: decision.allowedFields,
            activeOrgFields: decision.allowedFields.filter((f) => !isMissingInOrg(f)),
          };
        } else if (toolName === 'soql_query') {
          const requestedFields = selectedFieldNames(args, decision.allowedFields);
          const whereClause = whereClauseArgument(args);

          const ignoredMissingFields = requestedFields.filter(isMissingInOrg);
          let activeFields = requestedFields.filter((f) => !isMissingInOrg(f));

          const requestedLimit = Math.floor(Number(args.limit));
          const limit = Number.isFinite(requestedLimit) && requestedLimit > 0 ? Math.min(requestedLimit, 200) : 50;
          const runQuery = () => {
            const soql = `SELECT ${activeFields.length > 0 ? activeFields.join(', ') : 'Id'} FROM ${objectName}${
              whereClause ? ` WHERE ${whereClause}` : ''
            } LIMIT ${limit}`;
            return salesforceRestRequest(user, 'GET', `/query?q=${encodeURIComponent(soql)}`);
          };

          let sfRes: unknown;
          try {
            sfRes = await runQuery();
          } catch (queryErr: any) {
            // A field deleted in the org since the last sync: drop it from the SELECT and retry once.
            // Only a field this call selected qualifies; a bad WHERE field still fails.
            const invalidField = String(queryErr?.message || '').match(/No such column '([^']+)'/i)?.[1];
            const selected = invalidField
              ? activeFields.find((f) => f.toLowerCase() === invalidField.toLowerCase())
              : undefined;
            if (!selected) throw queryErr;
            ignoredMissingFields.push(selected);
            activeFields = activeFields.filter((f) => f !== selected);
            sfRes = await runQuery();
          }
          responsePayload = {
            objectName,
            fieldsQueried: activeFields.length > 0 ? activeFields : ['Id'],
            ...withIgnoredFields(ignoredMissingFields),
            totalSize: (sfRes as any)?.totalSize ?? 0,
            records: (sfRes as any)?.records ?? [],
          };
        } else if (toolName === 'get_record') {
          const recordId = requireRecordId(args);
          const requestedFields = selectedFieldNames(args, decision.allowedFields);
          const activeFields = requestedFields.filter((f) => !isMissingInOrg(f));
          const fieldList = activeFields.length > 0 ? activeFields : ['Id'];

          const record = await salesforceRestRequest(
            user,
            'GET',
            `/sobjects/${objectName}/${recordId}?fields=${encodeURIComponent(fieldList.join(','))}`
          );
          responsePayload = {
            objectName,
            recordId,
            fieldsReturned: fieldList,
            ...withIgnoredFields(requestedFields.filter(isMissingInOrg)),
            record,
          };
        } else if (toolName === 'create_record' || toolName === 'update_record') {
          const recordId = toolName === 'update_record' ? requireRecordId(args) : undefined;
          const fieldValues = requireFieldValues(args);

          const ignoredMissingFields = Object.keys(fieldValues).filter(isMissingInOrg);
          const activeValues = Object.fromEntries(
            Object.entries(fieldValues).filter(([field]) => !isMissingInOrg(field))
          );
          if (Object.keys(activeValues).length === 0) {
            throw new Error(`Every field in this ${toolName} call no longer exists in the Salesforce org.`);
          }

          let writtenId = recordId;
          if (recordId) {
            await salesforceRestRequest(user, 'PATCH', `/sobjects/${objectName}/${recordId}`, activeValues);
          } else {
            const sfRes = await salesforceRestRequest<{ id?: string; success?: boolean; errors?: unknown[] }>(
              user,
              'POST',
              `/sobjects/${objectName}`,
              activeValues
            );
            writtenId = sfRes?.id;
          }
          responsePayload = {
            status: 'SUCCESS',
            tool: toolName,
            objectName,
            recordId: writtenId,
            fieldNames: Object.keys(activeValues),
            ...withIgnoredFields(ignoredMissingFields),
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
        simulated: user.simulated,
        profileId: effective.profileId,
        profileName: effective.profileName,
        matchedGroups,
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
      // The policy allowed the call, so what failed is the call itself: Salesforce, or an org that no
      // longer has any of the fields it writes.
      const latencyMs = Math.max(1, Date.now() - startTime);
      store.recordCopilotMcpLog({
        sfUsername: user.username,
        simulated: user.simulated,
        profileId: user.profileId,
        profileName: user.profileName,
        matchedGroups,
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
