---
name: mcp-tool-dev
description: >-
  Step-by-step developer workflow for adding or modifying governed MCP tools in the
  Salesforce MCP Server. Ensures Profile-to-Group RBAC enforcement, Object/Field
  allowlist filtering, and PII-stripped audit logging.
---

# MCP Tool Development Skill (`mcp-tool-dev`)

Use this skill whenever adding a new MCP tool or modifying an existing tool exposed to Microsoft Copilot on `POST /mcp`.

## Architectural Invariants

Every MCP tool in this repository must satisfy four non-negotiable guarantees:
1. **Dynamic Visibility (`tools/list`)**: A tool is only advertised to Microsoft Copilot if the caller's Salesforce `ProfileId` is mapped to at least one Access Group that grants that tool.
2. **Pre-Execution Policy Gate (`tools/call`)**: Every tool invocation must call `evaluateMcpToolCall(user, toolName, targetObject)` before touching Salesforce.
3. **Field-Level Allowlisting**: Any tool that reads (`SELECT`) or mutates (`POST`/`PATCH`) fields on a Salesforce object must validate requested field names against `evaluation.allowedFields`.
4. **PII-Stripped Telemetry**: Every invocation (whether `ALLOWED`, `DENIED`, or `ERROR`) must be logged via `store.recordCopilotMcpLog(...)`, which passes payloads through `stripSensitivePayloadData(...)` so raw customer record values are never stored in SQLite.

---

## Step-by-Step Checklist for Adding a New MCP Tool

### Step 1: Register the Action in `src/types/governance.ts`
Add the new action definition to `AVAILABLE_MCP_ACTIONS` in `src/types/governance.ts`:
```ts
{
  id: 'your_new_action_id',
  label: 'Human-Readable Action Label',
  category: 'Discovery' | 'Read' | 'Write' | 'Delete',
  description: 'Clear description shown to Copilot and in the Admin Group Editor.',
}
```
Adding it to `AVAILABLE_MCP_ACTIONS` automatically surfaces the checkbox in `# Access Matrix > ## Groups` (`src/components/views/AccessMatrixViews.tsx`).

### Step 2: Define the JSON Schema in `src/mcp/server.ts`
Add the input schema to `TOOL_INPUT_SCHEMAS` in `src/mcp/server.ts`. If the tool targets a specific Salesforce object, always name the parameter `objectName` so the policy engine automatically extracts `targetObject = String(args.objectName)`.

### Step 3: Enforce Object CRUD in `src/rbac/policyEngine.ts`
In `evaluateMcpToolCall` (`src/rbac/policyEngine.ts`), verify that the tool's required CRUD capability (`canRead`, `canCreate`, `canUpdate`, or `canDelete`) is checked against `objPerm`:
- Read tools (`soql_query`, `get_record`, `describe_object`, custom read tools) require `objPerm.canRead`.
- Create tools require `objPerm.canCreate`.
- Update tools require `objPerm.canUpdate`.
- Delete tools require `objPerm.canDelete`.

### Step 4: Implement the Handler & Field Scoping in `src/mcp/server.ts`
Inside `CallToolRequestSchema` handler in `src/mcp/server.ts`:
1. Validate any caller-supplied field names against `evaluation.allowedFields` (case-insensitive).
2. Escape any user-supplied filter strings using `escapeSoqlString(val)` from `src/salesforce/client.ts`.
3. Execute the Salesforce call via `salesforceRestRequest(user, method, path, body)` so the per-user Salesforce OAuth Bearer token is used.
4. Return a concise response structure and let `store.recordCopilotMcpLog(...)` redact literal values before persisting to SQLite.

### Step 5: Verify
Run the `verify-and-test` skill (`NODE_ENV=test npx tsx src/test-self.ts && npx next build`) to confirm no TypeScript or policy regressions were introduced.
