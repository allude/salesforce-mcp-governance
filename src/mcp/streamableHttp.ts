import { Request, Response } from 'express';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { resolveSalesforceUserFromToken } from '../salesforce/client.js';
import { createUserScopedMcpServer } from './server.js';
import { config } from '../config.js';
import { store } from '../db/store.js';

/** Keeps reflected error text header-safe: printable ASCII only, no quotes or backslashes. */
function toHeaderSafe(text: string): string {
  return text.replace(/[^\x20-\x7e]|["\\]/g, "'").slice(0, 300);
}

export async function handleMcpStreamableHttpRequest(
  req: Request,
  res: Response
): Promise<void> {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.toLowerCase().startsWith('bearer ')) {
    const sfSettings = store.getSalesforceSettings();
    const authUrl = sfSettings.instanceUrl || 'https://login.salesforce.com';
    res.setHeader(
      'WWW-Authenticate',
      `Bearer realm="salesforce-mcp", resource_metadata="${config.baseUrl}/.well-known/oauth-protected-resource", authorization_uri="${authUrl}/services/oauth2/authorize"`
    );
    res.status(401).json({
      jsonrpc: '2.0',
      error: {
        code: -32001,
        message: 'Unauthorized: Missing per-user Salesforce OAuth 2.0 Bearer token.',
      },
      id: null,
    });
    return;
  }

  const bearerToken = authHeader.slice(7).trim();
  const instanceUrlHint = req.headers['x-salesforce-instance-url'] as
    | string
    | undefined;

  let verifiedUser;
  try {
    verifiedUser = await resolveSalesforceUserFromToken(
      bearerToken,
      instanceUrlHint
    );
  } catch (err: any) {
    store.recordCopilotMcpLog({
      sfUsername: 'unverified_caller',
      profileId: 'unverified',
      profileName: 'Unverified Token',
      matchedGroups: [],
      toolName: 'mcp_authenticate',
      targetObject: '*',
      status: 'DENIED',
      latencyMs: 1,
      rawRequestPayload: { method: req.body?.method || 'unknown' },
      rawResponseSummary: { error: err?.message || 'Token validation failed' },
    });

    res.setHeader(
      'WWW-Authenticate',
      `Bearer error="invalid_token", error_description="${toHeaderSafe(
        String(err?.message || 'Invalid Salesforce token')
      )}", resource_metadata="${config.baseUrl}/.well-known/oauth-protected-resource"`
    );
    res.status(401).json({
      jsonrpc: '2.0',
      error: {
        code: -32001,
        message: `Unauthorized: ${
          err?.message || 'Invalid or expired Salesforce Bearer token'
        }`,
      },
      id: null,
    });
    return;
  }

  try {
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      enableJsonResponse: true,
    });

    const mcpServer = createUserScopedMcpServer(verifiedUser);

    res.on('close', () => {
      transport.close().catch(() => {});
      mcpServer.close().catch(() => {});
    });

    await mcpServer.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (err: any) {
    if (!res.headersSent) {
      res.status(500).json({
        jsonrpc: '2.0',
        error: {
          code: -32603,
          message: `Internal MCP transport error: ${
            err?.message || String(err)
          }`,
        },
        id: null,
      });
    }
  }
}
