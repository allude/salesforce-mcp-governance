import { Request, Response } from 'express';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import {
  forgetVerifiedToken,
  isSimulatorToken,
  resolveSalesforceUserFromToken,
  SalesforceUnavailableError,
  salesforceAuthorizationBase,
} from '../salesforce/client.js';
import { VerificationBusyError } from '../salesforce/verificationGate.js';
import { parseBearerToken } from './bearer.js';
import { createUserScopedMcpServer } from './server.js';
import { config } from '../config.js';
import { store, UNVERIFIED_CALLER_USERNAME } from '../db/store.js';

/** Keeps reflected error text header-safe: printable ASCII only, no quotes or backslashes. */
export function toHeaderSafe(text: string): string {
  return text.replace(/[^\x20-\x7e]|["\\]/g, "'").slice(0, 300);
}

export async function handleMcpStreamableHttpRequest(
  req: Request,
  res: Response
): Promise<void> {
  const bearerToken = parseBearerToken(req.headers.authorization);
  if (!bearerToken) {
    const authUrl = salesforceAuthorizationBase();
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

  const instanceUrlHint = req.headers['x-salesforce-instance-url'] as
    | string
    | undefined;

  let verifiedUser;
  try {
    // Refused like any invalid token, so it is logged and counts toward the failed-attempt limit.
    if (config.isProd && isSimulatorToken(bearerToken)) {
      throw new Error('Simulator tokens are not accepted in production');
    }
    verifiedUser = await resolveSalesforceUserFromToken(
      bearerToken,
      instanceUrlHint
    );
  } catch (err: any) {
    // Capacity, not a verdict on the token: no log row, and the client keeps its token and retries.
    if (err instanceof VerificationBusyError) {
      res.setHeader('Retry-After', '5');
      res.status(503).json({ jsonrpc: '2.0', error: { code: -32000, message: err.message }, id: null });
      return;
    }
    // Salesforce gave no verdict: logged and counted like a rejection (the token is still unverified),
    // but a token that verified before keeps its exemption, and the client is told to retry, not
    // that its token is invalid.
    const unavailable = err instanceof SalesforceUnavailableError;
    if (!unavailable) forgetVerifiedToken(bearerToken);
    res.locals.tokenNotVerified = true;
    store.recordCopilotMcpLog({
      sfUsername: UNVERIFIED_CALLER_USERNAME,
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

    if (unavailable) {
      res.setHeader('Retry-After', '5');
      res.status(503).json({ jsonrpc: '2.0', error: { code: -32000, message: err.message }, id: null });
      return;
    }

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
