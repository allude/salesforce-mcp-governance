// Starts the Express app in-process on a random port and wraps the HTTP calls tests need.
import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';
import { TEST_ADMIN } from './env.js';

export interface TestServer {
  baseUrl: string;
  close(): Promise<void>;
}

export async function startTestServer(): Promise<TestServer> {
  const { app } = await import('../../src/index.js');
  const server: Server = await new Promise((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s));
  });
  const { port } = server.address() as AddressInfo;
  return {
    baseUrl: `http://127.0.0.1:${port}`,
    close: () => new Promise((resolve) => server.close(() => resolve())),
  };
}

export interface AdminSession {
  cookie: string;
  csrfToken: string;
}

export async function loginAsAdmin(
  baseUrl: string,
  username = TEST_ADMIN.username,
  password = TEST_ADMIN.password
): Promise<AdminSession> {
  const res = await fetch(`${baseUrl}/api/admin/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });
  if (res.status !== 200) {
    throw new Error(`Admin login failed (${res.status}): ${await res.text()}`);
  }
  const cookie = (res.headers.get('set-cookie') || '').split(';')[0];
  const body = (await res.json()) as { csrfToken: string };
  return { cookie, csrfToken: body.csrfToken };
}

/** Calls an Admin API route with the session cookie and CSRF header. */
export async function adminFetch(
  baseUrl: string,
  session: AdminSession,
  path: string,
  init: { method?: string; body?: unknown } = {}
): Promise<{ status: number; body: any }> {
  const res = await fetch(`${baseUrl}${path}`, {
    method: init.method || 'GET',
    headers: {
      Cookie: session.cookie,
      'X-CSRF-Token': session.csrfToken,
      ...(init.body !== undefined ? { 'Content-Type': 'application/json' } : {}),
    },
    body: init.body !== undefined ? JSON.stringify(init.body) : undefined,
  });
  const text = await res.text();
  let body: any = text;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    // leave as text
  }
  return { status: res.status, body };
}

let rpcId = 0;

/** Sends one JSON-RPC request to the stateless /mcp endpoint. */
export async function mcpRequest(
  baseUrl: string,
  token: string | null,
  method: string,
  params: Record<string, unknown> = {},
  extraHeaders: Record<string, string> = {}
): Promise<{ status: number; headers: Headers; body: any }> {
  const res = await fetch(`${baseUrl}/mcp`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json, text/event-stream',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...extraHeaders,
    },
    body: JSON.stringify({ jsonrpc: '2.0', id: ++rpcId, method, params }),
  });
  const text = await res.text();
  let body: any = text;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    // leave as text
  }
  return { status: res.status, headers: res.headers, body };
}

/** Parses the JSON text content of a tools/call result. */
export function toolResultPayload(body: any): any {
  const text = body?.result?.content?.[0]?.text;
  return text ? JSON.parse(text) : undefined;
}
