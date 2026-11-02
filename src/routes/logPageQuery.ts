// Parses the query strings of the paged log routes. Anything malformed is refused rather than
// ignored, so a typo in a filter cannot silently widen what an export contains.
import type { CopilotMcpLogPageQuery, PortalAdminLogPageQuery } from '../db/store.js';

export const LOG_PAGE_DEFAULT_ROWS = 200;
export const LOG_PAGE_MAX_ROWS = 1000;
const MAX_FILTER_LENGTH = 255;

export class LogPageQueryError extends Error {}

type RawQuery = Record<string, unknown>;

/** A parameter sent at most once as plain text; Express turns repeats and brackets into arrays and objects. */
function single(query: RawQuery, name: string): string | undefined {
  const value = query[name];
  if (value === undefined) return undefined;
  if (typeof value !== 'string') throw new LogPageQueryError(`"${name}" must be given once, as text.`);
  return value;
}

function text(query: RawQuery, name: string): string | undefined {
  const value = single(query, name);
  if (value === undefined) return undefined;
  if (value === '' || value.length > MAX_FILTER_LENGTH) {
    throw new LogPageQueryError(`"${name}" must be 1 to ${MAX_FILTER_LENGTH} characters.`);
  }
  return value;
}

function oneOf<T extends string>(query: RawQuery, name: string, allowed: readonly T[]): T | undefined {
  const value = single(query, name);
  if (value === undefined) return undefined;
  if (!(allowed as readonly string[]).includes(value)) {
    throw new LogPageQueryError(`"${name}" must be one of: ${allowed.join(', ')}.`);
  }
  return value as T;
}

function positiveInteger(query: RawQuery, name: string): number | undefined {
  const value = single(query, name);
  if (value === undefined) return undefined;
  const parsed = /^[1-9]\d*$/.test(value) ? Number(value) : NaN;
  if (!Number.isSafeInteger(parsed)) throw new LogPageQueryError(`"${name}" must be a positive whole number.`);
  return parsed;
}

function cursor(query: RawQuery): { before?: number; limit: number } {
  const limit = positiveInteger(query, 'limit') ?? LOG_PAGE_DEFAULT_ROWS;
  if (limit > LOG_PAGE_MAX_ROWS) {
    throw new LogPageQueryError(`"limit" must be at most ${LOG_PAGE_MAX_ROWS}.`);
  }
  const before = positiveInteger(query, 'before');
  return before === undefined ? { limit } : { before, limit };
}

export function parseMcpLogPageQuery(query: RawQuery): CopilotMcpLogPageQuery {
  const parsed: CopilotMcpLogPageQuery = cursor(query);
  const status = oneOf(query, 'status', ['ALLOWED', 'DENIED', 'ERROR'] as const);
  if (status !== undefined) parsed.status = status;
  const simulated = oneOf(query, 'simulated', ['true', 'false'] as const);
  if (simulated !== undefined) parsed.simulated = simulated === 'true';
  const toolName = text(query, 'tool');
  if (toolName !== undefined) parsed.toolName = toolName;
  const targetObject = text(query, 'object');
  if (targetObject !== undefined) parsed.targetObject = targetObject;
  return parsed;
}

export function parsePortalLogPageQuery(query: RawQuery): PortalAdminLogPageQuery {
  const parsed: PortalAdminLogPageQuery = cursor(query);
  const action = text(query, 'action');
  if (action !== undefined) parsed.action = action;
  const authMethod = oneOf(query, 'authMethod', ['password', 'okta_sso'] as const);
  if (authMethod !== undefined) parsed.authMethod = authMethod;
  return parsed;
}
