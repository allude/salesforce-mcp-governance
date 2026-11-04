// How a tools/call's arguments are read. The policy engine checks them with these readers and the
// tool handlers then read them with the same ones, so a handler never acts on a value read
// differently from the one that was checked.
import { SALESFORCE_API_NAME_PATTERN } from '../db/importers.js';

export type ToolArguments = Record<string, unknown>;

export const API_NAME_PATTERN = SALESFORCE_API_NAME_PATTERN;

const RECORD_ID_PATTERN = /^[a-zA-Z0-9]{15}(?:[a-zA-Z0-9]{3})?$/;

export const RECORD_ID_MESSAGE = 'recordId must be a 15 or 18-character Salesforce Record ID.';
export const FIELD_VALUES_MESSAGE = 'fields must be an object of field names to values.';

/** The `objectName` argument as text, or '*' when there is none. It is also the call's log target. */
export function targetObjectArgument(args: ToolArguments): string {
  return args.objectName ? String(args.objectName) : '*';
}

/** The trimmed `recordId`, or null when it is not a 15 or 18-character Salesforce ID. */
export function recordIdArgument(args: ToolArguments): string | null {
  const recordId = typeof args.recordId === 'string' ? args.recordId.trim() : '';
  return RECORD_ID_PATTERN.test(recordId) ? recordId : null;
}

/** The `fields` map of create_record and update_record, or null when it is not a non-empty object. */
export function fieldValuesArgument(args: ToolArguments): Record<string, unknown> | null {
  const fields = args.fields;
  if (!fields || typeof fields !== 'object' || Array.isArray(fields) || Object.keys(fields).length === 0) {
    return null;
  }
  return fields as Record<string, unknown>;
}

/** The fields soql_query and get_record select: the `fields` list, or else every allowed field. */
export function selectedFieldNames(args: ToolArguments, allowedFields: readonly string[]): string[] {
  return Array.isArray(args.fields)
    ? args.fields.map(String)
    : allowedFields.filter((f) => API_NAME_PATTERN.test(f));
}

/** The trimmed `whereClause` of soql_query, or '' when there is none. */
export function whereClauseArgument(args: ToolArguments): string {
  return typeof args.whereClause === 'string' && args.whereClause.trim() ? args.whereClause.trim() : '';
}
