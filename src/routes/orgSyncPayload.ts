import { SALESFORCE_API_NAME_PATTERN } from '../db/importers.js';

// The apply routes take back what their preview returned, through the browser, so none of it is
// trusted: every entry is checked before the first write and only these named properties survive.

export type PayloadResult<T> = { ok: true; value: T } | { ok: false; error: string };

export interface ObjectSyncPayload {
  pulledMetadata: Array<{
    objectName: string;
    label?: string;
    isCustom?: boolean;
    existsInOrg: boolean;
    fields: Array<{
      fieldName: string;
      label?: string;
      fieldType?: string;
      isCustom?: boolean;
      required?: boolean;
    }>;
  }>;
  removeObjectNames: string[];
  removeFields: Array<{ objectName: string; fieldName: string }>;
}

export interface ProfileSyncPayload {
  upserts: Array<{ id: string; name: string }>;
  removeProfileIds: string[];
  keptMissingProfileIds: string[];
}

class InvalidPayload extends Error {}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

function requireArray(value: unknown, path: string): unknown[] {
  if (!Array.isArray(value)) throw new InvalidPayload(`${path} must be an array.`);
  return value;
}

function requireRecord(value: unknown, path: string): Record<string, unknown> {
  if (!isRecord(value)) throw new InvalidPayload(`${path} must be an object.`);
  return value;
}

function requireString(value: unknown, path: string): string {
  if (typeof value !== 'string' || !value.trim()) {
    throw new InvalidPayload(`${path} must be a non-empty string.`);
  }
  return value;
}

function requireApiName(value: unknown, path: string): string {
  const name = requireString(value, path);
  if (!SALESFORCE_API_NAME_PATTERN.test(name)) {
    throw new InvalidPayload(`${path} is not a valid Salesforce API name: ${JSON.stringify(name.slice(0, 80))}.`);
  }
  return name;
}

function optionalString(value: unknown, path: string): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== 'string') throw new InvalidPayload(`${path} must be a string.`);
  return value;
}

function optionalBoolean(value: unknown, path: string): boolean | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== 'boolean') throw new InvalidPayload(`${path} must be true or false.`);
  return value;
}

/** A remove list may be left out, but what is sent must be well formed. */
function optionalStringList(value: unknown, path: string): string[] {
  if (value === undefined) return [];
  return requireArray(value, path).map((entry, i) => requireString(entry, `${path}[${i}]`));
}

function collect<T>(read: () => T): PayloadResult<T> {
  try {
    return { ok: true, value: read() };
  } catch (err) {
    if (err instanceof InvalidPayload) return { ok: false, error: err.message };
    throw err;
  }
}

export function parseObjectSyncPayload(body: unknown): PayloadResult<ObjectSyncPayload> {
  return collect(() => {
    const input = requireRecord(body, 'The request body');
    if (!Array.isArray(input.pulledMetadata)) {
      throw new InvalidPayload('pulledMetadata array is required.');
    }

    const existsByName = new Map<string, boolean>();
    const pulledMetadata = input.pulledMetadata.map((rawEntry, i) => {
      const path = `pulledMetadata[${i}]`;
      const entry = requireRecord(rawEntry, path);
      const objectName = requireApiName(entry.objectName, `${path}.objectName`);
      // Strict: a missing value read as false would flag the object as gone, or delete it.
      if (typeof entry.existsInOrg !== 'boolean') {
        throw new InvalidPayload(`${path}.existsInOrg must be true or false.`);
      }
      const existsInOrg = entry.existsInOrg;

      const reportedBefore = existsByName.get(objectName.toLowerCase());
      if (reportedBefore !== undefined && reportedBefore !== existsInOrg) {
        throw new InvalidPayload(`${path} contradicts an earlier entry about whether ${objectName} exists in the org.`);
      }
      existsByName.set(objectName.toLowerCase(), existsInOrg);

      const fields = requireArray(entry.fields, `${path}.fields`).map((rawField, j) => {
        const fieldPath = `${path}.fields[${j}]`;
        const field = requireRecord(rawField, fieldPath);
        return {
          fieldName: requireApiName(field.fieldName, `${fieldPath}.fieldName`),
          label: optionalString(field.label, `${fieldPath}.label`),
          fieldType: optionalString(field.fieldType, `${fieldPath}.fieldType`),
          isCustom: optionalBoolean(field.isCustom, `${fieldPath}.isCustom`),
          required: optionalBoolean(field.required, `${fieldPath}.required`),
        };
      });
      // The pull itself treats this as a failed read; here it would report every local field as gone.
      if (existsInOrg && fields.length === 0) {
        throw new InvalidPayload(`${path}.fields is empty, but ${objectName} is reported as present in the org.`);
      }

      return {
        objectName,
        label: optionalString(entry.label, `${path}.label`),
        isCustom: optionalBoolean(entry.isCustom, `${path}.isCustom`),
        existsInOrg,
        fields,
      };
    });

    const removeFields =
      input.removeFields === undefined
        ? []
        : requireArray(input.removeFields, 'removeFields').map((rawRemove, i) => {
            const path = `removeFields[${i}]`;
            const remove = requireRecord(rawRemove, path);
            return {
              objectName: requireString(remove.objectName, `${path}.objectName`),
              fieldName: requireString(remove.fieldName, `${path}.fieldName`),
            };
          });

    return {
      pulledMetadata,
      removeObjectNames: optionalStringList(input.removeObjectNames, 'removeObjectNames'),
      removeFields,
    };
  });
}

export function parseProfileSyncPayload(body: unknown): PayloadResult<ProfileSyncPayload> {
  return collect(() => {
    const input = requireRecord(body, 'The request body');
    if (!Array.isArray(input.upserts)) {
      throw new InvalidPayload('upserts array is required.');
    }
    return {
      upserts: input.upserts.map((rawUpsert, i) => {
        const path = `upserts[${i}]`;
        const upsert = requireRecord(rawUpsert, path);
        return {
          id: requireString(upsert.id, `${path}.id`),
          name: requireString(upsert.name, `${path}.name`),
        };
      }),
      removeProfileIds: optionalStringList(input.removeProfileIds, 'removeProfileIds'),
      keptMissingProfileIds: optionalStringList(input.keptMissingProfileIds, 'keptMissingProfileIds'),
    };
  });
}
