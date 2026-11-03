import type { ObjectSyncDiffPreview, RemovalResolutionAction } from '@/types/governance';

type Resolutions = Record<string, RemovalResolutionAction>;
type RemovedField = ObjectSyncDiffPreview['upsertedObjects'][number]['removedFieldsFromOrg'][number];

// The apply matches removals case-insensitively, because case variants are one object in the org.
// Variants share a resolution here too, so no row can show a Keep that the apply would not honour.
export const objectResolutionKey = (objectName: string): string => objectName.toLowerCase();

export const fieldResolutionKey = (objectName: string, fieldName: string): string =>
  `${objectName}.${fieldName}`.toLowerCase();

const removedFields = (preview: ObjectSyncDiffPreview): RemovedField[] =>
  preview.upsertedObjects.flatMap((uo) => uo.removedFieldsFromOrg);

/** Variants must reach the admin even with nothing to resolve: the apply changes every one of them. */
export function objectSyncNeedsReview(preview: ObjectSyncDiffPreview): boolean {
  return (
    preview.removedObjectsFromOrg.length > 0 ||
    removedFields(preview).length > 0 ||
    preview.upsertedObjects.some((uo) => uo.caseVariants.length > 0)
  );
}

export function otherObjectVariants(preview: ObjectSyncDiffPreview, objectName: string): string[] {
  const key = objectResolutionKey(objectName);
  return preview.removedObjectsFromOrg
    .map((mo) => mo.objectName)
    .filter((name) => name !== objectName && objectResolutionKey(name) === key);
}

export function otherFieldVariants(
  preview: ObjectSyncDiffPreview,
  field: { objectName: string; fieldName: string }
): string[] {
  const key = fieldResolutionKey(field.objectName, field.fieldName);
  const self = `${field.objectName}.${field.fieldName}`;
  return removedFields(preview)
    .map((mf) => ({ name: `${mf.objectName}.${mf.fieldName}`, key: fieldResolutionKey(mf.objectName, mf.fieldName) }))
    .filter((mf) => mf.name !== self && mf.key === key)
    .map((mf) => mf.name);
}

export function objectSyncRemovals(
  preview: ObjectSyncDiffPreview,
  objectResolutions: Resolutions,
  fieldResolutions: Resolutions
): { removeObjectNames: string[]; removeFields: Array<{ objectName: string; fieldName: string }> } {
  return {
    removeObjectNames: preview.removedObjectsFromOrg
      .filter((mo) => objectResolutions[objectResolutionKey(mo.objectName)] === 'DELETE')
      .map((mo) => mo.objectName),
    removeFields: removedFields(preview)
      .filter((mf) => fieldResolutions[fieldResolutionKey(mf.objectName, mf.fieldName)] === 'DELETE')
      .map((mf) => ({ objectName: mf.objectName, fieldName: mf.fieldName })),
  };
}
