---
name: sfdx-parser-debugger
description: >-
  Guide for maintaining, testing, and extending the Salesforce DX (SFDX) object/field
  XML parser (`parseSfdxFilesToObjects`) and Profile CSV importer.
---

# SFDX Metadata & CSV Parser Skill (`sfdx-parser-debugger`)

Use this skill when working on `# Salesforce > ## Objects` or `# Salesforce > ## Profiles` import logic in `src/db/importers.ts` (the parsers), `src/db/store.ts` (persistence), `src/routes/adminRoutes.ts`, and `src/components/views/SalesforceViews.tsx`. Tests live in `test/importers.test.ts` (parsers) and `test/store.test.ts` / `test/admin-api.test.ts` (import routes).

## Supported Salesforce Project Formats

The object importer (`parseSfdxFilesToObjects` in `src/db/importers.ts`, re-exported by `src/db/store.ts`) supports two Salesforce directory layouts:

1. **Salesforce DX (SFDX) Source Format (`force-app/main/default/objects/`)**:
   - Object metadata: `objects/<ObjectName>/<ObjectName>.object-meta.xml`
   - Field metadata: `objects/<ObjectName>/fields/<FieldName>.field-meta.xml`
   - Standard objects extended in SFDX (where `<ObjectName>.object-meta.xml` may be omitted and only `fields/*.field-meta.xml` exist): the parser automatically infers `<ObjectName>` from the parent directory of `fields/`. Field files whose object cannot be determined from the path are skipped (never attributed to a made-up object).

2. **Classic Metadata API Format (`unpackaged/objects/`)**:
   - Monolithic object file: `objects/<ObjectName>.object` containing inline `<fields>...</fields>` XML blocks.

Only **top-level** elements (direct children of `<CustomObject>` / `<CustomField>`, or of a classic `<fields>` block) are read. Metadata nests elements with the same names: `<label>` inside compact layouts, list views, name fields and picklist values, and `<fields>` inside compact layouts. Reading the first match anywhere in the document would give wrong labels.

The Profile CSV importer (`parseProfilesCsv` in `src/db/importers.ts`) handles quoted values with commas and `""` escapes, a UTF-8 BOM, CRLF endings, and a header row whose `Id` / `Name` columns may be in any order (extra columns, as in `sf data query --result-format csv` output, are ignored).

## How the Two Import Paths Work

1. **Browser Folder Upload (`Select SFDX objects/ Folder` button)**:
   - Uses `<input type="file" webkitdirectory directory multiple />` in `SalesforceObjectsView` (`src/components/views/SalesforceViews.tsx`).
   - Reads only `.object-meta.xml`, `.field-meta.xml`, `.object` and `.field` files in-browser and sends `Array<{ relativePath: string, content: string }>` to `POST /api/admin/objects/import-sfdx-files` (body limit 25 MB, checked after the admin session and CSRF token).
2. **Local Server Path Sync (`Sync from Local Path` bar)**:
   - Sends `{ folderPath: string }` to `POST /api/admin/objects/import-local-folder`.
   - `store.importObjectsFromLocalDiskFolder(folderPath)` recursively walks the directory on disk, parses all XML files, upserts into `sf_objects` and `sf_object_fields`, and saves `sfdx_objects_folder_path` in `sf_connection_settings`.

## Extending XML Tag Extraction
When adding support for additional SFDX field metadata tags (such as `<referenceTo>`, `<valueSet>`, `<length>`, or `<formula>`):
1. Extract the tag in `parseFieldXml` (`src/db/importers.ts`) using `topLevelText(xml, 'tagName')`, so nested elements with the same name are ignored.
2. Add the column to `sf_object_fields` in `src/db/store.ts` and `SalesforceObjectField` in `src/types/governance.ts`.
3. Preserve existing `enabled` states on re-import (`ON CONFLICT(object_name, field_name) DO UPDATE`) so re-syncing an SFDX folder does not reset an admin's manual field toggles.
4. Deleting an Object (`store.deleteObject`) also removes it from every Access Group, so a later re-import never silently restores access an admin revoked.
