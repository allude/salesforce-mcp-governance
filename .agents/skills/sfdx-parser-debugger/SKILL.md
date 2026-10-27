---
name: sfdx-parser-debugger
description: >-
  Guide for maintaining, testing, and extending the Salesforce DX (SFDX) object/field
  XML parser (`parseSfdxFilesToObjects`) and Profile CSV importer.
---

# SFDX Metadata & CSV Parser Skill (`sfdx-parser-debugger`)

Use this skill when working on `# Salesforce > ## Objects` or `# Salesforce > ## Profiles` import logic in `src/db/store.ts`, `src/routes/adminRoutes.ts`, and `src/components/views/SalesforceViews.tsx`.

## Supported Salesforce Project Formats

The object importer (`parseSfdxFilesToObjects` in `src/db/store.ts`) supports two Salesforce directory layouts:

1. **Salesforce DX (SFDX) Source Format (`force-app/main/default/objects/`)**:
   - Object metadata: `objects/<ObjectName>/<ObjectName>.object-meta.xml`
   - Field metadata: `objects/<ObjectName>/fields/<FieldName>.field-meta.xml`
   - Standard objects extended in SFDX (where `<ObjectName>.object-meta.xml` may be omitted and only `fields/*.field-meta.xml` exist): the parser automatically infers `<ObjectName>` from the parent directory of `fields/`.

2. **Classic Metadata API Format (`unpackaged/objects/`)**:
   - Monolithic object file: `objects/<ObjectName>.object` containing inline `<fields>...</fields>` XML blocks.

## How the Two Import Paths Work

1. **Browser Folder Upload (`Select SFDX objects/ Folder` button)**:
   - Uses `<input type="file" webkitdirectory directory multiple />` in `SalesforceObjectsView` (`src/components/views/SalesforceViews.tsx`).
   - Reads `.xml`, `.object`, and `.field` files in-browser and sends `Array<{ relativePath: string, content: string }>` to `POST /api/admin/objects/import-sfdx-files`.
2. **Local Server Path Sync (`Sync from Local Path` bar)**:
   - Sends `{ folderPath: string }` to `POST /api/admin/objects/import-local-folder`.
   - `store.importObjectsFromLocalDiskFolder(folderPath)` recursively walks the directory on disk, parses all XML files, upserts into `sf_objects` and `sf_object_fields`, and saves `sfdx_objects_folder_path` in `sf_connection_settings`.

## Extending XML Tag Extraction
When adding support for additional SFDX field metadata tags (such as `<referenceTo>`, `<valueSet>`, `<length>`, or `<formula>`):
1. Extract the tag in `parseSfdxFilesToObjects` (`src/db/store.ts`) using `extractXmlTag(xml, 'tagName')`.
2. Add the column to `sf_object_fields` in `src/db/store.ts` and `SalesforceObjectField` in `src/types/governance.ts`.
3. Preserve existing `enabled` states on re-import (`ON CONFLICT(object_name, field_name) DO UPDATE`) so re-syncing an SFDX folder does not reset an admin's manual field toggles.
