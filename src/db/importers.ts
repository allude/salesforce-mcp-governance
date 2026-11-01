/**
 * Parsers for the Admin Portal importers: Salesforce Profile CSV files and SFDX / Metadata API
 * object and field XML. No external XML or CSV dependencies.
 */

/**
 * Salesforce object and field API names: a letter, then letters, digits and underscores
 * (`Account`, `Amount__c`, `ns__Field__c`). Anything else (spaces, dots, parentheses) could change
 * the meaning of the SOQL and REST paths these names are later placed into, so it is rejected.
 */
export const SALESFORCE_API_NAME_PATTERN = /^[A-Za-z][A-Za-z0-9_]{0,79}$/;

export interface ParsedSfdxField {
  fieldName: string;
  label: string;
  fieldType: string;
  isCustom: boolean;
  required: boolean;
}

export interface ParsedSfdxObject {
  objectName: string;
  label: string;
  isCustom: boolean;
  sourcePath: string;
  fields: ParsedSfdxField[];
}

function decodeXmlEntities(text: string): string {
  return text
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, '&');
}

/** Removes `<!-- ... -->` comments and `<? ... ?>` processing instructions in one linear pass. */
function stripCommentsAndInstructions(xml: string): string {
  let out = '';
  let pos = 0;
  while (pos < xml.length) {
    const lt = xml.indexOf('<', pos);
    if (lt === -1) {
      out += xml.slice(pos);
      break;
    }
    out += xml.slice(pos, lt);
    const isComment = xml.startsWith('<!--', lt);
    const isInstruction = xml.startsWith('<?', lt);
    if (!isComment && !isInstruction) {
      out += '<';
      pos = lt + 1;
      continue;
    }
    const close = xml.indexOf(isComment ? '-->' : '?>', lt + 2);
    if (close === -1) break; // unterminated: drop the rest
    pos = close + (isComment ? 3 : 2);
  }
  return out;
}

/**
 * Returns the direct children of the document's root element. Metadata files nest elements with
 * the same names (`<label>` inside compact layouts, list views and picklist values; `<fields>`
 * inside compact layouts), so only top-level elements describe the object or field itself.
 * The scan is linear in the input size (each `<` and `>` is visited once), so malformed or
 * hostile files cannot stall the server.
 */
function topLevelElements(xml: string): Array<{ name: string; inner: string }> {
  const body = stripCommentsAndInstructions(xml);
  const elements: Array<{ name: string; inner: string }> = [];
  let depth = 0;
  let open: { name: string; start: number } | null = null;
  let pos = 0;
  while (pos < body.length) {
    const lt = body.indexOf('<', pos);
    if (lt === -1) break;
    const gt = body.indexOf('>', lt + 1);
    if (gt === -1) break; // unterminated tag: nothing more can be parsed
    const tag = body.slice(lt + 1, gt);
    pos = gt + 1;

    const match = /^(\/?)([A-Za-z_][\w:.-]*)/.exec(tag);
    if (!match) continue;
    const [, closing, name] = match;
    if (tag.endsWith('/')) {
      if (depth === 1) elements.push({ name, inner: '' });
      continue;
    }
    if (closing) {
      depth--;
      if (depth === 1 && open?.name === name) {
        elements.push({ name, inner: body.slice(open.start, lt) });
        open = null;
      }
      continue;
    }
    if (depth === 1) open = { name, start: pos };
    depth++;
  }
  return elements;
}

function topLevelText(xml: string, tag: string): string | null {
  const element = topLevelElements(xml).find((e) => e.name === tag);
  const text = element ? decodeXmlEntities(element.inner.trim()) : '';
  return text || null;
}

function parseFieldXml(xml: string, fallbackName: string): ParsedSfdxField | null {
  const fieldName = topLevelText(xml, 'fullName') || fallbackName;
  if (!fieldName || !SALESFORCE_API_NAME_PATTERN.test(fieldName)) return null;
  return {
    fieldName,
    label: topLevelText(xml, 'label') || fieldName,
    fieldType: topLevelText(xml, 'type') || 'Text',
    isCustom: fieldName.endsWith('__c'),
    required: topLevelText(xml, 'required') === 'true',
  };
}

/**
 * Parses SFDX source-format or Metadata API XML files into Objects & Fields:
 * - `objects/<Obj>/<Obj>.object-meta.xml` (object label)
 * - `objects/<Obj>/fields/<Field>.field-meta.xml` (works without the object file, e.g. standard objects)
 * - classic `objects/<Obj>.object` with inline top-level `<fields>` blocks
 * Field files whose owning object cannot be determined from the path are skipped.
 */
export function parseSfdxFilesToObjects(
  files: Array<{ relativePath: string; content: string }>
): ParsedSfdxObject[] {
  const objectMap = new Map<
    string,
    Omit<ParsedSfdxObject, 'fields'> & { fields: Map<string, ParsedSfdxField> }
  >();

  const ensureObject = (objectName: string, sourcePath: string) => {
    const cleanName = objectName.trim();
    if (!objectMap.has(cleanName)) {
      const isCustom = cleanName.endsWith('__c') || cleanName.endsWith('__mdt') || cleanName.endsWith('__e');
      const fields = new Map<string, ParsedSfdxField>();
      // Always include standard Id and Name fields if not present
      fields.set('Id', { fieldName: 'Id', label: 'Record ID', fieldType: 'Id', isCustom: false, required: true });
      fields.set('Name', { fieldName: 'Name', label: 'Name', fieldType: 'Text', isCustom: false, required: false });
      objectMap.set(cleanName, {
        objectName: cleanName,
        label: cleanName.replace(/__c$/, '').replace(/_/g, ' '),
        isCustom,
        sourcePath,
        fields,
      });
    }
    return objectMap.get(cleanName)!;
  };

  for (const file of files) {
    if (!file || typeof file.relativePath !== 'string' || typeof file.content !== 'string') continue;
    const normPath = file.relativePath.replace(/\\/g, '/');
    const parts = normPath.split('/').filter(Boolean);
    const fileName = parts[parts.length - 1] || '';

    // Case 1: Object definition: `.../objects/<ObjectName>/<ObjectName>.object-meta.xml` or `<ObjectName>.object`
    if (fileName.endsWith('.object-meta.xml') || fileName.endsWith('.object')) {
      const objectName = fileName.replace(/\.object-meta\.xml$/i, '').replace(/\.object$/i, '');
      if (!SALESFORCE_API_NAME_PATTERN.test(objectName)) continue;
      const obj = ensureObject(objectName, normPath);
      const xmlLabel = topLevelText(file.content, 'label') || topLevelText(file.content, 'fullName');
      if (xmlLabel) {
        obj.label = xmlLabel;
      }

      // Classic `.object` files carry their fields as top-level `<fields>` blocks
      for (const block of topLevelElements(file.content).filter((e) => e.name === 'fields')) {
        const field = parseFieldXml(`<fields>${block.inner}</fields>`, '');
        if (field) obj.fields.set(field.fieldName, field);
      }
    }

    // Case 2: Field definition: `.../objects/<ObjectName>/fields/<FieldName>.field-meta.xml`
    if (fileName.endsWith('.field-meta.xml') || fileName.endsWith('.field')) {
      const fieldsIdx = parts.findIndex((p) => p.toLowerCase() === 'fields');
      const objectName =
        fieldsIdx > 0 ? parts[fieldsIdx - 1] : parts.length >= 2 ? parts[parts.length - 2] : '';
      if (
        !SALESFORCE_API_NAME_PATTERN.test(objectName) ||
        objectName.toLowerCase() === 'objects' ||
        objectName.toLowerCase() === 'fields'
      ) {
        continue;
      }

      const fieldFromFilename = fileName.replace(/\.field-meta\.xml$/i, '').replace(/\.field$/i, '');
      const field = parseFieldXml(file.content, fieldFromFilename);
      if (!field) continue;

      const obj = ensureObject(objectName, parts.slice(0, Math.max(1, fieldsIdx)).join('/'));
      obj.fields.set(field.fieldName, field);
    }
  }

  return Array.from(objectMap.values()).map((o) => ({
    objectName: o.objectName,
    label: o.label,
    isCustom: o.isCustom,
    sourcePath: o.sourcePath,
    fields: Array.from(o.fields.values()),
  }));
}

/** Splits one CSV line, honouring double-quoted values (with `""` escapes) that contain commas. */
function parseCsvLine(line: string): string[] {
  const cols: string[] = [];
  let current = '';
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (inQuotes) {
      if (ch === '"' && line[i + 1] === '"') {
        current += '"';
        i++;
      } else if (ch === '"') {
        inQuotes = false;
      } else {
        current += ch;
      }
    } else if (ch === '"') {
      inQuotes = true;
    } else if (ch === ',') {
      cols.push(current);
      current = '';
    } else {
      current += ch;
    }
  }
  cols.push(current);
  return cols.map((c) => c.trim().replace(/^'(.*)'$/, '$1'));
}

const ID_HEADERS = new Set(['id', 'profileid', 'profile_id', 'profile id']);
const NAME_HEADERS = new Set(['name', 'profilename', 'profile_name', 'profile name']);

/**
 * Parses a Profile CSV (`id,name`, any extra columns ignored). A first row naming the columns
 * (e.g. `Id,Name` or `Name,Id,UserType` as exported by `sf data query`) is used as the header;
 * otherwise the first two columns are id and name. Blank lines and rows missing either value are skipped.
 */
export function parseProfilesCsv(csvText: string): Array<{ id: string; name: string }> {
  const lines = csvText
    .replace(/^﻿/, '')
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean);

  let idCol = 0;
  let nameCol = 1;
  const rows: Array<{ id: string; name: string }> = [];
  lines.forEach((line, index) => {
    const cols = parseCsvLine(line);
    if (index === 0) {
      const lower = cols.map((c) => c.toLowerCase());
      const headerId = lower.findIndex((c) => ID_HEADERS.has(c));
      const headerName = lower.findIndex((c) => NAME_HEADERS.has(c));
      if (headerId !== -1 || headerName !== -1) {
        // A recognised header fixes its column; the other value is taken from the other column.
        idCol = headerId !== -1 ? headerId : headerName === 0 ? 1 : 0;
        nameCol = headerName !== -1 ? headerName : idCol === 0 ? 1 : 0;
        return;
      }
    }
    const id = cols[idCol];
    const name = cols[nameCol];
    if (id && name) rows.push({ id, name });
  });
  return rows;
}
