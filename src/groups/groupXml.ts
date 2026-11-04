/**
 * The XML form of an Access Group: what export writes, import reads, and the group editor's XML view
 * shows and saves. Anything the file names that this server does not have (an object, a field, an
 * MCP tool) is kept and reported by `groupAvailabilityIssues`, not dropped.
 *
 * Reading is strict about structure: an element or attribute it does not know is an error, as a typo
 * such as `<objets>` or `reed="true"` would otherwise silently drop or deny access.
 */
import type { AccessGroupSnapshot, GroupObjectPermission, SalesforceObject } from '../types/governance.ts';
import { SALESFORCE_API_NAME_PATTERN } from '../db/importers.ts';
import { groupAvailabilityIssues, MCP_ACTION_ID_PATTERN, normalizeObjectPermissions } from './groupGrants.ts';

export const ACCESS_GROUP_XML_VERSION = '1';

/** A group as a file holds it. `id` is the group it was exported from, used to match it on import. */
export interface AccessGroupDocument extends AccessGroupSnapshot {
  id?: string;
}

export type AccessGroupXmlResult =
  | { ok: true; group: AccessGroupDocument }
  | { ok: false; error: string; line?: number };

// ============================================================================
// Writing
// ============================================================================

function escapeText(text: string): string {
  return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function escapeAttr(text: string): string {
  return escapeText(text).replace(/"/g, '&quot;');
}

/** A comment cannot contain `--` or end in `-`. */
function comment(text: string): string {
  return `<!-- ${text.replace(/-{2,}/g, '-').replace(/-$/, '')} -->`;
}

/**
 * The group as XML. With `objects`, each line naming something that is not available, or broken, on
 * this server ends in a comment saying why. Comments are for people: reading ignores them.
 */
export function accessGroupToXml(group: AccessGroupDocument, options: { objects?: readonly SalesforceObject[] } = {}): string {
  const notes = new Map<string, string>();
  if (options.objects) {
    for (const issue of groupAvailabilityIssues(group, options.objects)) {
      const key = `${issue.kind}:${issue.objectName.toLowerCase()}:${issue.name.toLowerCase()}`;
      notes.set(key, `${issue.status === 'broken' ? 'BROKEN' : 'NOT AVAILABLE'}: ${issue.message}`);
    }
  }
  const note = (kind: string, objectName: string, name: string) => {
    const text = notes.get(`${kind}:${objectName.toLowerCase()}:${name.toLowerCase()}`);
    return text ? ` ${comment(text)}` : '';
  };

  const lines = ['<?xml version="1.0" encoding="UTF-8"?>'];
  lines.push(`<AccessGroup version="${ACCESS_GROUP_XML_VERSION}"${group.id ? ` id="${escapeAttr(group.id)}"` : ''}>`);
  lines.push(`  <name>${escapeText(group.name)}</name>`);
  lines.push(`  <description>${escapeText(group.description || '')}</description>`);

  if (group.allowedActions.length === 0) {
    lines.push('  <mcpActions/>');
  } else {
    lines.push('  <mcpActions>');
    for (const id of group.allowedActions) lines.push(`    <action>${escapeText(id)}</action>${note('action', '', id)}`);
    lines.push('  </mcpActions>');
  }

  if (group.objectPermissions.length === 0) {
    lines.push('  <objects/>');
  } else {
    lines.push('  <objects>');
    for (const perm of group.objectPermissions) {
      const removed = perm.removed
        ? ` removedAt="${escapeAttr(perm.removed.at)}" removedBy="${escapeAttr(perm.removed.by)}"`
        : '';
      const open =
        `    <object name="${escapeAttr(perm.objectName)}" read="${perm.canRead}" create="${perm.canCreate}"` +
        ` update="${perm.canUpdate}" delete="${perm.canDelete}"${removed}`;
      const fieldLines = [
        ...perm.allowedFields.map(
          (f) => `      <field>${escapeText(f)}</field>${note('field', perm.objectName, f)}`
        ),
        ...(perm.removedFields || []).map(
          (f) =>
            `      <field removedAt="${escapeAttr(f.at)}" removedBy="${escapeAttr(f.by)}">${escapeText(f.fieldName)}</field>` +
            note('field', perm.objectName, f.fieldName)
        ),
      ];
      const objectNote = note('object', perm.objectName, perm.objectName);
      if (fieldLines.length === 0) {
        lines.push(`${open}/>${objectNote}`);
      } else {
        lines.push(`${open}>${objectNote}`, ...fieldLines, '    </object>');
      }
    }
    lines.push('  </objects>');
  }
  lines.push('</AccessGroup>');
  return `${lines.join('\n')}\n`;
}

// ============================================================================
// Reading: a small XML parser (elements, attributes, text, comments, CDATA), linear in the input
// ============================================================================

interface XmlElement {
  name: string;
  attrs: Map<string, string>;
  children: XmlElement[];
  text: string;
  line: number;
}

class XmlError extends Error {
  constructor(message: string, readonly line?: number) {
    super(message);
  }
}

const NAME_PATTERN = /^[A-Za-z_][\w.-]*(:[A-Za-z_][\w.-]*)?/;

function lineFinder(xml: string): (pos: number) => number {
  const starts = [0];
  for (let i = 0; i < xml.length; i++) if (xml.charCodeAt(i) === 10) starts.push(i + 1);
  return (pos) => {
    let lo = 0;
    let hi = starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (starts[mid] <= pos) lo = mid;
      else hi = mid - 1;
    }
    return lo + 1;
  };
}

function decodeEntities(text: string, line: number): string {
  return text.replace(/&([^;\s&<]*);?/g, (match, body: string) => {
    if (!match.endsWith(';')) throw new XmlError('A "&" must start an entity such as &amp;.', line);
    const named: Record<string, string> = { lt: '<', gt: '>', amp: '&', quot: '"', apos: "'" };
    if (body in named) return named[body];
    const numeric = /^#(x[0-9a-fA-F]{1,6}|[0-9]{1,7})$/.exec(body);
    if (numeric) {
      const code = numeric[1].startsWith('x') ? parseInt(numeric[1].slice(1), 16) : parseInt(numeric[1], 10);
      if (code > 0 && code <= 0x10ffff) return String.fromCodePoint(code);
    }
    throw new XmlError(`Unknown entity &${body};.`, line);
  });
}

function parseXmlDocument(xml: string): XmlElement {
  const lineAt = lineFinder(xml);
  const stack: XmlElement[] = [];
  let root: XmlElement | null = null;
  let pos = xml.charCodeAt(0) === 0xfeff ? 1 : 0;

  const appendText = (text: string, at: number) => {
    if (stack.length > 0) {
      stack[stack.length - 1].text += text;
    } else if (text.trim()) {
      throw new XmlError('Text is not allowed outside the root element.', lineAt(at));
    }
  };

  while (pos < xml.length) {
    const lt = xml.indexOf('<', pos);
    if (lt === -1) {
      appendText(decodeEntities(xml.slice(pos), lineAt(pos)), pos);
      break;
    }
    if (lt > pos) appendText(decodeEntities(xml.slice(pos, lt), lineAt(pos)), pos);

    if (xml.startsWith('<!--', lt)) {
      const end = xml.indexOf('-->', lt + 4);
      if (end === -1) throw new XmlError('A comment is not closed with -->.', lineAt(lt));
      pos = end + 3;
      continue;
    }
    if (xml.startsWith('<?', lt)) {
      const end = xml.indexOf('?>', lt + 2);
      if (end === -1) throw new XmlError('A <? ... ?> declaration is not closed.', lineAt(lt));
      pos = end + 2;
      continue;
    }
    if (xml.startsWith('<![CDATA[', lt)) {
      const end = xml.indexOf(']]>', lt + 9);
      if (end === -1) throw new XmlError('A CDATA section is not closed with ]]>.', lineAt(lt));
      appendText(xml.slice(lt + 9, end), lt);
      pos = end + 3;
      continue;
    }
    if (xml.startsWith('<!', lt)) {
      throw new XmlError('DOCTYPE and entity declarations are not allowed.', lineAt(lt));
    }

    const gt = xml.indexOf('>', lt + 1);
    if (gt === -1) throw new XmlError('A tag is not closed with >.', lineAt(lt));
    const line = lineAt(lt);

    if (xml[lt + 1] === '/') {
      const name = xml.slice(lt + 2, gt).trim();
      const open = stack.pop();
      if (!open) throw new XmlError(`</${name}> closes nothing.`, line);
      if (open.name !== name) throw new XmlError(`Expected </${open.name}> (opened on line ${open.line}) but found </${name}>.`, line);
      pos = gt + 1;
      continue;
    }

    let tag = xml.slice(lt + 1, gt);
    const selfClosing = tag.endsWith('/');
    if (selfClosing) tag = tag.slice(0, -1);
    const nameMatch = NAME_PATTERN.exec(tag);
    if (!nameMatch) throw new XmlError('A tag must start with an element name.', line);
    const element: XmlElement = { name: nameMatch[0], attrs: new Map(), children: [], text: '', line };

    let rest = tag.slice(nameMatch[0].length);
    while (rest.trim()) {
      const attr = /^\s+([A-Za-z_][\w.:-]*)\s*=\s*("([^"<]*)"|'([^'<]*)')/.exec(rest);
      if (!attr) throw new XmlError(`Could not read the attributes of <${element.name}>.`, line);
      if (element.attrs.has(attr[1])) throw new XmlError(`<${element.name}> has the attribute ${attr[1]} twice.`, line);
      element.attrs.set(attr[1], decodeEntities(attr[3] ?? attr[4] ?? '', line));
      rest = rest.slice(attr[0].length);
    }

    if (stack.length > 0) {
      stack[stack.length - 1].children.push(element);
    } else if (root) {
      throw new XmlError('A file can hold only one <AccessGroup>.', line);
    } else {
      root = element;
    }
    if (!selfClosing) stack.push(element);
    pos = gt + 1;
  }

  if (stack.length > 0) {
    const open = stack[stack.length - 1];
    throw new XmlError(`<${open.name}> is not closed.`, open.line);
  }
  if (!root) throw new XmlError('The file has no XML elements.');
  return root;
}

// ============================================================================
// Reading: the Access Group document
// ============================================================================

function expectOnly(element: XmlElement, allowedAttrs: string[], allowedChildren: string[]) {
  for (const name of element.attrs.keys()) {
    if (!allowedAttrs.includes(name)) {
      throw new XmlError(
        `<${element.name}> has an unknown attribute ${name}.${
          allowedAttrs.length > 0 ? ` Expected ${allowedAttrs.join(', ')}.` : ''
        }`,
        element.line
      );
    }
  }
  for (const child of element.children) {
    if (!allowedChildren.includes(child.name)) {
      throw new XmlError(
        `<${child.name}> is not allowed in <${element.name}>.${
          allowedChildren.length > 0 ? ` Expected ${allowedChildren.map((c) => `<${c}>`).join(', ')}.` : ''
        }`,
        child.line
      );
    }
  }
  if (allowedChildren.length > 0 && element.text.trim()) {
    throw new XmlError(`<${element.name}> holds elements, not text.`, element.line);
  }
}

function textOf(element: XmlElement, allowedAttrs: string[] = []): string {
  expectOnly(element, allowedAttrs, []);
  return element.text.trim();
}

function only(parent: XmlElement, name: string): XmlElement | undefined {
  const matches = parent.children.filter((c) => c.name === name);
  if (matches.length > 1) throw new XmlError(`<${parent.name}> may hold only one <${name}>.`, matches[1].line);
  return matches[0];
}

function flag(element: XmlElement, name: string): boolean {
  const value = element.attrs.get(name);
  if (value === undefined) return false;
  const lower = value.trim().toLowerCase();
  if (lower === 'true') return true;
  if (lower === 'false') return false;
  throw new XmlError(`${name}="${value}" on <${element.name}> must be "true" or "false".`, element.line);
}

function removalOf(element: XmlElement) {
  const at = element.attrs.get('removedAt');
  const by = element.attrs.get('removedBy');
  return at === undefined && by === undefined ? undefined : { at: (at || '').trim(), by: (by || '').trim() };
}

/** Reads a group from XML, or says what is wrong with the file and on which line. */
export function parseAccessGroupXml(xml: string): AccessGroupXmlResult {
  try {
    const root = parseXmlDocument(xml);
    if (root.name !== 'AccessGroup') {
      throw new XmlError(`The root element must be <AccessGroup>, not <${root.name}>.`, root.line);
    }
    expectOnly(root, ['version', 'id'], ['name', 'description', 'mcpActions', 'objects']);
    const version = root.attrs.get('version');
    if (version !== undefined && version.trim() !== ACCESS_GROUP_XML_VERSION) {
      throw new XmlError(`This server reads Access Group files of version ${ACCESS_GROUP_XML_VERSION}, not ${version}.`, root.line);
    }

    const nameElement = only(root, 'name');
    const name = nameElement ? textOf(nameElement) : '';
    if (!name) throw new XmlError('The group needs a <name>.', nameElement?.line ?? root.line);
    const descriptionElement = only(root, 'description');

    const allowedActions: string[] = [];
    const actionsElement = only(root, 'mcpActions');
    if (actionsElement) {
      expectOnly(actionsElement, [], ['action']);
      for (const action of actionsElement.children) {
        const id = textOf(action);
        if (!MCP_ACTION_ID_PATTERN.test(id)) throw new XmlError(`"${id}" is not a valid MCP action ID.`, action.line);
        if (!allowedActions.includes(id)) allowedActions.push(id);
      }
    }

    const objectPermissions: GroupObjectPermission[] = [];
    const objectsElement = only(root, 'objects');
    if (objectsElement) {
      expectOnly(objectsElement, [], ['object']);
      const seen = new Map<string, number>();
      for (const objectElement of objectsElement.children) {
        expectOnly(objectElement, ['name', 'read', 'create', 'update', 'delete', 'removedAt', 'removedBy'], ['field']);
        const objectName = (objectElement.attrs.get('name') || '').trim();
        if (!SALESFORCE_API_NAME_PATTERN.test(objectName)) {
          throw new XmlError(
            objectName ? `"${objectName}" is not a valid Salesforce object API name.` : '<object> needs a name attribute.',
            objectElement.line
          );
        }
        const firstLine = seen.get(objectName.toLowerCase());
        if (firstLine !== undefined) {
          throw new XmlError(`${objectName} is already listed on line ${firstLine}.`, objectElement.line);
        }
        seen.set(objectName.toLowerCase(), objectElement.line);

        const perm: GroupObjectPermission = {
          objectName,
          canRead: flag(objectElement, 'read'),
          canCreate: flag(objectElement, 'create'),
          canUpdate: flag(objectElement, 'update'),
          canDelete: flag(objectElement, 'delete'),
          allowedFields: [],
        };
        const removed = removalOf(objectElement);
        if (removed) perm.removed = removed;
        for (const fieldElement of objectElement.children) {
          const fieldName = textOf(fieldElement, ['removedAt', 'removedBy']);
          if (!SALESFORCE_API_NAME_PATTERN.test(fieldName)) {
            throw new XmlError(`"${fieldName}" is not a valid Salesforce field API name.`, fieldElement.line);
          }
          const heldAs = removalOf(fieldElement);
          if (heldAs) perm.removedFields = [...(perm.removedFields || []), { fieldName, ...heldAs }];
          else perm.allowedFields.push(fieldName);
        }
        objectPermissions.push(perm);
      }
    }

    // The same rules the server applies on save (duplicates, a field both granted and held).
    const normalized = normalizeObjectPermissions(objectPermissions);
    if (!normalized.ok) throw new XmlError(normalized.error);

    const id = root.attrs.get('id')?.trim();
    return {
      ok: true,
      group: {
        ...(id ? { id } : {}),
        name,
        description: descriptionElement ? textOf(descriptionElement) : '',
        allowedActions,
        objectPermissions: normalized.value,
      },
    };
  } catch (err) {
    if (err instanceof XmlError) return { ok: false, error: err.message, ...(err.line ? { line: err.line } : {}) };
    throw err;
  }
}
