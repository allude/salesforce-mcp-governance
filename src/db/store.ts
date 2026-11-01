import { DatabaseSync } from 'node:sqlite';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { config } from '../config.js';
import { encryptSecret, decryptSecret } from '../security/crypto.js';
import {
  SalesforceProfile,
  SalesforceObject,
  SalesforceObjectField,
  AccessGroup,
  GroupObjectPermission,
  ProfileGroupMapping,
  CopilotMcpLogRecord,
  PortalAdminLogRecord,
  OktaSsoSettings,
  SalesforceConnectionSettings,
  ProfileSyncDiffPreview,
  ObjectSyncDiffPreview,
  PortalUserSummary,
} from '../types/governance.js';
import {
  PulledOrgObjectMetadata,
  inspectCertificatePem,
  validatePrivateKeyPem,
} from '../salesforce/jwtConnection.js';

const dbDir = path.dirname(config.dbPath);
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}

const db = new DatabaseSync(config.dbPath);

db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA foreign_keys = ON;

  CREATE TABLE IF NOT EXISTS portal_users (
    username TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    password_salt TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'Admin',
    created_at TEXT NOT NULL,
    last_login_at TEXT
  );

  CREATE TABLE IF NOT EXISTS sf_profiles (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    missing_in_org INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS sf_objects (
    object_name TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    is_custom INTEGER NOT NULL DEFAULT 0,
    enabled INTEGER NOT NULL DEFAULT 1,
    source_path TEXT NOT NULL DEFAULT '',
    missing_in_org INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS sf_object_fields (
    object_name TEXT NOT NULL,
    field_name TEXT NOT NULL,
    label TEXT NOT NULL,
    field_type TEXT NOT NULL DEFAULT 'Text',
    is_custom INTEGER NOT NULL DEFAULT 0,
    required INTEGER NOT NULL DEFAULT 0,
    enabled INTEGER NOT NULL DEFAULT 1,
    missing_in_org INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (object_name, field_name),
    FOREIGN KEY (object_name) REFERENCES sf_objects(object_name) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS access_groups (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    allowed_actions_json TEXT NOT NULL DEFAULT '[]',
    object_permissions_json TEXT NOT NULL DEFAULT '[]',
    updated_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS profile_group_memberships (
    profile_id TEXT NOT NULL,
    group_id TEXT NOT NULL,
    PRIMARY KEY (profile_id, group_id),
    FOREIGN KEY (profile_id) REFERENCES sf_profiles(id) ON DELETE CASCADE,
    FOREIGN KEY (group_id) REFERENCES access_groups(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS mcp_copilot_logs (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    sf_username TEXT NOT NULL,
    profile_id TEXT NOT NULL,
    profile_name TEXT NOT NULL,
    matched_groups_json TEXT NOT NULL DEFAULT '[]',
    tool_name TEXT NOT NULL,
    target_object TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL,
    latency_ms INTEGER NOT NULL DEFAULT 0,
    sanitized_request_payload TEXT NOT NULL DEFAULT '{}',
    sanitized_response_summary TEXT NOT NULL DEFAULT '{}'
  );

  CREATE TABLE IF NOT EXISTS portal_admin_logs (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    admin_username TEXT NOT NULL,
    auth_method TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    details TEXT NOT NULL,
    ip_address TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS okta_config (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    enabled INTEGER NOT NULL DEFAULT 0,
    okta_domain TEXT NOT NULL DEFAULT '',
    issuer TEXT NOT NULL DEFAULT '',
    client_id TEXT NOT NULL DEFAULT '',
    client_secret_enc TEXT NOT NULL DEFAULT '',
    redirect_uri TEXT NOT NULL DEFAULT '',
    admin_group TEXT NOT NULL DEFAULT 'MCP-Admins',
    updated_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS sf_connection_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    enabled INTEGER NOT NULL DEFAULT 0,
    auth_mode TEXT NOT NULL DEFAULT 'jwt_bearer',
    login_url TEXT NOT NULL DEFAULT 'https://login.salesforce.com',
    client_id TEXT NOT NULL DEFAULT '',
    username TEXT NOT NULL DEFAULT '',
    private_key_enc TEXT NOT NULL DEFAULT '',
    certificate_pem TEXT NOT NULL DEFAULT '',
    cert_fingerprint TEXT NOT NULL DEFAULT '',
    connection_status TEXT NOT NULL DEFAULT 'disconnected',
    last_connected_at TEXT,
    last_error TEXT NOT NULL DEFAULT '',
    connected_org_id TEXT NOT NULL DEFAULT '',
    connected_user TEXT NOT NULL DEFAULT '',
    expected_org_id TEXT NOT NULL DEFAULT '',
    instance_url TEXT NOT NULL DEFAULT 'https://login.salesforce.com',
    api_version TEXT NOT NULL DEFAULT 'v62.0',
    enforce_org_id_lock INTEGER NOT NULL DEFAULT 0,
    sfdx_objects_folder_path TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL
  );
`);

function ensureColumnExists(tableName: string, columnName: string, columnDef: string) {
  const cols = db.prepare(`PRAGMA table_info(${tableName})`).all() as Array<{ name: string }>;
  if (!cols.some((c) => c.name === columnName)) {
    db.exec(`ALTER TABLE ${tableName} ADD COLUMN ${columnName} ${columnDef}`);
  }
}

function runSchemaMigrations() {
  ensureColumnExists('sf_profiles', 'missing_in_org', 'INTEGER NOT NULL DEFAULT 0');
  ensureColumnExists('sf_objects', 'missing_in_org', 'INTEGER NOT NULL DEFAULT 0');
  ensureColumnExists('sf_object_fields', 'missing_in_org', 'INTEGER NOT NULL DEFAULT 0');

  ensureColumnExists('sf_connection_settings', 'enabled', 'INTEGER NOT NULL DEFAULT 0');
  ensureColumnExists('sf_connection_settings', 'auth_mode', "TEXT NOT NULL DEFAULT 'jwt_bearer'");
  ensureColumnExists('sf_connection_settings', 'login_url', "TEXT NOT NULL DEFAULT 'https://login.salesforce.com'");
  ensureColumnExists('sf_connection_settings', 'client_id', "TEXT NOT NULL DEFAULT ''");
  ensureColumnExists('sf_connection_settings', 'username', "TEXT NOT NULL DEFAULT ''");
  ensureColumnExists('sf_connection_settings', 'private_key_enc', "TEXT NOT NULL DEFAULT ''");
  ensureColumnExists('sf_connection_settings', 'certificate_pem', "TEXT NOT NULL DEFAULT ''");
  ensureColumnExists('sf_connection_settings', 'cert_fingerprint', "TEXT NOT NULL DEFAULT ''");
  ensureColumnExists('sf_connection_settings', 'connection_status', "TEXT NOT NULL DEFAULT 'disconnected'");
  ensureColumnExists('sf_connection_settings', 'last_connected_at', 'TEXT');
  ensureColumnExists('sf_connection_settings', 'last_error', "TEXT NOT NULL DEFAULT ''");
  ensureColumnExists('sf_connection_settings', 'connected_org_id', "TEXT NOT NULL DEFAULT ''");
  ensureColumnExists('sf_connection_settings', 'connected_user', "TEXT NOT NULL DEFAULT ''");
}

runSchemaMigrations();

function hashPassword(password: string, salt: string): string {
  return crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
}

function initializeSystemSingletons() {
  const now = new Date().toISOString();

  // Ensure at least one portal admin user exists so the user can sign in with username & password
  const userCount = (
    db.prepare('SELECT COUNT(*) as cnt FROM portal_users').get() as { cnt: number }
  ).cnt;
  if (userCount === 0) {
    const salt = crypto.randomBytes(16).toString('hex');
    const defaultUsername = process.env.ADMIN_USERNAME || 'admin';
    const defaultPassword = process.env.ADMIN_BOOTSTRAP_PASSWORD || 'admin123';
    const hash = hashPassword(defaultPassword, salt);
    db.prepare(`
      INSERT INTO portal_users (username, display_name, password_hash, password_salt, role, created_at)
      VALUES (?, 'Portal Administrator', ?, ?, 'Super Admin', ?)
    `).run(defaultUsername, hash, salt, now);
  }

  const oktaCount = (
    db.prepare('SELECT COUNT(*) as cnt FROM okta_config').get() as { cnt: number }
  ).cnt;
  if (oktaCount === 0) {
    db.prepare(`
      INSERT INTO okta_config (
        id, enabled, okta_domain, issuer, client_id, client_secret_enc, redirect_uri, admin_group, updated_at
      ) VALUES (1, 0, '', '', '', '', ?, 'MCP-Admins', ?)
    `).run(`${config.baseUrl}/auth/okta/callback`, now);
  }

  const sfCount = (
    db.prepare('SELECT COUNT(*) as cnt FROM sf_connection_settings').get() as { cnt: number }
  ).cnt;
  if (sfCount === 0) {
    db.prepare(`
      INSERT INTO sf_connection_settings (
        id, expected_org_id, instance_url, api_version, enforce_org_id_lock, sfdx_objects_folder_path, updated_at
      ) VALUES (1, '', 'https://login.salesforce.com', 'v62.0', 0, '', ?)
    `).run(now);
  }
}

initializeSystemSingletons();

/**
 * Strips all sensitive data values from a payload while preserving keys, field names, and structure
 * so Copilot MCP logs never store raw customer PII or record values.
 */
export function stripSensitivePayloadData(input: unknown): unknown {
  if (input === null || input === undefined) return input;
  if (Array.isArray(input)) {
    return {
      _type: 'Array',
      count: input.length,
      sampleStructure: input.length > 0 ? stripSensitivePayloadData(input[0]) : null,
    };
  }
  if (typeof input === 'object') {
    const safeKeys = new Set([
      'objectName',
      'object',
      'sobject',
      'tool',
      'toolName',
      'fields',
      'fieldNames',
      'limit',
      'status',
      'totalSize',
      'done',
      'id',
      'Id',
    ]);
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(input as Record<string, unknown>)) {
      if (k === 'records' && Array.isArray(v)) {
        out.records = `[REDACTED ${v.length} RECORDS]`;
      } else if (k === 'soql' && typeof v === 'string') {
        // Redact quoted string literals in SOQL WHERE clauses (`'...'` -> `'[REDACTED]'`)
        out.soql = v.replace(/'[^']*'/g, "'[REDACTED]'");
      } else if (safeKeys.has(k) && (typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean')) {
        out[k] = v;
      } else if (Array.isArray(v) && safeKeys.has(k)) {
        out[k] = v;
      } else if (typeof v === 'object' && v !== null) {
        out[k] = stripSensitivePayloadData(v);
      } else {
        out[k] = `<REDACTED:${typeof v}>`;
      }
    }
    return out;
  }
  return `<REDACTED:${typeof input}>`;
}

/**
 * Helper to extract an XML tag value (`<tag>value</tag>`) without external XML dependencies.
 */
function extractXmlTag(xml: string, tag: string): string | null {
  const match = xml.match(new RegExp(`<${tag}>([\\s\\S]*?)<\\/${tag}>`, 'i'));
  return match ? match[1].trim() : null;
}

/**
 * Parses SFDX or Metadata API XML files into Objects & Fields.
 */
export function parseSfdxFilesToObjects(
  files: Array<{ relativePath: string; content: string }>
): Array<{
  objectName: string;
  label: string;
  isCustom: boolean;
  sourcePath: string;
  fields: Array<{
    fieldName: string;
    label: string;
    fieldType: string;
    isCustom: boolean;
    required: boolean;
  }>;
}> {
  const objectMap = new Map<
    string,
    {
      objectName: string;
      label: string;
      isCustom: boolean;
      sourcePath: string;
      fields: Map<
        string,
        {
          fieldName: string;
          label: string;
          fieldType: string;
          isCustom: boolean;
          required: boolean;
        }
      >;
    }
  >();

  const ensureObject = (objectName: string, sourcePath: string) => {
    const cleanName = objectName.trim();
    if (!objectMap.has(cleanName)) {
      const isCustom = cleanName.endsWith('__c') || cleanName.endsWith('__mdt') || cleanName.endsWith('__e');
      const fields = new Map();
      // Always include standard Id and Name fields if not present
      fields.set('Id', {
        fieldName: 'Id',
        label: 'Record ID',
        fieldType: 'Id',
        isCustom: false,
        required: true,
      });
      fields.set('Name', {
        fieldName: 'Name',
        label: 'Name',
        fieldType: 'Text',
        isCustom: false,
        required: false,
      });
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
    const normPath = file.relativePath.replace(/\\/g, '/');
    const parts = normPath.split('/');
    const fileName = parts[parts.length - 1] || '';

    // Case 1: SFDX Object definition: `.../objects/<ObjectName>/<ObjectName>.object-meta.xml` or `<ObjectName>.object`
    if (fileName.endsWith('.object-meta.xml') || fileName.endsWith('.object')) {
      const objectName = fileName
        .replace(/\.object-meta\.xml$/i, '')
        .replace(/\.object$/i, '');
      if (!objectName) continue;
      const obj = ensureObject(objectName, normPath);
      const xmlLabel = extractXmlTag(file.content, 'label') || extractXmlTag(file.content, 'fullName');
      if (xmlLabel) {
        obj.label = xmlLabel;
      }

      // Also check if classic `.object` XML has inline `<fields>...</fields>` blocks
      const fieldBlocks = file.content.match(/<fields>[\s\S]*?<\/fields>/gi) || [];
      for (const block of fieldBlocks) {
        const fn = extractXmlTag(block, 'fullName');
        if (!fn) continue;
        const flabel = extractXmlTag(block, 'label') || fn;
        const ftype = extractXmlTag(block, 'type') || 'Text';
        const freq = extractXmlTag(block, 'required') === 'true';
        obj.fields.set(fn, {
          fieldName: fn,
          label: flabel,
          fieldType: ftype,
          isCustom: fn.endsWith('__c'),
          required: freq,
        });
      }
    }

    // Case 2: SFDX Field definition: `.../objects/<ObjectName>/fields/<FieldName>.field-meta.xml`
    if (fileName.endsWith('.field-meta.xml') || fileName.endsWith('.field')) {
      const fieldsIdx = parts.findIndex((p) => p.toLowerCase() === 'fields');
      const objectName =
        fieldsIdx > 0
          ? parts[fieldsIdx - 1]
          : parts.length >= 2
          ? parts[parts.length - 2]
          : 'UnknownObject';
      const fieldFromFilename = fileName
        .replace(/\.field-meta\.xml$/i, '')
        .replace(/\.field$/i, '');
      const fn = extractXmlTag(file.content, 'fullName') || fieldFromFilename;
      if (!fn || !objectName) continue;

      const obj = ensureObject(objectName, parts.slice(0, Math.max(1, fieldsIdx)).join('/'));
      const flabel = extractXmlTag(file.content, 'label') || fn;
      const ftype = extractXmlTag(file.content, 'type') || 'Text';
      const freq = extractXmlTag(file.content, 'required') === 'true';
      obj.fields.set(fn, {
        fieldName: fn,
        label: flabel,
        fieldType: ftype,
        isCustom: fn.endsWith('__c'),
        required: freq,
      });
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

export const store = {
  // ============================================================================
  // 1. PORTAL USERS & AUTHENTICATION
  // ============================================================================
  verifyPortalUserCredentials(username: string, password: string): PortalUserSummary | null {
    const row = db
      .prepare('SELECT * FROM portal_users WHERE lower(username) = lower(?)')
      .get(username.trim()) as any;
    if (!row) return null;

    const computed = hashPassword(password, row.password_salt);
    const a = Buffer.from(computed, 'hex');
    const b = Buffer.from(row.password_hash, 'hex');
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      return null;
    }

    const now = new Date().toISOString();
    db.prepare('UPDATE portal_users SET last_login_at = ? WHERE username = ?').run(now, row.username);
    return {
      username: row.username,
      displayName: row.display_name,
      role: row.role,
      createdAt: row.created_at,
      lastLoginAt: now,
    };
  },

  getPortalUsers(): PortalUserSummary[] {
    const rows = db.prepare('SELECT * FROM portal_users ORDER BY username ASC').all() as any[];
    return rows.map((r) => ({
      username: r.username,
      displayName: r.display_name,
      role: r.role,
      createdAt: r.created_at,
      lastLoginAt: r.last_login_at,
    }));
  },

  upsertPortalUser(input: {
    username: string;
    displayName: string;
    password: string;
    role?: string;
  }): PortalUserSummary {
    const now = new Date().toISOString();
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = hashPassword(input.password, salt);
    const uname = input.username.trim();
    db.prepare(`
      INSERT INTO portal_users (username, display_name, password_hash, password_salt, role, created_at)
      VALUES (?, ?, ?, ?, ?, ?)
      ON CONFLICT(username) DO UPDATE SET
        display_name = excluded.display_name,
        password_hash = excluded.password_hash,
        password_salt = excluded.password_salt,
        role = excluded.role
    `).run(uname, input.displayName.trim() || uname, hash, salt, input.role || 'Admin', now);
    return this.getPortalUsers().find((u) => u.username.toLowerCase() === uname.toLowerCase())!;
  },

  deletePortalUser(username: string): boolean {
    const all = this.getPortalUsers();
    if (all.length <= 1) {
      throw new Error('Cannot delete the last remaining portal administrator account.');
    }
    const res = db.prepare('DELETE FROM portal_users WHERE username = ?').run(username);
    return res.changes > 0;
  },

  // ============================================================================
  // 2. SALESFORCE -> PROFILES (List + CSV Import + Org Pull & Reconciliation)
  // ============================================================================
  getProfiles(): SalesforceProfile[] {
    const rows = db.prepare('SELECT * FROM sf_profiles ORDER BY name ASC').all() as any[];
    return rows.map((r) => ({
      id: r.id,
      name: r.name,
      missingInOrg: Boolean(r.missing_in_org),
      updatedAt: r.updated_at,
    }));
  },

  getProfileById(id: string): SalesforceProfile | null {
    const r = db.prepare('SELECT * FROM sf_profiles WHERE id = ?').get(id.trim()) as any;
    if (!r) return null;
    return {
      id: r.id,
      name: r.name,
      missingInOrg: Boolean(r.missing_in_org),
      updatedAt: r.updated_at,
    };
  },

  upsertProfile(
    id: string,
    name: string,
    missingInOrg = false
  ): { profile: SalesforceProfile; action: 'inserted' | 'updated' } {
    const cleanId = id.trim();
    const cleanName = name.trim();
    const existing = this.getProfileById(cleanId);
    const now = new Date().toISOString();
    db.prepare(`
      INSERT INTO sf_profiles (id, name, missing_in_org, updated_at)
      VALUES (?, ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET
        name = excluded.name,
        missing_in_org = excluded.missing_in_org,
        updated_at = excluded.updated_at
    `).run(cleanId, cleanName, missingInOrg ? 1 : 0, now);
    return {
      profile: { id: cleanId, name: cleanName, missingInOrg, updatedAt: now },
      action: existing ? 'updated' : 'inserted',
    };
  },

  importProfilesFromCsvRows(
    rows: Array<{ id: string; name: string }>
  ): { inserted: number; updated: number; total: number } {
    let inserted = 0;
    let updated = 0;
    for (const r of rows) {
      if (!r.id || !r.name) continue;
      const res = this.upsertProfile(r.id, r.name, false);
      if (res.action === 'inserted') inserted++;
      else updated++;
    }
    return { inserted, updated, total: this.getProfiles().length };
  },

  deleteProfile(id: string): boolean {
    const res = db.prepare('DELETE FROM sf_profiles WHERE id = ?').run(id.trim());
    return res.changes > 0;
  },

  previewProfilesSyncFromOrg(
    orgProfiles: Array<{ id: string; name: string; userType?: string }>,
    orgInfo: { orgId: string; instanceUrl: string }
  ): ProfileSyncDiffPreview {
    const existingProfiles = this.getProfiles();
    const existingMap = new Map(existingProfiles.map((p) => [p.id, p]));
    const orgMap = new Map(orgProfiles.map((p) => [p.id.trim(), p]));

    const mappings = this.getProfileGroupMappings();
    const groups = this.getGroups();

    const added: ProfileSyncDiffPreview['added'] = [];
    const updated: ProfileSyncDiffPreview['updated'] = [];
    const removedFromOrg: ProfileSyncDiffPreview['removedFromOrg'] = [];

    for (const op of orgProfiles) {
      const cleanId = op.id.trim();
      const cleanName = op.name.trim();
      const prev = existingMap.get(cleanId);
      if (!prev) {
        added.push({
          id: cleanId,
          name: cleanName,
          userType: op.userType || 'Standard',
        });
      } else {
        updated.push({
          id: cleanId,
          name: cleanName,
          previousName: prev.name,
          unchanged: prev.name === cleanName && !prev.missingInOrg,
        });
      }
    }

    for (const local of existingProfiles) {
      if (!orgMap.has(local.id)) {
        const m = mappings.find((item) => item.profileId === local.id);
        const mappedGroupNames = (m?.groupIds || []).map(
          (gid) => groups.find((g) => g.id === gid)?.name || gid
        );
        removedFromOrg.push({
          id: local.id,
          name: local.name,
          mappedGroupNames,
        });
      }
    }

    return {
      orgId: orgInfo.orgId,
      instanceUrl: orgInfo.instanceUrl,
      added,
      updated,
      removedFromOrg,
    };
  },

  applyProfilesSyncFromOrg(input: {
    upserts: Array<{ id: string; name: string }>;
    removeProfileIds: string[];
    keptMissingProfileIds?: string[];
  }): { inserted: number; updated: number; removed: number; keptMissing: number; total: number } {
    let inserted = 0;
    let updated = 0;
    let removed = 0;
    let keptMissing = 0;

    for (const p of input.upserts) {
      if (!p.id || !p.name) continue;
      const res = this.upsertProfile(p.id, p.name, false);
      if (res.action === 'inserted') inserted++;
      else updated++;
    }

    for (const remId of input.removeProfileIds || []) {
      if (this.deleteProfile(remId)) {
        removed++;
      }
    }

    for (const keptId of input.keptMissingProfileIds || []) {
      const existing = this.getProfileById(keptId);
      if (existing) {
        db.prepare('UPDATE sf_profiles SET missing_in_org = 1 WHERE id = ?').run(keptId.trim());
        keptMissing++;
      }
    }

    return {
      inserted,
      updated,
      removed,
      keptMissing,
      total: this.getProfiles().length,
    };
  },

  // ============================================================================
  // 3. SALESFORCE -> OBJECTS (Toggle On/Off + SFDX Folder Import + Org Pull & Reconciliation)
  // ============================================================================
  getObjects(): SalesforceObject[] {
    const objRows = db.prepare('SELECT * FROM sf_objects ORDER BY object_name ASC').all() as any[];
    const fieldRows = db
      .prepare('SELECT * FROM sf_object_fields ORDER BY object_name ASC, field_name ASC')
      .all() as any[];

    const fieldsByObj = new Map<string, SalesforceObjectField[]>();
    for (const f of fieldRows) {
      const list = fieldsByObj.get(f.object_name) || [];
      list.push({
        objectName: f.object_name,
        fieldName: f.field_name,
        label: f.label,
        fieldType: f.field_type,
        isCustom: Boolean(f.is_custom),
        required: Boolean(f.required),
        enabled: Boolean(f.enabled),
        missingInOrg: Boolean(f.missing_in_org),
      });
      fieldsByObj.set(f.object_name, list);
    }

    return objRows.map((o) => {
      const fields = fieldsByObj.get(o.object_name) || [];
      return {
        objectName: o.object_name,
        label: o.label,
        isCustom: Boolean(o.is_custom),
        enabled: Boolean(o.enabled),
        sourcePath: o.source_path,
        fieldCount: fields.length,
        enabledFieldCount: fields.filter((f) => f.enabled).length,
        fields,
        missingInOrg: Boolean(o.missing_in_org),
        updatedAt: o.updated_at,
      };
    });
  },

  upsertObjectWithFields(input: {
    objectName: string;
    label?: string;
    isCustom?: boolean;
    enabled?: boolean;
    sourcePath?: string;
    missingInOrg?: boolean;
    fields?: Array<{
      fieldName: string;
      label?: string;
      fieldType?: string;
      isCustom?: boolean;
      required?: boolean;
      enabled?: boolean;
      missingInOrg?: boolean;
    }>;
  }): SalesforceObject {
    const now = new Date().toISOString();
    const objName = input.objectName.trim();
    const existing = db
      .prepare('SELECT * FROM sf_objects WHERE object_name = ?')
      .get(objName) as any;

    const isCustom =
      input.isCustom !== undefined
        ? input.isCustom
        : objName.endsWith('__c') || objName.endsWith('__mdt');
    const label = input.label?.trim() || existing?.label || objName;
    const enabled =
      input.enabled !== undefined
        ? input.enabled
        : existing
        ? Boolean(existing.enabled)
        : true;
    const sourcePath = input.sourcePath ?? existing?.source_path ?? 'manual';
    const missingInOrg = input.missingInOrg ? 1 : 0;

    db.prepare(`
      INSERT INTO sf_objects (object_name, label, is_custom, enabled, source_path, missing_in_org, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(object_name) DO UPDATE SET
        label = excluded.label,
        is_custom = excluded.is_custom,
        enabled = excluded.enabled,
        source_path = excluded.source_path,
        missing_in_org = excluded.missing_in_org,
        updated_at = excluded.updated_at
    `).run(objName, label, isCustom ? 1 : 0, enabled ? 1 : 0, sourcePath, missingInOrg, now);

    const fieldsToUpsert = input.fields || [
      { fieldName: 'Id', label: 'Record ID', fieldType: 'Id', isCustom: false, required: true },
      { fieldName: 'Name', label: 'Name', fieldType: 'Text', isCustom: false, required: false },
    ];

    const upsertFieldStmt = db.prepare(`
      INSERT INTO sf_object_fields (object_name, field_name, label, field_type, is_custom, required, enabled, missing_in_org)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(object_name, field_name) DO UPDATE SET
        label = excluded.label,
        field_type = excluded.field_type,
        is_custom = excluded.is_custom,
        required = excluded.required,
        missing_in_org = excluded.missing_in_org
    `);

    for (const f of fieldsToUpsert) {
      if (!f.fieldName) continue;
      upsertFieldStmt.run(
        objName,
        f.fieldName.trim(),
        (f.label || f.fieldName).trim(),
        f.fieldType || 'Text',
        (f.isCustom ?? f.fieldName.endsWith('__c')) ? 1 : 0,
        f.required ? 1 : 0,
        f.enabled !== undefined ? (f.enabled ? 1 : 0) : 1,
        f.missingInOrg ? 1 : 0
      );
    }

    return this.getObjects().find((o) => o.objectName === objName)!;
  },

  importObjectsFromParsedSfdx(
    parsedObjects: ReturnType<typeof parseSfdxFilesToObjects>
  ): { objectsImported: number; fieldsImported: number } {
    let objectsImported = 0;
    let fieldsImported = 0;
    for (const obj of parsedObjects) {
      this.upsertObjectWithFields({
        objectName: obj.objectName,
        label: obj.label,
        isCustom: obj.isCustom,
        sourcePath: obj.sourcePath,
        fields: obj.fields,
      });
      objectsImported++;
      fieldsImported += obj.fields.length;
    }
    return { objectsImported, fieldsImported };
  },

  importObjectsFromLocalDiskFolder(folderPath: string): {
    objectsImported: number;
    fieldsImported: number;
    resolvedPath: string;
  } {
    const resolved = path.resolve(folderPath.trim());
    if (!fs.existsSync(resolved) || !fs.statSync(resolved).isDirectory()) {
      throw new Error(`Directory not found on server: ${resolved}`);
    }

    const collectedFiles: Array<{ relativePath: string; content: string }> = [];
    const walk = (dir: string) => {
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          walk(full);
        } else if (
          entry.name.endsWith('.xml') ||
          entry.name.endsWith('.object') ||
          entry.name.endsWith('.field')
        ) {
          collectedFiles.push({
            relativePath: path.relative(resolved, full),
            content: fs.readFileSync(full, 'utf8'),
          });
        }
      }
    };

    // Also support SFDX directories where an object subfolder has no `.object-meta.xml` but has `fields/`
    const topEntries = fs.readdirSync(resolved, { withFileTypes: true });
    for (const entry of topEntries) {
      if (entry.isDirectory() && !entry.name.startsWith('.')) {
        const objMetaPath = path.join(resolved, entry.name, `${entry.name}.object-meta.xml`);
        if (!fs.existsSync(objMetaPath)) {
          collectedFiles.push({
            relativePath: `${entry.name}/${entry.name}.object-meta.xml`,
            content: `<CustomObject><label>${entry.name}</label></CustomObject>`,
          });
        }
      }
    }

    walk(resolved);
    const parsed = parseSfdxFilesToObjects(collectedFiles);
    const result = this.importObjectsFromParsedSfdx(parsed);

    // Save the folder path in settings for easy re-sync
    db.prepare('UPDATE sf_connection_settings SET sfdx_objects_folder_path = ?, updated_at = ? WHERE id = 1').run(
      resolved,
      new Date().toISOString()
    );

    return { ...result, resolvedPath: resolved };
  },

  toggleObject(objectName: string, enabled: boolean): SalesforceObject | null {
    const now = new Date().toISOString();
    db.prepare('UPDATE sf_objects SET enabled = ?, updated_at = ? WHERE object_name = ?').run(
      enabled ? 1 : 0,
      now,
      objectName
    );
    return this.getObjects().find((o) => o.objectName === objectName) || null;
  },

  toggleObjectField(objectName: string, fieldName: string, enabled: boolean): SalesforceObject | null {
    db.prepare(
      'UPDATE sf_object_fields SET enabled = ? WHERE object_name = ? AND field_name = ?'
    ).run(enabled ? 1 : 0, objectName, fieldName);
    return this.getObjects().find((o) => o.objectName === objectName) || null;
  },

  deleteObjectField(objectName: string, fieldName: string): SalesforceObject | null {
    db.prepare(
      'DELETE FROM sf_object_fields WHERE object_name = ? AND field_name = ?'
    ).run(objectName.trim(), fieldName.trim());
    return this.getObjects().find((o) => o.objectName === objectName.trim()) || null;
  },

  deleteObject(objectName: string): boolean {
    const res = db.prepare('DELETE FROM sf_objects WHERE object_name = ?').run(objectName);
    return res.changes > 0;
  },

  /**
   * Computes a non-destructive preview of Object & Field additions, updates, and removals
   * compared against the live Salesforce Org metadata.
   */
  previewObjectsSyncFromOrg(
    pulledMetadata: PulledOrgObjectMetadata[],
    orgInfo: { orgId: string; instanceUrl: string }
  ): ObjectSyncDiffPreview {
    const existingObjects = this.getObjects();
    const existingObjMap = new Map(
      existingObjects.map((o) => [o.objectName.toLowerCase(), o])
    );
    const groups = this.getGroups();

    const upsertedObjects: ObjectSyncDiffPreview['upsertedObjects'] = [];
    const removedObjectsFromOrg: ObjectSyncDiffPreview['removedObjectsFromOrg'] = [];

    for (const pulled of pulledMetadata) {
      const localObj = existingObjMap.get(pulled.objectName.toLowerCase());

      if (!pulled.existsInOrg) {
        if (localObj) {
          const referencedInGroups = groups
            .filter((g) =>
              g.objectPermissions.some(
                (op) => op.objectName.toLowerCase() === localObj.objectName.toLowerCase()
              )
            )
            .map((g) => g.name);

          removedObjectsFromOrg.push({
            objectName: localObj.objectName,
            label: localObj.label,
            fieldCount: localObj.fields.length,
            referencedInGroups,
          });
        }
        continue;
      }

      const orgFieldMap = new Map(
        pulled.fields.map((f) => [f.fieldName.toLowerCase(), f])
      );
      const localFieldMap = new Map(
        (localObj?.fields || []).map((f) => [f.fieldName.toLowerCase(), f])
      );

      const addedFields: ObjectSyncDiffPreview['upsertedObjects'][number]['addedFields'] = [];
      let updatedFieldsCount = 0;

      for (const f of pulled.fields) {
        if (!localFieldMap.has(f.fieldName.toLowerCase())) {
          addedFields.push(f);
        } else {
          updatedFieldsCount++;
        }
      }

      const removedFieldsFromOrg: ObjectSyncDiffPreview['upsertedObjects'][number]['removedFieldsFromOrg'] = [];
      if (localObj) {
        for (const lf of localObj.fields) {
          if (!orgFieldMap.has(lf.fieldName.toLowerCase())) {
            const referencedInGroups = groups
              .filter((g) =>
                g.objectPermissions.some(
                  (op) =>
                    op.objectName.toLowerCase() === localObj.objectName.toLowerCase() &&
                    op.allowedFields.some(
                      (af) => af.toLowerCase() === lf.fieldName.toLowerCase()
                    )
                )
              )
              .map((g) => g.name);

            removedFieldsFromOrg.push({
              objectName: localObj.objectName,
              fieldName: lf.fieldName,
              label: lf.label,
              fieldType: lf.fieldType,
              enabled: lf.enabled,
              referencedInGroups,
            });
          }
        }
      }

      upsertedObjects.push({
        objectName: pulled.objectName,
        label: pulled.label,
        isCustom: pulled.isCustom,
        isNewObject: !localObj,
        totalOrgFields: pulled.fields.length,
        addedFields,
        updatedFieldsCount,
        removedFieldsFromOrg,
      });
    }

    return {
      orgId: orgInfo.orgId,
      instanceUrl: orgInfo.instanceUrl,
      upsertedObjects,
      removedObjectsFromOrg,
    };
  },

  /**
   * Applies the Object & Field sync from Salesforce Org, deleting ONLY the objects/fields
   * the user explicitly chose to remove, and marking kept removed items with `missing_in_org = 1`.
   */
  applyObjectsSyncFromOrg(input: {
    pulledMetadata: PulledOrgObjectMetadata[];
    removeObjectNames: string[];
    removeFields: Array<{ objectName: string; fieldName: string }>;
  }): {
    objectsUpserted: number;
    fieldsUpserted: number;
    objectsRemoved: number;
    fieldsRemoved: number;
    objectsKeptMissing: number;
    fieldsKeptMissing: number;
  } {
    const removeObjSet = new Set(
      (input.removeObjectNames || []).map((n) => n.toLowerCase())
    );
    const removeFieldSet = new Set(
      (input.removeFields || []).map(
        (f) => `${f.objectName.toLowerCase()}.${f.fieldName.toLowerCase()}`
      )
    );

    let objectsUpserted = 0;
    let fieldsUpserted = 0;
    let objectsRemoved = 0;
    let fieldsRemoved = 0;
    let objectsKeptMissing = 0;
    let fieldsKeptMissing = 0;

    const existingObjects = this.getObjects();
    const existingObjMap = new Map(
      existingObjects.map((o) => [o.objectName.toLowerCase(), o])
    );

    for (const pulled of input.pulledMetadata) {
      const localObj = existingObjMap.get(pulled.objectName.toLowerCase());

      if (!pulled.existsInOrg) {
        if (localObj) {
          if (removeObjSet.has(localObj.objectName.toLowerCase())) {
            if (this.deleteObject(localObj.objectName)) {
              objectsRemoved++;
            }
          } else {
            db.prepare(
              'UPDATE sf_objects SET missing_in_org = 1, updated_at = ? WHERE object_name = ?'
            ).run(new Date().toISOString(), localObj.objectName);
            objectsKeptMissing++;
          }
        }
        continue;
      }

      // Upsert the object and all present org fields (setting missing_in_org = 0)
      this.upsertObjectWithFields({
        objectName: pulled.objectName,
        label: pulled.label,
        isCustom: pulled.isCustom,
        sourcePath: 'salesforce-org-jwt',
        missingInOrg: false,
        fields: pulled.fields.map((f) => ({
          ...f,
          missingInOrg: false,
        })),
      });
      objectsUpserted++;
      fieldsUpserted += pulled.fields.length;

      // Handle local fields on this object that were NOT in the Salesforce Org
      if (localObj) {
        const orgFieldSet = new Set(
          pulled.fields.map((f) => f.fieldName.toLowerCase())
        );
        for (const lf of localObj.fields) {
          if (!orgFieldSet.has(lf.fieldName.toLowerCase())) {
            const key = `${localObj.objectName.toLowerCase()}.${lf.fieldName.toLowerCase()}`;
            if (removeFieldSet.has(key)) {
              this.deleteObjectField(localObj.objectName, lf.fieldName);
              fieldsRemoved++;
            } else {
              db.prepare(
                'UPDATE sf_object_fields SET missing_in_org = 1 WHERE object_name = ? AND field_name = ?'
              ).run(localObj.objectName, lf.fieldName);
              fieldsKeptMissing++;
            }
          }
        }
      }
    }

    return {
      objectsUpserted,
      fieldsUpserted,
      objectsRemoved,
      fieldsRemoved,
      objectsKeptMissing,
      fieldsKeptMissing,
    };
  },

  // ============================================================================
  // 4. ACCESS MATRIX -> GROUPS & PROFILE-GROUP MATRIX
  // ============================================================================
  getGroups(): AccessGroup[] {
    const rows = db.prepare('SELECT * FROM access_groups ORDER BY name ASC').all() as any[];
    return rows.map((r) => ({
      id: r.id,
      name: r.name,
      description: r.description,
      allowedActions: JSON.parse(r.allowed_actions_json || '[]'),
      objectPermissions: JSON.parse(r.object_permissions_json || '[]'),
      updatedAt: r.updated_at,
    }));
  },

  upsertGroup(input: {
    id?: string;
    name: string;
    description?: string;
    allowedActions: string[];
    objectPermissions: GroupObjectPermission[];
  }): AccessGroup {
    const now = new Date().toISOString();
    const id =
      input.id?.trim() ||
      `grp_${input.name
        .trim()
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '_')}_${Math.random().toString(36).slice(2, 5)}`;

    db.prepare(`
      INSERT INTO access_groups (id, name, description, allowed_actions_json, object_permissions_json, updated_at)
      VALUES (?, ?, ?, ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET
        name = excluded.name,
        description = excluded.description,
        allowed_actions_json = excluded.allowed_actions_json,
        object_permissions_json = excluded.object_permissions_json,
        updated_at = excluded.updated_at
    `).run(
      id,
      input.name.trim(),
      (input.description || '').trim(),
      JSON.stringify(input.allowedActions || []),
      JSON.stringify(input.objectPermissions || []),
      now
    );

    return this.getGroups().find((g) => g.id === id)!;
  },

  deleteGroup(id: string): boolean {
    const res = db.prepare('DELETE FROM access_groups WHERE id = ?').run(id);
    return res.changes > 0;
  },

  getProfileGroupMappings(): ProfileGroupMapping[] {
    const profiles = this.getProfiles();
    const rows = db.prepare('SELECT * FROM profile_group_memberships').all() as Array<{
      profile_id: string;
      group_id: string;
    }>;
    const byProfile = new Map<string, string[]>();
    for (const r of rows) {
      const list = byProfile.get(r.profile_id) || [];
      list.push(r.group_id);
      byProfile.set(r.profile_id, list);
    }
    return profiles.map((p) => ({
      profileId: p.id,
      groupIds: byProfile.get(p.id) || [],
    }));
  },

  setProfileGroups(profileId: string, groupIds: string[]): ProfileGroupMapping {
    db.prepare('DELETE FROM profile_group_memberships WHERE profile_id = ?').run(profileId);
    const ins = db.prepare(
      'INSERT OR IGNORE INTO profile_group_memberships (profile_id, group_id) VALUES (?, ?)'
    );
    for (const gid of groupIds) {
      ins.run(profileId, gid);
    }
    return { profileId, groupIds };
  },

  // ============================================================================
  // 5. DUAL AUDIT LOGS (Copilot MCP Logs [Sanitized] & Portal Admin Logs)
  // ============================================================================
  getCopilotMcpLogs(limit = 150): CopilotMcpLogRecord[] {
    const rows = db
      .prepare('SELECT * FROM mcp_copilot_logs ORDER BY rowid DESC LIMIT ?')
      .all(limit) as any[];
    return rows.map((r) => ({
      id: r.id,
      timestamp: r.timestamp,
      sfUsername: r.sf_username,
      profileId: r.profile_id,
      profileName: r.profile_name,
      matchedGroups: JSON.parse(r.matched_groups_json || '[]'),
      toolName: r.tool_name,
      targetObject: r.target_object,
      status: r.status,
      latencyMs: r.latency_ms,
      sanitizedRequestPayload: r.sanitized_request_payload,
      sanitizedResponseSummary: r.sanitized_response_summary,
    }));
  },

  recordCopilotMcpLog(input: {
    sfUsername: string;
    profileId: string;
    profileName: string;
    matchedGroups: string[];
    toolName: string;
    targetObject: string;
    status: 'ALLOWED' | 'DENIED' | 'ERROR';
    latencyMs: number;
    rawRequestPayload: unknown;
    rawResponseSummary: unknown;
  }): CopilotMcpLogRecord {
    const id = `mcp_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 6)}`;
    const timestamp = new Date().toISOString();
    const sanitizedReq = JSON.stringify(
      stripSensitivePayloadData(input.rawRequestPayload),
      null,
      2
    );
    const sanitizedRes = JSON.stringify(
      stripSensitivePayloadData(input.rawResponseSummary),
      null,
      2
    );

    db.prepare(`
      INSERT INTO mcp_copilot_logs (
        id, timestamp, sf_username, profile_id, profile_name, matched_groups_json,
        tool_name, target_object, status, latency_ms,
        sanitized_request_payload, sanitized_response_summary
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      timestamp,
      input.sfUsername,
      input.profileId,
      input.profileName,
      JSON.stringify(input.matchedGroups),
      input.toolName,
      input.targetObject || '',
      input.status,
      input.latencyMs,
      sanitizedReq,
      sanitizedRes
    );

    return {
      id,
      timestamp,
      sfUsername: input.sfUsername,
      profileId: input.profileId,
      profileName: input.profileName,
      matchedGroups: input.matchedGroups,
      toolName: input.toolName,
      targetObject: input.targetObject,
      status: input.status,
      latencyMs: input.latencyMs,
      sanitizedRequestPayload: sanitizedReq,
      sanitizedResponseSummary: sanitizedRes,
    };
  },

  getPortalAdminLogs(limit = 150): PortalAdminLogRecord[] {
    const rows = db
      .prepare('SELECT * FROM portal_admin_logs ORDER BY rowid DESC LIMIT ?')
      .all(limit) as any[];
    return rows.map((r) => ({
      id: r.id,
      timestamp: r.timestamp,
      adminUsername: r.admin_username,
      authMethod: r.auth_method,
      action: r.action,
      target: r.target,
      details: r.details,
      ipAddress: r.ip_address,
    }));
  },

  recordPortalAdminLog(input: {
    adminUsername: string;
    authMethod: 'password' | 'okta_sso';
    action: string;
    target: string;
    details: string;
    ipAddress?: string;
  }): PortalAdminLogRecord {
    const id = `adm_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 6)}`;
    const timestamp = new Date().toISOString();
    const ip = input.ipAddress || '127.0.0.1';

    db.prepare(`
      INSERT INTO portal_admin_logs (
        id, timestamp, admin_username, auth_method, action, target, details, ip_address
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      timestamp,
      input.adminUsername,
      input.authMethod,
      input.action,
      input.target,
      input.details,
      ip
    );

    return {
      id,
      timestamp,
      adminUsername: input.adminUsername,
      authMethod: input.authMethod,
      action: input.action,
      target: input.target,
      details: input.details,
      ipAddress: ip,
    };
  },

  // ============================================================================
  // 6. OKTA SSO & SALESFORCE CONNECTION SETTINGS
  // ============================================================================
  getOktaConfig(): OktaSsoSettings & { clientSecret: string } {
    const row = db.prepare('SELECT * FROM okta_config WHERE id = 1').get() as any;
    let secret = '';
    try {
      secret = row.client_secret_enc ? decryptSecret(row.client_secret_enc) : '';
    } catch {
      secret = '';
    }
    return {
      enabled: Boolean(row.enabled),
      oktaDomain: row.okta_domain,
      issuer: row.issuer,
      clientId: row.client_id,
      clientSecret: secret,
      hasClientSecret: Boolean(secret),
      redirectUri: row.redirect_uri,
      adminGroup: row.admin_group,
      updatedAt: row.updated_at,
    };
  },

  updateOktaConfig(input: {
    enabled?: boolean;
    oktaDomain?: string;
    issuer?: string;
    clientId?: string;
    clientSecret?: string;
    redirectUri?: string;
    adminGroup?: string;
  }): OktaSsoSettings {
    const current = this.getOktaConfig();
    const nextSecret =
      input.clientSecret !== undefined && input.clientSecret !== ''
        ? input.clientSecret
        : current.clientSecret;
    const nextDomain = (input.oktaDomain ?? current.oktaDomain).trim();
    const nextIssuer =
      input.issuer !== undefined
        ? input.issuer.trim()
        : nextDomain
        ? `https://${nextDomain.replace(/^https?:\/\//, '')}/oauth2/default`
        : '';
    const now = new Date().toISOString();

    db.prepare(`
      UPDATE okta_config
      SET enabled = ?, okta_domain = ?, issuer = ?, client_id = ?,
          client_secret_enc = ?, redirect_uri = ?, admin_group = ?, updated_at = ?
      WHERE id = 1
    `).run(
      (input.enabled ?? current.enabled) ? 1 : 0,
      nextDomain,
      nextIssuer,
      (input.clientId ?? current.clientId).trim(),
      nextSecret ? encryptSecret(nextSecret) : '',
      (input.redirectUri ?? current.redirectUri).trim(),
      (input.adminGroup ?? current.adminGroup).trim(),
      now
    );

    const updated = this.getOktaConfig();
    return {
      enabled: updated.enabled,
      oktaDomain: updated.oktaDomain,
      issuer: updated.issuer,
      clientId: updated.clientId,
      hasClientSecret: updated.hasClientSecret,
      redirectUri: updated.redirectUri,
      adminGroup: updated.adminGroup,
      updatedAt: updated.updatedAt,
    };
  },

  getSalesforceSettings(): SalesforceConnectionSettings & { privateKeyPem?: string } {
    const row = db.prepare('SELECT * FROM sf_connection_settings WHERE id = 1').get() as any;
    let privateKeyPem = '';
    try {
      privateKeyPem = row.private_key_enc ? decryptSecret(row.private_key_enc) : '';
    } catch {
      privateKeyPem = '';
    }
    return {
      enabled: Boolean(row.enabled),
      authMode: row.auth_mode === 'simulated' ? 'simulated' : 'jwt_bearer',
      loginUrl: row.login_url || 'https://login.salesforce.com',
      clientId: row.client_id || '',
      username: row.username || '',
      hasPrivateKey: Boolean(privateKeyPem),
      certificatePem: row.certificate_pem || '',
      certFingerprint: row.cert_fingerprint || '',
      connectionStatus:
        row.connection_status === 'connected' || row.connection_status === 'error'
          ? row.connection_status
          : 'disconnected',
      lastConnectedAt: row.last_connected_at || null,
      lastError: row.last_error || '',
      connectedOrgId: row.connected_org_id || '',
      connectedUser: row.connected_user || '',
      expectedOrgId: row.expected_org_id || '',
      instanceUrl: row.instance_url || 'https://login.salesforce.com',
      apiVersion: row.api_version || 'v62.0',
      enforceOrgIdLock: Boolean(row.enforce_org_id_lock),
      sfdxObjectsFolderPath: row.sfdx_objects_folder_path || '',
      updatedAt: row.updated_at,
    };
  },

  getSalesforceSettingsWithSecrets(): SalesforceConnectionSettings & { privateKeyPem: string } {
    const row = db.prepare('SELECT * FROM sf_connection_settings WHERE id = 1').get() as any;
    let privateKeyPem = '';
    try {
      privateKeyPem = row.private_key_enc ? decryptSecret(row.private_key_enc) : '';
    } catch {
      privateKeyPem = '';
    }
    const base = this.getSalesforceSettings();
    return {
      ...base,
      privateKeyPem,
    };
  },

  updateSalesforceSettings(
    input: Partial<SalesforceConnectionSettings> & { privateKeyPem?: string }
  ): SalesforceConnectionSettings {
    const current = this.getSalesforceSettingsWithSecrets();
    const now = new Date().toISOString();

    let nextPrivateKey = current.privateKeyPem;
    if (input.privateKeyPem !== undefined && input.privateKeyPem.trim() !== '') {
      nextPrivateKey = validatePrivateKeyPem(input.privateKeyPem);
    }

    const nextCertPem =
      input.certificatePem !== undefined
        ? input.certificatePem.trim()
        : current.certificatePem;
    const certInfo = inspectCertificatePem(nextCertPem);
    const nextFingerprint =
      input.certFingerprint !== undefined
        ? input.certFingerprint
        : certInfo?.fingerprintSha256 || current.certFingerprint;

    const nextLoginUrl = (input.loginUrl ?? current.loginUrl).trim() || 'https://login.salesforce.com';
    const nextInstanceUrl = (input.instanceUrl ?? current.instanceUrl).trim() || nextLoginUrl;

    db.prepare(`
      UPDATE sf_connection_settings
      SET enabled = ?,
          auth_mode = ?,
          login_url = ?,
          client_id = ?,
          username = ?,
          private_key_enc = ?,
          certificate_pem = ?,
          cert_fingerprint = ?,
          connection_status = ?,
          last_connected_at = ?,
          last_error = ?,
          connected_org_id = ?,
          connected_user = ?,
          expected_org_id = ?,
          instance_url = ?,
          api_version = ?,
          enforce_org_id_lock = ?,
          sfdx_objects_folder_path = ?,
          updated_at = ?
      WHERE id = 1
    `).run(
      (input.enabled ?? current.enabled) ? 1 : 0,
      input.authMode ?? current.authMode,
      nextLoginUrl,
      (input.clientId ?? current.clientId).trim(),
      (input.username ?? current.username).trim(),
      nextPrivateKey ? encryptSecret(nextPrivateKey) : '',
      nextCertPem,
      nextFingerprint,
      input.connectionStatus ?? current.connectionStatus,
      input.lastConnectedAt !== undefined ? input.lastConnectedAt : current.lastConnectedAt,
      input.lastError !== undefined ? input.lastError : current.lastError,
      (input.connectedOrgId ?? current.connectedOrgId).trim(),
      (input.connectedUser ?? current.connectedUser).trim(),
      (input.expectedOrgId ?? current.expectedOrgId).trim(),
      nextInstanceUrl,
      (input.apiVersion ?? current.apiVersion).trim(),
      (input.enforceOrgIdLock ?? current.enforceOrgIdLock) ? 1 : 0,
      (input.sfdxObjectsFolderPath ?? current.sfdxObjectsFolderPath).trim(),
      now
    );
    return this.getSalesforceSettings();
  },

  // Legacy compatibility alias for adminAuth.ts
  recordAudit(entry: {
    actor: string;
    action: string;
    target?: string;
    details?: string;
    ipAddress?: string;
  }) {
    this.recordPortalAdminLog({
      adminUsername: entry.actor,
      authMethod: 'okta_sso',
      action: entry.action,
      target: entry.target || 'System',
      details: entry.details || '',
      ipAddress: entry.ipAddress,
    });
  },
};
