import { DatabaseSync } from 'node:sqlite';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { config, KNOWN_DEFAULT_PASSWORDS } from '../config.js';
import { encryptSecret, decryptSecret } from '../security/crypto.js';
import { parseSfdxFilesToObjects, SALESFORCE_API_NAME_PATTERN } from './importers.js';
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
import { salesforceIdKey } from '../salesforce/ids.js';
import { isUninitialisedMcpTokenHost, SIMULATED_ORG_ID, SIMULATED_ORG_INSTANCE_URL } from '../salesforce/simulatedOrg.js';

const dbDir = path.dirname(config.dbPath);
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}

const db = new DatabaseSync(config.dbPath);

let transactionDepth = 0;
let transactionDoomed = false;

/**
 * Runs `fn` atomically: either every statement in it commits or none does. A nested call joins the
 * open transaction. Its failure dooms the whole transaction, even if an outer step catches the error,
 * so a half-applied inner step can never commit. `fn` must be synchronous.
 */
export function runInTransaction<T>(fn: () => T): T {
  if (transactionDepth > 0) {
    transactionDepth++;
    try {
      return fn();
    } catch (err) {
      transactionDoomed = true;
      throw err;
    } finally {
      transactionDepth--;
    }
  }

  db.exec('BEGIN IMMEDIATE');
  transactionDepth = 1;
  transactionDoomed = false;
  try {
    const result = fn();
    if (transactionDoomed) {
      throw new Error('Transaction rolled back: a nested step failed.');
    }
    db.exec('COMMIT');
    return result;
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  } finally {
    transactionDepth = 0;
    transactionDoomed = false;
  }
}

/**
 * Deletes a field and revokes it from every Access Group, reporting which groups lost it.
 * While a case variant still exists the grants still refer to it and stay.
 */
function deleteFieldAndRevokeGrants(objName: string, fldName: string): { deleted: boolean; revokedGroups: string[] } {
  return runInTransaction(() => {
    const res = db
      .prepare('DELETE FROM sf_object_fields WHERE object_name = ? AND field_name = ?')
      .run(objName, fldName);
    if (res.changes === 0) return { deleted: false, revokedGroups: [] };
    const variantRemains = db
      .prepare(
        'SELECT 1 FROM sf_object_fields WHERE lower(object_name) = lower(?) AND lower(field_name) = lower(?) LIMIT 1'
      )
      .get(objName, fldName);
    if (variantRemains) return { deleted: true, revokedGroups: [] };

    const now = new Date().toISOString();
    const rows = db.prepare('SELECT id, name, object_permissions_json FROM access_groups').all() as Array<{
      id: string;
      name: string;
      object_permissions_json: string;
    }>;
    const updateGroup = db.prepare(
      'UPDATE access_groups SET object_permissions_json = ?, updated_at = ? WHERE id = ?'
    );
    const revokedGroups: string[] = [];
    for (const row of rows) {
      const perms = JSON.parse(row.object_permissions_json || '[]') as GroupObjectPermission[];
      let changed = false;
      const kept = perms.map((p) => {
        if (String(p.objectName).toLowerCase() !== objName.toLowerCase()) return p;
        const allowedFields = (p.allowedFields || []).filter(
          (f) => String(f).toLowerCase() !== fldName.toLowerCase()
        );
        if (allowedFields.length === (p.allowedFields || []).length) return p;
        changed = true;
        return { ...p, allowedFields };
      });
      if (changed) {
        updateGroup.run(JSON.stringify(kept), now, row.id);
        revokedGroups.push(row.name);
      }
    }
    return { deleted: true, revokedGroups };
  });
}

/**
 * Deletes an Object and its fields and revokes it from every Access Group, reporting which groups
 * lost it. Grants match objects case-insensitively; while a case variant (e.g. 'Account' after
 * deleting a stray 'account') still exists, the grants still refer to it and must stay.
 */
function deleteObjectAndRevokeGrants(objectName: string): { deleted: boolean; revokedGroups: string[] } {
  return runInTransaction(() => {
    const res = db.prepare('DELETE FROM sf_objects WHERE object_name = ?').run(objectName);
    if (res.changes === 0) return { deleted: false, revokedGroups: [] };
    const variantRemains = db
      .prepare('SELECT 1 FROM sf_objects WHERE lower(object_name) = lower(?) LIMIT 1')
      .get(objectName);
    if (variantRemains) return { deleted: true, revokedGroups: [] };

    const now = new Date().toISOString();
    const rows = db.prepare('SELECT id, name, object_permissions_json FROM access_groups').all() as Array<{
      id: string;
      name: string;
      object_permissions_json: string;
    }>;
    const updateGroup = db.prepare(
      'UPDATE access_groups SET object_permissions_json = ?, updated_at = ? WHERE id = ?'
    );
    const revokedGroups: string[] = [];
    for (const row of rows) {
      const perms = JSON.parse(row.object_permissions_json || '[]') as GroupObjectPermission[];
      const kept = perms.filter((p) => String(p.objectName).toLowerCase() !== objectName.toLowerCase());
      if (kept.length !== perms.length) {
        updateGroup.run(JSON.stringify(kept), now, row.id);
        revokedGroups.push(row.name);
      }
    }
    return { deleted: true, revokedGroups };
  });
}

let warnedUndecryptableOktaSecret = false;
let warnedUndecryptablePrivateKey = false;

/** Decrypts the stored JWT private key. A key that cannot be decrypted reads as empty and is flagged, never thrown. */
function readStoredPrivateKey(privateKeyEnc: string): { privateKeyPem: string; undecryptable: boolean } {
  try {
    return { privateKeyPem: privateKeyEnc ? decryptSecret(privateKeyEnc) : '', undecryptable: false };
  } catch {
    // Usually APP_SECRET_KEY changed. Keep the ciphertext (updateSalesforceSettings never overwrites
    // it unless a new key is entered) and tell the operator once.
    if (!warnedUndecryptablePrivateKey) {
      warnedUndecryptablePrivateKey = true;
      console.warn(
        '[store] The stored Salesforce JWT private key cannot be decrypted with the current APP_SECRET_KEY. Restore that key, or enter a new private key in Connect to Salesforce Org.'
      );
    }
    return { privateKeyPem: '', undecryptable: true };
  }
}

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
    sync_instance_url TEXT NOT NULL DEFAULT '',
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
  ensureColumnExists('sf_connection_settings', 'sync_instance_url', "TEXT NOT NULL DEFAULT ''");

  ensureColumnExists('mcp_copilot_logs', 'simulated', 'INTEGER NOT NULL DEFAULT 0');
  repairConnectInstanceUrls();
}

/**
 * Connect used to write its host into instance_url, which MCP sends bearer tokens to. A connected row
 * keeps showing that host as its sync instance. The simulated host is removed from instance_url unless
 * a real org connected on it, because auth_mode alone does not show that: saving the mode or a failed
 * live connect could leave jwt_bearer on a simulated host. Any other value may be the admin's, so it stays.
 */
export function repairConnectInstanceUrls() {
  db.prepare(`
    UPDATE sf_connection_settings SET sync_instance_url = instance_url
    WHERE connection_status = 'connected' AND sync_instance_url = ''
  `).run();
  db.prepare(`
    UPDATE sf_connection_settings
    SET instance_url = CASE WHEN login_url = :host THEN 'https://login.salesforce.com' ELSE login_url END
    WHERE instance_url = :host
      AND (auth_mode = 'simulated' OR TRIM(connected_org_id) = '' OR connected_org_id = :orgId)
  `).run({ host: SIMULATED_ORG_INSTANCE_URL, orgId: SIMULATED_ORG_ID });
}

runSchemaMigrations();

function hashPassword(password: string, salt: string): string {
  return crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
}

/**
 * Production must not run with a portal account whose password is publicly known (e.g. a database
 * first created by `npm run dev`). The bootstrap account is rotated to ADMIN_BOOTSTRAP_PASSWORD when
 * that is set to something else; any other such account stops the server with instructions.
 */
function enforceNoKnownDefaultPasswords() {
  const rows = db
    .prepare('SELECT username, password_hash, password_salt FROM portal_users')
    .all() as Array<{ username: string; password_hash: string; password_salt: string }>;
  for (const row of rows) {
    const stored = Buffer.from(row.password_hash, 'hex');
    const usesKnownPassword = KNOWN_DEFAULT_PASSWORDS.some((known) => {
      const candidate = Buffer.from(hashPassword(known, row.password_salt), 'hex');
      return candidate.length === stored.length && crypto.timingSafeEqual(candidate, stored);
    });
    if (!usesKnownPassword) continue;

    const bootstrap = config.bootstrapAdmin;
    if (row.username.toLowerCase() === bootstrap.username.toLowerCase() && !bootstrap.usesDefaultPassword) {
      const salt = crypto.randomBytes(16).toString('hex');
      db.prepare('UPDATE portal_users SET password_hash = ?, password_salt = ? WHERE username = ?').run(
        hashPassword(bootstrap.password, salt),
        salt,
        row.username
      );
      console.warn(`[store] Rotated portal user '${row.username}' off a publicly known default password (ADMIN_BOOTSTRAP_PASSWORD).`);
      continue;
    }
    throw new Error(
      `FATAL: Portal user '${row.username}' uses a publicly known default password. Set ADMIN_BOOTSTRAP_USERNAME=${row.username} and a strong ADMIN_BOOTSTRAP_PASSWORD to rotate it at startup.`
    );
  }
}

function initializeSystemSingletons() {
  const now = new Date().toISOString();

  // Ensure at least one portal admin user exists so the user can sign in with username & password
  const userCount = (
    db.prepare('SELECT COUNT(*) as cnt FROM portal_users').get() as { cnt: number }
  ).cnt;
  if (userCount === 0) {
    const { username, password, usesDefaultPassword } = config.bootstrapAdmin;
    if (config.isProd && usesDefaultPassword) {
      throw new Error(
        'FATAL: Refusing to seed the bootstrap portal admin with the default password in production. Set ADMIN_BOOTSTRAP_PASSWORD.'
      );
    }
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = hashPassword(password, salt);
    db.prepare(`
      INSERT INTO portal_users (username, display_name, password_hash, password_salt, role, created_at)
      VALUES (?, 'Portal Administrator', ?, ?, 'Super Admin', ?)
    `).run(username, hash, salt, now);
  } else if (config.isProd) {
    enforceNoKnownDefaultPasswords();
  }

  const oktaCount = (
    db.prepare('SELECT COUNT(*) as cnt FROM okta_config').get() as { cnt: number }
  ).cnt;
  if (oktaCount === 0) {
    // Pre-fill from OKTA_* env vars; SSO stays disabled until an admin enables it in the portal.
    const issuer = config.okta.issuer.trim();
    let oktaDomain = '';
    try {
      oktaDomain = issuer ? new URL(issuer).host : '';
    } catch {
      oktaDomain = '';
    }
    db.prepare(`
      INSERT INTO okta_config (
        id, enabled, okta_domain, issuer, client_id, client_secret_enc, redirect_uri, admin_group, updated_at
      ) VALUES (1, 0, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      oktaDomain,
      issuer,
      config.okta.clientId.trim(),
      config.okta.clientSecret ? encryptSecret(config.okta.clientSecret) : '',
      config.okta.redirectUri,
      config.okta.requiredGroup,
      now
    );
  }

  const sfCount = (
    db.prepare('SELECT COUNT(*) as cnt FROM sf_connection_settings').get() as { cnt: number }
  ).cnt;
  if (sfCount === 0) {
    db.prepare(`
      INSERT INTO sf_connection_settings (
        id, expected_org_id, instance_url, api_version, enforce_org_id_lock, sfdx_objects_folder_path, updated_at
      ) VALUES (1, '', ?, ?, 0, '', ?)
    `).run(config.salesforce.loginUrl, config.salesforce.apiVersion, now);
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
    // Structural values (object/field API names, record ids, tool names) are kept; anything that
    // does not look like one (e.g. a record's values sent where field names belong) is redacted.
    const isStructuralToken = (item: unknown) =>
      typeof item === 'number' || (typeof item === 'string' && /^(\*|[A-Za-z0-9_.:-]{1,120})$/.test(item));
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(input as Record<string, unknown>)) {
      if (k === 'records' && Array.isArray(v)) {
        out.records = `[REDACTED ${v.length} RECORDS]`;
      } else if (k === 'soql' && typeof v === 'string') {
        // Redact quoted string literals in SOQL WHERE clauses (`'...'` -> `'[REDACTED]'`)
        out.soql = v.replace(/'(?:[^'\\]|\\.)*'?/g, "'[REDACTED]'");
      } else if (safeKeys.has(k) && (typeof v === 'number' || typeof v === 'boolean' || isStructuralToken(v))) {
        out[k] = v;
      } else if (Array.isArray(v) && safeKeys.has(k) && v.every(isStructuralToken)) {
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

export { parseSfdxFilesToObjects } from './importers.js';

/** Local Profile rows by Salesforce ID key, keeping `rows` order within each key. */
function groupProfileForms(rows: SalesforceProfile[]): Map<string, SalesforceProfile[]> {
  const forms = new Map<string, SalesforceProfile[]>();
  for (const row of rows) {
    const key = salesforceIdKey(row.id);
    forms.set(key, [...(forms.get(key) || []), row]);
  }
  return forms;
}

/** The ID a Profile is stored under after a sync: an 18-character form is never given up for a 15. */
function profileSyncTargetId(orgId: string, forms: SalesforceProfile[]): string {
  return forms.find((f) => f.id.length > orgId.length)?.id ?? orgId;
}

/**
 * Decides what a sync may do with several local rows that are forms of one org Profile. `forms` must
 * be in `getProfiles` order, so the first row is the one the policy engine resolves and its groups
 * are the access in force. Rows with different groups merge only if the union adds nothing to that;
 * otherwise neither dropping a row (a membership disappears) nor the union (access grows) is safe.
 * When only one set of groups exists it is kept even if an empty row is in force today, as that is
 * the assignment an admin made; the caller must report `granted`.
 */
function planProfileForms(forms: SalesforceProfile[], groupIdsOf: (profileId: string) => string[]) {
  const inForce = new Set(groupIdsOf(forms[0].id));
  const union = Array.from(new Set(forms.flatMap((f) => groupIdsOf(f.id))));
  const granted = union.filter((groupId) => !inForce.has(groupId));
  const distinctSets = new Set(
    forms.map((f) => [...groupIdsOf(f.id)].sort().join('\n')).filter((set) => set !== '')
  );
  return { conflict: distinctSets.size > 1 && granted.length > 0, union, granted };
}

export const store = {
  // ============================================================================
  // 1. PORTAL USERS & AUTHENTICATION
  // ============================================================================
  verifyPortalUserCredentials(username: string, password: string): PortalUserSummary | null {
    const row = db
      .prepare('SELECT * FROM portal_users WHERE lower(username) = lower(?)')
      .get(username.trim()) as any;
    if (!row) {
      // Spend the same PBKDF2 time for unknown usernames so response timing does not reveal them.
      hashPassword(password, 'unknown-user-timing-equalizer');
      return null;
    }

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

  portalUserExists(username: string): boolean {
    return Boolean(
      db.prepare('SELECT 1 AS found FROM portal_users WHERE lower(username) = lower(?)').get(username.trim())
    );
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
    displayName?: string;
    password: string;
    role?: string;
  }): PortalUserSummary {
    const now = new Date().toISOString();
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = hashPassword(input.password, salt);
    const uname = input.username.trim();
    // Sign-in matches usernames case-insensitively, so 'Admin' and 'admin' are the same account.
    const existing = db
      .prepare('SELECT username, display_name, role FROM portal_users WHERE lower(username) = lower(?)')
      .get(uname) as { username: string; display_name: string; role: string } | undefined;
    const targetUsername = existing?.username ?? uname;
    const displayName = input.displayName?.trim() || existing?.display_name || uname;
    const role = input.role?.trim() || existing?.role || 'Admin';
    db.prepare(`
      INSERT INTO portal_users (username, display_name, password_hash, password_salt, role, created_at)
      VALUES (?, ?, ?, ?, ?, ?)
      ON CONFLICT(username) DO UPDATE SET
        display_name = excluded.display_name,
        password_hash = excluded.password_hash,
        password_salt = excluded.password_salt,
        role = excluded.role
    `).run(targetUsername, displayName, hash, salt, role, now);
    return this.getPortalUsers().find((u) => u.username === targetUsername)!;
  },

  deletePortalUser(username: string): boolean {
    const requested = username.trim();
    // Resolve one exact row (preferring an exact-case match), so case variants left by older
    // versions are never deleted together and the last-administrator guard always holds.
    const target = db
      .prepare(
        'SELECT username FROM portal_users WHERE lower(username) = lower(?) ORDER BY (username = ?) DESC LIMIT 1'
      )
      .get(requested, requested) as { username: string } | undefined;
    if (!target) return false;
    if (this.getPortalUsers().length <= 1) {
      throw new Error('Cannot delete the last remaining portal administrator account.');
    }
    const res = db.prepare('DELETE FROM portal_users WHERE username = ?').run(target.username);
    return res.changes > 0;
  },

  // ============================================================================
  // 2. SALESFORCE -> PROFILES (List + CSV Import + Org Pull & Reconciliation)
  // ============================================================================
  getProfiles(): SalesforceProfile[] {
    const rows = db.prepare('SELECT * FROM sf_profiles ORDER BY name ASC, id ASC').all() as any[];
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
    const formsByKey = groupProfileForms(existingProfiles);
    const orgKeys = new Set(orgProfiles.map((p) => salesforceIdKey(p.id)));

    const mappings = this.getProfileGroupMappings();
    const groups = this.getGroups();
    const groupIdsOf = (profileId: string) =>
      mappings.find((item) => item.profileId === profileId)?.groupIds || [];
    const groupNames = (groupIds: string[]) =>
      groupIds.map((gid) => groups.find((g) => g.id === gid)?.name || gid);

    const added: ProfileSyncDiffPreview['added'] = [];
    const updated: ProfileSyncDiffPreview['updated'] = [];
    const removedFromOrg: ProfileSyncDiffPreview['removedFromOrg'] = [];
    const duplicates: ProfileSyncDiffPreview['duplicates'] = [];

    for (const op of orgProfiles) {
      const cleanId = op.id.trim();
      const cleanName = op.name.trim();
      const forms = formsByKey.get(salesforceIdKey(cleanId)) || [];
      if (forms.length === 0) {
        added.push({
          id: cleanId,
          name: cleanName,
          userType: op.userType || 'Standard',
        });
        continue;
      }
      const targetId = profileSyncTargetId(cleanId, forms);
      if (forms.length > 1) {
        const plan = planProfileForms(forms, groupIdsOf);
        duplicates.push({
          id: targetId,
          name: cleanName,
          rows: forms.map((f) => ({ id: f.id, name: f.name, groupNames: groupNames(groupIdsOf(f.id)) })),
          outcome: plan.conflict ? 'conflict' : 'merge',
          resultGroupNames: plan.conflict ? [] : groupNames(plan.union),
          grantedGroupNames: plan.conflict ? [] : groupNames(plan.granted),
        });
        if (plan.conflict) continue;
      }
      const prev = forms[0];
      updated.push({
        id: cleanId,
        name: cleanName,
        previousName: prev.name,
        ...(prev.id !== targetId ? { previousId: prev.id } : {}),
        unchanged: forms.length === 1 && prev.id === targetId && prev.name === cleanName && !prev.missingInOrg,
      });
    }

    for (const local of existingProfiles) {
      if (!orgKeys.has(salesforceIdKey(local.id))) {
        removedFromOrg.push({
          id: local.id,
          name: local.name,
          mappedGroupNames: groupNames(groupIdsOf(local.id)),
        });
      }
    }

    return {
      orgId: orgInfo.orgId,
      instanceUrl: orgInfo.instanceUrl,
      added,
      updated,
      removedFromOrg,
      duplicates,
    };
  },

  /**
   * Applies a Profile sync in one transaction: any failure leaves the database untouched. An id in
   * `upserts` is present in the org, so a remove or keep-as-missing entry for any form of it is
   * ignored. Local forms of an upserted id become one row under its 18-character form, memberships
   * included, unless `planProfileForms` finds a conflict: those rows stay exactly as they are, since
   * even a rename could change which one the policy engine resolves.
   */
  applyProfilesSyncFromOrg(input: {
    upserts: Array<{ id: string; name: string }>;
    removeProfileIds: string[];
    keptMissingProfileIds?: string[];
  }): {
    inserted: number;
    updated: number;
    removed: number;
    keptMissing: number;
    total: number;
    affected: {
      upserted: string[];
      removed: string[];
      keptMissing: string[];
      groupsLosingMembers: string[];
      idsUpgraded: string[];
      duplicatesMerged: string[];
      duplicatesUnresolved: string[];
      accessGranted: string[];
    };
  } {
    return runInTransaction(() => {
      let inserted = 0;
      let updated = 0;
      const affected = {
        upserted: [] as string[],
        removed: [] as string[],
        keptMissing: [] as string[],
        groupsLosingMembers: [] as string[],
        idsUpgraded: [] as string[],
        duplicatesMerged: [] as string[],
        duplicatesUnresolved: [] as string[],
        accessGranted: [] as string[],
      };
      const presentInOrg = new Set<string>();
      const formsByKey = groupProfileForms(this.getProfiles());
      const groupIdsOf = (profileId: string) =>
        (db
          .prepare('SELECT group_id FROM profile_group_memberships WHERE profile_id = ?')
          .all(profileId) as Array<{ group_id: string }>).map((row) => row.group_id);
      const groupName = db.prepare('SELECT name FROM access_groups WHERE id = ?');
      const moveMemberships = db.prepare(`
        INSERT OR IGNORE INTO profile_group_memberships (profile_id, group_id)
        SELECT ?, group_id FROM profile_group_memberships WHERE profile_id = ?
      `);

      for (const p of input.upserts) {
        if (!p.id || !p.name) continue;
        const key = salesforceIdKey(p.id);
        presentInOrg.add(key);
        const forms = formsByKey.get(key) || [];

        if (forms.length > 1) {
          const plan = planProfileForms(forms, groupIdsOf);
          if (plan.conflict) {
            affected.duplicatesUnresolved.push(p.name.trim());
            continue;
          }
          affected.duplicatesMerged.push(p.name.trim());
          for (const groupId of plan.granted) {
            const group = groupName.get(groupId) as { name: string } | undefined;
            affected.accessGranted.push(`${p.name.trim()} now grants ${group?.name || groupId}`);
          }
        }

        const targetId = profileSyncTargetId(p.id.trim(), forms);
        const res = this.upsertProfile(targetId, p.name, false);
        if (forms.length === 0) inserted++;
        else updated++;
        affected.upserted.push(res.profile.name);

        const replaced = forms.filter((f) => f.id !== targetId);
        for (const form of replaced) {
          // The foreign key has no ON UPDATE CASCADE, so memberships move before the old row goes.
          moveMemberships.run(targetId, form.id);
          this.deleteProfile(form.id);
        }
        if (forms.length === 1 && replaced.length === 1) affected.idsUpgraded.push(res.profile.name);
        formsByKey.set(key, [res.profile]);
      }

      const lostGroups = new Set<string>();
      const groupNamesOfProfile = db.prepare(`
        SELECT g.name AS name FROM profile_group_memberships m
        JOIN access_groups g ON g.id = m.group_id
        WHERE m.profile_id = ?
      `);
      for (const remId of input.removeProfileIds || []) {
        const id = remId.trim();
        if (presentInOrg.has(salesforceIdKey(id))) continue;
        const existing = this.getProfileById(id);
        if (!existing) continue;
        for (const row of groupNamesOfProfile.all(id) as Array<{ name: string }>) {
          lostGroups.add(row.name);
        }
        if (this.deleteProfile(id)) {
          affected.removed.push(existing.name);
        }
      }
      affected.groupsLosingMembers = Array.from(lostGroups);

      for (const keptId of input.keptMissingProfileIds || []) {
        const id = keptId.trim();
        if (presentInOrg.has(salesforceIdKey(id))) continue;
        const existing = this.getProfileById(id);
        if (existing) {
          db.prepare('UPDATE sf_profiles SET missing_in_org = 1 WHERE id = ?').run(id);
          affected.keptMissing.push(existing.name);
        }
      }

      return {
        inserted,
        updated,
        removed: affected.removed.length,
        keptMissing: affected.keptMissing.length,
        total: this.getProfiles().length,
        affected,
      };
    });
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

  /**
   * The stored spelling of an object name. Salesforce API names are case-insensitive, so a name
   * differing only by case is the same object: incoming names go through this first, because a new
   * row would start enabled and undo an admin's disable.
   */
  resolveObjectName(objectName: string): string {
    const name = objectName.trim();
    const row = (db.prepare('SELECT object_name FROM sf_objects WHERE object_name = ?').get(name) ||
      db
        .prepare('SELECT object_name FROM sf_objects WHERE lower(object_name) = lower(?) ORDER BY object_name LIMIT 1')
        .get(name)) as { object_name: string } | undefined;
    return row?.object_name ?? name;
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
    if (!SALESFORCE_API_NAME_PATTERN.test(objName)) {
      throw new Error(`'${objName}' is not a valid Salesforce object API name.`);
    }
    const invalidField = (input.fields || []).find(
      (f) => f?.fieldName && !SALESFORCE_API_NAME_PATTERN.test(String(f.fieldName).trim())
    );
    if (invalidField) {
      throw new Error(`'${invalidField.fieldName}' is not a valid Salesforce field API name.`);
    }
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
    // Only org sync passes this; a re-import or manual save must not clear what sync flagged.
    const missingInOrg =
      input.missingInOrg !== undefined
        ? input.missingInOrg
        : existing
        ? Boolean(existing.missing_in_org)
        : false;

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
    `).run(objName, label, isCustom ? 1 : 0, enabled ? 1 : 0, sourcePath, missingInOrg ? 1 : 0, now);

    const fieldsToUpsert = input.fields || [
      { fieldName: 'Id', label: 'Record ID', fieldType: 'Id', isCustom: false, required: true },
      { fieldName: 'Name', label: 'Name', fieldType: 'Text', isCustom: false, required: false },
    ];

    // An explicit `enabled` or `missingInOrg` is applied; when omitted (e.g. an SFDX re-import) an
    // existing field keeps the admin's manual toggle and what org sync flagged.
    const fieldUpsertSql = (applyEnabled: boolean, applyMissingInOrg: boolean) => `
      INSERT INTO sf_object_fields (object_name, field_name, label, field_type, is_custom, required, enabled, missing_in_org)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(object_name, field_name) DO UPDATE SET
        label = excluded.label,
        field_type = excluded.field_type,
        is_custom = excluded.is_custom,
        required = excluded.required${applyMissingInOrg ? ',\n        missing_in_org = excluded.missing_in_org' : ''}${applyEnabled ? ',\n        enabled = excluded.enabled' : ''}
    `;
    const fieldUpsertStatements = new Map<string, ReturnType<typeof db.prepare>>();
    const fieldUpsertStatement = (applyEnabled: boolean, applyMissingInOrg: boolean) => {
      const key = `${applyEnabled}:${applyMissingInOrg}`;
      let statement = fieldUpsertStatements.get(key);
      if (!statement) {
        statement = db.prepare(fieldUpsertSql(applyEnabled, applyMissingInOrg));
        fieldUpsertStatements.set(key, statement);
      }
      return statement;
    };

    const existingFieldNames = (
      db.prepare('SELECT field_name FROM sf_object_fields WHERE object_name = ? ORDER BY field_name').all(objName) as Array<{
        field_name: string;
      }>
    ).map((r) => r.field_name);
    const exactFieldNames = new Set(existingFieldNames);
    const fieldNameByLower = new Map<string, string>();
    for (const name of existingFieldNames) {
      if (!fieldNameByLower.has(name.toLowerCase())) fieldNameByLower.set(name.toLowerCase(), name);
    }

    for (const f of fieldsToUpsert) {
      if (!f.fieldName) continue;
      const requestedField = f.fieldName.trim();
      const fieldName = exactFieldNames.has(requestedField)
        ? requestedField
        : fieldNameByLower.get(requestedField.toLowerCase()) ?? requestedField;
      exactFieldNames.add(fieldName);
      if (!fieldNameByLower.has(fieldName.toLowerCase())) fieldNameByLower.set(fieldName.toLowerCase(), fieldName);
      const stmt = fieldUpsertStatement(f.enabled !== undefined, f.missingInOrg !== undefined);
      stmt.run(
        objName,
        fieldName,
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
        objectName: this.resolveObjectName(obj.objectName),
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

  /** Returns null when the object has no such field. */
  toggleObjectField(objectName: string, fieldName: string, enabled: boolean): SalesforceObject | null {
    const res = db.prepare(
      'UPDATE sf_object_fields SET enabled = ? WHERE object_name = ? AND field_name = ?'
    ).run(enabled ? 1 : 0, objectName, fieldName);
    if (res.changes === 0) return null;
    return this.getObjects().find((o) => o.objectName === objectName) || null;
  },

  /**
   * Deletes a field and revokes it from every Access Group, so a later sync that brings the field
   * back does not silently restore access an admin removed. Returns null when there is no such field.
   */
  deleteObjectField(objectName: string, fieldName: string): SalesforceObject | null {
    const objName = objectName.trim();
    const fldName = fieldName.trim();
    if (!deleteFieldAndRevokeGrants(objName, fldName).deleted) return null;
    return this.getObjects().find((o) => o.objectName === objName) || null;
  },

  /**
   * Deletes an Object and its fields, and revokes it from every Access Group, so re-importing the
   * object later (e.g. an SFDX re-sync) does not silently restore access an admin removed.
   */
  deleteObject(objectName: string): boolean {
    return deleteObjectAndRevokeGrants(objectName).deleted;
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
   * Applies the Object & Field sync from Salesforce Org in one transaction, so any failure leaves the
   * database untouched. Deletes ONLY the objects/fields the user explicitly chose to remove and the
   * pull reports as gone, and marks kept removed items with `missing_in_org = 1`.
   */
  applyObjectsSyncFromOrg(input: {
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
  }): {
    objectsUpserted: number;
    fieldsUpserted: number;
    objectsRemoved: number;
    fieldsRemoved: number;
    objectsKeptMissing: number;
    fieldsKeptMissing: number;
    affected: {
      objectsSynced: string[];
      objectsRemoved: string[];
      fieldsRemoved: string[];
      objectsKeptMissing: string[];
      fieldsKeptMissing: string[];
      groupsLosingGrants: string[];
    };
  } {
    const removeObjSet = new Set(
      (input.removeObjectNames || []).map((n) => n.toLowerCase())
    );
    const removeFieldSet = new Set(
      (input.removeFields || []).map(
        (f) => `${f.objectName.toLowerCase()}.${f.fieldName.toLowerCase()}`
      )
    );
    // Across every entry for a name: a field any of them reports is present, whatever the others say.
    const reportedFields = new Map<string, Set<string>>();
    for (const pulled of input.pulledMetadata) {
      const key = pulled.objectName.toLowerCase();
      const names = reportedFields.get(key) || new Set<string>();
      for (const f of pulled.fields) names.add(f.fieldName.toLowerCase());
      reportedFields.set(key, names);
    }

    return runInTransaction(() => {
      let fieldsUpserted = 0;
      const lostGrants = new Set<string>();
      const affected = {
        objectsSynced: [] as string[],
        objectsRemoved: [] as string[],
        fieldsRemoved: [] as string[],
        objectsKeptMissing: [] as string[],
        fieldsKeptMissing: [] as string[],
        groupsLosingGrants: [] as string[],
      };

      const existingObjects = this.getObjects();
      const existingObjMap = new Map(
        existingObjects.map((o) => [o.objectName.toLowerCase(), o])
      );

      for (const pulled of input.pulledMetadata) {
        const localObj = existingObjMap.get(pulled.objectName.toLowerCase());

        if (!pulled.existsInOrg) {
          if (localObj) {
            if (removeObjSet.has(localObj.objectName.toLowerCase())) {
              const result = deleteObjectAndRevokeGrants(localObj.objectName);
              if (result.deleted) {
                affected.objectsRemoved.push(localObj.objectName);
                result.revokedGroups.forEach((g) => lostGrants.add(g));
              }
            } else {
              db.prepare(
                'UPDATE sf_objects SET missing_in_org = 1, updated_at = ? WHERE object_name = ?'
              ).run(new Date().toISOString(), localObj.objectName);
              affected.objectsKeptMissing.push(localObj.objectName);
            }
          }
          continue;
        }

        // Upsert the object and all present org fields (setting missing_in_org = 0). Named one by one
        // so `enabled` stays the admin's: nothing in a pull may decide what is exposed.
        const syncedObject = this.upsertObjectWithFields({
          objectName: this.resolveObjectName(pulled.objectName),
          label: pulled.label,
          isCustom: pulled.isCustom,
          sourcePath: 'salesforce-org-jwt',
          missingInOrg: false,
          fields: pulled.fields.map((f) => ({
            fieldName: f.fieldName,
            label: f.label,
            fieldType: f.fieldType,
            isCustom: f.isCustom,
            required: f.required,
            missingInOrg: false,
          })),
        });
        affected.objectsSynced.push(syncedObject.objectName);
        fieldsUpserted += pulled.fields.length;

        // Handle local fields on this object that were NOT in the Salesforce Org
        if (localObj) {
          const orgFieldSet = reportedFields.get(pulled.objectName.toLowerCase())!;
          for (const lf of localObj.fields) {
            if (!orgFieldSet.has(lf.fieldName.toLowerCase())) {
              const key = `${localObj.objectName.toLowerCase()}.${lf.fieldName.toLowerCase()}`;
              const qualifiedName = `${localObj.objectName}.${lf.fieldName}`;
              if (removeFieldSet.has(key)) {
                const result = deleteFieldAndRevokeGrants(localObj.objectName, lf.fieldName);
                if (result.deleted) {
                  affected.fieldsRemoved.push(qualifiedName);
                  result.revokedGroups.forEach((g) => lostGrants.add(g));
                }
              } else {
                db.prepare(
                  'UPDATE sf_object_fields SET missing_in_org = 1 WHERE object_name = ? AND field_name = ?'
                ).run(localObj.objectName, lf.fieldName);
                affected.fieldsKeptMissing.push(qualifiedName);
              }
            }
          }
        }
      }
      affected.groupsLosingGrants = Array.from(lostGrants);

      return {
        objectsUpserted: affected.objectsSynced.length,
        fieldsUpserted,
        objectsRemoved: affected.objectsRemoved.length,
        fieldsRemoved: affected.fieldsRemoved.length,
        objectsKeptMissing: affected.objectsKeptMissing.length,
        fieldsKeptMissing: affected.fieldsKeptMissing.length,
        affected,
      };
    });
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
    const requestedId = input.id?.trim();
    // New groups get a random id, and a create is a plain INSERT, so it can never collide with
    // (and silently overwrite) another group. Passing an id updates that group.
    const id =
      requestedId ||
      `grp_${input.name
        .trim()
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '_')}_${crypto.randomBytes(6).toString('hex')}`;

    const insertSql = `
      INSERT INTO access_groups (id, name, description, allowed_actions_json, object_permissions_json, updated_at)
      VALUES (?, ?, ?, ?, ?, ?)`;
    db.prepare(
      requestedId
        ? `${insertSql}
      ON CONFLICT(id) DO UPDATE SET
        name = excluded.name,
        description = excluded.description,
        allowed_actions_json = excluded.allowed_actions_json,
        object_permissions_json = excluded.object_permissions_json,
        updated_at = excluded.updated_at`
        : insertSql
    ).run(
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

  /** Replaces a Profile's groups atomically; unknown group ids are rejected before anything changes. */
  setProfileGroups(profileId: string, groupIds: string[]): ProfileGroupMapping {
    const uniqueIds = Array.from(new Set(groupIds));
    const knownIds = new Set(this.getGroups().map((g) => g.id));
    const unknownIds = uniqueIds.filter((gid) => !knownIds.has(gid));
    if (unknownIds.length > 0) {
      throw new Error(`Unknown Access Group id(s): ${unknownIds.join(', ')}`);
    }

    runInTransaction(() => {
      db.prepare('DELETE FROM profile_group_memberships WHERE profile_id = ?').run(profileId);
      const ins = db.prepare(
        'INSERT OR IGNORE INTO profile_group_memberships (profile_id, group_id) VALUES (?, ?)'
      );
      for (const gid of uniqueIds) {
        ins.run(profileId, gid);
      }
    });
    return { profileId, groupIds: uniqueIds };
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
      ...(r.simulated ? { simulated: true as const } : {}),
    }));
  },

  /** Totals for the dashboard KPIs: real traffic only, so the simulator cannot inflate them. */
  getCopilotMcpLogStats(): { total: number; allowed: number; denied: number; errors: number } {
    const row = db
      .prepare(
        `SELECT COUNT(*) AS total,
                COALESCE(SUM(CASE WHEN status = 'ALLOWED' THEN 1 ELSE 0 END), 0) AS allowed,
                COALESCE(SUM(CASE WHEN status = 'DENIED' THEN 1 ELSE 0 END), 0) AS denied,
                COALESCE(SUM(CASE WHEN status = 'ERROR' THEN 1 ELSE 0 END), 0) AS errors
         FROM mcp_copilot_logs
         WHERE simulated = 0`
      )
      .get() as { total: number; allowed: number; denied: number; errors: number };
    return { total: row.total, allowed: row.allowed, denied: row.denied, errors: row.errors };
  },

  /**
   * When the last real call reached the MCP tools, read from the table because simulator rows can
   * fill the capped list. A rejected token does not count: anyone can send one, and it would
   * present an unauthenticated request as MCP activity.
   */
  getLastRealMcpCallAt(): string | null {
    const row = db
      .prepare(
        `SELECT timestamp FROM mcp_copilot_logs
         WHERE simulated = 0 AND sf_username <> 'unverified_caller'
         ORDER BY rowid DESC LIMIT 1`
      )
      .get() as { timestamp: string } | undefined;
    return row?.timestamp ?? null;
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
    /** Callers pass this from a verified token or a server route, never from request input. */
    simulated?: boolean;
  }): CopilotMcpLogRecord {
    const id = `mcp_${Date.now().toString(36)}_${crypto.randomBytes(8).toString('hex')}`;
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
        sanitized_request_payload, sanitized_response_summary, simulated
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
      sanitizedRes,
      input.simulated ? 1 : 0
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
      ...(input.simulated ? { simulated: true as const } : {}),
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
    const id = `adm_${Date.now().toString(36)}_${crypto.randomBytes(8).toString('hex')}`;
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
      // Usually APP_SECRET_KEY changed. Keep the ciphertext (updateOktaConfig never overwrites it
      // unless a new secret is entered) and tell the operator once.
      secret = '';
      if (!warnedUndecryptableOktaSecret) {
        warnedUndecryptableOktaSecret = true;
        console.warn(
          '[store] The stored Okta client secret cannot be decrypted with the current APP_SECRET_KEY. Re-enter it in Settings > Portal Login & Okta SSO.'
        );
      }
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
    const storedSecretEnc = (
      db.prepare('SELECT client_secret_enc FROM okta_config WHERE id = 1').get() as { client_secret_enc: string }
    ).client_secret_enc;
    // A blank secret means "keep the stored one"; the stored ciphertext is kept as-is, even if it
    // cannot be decrypted right now, so a key change never silently destroys it.
    const nextSecretEnc =
      input.clientSecret !== undefined && input.clientSecret !== ''
        ? encryptSecret(input.clientSecret)
        : storedSecretEnc;
    const nextDomain = (input.oktaDomain ?? current.oktaDomain).trim();
    const derivedIssuer = nextDomain
      ? `https://${nextDomain.replace(/^https?:\/\//, '').replace(/\/+$/, '')}/oauth2/default`
      : '';
    const domainChanged = nextDomain !== current.oktaDomain;
    // An explicit issuer wins; an empty one means "derive from the domain". Otherwise keep a custom
    // issuer (e.g. the Okta org authorization server) across saves that do not change the domain.
    const requestedIssuer = input.issuer?.trim();
    const nextIssuer = requestedIssuer
      ? requestedIssuer
      : input.issuer !== undefined || domainChanged || !current.issuer
      ? derivedIssuer
      : current.issuer;
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
      nextSecretEnc,
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
    const { privateKeyPem } = readStoredPrivateKey(row.private_key_enc);
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
        row.connection_status === 'connected' ||
        row.connection_status === 'error' ||
        row.connection_status === 'not_verified'
          ? row.connection_status
          : 'disconnected',
      lastConnectedAt: row.last_connected_at || null,
      lastError: row.last_error || '',
      connectedOrgId: row.connected_org_id || '',
      connectedUser: row.connected_user || '',
      expectedOrgId: row.expected_org_id || '',
      instanceUrl: row.instance_url || 'https://login.salesforce.com',
      syncInstanceUrl: row.sync_instance_url || '',
      apiVersion: row.api_version || 'v62.0',
      enforceOrgIdLock: Boolean(row.enforce_org_id_lock),
      sfdxObjectsFolderPath: row.sfdx_objects_folder_path || '',
      updatedAt: row.updated_at,
    };
  },

  getSalesforceSettingsWithSecrets(): SalesforceConnectionSettings & {
    privateKeyPem: string;
    privateKeyUndecryptable: boolean;
  } {
    const row = db.prepare('SELECT private_key_enc FROM sf_connection_settings WHERE id = 1').get() as {
      private_key_enc: string;
    };
    const { privateKeyPem, undecryptable } = readStoredPrivateKey(row.private_key_enc);
    const base = this.getSalesforceSettings();
    return {
      ...base,
      privateKeyPem,
      privateKeyUndecryptable: undecryptable,
    };
  },

  updateSalesforceSettings(
    input: Partial<SalesforceConnectionSettings> & { privateKeyPem?: string }
  ): SalesforceConnectionSettings {
    const current = this.getSalesforceSettings();
    const now = new Date().toISOString();

    const storedPrivateKeyEnc = (
      db.prepare('SELECT private_key_enc FROM sf_connection_settings WHERE id = 1').get() as { private_key_enc: string }
    ).private_key_enc;
    // A blank key means "keep the stored one"; the stored ciphertext is kept as-is, even if it
    // cannot be decrypted right now, so a key change never silently destroys it.
    const nextPrivateKeyEnc =
      input.privateKeyPem !== undefined && input.privateKeyPem.trim() !== ''
        ? encryptSecret(validatePrivateKeyPem(input.privateKeyPem))
        : storedPrivateKeyEnc;

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
          sync_instance_url = ?,
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
      nextPrivateKeyEnc,
      nextCertPem,
      nextFingerprint,
      input.connectionStatus ?? current.connectionStatus,
      input.lastConnectedAt !== undefined ? input.lastConnectedAt : current.lastConnectedAt,
      input.lastError !== undefined ? input.lastError : current.lastError,
      (input.connectedOrgId ?? current.connectedOrgId).trim(),
      (input.connectedUser ?? current.connectedUser).trim(),
      (input.expectedOrgId ?? current.expectedOrgId).trim(),
      nextInstanceUrl,
      (input.syncInstanceUrl ?? current.syncInstanceUrl).trim(),
      (input.apiVersion ?? current.apiVersion).trim(),
      (input.enforceOrgIdLock ?? current.enforceOrgIdLock) ? 1 : 0,
      (input.sfdxObjectsFolderPath ?? current.sfdxObjectsFolderPath).trim(),
      now
    );
    return this.getSalesforceSettings();
  },

  /**
   * Saves a successful connect. Its host always goes in sync_instance_url. instance_url decides where MCP
   * sends bearer tokens, so a real connect may only initialise it, and a host an admin set is never moved.
   * A simulated connect never writes it, and the simulated host is never adopted.
   */
  saveVerifiedSalesforceConnection(
    input: Partial<SalesforceConnectionSettings> & { privateKeyPem?: string },
    session: { orgId: string; username: string; instanceUrl: string; authMode: 'jwt_bearer' | 'simulated' }
  ): SalesforceConnectionSettings {
    return runInTransaction(() => {
      const { instance_url: currentHost } = db
        .prepare('SELECT instance_url FROM sf_connection_settings WHERE id = 1')
        .get() as { instance_url: string };
      if (
        session.authMode !== 'simulated' &&
        session.instanceUrl !== SIMULATED_ORG_INSTANCE_URL &&
        isUninitialisedMcpTokenHost(currentHost)
      ) {
        db.prepare('UPDATE sf_connection_settings SET instance_url = ? WHERE id = 1').run(session.instanceUrl);
      }
      return this.updateSalesforceSettings({
        ...input,
        enabled: true,
        connectionStatus: 'connected',
        lastConnectedAt: new Date().toISOString(),
        lastError: '',
        connectedOrgId: session.orgId,
        connectedUser: session.username,
        syncInstanceUrl: session.instanceUrl,
      });
    });
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
