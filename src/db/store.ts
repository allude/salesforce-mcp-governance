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
  McpLogDecision,
  McpLogKind,
  PortalAdminLogRecord,
  OktaSsoSettings,
  SalesforceConnectionSettings,
  ProfileSyncDiffPreview,
  ObjectSyncDiffPreview,
  PortalUserSummary,
  AVAILABLE_MCP_ACTIONS,
} from '../types/governance.js';
import {
  PulledOrgObjectMetadata,
  inspectCertificatePem,
  validatePrivateKeyPem,
} from '../salesforce/jwtConnection.js';
import { salesforceIdKey, salesforceIdsMatch } from '../salesforce/ids.js';
import { isSimulatedOrgHost, isUninitialisedMcpTokenHost } from '../salesforce/simulatedOrg.js';
import { soqlSkeleton } from '../mcp/soqlGuard.js';
import { auditResultFromAction, PORTAL_AUDIT_RESULTS, type PortalAuditResult } from '../security/auditResult.js';
import { malformedGrantReason, mergeGrants, spellingLookup, uniqueIgnoringCase } from '../rbac/groupGrants.js';
import { decisionLogColumns, policySnapshotCatalog, type GatewayDecision } from '../rbac/decisionLog.js';
import type { PolicyDecision, PolicySnapshot } from '../rbac/policyEngine.js';

const dbDir = path.dirname(config.dbPath);
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}

const db = new DatabaseSync(config.dbPath);

// What the policy revision triggers need to know of this connection (see installPolicyRevision):
// whether runInTransaction has a transaction open and whether it has bumped the revision yet. A TEMP
// table is never stored, so it starts afresh with every boot, and a rollback restores it as it does
// everything else.
db.exec(`
  CREATE TEMP TABLE policy_txn (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    active INTEGER NOT NULL,
    bumped INTEGER NOT NULL
  );
  INSERT INTO temp.policy_txn (id, active, bumped) VALUES (1, 0, 0);
`);
const openPolicyTxn = db.prepare('UPDATE temp.policy_txn SET active = 1, bumped = 0 WHERE id = 1');
const closePolicyTxn = db.prepare('UPDATE temp.policy_txn SET active = 0, bumped = 0 WHERE id = 1');

let transactionDepth = 0;
let transactionDoomed = false;

/**
 * Runs `fn` atomically: either every statement in it commits or none does. A nested call joins the
 * open transaction. Its failure dooms the whole transaction, even if an outer step catches the error,
 * so a half-applied inner step can never commit. `fn` must be synchronous. However many policy rows
 * the transaction changes, it raises the policy revision once, and only if it commits.
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
    openPolicyTxn.run();
    const result = fn();
    if (transactionDoomed) {
      throw new Error('Transaction rolled back: a nested step failed.');
    }
    closePolicyTxn.run();
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
      'UPDATE access_groups SET object_permissions_json = ?, version = version + 1, updated_at = ? WHERE id = ?'
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
      'UPDATE access_groups SET object_permissions_json = ?, version = version + 1, updated_at = ? WHERE id = ?'
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

/**
 * Local rows by lower-case name. Salesforce API names are case-insensitive, but a database from an
 * older version can hold 'Account' and 'account' as separate rows: org sync acts on all of them.
 */
function groupObjectsByLowerName(objects: SalesforceObject[]): Map<string, SalesforceObject[]> {
  const groups = new Map<string, SalesforceObject[]>();
  for (const obj of objects) {
    const key = obj.objectName.toLowerCase();
    groups.set(key, [...(groups.get(key) || []), obj]);
  }
  return groups;
}

/**
 * One entry per object, however many spellings the pull asked about: the routes pull every tracked
 * name, so a case-variant database reports the same object twice. A field any entry reports is
 * present, and so is an object, so that a disagreement can never lead to a deletion.
 */
function mergePulledEntriesByObject<
  F extends { fieldName: string },
  T extends { objectName: string; label?: string; isCustom?: boolean; existsInOrg: boolean; fields: F[] },
>(entries: T[]): T[] {
  const merged = new Map<string, { entry: T; fields: Map<string, F> }>();
  for (const entry of entries) {
    const key = entry.objectName.toLowerCase();
    const seen = merged.get(key);
    if (!seen) {
      merged.set(key, { entry, fields: new Map(entry.fields.map((f) => [f.fieldName.toLowerCase(), f])) });
      continue;
    }
    seen.entry = {
      ...seen.entry,
      label: entry.label ?? seen.entry.label,
      isCustom: entry.isCustom ?? seen.entry.isCustom,
      existsInOrg: seen.entry.existsInOrg || entry.existsInOrg,
    };
    for (const f of entry.fields) seen.fields.set(f.fieldName.toLowerCase(), f);
  }
  return Array.from(merged.values(), ({ entry, fields }) => ({ ...entry, fields: Array.from(fields.values()) }));
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

/** The MCP log user for a bearer token that failed verification, so the caller is unknown. */
export const UNVERIFIED_CALLER_USERNAME = 'unverified_caller';

type LogTable = 'mcp_copilot_logs' | 'portal_admin_logs';

/**
 * The two log tables. A new database creates them from these, and rebuildLogTableWithSeq rebuilds an
 * older one from the same text, so both end with the same table. `seq` is the write order: the order
 * every reader lists rows in and the paging cursor. On mcp_copilot_logs, the columns after `simulated`
 * describe how the call was decided and timed; '' (or '[]') and NULL mean "not recorded", which is what
 * a row written before they existed holds. `kind` is the exception: it is filled in for every row (see
 * classifyMcpLogKinds), and its default '' exists only so that an older release can still insert.
 */
const LOG_TABLE_COLUMNS: Record<LogTable, string> = {
  mcp_copilot_logs: `
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    id TEXT NOT NULL UNIQUE,
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
    sanitized_response_summary TEXT NOT NULL DEFAULT '{}',
    simulated INTEGER NOT NULL DEFAULT 0,
    kind TEXT NOT NULL DEFAULT '',
    decision_json TEXT NOT NULL DEFAULT '',
    decision_stage TEXT NOT NULL DEFAULT '',
    decision_code TEXT NOT NULL DEFAULT '',
    assigned_group_ids_json TEXT NOT NULL DEFAULT '[]',
    deciding_group_ids_json TEXT NOT NULL DEFAULT '[]',
    policy_revision INTEGER,
    caller_profile_id TEXT NOT NULL DEFAULT '',
    matched_profile_id TEXT NOT NULL DEFAULT '',
    match_method TEXT NOT NULL DEFAULT '',
    verification_ms INTEGER,
    total_ms INTEGER
  `,
  portal_admin_logs: `
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    id TEXT NOT NULL UNIQUE,
    timestamp TEXT NOT NULL,
    admin_username TEXT NOT NULL,
    auth_method TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    details TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    result TEXT NOT NULL DEFAULT 'SUCCESS',
    target_type TEXT NOT NULL DEFAULT '',
    target_id TEXT NOT NULL DEFAULT '',
    diff_json TEXT NOT NULL DEFAULT '',
    correlation_id TEXT NOT NULL DEFAULT ''
  `,
};

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
    updated_at TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1
  );

  CREATE TABLE IF NOT EXISTS profile_group_memberships (
    profile_id TEXT NOT NULL,
    group_id TEXT NOT NULL,
    PRIMARY KEY (profile_id, group_id),
    FOREIGN KEY (profile_id) REFERENCES sf_profiles(id) ON DELETE CASCADE,
    FOREIGN KEY (group_id) REFERENCES access_groups(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS mcp_copilot_logs (${LOG_TABLE_COLUMNS.mcp_copilot_logs});

  CREATE TABLE IF NOT EXISTS portal_admin_logs (${LOG_TABLE_COLUMNS.portal_admin_logs});

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

  CREATE TABLE IF NOT EXISTS policy_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    revision INTEGER NOT NULL DEFAULT 1,
    uncounted_writes INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL
  );
`);

/** Returns true only when this call added the column. */
function ensureColumnExists(tableName: string, columnName: string, columnDef: string): boolean {
  const cols = db.prepare(`PRAGMA table_info(${tableName})`).all() as Array<{ name: string }>;
  if (cols.some((c) => c.name === columnName)) return false;
  db.exec(`ALTER TABLE ${tableName} ADD COLUMN ${columnName} ${columnDef}`);
  return true;
}

/** The tables an /mcp decision is made from. A change to any of their rows is a policy change. */
const POLICY_TABLES = ['sf_profiles', 'sf_objects', 'sf_object_fields', 'access_groups', 'profile_group_memberships'];

/** Columns of those tables that change without changing the policy: when a row was saved, and how often a group was. */
const NON_POLICY_COLUMNS = new Set(['updated_at', 'version']);

/**
 * The policy revision is one counter in policy_state for everything /mcp decides from: Profiles, Objects
 * and fields, Access Groups and memberships. It starts at 1, on a new database and on one upgraded to
 * it alike, and never goes down. TEMP triggers on this connection raise it, so whichever store function,
 * migration or ON DELETE CASCADE changes those rows, nobody has to remember to: an insert, a delete, or
 * an update that changes a value other than a timestamp or a group's version. Saving the same values
 * again fires nothing. Inside runInTransaction the first such row raises it, in the same transaction,
 * and the rest of that transaction does not, so a change and its revision commit or roll back together.
 * A statement outside a transaction commits by itself, so each row it changes raises it, which is why
 * store functions that change several rows run in a transaction. Admin sessions, portal users, Okta
 * and Salesforce connection settings and the logs are in no such table: they never raise it.
 *
 * Another connection has no TEMP triggers: an older release run on this database after a rollback, or
 * a hand edit. So that its changes are not left out, triggers stored in the database add every row they
 * fire for to uncounted_writes, on any connection, and the TEMP triggers take it away again. They name
 * no TEMP table (they cannot), so an older release's writes still succeed. Whatever is left when the
 * store loads was changed without being counted, and raises the revision by one before anything reads it.
 *
 * The compared columns are read when the store loads, so this runs after the migrations that add a
 * column to these tables and before any that changes their rows, which then counts as a change. The
 * stored triggers are made again each time, so they compare the same columns as the TEMP ones.
 */
function installPolicyRevision() {
  const bump = `BEGIN
    UPDATE policy_state SET revision = revision + 1, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
    WHERE id = 1 AND (SELECT active = 0 OR bumped = 0 FROM temp.policy_txn WHERE id = 1);
    UPDATE policy_txn SET bumped = 1 WHERE id = 1 AND active = 1;
    UPDATE policy_state SET uncounted_writes = uncounted_writes - 1 WHERE id = 1;
  END`;
  const tally = `BEGIN
    UPDATE policy_state SET uncounted_writes = uncounted_writes + 1 WHERE id = 1;
  END`;
  runInTransaction(() => {
    const now = new Date().toISOString();
    db.prepare('INSERT OR IGNORE INTO policy_state (id, revision, updated_at) VALUES (1, 1, ?)').run(now);
    for (const table of POLICY_TABLES) {
      const changed = (db.prepare(`PRAGMA table_info(${table})`).all() as Array<{ name: string }>)
        .filter((c) => !NON_POLICY_COLUMNS.has(c.name))
        .map((c) => `OLD."${c.name}" IS NOT NEW."${c.name}"`)
        .join(' OR ');
      for (const [event, when] of [['INSERT', ''], ['UPDATE', `WHEN ${changed}`], ['DELETE', '']]) {
        const suffix = `${table}_${event.toLowerCase()}`;
        db.exec(`
          DROP TRIGGER IF EXISTS main.policy_writes_${suffix};
          CREATE TRIGGER main.policy_writes_${suffix} AFTER ${event} ON ${table} ${when} ${tally};
          CREATE TEMP TRIGGER policy_revision_${suffix} AFTER ${event} ON ${table} ${when} ${bump};
        `);
      }
    }
    db.prepare(
      'UPDATE policy_state SET revision = revision + 1, uncounted_writes = 0, updated_at = ? WHERE id = 1 AND uncounted_writes <> 0'
    ).run(now);
  });
}

/**
 * Before this column existed, simulator calls were logged unmarked under these default names, which
 * would otherwise count as real traffic. It runs only when the column is added, in one transaction
 * with it, so an interrupted upgrade retries and a later real row under such a name is left alone.
 * Naming the identities also leaves rejected-token rows out: those are logged as unverified_caller.
 */
function addSimulatedColumnAndMarkLegacyRows() {
  runInTransaction(() => {
    if (!ensureColumnExists('mcp_copilot_logs', 'simulated', 'INTEGER NOT NULL DEFAULT 0')) return;
    db.prepare(
      `UPDATE mcp_copilot_logs SET simulated = 1
       WHERE sf_username IN ('copilot.user@enterprise.com', 'alex.demo@company.my.salesforce.com')`
    ).run();
  });
}

/** The kind of an MCP log row written without one: classifyMcpLogKinds applies the same rule in SQL. */
function mcpLogKind(simulated: boolean, sfUsername: string): McpLogKind {
  if (simulated) return 'simulated';
  return sfUsername === UNVERIFIED_CALLER_USERNAME ? 'rejected' : 'real';
}

const quoteIdentifier = (name: string) => `"${name.replace(/"/g, '""')}"`;

/**
 * Gives a log table an explicit write order, `seq INTEGER PRIMARY KEY AUTOINCREMENT`, in place of the
 * implicit rowid its rows were listed and paged by: VACUUM may renumber the rowids of a table without an
 * INTEGER PRIMARY KEY, and a column of its own is the order once rows can no longer be rewritten. It runs
 * only when the column is missing, in one transaction: a new table is created from LOG_TABLE_COLUMNS
 * (what a new database gets), every row is copied with its rowid as its seq, so the order and every
 * paging cursor already handed out stay as they were, the old table is dropped, the new one renamed and
 * the old table's indexes made again. Ids and every other value are copied unchanged, a column the old
 * table lacks gets its default, and one only the old table has (none a release wrote) is kept.
 */
function rebuildLogTableWithSeq(table: LogTable) {
  runInTransaction(() => {
    const columnsOf = (name: string) =>
      db.prepare(`PRAGMA table_info(${quoteIdentifier(name)})`).all() as Array<{ name: string; type: string }>;
    const oldColumns = columnsOf(table);
    if (oldColumns.some((c) => c.name === 'seq')) return;
    const indexes = (
      db
        .prepare(`SELECT sql FROM sqlite_master WHERE type = 'index' AND tbl_name = ? AND sql IS NOT NULL`)
        .all(table) as Array<{ sql: string }>
    ).map((row) => row.sql);

    const rebuilt = `${table}__with_seq`;
    db.exec(`DROP TABLE IF EXISTS ${rebuilt}`);
    db.exec(`CREATE TABLE ${rebuilt} (${LOG_TABLE_COLUMNS[table]})`);
    const newNames = new Set(columnsOf(rebuilt).map((c) => c.name));
    for (const column of oldColumns.filter((c) => !newNames.has(c.name))) {
      db.exec(`ALTER TABLE ${rebuilt} ADD COLUMN ${quoteIdentifier(column.name)} ${column.type}`);
    }
    const copied = oldColumns.map((c) => quoteIdentifier(c.name)).join(', ');
    db.exec(`INSERT INTO ${rebuilt} (seq, ${copied}) SELECT rowid, ${copied} FROM ${table} ORDER BY rowid`);
    db.exec(`DROP TABLE ${table}`);
    db.exec(`ALTER TABLE ${rebuilt} RENAME TO ${table}`);
    for (const sql of indexes) db.exec(sql);
  });
}

/**
 * Gives every MCP log row without a kind the one its other columns imply (mcpLogKind): a simulator row
 * is 'simulated', a refused token's row, logged as unverified_caller, 'rejected', and anything else
 * 'real'. This release writes every row with its kind, so the rows without one are those written before
 * the column existed and those an older release writes after a rollback; like backfillLegacyAuditResults
 * it runs on every boot. Only the kind is filled in: their decision, identity and timing columns stay not
 * recorded.
 */
function classifyMcpLogKinds() {
  db.prepare(
    `UPDATE mcp_copilot_logs
     SET kind = CASE WHEN simulated <> 0 THEN 'simulated' WHEN sf_username = ? THEN 'rejected' ELSE 'real' END
     WHERE kind = ''`
  ).run(UNVERIFIED_CALLER_USERNAME);
}

/**
 * Before the result column, a row's outcome was only its action name's suffix, which is still the rule
 * for a row written without one. A row with no correlation id was written by a release that predates
 * these columns (recordPortalAdminLog always sets one), so its result is only the column default. Such
 * rows are given the rule's result on every boot, not only on the one that adds the column: an older
 * release run on this database after a rollback writes them too. A row this version wrote is never
 * touched. The other structured columns stay empty on those rows.
 */
function backfillLegacyAuditResults() {
  runInTransaction(() => {
    const actions = db
      .prepare(`SELECT DISTINCT action FROM portal_admin_logs WHERE correlation_id = '' AND result = 'SUCCESS'`)
      .all() as Array<{ action: string }>;
    const setResult = db.prepare(
      `UPDATE portal_admin_logs SET result = ? WHERE action = ? AND correlation_id = '' AND result = 'SUCCESS'`
    );
    for (const { action } of actions) {
      const result = auditResultFromAction(action);
      if (result !== 'SUCCESS') setResult.run(result, action);
    }
  });
}

/**
 * Rewrites one group's grants with the catalog's spelling of their Object and field names, matched
 * case-insensitively as the policy engine matches them, and merges the entries that then name the same
 * Object (see mergeGrants, which also keeps the Id an entry naming no field of its Object gave).
 * Returns null when nothing changes. A malformed entry, an entry for an Object the catalog does not
 * have and a field it does not have are kept as they are: the engine grants nothing for them either
 * way. Names are not trimmed, because the engine does not trim them.
 */
function canonicalGroupGrants(
  entries: unknown[],
  objectSpelling: (name: string) => string | null,
  fieldNamesOf: (objectName: string) => readonly string[]
): unknown[] | null {
  const out: unknown[] = [];
  const slots = new Map<string, { index: number; grants: GroupObjectPermission[] }>();
  for (const entry of entries) {
    if (malformedGrantReason(entry) !== null) {
      out.push(entry);
      continue;
    }
    const grant = entry as GroupObjectPermission;
    const objectName = objectSpelling(grant.objectName);
    if (!objectName) {
      out.push(entry);
      continue;
    }
    const field = spellingLookup(fieldNamesOf(objectName));
    const renamed: GroupObjectPermission = {
      ...grant,
      objectName,
      ...(Array.isArray(grant.allowedFields)
        ? { allowedFields: uniqueIgnoringCase(grant.allowedFields.map((name) => field(name) ?? name)) }
        : {}),
    };
    const key = objectName.toLowerCase();
    const slot = slots.get(key);
    if (slot) {
      slot.grants.push(renamed);
    } else {
      slots.set(key, { index: out.length, grants: [renamed] });
      out.push(renamed);
    }
  }
  for (const { index, grants } of slots.values()) {
    if (grants.length > 1) out[index] = mergeGrants(grants, fieldNamesOf)[0];
  }
  return JSON.stringify(out) === JSON.stringify(entries) ? null : out;
}

/**
 * Before the version column, POST /groups stored Object and field names as sent, so a grant could name
 * 'account' while Salesforce > Objects holds 'Account'. /mcp matches names case-insensitively and so
 * honoured it, but the group editor showed no such grant. This runs only when the column is added, in
 * one transaction with it, like addSimulatedColumnAndMarkLegacyRows, so it happens once. Every group it
 * changes gets version 2, so a portal tab opened before the upgrade cannot save over the result. If it
 * changes any group, the policy revision goes up by one, like any other transaction that changes a group.
 */
function addGroupVersionAndCanonicalizeGrants() {
  runInTransaction(() => {
    if (!ensureColumnExists('access_groups', 'version', 'INTEGER NOT NULL DEFAULT 1')) return;
    const objectNames = (
      db.prepare('SELECT object_name FROM sf_objects ORDER BY object_name').all() as Array<{ object_name: string }>
    ).map((row) => row.object_name);
    const fieldRows = db
      .prepare('SELECT object_name, field_name FROM sf_object_fields ORDER BY object_name, field_name')
      .all() as Array<{ object_name: string; field_name: string }>;
    const fieldNamesOf = new Map<string, string[]>();
    for (const row of fieldRows) {
      fieldNamesOf.set(row.object_name, [...(fieldNamesOf.get(row.object_name) ?? []), row.field_name]);
    }
    const objectSpelling = spellingLookup(objectNames);

    const rows = db.prepare('SELECT id, object_permissions_json FROM access_groups').all() as Array<{
      id: string;
      object_permissions_json: string;
    }>;
    const update = db.prepare(
      'UPDATE access_groups SET object_permissions_json = ?, version = version + 1, updated_at = ? WHERE id = ?'
    );
    const now = new Date().toISOString();
    for (const row of rows) {
      const entries = parseStoredJson(row.object_permissions_json);
      if (!Array.isArray(entries)) continue;
      const canonical = canonicalGroupGrants(entries, objectSpelling, (name) => fieldNamesOf.get(name) ?? []);
      if (canonical) update.run(JSON.stringify(canonical), now, row.id);
    }
  });
}

/** A stored JSON column, or undefined when it does not parse. */
function parseStoredJson(json: string): unknown {
  try {
    return JSON.parse(json || '[]');
  } catch {
    return undefined;
  }
}

function runSchemaMigrations() {
  ensureColumnExists('sf_profiles', 'missing_in_org', 'INTEGER NOT NULL DEFAULT 0');
  ensureColumnExists('sf_objects', 'missing_in_org', 'INTEGER NOT NULL DEFAULT 0');
  ensureColumnExists('sf_object_fields', 'missing_in_org', 'INTEGER NOT NULL DEFAULT 0');
  // The policy tables now have every column they compare; the grant canonicalization below is a change.
  installPolicyRevision();

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

  addSimulatedColumnAndMarkLegacyRows();

  // In the order CREATE TABLE lists them, so an upgraded database ends with the same table as a new one.
  ensureColumnExists('portal_admin_logs', 'result', "TEXT NOT NULL DEFAULT 'SUCCESS'");
  ensureColumnExists('portal_admin_logs', 'target_type', "TEXT NOT NULL DEFAULT ''");
  ensureColumnExists('portal_admin_logs', 'target_id', "TEXT NOT NULL DEFAULT ''");
  ensureColumnExists('portal_admin_logs', 'diff_json', "TEXT NOT NULL DEFAULT ''");
  ensureColumnExists('portal_admin_logs', 'correlation_id', "TEXT NOT NULL DEFAULT ''");
  backfillLegacyAuditResults();

  addGroupVersionAndCanonicalizeGrants();

  // After the column migrations above, so the simulated backfill has run once on a database from before
  // that column, and the copy carries every column they added. Neither rebuild runs again.
  rebuildLogTableWithSeq('mcp_copilot_logs');
  rebuildLogTableWithSeq('portal_admin_logs');
  classifyMcpLogKinds();
}

/**
 * Connect used to write its host into instance_url, which MCP sends bearer tokens to. A connected row
 * keeps showing that host as its sync instance. The simulated host is removed from instance_url whatever
 * the connection state says: no real token may reach it, and a real connect can no longer produce it, so
 * a row that names it with a real org ID (an old exact-match guard let the port form through) is no
 * evidence of a real org there. Any other value may be the admin's, so it stays.
 */
export function repairConnectInstanceUrls() {
  db.prepare(`
    UPDATE sf_connection_settings SET sync_instance_url = instance_url
    WHERE connection_status = 'connected' AND sync_instance_url = ''
  `).run();
  // Matched in code by hostname, as an exact SQL match missed the host with a port, other case or trailing dot.
  const row = db
    .prepare('SELECT instance_url, login_url FROM sf_connection_settings WHERE id = 1')
    .get() as { instance_url: string; login_url: string } | undefined;
  if (!row || !isSimulatedOrgHost(row.instance_url)) return;
  const replacement = isSimulatedOrgHost(row.login_url) ? 'https://login.salesforce.com' : row.login_url;
  db.prepare('UPDATE sf_connection_settings SET instance_url = ? WHERE id = 1').run(replacement);
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
// After the seed, which fills instance_url from SALESFORCE_LOGIN_URL and could write the simulated host.
repairConnectInstanceUrls();

/** The portal admin log action written once per policy simulation. */
export const SIMULATE_MCP_CALL_ACTION = 'SIMULATE_MCP_CALL';

const MCP_LOG_KINDS: readonly string[] = ['real', 'simulated', 'rejected'] satisfies McpLogKind[];
const MCP_LOG_MATCH_METHODS: readonly string[] = ['id', 'name', 'none'];

/** A stored decision, or null when none was recorded. A value that is not a JSON object reads as none. */
function parseLoggedDecision(json: string): McpLogDecision | null {
  const parsed = json ? parseStoredJson(json) : undefined;
  return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? (parsed as McpLogDecision) : null;
}

/** A stored list of ids; anything else reads as none. */
function parseIdList(json: string): string[] {
  const parsed = parseStoredJson(json);
  return Array.isArray(parsed) ? parsed.filter((id): id is string => typeof id === 'string') : [];
}

const storedNumberOrNull = (value: unknown) => (value === null || value === undefined ? null : Number(value));

function toCopilotMcpLogRecord(r: any): CopilotMcpLogRecord {
  return {
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
    seq: Number(r.seq),
    // A row an older release wrote since the last boot has no kind yet; it reads as the one it will get.
    kind: MCP_LOG_KINDS.includes(r.kind) ? r.kind : mcpLogKind(Boolean(r.simulated), r.sf_username),
    decision: parseLoggedDecision(r.decision_json),
    decisionStage: r.decision_stage,
    decisionCode: r.decision_code,
    assignedGroupIds: parseIdList(r.assigned_group_ids_json),
    decidingGroupIds: parseIdList(r.deciding_group_ids_json),
    policyRevision: storedNumberOrNull(r.policy_revision),
    callerProfileId: r.caller_profile_id,
    matchedProfileId: r.matched_profile_id,
    matchMethod: MCP_LOG_MATCH_METHODS.includes(r.match_method) ? r.match_method : '',
    verificationMs: storedNumberOrNull(r.verification_ms),
    totalMs: storedNumberOrNull(r.total_ms),
  };
}

/**
 * What decided a logged call. A policy decision comes with the snapshot it was made from: its names and
 * ids are checked against that snapshot (policySnapshotCatalog), not against the tables when the row is
 * written, so access revoked while the call ran does not unname the group, Object or Profile it was
 * decided on. A GatewayDecision (a refused token or an outage) read no policy.
 */
type DecidedBy =
  | { decision?: GatewayDecision; policySnapshot?: undefined }
  | { decision: PolicyDecision; policySnapshot: PolicySnapshot };

/** A duration as stored: whole non-negative milliseconds, or NULL (not recorded). */
function storedMs(ms: number | undefined): number | null {
  return typeof ms === 'number' && Number.isFinite(ms) && ms >= 0 ? Math.round(ms) : null;
}

/**
 * The longest diff_json a Portal Admin log row keeps. The log cannot be cleared and /overview sends its
 * latest rows on every poll, so a larger diff is replaced by a note of its length; the row itself, with
 * its action, target and details, is still written.
 */
const AUDIT_DIFF_MAX_LENGTH = 64 * 1024;

function storedAuditDiff(diff: Record<string, unknown> | undefined): string {
  if (!diff) return '';
  const json = JSON.stringify(diff);
  return json.length > AUDIT_DIFF_MAX_LENGTH ? JSON.stringify({ truncated: true, length: json.length }) : json;
}

/** A stored diff, or null when none was recorded. A value that is not a JSON object reads as none. */
function parseAuditDiff(diffJson: string): Record<string, unknown> | null {
  if (!diffJson) return null;
  try {
    const parsed = JSON.parse(diffJson);
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function toPortalAdminLogRecord(r: any): PortalAdminLogRecord {
  return {
    id: r.id,
    timestamp: r.timestamp,
    adminUsername: r.admin_username,
    authMethod: r.auth_method,
    action: r.action,
    target: r.target,
    details: r.details,
    ipAddress: r.ip_address,
    result: r.result,
    targetType: r.target_type,
    targetId: r.target_id,
    diff: parseAuditDiff(r.diff_json),
    correlationId: r.correlation_id,
  };
}

/** Keeps a log row's `seq`, the order rows were written in and the paging cursor. */
function withSeq<T>(toRecord: (r: any) => T): (r: any) => T & { seq: number } {
  return (r) => ({ ...toRecord(r), seq: Number(r.seq) });
}

export interface LogPageCursor {
  /** Only rows written before this `seq`; omitted for the newest page. */
  before?: number;
  limit: number;
}

export interface CopilotMcpLogPageQuery extends LogPageCursor {
  status?: 'ALLOWED' | 'DENIED' | 'ERROR';
  simulated?: boolean;
  toolName?: string;
  targetObject?: string;
}

export interface PortalAdminLogPageQuery extends LogPageCursor {
  action?: string;
  authMethod?: 'password' | 'okta_sso';
}

export interface LogPage<T> {
  rows: Array<T & { seq: number }>;
  /** The `before` cursor for the next older page, or null when no older matching row exists. */
  nextBefore: number | null;
}

/** Reads one more row than asked for, so the caller learns whether an older page exists. */
function readLogPage<T>(
  table: 'mcp_copilot_logs' | 'portal_admin_logs',
  where: string[],
  params: Record<string, string | number>,
  cursor: LogPageCursor,
  toRecord: (r: any) => T
): LogPage<T> {
  const conditions = [...where];
  const bound: Record<string, string | number> = { ...params, limit: cursor.limit + 1 };
  if (cursor.before !== undefined) {
    conditions.push('seq < :before');
    bound.before = cursor.before;
  }
  const filter = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
  const rows = db
    .prepare(`SELECT * FROM ${table} ${filter} ORDER BY seq DESC LIMIT :limit`)
    .all(bound) as any[];
  const page = rows.slice(0, cursor.limit).map(withSeq(toRecord));
  return {
    rows: page,
    nextBefore: rows.length > cursor.limit ? page[page.length - 1].seq : null,
  };
}

/**
 * Strips all sensitive data values from a payload while preserving keys, field names, and structure
 * so Copilot MCP logs never store raw customer PII or record values.
 */
export function stripSensitivePayloadData(input: unknown): unknown {
  return stripPayloadLevel(input, true);
}

// Safe keys count only at the payload's top level. Below it, e.g. in the field-to-value map of
// create_record and update_record, a key such as `status` or `limit` is a record field and its
// value is customer data.
function stripPayloadLevel(input: unknown, topLevel: boolean): unknown {
  if (input === null || input === undefined) return input;
  if (Array.isArray(input)) {
    return {
      _type: 'Array',
      count: input.length,
      sampleStructure: input.length > 0 ? stripPayloadLevel(input[0], false) : null,
    };
  }
  if (typeof input === 'object') {
    const safeKeys = new Set([
      'fields',
      'fieldNames',
      'limit',
      'status',
      'totalSize',
      'done',
      'id',
      'Id',
    ]);
    // Structural values (field API names, record ids, limits) are kept; anything that
    // does not look like one (e.g. a record's values sent where field names belong) is redacted.
    const isStructuralToken = (item: unknown) =>
      typeof item === 'number' || (typeof item === 'string' && /^(\*|[A-Za-z0-9_.:-]{1,120})$/.test(item));
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(input as Record<string, unknown>)) {
      const safe = topLevel && safeKeys.has(k);
      const storedName = topLevel ? STORED_NAME_KEYS.get(k) : undefined;
      if (k === 'records' && Array.isArray(v)) {
        out.records = `[REDACTED ${v.length} RECORDS]`;
      } else if (topLevel && k === 'soql' && typeof v === 'string') {
        // Every literal (string, number, date, ...) becomes a typed placeholder.
        out.soql = soqlSkeleton(v);
      } else if (storedName && typeof v === 'string') {
        // The check the tool_name and target_object columns use, so the payload keeps no text they refuse.
        out[k] = storedName(v);
      } else if (safe && (typeof v === 'number' || typeof v === 'boolean' || isStructuralToken(v))) {
        out[k] = v;
      } else if (Array.isArray(v) && safe && v.every(isStructuralToken)) {
        out[k] = v;
      } else if (typeof v === 'object' && v !== null) {
        out[k] = stripPayloadLevel(v, false);
      } else {
        out[k] = `<REDACTED:${typeof v}>`;
      }
    }
    return out;
  }
  return `<REDACTED:${typeof input}>`;
}

const LOGGED_TOOL_NAMES = new Set<string>([
  ...AVAILABLE_MCP_ACTIONS.map((action) => action.id),
  // The row /mcp writes for a rejected token (src/mcp/streamableHttp.ts).
  'mcp_authenticate',
]);

// tool_name and target_object arrive from the caller. Text that is not a known tool or an API name
// is stored by its length only, like any other redacted value.
function storedToolName(toolName: string): string {
  return LOGGED_TOOL_NAMES.has(toolName) ? toolName : `<invalid:len=${toolName.length}>`;
}

/** '*' (or '') is a call without an object. */
function storedTargetObject(targetObject: string): string {
  if (!targetObject || targetObject === '*' || SALESFORCE_API_NAME_PATTERN.test(targetObject)) {
    return targetObject || '';
  }
  return `<invalid:len=${targetObject.length}>`;
}

// Top-level payload keys that name the tool or the object. A value of any other type under them is redacted.
const STORED_NAME_KEYS = new Map<string, (value: string) => string>([
  ['objectName', storedTargetObject],
  ['object', storedTargetObject],
  ['sobject', storedTargetObject],
  ['tool', storedToolName],
  ['toolName', storedToolName],
]);

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
 * Moves Profile rows onto `targetId` inside the caller's transaction, creating that row from the
 * first replaced one if needed. The foreign key has no ON UPDATE CASCADE, so memberships move
 * before the old rows go.
 */
function replaceProfileRows(targetId: string, replaced: SalesforceProfile[]): void {
  const first = replaced[0];
  db.prepare(`
    INSERT OR IGNORE INTO sf_profiles (id, name, missing_in_org, updated_at) VALUES (?, ?, ?, ?)
  `).run(targetId, first.name, first.missingInOrg ? 1 : 0, new Date().toISOString());
  for (const row of replaced) {
    db.prepare(`
      INSERT OR IGNORE INTO profile_group_memberships (profile_id, group_id)
      SELECT ?, group_id FROM profile_group_memberships WHERE profile_id = ?
    `).run(targetId, row.id);
    db.prepare('DELETE FROM sf_profiles WHERE id = ?').run(row.id);
  }
}

/**
 * The rows to rename so a Profile stored under several forms keeps the row in force, or null if no
 * rename can. `forms` must be in `getProfiles` order, which sorts by name then ID: a form that would
 * overtake the first row is renamed with it if its higher ID then loses the tie.
 */
function profileFormsToRename(forms: SalesforceProfile[], name: string): SalesforceProfile[] | null {
  const [inForce, ...others] = forms;
  const overtaking = others.filter((f) => f.name < name || (f.name === name && f.id < inForce.id));
  if (overtaking.some((f) => f.id < inForce.id)) return null;
  return [inForce, ...overtaking];
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

/** Single memberships to add and remove. Every membership not named stays as it is. */
export interface MembershipDelta {
  add: string[];
  remove: string[];
}

/** A membership change naming a Profile or group that does not exist, or adding and removing one id. */
export class MembershipChangeError extends Error {}

/** The delta's ids without repeats; an id both added and removed has no meaning, so it is refused. */
function distinctMembershipDelta(delta: MembershipDelta, kind: string): MembershipDelta {
  const add = Array.from(new Set(delta.add));
  const remove = Array.from(new Set(delta.remove));
  const both = add.filter((id) => remove.includes(id));
  if (both.length > 0) {
    throw new MembershipChangeError(`${kind} id(s) both added and removed: ${both.join(', ')}`);
  }
  return { add, remove };
}

function unknownIdsIn(table: 'sf_profiles' | 'access_groups', ids: string[]): string[] {
  const known = db.prepare(`SELECT 1 FROM ${table} WHERE id = ?`);
  return ids.filter((id) => !known.get(id));
}

/**
 * Adds and removes [profileId, groupId] memberships inside the caller's transaction and returns the
 * ones that really changed. Each pair is one INSERT OR IGNORE or one single-row DELETE, so a
 * membership no pair names is never touched.
 */
function writeMemberships(add: Array<[string, string]>, remove: Array<[string, string]>) {
  const insert = db.prepare(
    'INSERT OR IGNORE INTO profile_group_memberships (profile_id, group_id) VALUES (?, ?)'
  );
  const del = db.prepare('DELETE FROM profile_group_memberships WHERE profile_id = ? AND group_id = ?');
  return {
    added: add.filter(([profileId, groupId]) => insert.run(profileId, groupId).changes > 0),
    removed: remove.filter(([profileId, groupId]) => del.run(profileId, groupId).changes > 0),
  };
}

/** What an Okta settings save may change. An omitted field keeps the stored value. */
export interface OktaConfigInput {
  enabled?: boolean;
  oktaDomain?: string;
  issuer?: string;
  clientId?: string;
  clientSecret?: string;
  redirectUri?: string;
  adminGroup?: string;
}

/** What a group write stores, besides its id. */
type GroupWrite = {
  name: string;
  description?: string;
  allowedActions: string[];
  objectPermissions: GroupObjectPermission[];
};

const warnedUnreadableGroupColumns = new Set<string>();

/**
 * A group's JSON list column. One that does not parse or holds no list reads as an empty list,
 * which grants nothing, so that no reader (the policy engine above all) can fail on it. The
 * operator is told once per group and column, without the stored text.
 */
function storedGroupList(groupId: string, column: string, json: string): any[] {
  const value = parseStoredJson(json);
  if (Array.isArray(value)) return value;
  const key = `${groupId}\u0000${column}`;
  if (!warnedUnreadableGroupColumns.has(key)) {
    warnedUnreadableGroupColumns.add(key);
    console.warn(
      `[store] Access Group ${groupId} has an unreadable ${column}; it is read as an empty list and grants nothing until the group is saved again.`
    );
  }
  return [];
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

  /**
   * The stored username that `username` names, matched like sign-in does (trimmed, any case), or
   * undefined. It resolves one exact row, preferring an exact-case match, so case variants left by
   * older versions stay apart. deletePortalUser deletes that row.
   */
  findPortalUsername(username: string): string | undefined {
    const requested = username.trim();
    const target = db
      .prepare(
        'SELECT username FROM portal_users WHERE lower(username) = lower(?) ORDER BY (username = ?) DESC LIMIT 1'
      )
      .get(requested, requested) as { username: string } | undefined;
    return target?.username;
  },

  deletePortalUser(username: string): boolean {
    // One exact row, so case variants are never deleted together and the last-administrator guard always holds.
    const target = this.findPortalUsername(username);
    if (target === undefined) return false;
    if (this.getPortalUsers().length <= 1) {
      throw new Error('Cannot delete the last remaining portal administrator account.');
    }
    const res = db.prepare('DELETE FROM portal_users WHERE username = ?').run(target);
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

  /**
   * Saves a Profile under whichever form of its ID is already stored, so no entry point adds a second
   * row. An 18-character form upgrades a stored 15-character row and keeps its memberships. If several
   * forms are stored already, the row the policy engine resolves is updated and the rest are left for
   * org sync to reconcile; `nameKept` reports a rename refused because it would change that row.
   */
  upsertProfile(
    id: string,
    name: string,
    // Only org sync passes this; a re-import or manual save must not clear what sync flagged.
    missingInOrg?: boolean
  ): {
    profile: SalesforceProfile;
    action: 'inserted' | 'updated';
    previousId?: string;
    nameKept?: boolean;
  } {
    const cleanId = id.trim();
    const cleanName = name.trim();
    return runInTransaction(() => {
      const forms = this.getProfiles().filter((p) => salesforceIdsMatch(p.id, cleanId));
      const now = new Date().toISOString();

      if (forms.length === 0) {
        const nextMissing = missingInOrg ?? false;
        db.prepare(`
          INSERT INTO sf_profiles (id, name, missing_in_org, updated_at) VALUES (?, ?, ?, ?)
        `).run(cleanId, cleanName, nextMissing ? 1 : 0, now);
        return {
          profile: { id: cleanId, name: cleanName, missingInOrg: nextMissing, updatedAt: now },
          action: 'inserted' as const,
        };
      }

      const stored = forms[0];
      const nextMissing = missingInOrg ?? stored.missingInOrg;
      const rename = db.prepare('UPDATE sf_profiles SET name = ?, updated_at = ? WHERE id = ?');
      const setMissing = db.prepare('UPDATE sf_profiles SET missing_in_org = ? WHERE id = ?');

      if (forms.length > 1) {
        setMissing.run(nextMissing ? 1 : 0, stored.id);
        const toRename = profileFormsToRename(forms, cleanName);
        for (const form of toRename || []) rename.run(cleanName, now, form.id);
        return {
          profile: { ...stored, name: toRename ? cleanName : stored.name, missingInOrg: nextMissing },
          action: 'updated' as const,
          ...(toRename ? {} : { nameKept: true }),
        };
      }

      const upgrades = cleanId.length > stored.id.length;
      const targetId = upgrades ? cleanId : stored.id;
      if (upgrades) replaceProfileRows(targetId, [stored]);
      rename.run(cleanName, now, targetId);
      setMissing.run(nextMissing ? 1 : 0, targetId);
      return {
        profile: { id: targetId, name: cleanName, missingInOrg: nextMissing, updatedAt: now },
        action: 'updated' as const,
        ...(upgrades ? { previousId: stored.id } : {}),
      };
    });
  },

  /** Saves every row or none, in one transaction, so an import is one policy revision. */
  importProfilesFromCsvRows(
    rows: Array<{ id: string; name: string }>
  ): { inserted: number; updated: number; idsUpgraded: number; namesKept: number; total: number } {
    return runInTransaction(() => {
      let inserted = 0;
      let updated = 0;
      let idsUpgraded = 0;
      let namesKept = 0;
      for (const r of rows) {
        if (!r.id || !r.name) continue;
        const res = this.upsertProfile(r.id, r.name);
        if (res.action === 'inserted') inserted++;
        else updated++;
        if (res.previousId) idsUpgraded++;
        if (res.nameKept) namesKept++;
      }
      return { inserted, updated, idsUpgraded, namesKept, total: this.getProfiles().length };
    });
  },

  deleteProfile(id: string): boolean {
    // In a transaction, so the Profile and the memberships its delete cascades to are one policy revision.
    return runInTransaction(() => db.prepare('DELETE FROM sf_profiles WHERE id = ?').run(id.trim()).changes > 0);
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
        const replaced = forms.filter((f) => f.id !== targetId);
        // One row is left, so the upsert below writes exactly the row sync chose.
        if (replaced.length > 0) replaceProfileRows(targetId, replaced);
        const res = this.upsertProfile(targetId, p.name, false);
        if (forms.length === 0) inserted++;
        else updated++;
        affected.upserted.push(res.profile.name);
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

  /** The field names of the object stored under exactly this name, or null when there is no such object. */
  getObjectFieldNames(objectName: string): string[] | null {
    if (!db.prepare('SELECT 1 FROM sf_objects WHERE object_name = ?').get(objectName)) return null;
    return (
      db
        .prepare('SELECT field_name FROM sf_object_fields WHERE object_name = ? ORDER BY field_name')
        .all(objectName) as Array<{ field_name: string }>
    ).map((row) => row.field_name);
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
    // The object and its fields are one transaction, and so one policy revision.
    return runInTransaction(() => {
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
    });
  },

  /** Saves every Object or none, in one transaction, so an import is one policy revision. */
  importObjectsFromParsedSfdx(
    parsedObjects: ReturnType<typeof parseSfdxFilesToObjects>
  ): { objectsImported: number; fieldsImported: number } {
    return runInTransaction(() => {
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
    });
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
    const localByName = groupObjectsByLowerName(this.getObjects());
    const groups = this.getGroups();

    const upsertedObjects: ObjectSyncDiffPreview['upsertedObjects'] = [];
    const removedObjectsFromOrg: ObjectSyncDiffPreview['removedObjectsFromOrg'] = [];

    for (const pulled of mergePulledEntriesByObject(pulledMetadata)) {
      const variants = localByName.get(pulled.objectName.toLowerCase()) || [];

      if (!pulled.existsInOrg) {
        const referencedInGroups = groups
          .filter((g) =>
            g.objectPermissions.some(
              (op) => op.objectName.toLowerCase() === pulled.objectName.toLowerCase()
            )
          )
          .map((g) => g.name);

        for (const variant of variants) {
          removedObjectsFromOrg.push({
            objectName: variant.objectName,
            label: variant.label,
            fieldCount: variant.fields.length,
            referencedInGroups,
          });
        }
        continue;
      }

      const orgFieldMap = new Map(
        pulled.fields.map((f) => [f.fieldName.toLowerCase(), f])
      );
      const localFieldNames = new Set(
        variants.flatMap((v) => v.fields.map((f) => f.fieldName.toLowerCase()))
      );

      const addedFields: ObjectSyncDiffPreview['upsertedObjects'][number]['addedFields'] = [];
      let updatedFieldsCount = 0;

      for (const f of pulled.fields) {
        if (!localFieldNames.has(f.fieldName.toLowerCase())) {
          addedFields.push(f);
        } else {
          updatedFieldsCount++;
        }
      }

      const removedFieldsFromOrg: ObjectSyncDiffPreview['upsertedObjects'][number]['removedFieldsFromOrg'] = [];
      for (const variant of variants) {
        for (const lf of variant.fields) {
          if (!orgFieldMap.has(lf.fieldName.toLowerCase())) {
            const referencedInGroups = groups
              .filter((g) =>
                g.objectPermissions.some(
                  (op) =>
                    op.objectName.toLowerCase() === pulled.objectName.toLowerCase() &&
                    op.allowedFields.some(
                      (af) => af.toLowerCase() === lf.fieldName.toLowerCase()
                    )
                )
              )
              .map((g) => g.name);

            removedFieldsFromOrg.push({
              objectName: variant.objectName,
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
        isNewObject: variants.length === 0,
        totalOrgFields: pulled.fields.length,
        addedFields,
        updatedFieldsCount,
        removedFieldsFromOrg,
        caseVariants: variants.length > 1 ? variants.map((v) => v.objectName) : [],
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
   *
   * Case variants of an object are one object in the org, so each decision covers them all, but their
   * rows are not merged: that would change access without an admin choosing it.
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

      const localByName = groupObjectsByLowerName(this.getObjects());

      for (const pulled of mergePulledEntriesByObject(input.pulledMetadata)) {
        const variants = localByName.get(pulled.objectName.toLowerCase()) || [];

        if (!pulled.existsInOrg) {
          for (const variant of variants) {
            if (removeObjSet.has(variant.objectName.toLowerCase())) {
              // Grants are revoked with the last variant: until then they still refer to a row.
              const result = deleteObjectAndRevokeGrants(variant.objectName);
              if (result.deleted) {
                affected.objectsRemoved.push(variant.objectName);
                result.revokedGroups.forEach((g) => lostGrants.add(g));
              }
            } else {
              db.prepare(
                'UPDATE sf_objects SET missing_in_org = 1, updated_at = ? WHERE object_name = ?'
              ).run(new Date().toISOString(), variant.objectName);
              affected.objectsKeptMissing.push(variant.objectName);
            }
          }
          continue;
        }

        // A new field goes on one row, and only if no variant has it yet: a new row starts enabled,
        // which would expose a field an admin disabled on the other variant.
        const newFieldsRow = this.resolveObjectName(pulled.objectName);
        const heldByAnyVariant = new Set(
          variants.flatMap((v) => v.fields.map((f) => f.fieldName.toLowerCase()))
        );
        const rowsToSync = variants.length > 0 ? variants : [{ objectName: newFieldsRow, fields: [] }];

        for (const row of rowsToSync) {
          const heldByRow = new Set(row.fields.map((f) => f.fieldName.toLowerCase()));
          const fields = pulled.fields.filter((f) => {
            const name = f.fieldName.toLowerCase();
            return heldByRow.has(name) || (row.objectName === newFieldsRow && !heldByAnyVariant.has(name));
          });

          // Upsert the object and its present org fields (setting missing_in_org = 0). Named one by one
          // so `enabled` stays the admin's: nothing in a pull may decide what is exposed.
          const syncedObject = this.upsertObjectWithFields({
            objectName: row.objectName,
            label: pulled.label,
            isCustom: pulled.isCustom,
            sourcePath: 'salesforce-org-jwt',
            missingInOrg: false,
            fields: fields.map((f) => ({
              fieldName: f.fieldName,
              label: f.label,
              fieldType: f.fieldType,
              isCustom: f.isCustom,
              required: f.required,
              missingInOrg: false,
            })),
          });
          affected.objectsSynced.push(syncedObject.objectName);
          fieldsUpserted += fields.length;
        }

        // Handle local fields on this object that were NOT in the Salesforce Org
        const orgFieldSet = new Set(pulled.fields.map((f) => f.fieldName.toLowerCase()));
        for (const variant of variants) {
          for (const lf of variant.fields) {
            if (!orgFieldSet.has(lf.fieldName.toLowerCase())) {
              const key = `${variant.objectName.toLowerCase()}.${lf.fieldName.toLowerCase()}`;
              const qualifiedName = `${variant.objectName}.${lf.fieldName}`;
              if (removeFieldSet.has(key)) {
                const result = deleteFieldAndRevokeGrants(variant.objectName, lf.fieldName);
                if (result.deleted) {
                  affected.fieldsRemoved.push(qualifiedName);
                  result.revokedGroups.forEach((g) => lostGrants.add(g));
                }
              } else {
                db.prepare(
                  'UPDATE sf_object_fields SET missing_in_org = 1 WHERE object_name = ? AND field_name = ?'
                ).run(variant.objectName, lf.fieldName);
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
      allowedActions: storedGroupList(r.id, 'allowed_actions_json', r.allowed_actions_json),
      objectPermissions: storedGroupList(r.id, 'object_permissions_json', r.object_permissions_json),
      version: Number(r.version),
      updatedAt: r.updated_at,
    }));
  },

  /**
   * Creates a group. A create is a plain INSERT, so it can never collide with (and silently
   * overwrite) another group. A new group gets a random id; `id` is for the sample matrix and tests,
   * which need a fixed one.
   */
  createGroup(input: GroupWrite & { id?: string }): AccessGroup {
    const id =
      input.id?.trim() ||
      `grp_${input.name
        .trim()
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '_')}_${crypto.randomBytes(6).toString('hex')}`;
    db.prepare(`
      INSERT INTO access_groups (id, name, description, allowed_actions_json, object_permissions_json, updated_at, version)
      VALUES (?, ?, ?, ?, ?, ?, 1)
    `).run(
      id,
      input.name.trim(),
      (input.description || '').trim(),
      JSON.stringify(input.allowedActions || []),
      JSON.stringify(input.objectPermissions || []),
      new Date().toISOString()
    );
    return this.getGroups().find((g) => g.id === id)!;
  },

  /**
   * Creates a group when no id is given and updates the group with the given id, whose version then
   * goes up by one. An id no group has is refused: it never creates a group.
   */
  upsertGroup(input: GroupWrite & { id?: string }): AccessGroup {
    const requestedId = input.id?.trim();
    if (!requestedId) return this.createGroup(input);

    const res = db.prepare(`
      UPDATE access_groups SET
        name = ?, description = ?, allowed_actions_json = ?, object_permissions_json = ?,
        version = version + 1, updated_at = ?
      WHERE id = ?
    `).run(
      input.name.trim(),
      (input.description || '').trim(),
      JSON.stringify(input.allowedActions || []),
      JSON.stringify(input.objectPermissions || []),
      new Date().toISOString(),
      requestedId
    );
    if (res.changes === 0) throw new Error(`Unknown Access Group id: ${requestedId}`);
    return this.getGroups().find((g) => g.id === requestedId)!;
  },

  deleteGroup(id: string): boolean {
    // In a transaction, so the group and the memberships its delete cascades to are one policy revision.
    return runInTransaction(() => db.prepare('DELETE FROM access_groups WHERE id = ?').run(id).changes > 0);
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

  /**
   * Replaces a Profile's groups atomically; unknown group ids are rejected before anything changes.
   * Only the memberships that differ are written, so saving the same groups again changes nothing.
   */
  setProfileGroups(profileId: string, groupIds: string[]): ProfileGroupMapping {
    const uniqueIds = Array.from(new Set(groupIds));
    const knownIds = new Set(this.getGroups().map((g) => g.id));
    const unknownIds = uniqueIds.filter((gid) => !knownIds.has(gid));
    if (unknownIds.length > 0) {
      throw new Error(`Unknown Access Group id(s): ${unknownIds.join(', ')}`);
    }

    runInTransaction(() => {
      const stored = this.getProfileGroupIds(profileId);
      writeMemberships(
        uniqueIds.filter((gid) => !stored.includes(gid)).map((gid) => [profileId, gid]),
        stored.filter((gid) => !uniqueIds.includes(gid)).map((gid) => [profileId, gid])
      );
    });
    return { profileId, groupIds: uniqueIds };
  },

  getProfileGroupIds(profileId: string): string[] {
    const rows = db
      .prepare('SELECT group_id FROM profile_group_memberships WHERE profile_id = ?')
      .all(profileId) as Array<{ group_id: string }>;
    return rows.map((r) => r.group_id);
  },

  /**
   * Adds and removes single groups of one Profile and keeps its other groups, so a client working
   * from an old copy of the matrix cannot undo a change it never saw. Unknown ids are rejected before
   * anything changes; `added` and `removed` hold only the memberships that really changed.
   */
  applyMembershipDelta(
    profileId: string,
    delta: MembershipDelta
  ): { mapping: ProfileGroupMapping; added: string[]; removed: string[] } {
    return runInTransaction(() => {
      const { add, remove } = distinctMembershipDelta(delta, 'Access Group');
      const unknownIds = unknownIdsIn('access_groups', [...add, ...remove]);
      if (unknownIds.length > 0) {
        throw new MembershipChangeError(`Unknown Access Group id(s): ${unknownIds.join(', ')}`);
      }
      if (unknownIdsIn('sf_profiles', [profileId]).length > 0) {
        throw new MembershipChangeError(`Unknown Profile id: ${profileId}`);
      }

      const changed = writeMemberships(
        add.map((groupId) => [profileId, groupId]),
        remove.map((groupId) => [profileId, groupId])
      );
      return {
        mapping: { profileId, groupIds: this.getProfileGroupIds(profileId) },
        added: changed.added.map(([, groupId]) => groupId),
        removed: changed.removed.map(([, groupId]) => groupId),
      };
    });
  },

  /** The same for many Profiles of one group: only the memberships of the Profiles named change. */
  applyGroupMembershipDelta(
    groupId: string,
    delta: MembershipDelta
  ): { membership: { groupId: string; profileIds: string[] }; added: string[]; removed: string[] } {
    return runInTransaction(() => {
      const { add, remove } = distinctMembershipDelta(delta, 'Profile');
      if (unknownIdsIn('access_groups', [groupId]).length > 0) {
        throw new MembershipChangeError(`Unknown Access Group id: ${groupId}`);
      }
      const unknownIds = unknownIdsIn('sf_profiles', [...add, ...remove]);
      if (unknownIds.length > 0) {
        throw new MembershipChangeError(`Unknown Profile id(s): ${unknownIds.join(', ')}`);
      }

      const changed = writeMemberships(
        add.map((profileId) => [profileId, groupId]),
        remove.map((profileId) => [profileId, groupId])
      );
      const profileIds = (
        db
          .prepare('SELECT profile_id FROM profile_group_memberships WHERE group_id = ?')
          .all(groupId) as Array<{ profile_id: string }>
      ).map((r) => r.profile_id);
      return {
        membership: { groupId, profileIds },
        added: changed.added.map(([profileId]) => profileId),
        removed: changed.removed.map(([profileId]) => profileId),
      };
    });
  },

  /**
   * The policy revision: 1 on a new database, and one more for every committed change to a Profile, an
   * Object or field, an Access Group or a membership (see installPolicyRevision). Read inside a
   * transaction, it already counts that transaction's change.
   */
  getPolicyRevision(): number {
    const row = db.prepare('SELECT revision FROM policy_state WHERE id = 1').get() as { revision: number };
    return Number(row.revision);
  },

  // ============================================================================
  // 5. DUAL AUDIT LOGS (Copilot MCP Logs [Sanitized] & Portal Admin Logs)
  // ============================================================================
  getCopilotMcpLogs(limit = 150): CopilotMcpLogRecord[] {
    const rows = db
      .prepare('SELECT * FROM mcp_copilot_logs ORDER BY seq DESC LIMIT ?')
      .all(limit) as any[];
    return rows.map(toCopilotMcpLogRecord);
  },

  /**
   * Newest first, with verified calls, simulated calls and rejected tokens capped separately, so
   * neither simulator runs nor junk bearer tokens (which anyone can send) can push verified calls out
   * of what the portal can see. Every row stays in the table.
   */
  getCopilotMcpLogsCappedByKind(
    realLimit: number,
    simulatedLimit: number,
    rejectedLimit: number
  ): CopilotMcpLogRecord[] {
    const rows = db
      .prepare(
        `SELECT * FROM (
           SELECT * FROM mcp_copilot_logs
           WHERE simulated = 0 AND sf_username <> :unverified ORDER BY seq DESC LIMIT :realLimit
         )
         UNION ALL
         SELECT * FROM (
           SELECT * FROM mcp_copilot_logs WHERE simulated <> 0 ORDER BY seq DESC LIMIT :simulatedLimit
         )
         UNION ALL
         SELECT * FROM (
           SELECT * FROM mcp_copilot_logs
           WHERE simulated = 0 AND sf_username = :unverified ORDER BY seq DESC LIMIT :rejectedLimit
         )
         ORDER BY seq DESC`
      )
      .all({ unverified: UNVERIFIED_CALLER_USERNAME, realLimit, simulatedLimit, rejectedLimit }) as any[];
    return rows.map(toCopilotMcpLogRecord);
  },

  /**
   * One page of the whole MCP log, newest first, for reading past the /overview caps. Pass the
   * previous page's `nextBefore` as `before`; it is null once the oldest matching row is returned.
   */
  getCopilotMcpLogPage(query: CopilotMcpLogPageQuery): LogPage<CopilotMcpLogRecord> {
    const where: string[] = [];
    const params: Record<string, string | number> = {};
    if (query.status !== undefined) {
      where.push('status = :status');
      params.status = query.status;
    }
    if (query.simulated !== undefined) where.push(query.simulated ? 'simulated <> 0' : 'simulated = 0');
    if (query.toolName !== undefined) {
      where.push('tool_name = :toolName');
      params.toolName = query.toolName;
    }
    if (query.targetObject !== undefined) {
      where.push('target_object = :targetObject');
      params.targetObject = query.targetObject;
    }
    return readLogPage('mcp_copilot_logs', where, params, query, toCopilotMcpLogRecord);
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
   * When the last real call reached the MCP tools, read from the table because rejected-token rows
   * can fill the capped list. A rejected token does not count: anyone can send one, and it would
   * present an unauthenticated request as MCP activity.
   */
  getLastRealMcpCallAt(): string | null {
    const row = db
      .prepare(
        `SELECT timestamp FROM mcp_copilot_logs
         WHERE simulated = 0 AND sf_username <> ?
         ORDER BY seq DESC LIMIT 1`
      )
      .get(UNVERIFIED_CALLER_USERNAME) as { timestamp: string } | undefined;
    return row?.timestamp ?? null;
  },

  /**
   * Writes one MCP log row. Its kind follows from `simulated` and the user (mcpLogKind): a refused
   * token is logged as UNVERIFIED_CALLER_USERNAME. The payloads go through stripSensitivePayloadData;
   * the decision is reduced to names, ids and codes its policy snapshot holds (decisionLogColumns) and
   * never goes through it, since it holds no value.
   */
  recordCopilotMcpLog(input: DecidedBy & {
    sfUsername: string;
    profileId: string;
    profileName: string;
    matchedGroups: string[];
    toolName: string;
    targetObject: string;
    status: 'ALLOWED' | 'DENIED' | 'ERROR';
    /** The latency of a row written without totalMs. */
    latencyMs?: number;
    rawRequestPayload: unknown;
    rawResponseSummary: unknown;
    /** Callers pass this from a verified token or a server route, never from request input. */
    simulated?: boolean;
    /** How long verifying the bearer token took, in ms; left out when the row's request verified none. */
    verificationMs?: number;
    /** Ms from the request's receipt to this row; latency_ms is written from it. */
    totalMs?: number;
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
    const toolName = storedToolName(input.toolName);
    const targetObject = storedTargetObject(input.targetObject);
    const simulated = input.simulated === true;
    const decided = input.decision
      ? decisionLogColumns(input.decision, policySnapshotCatalog(input.policySnapshot))
      : null;
    const totalMs = storedMs(input.totalMs);

    const { lastInsertRowid } = db.prepare(`
      INSERT INTO mcp_copilot_logs (
        id, timestamp, sf_username, profile_id, profile_name, matched_groups_json,
        tool_name, target_object, status, latency_ms,
        sanitized_request_payload, sanitized_response_summary, simulated, kind,
        decision_json, decision_stage, decision_code, assigned_group_ids_json, deciding_group_ids_json,
        policy_revision, caller_profile_id, matched_profile_id, match_method, verification_ms, total_ms
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      timestamp,
      input.sfUsername,
      input.profileId,
      input.profileName,
      JSON.stringify(input.matchedGroups),
      toolName,
      targetObject,
      input.status,
      totalMs ?? input.latencyMs ?? 0,
      sanitizedReq,
      sanitizedRes,
      simulated ? 1 : 0,
      mcpLogKind(simulated, input.sfUsername),
      decided ? JSON.stringify(decided.decision) : '',
      decided?.stage ?? '',
      decided?.code ?? '',
      JSON.stringify(decided?.assignedGroupIds ?? []),
      JSON.stringify(decided?.decidingGroupIds ?? []),
      decided?.policyRevision ?? null,
      decided?.callerProfileId ?? '',
      decided?.matchedProfileId ?? '',
      decided?.matchMethod ?? '',
      storedMs(input.verificationMs),
      totalMs
    );

    // Read back, so the row returned is the one every reader returns.
    return toCopilotMcpLogRecord(db.prepare('SELECT * FROM mcp_copilot_logs WHERE seq = ?').get(lastInsertRowid));
  },

  getPortalAdminLogs(limit = 150): PortalAdminLogRecord[] {
    const rows = db
      .prepare('SELECT * FROM portal_admin_logs ORDER BY seq DESC LIMIT ?')
      .all(limit) as any[];
    return rows.map(toPortalAdminLogRecord);
  },

  /**
   * Newest first, with policy simulations capped apart from every other action so a run of them
   * cannot push earlier audit entries out of the portal view. Every row stays in the table.
   */
  getPortalAdminLogsCappedByKind(otherLimit: number, simulationLimit: number): PortalAdminLogRecord[] {
    const rows = db
      .prepare(
        `SELECT * FROM (
           SELECT * FROM portal_admin_logs WHERE action <> :action ORDER BY seq DESC LIMIT :otherLimit
         )
         UNION ALL
         SELECT * FROM (
           SELECT * FROM portal_admin_logs WHERE action = :action ORDER BY seq DESC LIMIT :simulationLimit
         )
         ORDER BY seq DESC`
      )
      .all({ action: SIMULATE_MCP_CALL_ACTION, otherLimit, simulationLimit }) as any[];
    return rows.map(withSeq(toPortalAdminLogRecord));
  },

  /** One page of the whole portal audit log, newest first; paged like getCopilotMcpLogPage. */
  getPortalAdminLogPage(query: PortalAdminLogPageQuery): LogPage<PortalAdminLogRecord> {
    const where: string[] = [];
    const params: Record<string, string | number> = {};
    if (query.action !== undefined) {
      where.push('action = :action');
      params.action = query.action;
    }
    if (query.authMethod !== undefined) {
      where.push('auth_method = :authMethod');
      params.authMethod = query.authMethod;
    }
    return readLogPage('portal_admin_logs', where, params, query, toPortalAdminLogRecord);
  },

  recordPortalAdminLog(input: {
    adminUsername: string;
    authMethod: 'password' | 'okta_sso';
    action: string;
    target: string;
    details: string;
    ipAddress?: string;
    /** Defaults to the action-name rule: *_FAILED is FAILED, *_DENIED is DENIED, anything else SUCCESS. */
    result?: PortalAuditResult;
    /** What the action changed, by a stable id, e.g. 'group' and the group's id. */
    targetType?: string;
    targetId?: string;
    /**
     * Names, ids and flags of what changed, stored as JSON. Never a secret, a password, a key or a token.
     * One over 64 KB is stored as { truncated: true, length } instead.
     */
    diff?: Record<string, unknown>;
    /** The id of the Admin API request that wrote this row. A row written without one gets its own. */
    correlationId?: string;
  }): PortalAdminLogRecord {
    const result = input.result ?? auditResultFromAction(input.action);
    if (!PORTAL_AUDIT_RESULTS.includes(result)) {
      throw new Error(`Unknown audit result '${result}'.`);
    }
    const id = `adm_${Date.now().toString(36)}_${crypto.randomBytes(8).toString('hex')}`;
    const timestamp = new Date().toISOString();
    const ip = input.ipAddress || '127.0.0.1';
    const targetType = input.targetType || '';
    const targetId = input.targetId || '';
    const diffJson = storedAuditDiff(input.diff);
    const correlationId = input.correlationId || crypto.randomUUID();

    db.prepare(`
      INSERT INTO portal_admin_logs (
        id, timestamp, admin_username, auth_method, action, target, details, ip_address,
        result, target_type, target_id, diff_json, correlation_id
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      timestamp,
      input.adminUsername,
      input.authMethod,
      input.action,
      input.target,
      input.details,
      ip,
      result,
      targetType,
      targetId,
      diffJson,
      correlationId
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
      result,
      targetType,
      targetId,
      diff: parseAuditDiff(diffJson),
      correlationId,
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

  /**
   * The values a save of `input` would store. The production https gate reads this, so it judges
   * the same result the save writes, including values kept from the stored row.
   */
  resolveOktaSave(input: OktaConfigInput) {
    const current = this.getOktaConfig();
    const oktaDomain = (input.oktaDomain ?? current.oktaDomain).trim();
    const derivedIssuer = oktaDomain
      ? `https://${oktaDomain.replace(/^https?:\/\//, '').replace(/\/+$/, '')}/oauth2/default`
      : '';
    const domainChanged = oktaDomain !== current.oktaDomain;
    // An explicit issuer wins; an empty one means "derive from the domain". Otherwise keep a custom
    // issuer (e.g. the Okta org authorization server) across saves that do not change the domain.
    const requestedIssuer = input.issuer?.trim();
    const issuer = requestedIssuer
      ? requestedIssuer
      : input.issuer !== undefined || domainChanged || !current.issuer
      ? derivedIssuer
      : current.issuer;
    return {
      enabled: Boolean(input.enabled ?? current.enabled),
      oktaDomain,
      issuer,
      redirectUri: (input.redirectUri ?? current.redirectUri).trim(),
    };
  },

  updateOktaConfig(input: OktaConfigInput): OktaSsoSettings {
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
    const next = this.resolveOktaSave(input);
    const now = new Date().toISOString();

    db.prepare(`
      UPDATE okta_config
      SET enabled = ?, okta_domain = ?, issuer = ?, client_id = ?,
          client_secret_enc = ?, redirect_uri = ?, admin_group = ?, updated_at = ?
      WHERE id = 1
    `).run(
      next.enabled ? 1 : 0,
      next.oktaDomain,
      next.issuer,
      (input.clientId ?? current.clientId).trim(),
      nextSecretEnc,
      next.redirectUri,
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
    const { privateKeyPem, undecryptable } = readStoredPrivateKey(row.private_key_enc);
    return {
      enabled: Boolean(row.enabled),
      authMode: row.auth_mode === 'simulated' ? 'simulated' : 'jwt_bearer',
      loginUrl: row.login_url || 'https://login.salesforce.com',
      clientId: row.client_id || '',
      username: row.username || '',
      hasPrivateKey: Boolean(privateKeyPem),
      privateKeyUndecryptable: undecryptable,
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

  getSalesforceSettingsWithSecrets(): SalesforceConnectionSettings & { privateKeyPem: string } {
    const row = db.prepare('SELECT private_key_enc FROM sf_connection_settings WHERE id = 1').get() as {
      private_key_enc: string;
    };
    const { privateKeyPem } = readStoredPrivateKey(row.private_key_enc);
    const base = this.getSalesforceSettings();
    return {
      ...base,
      privateKeyPem,
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
        !isSimulatedOrgHost(session.instanceUrl) &&
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
