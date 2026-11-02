import type { CopilotMcpLogEntry, PortalAdminLogEntry, PortalOverviewPayload } from '@/types/governance';

/** Rows asked for by each click of "Load older". */
export const LOG_HISTORY_PAGE_ROWS = 200;
/** The most rows one CSV export reads, so an export of a huge log stays a bounded download. */
export const LOG_EXPORT_MAX_ROWS = 10_000;
/** The largest page the log routes serve. */
export const LOG_EXPORT_PAGE_ROWS = 1000;

export interface LogPage<T> {
  rows: T[];
  nextBefore: number | null;
}

/** Reads one page older than `before` (the newest page when undefined), at most `limit` rows. */
export type ReadLogPage<T> = (before: number | undefined, limit: number) => Promise<LogPage<T>>;

export type LogQuery = Record<string, string | number | undefined>;

/** The route plus its query string, leaving out unset parameters. */
export function logPageUrl(path: string, query: LogQuery): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value !== undefined && value !== '') params.set(key, String(value));
  }
  const qs = params.toString();
  return qs ? `${path}?${qs}` : path;
}

/** One list, newest first by write order, each row once; later lists win for a repeated id. */
export function mergeNewestFirst<T extends { id: string; seq?: number }>(...lists: T[][]): T[] {
  const byId = new Map<string, T>();
  for (const list of lists) for (const row of list) byId.set(row.id, row);
  return Array.from(byId.values()).sort((a, b) => (b.seq ?? 0) - (a.seq ?? 0));
}

/**
 * Reads pages older than `cursor` until one adds a row the view does not hold yet, or the log ends.
 * The first contiguous pages can be wholly inside the capped /overview lists, and a click that shows
 * nothing new would look broken. Those lists hold a few hundred rows, so this stops within a few pages.
 */
export async function readOlderRows<T extends { id: string }>(
  readPage: ReadLogPage<T>,
  cursor: number | undefined,
  held: ReadonlySet<string>,
  pageRows = LOG_HISTORY_PAGE_ROWS
): Promise<LogPage<T>> {
  const rows: T[] = [];
  let before = cursor;
  for (;;) {
    const page = await readPage(before, pageRows);
    rows.push(...page.rows);
    const advanced = page.nextBefore !== null && (before === undefined || page.nextBefore < before);
    if (!advanced || page.rows.some((row) => !held.has(row.id))) {
      return { rows, nextBefore: advanced ? page.nextBefore : null };
    }
    before = page.nextBefore as number;
  }
}

/** The newest write-order seq among `rows`, or 0 when there are none. */
export function newestSeq(rows: Array<{ seq?: number }>): number {
  return rows.reduce((newest, row) => Math.max(newest, row.seq ?? 0), 0);
}

/**
 * The rows "Load older" has read beside the /overview list. `cursor` is undefined before the first
 * page and null once the oldest row has been read. `loadedTop` is the newest seq the loaded pages
 * cover, recorded when the first page is read (0 for a log that was empty then): the pages run
 * unbroken from that row down to the cursor, and only /overview rows can stand in for newer ones.
 */
export interface OlderRowsState<T> {
  older: T[];
  cursor: number | null | undefined;
  loadedTop: number | undefined;
}

export function emptyOlderRows<T>(): OlderRowsState<T> {
  return { older: [], cursor: undefined, loadedTop: undefined };
}

/**
 * The state after one "Load older": the next pages older than the cursor that add a row the view
 * does not hold. From an empty state this reads down from the newest row of the log and records it.
 */
export async function loadOlderRows<T extends { id: string; seq?: number }>(
  readPage: ReadLogPage<T>,
  state: OlderRowsState<T>,
  overview: T[],
  pageRows = LOG_HISTORY_PAGE_ROWS
): Promise<OlderRowsState<T>> {
  if (state.cursor === null) return state;
  const held = new Set([...overview, ...state.older].map((row) => row.id));
  const page = await readOlderRows(readPage, state.cursor, held, pageRows);
  return {
    older: mergeNewestFirst(state.older, page.rows),
    cursor: page.nextBefore,
    loadedTop: state.cursor === undefined ? newestSeq(page.rows) : state.loadedTop,
  };
}

/**
 * Every row the route returns, newest first, up to `max`. `truncated` says older matching rows
 * exist that were left out, so the export can say so.
 */
export async function readAllRows<T>(
  readPage: ReadLogPage<T>,
  max = LOG_EXPORT_MAX_ROWS,
  pageRows = LOG_EXPORT_PAGE_ROWS
): Promise<{ rows: T[]; truncated: boolean }> {
  const rows: T[] = [];
  let before: number | undefined;
  for (;;) {
    const page = await readPage(before, Math.min(pageRows, max - rows.length));
    rows.push(...page.rows.slice(0, max - rows.length));
    // A cursor that does not move would loop forever; treat it as the end of the log.
    const advanced = page.nextBefore !== null && (before === undefined || page.nextBefore < before);
    if (!advanced) return { rows, truncated: false };
    if (rows.length >= max) return { rows, truncated: true };
    before = page.nextBefore as number;
  }
}

/** The export's file name, marked when the row limit cut it short so the file says so on its own. */
export function exportFileName(base: string, date: string, truncated: boolean, max = LOG_EXPORT_MAX_ROWS): string {
  return truncated ? `${base}-${date}-newest-${max}-rows.csv` : `${base}-${date}.csv`;
}

export function exportTruncatedMessage(max = LOG_EXPORT_MAX_ROWS): string {
  return `Export stopped at the newest ${max.toLocaleString('en-US')} matching rows; older rows are not in the file.`;
}

export interface TrafficFilters {
  status: 'all' | 'ALLOWED' | 'DENIED' | 'ERROR';
  tool: string;
  object: string;
  search: string;
}

/** Filters the route applies itself; the free-text search is applied to the rows it returns. */
export function trafficRouteQuery(filters: TrafficFilters): LogQuery {
  return {
    status: filters.status === 'all' ? undefined : filters.status,
    tool: filters.tool === 'all' ? undefined : filters.tool,
    object: filters.object === 'all' ? undefined : filters.object,
  };
}

export function trafficRowMatches(row: CopilotMcpLogEntry, filters: TrafficFilters): boolean {
  const q = filters.search.toLowerCase();
  return (
    (filters.status === 'all' || row.status === filters.status) &&
    (filters.tool === 'all' || row.toolName === filters.tool) &&
    (filters.object === 'all' || row.targetObject === filters.object) &&
    (!q ||
      row.sfUsername.toLowerCase().includes(q) ||
      row.profileName.toLowerCase().includes(q) ||
      row.toolName.toLowerCase().includes(q) ||
      row.targetObject.toLowerCase().includes(q) ||
      row.profileId.toLowerCase().includes(q))
  );
}

export interface AuditFilters {
  method: 'all' | 'okta_sso' | 'password';
  action: string;
  search: string;
}

export function auditRouteQuery(filters: AuditFilters): LogQuery {
  return {
    authMethod: filters.method === 'all' ? undefined : filters.method,
    action: filters.action === 'all' ? undefined : filters.action,
  };
}

export function auditRowMatches(row: PortalAdminLogEntry, filters: AuditFilters): boolean {
  const q = filters.search.toLowerCase();
  return (
    (filters.method === 'all' || row.authMethod === filters.method) &&
    (filters.action === 'all' || row.action === filters.action) &&
    (!q ||
      row.adminUsername.toLowerCase().includes(q) ||
      row.action.toLowerCase().includes(q) ||
      row.target.toLowerCase().includes(q) ||
      row.details.toLowerCase().includes(q))
  );
}

/** The MCP log user for a rejected bearer token; matches UNVERIFIED_CALLER_USERNAME in the store. */
export const REJECTED_TOKEN_USERNAME = 'unverified_caller';
/** The audit action written per policy simulation; matches SIMULATE_MCP_CALL_ACTION in the store. */
export const SIMULATION_ACTION = 'SIMULATE_MCP_CALL';

/** How many rows of each kind the /overview log lists hold at most. */
export type OverviewLogCaps = PortalOverviewPayload['logCaps'];

/** The caps /overview has used since they were split by kind, for a response that does not send them. */
export const DEFAULT_OVERVIEW_LOG_CAPS: OverviewLogCaps = {
  copilotLogs: { calls: 150, simulated: 50, rejected: 50 },
  portalLogs: { events: 150, simulations: 50 },
};

export interface LogKind<T> {
  noun: string;
  cap: number;
  matches: (row: T) => boolean;
}

export function trafficLogKinds(caps: OverviewLogCaps['copilotLogs']): Array<LogKind<CopilotMcpLogEntry>> {
  const rejected = (r: CopilotMcpLogEntry) => !r.simulated && r.sfUsername === REJECTED_TOKEN_USERNAME;
  return [
    { noun: 'calls', cap: caps.calls, matches: (r) => !r.simulated && !rejected(r) },
    { noun: 'simulated', cap: caps.simulated, matches: (r) => r.simulated === true },
    { noun: 'rejected', cap: caps.rejected, matches: rejected },
  ];
}

export function auditLogKinds(caps: OverviewLogCaps['portalLogs']): Array<LogKind<PortalAdminLogEntry>> {
  return [
    { noun: 'events', cap: caps.events, matches: (r) => r.action !== SIMULATION_ACTION },
    { noun: 'simulations', cap: caps.simulations, matches: (r) => r.action === SIMULATION_ACTION },
  ];
}

function utcSeconds(iso: string): string {
  return `${iso.slice(0, 19).replace('T', ' ')} UTC`;
}

/**
 * The kinds whose rows have a gap above the loaded pages. Live refreshes replace the /overview list,
 * which keeps only the newest `cap` rows of each kind: once more than that many arrive after the
 * pages were loaded, the list's oldest row of that kind is newer than `loadedTop`, and the rows in
 * between are in neither the list nor the pages. A kind under its cap is held in full, so has none.
 */
export function heldLogGaps<T extends { seq?: number }>(input: {
  overview: T[];
  loadedTop: number | undefined;
  kinds: Array<LogKind<T>>;
}): string[] {
  const { overview, loadedTop, kinds } = input;
  if (loadedTop === undefined) return [];
  return kinds.flatMap((kind) => {
    const rows = overview.filter(kind.matches);
    if (rows.length === 0 || rows.length < kind.cap) return [];
    const oldest = rows.reduce((min, row) => Math.min(min, row.seq ?? 0), Infinity);
    return oldest > loadedTop ? [kind.noun] : [];
  });
}

/**
 * What a Logs view holds, for its toolbar. The /overview list caps each kind on its own, so older
 * rows of one kind can be missing between shown rows of another; naming the latest rows held keeps
 * a reader from taking those gaps for a quiet period. A kind with fewer rows than its cap is held
 * in full. `loadedTop` is the newest seq the loaded pages covered when they were first read; rows
 * that have since passed out of the /overview list leave a gap the text must name.
 */
export function describeHeldLogs<T extends { seq?: number; timestamp: string }>(input: {
  overview: T[];
  older: T[];
  cursor: number | null | undefined;
  kinds: Array<LogKind<T>>;
  loadedTop?: number;
}): string {
  const { overview, older, cursor, kinds } = input;
  if (cursor !== undefined) {
    const gaps = heldLogGaps({ overview, loadedTop: input.loadedTop, kinds });
    if (gaps.length > 0) {
      const after = older.length > 0 ? ` after ${utcSeconds(older[0].timestamp)}` : ' since older rows were loaded';
      return `gap: some ${gaps.join(' + ')}${after} are not held; reload to fill it`;
    }
  }
  if (cursor === null) return 'the whole log';

  const oldestLoaded = older.length > 0 ? older[older.length - 1] : undefined;
  if (cursor !== undefined && oldestLoaded) {
    // Loaded pages run unbroken from the newest row, so only /overview rows older than them have gaps.
    const outside = overview.filter((row) => (row.seq ?? 0) < (oldestLoaded.seq ?? 0)).length;
    const since = `every event since ${utcSeconds(oldestLoaded.timestamp)}`;
    return outside > 0 ? `${since} + ${outside} older from the latest-row lists` : since;
  }

  const parts = kinds.flatMap((kind) => {
    const count = overview.filter(kind.matches).length;
    if (count === 0) return [];
    return [count >= kind.cap ? `latest ${kind.cap} ${kind.noun}` : `all ${count} ${kind.noun}`];
  });
  return parts.length > 0 ? parts.join(' + ') : 'no events';
}
