import type { CopilotMcpLogEntry, PortalAdminLogEntry, PortalOverviewPayload } from '@/types/governance';

/** Rows asked for by each click of "Load older". */
export const LOG_HISTORY_PAGE_ROWS = 200;
/** The most rows one CSV export reads, so an export of a huge log stays a bounded download. */
export const LOG_EXPORT_MAX_ROWS = 10_000;
/** The largest page the log routes serve. */
export const LOG_EXPORT_PAGE_ROWS = 1000;
/** The most rows one export reads while looking for matches, so a rare search cannot read forever. */
export const LOG_EXPORT_MAX_SCANNED_ROWS = 100_000;

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
 * `cleared` is set by Clear log, which empties only the view, until rows come back into it.
 */
export interface OlderRowsState<T> {
  older: T[];
  cursor: number | null | undefined;
  loadedTop: number | undefined;
  cleared: boolean;
}

export function emptyOlderRows<T>(): OlderRowsState<T> {
  return { older: [], cursor: undefined, loadedTop: undefined, cleared: false };
}

/** The state after Clear log: no loaded pages, and a view the toolbar calls cleared. */
export function clearedOlderRows<T>(): OlderRowsState<T> {
  return { ...emptyOlderRows<T>(), cleared: true };
}

/**
 * The state after one "Load older": the next pages older than the cursor that add a row the view
 * does not hold. From an empty state this reads down from the newest row of the log and records it.
 * Rows read into a cleared view refill it, so it is no longer called cleared.
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
    cleared: state.cleared && page.rows.length === 0,
  };
}

/**
 * Why an export stopped before the start of the log, or null when it read all of it. `matches`: it
 * kept `matched` rows, the most one export holds, and older rows were not checked. `scan`: it read
 * `scanned` rows without reaching that many matches, and older rows were not checked.
 */
export type ExportCut =
  | null
  | { by: 'matches'; matched: number; scanned: number }
  | { by: 'scan'; matched: number; scanned: number };

export interface ExportRead<T> {
  rows: T[];
  scanned: number;
  truncated: boolean;
  cut: ExportCut;
}

/**
 * Every row the route returns that `keep` accepts, newest first, up to `max` kept rows. The route
 * cannot apply the free-text search, so each page is filtered as it arrives and the limit counts
 * the rows kept; `maxScanned` bounds the rows read, so a search that matches rarely cannot read a
 * huge log to its start. `cut` says which limit stopped it, so the export can say exactly that.
 */
export async function readAllRows<T>(
  readPage: ReadLogPage<T>,
  max = LOG_EXPORT_MAX_ROWS,
  pageRows = LOG_EXPORT_PAGE_ROWS,
  options: { keep?: (row: T) => boolean; maxScanned?: number } = {}
): Promise<ExportRead<T>> {
  const { keep, maxScanned = LOG_EXPORT_MAX_SCANNED_ROWS } = options;
  const rows: T[] = [];
  let scanned = 0;
  const stop = (by: 'matches' | 'scan'): ExportRead<T> => ({
    rows,
    scanned,
    truncated: true,
    cut: { by, matched: rows.length, scanned },
  });
  let before: number | undefined;
  for (;;) {
    // Unfiltered, every row read is kept, so ask only for the rows still needed.
    const want = keep ? Math.min(pageRows, maxScanned - scanned) : Math.min(pageRows, max - rows.length);
    const page = await readPage(before, want);
    for (const row of page.rows) {
      if (scanned >= maxScanned) return stop('scan');
      const kept = !keep || keep(row);
      if (kept && rows.length >= max) return stop('matches');
      scanned += 1;
      if (kept) rows.push(row);
    }
    // A cursor that does not move would loop forever; treat it as the end of the log.
    const advanced = page.nextBefore !== null && (before === undefined || page.nextBefore < before);
    if (!advanced) return { rows, scanned, truncated: false, cut: null };
    if (rows.length >= max) return stop('matches');
    if (scanned >= maxScanned) return stop('scan');
    before = page.nextBefore as number;
  }
}

/** The legacy `true` means the match limit cut an export at `max` rows. */
function normalizeCut(cut: ExportCut | boolean, max: number): ExportCut {
  if (cut === true) return { by: 'matches', matched: max, scanned: max };
  return cut === false ? null : cut;
}

/** The export's file name, marked when a limit cut it short so the file says so on its own. */
export function exportFileName(
  base: string,
  date: string,
  cut: ExportCut | boolean,
  max = LOG_EXPORT_MAX_ROWS
): string {
  const c = normalizeCut(cut, max);
  if (!c) return `${base}-${date}.csv`;
  if (c.by === 'matches') return `${base}-${date}-newest-${c.matched}-rows.csv`;
  return `${base}-${date}-${c.matched}-matching-in-newest-${c.scanned}-rows.csv`;
}

/** The notice for a cut export: how many rows matched, and which limit stopped it. */
export function exportCutMessage(cut: Exclude<ExportCut, null>): string {
  const n = (count: number) => count.toLocaleString('en-US');
  if (cut.by === 'matches') {
    return `Export stopped at the newest ${n(cut.matched)} matching rows, the most one file holds; older rows were not checked.`;
  }
  const matched = cut.matched === 1 ? '1 row matched' : `${n(cut.matched)} rows matched`;
  return `Export stopped after checking the newest ${n(cut.scanned)} rows, the most one export reads: ${matched}; older rows were not checked.`;
}

export function exportTruncatedMessage(max = LOG_EXPORT_MAX_ROWS): string {
  return exportCutMessage({ by: 'matches', matched: max, scanned: max });
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
