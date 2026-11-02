const MINUTE_MS = 60_000;
const HOUR_MS = 60 * MINUTE_MS;
const DAY_MS = 24 * HOUR_MS;

export interface McpActivityStatus {
  label: string;
  /** 'ok' only while the last call is recent: an old call says nothing about the link today. */
  tone: 'ok' | 'off';
}

function timeAgo(ageMs: number): string {
  if (ageMs < MINUTE_MS) return 'just now';
  if (ageMs < HOUR_MS) return `${Math.floor(ageMs / MINUTE_MS)} min ago`;
  if (ageMs < DAY_MS) return `${Math.floor(ageMs / HOUR_MS)} h ago`;
  const days = Math.floor(ageMs / DAY_MS);
  return `${days} ${days === 1 ? 'day' : 'days'} ago`;
}

/**
 * The header's only claim about MCP traffic: when the last real call happened. `lastCallAt` is
 * undefined until the server has answered, and null once it has said there are none. `now` should be
 * on the server's clock, which stamps the call, or a skewed browser clock misstates its age.
 */
export function mcpActivityStatus(lastCallAt: string | null | undefined, now: number): McpActivityStatus {
  if (lastCallAt === null) return { label: 'No MCP calls yet', tone: 'off' };
  const time = lastCallAt === undefined ? NaN : Date.parse(lastCallAt);
  if (Number.isNaN(time)) return { label: 'Last MCP call unknown', tone: 'off' };
  const age = Math.max(now - time, 0);
  return { label: `Last MCP call ${timeAgo(age)}`, tone: age < DAY_MS ? 'ok' : 'off' };
}
