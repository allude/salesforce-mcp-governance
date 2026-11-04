/**
 * Timestamps as the portal shows them: always with the date and an explicit zone. The portal states UTC,
 * the zone the server stamps rows in, so a time reads the same for every admin and in every export; the
 * admin's local time is in the tooltip. Replaces the time-only formatShortTime and the zone-less
 * formatDateShort.
 */
const pad = (n: number) => String(n).padStart(2, '0');

function parse(iso: string | null | undefined): Date | null {
  if (!iso) return null;
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? null : d;
}

/** 2026-11-04 21:56:14 UTC, or '—' when there is no time; an unreadable value is shown as given. */
export function formatTimestamp(iso: string | null | undefined): string {
  const d = parse(iso);
  if (!d) return iso ? String(iso) : '—';
  return `${d.toISOString().slice(0, 10)} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())} UTC`;
}

/** 2026-11-04 (UTC), for columns too narrow for the time. */
export function formatDateUtc(iso: string | null | undefined): string {
  const d = parse(iso);
  if (!d) return iso ? String(iso) : '—';
  return d.toISOString().slice(0, 10);
}

/** 21:56:14 UTC, for a label that already names the day (an activity window ending today). */
export function formatTimeOfDayUtc(iso: string | null | undefined): string {
  const d = parse(iso);
  if (!d) return iso ? String(iso) : '—';
  return `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())} UTC`;
}

/** The tooltip: the same moment in the admin's own zone, named. */
export function formatLocalTimestamp(iso: string | null | undefined): string {
  const d = parse(iso);
  if (!d) return '';
  return d.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    timeZoneName: 'short',
  });
}
