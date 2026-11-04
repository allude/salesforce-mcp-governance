import type { StatusTone } from '@/components/ui/statusTone';
import { statusTone } from '@/components/ui/statusTone';

/**
 * The header's freshness chip: "Updated 4s ago · Live", "Paused", or amber "Degraded" once a refresh
 * has failed since the last success. `lastOkAt` is null until the first refresh answered.
 */
export interface FreshnessInput {
  live: boolean;
  lastOkAt: number | null;
  /** Failures since the last successful refresh. */
  failures: number;
  now: number;
}

export interface Freshness {
  state: 'live' | 'paused' | 'degraded' | 'connecting';
  label: string;
  updated: string;
  tone: StatusTone;
}

export function updatedAgo(lastOkAt: number | null, now: number): string {
  if (lastOkAt === null) return 'Not updated yet';
  const s = Math.max(0, Math.floor((now - lastOkAt) / 1000));
  if (s < 60) return `Updated ${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `Updated ${m} min ago`;
  return `Updated ${Math.floor(m / 60)} h ago`;
}

export function freshness({ live, lastOkAt, failures, now }: FreshnessInput): Freshness {
  const updated = updatedAgo(lastOkAt, now);
  if (failures > 0) return { state: 'degraded', label: 'Degraded', updated, tone: statusTone('DEGRADED') };
  if (!live) return { state: 'paused', label: 'Paused', updated, tone: statusTone('PAUSED') };
  if (lastOkAt === null) return { state: 'connecting', label: 'Connecting', updated, tone: 'neutral' };
  return { state: 'live', label: 'Live', updated, tone: statusTone('LIVE') };
}

/** The footer's session chip: "Session 6:42 left", from /session's expiresAt. */
export function sessionTimeLeft(expiresAt: string | null | undefined, now: number): string | null {
  const end = expiresAt ? Date.parse(expiresAt) : NaN;
  if (Number.isNaN(end)) return null;
  const minutes = Math.max(0, Math.floor((end - now) / 60_000));
  if (minutes <= 0) return 'Session ending';
  return `Session ${Math.floor(minutes / 60)}:${String(minutes % 60).padStart(2, '0')} left`;
}
