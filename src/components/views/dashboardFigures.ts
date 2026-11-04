import { formatShortTime } from '@/components/ui/primitives';
import type { McpActivityFigures } from '@/types/governance';

/** The dashboard's target share of MCP calls answered without an error, in percent. */
export const SUCCESS_RATE_TARGET = 98;

export interface SuccessRate {
  /** Percent with one decimal, for display. */
  label: string;
  meetsTarget: boolean;
}

/**
 * Share of calls answered without an error. A policy denial is the access matrix doing its job, so it
 * is not a failure here; denials have their own figure. With no calls there is nothing that failed.
 * The label rounds down, so a rate just short of the target never reads as meeting it; the target is
 * judged on the counts themselves, not on the rounded label.
 */
export function successRate(totalCalls: number, errorCalls: number): SuccessRate {
  if (totalCalls <= 0) return { label: '100.0', meetsTarget: true };
  const ok = totalCalls - errorCalls;
  return {
    label: (Math.floor((ok * 1000) / totalCalls) / 10).toFixed(1),
    meetsTarget: ok * 100 >= SUCCESS_RATE_TARGET * totalCalls,
  };
}

/** Older than this, the activity figures name when their window ended rather than say "last". */
const ACTIVITY_CURRENT_MS = 2 * 60_000;

/**
 * The window the activity figures cover. They are as of the last answer from the server, while the
 * chart beside them keeps ageing between answers, so once they are older than a couple of polls,
 * which happens while live refresh is paused, the label says when the window ended, with its date
 * when that was an earlier day. `now` should be on the server's clock.
 */
export function activityWindowLabel(figures: McpActivityFigures | null | undefined, now: number): string {
  const hours = figures?.windowHours ?? 24;
  const asOf = figures ? Date.parse(figures.asOf) : NaN;
  if (Number.isNaN(asOf) || now - asOf < ACTIVITY_CURRENT_MS) return `last ${hours} h`;
  const end = new Date(asOf);
  const day =
    end.toDateString() === new Date(now).toDateString()
      ? ''
      : `${end.toLocaleDateString([], { month: 'short', day: 'numeric' })} `;
  return `${hours} h to ${day}${formatShortTime(figures!.asOf)}`;
}
