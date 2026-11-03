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
