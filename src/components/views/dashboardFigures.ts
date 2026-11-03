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
 */
export function successRate(totalCalls: number, errorCalls: number): SuccessRate {
  if (totalCalls <= 0) return { label: '100.0', meetsTarget: true };
  const percent = ((totalCalls - errorCalls) / totalCalls) * 100;
  return { label: percent.toFixed(1), meetsTarget: percent >= SUCCESS_RATE_TARGET };
}
