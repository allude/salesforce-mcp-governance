/**
 * Fixed-window failure counter per key. Unlike express-rate-limit, it counts a request only once
 * its outcome is known, so a request that verifies, or a stream that is dropped before it ends,
 * never uses up a slot.
 */
export interface FailureWindow {
  /** Seconds until the key may try again, or 0 when it is under the limit. */
  retryAfterSeconds(key: string, now?: number): number;
  record(key: string, now?: number): void;
}

export function createFailureWindow(options: { windowMs: number; max: number; maxKeys: number }): FailureWindow {
  const windows = new Map<string, { count: number; resetAt: number }>();

  const current = (key: string, now: number) => {
    const entry = windows.get(key);
    if (!entry || entry.resetAt <= now) return undefined;
    return entry;
  };

  return {
    retryAfterSeconds(key, now = Date.now()) {
      const entry = current(key, now);
      return entry && entry.count >= options.max ? Math.max(1, Math.ceil((entry.resetAt - now) / 1000)) : 0;
    },
    record(key, now = Date.now()) {
      const entry = current(key, now);
      if (entry) {
        entry.count += 1;
        return;
      }
      if (windows.size >= options.maxKeys) {
        for (const [k, value] of windows) {
          if (value.resetAt <= now) windows.delete(k);
        }
        // Still full: drop the oldest window. Its key starts again from zero, which errs towards
        // letting a caller in rather than blocking one that never failed.
        while (windows.size >= options.maxKeys) {
          const oldest = windows.keys().next().value;
          if (oldest === undefined) break;
          windows.delete(oldest);
        }
      }
      // Delete first so a key whose old window expired moves to the end and is not taken for the oldest.
      windows.delete(key);
      windows.set(key, { count: 1, resetAt: now + options.windowMs });
    },
  };
}
