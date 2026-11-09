// Per-account sign-in throttling with exponential backoff instead of a lockout.
//
// A hard lockout (N failures, then refuse for 15 minutes) lets anyone who knows a username keep that
// account locked, which is exactly what an attacker wants during an Okta outage, when the break-glass
// account is the only way in. Here the first few failures are free, then each further failure makes
// the account wait longer before its next attempt (1s, 2s, 4s ... capped at maxDelayMs), so online
// guessing stays slow while the owner is never kept out for more than the cap. The login route also
// lets a throttled attempt through when it carries a correct password and authenticator code.

export interface LoginThrottleOptions {
  /** Failures allowed before any delay applies. */
  freeFailures: number;
  baseDelayMs: number;
  maxDelayMs: number;
  /** A key's failures are forgotten this long after its last failure. */
  forgetAfterMs: number;
  /** Bounds memory under a flood of distinct usernames; the stalest keys are dropped first. */
  maxKeys: number;
}

export interface LoginThrottle {
  /** Milliseconds this key must still wait before its next attempt, 0 when it may try now. */
  retryAfterMs(key: string, nowMs?: number): number;
  recordFailure(key: string, nowMs?: number): void;
  recordSuccess(key: string): void;
}

export const DEFAULT_LOGIN_THROTTLE: LoginThrottleOptions = {
  freeFailures: 5,
  baseDelayMs: 1_000,
  maxDelayMs: 30_000,
  forgetAfterMs: 15 * 60 * 1000,
  maxKeys: 10_000,
};

export function createLoginThrottle(options: LoginThrottleOptions = DEFAULT_LOGIN_THROTTLE): LoginThrottle {
  const entries = new Map<string, { failures: number; lastFailureAt: number }>();

  const live = (key: string, nowMs: number) => {
    const entry = entries.get(key);
    if (!entry) return undefined;
    if (nowMs - entry.lastFailureAt >= options.forgetAfterMs) {
      entries.delete(key);
      return undefined;
    }
    return entry;
  };

  const delayAfter = (failures: number) => {
    const over = failures - options.freeFailures;
    if (over <= 0) return 0;
    return Math.min(options.baseDelayMs * 2 ** (over - 1), options.maxDelayMs);
  };

  return {
    retryAfterMs(key, nowMs = Date.now()) {
      const entry = live(key, nowMs);
      if (!entry) return 0;
      return Math.max(0, entry.lastFailureAt + delayAfter(entry.failures) - nowMs);
    },
    recordFailure(key, nowMs = Date.now()) {
      const entry = live(key, nowMs);
      entries.delete(key);
      if (!entry && entries.size >= options.maxKeys) {
        const oldest = entries.keys().next().value;
        if (oldest !== undefined) entries.delete(oldest);
      }
      // Re-inserted, so the map stays ordered by last failure and the stalest key is evicted first.
      entries.set(key, { failures: (entry?.failures ?? 0) + 1, lastFailureAt: nowMs });
    },
    recordSuccess(key) {
      entries.delete(key);
    },
  };
}

/** The throttle key of a login identifier: usernames are matched case-insensitively. */
export function loginThrottleKey(identifier: string): string {
  return identifier.trim().toLowerCase().slice(0, 200);
}
