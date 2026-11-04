/**
 * The shell's refresh loop, kept apart from React so its rules are unit-tested with fake timers:
 *
 * - single flight: a tick that finds a refresh still running skips instead of stacking a second one;
 * - every run gets an AbortController (aborted on stop and when the tab hides) and a sequence number,
 *   and only the latest run may report, so a slow answer cannot overwrite a newer one;
 * - it pauses while the document is hidden and refreshes at once when it becomes visible again;
 * - failures are reported (onResult), never swallowed.
 */
export interface PollerDeps {
  intervalMs: number;
  run: (signal: AbortSignal) => Promise<void>;
  onResult: (result: { ok: true; at: number } | { ok: false; at: number; error: unknown }) => void;
  isHidden: () => boolean;
  now?: () => number;
  setTimer?: (fn: () => void, ms: number) => unknown;
  clearTimer?: (handle: unknown) => void;
}

export interface Poller {
  start(): void;
  stop(): void;
  /** Runs now (unless one is in flight), e.g. after a mutation or on "Retry now". */
  refresh(): Promise<void>;
  /** Call on visibilitychange. */
  visibilityChanged(): void;
  readonly running: boolean;
  readonly inFlight: boolean;
}

export function createPoller(deps: PollerDeps): Poller {
  const now = deps.now ?? (() => Date.now());
  const setTimer = deps.setTimer ?? ((fn, ms) => setTimeout(fn, ms));
  const clearTimer = deps.clearTimer ?? ((h) => clearTimeout(h as ReturnType<typeof setTimeout>));
  let started = false;
  let timer: unknown = null;
  let controller: AbortController | null = null;
  let inFlight: Promise<void> | null = null;
  let seq = 0;

  const schedule = () => {
    if (timer !== null) clearTimer(timer);
    timer = null;
    if (!started || deps.isHidden()) return;
    timer = setTimer(() => {
      timer = null;
      void tick().finally(schedule);
    }, deps.intervalMs);
  };

  const tick = (): Promise<void> => {
    if (inFlight) return inFlight;
    if (!started || deps.isHidden()) return Promise.resolve();
    const mine = ++seq;
    const ctl = new AbortController();
    controller = ctl;
    let current: Promise<void> | null = null;
    current = (async () => {
      try {
        await deps.run(ctl.signal);
        if (mine === seq && !ctl.signal.aborted) deps.onResult({ ok: true, at: now() });
      } catch (error) {
        if (mine === seq && !ctl.signal.aborted) deps.onResult({ ok: false, at: now(), error });
      } finally {
        if (controller === ctl) controller = null;
        if (inFlight === current) inFlight = null;
      }
    })();
    inFlight = current;
    return current as Promise<void>;
  };

  const abort = () => {
    controller?.abort();
    controller = null;
    // A new run may start straight away; the aborted one can no longer report (seq moved on).
    seq++;
    inFlight = null;
  };

  return {
    start() {
      if (started) return;
      started = true;
      void tick().finally(schedule);
    },
    stop() {
      started = false;
      if (timer !== null) clearTimer(timer);
      timer = null;
      abort();
    },
    refresh() {
      return tick();
    },
    visibilityChanged() {
      if (!started) return;
      if (deps.isHidden()) {
        if (timer !== null) clearTimer(timer);
        timer = null;
        abort();
      } else {
        void tick().finally(schedule);
      }
    },
    get running() {
      return started;
    },
    get inFlight() {
      return inFlight !== null;
    },
  };
}
