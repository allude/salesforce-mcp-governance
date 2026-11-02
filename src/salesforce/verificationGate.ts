/** Thrown when token verification is at capacity; the caller should retry shortly. */
export class VerificationBusyError extends Error {
  constructor() {
    super('Salesforce token verification is busy, please retry shortly');
    this.name = 'VerificationBusyError';
  }
}

export interface VerificationGate {
  /** Runs `task` when a slot is free. Priority callers go ahead of the others in the queue. */
  run<T>(priority: boolean, task: () => Promise<T>): Promise<T>;
  /** For tests: slots in use and callers waiting. */
  stats(): { active: number; queued: number };
}

interface Waiter {
  start: () => void;
  refuse: () => void;
  timer: ReturnType<typeof setTimeout>;
}

/**
 * Caps how many token verifications reach Salesforce at once. When every caller shares one IP
 * there is no fair per-client limit, so a flood of junk tokens is slowed to this pace instead of
 * being refused outright, and real callers are never shut out by a counter someone else filled.
 * Callers whose token verified recently skip ahead, so a flood mostly delays brand-new tokens.
 */
export function createVerificationGate(options: { maxConcurrent: number; maxQueued: number; maxWaitMs: number }): VerificationGate {
  let active = 0;
  const priorityQueue: Waiter[] = [];
  const queue: Waiter[] = [];

  const release = () => {
    active -= 1;
    const next = priorityQueue.shift() || queue.shift();
    if (next) {
      clearTimeout(next.timer);
      next.start();
    }
  };

  const execute = <T>(task: () => Promise<T>): Promise<T> => {
    active += 1;
    let result: Promise<T>;
    try {
      result = Promise.resolve(task());
    } catch (err) {
      result = Promise.reject(err);
    }
    return result.finally(release);
  };

  return {
    run(priority, task) {
      if (active < options.maxConcurrent) return execute(task);
      if (priorityQueue.length + queue.length >= options.maxQueued) {
        if (!priority || queue.length === 0) return Promise.reject(new VerificationBusyError());
        // A full queue sheds its newest ordinary waiter to make room for a priority caller.
        const shed = queue.pop()!;
        clearTimeout(shed.timer);
        shed.refuse();
      }

      return new Promise((resolve, reject) => {
        const list = priority ? priorityQueue : queue;
        const waiter: Waiter = {
          start: () => execute(task).then(resolve, reject),
          refuse: () => reject(new VerificationBusyError()),
          timer: setTimeout(() => {
            const index = list.indexOf(waiter);
            if (index !== -1) list.splice(index, 1);
            waiter.refuse();
          }, options.maxWaitMs),
        };
        list.push(waiter);
      });
    },
    stats() {
      return { active, queued: priorityQueue.length + queue.length };
    },
  };
}
