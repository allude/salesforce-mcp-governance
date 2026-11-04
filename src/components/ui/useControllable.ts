'use client';

import { useCallback, useState } from 'react';

/**
 * State a view keeps itself unless its page controls it (the (portal) pages keep filters in the URL).
 * With `value` given, the view shows it and reports changes through `onChange`.
 */
export function useControllable<T>(value: T | undefined, onChange: ((next: T) => void) | undefined, initial: T) {
  const [local, setLocal] = useState<T>(initial);
  const controlled = value !== undefined && onChange !== undefined;
  const set = useCallback(
    (next: T) => {
      if (controlled) onChange!(next);
      else setLocal(next);
    },
    [controlled, onChange]
  );
  return [controlled ? (value as T) : local, set] as const;
}
