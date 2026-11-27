import { Resource, Signal, linkedSignal } from '@angular/core';

/**
 * The value of `resource`, or `empty` while it has none.
 *
 * A failed reload keeps the previous value as long as `key` (for example the ID the request is
 * made for) is unchanged, so a brief server outage does not empty a live view; the error is still
 * reported by `resource.error()`. A new key starts again from `empty`.
 */
export function lastValue<T>(
  resource: Resource<T | undefined>,
  empty: T,
  key: () => unknown = () => null,
): Signal<T> {
  return linkedSignal<{ key: unknown; value: T | undefined }, T>({
    source: () => ({ key: key(), value: resource.hasValue() ? resource.value() : undefined }),
    computation: (current, previous) => {
      if (current.value !== undefined) {
        return current.value;
      }
      const sameKey = previous !== undefined && Object.is(previous.source.key, current.key);
      return sameKey && resource.status() === 'error' ? previous.value : empty;
    },
  }).asReadonly();
}
