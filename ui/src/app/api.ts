import { httpResource, HttpResourceRef } from '@angular/common/http';
import { Signal } from '@angular/core';

import { SourceSummary, TraceRow } from './models';

// The read API of agent-trace-server (same origin). The resources must be created in an
// injection context, for example in a component's field initializers.

/** `GET /api/v1/sources`: every registered recorder. */
export function sourcesResource(): HttpResourceRef<SourceSummary[] | undefined> {
  return httpResource<SourceSummary[]>(() => '/api/v1/sources');
}

/** `GET /api/v1/traces?source=ID`: the traces of the chosen source; idle while none is chosen. */
export function tracesResource(
  sourceId: Signal<string | null>,
): HttpResourceRef<TraceRow[] | undefined> {
  return httpResource<TraceRow[]>(() => {
    const source = sourceId();
    return source ? { url: '/api/v1/traces', params: { source } } : undefined;
  });
}
