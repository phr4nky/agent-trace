import { TraceRow } from '../models';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** Only well-formed trace IDs become URLs (the graph frame's address is built from it). */
export function isTraceId(id: string): boolean {
  return UUID.test(id);
}

/** Address of the causal graph page of a trace (shown in a sandboxed frame). */
export function graphPath(trace: TraceRow): string | null {
  if (!isTraceId(trace.trace_id)) {
    return null;
  }
  // The event count is part of the address, so a growing trace is drawn again.
  return `/api/v1/traces/${trace.trace_id}/graph?v=${trace.events}`;
}
