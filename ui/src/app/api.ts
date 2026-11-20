import { HttpClient } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';

/** A recorder that sends traces to the server (`GET /api/v1/sources`). */
export interface SourceSummary {
  source_id: string;
  name: string;
  created_at: string;
  last_seen_at: string | null;
  last_ip: string | null;
  traces: number;
}

/** One trace of a source (`GET /api/v1/traces?source=ID`). */
export interface TraceRow {
  trace_id: string;
  name: string;
  status: string;
  created_at: string;
  execution_mode: string;
  events: number;
  findings: number;
  max_severity: string | null;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** Only well-formed trace IDs become URLs (the graph frame's address is built from it). */
export function isTraceId(id: string): boolean {
  return UUID.test(id);
}

/** The read API of agent-trace-server (same origin). */
@Injectable({ providedIn: 'root' })
export class TraceApi {
  private readonly http = inject(HttpClient);

  sources(): Observable<SourceSummary[]> {
    return this.http.get<SourceSummary[]>('/api/v1/sources');
  }

  traces(sourceId: string): Observable<TraceRow[]> {
    return this.http.get<TraceRow[]>('/api/v1/traces', { params: { source: sourceId } });
  }

  /** Address of the causal graph page of a trace (shown in a sandboxed frame). */
  graphPath(trace: TraceRow): string | null {
    if (!isTraceId(trace.trace_id)) {
      return null;
    }
    // The event count is part of the address, so a growing trace is drawn again.
    return `/api/v1/traces/${trace.trace_id}/graph?v=${trace.events}`;
  }
}
