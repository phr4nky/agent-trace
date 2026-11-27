import { SourceSummary, TraceRow } from '../models';

/** Test data in the shape the server sends. */
export const SOURCE: SourceSummary = {
  source_id: '0b8e7c1e-6f1d-4d6e-9a43-2a1c7f1b3c4d',
  name: 'laptop',
  created_at: '2026-11-20T10:00:00Z',
  last_seen_at: '2026-11-20T10:05:00Z',
  last_ip: '127.0.0.1',
  traces: 1,
};

export const TRACE: TraceRow = {
  trace_id: '2fd80407-4c89-5f64-bc7e-93536e96e8ca',
  name: 'local-lab/exfil-attempt',
  status: 'completed',
  created_at: '2026-11-20T10:01:00Z',
  execution_mode: 'simulated',
  events: 13,
  findings: 4,
  max_severity: 'high',
};
