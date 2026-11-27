import { Severity } from './severity';

/** State of a trace (`TraceStatus` in agent-trace-core). */
export type TraceStatus = 'running' | 'completed' | 'aborted';

/** Whether the tools of a trace ran for real (`ExecutionMode` in agent-trace-core). */
export type ExecutionMode = 'simulated' | 'live';

/** One trace of a source (`GET /api/v1/traces?source=ID`). */
export type TraceRow = {
  readonly trace_id: string;
  readonly name: string;
  readonly status: TraceStatus;
  readonly created_at: string;
  readonly execution_mode: ExecutionMode;
  readonly events: number;
  readonly findings: number;
  /** Highest severity of the trace's findings; `null` when it has none. */
  readonly max_severity: Severity | null;
};
