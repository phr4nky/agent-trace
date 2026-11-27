/** A recorder that sends traces to the server (`GET /api/v1/sources`). */
export type SourceSummary = {
  readonly source_id: string;
  readonly name: string;
  readonly created_at: string;
  readonly last_seen_at: string | null;
  readonly last_ip: string | null;
  readonly traces: number;
};
