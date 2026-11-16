# Architecture

```text
                        +--------------------------+
                        |   agent-trace CLI        |
                        |  clap / ratatui          |
                        +------------+-------------+
                                     |
                 +-------------------+-------------------+
                 |                                       |
         +-------v---------+                     +-------v--------+
         | agent-trace-mcp |                     | Trace explorer |
         | scripted agent  |                     | queries / TUI  |
         | rmcp stdio      |                     +-------+--------+
         +-------+---------+                             |
                 |                                       |
         +-------v---------------------------------------v-------+
         |                agent-trace-core                       |
         | recorder (ids, sequence, redaction) · provenance      |
         | validation · policy · rules AT-001…AT-005             |
         +--------------------------+----------------------------+
                                    |
                         +----------v-----------+
                         | agent-trace-storage  |
                         | SQLite + JSONL/JSON  |
                         +----------------------+
```

## Crates

| Crate | Responsibility | Must not depend on |
|---|---|---|
| `agent-trace-core` | Event/trace/finding model, `TraceRecorder`, `Redactor`, provenance index, validation, `ToolPolicy`, rules | `rmcp`, `ratatui`, storage, vendors |
| `agent-trace-storage` | SQLite schema + migrations, JSONL import/export, JSON evidence report | `rmcp`, `ratatui` |
| `agent-trace-mcp` | `McpSession` adapter (rmcp client over child-process stdio or in-process), `LabServer`, scripted (multi-)agent, shared policy gate | `ratatui`, any HTTP client |
| `agent-trace-llm` | Anthropic Messages / OpenAI Chat Completions clients (reqwest + rustls), LLM agent loop with delegation | `ratatui` |
| `agent-trace-cli` | `agent-trace` binary, commands, ratatui explorer, redacting log writer | — |

## Data flow of a lab run

1. The CLI starts itself as `agent-trace lab-server --documents …` (child process, stdio).
2. `McpSession::connect` performs the MCP `initialize` handshake and `tools/list`.
3. The scripted agent records `agent_started`, `user_prompt_received` and simulated `agent_decision`s.
4. Each tool use creates `tool_call_requested` and then a `tool_policy_decision`. If the call is allowed,
   the adapter records `tool_call_executed`, then sends the real `tools/call`, then records
   `tool_result_received` (origin `mcp_tool`, `lower_trust`) and `tool_call_completed`/`failed`.
5. The recorder redacts every payload and metadata map before storing the event.
6. The trace is stored in SQLite, analyzed (`Analyzer`), and exported as JSONL + JSON report.

## Live recording

`TraceRecorder::with_sink` hands every (already redacted) event to a sink the moment it is recorded.
The CLI's sink is `agent-trace-storage::LiveWriter`: a dedicated thread that owns the `Store`,
creates the trace (`status = running`), appends each event, re-runs the rules after every event,
and finally updates the header (`completed` / `aborted`). The thread keeps blocking database drivers
away from the async agent code. `explore --follow` polls the store and refreshes the view.

## LLM agents

`agent-trace-llm` converts a provider-neutral message model to the Anthropic and OpenAI wire formats.
The agent loop records `model_request` / `model_response` per turn and routes every tool call through
the same `gated_tool_call` as the scripted agent (policy first, then MCP). In multi-agent scenarios the
orchestrator gets a `delegate_to_<agent>` tool. Calling it runs a second agent loop, and its report flows
back through `begin_delegation` / `end_delegation`, which also implement the taint propagation.
Tests use a local fake HTTP provider and an in-process MCP transport.

## Causality

- `parent_event_id`: structural parent. Lifecycle events of a tool call (`policy_decision`, `executed`,
  `result_received`, `completed`/`failed`) have the request as parent.
- `caused_by_event_id`: the event that directly caused this one, e.g. decision ← tool result.
- `context_event_ids`: further explicit causes, e.g. everything in a model's context window.
- Rules search the shortest path over cause and context links (breadth first) to the nearest matching source.
- Rules only follow these explicit links. The analyzer never infers a cause from ordering or time.

## Determinism

`TraceRecorder::deterministic(seed)` derives UUID v5 identifiers and fixed timestamps.
Finding IDs are always UUID v5 of (trace, rule, rule version, evidence). Re-analysis is idempotent,
and storage keeps the original `created_at` of findings it already has.

## Storage backends

`agent-trace-storage` writes its logic once against a small `Backend` trait (`execute` / `query`
with `?` placeholders and three value types). Each database only adds driver glue and dialect details:

| Backend | Driver | Dialect specifics |
|---|---|---|
| SQLite (default) | `rusqlite` (bundled) | WAL, `foreign_keys=ON`, private file permissions |
| PostgreSQL | `postgres` + `tokio-postgres-rustls` | `$n` placeholders, identity column, `sslmode=require` default for remote hosts |
| MySQL / MariaDB | `mysql` (rustls) | `LONGTEXT`, InnoDB/utf8mb4, `STRICT_ALL_TABLES`, `ssl-mode` URL parameter |

TLS uses rustls with the `ring` provider and Mozilla roots for both server drivers (no OpenSSL).
Traces and events keep their complete JSON body, so indexed columns can be bounded (e.g. names ≤ 255 chars)
without losing data. MySQL/MariaDB commit DDL implicitly, so a failed migration there can be partial.
`tests/backend_conformance.rs` runs the same checks against every backend.

## Implementation notes (deviations from the original plan)

- **Version:** the first release is v1.0.0.
- **Integration tests** live in each crate's `tests/` directory. The workspace root is a virtual manifest and has no top-level `tests/`.
- **MCP server location:** the lab server lives in `agent-trace-mcp` (`server.rs`, binary `agent-trace-lab-server`).
  The CLI starts itself as the server (hidden `lab-server` subcommand), so `cargo run -p agent-trace-cli` is enough.
- **Additional fixture** `examples/local-lab/documents/exfil-readme.md` holds the exfil scenario's fake secret.
- **Exfil scenario findings** are `AT-001`, `AT-002`, `AT-003`, `AT-004`. `AT-002` fires too: the blocked webhook request is a privileged request caused by lower-trust content.
- **Policy gate:** policy is enforced client-side before dispatch, so a blocked call never reaches the MCP server. `send_webhook_mock` also enforces the allowlist server-side as a second layer.
- **`export` without `--output`** writes to stdout. **`explore --snapshot`** renders the explorer without a TTY.
- **Storage:** besides SQLite, PostgreSQL and MySQL/MariaDB are supported via `--database-url`.
- **Beyond the plan's v1 scope, also in v1.0.0:** real LLM providers (Anthropic, OpenAI-compatible), multi-agent
  traces with rule AT-006, schema 1.1 (agent IDs, context links, trace status), and live recording with `explore --follow`.
- **Rule versions:** AT-002 and AT-003 are version 2 (they follow context links).
- **Versions:** `rmcp` 3.10 (MCP protocol 2025-11-25 negotiated), `ratatui` 0.30, Rust edition 2024. All pinned in `Cargo.lock`.
- **License:** MIT.
