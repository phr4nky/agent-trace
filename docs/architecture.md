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
         | lab · proxy     |                     | queries / TUI  |
         | rmcp stdio      |                     +-------+--------+
         +-------+---------+                             |
                 |                                       |
         +-------v---------------------------------------v-------+
         |                agent-trace-core                       |
         | recorder (ids, sequence, redaction) · provenance      |
         | validation · policy · rules AT-001…AT-006             |
         +--------------------------+----------------------------+
                                    |
                         +----------v-----------+
                         | agent-trace-storage  |
                         | SQL backends, JSONL  |
                         +----------------------+
```

## Crates

| Crate | Responsibility | Must not depend on |
|---|---|---|
| `agent-trace-core` | Event/trace/finding model, `TraceRecorder`, `Redactor`, provenance index, validation, `ToolPolicy`, rules | `rmcp`, `ratatui`, storage, vendors |
| `agent-trace-storage` | SQLite, PostgreSQL and MySQL/MariaDB backends with migrations, `LiveWriter`, JSONL import/export, JSON evidence report | `rmcp`, `ratatui` |
| `agent-trace-mcp` | `McpSession` adapter (rmcp client over child-process stdio or in-process), `LabServer`, scripted (multi-)agent, shared policy gate, MCP `Proxy` | `ratatui`, any HTTP client |
| `agent-trace-llm` | Anthropic Messages / OpenAI Chat Completions clients (reqwest + rustls), LLM agent loop with delegation | `ratatui` |
| `agent-trace-net` | MCP streamable HTTP upstream for the proxy (rmcp's reqwest client + rustls/ring), URL and credential rules | `ratatui`; must not be a dependency of `agent-trace-mcp` |
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

## Data flow of a proxied session

1. An MCP client starts `agent-trace proxy -- <server command>` as its server.
2. The proxy starts the upstream server (`McpSession::connect_upstream`, environment unchanged)
   and then answers the client's `initialize` with the upstream's name, version and instructions,
   announcing only tools, resources and prompts.
3. `tools/list`, `resources/read` and `prompts/get` answers are forwarded and recorded as
   `external_content_observed` (`lower_trust`).
4. `tools/call` is recorded with the lab's lifecycle (`record_gate`, `McpSession::record_executed`,
   `McpSession::record_result`). The request lists earlier untrusted results as
   `context_event_ids` with `link_basis = session_context`; there is no `caused_by` link, because
   the proxy cannot see the model's context. In `enforce` mode a denied call is answered with a
   tool error and never forwarded.
5. Events stream to `LiveWriter`, which runs the rules with the configured policy after each event.
6. The trace ends when the client disconnects or on Ctrl-C/SIGTERM.

The recorder lock is held only while recording, never across a call to the upstream server, so
concurrent tool calls from the client are not serialized. Details: [proxy.md](proxy.md).

## Causal graph (`agent-trace graph`)

`commands/graph.rs` fills `graph/template.html` with the redacted evidence report (the
`export --format json` content, escaped for a `<script>` data block), `graph/graph.css` and
`graph/graph.js`, and writes one HTML file. The viewer is plain JavaScript and SVG, no libraries:
events are placed left to right by sequence, in one lane per agent and one per MCP server (for
what the server returned); links are the recorded `caused_by_event_id`, `context_event_ids` and
`parent_event_id`. Highlighting walks the same links the rules follow. The CSP hashes of the
inline script and style are computed when the page is written.

## Shared traces (proxy sessions, hooks)

`agent-trace-core` defines `TraceAccess`: run a closure on a trace's recorder under the trace's
lock and persist what it recorded. `MemoryTrace` keeps a trace in memory (tests, embedders);
`agent-trace-storage::SharedTrace` keeps it in the store: each access takes a file lock, loads
the trace, resumes it with `TraceRecorder::resume`, appends the new events, updates the header
and re-runs the rules. The MCP proxies of one client session and the Claude Code hook processes
of one session use it, so separate processes write one gap-free trace.

The proxy reads its session state from the trace itself: untrusted content carries
`taint_source` metadata, the number of connected proxies is a trace metadata counter. Nothing
the decision needs lives only in one process.

`agent-trace-mcp` contains no networking code (checked by a test over its sources and manifest).
An HTTP upstream is connected by `agent-trace-net` and handed over as an `McpSession`
(`McpSession::from_service`).

## Data flow of a Claude Code session (hooks)

Claude Code starts `agent-trace hook` as a new process for every hook event, with the event as
JSON on stdin. The process:

1. derives the trace ID from `session_id` (UUID v5), takes a file lock for that session in
   `<data dir>/hooks/` (parallel tool calls run hooks concurrently),
2. loads the trace and continues it with `TraceRecorder::resume`, or starts it with
   `TraceRecorder::with_trace_id`,
3. maps the event (`hooks.rs`): PreToolUse uses `record_gate` and
   `ToolPolicy::evaluate_in_session`, the same decision as the proxy; PostToolUse finds its
   request by `tool_use_id`,
4. appends the new events, updates the header and re-runs the rules,
5. prints Claude Code's deny decision on stdout when a PreToolUse call is denied in enforce mode.

There is no long-running process: all state is in the trace. Details:
[claude-code-hooks.md](claude-code-hooks.md).

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
- **Rule versions:** see the rule table in the README; finding IDs include the rule version.
  Version 1.3 moved AT-002 to v4 and AT-006 to v3 (medium confidence on proxy session links).
- **Versions:** `rmcp` 3.10 (MCP protocol 2025-11-25 negotiated), `ratatui` 0.30, Rust edition 2024. All pinned in `Cargo.lock`.
- **License:** MIT.
