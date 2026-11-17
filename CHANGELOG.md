# Changelog

All notable changes to agent-trace are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The section of a version is used as the release notes of its GitHub release.

## [Unreleased]

**Upgrade notes:**

- Proxies now write one trace per MCP client session, named `proxy-session/<id>`, instead of one
  trace per proxy named `proxy/<name>`. Use `--no-session` for the previous behavior. The proxy
  mode and policy are recorded per connection (`mcp-server-connected` event), no longer in the
  trace metadata.
- A proxy in enforce mode now denies tool calls when it cannot read the session from the store.
- `Bash`, `PowerShell`, `Write`, `Edit`, `MultiEdit` and `NotebookEdit` are now privileged
  tools in the default policy. Imported traces of Claude Code sessions can report AT-002 and
  AT-006 findings where they did not before.

### Added

- `agent-trace proxy --url URL`: proxy remote MCP servers over streamable HTTP. https only
  (plain http for loopback), bearer token and headers from environment variables
  (`--bearer-token-env`, `--header-env NAME=VAR`), same-origin redirects only. New crate
  `agent-trace-net`.
- One trace across servers: all proxies an MCP client starts share a trace (key: the client
  process and its start time on Linux and macOS, or `--session KEY` / `AGENT_TRACE_SESSION`).
  Untrusted content from one server counts against privileged calls to every other server, and
  denials name the source, e.g. `issues:get_issue`.
- Library: `TraceAccess`, `MemoryTrace` and `agent_trace_storage::SharedTrace` for traces written
  by several processes; `McpSession::from_service`. `Proxy::new` takes an
  `Arc<dyn TraceAccess>`, `Proxy::finish` and `serve_stdio` no longer return the trace, and
  `McpSession::record_result` takes extra result metadata.
- `agent-trace hook`: Claude Code hooks adapter. Registered for SessionStart, UserPromptSubmit,
  PreToolUse, PostToolUse, PostToolUseFailure, SubagentStart, SubagentStop, Stop and SessionEnd,
  it records a whole session as one live trace, built-in tools and MCP tools alike, with
  subagents as separate agents. In enforce mode it denies a privileged tool call after untrusted
  content reached the acting agent, also through a subagent's report (AT-006).
  `agent-trace hook --print-settings` prints the block for Claude Code's settings. See
  `docs/claude-code-hooks.md`.
- `[hooks]` table in `agent-trace.toml`: mode, taint sources (default WebFetch, WebSearch and
  MCP tools) and `on_error` (fail open by default, or deny tool calls while recording fails).
- The network guard test checks `agent-trace-mcp` by its sources and manifest instead of
  `Cargo.lock`, because `agent-trace-net` enables rmcp's HTTP client for the whole workspace.
  `agent-trace-core` and `agent-trace-storage` must still reach no HTTP client.
- Library: `TraceRecorder::with_trace_id`, `TraceRecorder::resume`,
  `TraceRecorder::set_status`, `ToolPolicy::evaluate_in_session`, `agent_trace_mcp::apply_mode`.

## [1.3.0] - 2026-11-17

Record and protect the agents you already use: an MCP proxy for Claude Code, Cursor, Claude
Desktop and any other MCP client, and a configuration file for the policy.

**Upgrade notes:**

- AT-002 moves to rule version 4 and AT-006 to version 3, so their finding IDs change.
- `analyze`, `import`, `export`, `explore` and `demo run` now read `agent-trace.toml` from the
  working directory or the data directory if one exists. Pass `--config` in CI to pin it.

### Added

- `agent-trace proxy -- <server command>`: an MCP proxy for stdio servers. Put it in the MCP
  configuration of Claude Code, Cursor, Claude Desktop or any other client. It records every tool
  call with the same lifecycle as the lab, records `tools/list`, `resources/read` and
  `prompts/get` answers as lower-trust content, runs the rules live and, with `--mode enforce`,
  answers denied calls with a tool error instead of forwarding them. See `docs/proxy.md`.
- `agent-trace.toml` and the global `--config` option (also `AGENT_TRACE_CONFIG`): additional
  privileged and outbound tools, destination allowlist entries, proxy mode, taint sources and
  call timeout.
- Tool names in the policy may use `*` wildcards; allowlist entries `*.example.com` allow
  subdomains.
- Library: `McpSession::connect_upstream`, `call_tool_raw`, `record_executed`, `record_result`,
  `McpSession::connect_in_process` for any server handler, `record_gate`,
  `LiveWriter::spawn_with`, `ToolPolicy::with_config`.

### Changed

- AT-002 and AT-006 report findings whose link is session context recorded by the proxy with
  medium confidence and say so in the description.

### Fixed

- The AT-004 text for a denied action that was executed anyway contained runs of spaces.

## [1.2.0] - 2026-11-17

Fixes from a multi-agent bug hunt on v1.1.0.

**Upgrade notes:**

- The outbound allowlist is stricter again. A CI gate that passed with v1.1.0 can report AT-003 for
  the same traces when a destination used a slashless URL, a recipient list or a `cc`/`bcc` field.
- AT-004 moves to rule version 2, so its finding IDs change.
- Usage errors (for example `--fail-on High`) now exit with code 1 instead of 2. Exit code 2 now
  always means findings.

### Added

- `McpSession::with_call_timeout` for library users. A `tools/call` without an answer now fails
  after 300 s by default and is recorded as a failed tool call, instead of hanging.

### Changed

- AT-004 (policy denial) reports `executed` with high severity when the trace records an execution
  of the denied request (an audit-only or fail-open gate). Before, it always said "not executed".
- Rejected imports report the line number for every structural error (duplicate id, sequence,
  links, schema version), as the README promises.

### Fixed

- **Outbound allowlist bypasses** (policy gate and AT-003):
  - URLs without slashes after the scheme (`http:evil.example/?r=://localhost`) were judged by
    the later `://`. URLs are now parsed exactly like HTTP clients (WHATWG, the `url` crate).
  - In a recipient list (`attacker@evil.example,ops@localhost`) only the last address was checked.
    Now every address is.
  - `cc`, `bcc`, `reply_to`, differently cased keys and `*_url`/`*_uri`/`*_endpoint` arguments
    were not checked.
- **Import:**
  - Secrets only in event metadata did not mark the event as sensitive, so AT-003 was missed.
  - Memory was about 30 times the file size. Events are now redacted while reading, and an
    import holds at most 10 million JSON values.
  - Many keys that redact to the same text made import quadratic: one crafted line took minutes.
  - Export and re-import truncated already truncated text again and lost the original byte
    count.
  - Error messages no longer repeat their cause.
- **Storage:**
  - Opening a SQLite database no longer changes the permissions of an existing directory.
    `sqlite:./traces.db` locked other users out of the project directory, and `/tmp` failed.
  - Several commands opening a new SQLite database at the same time no longer fail with
    "database is locked" or "table already exists".
  - On PostgreSQL and MySQL, re-analysing a trace while it is recorded live can no longer
    collide.
  - A PostgreSQL server on localhost with a self-signed certificate (the Debian/Ubuntu default)
    works without `sslmode=disable`. Connection errors show their cause.
  - Export files can no longer be redirected by a symlink created between the check and the
    write.
- **MCP and agents:**
  - Tool result text with duplicated JSON keys could carry instructions the model saw but the
    trace did not. The full text is now recorded.
  - Tool calls with non-object input skipped the policy gate and the trace.
- **CLI:**
  - Piping output into `head` no longer crashes with exit code 101.
  - `demo run` no longer loses already recorded traces when a scenario file is broken or the
    database fails during the run. On a database failure the traces are saved as JSONL.

## [1.1.0] - 2026-11-17

Security fixes from the review of v1.0.0.

**Upgrade note:** detection is stricter. A CI gate that passed with v1.0.0 can report findings
with v1.1.0 for the same traces. That is intended: those traces contained something v1.0.0 missed.

### Added

- `agent-trace import --fail-on <level>`: exit code 2 when a finding of the imported trace reaches
  the threshold. The verdict comes from the validated import itself, not from a later read of the
  database. The CI examples (`examples/ci/agent-trace-gate.sh`, `Jenkinsfile`, README) use it.
- `agent-trace demo run --fail-on <level>`, with the same exit code contract.
- `SHA256SUMS` for the release archives.

### Security

- **Detection blind spots closed.**
  - Content rules scan a payload before it is truncated, so instructions placed past the
    truncation limit are still detected.
  - Object keys are scanned as content, not only values.
  - For MCP tool results, the text content the model receives is always recorded next to the
    structured content. A server could otherwise hide instructions in the text while the trace
    showed only harmless structured data.
- **Outbound allowlist:** hosts are parsed as WHATWG URL parsing does, so the policy agrees with
  what HTTP clients connect to. Every destination-like argument of an outbound tool is checked, and
  ambiguous authorities (whitespace, control characters) are denied.
- **Database TLS default:** whether TLS is required is decided from the host the driver actually
  connects to. A `?host=` parameter can no longer switch TLS off for a remote server, and every
  loopback address (`127.0.0.0/8`, `[::1]`) is recognized.
- **Redaction gaps:**
  - URL passwords containing `@` are covered completely.
  - Quoted key/value secrets are covered.
  - Secret key names are matched by segment (`db_password`, `githubToken`, `x-auth-token`).
  - Tokens used as object keys are redacted.
  - Text that only looks like a redaction placeholder is no longer trusted.
- **LLM client:**
  - Redirects are never followed, so the API key is not replayed to another host.
  - Keys are sent only over `https://`, or plain http to a loopback host.
  - Provider responses are limited to 16 MiB.
- **Terminal output:** control characters in trace names, findings and error messages are escaped
  before printing.
- **Robustness:**
  - Analysis runs in linear time.
  - Imports are limited to 512 MiB in total.
  - NUL characters in name columns are handled.
  - Lab documents are read with bounded, race-free size checks.
- **Multi-agent lab:** a sub-agent can only call the tools of its role.
- **Exported files** are created readable by the owner only.
- **Release workflow:** read-only token by default; only the job that publishes the release can
  write.

## [1.0.0] - 2026-11-16

First release.

- Event, trace and finding model (schema 1.1, schema 1.0 still readable) with explicit causal
  links, recorder, validation and redaction before anything is stored or printed.
- Rules AT-001 to AT-006: prompt-injection indicators, trust-boundary crossings, exfiltration,
  policy denials, authority spoofing and cross-agent taint.
- Storage in SQLite (default), PostgreSQL, MariaDB and MySQL, with automatic migrations.
- Live recording and `explore --follow`.
- MCP lab server with four scenarios, including a multi-agent handoff.
- Optional real models: Anthropic, OpenAI and OpenAI-compatible servers.
- CLI commands `demo`, `trace`, `analyze --fail-on`, `explore`, `export` and `import`.
- CI examples for GitHub Actions, GitLab CI and Jenkins.

[Unreleased]: https://github.com/phr4nky/agent-trace/compare/v1.3.0...HEAD
[1.3.0]: https://github.com/phr4nky/agent-trace/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/phr4nky/agent-trace/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/phr4nky/agent-trace/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/phr4nky/agent-trace/releases/tag/v1.0.0
