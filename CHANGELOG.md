# Changelog

All notable changes to agent-trace are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The section of a version is used as the release notes of its GitHub release.

## [Unreleased]

### Added

- **Ask mode** (`--mode ask`, `mode = "ask"` in `[proxy]` and `[hooks]`): a middle ground
  between observe and enforce. Calls denied by a session heuristic (a privileged call after
  untrusted content, an outbound destination that is not allowlisted) are put to a human
  instead of blocked. The Claude Code hook answers PreToolUse with
  `permissionDecision = "ask"` and records the decision as `ask`; a later PostToolUse shows
  that the call ran (`after_ask` on its execution), and nothing is recorded as approved
  otherwise. The MCP proxy asks through MCP elicitation (`elicitation/create`, a yes/no form)
  and forwards only an approved call; a declined, cancelled or unanswered question, an error
  and a client without elicitation support all deny the call (fail closed). The outcome is
  recorded as a second policy decision with `human_approval`. AT-004 does not report approved
  calls; AT-002 still reports them as executed and says that a human approved them. Canary
  tokens stay a hard denial in ask mode. `[proxy] ask_timeout_secs` (default 300) limits the
  wait.
- **Task profiles** (`[profiles.<name>] tools = [...]`, selected with `--profile NAME` on
  `proxy` and `hook` or `$AGENT_TRACE_PROFILE`): only the listed tools (`*` wildcards) are
  allowed. Other tools are denied in enforce and ask mode (never asked about) and recorded as
  `would_deny` in observe mode; the proxy also hides them from `tools/list`. An unknown profile
  name is an error. The active profile is recorded in the proxy's connection event, the hook
  session's metadata and each decision.
- `PolicyOutcome` has a `class` (`hard` or `askable`) that says whether a denial may be put to
  a human; it is serialized only for askable denials, so existing JSON is unchanged.

- **Rug-pull protection for MCP servers** (`agent-trace pins list|show|reset`, `[proxy]
  pin_tools`, on by default): the proxy pins every tool definition a server announces the first
  time (SHA-256 over the canonical JSON of name, title, description, schemas and annotations)
  in `<data dir>/pins/<name>.json`, and compares every complete `tools/list` and the tools before
  the first call of a connection with the pins. New rule **AT-008** reports a changed definition
  (high) or a tool added later (low); the change event keeps the pinned and current
  descriptions and hashes. A changed tool is never re-pinned automatically: in enforce mode it
  is hidden from `tools/list` and its calls are denied until `pins reset` accepts the reviewed
  change.
- **Canary tokens** (`[[canaries]]` in `agent-trace.toml`, `agent-trace canary new|list`): decoy
  secrets whose use in a tool call is evidence of a leak attempt. Values are matched on the
  original content (as written and percent-encoded) before redaction, stored traces keep only
  the canary's name, and the value is replaced with `[REDACTED:canary]` everywhere. New rule
  **AT-007** reports tool calls that carry a canary (critical, or high when blocked) with the
  path from where it entered the trace. The policy gate of the proxy and the hooks denies such
  calls in enforce mode, whatever the tool. Values can come from an environment variable, so
  the canary list need not sit in a file the agent can read. `canary new` prints realistic
  decoys (AWS key ID, GitHub token, hex key, password). See docs/canaries.md.
- **Graph:** clicking an event opens an info card next to it: agent, origin, trust, tool state
  and redactions at a glance, timing (since start, since the previous event and since its
  cause), a payload summary, the findings it is evidence for, how many events lie up- and
  downstream and which lower-trust events influenced it, with buttons to focus the chain, open
  the full details and copy the payload. The side panel adds the lane, the payload size, the
  upstream chain and the findings; findings show their remediation and evidence events.
  Events that are evidence for a finding carry a severity dot, and ←/→ step through the events.

## [1.5.0] - 2026-11-17

Findings in GitHub Code Scanning, exports that prove they are unchanged, control over what is
kept and redacted, your own detection rules, and traces from any agent framework that speaks
OpenTelemetry.

**Upgrade notes:**

- JSONL exports end with a new `integrity` record. `import` of older versions of agent-trace
  rejects such files as an unknown record type; remove the last line to import them there.
- `import` rejects an exported file that was changed after export. Files without an integrity
  record (hand-written traces) are accepted as before.
- An `agent-trace.toml` that cannot be loaded (unknown keys, invalid pattern or rule), or a
  `--config` / `AGENT_TRACE_CONFIG` file that does not exist, is now an error for every command,
  because configured redaction must not be skipped silently.
- `Rule::id` and `Rule::title` return `&str` instead of `&'static str` (as does the new
  `Rule::description`). Implementations that return string literals compile unchanged.

### Added

- `agent-trace sarif FILE... [--output PATH] [--fail-on SEVERITY]`: convert JSONL trace files into
  one SARIF 2.1.0 file for GitHub Code Scanning (`github/codeql-action/upload-sarif`). Each finding
  is a result located at the line of its key event (the tool request) in the trace file, with the
  evidence path as a code flow and the evidence steps as related locations. Levels and
  `security-severity` follow the finding severity; fingerprints do not depend on trace or event
  IDs, so re-recorded behavior updates the same alert. Files are validated and re-redacted like
  `import`; nothing is stored.
- `export --format sarif [--artifact-uri URI]` for a stored trace.
- `Rule::description` and `Rule::default_severity` (with defaults) for rule metadata; custom rules
  report their configured description and severity.
- Tamper evidence for exports: every JSONL export ends with an integrity record, a SHA-256 hash
  chain over all other lines with checkpoints. `import` and the new `agent-trace verify FILE`
  reject a file that was changed, shortened, reordered or extended after export.
- Signed exports: `agent-trace keys generate|show` creates an Ed25519 key (PKCS#8, mode 0600,
  never overwritten), `export --format jsonl --sign [--key PATH]` signs the chain head, and
  `verify` accepts the signature only for a trusted key (`--public-key HEX|FILE`, or your own
  key); `--require-signature` rejects unsigned files.
- Library: `agent_trace_storage::{integrity, write_jsonl_signed, SigningKey}`;
  `Imported::integrity`.
- `agent-trace prune [--older-than AGE] [--keep N] [--dry-run]` and `[retention]`
  (`max_age_days`, `max_traces`): delete old traces with their events, findings and evidence
  links; traces still being recorded are kept. On SQLite, deleted content is overwritten
  (`secure_delete`) and the write-ahead log truncated. `Store::delete_trace`, `Store::compact`.
- `[redaction]`: additional secret patterns (with an optional `value` capture group) and field
  names, applied to everything the process stores, exports, logs and prints.
  `agent_trace_core::redact::{RedactionConfig, configure}`.
- Declarative rules (`[[rules]]`): tool-call rules (tool globs, argument regexes, optional
  `after_untrusted` provenance like AT-002, attempt status from the recorded lifecycle) and
  content rules (regex on lower-trust content). They run wherever traces are analyzed.
  `Analyzer::with_rule` and `agent_trace_core::rules::CustomRule` for Rust users.
- `docs/configuration.md` (the whole `agent-trace.toml`) and `docs/rules.md` (writing rules).
- `agent-trace import --format otlp`: import OpenTelemetry traces (OTLP/JSON, one request per file
  or per line as the Collector's `file` exporter writes) and map the GenAI semantic conventions
  onto events (mapping `otel-genai/1`): agent spans with delegation and reports, model calls with
  the user prompt, tool calls (including MCP `tools/call`) with lower-trust results. Links come
  only from the data: tool call IDs in input and output messages, and span structure (a tool that
  runs an agent gets that agent's report as the cause of its result). Every OTel trace becomes
  one trace; re-importing skips traces already imported. A note says when no message content was
  captured. See `docs/otlp.md` and `examples/otlp/agent-injection.otlp.jsonl`.
- Library: `agent_trace_storage::otlp::read_otlp`.

## [1.4.0] - 2026-11-17

Record whole Claude Code sessions, follow an attack across several MCP servers, look at it as a
graph, and check whether a new model or prompt would still fall for it.

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

- **Claude Code hooks** (`agent-trace hook`): registered for SessionStart, UserPromptSubmit,
  PreToolUse, PostToolUse, PostToolUseFailure, SubagentStart, SubagentStop, Stop and SessionEnd,
  it records a whole session as one live trace, built-in tools and MCP tools alike, with
  subagents as separate agents. In enforce mode it denies a privileged tool call after untrusted
  content reached the acting agent, also through a subagent's report (AT-006).
  `agent-trace hook --print-settings` prints the block for Claude Code's settings. A `[hooks]`
  table in `agent-trace.toml` sets the mode, the taint sources (default WebFetch, WebSearch and
  MCP tools) and `on_error` (fail open by default, or deny tool calls while recording fails).
  See `docs/claude-code-hooks.md`.
- **Remote MCP servers** (`agent-trace proxy --url URL`): proxy servers over streamable HTTP.
  https only (plain http for loopback), bearer token and headers from environment variables
  (`--bearer-token-env`, `--header-env NAME=VAR`), same-origin redirects only. New crate
  `agent-trace-net`.
- **One trace across MCP servers:** all proxies an MCP client starts share a trace (key: the
  client process and its start time on Linux and macOS, or `--session KEY` /
  `AGENT_TRACE_SESSION`). Untrusted content from one server counts against privileged calls to
  every other server, and denials name the source, e.g. `issues:get_issue`.
- **Causal graph** (`agent-trace graph <trace-id>|--latest [--output PATH]`): the trace as one
  self-contained HTML file. Lanes per agent and per MCP server, cause / context / structure
  edges, a finding's evidence path, an event's ancestors and descendants, payload and links of
  an event, pan, zoom and search. The page contains the redacted evidence report, makes no
  network requests (no CDN, no server), and its Content-Security-Policy allows only its own
  script and style by hash; trace content is inserted as text only.
- **Replay and model regression suites** (`agent-trace replay trace <trace>|--latest|--input
  FILE`, `agent-trace replay suite FILE`): run a model, or a new system prompt
  (`--system-prompt`), against a recorded session. The recorded task and tool results are
  served by an in-process MCP server; only the model is live, and nothing is executed. Replays
  are stored as traces (`replay/<name>`, `replay_of`), compared with the recording rule by rule,
  and fail when a model action (`attempted`, `blocked`, `executed`) reaches the threshold. Suites
  (TOML) set recordings, prompts, thresholds and repeat counts per case; `--report` writes JSON;
  exit code 2 for CI. See `docs/replay.md`.

### Changed

- The network guard test checks `agent-trace-mcp` by its sources and manifest instead of
  `Cargo.lock`, because `agent-trace-net` enables rmcp's HTTP client for the whole workspace.
  `agent-trace-core` and `agent-trace-storage` must still reach no HTTP client.

### Library

- Shared traces written by several processes: `TraceAccess`, `MemoryTrace`,
  `agent_trace_storage::SharedTrace`; `TraceRecorder::with_trace_id`, `TraceRecorder::resume`,
  `TraceRecorder::set_status`.
- `ToolPolicy::evaluate_in_session` and `agent_trace_mcp::apply_mode` (the decision shared by
  the proxy and the hooks); `McpSession::from_service`.
- `Proxy::new` takes an `Arc<dyn TraceAccess>`; `Proxy::finish` and `serve_stdio` no longer
  return the trace; `McpSession::record_result` takes extra result metadata.
- Replay: `LlmRunOptions::system_prompt`, `agent_trace_llm::{replay_trace, compare, verdict}`,
  `agent_trace_mcp::{ReplayFixture, ReplayServer}`.

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

[Unreleased]: https://github.com/phr4nky/agent-trace/compare/v1.5.0...HEAD
[1.5.0]: https://github.com/phr4nky/agent-trace/compare/v1.4.0...v1.5.0
[1.4.0]: https://github.com/phr4nky/agent-trace/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/phr4nky/agent-trace/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/phr4nky/agent-trace/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/phr4nky/agent-trace/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/phr4nky/agent-trace/releases/tag/v1.0.0
