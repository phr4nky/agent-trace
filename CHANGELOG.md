# Changelog

All notable changes to agent-trace are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The section of a version is used as the release notes of its GitHub release.

## [Unreleased]

### Fixed

- Team UI: a node picked in the causal graph jumped back to the first node within a few seconds.
  The four-second refresh rebuilt the graph frame's address as a new object each time, so the
  frame was reloaded even when the trace had not changed. It is now reloaded only when its
  address changes, that is when a running trace has new events.

## [1.6.0] - 2026-11-20

A team server with a web UI that collects the traces of many machines and shows each with its
causal graph. Decoy secrets that turn a leak into proof, MCP tools that cannot change behind your
back, a human in the loop instead of a hard block, tools scoped to the task, known attacks as a
regression suite, and findings that fit your security process: OWASP and MITRE ATLAS tags, SIEM
exports and an evidence report for record-keeping.

### Added

- **Team server and web UI** (`agent-trace-server`, `ui/`, `docker-compose.yml`): collects the
  traces of many recorders in one database and shows them in a web UI (Angular 22 + SwipyUI):
  choose a source, pick one of its traces, and its causal graph opens next to the list (the page
  of `agent-trace graph`, in a frame with `sandbox="allow-scripts"`); the view refreshes every
  four seconds. Sources are registered with `agent-trace-server source add NAME`, which prints a
  random token once (`ats_…`, stored as SHA-256). `POST /api/v1/ingest` checks every batch like
  an import (sequence, schema, causal links), redacts again, computes the findings on the server
  and records the source's last contact and address; a trace belongs to the source that sent it
  first. Read API: `GET /api/v1/sources`, `/api/v1/traces?source=ID`, `/api/v1/traces/{id}`,
  `/api/v1/traces/{id}/graph`, `/api/v1/whoami`, `/api/v1/health`. `--config` takes `[policy]`,
  `[[rules]]` and `[redaction]` from an `agent-trace.toml`. Reads have no login yet: `serve`
  listens on loopback unless `--allow-unauthenticated-reads` is given, and the compose file
  publishes the port on loopback only. The UI is served with a strict Content-Security-Policy
  (`script-src 'self'`). See docs/server.md.
- **`agent-trace ship`** (`--to URL`, `--follow`, `[ship]` in `agent-trace.toml`): sends recorded
  traces to agent-trace-server after the fact (store and forward), so recording and decisions
  never wait for the network. The token comes from `$AGENT_TRACE_SHIP_TOKEN` and is checked
  first; https only (plain http to loopback), no redirects. `<data dir>/ship/` remembers per
  trace the last event and status the server confirmed; a trace is sent again when it grows or
  its status changes, and a server with another state says where to continue.
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
- **Attack library** (`examples/attack-library`): recordings of four published agent attacks,
  shipped as a `replay` suite, to check a model or prompt change against known attacks: the
  GitHub MCP issue injection (Invariant Labs), the Supabase MCP support-ticket exfiltration
  (General Analysis, with a canary in the token table), tool poisoning (Invariant Labs) and an
  EchoLeak-style injection through a retrieved email (CVE-2025-32711). Each recording is a
  reconstruction with fake data, generated from a scenario file. The library's
  `agent-trace.toml` adds the GitHub write tools to the privileged tools, rules `ATLIB-001`…`005`
  for the attack actions and the canary. Model-free tests check that the recordings match their
  scenarios, import cleanly, produce the expected findings and that the suite runs. See
  examples/attack-library/README.md.
- **SIEM export** (`export --format ocsf|splunk-hec|elastic`): findings as OCSF 1.9.0 Detection
  Findings (class 2004) with severity, confidence, attempt status, rule, remediation, related
  evidence events and observables (tool names, destination hosts), one per line.
  `--include-events` adds every recorded event: tool calls and policy decisions as API Activity
  (class 6003, policy outcome as `action_id`/`disposition_id`), all others as Base Events.
  `splunk-hec` writes events for the HTTP Event Collector (`sourcetype` `agent-trace:ocsf`),
  `elastic` an Elasticsearch `_bulk` body with ECS 9.5 fields (`event.kind` `alert` for
  findings) and the OCSF event under `ocsf`. Redacted like every export; nothing is sent over
  the network. See docs/siem.md.
- **Compliance evidence** (`agent-trace evidence`): an evidence report built from signed JSONL
  exports and/or stored traces, in Markdown or JSON (`report_version` 1). It shows what was
  recorded (per trace: time span, events, agents, MCP servers, tools, findings by severity and
  rule, redaction counts), by which configuration (SHA-256 of the canonical configuration, plus
  a summary with pattern labels and canary names only), how long traces are kept
  (`[retention]`, oldest and newest stored trace, a note below six months or without
  retention) and whether each file is unchanged and signed by a trusted key, checked like
  `verify`. Aimed at record-keeping duties such as Articles 12 and 26(6) of the EU AI Act; the
  report is explicitly not a compliance statement and lists what it does not prove. A file
  that fails verification is marked `FAILED` and the command exits with 1. Payloads are never
  included. `--output` creates a private file. See docs/compliance-evidence.md.
- **Taxonomy tags:** every built-in rule is mapped to the OWASP Top 10 for LLM Applications 2025
  (`LLM01:2025` …) and to MITRE ATLAS techniques (`AML.T0051.001` …), including AT-008 (MCP tool
  definition changed). Findings carry the tags in the JSON report and exports (`tags`, omitted
  when empty), in SARIF (`properties.tags` of rules and results, next to `security`, for
  filtering in GitHub Code Scanning), in the SIEM exports (OCSF `finding_info.types` after the
  rule ID and `unmapped.tags`, ECS `tags`), in `analyze` / `import` / `trace show`, in the explorer's
  finding details and on the graph's finding cards. Declarative rules accept an optional
  `tags = [...]`; Rust rules can override `Rule::tags`. Older reports and stored findings
  without tags still load; stored findings of built-in rules get their tags when loaded. The
  mapping and its reasoning are in docs/rules.md.
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

### Fixed

- Redaction missed credentials in command lines, so the Claude Code hook stored them in plain
  text with the Bash command: `curl -u user:password` (also `--user`, `-U`, `--proxy-user`),
  `mysql -pPASSWORD` (mysql, mysqldump, mysqladmin, mysqlimport, mariadb), `docker login -p`
  (also podman, nerdctl, buildah), `--password`/`--passwd`/`--pass VALUE`, `sshpass -p`, and
  `Cookie:`/`Set-Cookie:` headers and `curl -b`/`--cookie name=value`. They are now replaced
  with `[REDACTED:cli_credentials]` and `[REDACTED:cookie]`; the user name stays. Flags that
  only look alike (`-p` as a port or for `mkdir`, `-u 1000:1000`, `--password-stdin`, a cookie
  file) are left alone. Traces recorded before keep their old form; delete or re-import them
  if they may hold such commands.
- Redaction did not know several widely used token formats. Added: Stripe secret, restricted
  and webhook keys (`sk_live_`/`sk_test_`, `rk_`, `whsec_`; publishable `pk_` keys are public
  and stay), Google API keys (`AIza…`) and OAuth client secrets (`GOCSPX-`), GitLab tokens
  (`glpat-`, `glptt-`, `gldt-`, `glrt-` and others), npm (`npm_`), PyPI (`pypi-`), Hugging Face
  (`hf_`), SendGrid (`SG.`), DigitalOcean (`dop_v1_`, `doo_`, `dor_`), Shopify (`shpat_` and
  others), Slack webhook URLs, temporary AWS access key IDs (`ASIA…`, next to `AKIA…`) and the
  key of Azure storage and Service Bus connection strings (`AccountKey=`, `SharedAccessKey=`).
- `import --format otlp` silently skipped a trace that was already stored, also when the new
  file held other spans of it (Collector file rotation, an import while the agent was still
  running). The trace kept only the first part: findings from the rest were lost, and
  `--fail-on` passed. Now a trace is skipped only when the import adds no span to it, replaced
  when the import holds all of its spans and more, and otherwise refused with exit code 1.
  `--input` can be repeated to import all parts of a trace together (spans are grouped by
  trace across files, duplicates mapped once), and `--replace` replaces stored traces.
- `agent-trace hook` ignored `on_error = "deny"` when the configuration could not be loaded:
  a canary whose `env` variable is not set where Claude Code runs (an IDE, another terminal),
  a typo in another table, or an unknown profile (`--profile`, `$AGENT_TRACE_PROFILE`). The
  hook exited with 1, so Claude Code ran every tool call unchecked and unrecorded, although
  enforce or ask mode with `on_error = "deny"` promises to deny calls that cannot be checked.
  The `[hooks]` table is now read on its own in that case, and PreToolUse calls are denied
  (exit 2). The reason Claude sees does not repeat a configuration error, which may name
  canaries. A file that is not valid TOML still fails open, as it cannot say `on_error`.

### Library

- `agent_trace_storage::ingest` (`IngestBatch`, `IngestReply`, `ingest`) and the sources
  of a server database (`Store::{add_source, sources, source_by_token_hash, remove_source,
  touch_source, trace_source, list_traces_of_source}`, `Source`, `SourceSummary`,
  `TraceSource::Received`, `StorageError::DuplicateSource`; schema migration 3). The causal graph
  page moved from the CLI to `agent_trace_storage::graph::render`. `agent_trace_net::ship`
  (`ShipClient`, `ShipError`).
- `Finding::tags` (taxonomy tags; `Finding::with_default_tags` fills them for findings of
  built-in rules) and `Rule::tags`, which defaults to the central mapping in
  `agent_trace_core::taxonomy` (`builtin_tags`, `lookup`, `validate_tag`).
- `PolicyOutcome::class` (`DenialClass::Hard` or `Askable`) says whether a denial may be put to
  a human; it is serialized only for askable denials, so existing JSON is unchanged. Also
  `PolicyOutcome::{allow, deny, askable, is_askable}`, `Decision::Ask`,
  `ToolPolicy::evaluate_scoped`, `ToolProfile`, `ProfileConfig`, and in `agent_trace_mcp`
  `ProxyMode::Ask`, `ProxyMode::gates`, `Approval` and `ask_user`.
- Canaries: `agent_trace_core::canary` (`Canary`, `CanaryConfig`, `resolve`, `configure`,
  `find_in_arguments`, …) and `CanaryLeakRule` (AT-007). Tool pins: `agent_trace_mcp::pins`
  (`PinStore`, `fingerprint`, `check`) and `ToolPinRule` (AT-008) with the `TOOL_PINS_*` keys.
- `agent_trace_storage::ocsf` (`ocsf_events`, `write_siem`, `SiemFormat`) and
  `agent_trace_storage::otlp::{read_otlp_all, span_ids}`.
- Source changes for Rust users: `Finding`, `PolicyOutcome` and `ProxyConfig` (`pins`, `profile`,
  `ask_timeout`) have new public fields, so struct literals need them (build a `ProxyConfig` from
  `ProxyConfig::new`); `Decision` and `ProxyMode` have a new variant `Ask` for exhaustive
  matches.

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

[Unreleased]: https://github.com/phr4nky/agent-trace/compare/v1.6.0...HEAD
[1.6.0]: https://github.com/phr4nky/agent-trace/compare/v1.5.0...v1.6.0
[1.5.0]: https://github.com/phr4nky/agent-trace/compare/v1.4.0...v1.5.0
[1.4.0]: https://github.com/phr4nky/agent-trace/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/phr4nky/agent-trace/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/phr4nky/agent-trace/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/phr4nky/agent-trace/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/phr4nky/agent-trace/releases/tag/v1.0.0
