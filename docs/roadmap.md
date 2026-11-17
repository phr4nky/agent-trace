# Roadmap

## Unreleased

- `agent-trace sarif FILE...` and `export --format sarif`: SARIF 2.1.0 for GitHub Code Scanning,
  alerts at the line of the risky tool request in the trace file, evidence as a code flow
- Tamper evidence: every JSONL export ends with a SHA-256 hash chain; `export --sign` adds an
  Ed25519 signature; `agent-trace verify` and `import` reject changed files
- Retention (`agent-trace prune`, `[retention]`), redaction configuration (`[redaction]`), and
  declarative custom rules (`[[rules]]`) plus documented Rust rules

## v1.4.0

- `agent-trace replay`: run a model or system prompt against a recorded session (task and tool
  results from the recording, nothing executed) and compare the findings; regression suites in
  TOML with exit code 2 for CI
- `agent-trace graph`: interactive causal graph as one self-contained, offline HTML file (lanes
  per agent and MCP server, evidence paths of findings, ancestors and descendants of an event)
- `agent-trace proxy --url`: remote MCP servers over streamable HTTP (https, tokens from the
  environment)
- One trace per client session across all proxied servers: an injection through one server and
  a privileged call to another are linked and blocked
- `agent-trace hook`: Claude Code hooks record a whole session (prompts, built-in tools, MCP
  tools, subagents) as one trace and can deny tool calls before they run
- Claude Code's Bash, PowerShell, Write, Edit, MultiEdit and NotebookEdit are privileged by default

## v1.3.0

- `agent-trace proxy`: record and optionally enforce the traffic between any MCP client and an
  MCP server over stdio
- `agent-trace.toml`: privileged and outbound tools (with `*` wildcards), destination allowlist
  (with `*.domain`), proxy mode and taint sources; used by every command
- AT-002/AT-006 report session-context links with medium confidence

## v1.2.0

- Fixes from a multi-agent bug hunt: three more outbound-allowlist bypasses, import memory and
  speed limits, redaction and truncation fixes, concurrent SQLite opens and migrations, loopback
  PostgreSQL with self-signed TLS, MCP call timeout, CLI exit codes
- AT-004 reports a denied action that was still executed as `executed`

## v1.1.0

- Security fixes from the v1.0.0 review: detection blind spots (truncated payloads, structured
  content, object keys), WHATWG-consistent outbound allowlist, driver-based database TLS default,
  redaction gaps, terminal output escaping, linear-time analysis, import size limit, LLM client
  hardening, least-privilege release workflow
- `import --fail-on` and `demo run --fail-on`: the CI verdict comes from the validated import itself
- Note: detection is stricter, so a CI gate that passed with v1.0.0 can now report findings

## v1.0.0


- Versioned event/trace/finding model (schema 1.1), recorder, redaction, validation
- Storage backends: SQLite (default), PostgreSQL, MariaDB/MySQL with automatic migrations
- Live recording (per-event persistence, trace status) and `explore --follow`
- Real `rmcp` MCP lab server, scripted simulated agent, four scenarios incl. multi-agent handoff
- Opt-in LLM agents: Anthropic Messages API, OpenAI Chat Completions and compatible servers
- Rules AT-001 … AT-006 (incl. cross-agent taint), golden traces
- CLI, ratatui explorer, JSONL/JSON import/export, CI + release workflows

## Next

- OTLP ingestion with a versioned GenAI semantic-convention mapping
