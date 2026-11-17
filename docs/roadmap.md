# Roadmap

## Unreleased

- `agent-trace sarif FILE...` and `export --format sarif`: SARIF 2.1.0 for GitHub Code Scanning,
  alerts at the line of the risky tool request in the trace file, evidence as a code flow
- Tamper evidence: every JSONL export ends with a SHA-256 hash chain; `export --sign` adds an
  Ed25519 signature; `agent-trace verify` and `import` reject changed files
- Retention (`agent-trace prune`, `[retention]`), redaction configuration (`[redaction]`), and
  declarative custom rules (`[[rules]]`) plus documented Rust rules
- OTLP ingestion: `import --format otlp` maps OpenTelemetry GenAI spans (agents, model calls,
  tool calls, MCP) onto events, with links only from tool call IDs and span structure

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

## In review

- SARIF export and GitHub Code Scanning integration (#13)
- Tamper evidence: hash-chained and signed exports (#14)
- Retention and redaction configuration, declarative rules (#15)
- OTLP ingestion with a versioned GenAI semantic-convention mapping (#16)

## Next

In order of priority:

1. **Canary tokens: from indicator to proof.** Plant decoy secrets (a fake cloud key in `.env`,
   a token in a document) and report it as critical when one of them shows up in the arguments
   of an outbound tool call. Today's findings are indicators; a leaked canary is evidence.
2. **Rug-pull protection for MCP servers.** Pin the tool descriptions a server announces the first
   time (hash of `tools/list`) and alert or block in the proxy when they change later. Changed or
   poisoned tool descriptions are a known way to slip instructions into an approved server.
3. **Approval mode.** Besides allow and deny, ask a human before a privileged call that follows
   untrusted content (Claude Code: `permissionDecision: "ask"`; proxy: MCP elicitation), and
   task-scoped permissions: a read-only task gets no write tools.
4. **Attack library.** Recordings of publicly documented agent attacks (prompt injection through
   issues, tickets, web pages and tool descriptions) shipped as a replay suite, so a model or
   prompt change can be checked against known attacks before it ships.
5. **Taxonomy tags.** Map rules and findings to the OWASP Top 10 for LLM Applications and to
   MITRE ATLAS, in reports, SARIF and the explorer.
6. **Compliance evidence.** An evidence report built from signed traces for record-keeping
   requirements such as Article 12 of the EU AI Act: what was recorded, how long it is kept, and
   proof that it is unchanged.
7. **SIEM export.** Findings and events as OCSF, plus ready-made outputs for Splunk and Elastic,
   so security operations teams see agent incidents in the tools they already use.

## Later

- A local OTLP/HTTP receiver, and mappings for OpenInference and OpenLLMetry attributes
- Baselines of normal agent behavior (statistical, no model judges)
- Agent-to-agent protocols (A2A) across organizations
- Computer-use and browser agents: screen and page content as untrusted input
