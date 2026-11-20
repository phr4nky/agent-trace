# Roadmap

## Next

Proposals, not commitments; the numbers are for discussion, not an order.

**Team server and web UI**

1. Login and roles: OIDC/SSO for the web UI and the read API, roles that decide who sees which
   sources; replaces `--allow-unauthenticated-reads`
2. Server in the release: `agent-trace-server` as a binary and a signed container image (GHCR)
   in every release, not only from source
3. Live view by push: server-sent events instead of polling every four seconds, so a running
   session grows as it happens
4. Search and filters across all traces: by rule, severity, tool, destination host and time,
   over all sources
5. Alerts: webhook, Slack or mail for new findings from a chosen severity, with a link to the
   graph
6. Signed batches: the recorder signs every batch with Ed25519 and the server verifies it, so the
   evidence chain runs unbroken from the machine to the database
7. Rate limits and quotas per source, against a faulty or compromised recorder
8. Paging of very large traces in the graph: sections and loading on demand for sessions with
   tens of thousands of events

**Recording**

9. More agent hooks: adapters for Codex CLI, Gemini CLI and Cursor, like the Claude Code hooks
10. OTLP live ingest: the server accepts OTLP/HTTP directly, so LangGraph, OpenAI Agents or
    Semantic Kernel apps send traces without export files
11. Clean session ends: a hook trace without SessionEnd is closed as `abandoned` after an idle
    timeout instead of staying `running`
12. Taint across fork and resume: a resumed or forked Claude Code session inherits the trust state
    of the session it continues

**Detection and policy**

13. Data-flow rules for content: detect when content from confidential sources (files, database
    tools) appears in outbound calls, by fingerprints, not only by origin
14. Policy tests: `agent-trace policy test`, unit tests for `agent-trace.toml` (given events,
    expected decision) for CI
15. Trace diff: `agent-trace diff A B` shows two sessions or two model versions side by side, next
    to `replay`
16. A growing attack library: newly published attacks (for example rules-file backdoors and MCP
    sampling abuse) as replay cases, with a regular update routine

**Operations and evidence**

17. Retention on the server: retention and deletion per source (deadlines, client addresses as
    personal data under the GDPR), export as signed JSONL
18. Evidence report from the server: `agent-trace evidence` over all sources of a period, straight
    from the server database

## v1.6.0

- Team server and web UI: `agent-trace ship` sends recorded traces (store and forward, a token
  per source) to `agent-trace-server`, which checks, redacts and analyzes them again; the web UI
  (Angular + SwipyUI, `ui/`) shows the traces of each source with their causal graph.
  `docker-compose.yml` runs it with PostgreSQL
- Canary tokens (`[[canaries]]`, `agent-trace canary new|list`): decoy secrets, matched before
  redaction; a tool call that carries one is reported (AT-007, critical) and denied in enforce
  and ask mode
- Rug-pull protection: the MCP proxy pins every tool definition on first use and reports a
  changed or added tool (AT-008); in enforce and ask mode a changed tool is hidden and denied
  until `agent-trace pins reset` accepts it
- Ask mode (`--mode ask`): a privileged call after untrusted content, or one to a destination
  that is not allowlisted, is put to a human (Claude Code `permissionDecision: "ask"`, MCP
  elicitation in the proxy) instead of being blocked; task profiles (`[profiles.<name>]`,
  `--profile`) allow only the tools a task needs
- Attack library: published agent attacks ([GitHub MCP][github], [Supabase MCP][supabase],
  [tool poisoning][poisoning], [EchoLeak][echoleak]) as a `replay` suite with fake data
- Taxonomy tags: every built-in rule mapped to the [OWASP Top 10 for LLM Applications][owasp-llm]
  and [MITRE ATLAS][atlas], shown in reports, SARIF, SIEM exports, the explorer and the graph
- `agent-trace evidence`: an evidence report for record-keeping duties such as
  [Article 12 of the EU AI Act][aiact12] (what was recorded, by which configuration, how long it
  is kept, whether exports are unchanged); explicitly not a compliance statement
- SIEM export: `export --format ocsf|splunk-hec|elastic` ([OCSF][ocsf] 1.9.0, Splunk HEC,
  Elasticsearch bulk with ECS)
- Graph: an info card with the details of each event; fixes for the redaction of command-line
  credentials and common token formats, OTLP traces split across files, and `on_error = "deny"`
  when a hook cannot load its configuration

## v1.5.0

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

## Later

- A local OTLP/HTTP receiver, and mappings for OpenInference and OpenLLMetry attributes
- Baselines of normal agent behavior (statistical, no model judges)
- Agent-to-agent protocols (A2A) across organizations
- Computer-use and browser agents: screen and page content as untrusted input

[github]: https://invariantlabs.ai/blog/mcp-github-vulnerability
[supabase]: https://generalanalysis.com/blog/supabase-mcp-blog
[poisoning]: https://invariantlabs.ai/blog/mcp-security-notification
[echoleak]: https://thehackernews.com/2025/06/zero-click-ai-vulnerability-exposes.html
[owasp-llm]: https://genai.owasp.org/llm-top-10/
[atlas]: https://atlas.mitre.org/
[aiact12]: https://artificialintelligenceact.eu/article/12/
[ocsf]: https://ocsf.io/
