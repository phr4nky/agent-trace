# Roadmap

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

## Next

In order of priority. Each item names the real-world problem it answers and a rough effort.

### 1. Canary tokens: from indicator to proof

Plant decoy secrets (a fake cloud key in `.env`, a token in a document or a database row) and
report a critical finding when one of them shows up in the arguments of an outbound tool call or
in content written to a place the attacker can read. Today's findings are indicators; a leaked
canary is evidence.

- **Real world:** in a demonstration against the Supabase MCP server, a support ticket told a
  coding agent to read the `integration_tokens` table and write it back into the ticket, where
  the attacker could read it ([General Analysis, July 2025][supabase]; Supabase states no
  customer data was leaked this way). A canary row in that table would have made the leak
  unambiguous.
- **Effort:** small. The policy gate, the redactor and the rules already see every argument.

### 2. Rug-pull protection for MCP servers

Pin the tool descriptions and schemas a server announces the first time (a hash of its
`tools/list` answer) and alert, or block in enforce mode, when they change later. The proxy
already records `tools/list`.

- **Real world:** "tool poisoning" hides instructions in tool descriptions, and a "rug pull"
  changes a tool's description after the user approved it ([Invariant Labs, April 2025][poisoning];
  tool poisoning is MCP03 in OWASP's MCP Top 10). Invariant's MCP-Scan pins tool definitions as
  a separate scan; agent-trace would do it on the live connection and keep the change in the trace.
- **Effort:** small.

### 3. Approval mode and task-scoped permissions

Besides allow and deny, ask a human before a privileged call that follows untrusted content
(Claude Code: `permissionDecision: "ask"`; proxy: MCP elicitation). And scope tools to the task:
a read-only task gets no write tools.

- **Real world:** in the GitHub MCP attack, a malicious issue in a public repository made an
  agent copy private repository content into a public pull request; the task was only to look
  at issues ([Invariant Labs, May 2025][github]). Invariant describes it as a design problem that
  server-side patches cannot fix, which is where a gate on the agent's side helps. Today's enforce
  mode can only block; teams need a middle ground before they turn it on.
- **Effort:** medium.

### 4. Attack library

Recordings of publicly documented agent attacks, shipped as a `replay` suite, so a model or
prompt change can be checked against known attacks before it ships: injection through issues
([GitHub MCP][github]), support tickets ([Supabase MCP][supabase]), tool descriptions
([tool poisoning][poisoning]) and documents or emails pulled into context ([EchoLeak,
CVE-2025-32711][echoleak], a zero-click prompt injection in Microsoft 365 Copilot).

- **Real world:** before switching to a new model version, a team runs the suite and sees
  whether the new model still follows the injected instructions.
- **Effort:** small to medium. `replay` and suites exist; the work is faithful recordings.

### 5. Taxonomy tags

Map rules and findings to the [OWASP Top 10 for LLM Applications][owasp-llm] and
[MITRE ATLAS][atlas], and show the tags in reports, SARIF and the explorer.

- **Real world:** security teams, audits and risk registers sort findings by these
  taxonomies, not by tool-specific rule IDs.
- **Effort:** small.

### 6. Compliance evidence

An evidence report built from signed traces: what was recorded, by which configuration, how long
it is kept, and proof that it is unchanged. Aimed at record-keeping duties such as
[Article 12 of the EU AI Act][aiact12] (automatic logging for high-risk AI systems; deployers
keep logs for at least six months under Article 26(6)).

- **Real world:** operators of high-risk AI systems must be able to show their logs. The
  application dates of these obligations are still subject to change; the report will not
  claim compliance, only provide the evidence.
- **Effort:** medium; builds on signed exports (#14) and retention (#15).

### 7. SIEM export

Findings and events as [OCSF][ocsf] events, plus ready-made outputs for Splunk and Elastic.

- **Real world:** security operations teams triage incidents in their SIEM; an agent incident
  that only lives in a separate tool is easily missed.
- **Effort:** small to medium.

[github]: https://invariantlabs.ai/blog/mcp-github-vulnerability
[supabase]: https://generalanalysis.com/blog/supabase-mcp-blog
[poisoning]: https://invariantlabs.ai/blog/mcp-security-notification
[echoleak]: https://thehackernews.com/2025/06/zero-click-ai-vulnerability-exposes.html
[owasp-llm]: https://genai.owasp.org/llm-top-10/
[atlas]: https://atlas.mitre.org/
[aiact12]: https://artificialintelligenceact.eu/article/12/
[ocsf]: https://ocsf.io/

## Later

- A local OTLP/HTTP receiver, and mappings for OpenInference and OpenLLMetry attributes
- Baselines of normal agent behavior (statistical, no model judges)
- Agent-to-agent protocols (A2A) across organizations
- Computer-use and browser agents: screen and page content as untrusted input
