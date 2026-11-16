# Roadmap

## v1.2.0 (this release)

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
- MCP proxy to record existing agents without code changes (stdio and streamable HTTP)
- Interactive causal graph (Angular + Cytoscape.js or equivalent)
- SARIF export and GitHub Code Scanning integration
- Tamper evidence (hash-chained events, signed exports)
- Retention and redaction configuration, rule/plugin SDK
- Controlled replay and model regression suites
