# Roadmap

## v1.0.0 (this release)

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
