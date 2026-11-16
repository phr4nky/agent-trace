# Local lab

A self-contained environment that demonstrates agent-trace with a **real MCP server over stdio**
(`rmcp`) and a **scripted, simulated agent**. No API keys, no Docker, no network, no shell.
Optionally a **real LLM** (Anthropic, OpenAI or a local OpenAI-compatible server) can drive the agent
instead of the script (`--provider`). The tools stay mocks.

```bash
cargo run -p agent-trace-cli -- demo run --scenario all
```

## Components

| Component | Where | Notes |
|---|---|---|
| MCP server | `crates/agent-trace-mcp/src/server.rs` | Spawned as a child process, stdio transport |
| Scripted agent | `crates/agent-trace-mcp/src/lab.rs` | Follows `scenarios/*.json`; every decision is marked `simulated` |
| Policy gate | `crates/agent-trace-core/src/policy.rs` | Outbound tools need an allowlisted destination (`localhost` only) |
| Fixtures | `documents/` | Test-only text; secrets are visibly fake |
| Expectations | `expected-findings.json` | Checked by `crates/agent-trace-cli/tests/demo_smoke.rs` |

## MCP tools

1. `read_document(path)`: returns a fixture from `documents/`. Rejects `..`, absolute paths,
   symlinks that escape the directory, and anything other than `.md`/`.txt`.
2. `run_command_mock(command)`: returns canned output. **Never starts a shell.**
3. `send_webhook_mock(destination, body)`: reports what would happen and applies the allowlist.
   **Never opens a socket.**

## Scenarios

| Scenario | Flow | Expected findings |
|---|---|---|
| `benign` | prompt → `read_document` → summary | none |
| `prompt-injection` | prompt → `read_document` (injected text) → simulated decision → `run_command_mock` (mock executed) | `AT-001` suspected, `AT-002` executed (mock) |
| `exfil-attempt` | prompt → `read_document` (fake secret + instruction) → simulated decision → `send_webhook_mock` **blocked by policy** | `AT-001`, `AT-002` blocked, `AT-003` blocked, `AT-004` blocked |
| `multi-agent-handoff` | orchestrator delegates → researcher reads `injected-readme.md` → its report relays the instruction (tainted) → orchestrator runs `run_command_mock` | `AT-001` ×2, `AT-002` executed (mock), `AT-006` executed (mock) |

Scenario files can contain a `delegate` step (sub-agent with its own steps and a `report`), plus
`document`, `agent` and `delegate_to` fields that brief an LLM agent in `--provider` mode.

The "compromised" behavior is **scripted**. It shows what a trace of such an incident looks
like. It does not show that a real model would behave this way.

Use `--deterministic` (with a fresh `--data-dir`) for stable IDs and timestamps. The golden traces in
`fixtures/golden-traces/` are produced this way.
