# Security model

## Assets

Recorded traces (may contain prompts, document fragments, tool arguments), findings, and the
integrity of evidence.

## Threats and mitigations

| Threat | Mitigation |
|---|---|
| Hostile MCP server results / prompt injection in documents | Results are labelled `lower_trust` and treated as data. AT-001/AT-005 flag suspicious content and AT-002 flags privileged requests caused by it |
| Exfiltration via outbound tools | Destination allowlist in `ToolPolicy`, enforced in the client gate (and server-side for the lab). AT-003/AT-004 record attempts |
| Accidental secret logging | Same `Redactor` on storage, JSONL/JSON, logs (redacting writer) and TUI. Field-name and value patterns |
| Maliciously shaped JSONL imports | Line-length, event-count and total-size limits, strict parsing, schema version check, link/cycle validation, re-redaction. Imported findings are ignored. Rules run in time linear in the number of causal links |
| Path traversal in lab server | Relative `Normal` components only, extension allowlist, canonicalization + prefix check (symlinks), size limit |
| Demo causing real harm | Mock-only privileged tools, `.invalid` destination, fake secrets, static test guarding against process/network APIs |
| False positives / overclaiming | Findings carry confidence and attempt status; there is no "succeeded" state; simulated traces are labelled |
| Database credentials / traffic | Passwords in URLs are redacted in all output and errors. TLS required by default for non-loopback PostgreSQL/MySQL/MariaDB (rustls, Mozilla roots). Prefer `AGENT_TRACE_DATABASE_URL` over a CLI flag |
| Data sent to LLM providers | Only with explicit `--provider`. The CLI prints a notice; only lab prompts and fixtures (fake secrets) are sent. Keys come from the environment only, never stored or logged; API errors are redacted. Privileged tools stay mocks and policy-gated |
| Injection relayed between agents | Sub-agent reports inherit `lower_trust` when the sub-agent saw untrusted content (taint propagation); AT-006 flags privileged actions downstream |
| Agent acting on injected content through a real MCP server | `agent-trace proxy --mode enforce` denies privileged calls after untrusted content from a configured taint source entered the session, and outbound calls to non-allowlisted destinations, before they reach the server. Links are session context (medium confidence), never invented causes |
| Agent running commands after reading injected content (Claude Code) | `agent-trace hook` in enforce mode denies privileged built-in and MCP tool calls after untrusted content reached the acting agent, including through a subagent's report. A recorder failure fails open by default (`on_error = "deny"` to fail closed) |
| Weakened configuration (`agent-trace.toml`) | Config files only add to the built-in policy, so they cannot remove privileged or outbound tools; they can widen the destination allowlist. The file in use is printed on stderr. A CI gate should pass `--config` explicitly instead of trusting `./agent-trace.toml` from a checked-out branch. Invalid files are errors |
| Trace tampering | **Not mitigated in v1.0** (no signatures). Planned: hash chains / signing |

## Residual risk

- Redaction is pattern based and can miss unknown secret formats.
- SQLite is not encrypted at rest. Unix permissions restrict access to the owner (0700/0600).
- Inferred facts: rules only use explicit links, but adapters can record wrong links. Findings show their evidence so you can check them.
- The MCP proxy only sees MCP traffic. The client's built-in tools (for example a shell tool) and other servers are outside its view; a session can be harmful without anything suspicious in its trace.
