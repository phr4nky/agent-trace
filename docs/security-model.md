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
| Maliciously shaped JSONL imports | Line-length and event-count limits, strict parsing, schema version check, link/cycle validation, re-redaction. Imported findings are ignored |
| Path traversal in lab server | Relative `Normal` components only, extension allowlist, canonicalization + prefix check (symlinks), size limit |
| Demo causing real harm | Mock-only privileged tools, `.invalid` destination, fake secrets, static test guarding against process/network APIs |
| False positives / overclaiming | Findings carry confidence and attempt status; there is no "succeeded" state; simulated traces are labelled |
| Database credentials / traffic | Passwords in URLs are redacted in all output and errors. TLS required by default for non-loopback PostgreSQL/MySQL/MariaDB (rustls, Mozilla roots). Prefer `AGENT_TRACE_DATABASE_URL` over a CLI flag |
| Data sent to LLM providers | Only with explicit `--provider`. The CLI prints a notice; only lab prompts and fixtures (fake secrets) are sent. Keys come from the environment only, never stored or logged; API errors are redacted. Privileged tools stay mocks and policy-gated |
| Injection relayed between agents | Sub-agent reports inherit `lower_trust` when the sub-agent saw untrusted content (taint propagation); AT-006 flags privileged actions downstream |
| Trace tampering | **Not mitigated in v1.0** (no signatures). Planned: hash chains / signing |

## Residual risk

- Redaction is pattern based and can miss unknown secret formats.
- SQLite is not encrypted at rest. Unix permissions restrict access to the owner (0700/0600).
- Inferred facts: rules only use explicit links, but adapters can record wrong links. Findings show their evidence so you can check them.
