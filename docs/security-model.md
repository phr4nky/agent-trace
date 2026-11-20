# Security model

## Assets

Recorded traces (may contain prompts, document fragments, tool arguments), findings, and the
integrity of evidence.

## Threats and mitigations

| Threat | Mitigation |
|---|---|
| Hostile MCP server results / prompt injection in documents | Results are labelled `lower_trust` and treated as data. AT-001/AT-005 flag suspicious content and AT-002 flags privileged requests caused by it |
| Exfiltration via outbound tools | Destination allowlist in `ToolPolicy`, enforced in the client gate (and server-side for the lab). AT-003/AT-004 record attempts |
| Secrets moved by a steered agent, including to allowlisted places (a ticket, a pull request) | Canary tokens: configured decoy values are matched before redaction, only their names are stored, AT-007 reports every tool call that carries one and the policy gate denies it in enforce mode. Values can come from the environment so the agent cannot read the canary list. Transformed values (base64, split) are not recognized |
| Accidental secret logging | Same `Redactor` on storage, JSONL/JSON, logs (redacting writer) and TUI. Field-name and value patterns |
| Maliciously shaped JSONL imports | Line-length, event-count and total-size limits, strict parsing, schema version check, link/cycle validation, re-redaction. Imported findings are ignored. Rules run in time linear in the number of causal links |
| Path traversal in lab server | Relative `Normal` components only, extension allowlist, canonicalization + prefix check (symlinks), size limit |
| Demo causing real harm | Mock-only privileged tools, `.invalid` destination, fake secrets, static test guarding against process/network APIs |
| False positives / overclaiming | Findings carry confidence and attempt status; there is no "succeeded" state; simulated traces are labelled |
| Database credentials / traffic | Passwords in URLs are redacted in all output and errors. TLS required by default for non-loopback PostgreSQL/MySQL/MariaDB (rustls, Mozilla roots). Prefer `AGENT_TRACE_DATABASE_URL` over a CLI flag |
| Data sent to LLM providers | Only with explicit `--provider`. The CLI prints a notice. `demo run` sends lab prompts and fixtures (fake secrets); `replay` sends the recorded prompt and tool results, which are redacted (secrets appear as `[REDACTED:<kind>]`). Keys come from the environment only, never stored or logged; API errors are redacted. Privileged tools stay mocks and policy-gated |
| Injection relayed between agents | Sub-agent reports inherit `lower_trust` when the sub-agent saw untrusted content (taint propagation); AT-006 flags privileged actions downstream |
| Agent acting on injected content through a real MCP server | `agent-trace proxy --mode enforce` denies privileged calls after untrusted content from a configured taint source entered the session, and outbound calls to non-allowlisted destinations, before they reach the server. Links are session context (medium confidence), never invented causes |
| Agent running commands after reading injected content (Claude Code) | `agent-trace hook` in enforce mode denies privileged built-in and MCP tool calls after untrusted content reached the acting agent, including through a subagent's report. A recorder failure fails open by default (`on_error = "deny"` to fail closed) |
| Credentials and traffic to remote MCP servers | `proxy --url` requires https (plain http only for loopback), follows only same-origin 307/308 redirects, and takes tokens and header values from environment variables only. They are marked sensitive and never recorded; the trace stores the URL without credentials, query or fragment |
| Injection through one MCP server, action through another | The proxies of one client session share a trace; untrusted content from any server counts against privileged calls to all of them. In enforce mode a proxy that cannot read the session's history denies instead of forwarding unchecked |
| Injected content in a trace attacking the viewer (`graph` HTML) | Embedded data escapes `<`, `>`, `&` and line separators, so it cannot end its `<script type="application/json">` element. The viewer inserts trace content only with `textContent`/`setAttribute`. The page's CSP allows only its own inline script and style by SHA-256 hash, no other script, no connections and no forms; it loads nothing remote. Tests check the escaping, the hashes and that the viewer uses no HTML-injection or network APIs |
| Replay causing side effects | Replays never reach a real tool: an in-process MCP server answers from the recording, and a call without a recorded result gets an error saying nothing was executed. Suites and recordings are validated (and recordings re-redacted) before the first model call |
| Old traces kept longer than needed | `agent-trace prune` (`--older-than`, `--keep`, `[retention]`) deletes traces with their events, findings and evidence links, never traces still being recorded. On SQLite, `secure_delete` overwrites the freed pages and the WAL is truncated, so pruned content is not left in the files (tested). Server databases reuse freed space on their own schedule |
| Weakened configuration (`agent-trace.toml`) | Config files only add to the built-in policy, so they cannot remove privileged or outbound tools; they can widen the destination allowlist. The file in use is printed on stderr. A CI gate should pass `--config` explicitly instead of trusting `./agent-trace.toml` from a checked-out branch. Invalid files are errors |
| Trace tampering (exported evidence) | Every JSONL export ends with an integrity record: a SHA-256 chain over the exact bytes of all other lines, with checkpoints every 256 lines. `import` and `verify` reject a file whose chain differs. `export --sign` adds an Ed25519 signature over the head, bound to the trace id; `verify` accepts it only for a trusted key (`--public-key` or the local signing key), since anyone can sign an edited file with their own key. The private key is a PKCS#8 file created with mode 0600 and never overwritten |
| Trace tampering (database) | **Not mitigated.** Whoever can write the database can change stored traces; there is nothing to check them against. Export and sign promptly |

## Residual risk

- Redaction is pattern based and can miss unknown secret formats. Organization-specific formats and field names can be added in `[redaction]`; they apply to everything the process stores, exports, logs and prints, but data recorded before a pattern was added keeps its old form.
- SQLite is not encrypted at rest. Unix permissions restrict access to the owner (0700/0600).
- Inferred facts: rules only use explicit links, but adapters can record wrong links. Findings show their evidence so you can check them.
- The MCP proxy only sees MCP traffic. The client's built-in tools (for example a shell tool) and other servers are outside its view; a session can be harmful without anything suspicious in its trace.
