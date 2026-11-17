# Security Policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's
**Security → Report a vulnerability** (private advisory) on this repository. Do not open public
issues for security problems. We aim to acknowledge reports within 7 days.

## Scope and design principles

agent-trace processes **untrusted data**: MCP tool results, documents, prompts and imported
JSONL traces. Relevant security properties:

- Recorded content is **data only**. It is never evaluated as code, commands or instructions.
- Redaction is applied **before** anything is written to SQLite, JSONL/JSON exports, logs or the TUI.
  All of these paths use the same `Redactor` (`crates/agent-trace-core/src/redact.rs`).
- Imports are validated (schema version, unique IDs, contiguous sequences, link targets, no cycles,
  no forward links, size limits) and re-redacted. Findings in imported files are ignored and recomputed.
- The local lab never starts a shell and never opens a network socket. Privileged tools are mocks.
  `read_document` is sandboxed to the fixture directory (no `..`, no absolute paths, no symlink escape, `.md`/`.txt` only).
- No telemetry, uploads or online model judges. LLM providers are contacted only with an explicit
  `--provider`; API keys are read from the environment and never stored, logged or traced.
- Data directories are created `0700` and files `0600` on Unix.

## Residual risks

- **Regex redaction is best effort.** Unknown secret formats can slip through. Do not import
  sensitive production traces without additional controls.
- **SQLite is not encrypted at rest.** Protect the data directory like any other sensitive file.
- **Rules produce indicators, not proof.** False positives and false negatives are expected.
- **Trace tampering:** JSONL exports carry a hash chain and can be signed (`export --sign`,
  `agent-trace verify`). The trace database is not protected: an attacker with write access to
  the data directory can alter stored traces. Export and sign evidence promptly and keep the
  signing key outside the data directory if the data directory is not trusted.

See [docs/security-model.md](docs/security-model.md) for the threat model.
