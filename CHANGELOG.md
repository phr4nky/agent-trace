# Changelog

All notable changes to agent-trace are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The section of a version is used as the release notes of its GitHub release.

## [Unreleased]

## [1.1.0] - 2026-11-17

Security fixes from the review of v1.0.0.

**Upgrade note:** detection is stricter. A CI gate that passed with v1.0.0 can report findings
with v1.1.0 for the same traces. That is intended: those traces contained something v1.0.0 missed.

### Added

- `agent-trace import --fail-on <level>`: exit code 2 when a finding of the imported trace reaches
  the threshold. The verdict comes from the validated import itself, not from a later read of the
  database. The CI examples (`examples/ci/agent-trace-gate.sh`, `Jenkinsfile`, README) use it.
- `agent-trace demo run --fail-on <level>`, with the same exit code contract.
- `SHA256SUMS` for the release archives.

### Security

- **Detection blind spots closed.**
  - Content rules scan a payload before it is truncated, so instructions placed past the
    truncation limit are still detected.
  - Object keys are scanned as content, not only values.
  - For MCP tool results, the text content the model receives is always recorded next to the
    structured content. A server could otherwise hide instructions in the text while the trace
    showed only harmless structured data.
- **Outbound allowlist:** hosts are parsed as WHATWG URL parsing does, so the policy agrees with
  what HTTP clients connect to. Every destination-like argument of an outbound tool is checked, and
  ambiguous authorities (whitespace, control characters) are denied.
- **Database TLS default:** whether TLS is required is decided from the host the driver actually
  connects to. A `?host=` parameter can no longer switch TLS off for a remote server, and every
  loopback address (`127.0.0.0/8`, `[::1]`) is recognized.
- **Redaction gaps:**
  - URL passwords containing `@` are covered completely.
  - Quoted key/value secrets are covered.
  - Secret key names are matched by segment (`db_password`, `githubToken`, `x-auth-token`).
  - Tokens used as object keys are redacted.
  - Text that only looks like a redaction placeholder is no longer trusted.
- **LLM client:**
  - Redirects are never followed, so the API key is not replayed to another host.
  - Keys are sent only over `https://`, or plain http to a loopback host.
  - Provider responses are limited to 16 MiB.
- **Terminal output:** control characters in trace names, findings and error messages are escaped
  before printing.
- **Robustness:**
  - Analysis runs in linear time.
  - Imports are limited to 512 MiB in total.
  - NUL characters in name columns are handled.
  - Lab documents are read with bounded, race-free size checks.
- **Multi-agent lab:** a sub-agent can only call the tools of its role.
- **Exported files** are created readable by the owner only.
- **Release workflow:** read-only token by default; only the job that publishes the release can
  write.

## [1.0.0] - 2026-11-16

First release.

- Event, trace and finding model (schema 1.1, schema 1.0 still readable) with explicit causal
  links, recorder, validation and redaction before anything is stored or printed.
- Rules AT-001 to AT-006: prompt-injection indicators, trust-boundary crossings, exfiltration,
  policy denials, authority spoofing and cross-agent taint.
- Storage in SQLite (default), PostgreSQL, MariaDB and MySQL, with automatic migrations.
- Live recording and `explore --follow`.
- MCP lab server with four scenarios, including a multi-agent handoff.
- Optional real models: Anthropic, OpenAI and OpenAI-compatible servers.
- CLI commands `demo`, `trace`, `analyze --fail-on`, `explore`, `export` and `import`.
- CI examples for GitHub Actions, GitLab CI and Jenkins.

[Unreleased]: https://github.com/phr4nky/agent-trace/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/phr4nky/agent-trace/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/phr4nky/agent-trace/releases/tag/v1.0.0
