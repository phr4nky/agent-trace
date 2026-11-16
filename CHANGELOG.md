# Changelog

All notable changes to agent-trace are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The section of a version is used as the release notes of its GitHub release.

## [Unreleased]

## [1.2.0] - 2026-11-17

Fixes from a multi-agent bug hunt on v1.1.0.

**Upgrade notes:**

- The outbound allowlist is stricter again. A CI gate that passed with v1.1.0 can report AT-003 for
  the same traces when a destination used a slashless URL, a recipient list or a `cc`/`bcc` field.
- AT-004 moves to rule version 2, so its finding IDs change.
- Usage errors (for example `--fail-on High`) now exit with code 1 instead of 2. Exit code 2 now
  always means findings.

### Added

- `McpSession::with_call_timeout` for library users. A `tools/call` without an answer now fails
  after 300 s by default and is recorded as a failed tool call, instead of hanging.

### Changed

- AT-004 (policy denial) reports `executed` with high severity when the trace records an execution
  of the denied request (an audit-only or fail-open gate). Before, it always said "not executed".
- Rejected imports report the line number for every structural error (duplicate id, sequence,
  links, schema version), as the README promises.

### Fixed

- **Outbound allowlist bypasses** (policy gate and AT-003):
  - URLs without slashes after the scheme (`http:evil.example/?r=://localhost`) were judged by
    the later `://`. URLs are now parsed exactly like HTTP clients (WHATWG, the `url` crate).
  - In a recipient list (`attacker@evil.example,ops@localhost`) only the last address was checked.
    Now every address is.
  - `cc`, `bcc`, `reply_to`, differently cased keys and `*_url`/`*_uri`/`*_endpoint` arguments
    were not checked.
- **Import:**
  - Secrets only in event metadata did not mark the event as sensitive, so AT-003 was missed.
  - Memory was about 30 times the file size. Events are now redacted while reading, and an
    import holds at most 10 million JSON values.
  - Many keys that redact to the same text made import quadratic: one crafted line took minutes.
  - Export and re-import truncated already truncated text again and lost the original byte
    count.
  - Error messages no longer repeat their cause.
- **Storage:**
  - Opening a SQLite database no longer changes the permissions of an existing directory.
    `sqlite:./traces.db` locked other users out of the project directory, and `/tmp` failed.
  - Several commands opening a new SQLite database at the same time no longer fail with
    "database is locked" or "table already exists".
  - On PostgreSQL and MySQL, re-analysing a trace while it is recorded live can no longer
    collide.
  - A PostgreSQL server on localhost with a self-signed certificate (the Debian/Ubuntu default)
    works without `sslmode=disable`. Connection errors show their cause.
  - Export files can no longer be redirected by a symlink created between the check and the
    write.
- **MCP and agents:**
  - Tool result text with duplicated JSON keys could carry instructions the model saw but the
    trace did not. The full text is now recorded.
  - Tool calls with non-object input skipped the policy gate and the trace.
- **CLI:**
  - Piping output into `head` no longer crashes with exit code 101.
  - `demo run` no longer loses already recorded traces when a scenario file is broken or the
    database fails during the run. On a database failure the traces are saved as JSONL.

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

[Unreleased]: https://github.com/phr4nky/agent-trace/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/phr4nky/agent-trace/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/phr4nky/agent-trace/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/phr4nky/agent-trace/releases/tag/v1.0.0
