# Contributing

Thanks for helping! Please keep changes small, auditable and tested.

## Workflow

- Branch from `main`, keep a **linear history** (rebase, no merge commits):
  `git pull --rebase` and `git rebase main` before opening a pull request.
- One topic per pull request. Each PR must compile and pass all checks.

## Checks (CI runs the same)

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -p agent-trace-cli -- --data-dir /tmp/at-demo demo run --scenario all
```

Storage backends: set `AGENT_TRACE_TEST_POSTGRES_URL` / `AGENT_TRACE_TEST_MYSQL_URL` to run the
conformance and end-to-end tests against PostgreSQL and MySQL/MariaDB (see README → Development).

## Rules of the road

- `agent-trace-core` must not depend on `rmcp`, `ratatui` or any vendor SDK.
- Causality is explicit (`parent_event_id`, `caused_by_event_id`); never infer it from timestamps.
- New rules: add a typed `Rule`, bump `version()` when semantics change, and add positive **and**
  negative fixtures in `crates/agent-trace-core/tests/rule_detection.rs`.
- Never commit real credentials. Test secrets must be visibly fake (e.g. `FAKE_SECRET_…`).
- Demo/lab code must never execute shell commands or perform network I/O.
- If you change the event model or lab scenarios, regenerate golden traces:
  `UPDATE_GOLDEN=1 cargo test -p agent-trace-cli --test demo_smoke deterministic`
  and review the diff.
