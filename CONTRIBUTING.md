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

## Releasing

Versions follow [SemVer](https://semver.org/): **patch** for backward-compatible fixes,
**minor** for new backward-compatible features (e.g. a new CLI flag), **major** for breaking
changes (removed/renamed flags, incompatible event schema). Stricter detection is a fix, but
call it out in the release notes: a CI gate that passed before can now report findings.

The version is bumped in a **dedicated release pull request**, never in feature PRs (they would
conflict in `Cargo.lock` and the golden traces) and never by pushing to `main` directly.

1. Branch from the current `main`:

   ```bash
   git switch -c release/vX.Y.Z origin/main
   ```

2. Bump the version and everything that embeds it:

   ```bash
   # [workspace.package] version in Cargo.toml, then refresh the lockfile
   cargo update --workspace
   # the lab server version is part of the golden traces
   UPDATE_GOLDEN=1 cargo test -p agent-trace-cli --test demo_smoke deterministic
   grep -rn "vOLD\|OLD" README.md docs/ examples/ci/   # install URLs, Jenkinsfile, sample output
   ```

   Also add a section for the release to `docs/roadmap.md`.

3. Run the checks above, open the PR (title `Release vX.Y.Z`) and merge it once CI is green.

4. Tag the merged commit on `main`. The tag starts `.github/workflows/release.yml`, which tests and
   builds Linux, macOS and Windows binaries and creates the GitHub release with them:

   ```bash
   git fetch origin
   git tag vX.Y.Z origin/main
   git push origin vX.Y.Z
   ```

   Check that the release has all three archives and that `agent-trace --version` in one of them
   reports the new version.

Tags are immutable releases: never move or re-push a published tag. If a release is broken, fix it
on `main` and publish the next patch version.
