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
  and review the diff. The attack library's recordings come from
  `examples/attack-library/scenarios/*.json`; regenerate them with
  `UPDATE_GOLDEN=1 cargo test -p agent-trace-cli --test attack_library recordings_match`.

## Changelog

Every user-visible change adds a line under `## [Unreleased]` in [CHANGELOG.md](CHANGELOG.md),
in the same pull request, grouped as Added / Changed / Fixed / Removed / Security.

## Releasing

Versions follow [SemVer](https://semver.org/):
- **patch:** backward-compatible fixes
- **minor:** new backward-compatible features, for example a new CLI flag
- **major:** breaking changes, such as removed or renamed flags or an incompatible event schema

Stricter detection counts as a fix, but say so in the changelog: a CI gate that passed before can
now report findings.

The version is bumped in a **dedicated release pull request from `release/X.Y.Z`**. Never bump it
in a feature PR, which would conflict in `Cargo.lock` and the golden traces, and never push the
bump to `main` directly.

1. Branch from the current `main`:

   ```bash
   git switch -c release/X.Y.Z origin/main
   ```

2. Bump the version and everything that embeds it:

   ```bash
   # set [workspace.package] version in Cargo.toml, then refresh the lockfile
   cargo update --workspace
   # the lab server version is part of the golden traces
   UPDATE_GOLDEN=1 cargo test -p agent-trace-cli --test demo_smoke deterministic
   # install URLs, Jenkinsfile and sample output still naming the previous version
   grep -rn "OLD_VERSION" README.md docs/ examples/ci/
   ```

3. In `CHANGELOG.md`, rename `## [Unreleased]` to `## [X.Y.Z] - YYYY-MM-DD`, add a new empty
   `## [Unreleased]` above it, and update the compare links at the bottom. This section becomes
   the release notes of the GitHub release, so write it for users.

4. Run the checks above, open the PR with the title `Release X.Y.Z` and merge it once CI is green.

5. Tag the merged commit on `main`:

   ```bash
   git fetch origin
   git tag vX.Y.Z origin/main
   git push origin vX.Y.Z
   ```

   The tag starts `.github/workflows/release.yml`. It tests and builds the Linux, macOS and Windows
   binaries, then creates the GitHub release with the archives, `SHA256SUMS` and the changelog
   section as notes. Check that all files are attached and that `agent-trace --version` in one of
   the archives reports the new version.

Release tags are immutable: a ruleset blocks moving or deleting `v*` tags. If a release is broken,
fix it on `main` and publish the next patch version.
