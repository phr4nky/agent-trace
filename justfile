# Convenience commands (optional; plain cargo works the same).

default: check

check:
    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets -- -D warnings
    cargo test --workspace

demo:
    cargo run -p agent-trace-cli -- demo run --scenario all

explore:
    cargo run -p agent-trace-cli -- explore --latest

update-golden:
    UPDATE_GOLDEN=1 cargo test -p agent-trace-cli --test demo_smoke deterministic
