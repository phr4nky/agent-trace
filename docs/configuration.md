# Configuration (`agent-trace.toml`)

One optional file configures every command. It is found in this order: `--config PATH`,
`$AGENT_TRACE_CONFIG`, `./agent-trace.toml`, `<data dir>/agent-trace.toml`. When a file is used,
commands that analyze name it on stderr. A file with unknown keys, wrong types, an invalid
pattern or an invalid rule is an error for every command; it is never silently ignored.

Everything adds to the built-in defaults; nothing built in can be switched off.

```toml
[policy]                          # tool classes and destinations (see docs/proxy.md)
privileged = ["create_*"]
outbound = ["post_*"]
allow_destinations = ["hooks.corp.example", "*.corp.example"]

[proxy]                           # agent-trace proxy (see docs/proxy.md)
mode = "observe"                  # or "enforce"
taint_sources = ["*"]
call_timeout_secs = 300
pin_tools = true                  # pin MCP tool definitions per server (see docs/proxy.md)

[hooks]                           # agent-trace hook (see docs/claude-code-hooks.md)
mode = "observe"
taint_sources = ["WebFetch", "WebSearch", "mcp__*"]
on_error = "allow"                # or "deny"

[redaction]                       # added to the built-in secret patterns
patterns = [
  { label = "corp_token", regex = '\bCORP-[A-Z0-9]{20}\b' },
  { label = "pin", regex = 'PIN:\s*(?P<value>\d{4,8})' },   # only the `value` group is replaced
]
keys = ["x-corp-auth", "session_secret"]   # field names whose values are always replaced

[retention]                       # defaults for `agent-trace prune`
max_age_days = 30
max_traces = 1000

[[rules]]                         # declarative detection rules (see docs/rules.md)
id = "CORP-001"
title = "Download piped into a shell"
severity = "high"
tools = ["Bash"]
arguments = { command = 'curl[^|]*\|\s*sh' }
after_untrusted = true

[[canaries]]                      # decoy secrets (see docs/canaries.md)
name = "aws-decoy"
env = "AGENT_TRACE_CANARY_AWS_DECOY"     # or: value = "AKIA…"
```

## `[redaction]`

- `patterns`: `label` (1–32 lowercase letters or `_`, shown as `[REDACTED:<label>]`) and a
  regular expression. With a capture group named `value`, only that group is replaced; otherwise
  the whole match. Patterns that match the empty string or compile to more than 1 MiB are rejected.
- `keys`: object keys whose values are replaced with `[REDACTED:field]`, matched
  case-insensitively with `-` and `_` treated alike.
- The rules apply to everything the process stores, exports, logs and prints, including
  `import` (before anything is stored). Data recorded before a pattern was added keeps its old
  form; re-redacting stored traces is not done automatically.
- Redacted values count as sensitive data for AT-003.

## `[[canaries]]`

- `name`: 1–64 lowercase letters, digits, `-`, `_` or `.`; shown in findings and stored in traces.
- Exactly one of `value` (the decoy itself, 12–1024 characters without spaces) and `env` (the
  name of an environment variable that holds it). An `env` variable that is not set is an error
  for every command, so a canary is never silently inactive.
- Keep this table where the agent cannot read it: the agent-trace.toml in the data directory,
  `--config`, or `env`. `agent-trace canary new NAME` prints a fresh decoy and its entry.
- Canary values are replaced with `[REDACTED:canary]` everywhere; tool calls that carry one are
  reported as AT-007 and denied by the policy gate. Details: [canaries.md](canaries.md).

## `[retention]` and `agent-trace prune`

```sh
agent-trace prune --older-than 30d          # also 12h, 90m; a plain number means days
agent-trace prune --keep 100                # only the newest 100 traces
agent-trace prune --dry-run                 # list what would be deleted
agent-trace prune                           # use [retention]
```

- A trace is deleted with its events, findings and evidence links. Traces that are still being
  recorded (`running`) are never deleted.
- On SQLite, deleted content is overwritten (`secure_delete`) and the write-ahead log is
  truncated, so it does not linger in the files. On PostgreSQL and MySQL/MariaDB, the database
  server decides when freed space is reused.
- Without `--older-than`, `--keep` or a `[retention]` table, `prune` is an error, never
  "delete everything".
- Pruning is not automatic: run it from cron or a CI schedule.
- Exports (JSONL, JSON, SARIF, graphs) are files you own; `prune` does not touch them.
