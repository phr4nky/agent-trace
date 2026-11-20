# Writing rules

agent-trace ships seven rules (AT-001 … AT-007; AT-007 reports [canary tokens](canaries.md)). Add your own in two ways:

- **Declarative rules** in `agent-trace.toml`: no code, no rebuild. They run in every command
  that analyzes (`analyze`, `import`, `demo run`, the proxy, the hooks, `replay`, `graph`).
- **Rust rules** through the `Rule` trait, for embedders who build their own tooling on the crates.

Findings of custom rules are like any other: they have an ID, a version, a severity, a confidence,
an attempt status and evidence events; they appear in `analyze`, the explorer, exports, `--fail-on`
gates and the graph.

## Declarative rules

### A dangerous tool call

```toml
[[rules]]
id = "CORP-001"
title = "Download piped into a shell"
severity = "high"                       # info | low | medium | high | critical
confidence = "high"                     # low | medium (default) | high
description = "A shell command downloads a script and runs it."
remediation = "Never pipe downloads into a shell; pin and verify installers."
tools = ["Bash", "run_command*"]        # tool names, `*` wildcards; empty = any tool
arguments = { command = 'curl[^|]*\|\s*(ba)?sh' }   # every listed argument must match
after_untrusted = true                  # only after lower-trust content (see below)
```

- `on = "tool_call"` (the default) checks every `tool_call_requested` event: the tool name must
  match one of `tools`, and each argument in `arguments` must exist and match its regular
  expression. Non-string arguments are matched as JSON text.
- `after_untrusted = true` reports only requests with an explicit causal or context path back to
  lower-trust content (a tool result, a document, another agent's tainted report) — the same
  provenance AT-002 uses. Without it, every matching request is reported.
- The attempt status comes from the recorded lifecycle: `blocked` after a policy denial,
  `executed` after a recorded execution, otherwise `attempted`.

### Untrusted content

```toml
[[rules]]
id = "CORP-002"
title = "Internal project name in untrusted content"
severity = "medium"
on = "content"
pattern = 'ACME-PROJECT-[A-Z]+-\d+'
```

`on = "content"` scans lower-trust content (tool results, external content, model and agent
messages marked lower-trust) and reports matches as `suspected`, like AT-001.

### Rules for rule files

- `id` is `PREFIX-NNN`: uppercase letters and digits, a dash, one to six digits (`CORP-001`).
  `AT-` is reserved for built-in rules. IDs must be unique.
- `version` (default 1) is part of every finding ID. Increase it when you change what a rule
  means, so stored findings of the old version are replaced on the next analysis.
- Regular expressions use the [`regex`](https://docs.rs/regex) syntax (no look-around or
  back-references; linear time). Patterns that match the empty string are rejected. In TOML,
  single-quoted strings keep backslashes as they are.
- A file with an invalid rule is an error for every command, never silently ignored.

## Rust rules

```rust
use agent_trace_core::rules::{Rule, RuleContext};
use agent_trace_core::{Analyzer, EventKind, Finding};

struct NoDeleteAll;

impl Rule for NoDeleteAll {
    fn id(&self) -> &str { "CORP-100" }
    fn version(&self) -> u32 { 1 }
    fn title(&self) -> &str { "Recursive delete requested" }
    fn evaluate(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        // ctx.record: the trace; ctx.index: provenance (causes, context links);
        // ctx.policy: the tool policy. Build findings with explicit evidence event IDs.
        let _requests = ctx.record.events.iter().filter(|e| e.kind == EventKind::ToolCallRequested);
        Vec::new()
    }
}

let analyzer = Analyzer::default().with_rule(Box::new(NoDeleteAll));
```

Rules see only what the trace records and should only follow explicit links
(`caused_by_event_id`, `context_event_ids`, `parent_event_id`), never timing: causality is not
inferred. Findings must be deterministic for the same trace and rule version; `Finding::derive_id`
gives stable IDs.
