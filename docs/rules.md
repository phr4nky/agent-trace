# Writing rules

agent-trace ships eight rules (AT-001 … AT-008; AT-007 reports [canary tokens](canaries.md), AT-008
changed [MCP tool definitions](proxy.md#tool-pinning-rug-pulls-and-tool-poisoning)). Add your own in two ways:

- **Declarative rules** in `agent-trace.toml`: no code, no rebuild. They run in every command
  that analyzes (`analyze`, `import`, `demo run`, the proxy, the hooks, `replay`, `graph`).
- **Rust rules** through the `Rule` trait, for embedders who build their own tooling on the crates.

Findings of custom rules are like any other: they have an ID, a version, a severity, a confidence,
an attempt status, evidence events and optional taxonomy tags; they appear in `analyze`, the
explorer, exports, `--fail-on` gates and the graph.

## Taxonomy tags

Every built-in rule is mapped to the [OWASP Top 10 for LLM Applications 2025][owasp] and to
[MITRE ATLAS][atlas] techniques. The mapping is conservative: a tag is listed only when the entry
clearly describes what the rule detects. Tags are plain IDs, copied onto every finding.

| Rule | OWASP LLM Top 10 (2025) | MITRE ATLAS | Why |
|---|---|---|---|
| `AT-001` | [LLM01:2025 Prompt Injection][llm01] | [AML.T0051.001 LLM Prompt Injection: Indirect][t0051.001] | Instructions in content the agent ingests from tools, documents or other agents: indirect prompt injection. |
| `AT-002` | [LLM01:2025 Prompt Injection][llm01], [LLM06:2025 Excessive Agency][llm06] | [AML.T0053 AI Agent Tool Invocation][t0053] | Untrusted content leads to a privileged tool request: injection turned into tool use by an agent with more agency than its input deserves. |
| `AT-003` | [LLM02:2025 Sensitive Information Disclosure][llm02] | [AML.T0086 Exfiltration via AI Agent Tool Invocation][t0086] | Sensitive data leaves through an outbound tool to a non-allowlisted destination. |
| `AT-004` | [LLM06:2025 Excessive Agency][llm06] | none | A tool call denied by policy: the LLM06 mitigation at work. Whether an adversary caused the call is unknown, so no ATLAS technique is claimed. |
| `AT-005` | [LLM01:2025 Prompt Injection][llm01] | [AML.T0051.001 LLM Prompt Injection: Indirect][t0051.001], [AML.T0073 Impersonation][t0073] | Untrusted content claims system, developer or operator authority to steer the agent. |
| `AT-006` | [LLM01:2025 Prompt Injection][llm01], [LLM06:2025 Excessive Agency][llm06] | [AML.T0053 AI Agent Tool Invocation][t0053], [AML.T0143 LLM Prompt Propagation][t0143] | Like AT-002, but the untrusted content was carried from one agent to another agent's privileged action. |
| `AT-007` | [LLM02:2025 Sensitive Information Disclosure][llm02] | [AML.T0086 Exfiltration via AI Agent Tool Invocation][t0086] | A planted decoy secret travels in a tool call's arguments. |
| `AT-008` | [LLM03:2025 Supply Chain][llm03] | [AML.T0109 AI Supply Chain Rug Pull][t0109], [AML.T0110.000 AI Agent Tool Poisoning: Definition and Instructions][t0110.000] | An MCP tool definition changed after it was pinned (rug pull, tool poisoning). |

Where tags appear:

- **JSON report and exports:** `tags` on each finding (`export --format json|jsonl`, `graph`).
  The field is omitted when empty; files from older versions without it still import, and
  findings stored by older versions get the built-in tags when they are loaded.
- **SARIF:** `properties.tags` of each rule (after `security` and `ai-agent`) and of each result,
  so GitHub Code Scanning can filter alerts by `LLM01:2025` or `AML.T0051.001`.
- **SIEM:** OCSF `finding_info.types` (after the rule ID) and `unmapped.tags`
  (`export --format ocsf|splunk-hec`), ECS `tags` (`export --format elastic`). See
  [siem.md](siem.md).
- **Terminal:** `analyze`, `import` and `trace show` end each finding line with `tags: …`.
- **Explorer:** with findings focused (`f`), the detail pane shows the selected finding with its
  tags and their names.
- **Graph:** a finding card shows its tags as chips.

The mapping lives in `crates/agent-trace-core/src/taxonomy.rs` (`taxonomy::builtin_tags`). IDs
and names were checked against [genai.owasp.org/llm-top-10][owasp] and the ATLAS data
([mitre-atlas/atlas-data][atlas-data], release 2026.10).

[owasp]: https://genai.owasp.org/llm-top-10/
[atlas]: https://atlas.mitre.org/
[atlas-data]: https://github.com/mitre-atlas/atlas-data
[llm01]: https://genai.owasp.org/llmrisk/llm01-prompt-injection/
[llm02]: https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/
[llm03]: https://genai.owasp.org/llmrisk/llm032025-supply-chain/
[llm06]: https://genai.owasp.org/llmrisk/llm062025-excessive-agency/
[t0051.001]: https://atlas.mitre.org/techniques/AML.T0051.001
[t0053]: https://atlas.mitre.org/techniques/AML.T0053
[t0073]: https://atlas.mitre.org/techniques/AML.T0073
[t0086]: https://atlas.mitre.org/techniques/AML.T0086
[t0109]: https://atlas.mitre.org/techniques/AML.T0109
[t0110.000]: https://atlas.mitre.org/techniques/AML.T0110.000
[t0143]: https://atlas.mitre.org/techniques/AML.T0143

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
tags = ["LLM06:2025", "AML.T0053", "CORP-shell"]    # optional taxonomy tags
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
- `tags` (optional) are copied onto every finding of the rule and shown wherever findings are
  (see [Taxonomy tags](#taxonomy-tags)). Use OWASP IDs like `LLM01:2025`, ATLAS IDs like
  `AML.T0051` or `AML.T0051.001`, or your own labels. Each tag is 1–64 bytes without control or
  invisible formatting characters and without leading or trailing whitespace; at most 32 tags,
  no duplicates. The format is not checked further. Custom rules have no tags unless you list them.
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
    // Optional; the default is the built-in mapping by rule ID (none for your own IDs).
    fn tags(&self) -> Vec<String> { vec!["LLM06:2025".into(), "AML.T0101".into()] }
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
