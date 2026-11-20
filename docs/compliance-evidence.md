# Compliance evidence: `agent-trace evidence`

`agent-trace evidence` writes an evidence report about recorded traces. It answers four
questions:

1. **What was recorded?** Per trace: id, name, mode, status, time span, number of events,
   agents, MCP servers and tools requested, findings by severity and rule, and how many values
   were redacted.
2. **By which configuration?** A SHA-256 of the configuration in canonical form, plus a summary:
   policy additions, redaction additions (labels and field names only), retention settings,
   custom rule IDs, canary names and the proxy and hooks modes.
3. **How long is it kept?** The configured `[retention]` limits, the oldest and newest trace in
   the store, and notes when retention is shorter than six months or not configured.
4. **Is it unchanged?** For each JSONL export: the result of the same hash-chain and signature
   check that `agent-trace verify` runs, the signer's key id, and whether that key is trusted.

> **The report is not a statement of compliance.** It collects evidence that an operator can
> use for record-keeping duties, for example under the EU AI Act. Whether an obligation
> applies to a system, and whether it is met, is for the operator and their legal advisers to
> assess. The report says so at the top, in both formats.

## Usage

```sh
# Signed exports (tamper-evident), verified like `agent-trace verify`
agent-trace keys generate
agent-trace export <trace-id> --format jsonl --sign --output evidence/trace-<id>.jsonl
agent-trace evidence evidence/*.jsonl --output evidence-report.md

# Exports signed by someone else: trust their key explicitly
agent-trace evidence evidence/*.jsonl --public-key colleague.pub --format json

# Traces from the store (not tamper-evident)
agent-trace evidence --all
agent-trace evidence --since 2026-05-01
agent-trace evidence --trace 1f78 --trace 9c2e
```

```text
agent-trace evidence [FILE...] [--trace ID]... [--since DATE] [--all]
                     [--public-key HEX|FILE]... [--require-signature]
                     [--format markdown|json] [--output PATH]
```

| Option | Meaning |
|---|---|
| `FILE...` | JSONL exports. Each is checked with the code `verify` uses: hash chain, signature, trusted key |
| `--trace ID` | A stored trace (id or unique prefix). Repeatable |
| `--since DATE` | Stored traces created at or after `YYYY-MM-DD` (midnight UTC) or an RFC 3339 timestamp |
| `--all` | Every stored trace |
| `--public-key` | A trusted signer (hex or `.pub` file). Repeatable. Your own signing key is always trusted |
| `--require-signature` | Count unsigned files as failed |
| `--format` | `markdown` (default) or `json` |
| `--output PATH` | Write to a file created readable only by you (mode 0600, no symlinks followed), like exports. Default: stdout |

Files and store selections can be combined. At least one input is required.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Report written; no input failed verification |
| `1` | An input failed verification (the report is still written, with that input marked `FAILED`), or an error: no input given, unreadable configuration, database unavailable, unknown trace id |

Findings do not change the exit code (there is no `--fail-on`); use `analyze --fail-on` or
`sarif --fail-on` for a findings gate.

### Integrity status per input

| Status | Meaning | Fails the run |
|---|---|---|
| `verified` | Hash chain intact and signed by a trusted key | no |
| `unsigned` | Hash chain intact, no signature: the file is consistent, but anyone could have recomputed the chain | only with `--require-signature` |
| `untrusted_signer` | Hash chain and signature valid, but the key is not trusted (pass it with `--public-key`) | yes |
| `failed` | Unreadable, changed after export, invalid signature, or no integrity record | yes |
| `not_tamper_evident` | Read from the store: there is nothing to check it against | no |

A file that fails verification contributes no trace facts to the report: its content cannot be
relied on. The error says why it failed and, for a changed file, between which records.

## What the report shows, and how

- **Trace facts** come from the verified file (or the store). Findings in a file are ignored
  and recomputed with the current rules, as `import` and `sarif` do; for stored traces, the
  stored findings are used (or computed in memory, without writing, if there are none).
- **Redaction** is the sum of `metadata.redactions` over all events, the number of events with
  redactions, and the number of events whose payload was cut to the size limit.
- **Configuration hash:** SHA-256 over the parsed configuration serialized as JSON with sorted
  keys, every option included (unset ones as `null`). Key order, table order, whitespace and
  comments in `agent-trace.toml` do not change it; values and the order of list entries do.
  Canary values are left out of the hashed form, because a hash of a short decoy value could be
  brute-forced. With no configuration file, the hash is that of the built-in defaults. The
  agent-trace version is reported separately; it determines the built-in rules and redaction.
- **Retention** shows `max_age_days` and `max_traces` from `[retention]`, the store's location
  and size, and its oldest and newest trace. Notes, worded neutrally:
  - no retention configured: agent-trace does not define how long traces are kept;
  - `max_age_days` below 183 days (six months): `prune` deletes traces earlier than that;
  - `max_traces` set: retention by count, so the period covered depends on volume.

  Each of the first two notes adds: "Article 26(6) of the EU AI Act names at least six months
  for deployers of high-risk AI systems."

## What the report does not prove

The report lists these in its own section:

- **Compliance.** It is not a statement of compliance with the EU AI Act or any other law, and
  says nothing about whether a system is high-risk.
- **Integrity of stored traces.** The database is not tamper-evident. Only signed exports,
  verified against a trusted key, show that a trace is unchanged since it was exported. Export
  and sign the traces you need to keep.
- **Completeness.** Only what passed through agent-trace (proxy, hooks, lab, imports) is
  recorded. A signature does not show that a recording is complete.
- **Configuration at recording time.** The configuration hash describes the configuration when
  the report was generated, not necessarily the one in effect when a trace was recorded.
- **Retention in practice.** `[retention]` takes effect only when `agent-trace prune` runs
  (pruning is not automatic). The report shows the limits and the current oldest and newest
  trace, not that traces were kept for any period.
- **Time.** Timestamps come from the recording machine's clock and are not attested.
- **Absence of attacks.** Findings are indicators, and no findings is not proof that nothing
  happened.
- **Absence of sensitive data.** Redaction counts show that values were replaced, not that
  nothing sensitive remains.

## Privacy

The report contains metadata and counts only, never payloads (prompts, tool arguments, tool
results). Trace names, agent ids, tool and server names, file paths and error messages pass
through the redactor, and in Markdown are escaped so they cannot add markup. From the
configuration it shows redaction pattern **labels** and field names, never the patterns, and
canary **names**, never their values.

## Legal context

The roadmap item behind this command refers to two articles of the EU AI Act (Regulation (EU)
2024/1689). In short, as published on
[artificialintelligenceact.eu](https://artificialintelligenceact.eu/) (checked November 2026):

- [**Article 12** (Record-keeping)](https://artificialintelligenceact.eu/article/12/):
  "High-risk AI systems shall technically allow for the automatic recording of events (logs)
  over the lifetime of the system." Paragraph 2 says what the logging should enable (among
  other things, identifying situations that may result in a risk, post-market monitoring, and
  monitoring of the operation by deployers under Article 26(5)).
- [**Article 26(6)** (Obligations of deployers)](https://artificialintelligenceact.eu/article/26/):
  deployers of high-risk AI systems shall keep the logs automatically generated by that system,
  to the extent such logs are under their control, for a period appropriate to the intended
  purpose of the system, of at least six months, unless provided otherwise in applicable Union
  or national law. The paragraph also refers to Union data protection law, and has a special
  case for financial institutions.

Both apply to **high-risk** AI systems only. Their **application dates have changed and may
change again**: at the time of writing the site lists 2 December 2027 for high-risk systems
under Annex III and 2 August 2028 for those under Annex I. Check the current text before you
rely on a date. agent-trace records AI agents; whether such an agent is (part of) a high-risk
AI system depends on its use, not on agent-trace.

## Example

`agent-trace evidence trace.jsonl --since 2026-11-01` (shortened):

```markdown
# agent-trace evidence report

> **Not a compliance statement.** This report is not a statement of compliance with the EU AI
> Act or any other law. ...

- Generated at: 2026-11-20T16:53:47.197135Z
- Generated by: agent-trace 1.6.0
- Report version: 1
- Result: **OK**: no input failed verification

## Configuration

- Source: built-in defaults (no agent-trace.toml)
- SHA-256 (canonical form, canary values excluded): `d5fd734a…`
- Policy additions: privileged: none; outbound: none; allowed destinations: none
- ...

## Retention

- max_age_days: 30
- max_traces: not set
- Applied by: `agent-trace prune` (not automatic; run it on a schedule)
- Oldest trace in the store: 2026-11-20T16:49:58.94Z (`859f1b1f-…`)

- **Note:** max_age_days = 30 is shorter than six months (183 days): `agent-trace prune`
  deletes older traces. Article 26(6) of the EU AI Act names at least six months for deployers
  of high-risk AI systems.

## Traces

### 1. local-lab/exfil-attempt (`bbee6e01-80c5-4d7c-8870-cc0182076991`)

| Field | Value |
| --- | --- |
| Source | file trace.jsonl |
| Integrity | **VERIFIED**: hash chain OK (18 records), signed by key `9964e9c2f37bb5e5` (trusted: your signing key) |
| Mode | simulated |
| Time span | 2026-11-20T16:49:59.49Z to 2026-11-20T16:49:59.63Z |
| Events | 13 |
| Agents | main |
| MCP servers | agent-trace-lab-server |
| Tools requested | read\_document, send\_webhook\_mock |
| Findings | 4 (high 2, medium 2) |
| Findings by rule | AT-001 ×1, AT-002 ×1, AT-003 ×1, AT-004 ×1 |
| Redaction | 2 value(s) redacted in 2 event(s); 0 event(s) truncated |

## What this report does not prove
...
```

## JSON format

`--format json` has stable field names within a `report_version` (currently `"1"`):

```text
report_version, report_type ("agent-trace-evidence"), generated_at, generated_by, disclaimer,
result ("ok" | "failed"),
summary        { traces, from_files, from_store, verified, unsigned, failed,
                 not_tamper_evident, events, findings }
configuration  { source, sha256, policy { privileged, outbound, allow_destinations },
                 redaction { pattern_labels, keys }, retention { max_age_days, max_traces },
                 custom_rules, canaries, profiles { <name>: [tools] }, proxy_mode,
                 hooks_mode, hooks_on_error }
retention      { max_age_days, max_traces, applied_by,
                 store { location, traces, oldest { trace_id, created_at }, newest { … } },
                 warnings [] }
traces []      { source ("file" | "store"), file,
                 integrity { status, chained_records, signed, signer_key_id,
                             signer_public_key, signer_trusted, trusted_by, error },
                 trace { trace_id, name, execution_mode, status, started_at, ended_at,
                         event_count, agents, mcp_servers, tools,
                         findings { total, by_severity { critical, high, medium, low, info },
                                    by_rule { <rule id>: n } },
                         redaction { redacted_values, events_with_redactions,
                                     truncated_events } } | null }
not_proven [], references [ { title, url } ]
```

## Limits

- The report itself is not signed. Its source files are, and a recipient can verify them with
  `agent-trace verify` or by running `agent-trace evidence` again. To sign the report, use a
  general-purpose tool (for example `ssh-keygen -Y sign` or minisign).
- The configuration in the report is the one loaded when the report runs (`--config`,
  `$AGENT_TRACE_CONFIG`, `./agent-trace.toml`, then the data directory). Run the report with the
  configuration used for recording.
