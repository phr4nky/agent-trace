# Event schema (version 1.1)

Version 1.1 adds `agent_id`, `context_event_ids`, the trace `status` and three agent-to-agent
event kinds. It is backwards compatible: 1.0 traces are read as written (agent = `main`,
no context links, status = `completed`).

## Event

| Field | Type | Notes |
|---|---|---|
| `schema_version` | string | `"1.1"` (`"1.0"` accepted) |
| `event_id` | UUID | unique within the trace |
| `trace_id` | UUID | |
| `sequence` | integer | starts at 1, +1 per event |
| `timestamp` | RFC 3339 UTC | informational only, never used for causality |
| `kind` | enum | see below |
| `parent_event_id` | UUID \| null | must reference an earlier event of the same trace |
| `caused_by_event_id` | UUID \| null | must reference an earlier event of the same trace |
| `origin` | `user` `agent` `model` `mcp_tool` `external_document` `policy` `system` | |
| `trust_level` | `trusted` `lower_trust` `unknown` | |
| `name` | string | tool / agent / operation name |
| `payload` | object | **redacted**, string values ≤ 16 KiB, payload ≤ 256 KiB (else truncated with marker) |

When a payload is truncated, the content rules scan the original first and store the matching
indicator labels in `metadata.content_indicators` (`{"AT-001": [...], "AT-005": [...]}`), so text
beyond the size limits is still analyzed. Only labels from the built-in indicator lists are honored.
| `execution_mode` | `simulated` `live` | |
| `tool_state` | `requested` `policy_decision` `blocked` `executed` `completed` `failed` (optional) | |
| `metadata` | object | e.g. `transport`, `mcp_server`, `redactions`, `truncated`, `content_indicators`, `simulated_decision`, `mock_tool`, `tool_use_id` |
| `agent_id` | string (optional, 1.1) | acting agent; absent = `main` |
| `context_event_ids` | UUID[] (optional, 1.1) | additional explicit causes: everything that was in the context of this event (e.g. all tool results a `model_request` was based on). Must reference earlier events |

### Kinds

`agent_started`, `agent_completed`, `user_prompt_received`, `model_request`, `model_response`,
`tool_call_requested`, `tool_policy_decision`, `tool_call_executed`, `tool_call_completed`,
`tool_call_failed`, `tool_result_received`, `external_content_observed`, `agent_decision`,
and (1.1) `agent_delegated`, `agent_message_sent`, `agent_message_received`.

### Multi-agent conventions

- `agent_delegated` (parent agent) → sub-agent `agent_started` (caused by the delegation).
- The sub-agent's report is `agent_message_sent` (sub-agent) → `agent_message_received` (parent).
  If the sub-agent observed lower-trust content, both are `lower_trust` (taint propagation) and
  link that content via `context_event_ids`.

### LLM conventions

- `model_request` (origin `agent`): caused by the previous step, with `context_event_ids` listing the
  prompt, earlier model responses and every tool result in the context window.
- `model_response` (origin `model`): text, tool calls (`id`, `name`, `input`), stop reason, token usage.
- Tool requests derived from a response are caused by that `model_response`; `metadata.tool_use_id`
  keeps the provider's call ID.

### Invariants (enforced on import)

1. Supported `schema_version` on the trace and on every event.
2. All events belong to the trace; `event_id`s are unique.
3. `sequence` is contiguous starting at 1, and events are ordered by sequence.
4. Links (parent, cause and context) reference existing events, not the event itself. The link graph is acyclic and only points backwards.
5. Payload size is limited.

### Example

```json
{
  "schema_version": "1.0",
  "event_id": "fe5950d3-af4e-4f96-a26a-e8a448914117",
  "trace_id": "fd13b98d-64e3-467a-9850-5e693b2784b7",
  "sequence": 10,
  "timestamp": "2026-11-16T10:00:00Z",
  "kind": "tool_call_requested",
  "parent_event_id": "…",
  "caused_by_event_id": "…",
  "origin": "agent",
  "trust_level": "unknown",
  "name": "send_webhook_mock",
  "payload": {
    "tool": "send_webhook_mock",
    "arguments": {"destination": "https://example.invalid/mock-endpoint", "body": "API_TOKEN=[REDACTED:test_secret]"}
  },
  "execution_mode": "simulated",
  "tool_state": "requested",
  "metadata": {"redactions": 1, "simulated_decision": true, "decision_source": "scenario_script", "privileged": true}
}
```

## Trace header

`schema_version`, `trace_id`, `name`, `created_at`, `execution_mode`, `metadata`, and (1.1) `status`:
`running` while being recorded, `completed`, or `aborted` after an error. A trace that stays `running`
was never finished (crash or kill).

## Finding

`finding_id` (UUID v5, deterministic), `trace_id`, `rule_id`, `rule_version`, `title`, `description`,
`severity` (`info|low|medium|high|critical`), `confidence` (`low|medium|high`),
`evidence_event_ids[]`, `attempt_status` (`suspected|attempted|blocked|executed|unknown`),
`remediation`, `created_at`.

`executed` means only that the trace records an execution event. It does not mean an attack succeeded.

## JSONL

One JSON object per line with a `record_type` tag: first `trace`, then `event`s in sequence order,
then optional `finding`s, then (in exports) one `integrity` record. Finding lines are ignored on
import (findings are recomputed).

### Integrity record

```json
{"record_type":"integrity","version":1,"algorithm":"sha256-chain","lines":18,
 "head":"<64 hex>","checkpoints":[{"line":256,"hash":"<64 hex>"}],
 "signature":{"algorithm":"ed25519","key_id":"<16 hex>","public_key":"<64 hex>","value":"<128 hex>"}}
```

- `h0 = SHA-256("agent-trace-chain-v1")`; for every non-blank line before the record, in order,
  `hᵢ = SHA-256(hᵢ₋₁ ‖ line)` over the exact bytes of the line without its line break. `lines` is
  the number of chained lines, `head` the last `hᵢ`, `checkpoints` every 256th `hᵢ`.
- `signature` (optional): Ed25519 over
  `"agent-trace-integrity-v1\n" ‖ trace_id ‖ "\n" ‖ lines ‖ "\n" ‖ head`. `key_id` is the first 16
  hex digits of SHA-256 of the public key.
- The record must be the last record. Files without one (hand-written traces) are accepted; a
  record whose chain or signature does not match rejects the file.

## Migration strategy

- Additive, backwards-compatible fields → minor bump (`1.x`). Readers ignore unknown metadata.
- Breaking changes → new major version, add an explicit upgrade step in the importer, and keep
  `SUPPORTED_SCHEMA_VERSIONS` until the old version is removed.
- SQLite schema changes are numbered migrations in `schema_migrations`. They are never edited after release.
