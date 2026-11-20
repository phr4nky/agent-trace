# SIEM export (OCSF, Splunk, Elastic)

Security operations teams triage incidents in their SIEM. `agent-trace export` writes a trace's
findings, and optionally all of its events, as [OCSF](https://schema.ocsf.io/) events, so an
agent incident lands next to the rest of your alerts.

```sh
agent-trace export --latest --format ocsf                    # findings only
agent-trace export --latest --format ocsf --include-events   # findings, then every event
agent-trace export <trace-id> --format splunk-hec --include-events --output hec.ndjson
agent-trace export <trace-id> --format elastic --include-events --output bulk.ndjson
```

| Format | Output | For |
| --- | --- | --- |
| `ocsf` | NDJSON, one OCSF event per line | any OCSF consumer (Amazon Security Lake, data lakes, custom pipelines) |
| `splunk-hec` | NDJSON, one HEC event per line | Splunk HTTP Event Collector, `/services/collector/event` |
| `elastic` | NDJSON, an action line and a document line per event | Elasticsearch `_bulk` API |

All three contain the same OCSF events in the same order: the findings in analyzer order, then,
with `--include-events`, every event in sequence order. Without `--include-events` only the
findings are written: they are the alerts, the events are context. `--include-events` is
rejected for the other formats.

Like every export, the SIEM formats are **always redacted** (the same redaction as
`--format json`), and agent-trace **sends nothing over the network**: it writes to stdout or to
`--output` (created readable only by you). You send the file with the tools below.

The output is deterministic: the same stored trace and findings give the same bytes (object
keys are sorted). Finding IDs are derived from the trace, rule and evidence, so a finding keeps
its ID across exports.

## OCSF mapping

Schema version **1.9.0**, the current release at [schema.ocsf.io](https://schema.ocsf.io/)
when this export was written. `type_uid` is `class_uid * 100 + activity_id`, as OCSF requires.

| agent-trace | OCSF class | `class_uid` | `category_uid` | `activity_id` | `type_uid` |
| --- | --- | --- | --- | --- | --- |
| Finding | Detection Finding | 2004 | 2 Findings | 1 Create | 200401 |
| Tool event: `tool_call_requested`, `tool_policy_decision`, `tool_call_executed`, `tool_result_received`, `tool_call_completed`, `tool_call_failed` | API Activity | 6003 | 6 Application Activity | 99 Other | 600399 |
| Every other event (agent start and end, prompts, model requests and responses, decisions, delegation and messages between agents, external content) | Base Event | 0 | 0 Uncategorized | 99 Other | 99 |

Why these classes:

- **Detection Finding** is OCSF's class for a detection by a rule or analytic, which is what an
  agent-trace finding is. It carries severity, confidence, status, evidence and remediation.
- **API Activity** fits tool calls: an MCP `tools/call` (or a hook-observed tool call) is an API
  operation the agent performs, with an actor, a caller and a destination. A policy decision is
  the outcome of the security control on that same call, so it stays in the same class and
  carries the `security_control` profile (`action_id`, `disposition_id`). The CRUD activities
  (Create, Read, Update, Delete) cannot be read from a tool call reliably, so the activity is
  99 Other with the agent-trace event kind as `activity_name`.
- **Base Event** for everything else: OCSF 1.9.0 has no class for model requests, prompts or
  agent hand-offs that would fit without inventing data (Application Lifecycle, for example,
  describes installing, starting and stopping applications, not an agent run). The Base Event
  keeps them searchable with the same `metadata`, `time` and `unmapped` fields.

### Common fields

| OCSF field | Value |
| --- | --- |
| `time` | finding: analysis time; event: event timestamp. Epoch milliseconds |
| `metadata.product` | `{"name": "agent-trace", "vendor_name": "agent-trace", "version": "<agent-trace version>"}` |
| `metadata.version` | `1.9.0` (OCSF schema version) |
| `metadata.uid` | finding ID or event ID |
| `metadata.correlation_uid` | trace ID: all events of one trace share it |
| `metadata.log_name` | `findings` or `events` |
| `metadata.labels` | `["execution_mode:live"]` or `["execution_mode:simulated"]` (demo traces) |
| `metadata.profiles` | `["security_control"]` when `action_id`/`disposition_id` are set |
| `message` | finding: title, attempt status, confidence and description; event: `#<sequence> <kind> \`<name>\`` |
| `unmapped` | agent-trace fields without an OCSF equivalent (see below) |

### Detection Finding (findings)

| agent-trace | OCSF |
| --- | --- |
| `finding_id` | `finding_info.uid`, `metadata.uid` |
| `title` | `finding_info.title`, `finding_info.analytic.name` |
| `description` | `finding_info.desc` |
| `rule_id` | `finding_info.analytic.uid`, `finding_info.types[0]`; `finding_info.analytic.type_id` = 1 Rule |
| `tags` (OWASP LLM Top 10, MITRE ATLAS) | `finding_info.types[1..]`, `unmapped.tags` (left out when empty) |
| `rule_version` | `finding_info.analytic.version` |
| `created_at` | `time`, `finding_info.created_time` |
| first and last evidence event | `finding_info.first_seen_time`, `finding_info.last_seen_time` |
| `severity` info / low / medium / high / critical | `severity_id` 1 Informational / 2 Low / 3 Medium / 4 High / 5 Critical |
| `confidence` low / medium / high | `confidence_id` 1 Low / 2 Medium / 3 High |
| (new to the SIEM) | `status_id` 1 New |
| `attempt_status` | `status_detail` (`suspected`, `attempted`, `blocked`, `executed`, `unknown`) |
| `attempt_status` blocked | `action_id` 2 Denied, `disposition_id` 2 Blocked |
| `attempt_status` executed | `action_id` 1 Allowed, `disposition_id` 1 Allowed |
| `evidence_event_ids` | `finding_info.related_events[]` (`uid` = event ID = that event's `metadata.uid`, `type_uid`, `type_name`, `title`, `created_time`), `finding_info.related_events_count` |
| evidence events | `evidences[]`: `data` (event ID, sequence, kind, name, origin, trust level), `api.operation` for tool events, `dst_endpoint.hostname` for a destination |
| tool names, destination hosts of the evidence | `observables[]`: `{"name": "api.operation", "type_id": 99}`, `{"name": "dst_endpoint.hostname", "type_id": 1 Hostname}` |
| `remediation` | `remediation.desc` |
| trace ID and name, execution mode, rule ID and version, attempt status, evidence event IDs | `unmapped` |

For suspected, attempted and unknown attempts `action_id`/`disposition_id` are left out: the
trace does not show what the control did.

### API Activity (tool events)

| agent-trace | OCSF |
| --- | --- |
| tool name (`payload.tool`, else the event name) | `api.operation` |
| `metadata.mcp_server` | `api.service.name` |
| acting agent (`agent_id`, default `main`) | `actor.application.name`, `src_endpoint.name` |
| destination argument of a request (`url`, `destination`, `to`, `*_url`, ...) | `dst_endpoint.hostname` (first host), `observables` (all hosts) |
| policy decision `deny` / tool state `blocked` | `status_id` 2 Failure, `action_id` 2 Denied, `disposition_id` 2 Blocked |
| policy decision `allow` | `status_id` 1 Success, `action_id` 1 Allowed, `disposition_id` 1 Allowed |
| policy decision reason | `status_detail` |
| `tool_call_failed`, a result or completion with `is_error: true` | `status_id` 2 Failure |
| `tool_call_executed`, `tool_result_received`, `tool_call_completed` | `status_id` 1 Success |
| `tool_call_requested` | `status_id` 0 Unknown |
| tool state (other events) | `status_detail` |

### All events

| agent-trace | OCSF |
| --- | --- |
| `event_id` | `metadata.uid` |
| `sequence` | `metadata.sequence` |
| `kind` | `activity_name` |
| `timestamp` | `time` |
| — | `severity_id` 1 Informational (severity belongs to findings) |
| the redacted agent-trace event record (as in `--format jsonl`) | `raw_data` (JSON string) |
| trace ID and name, execution mode, kind, origin, trust level, agent, tool state, parent, cause and context event IDs | `unmapped` |

Hosts are read from the request's arguments without any network resolution, with the same
parser the policy uses.

## Splunk HTTP Event Collector

`--format splunk-hec` writes one JSON object per line in the format of the
[HEC `/services/collector/event` endpoint](https://help.splunk.com/en/splunk-enterprise/get-started/get-data-in/9.4/get-data-with-http-event-collector/format-events-for-http-event-collector):

```json
{"event":{...OCSF event...},"source":"agent-trace","sourcetype":"agent-trace:ocsf","time":1767225601.0}
```

`time` is epoch seconds with milliseconds as the fraction (the OCSF `time` divided by 1000).
`host` and `index` are not set: the HEC token's defaults apply. HEC accepts several
concatenated events in one request, so the whole file can be sent at once:

```sh
agent-trace export --latest --format splunk-hec --include-events --output hec.ndjson
curl -sS "https://splunk.example.com:8088/services/collector/event" \
  -H "Authorization: Splunk $SPLUNK_HEC_TOKEN" \
  --data-binary @hec.ndjson
```

Search example: `sourcetype="agent-trace:ocsf" class_uid=2004 severity_id>=4`.

## Elasticsearch `_bulk`

`--format elastic` writes an NDJSON body for the
[`_bulk` API](https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-bulk.html):
for each OCSF event an action line and an [ECS](https://www.elastic.co/guide/en/ecs/current/index.html)
document. The file ends with a newline, as `_bulk` requires.

```json
{"create":{"_id":"<finding or event ID>"}}
{"@timestamp":"2026-01-01T00:00:12Z","ecs":{"version":"9.5.0"},"event":{...},"message":"...","ocsf":{...OCSF event...},...}
```

- The action is `create`, which works for indices and data streams (data streams accept only
  `create`). `_id` is the finding or event ID, so sending the same export twice adds no
  duplicates (the repeated documents fail with a version conflict).
- No `_index` is set: name the index or data stream in the URL.

| ECS field | Value |
| --- | --- |
| `@timestamp` | OCSF `time` as RFC 3339 |
| `message` | OCSF `message` |
| `ecs.version` | `9.5.0` |
| `event.kind` | `alert` for findings, `event` for events |
| `event.category` | `["intrusion_detection"]` for findings, `["api"]` for tool events, not set for Base Events |
| `event.type` | `["denied"]` when blocked, `["allowed"]` when allowed, else `["info"]` (not set for Base Events) |
| `event.outcome` | tool events: `success`, `failure` or `unknown` (from `status_id`) |
| `event.severity` | OCSF `severity_id` (1 to 5) |
| `event.action` | rule ID for findings, event kind for events |
| `event.id` | finding or event ID |
| `event.dataset`, `event.module`, `event.provider` | `agent_trace.ocsf`, `agent_trace`, `agent-trace` |
| `rule.id`, `rule.name`, `rule.description`, `rule.version`, `rule.ruleset` | findings: rule ID, title, description, rule version, `agent-trace` |
| `tags` | findings: taxonomy tags (`LLM01:2025`, `AML.T0051.001`, …), left out when empty |
| `observer.vendor`, `observer.product`, `observer.version` | `agent-trace`, `agent-trace`, agent-trace version |
| `labels.trace_id`, `labels.execution_mode` | trace ID, `live` or `simulated` |
| `related.hosts` | destination hosts |
| `ocsf` | the complete OCSF event |

```sh
agent-trace export --latest --format elastic --include-events --output bulk.ndjson
curl -sS -X POST "https://elastic.example.com:9200/agent-trace-ocsf/_bulk" \
  -H "Authorization: ApiKey $ELASTIC_API_KEY" \
  -H "Content-Type: application/x-ndjson" \
  --data-binary @bulk.ndjson
```

`--data-binary` keeps the newlines (`-d` would strip them). Check the response's `errors`
field: `_bulk` returns 200 even when single documents fail.

`ocsf.unmapped` and `ocsf.raw_data` hold free-form data. With dynamic mapping, consider mapping
`ocsf.unmapped` as [`flattened`](https://www.elastic.co/guide/en/elasticsearch/reference/current/flattened.html)
and `ocsf.raw_data` with `"index": false` in your index template.

## Limits

- **One trace per export**, selected by ID or `--latest`. Export each trace you want to send;
  `metadata.correlation_uid` ties a trace's events together in the SIEM.
- **Nothing is sent.** There is no built-in forwarder, retry or batching by size; use `curl`,
  a Splunk/Elastic agent watching a directory, or your log shipper.
- **Large traces:** with `--include-events`, `raw_data` repeats the (redacted, size-limited)
  payload of each event. HEC and `_bulk` limit the request size (HEC: `max_content_length` in
  Splunk's `limits.conf`; Elasticsearch: `http.max_content_length`, 100 MB by default). Split big
  files by lines; for `elastic`, split at even line numbers so pairs stay together.
- **Finding time is analysis time.** A finding's `time` is when the analyzer produced it; the
  time of the behavior is in `finding_info.first_seen_time` and `last_seen_time`.
- **Base Events** carry no OCSF semantics beyond time, metadata and the kind; filter them with
  `class_uid=0` if you only want tool activity and findings.
- **Validation:** the output follows the required attributes of OCSF 1.9.0 for the three
  classes; it is not run through an OCSF validator. `actor.application` is used because
  `actor.app_name` is deprecated in 1.9.0.
- **Redaction** is pattern-based, as everywhere in agent-trace: unknown secret formats can be
  missed. Add patterns in `[redaction]` (see [configuration.md](configuration.md#redaction)).
