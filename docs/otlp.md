# Importing OpenTelemetry traces (OTLP)

Agent frameworks and model SDKs that follow the OpenTelemetry **GenAI semantic conventions**
emit spans for agent runs, model calls and tool calls. `agent-trace import --format otlp` turns
those traces into agent-trace traces and runs the rules on them, so you can analyze agents you
already instrument, without an adapter.

```sh
agent-trace import --format otlp --input traces.otlp.jsonl --fail-on high
```

Every OpenTelemetry trace in the file becomes one agent-trace trace (`otel/<service>/<root span>`).
Importing the same file again skips traces already imported.

## Getting the file

The importer reads OTLP/JSON: one `ExportTraceServiceRequest` (`{"resourceSpans": [...]}`) per
file, or one per line. The OpenTelemetry Collector's `file` exporter writes the second form. A
minimal Collector that receives from your application and writes a file:

```yaml
receivers:
  otlp:
    protocols:
      http:
        endpoint: 127.0.0.1:4318     # point OTEL_EXPORTER_OTLP_ENDPOINT here
exporters:
  file:
    path: ./agent-traces.otlp.jsonl  # newline-delimited OTLP JSON
service:
  pipelines:
    traces:
      receivers: [otlp]
      exporters: [file]
```

**Turn on content capture.** Prompts, messages, tool arguments and tool results are opt-in in
OpenTelemetry. Without them, agent-trace still records every agent, model and tool call, but it
cannot tell what caused a tool call, and the causal rules (AT-002, AT-003, AT-006) cannot fire.
The import says so when content is missing. The current variable in OpenTelemetry's Python
instrumentations is `OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT=SPAN_ONLY`; check your
instrumentation's documentation, as the conventions are still in development.

Content capture records what your users and tools sent to the model. agent-trace redacts it on
import like any other trace, but the Collector's file is not redacted: protect it accordingly.

## Mapping (`otel-genai/1`)

Based on the GenAI conventions as released in semantic-conventions v1.41.0 and as of the
semantic-conventions-genai repository (November 2026). Both are marked *Development*; the mapping
version is recorded on every imported trace (`otel_mapping`).

| Span (`gen_ai.operation.name`) | Events |
|---|---|
| `invoke_agent`, `invoke_workflow`, `invoke_*` | `agent_started` … `agent_completed`. An agent span inside another agent: `agent_delegated`, then its output (`gen_ai.output.messages`) as `agent_message_sent` / `agent_message_received`, lower-trust if that agent saw lower-trust content |
| `chat`, `generate_content`, `text_completion`, `realtime_inference` | first user message (`gen_ai.input.messages`) as `user_prompt_received`; `model_request`; `model_response` with text, tool call IDs, finish reasons and token usage |
| `execute_tool`, or an MCP `tools/call` span (`mcp.method.name`) without one | `tool_call_requested` (`gen_ai.tool.call.arguments`), `tool_call_executed`, `tool_result_received` (`gen_ai.tool.call.result`, **lower-trust**), `tool_call_completed` or `tool_call_failed` (span status error) |
| everything else (HTTP, database, framework internals) | skipped; counted in `ignored_spans` |

An MCP `tools/call` span inside an `execute_tool` span is the same call and is not recorded twice.
Event times come from the spans. Agent names come from `gen_ai.agent.name` (or `gen_ai.agent.id`);
the outermost agent is the trace's default agent.

### Links: only from the data

agent-trace never infers causality from timing. Links come from:

- **Tool call IDs:** a `tool_call_requested` is caused by the `model_response` whose output
  messages contain a `tool_call` part with its `gen_ai.tool.call.id`.
- **Input messages:** a `model_request` has the prompt and the tool results whose
  `tool_call_response` parts appear in its input as its context.
- **Span structure:** a tool call's lifecycle; a tool that runs an agent (`invoke_agent` inside
  `execute_tool`, e.g. "agents as tools") has that agent's report as the cause of its result; a
  sub-agent's report has the lower-trust content that agent saw as its context.

So an injection fetched by a sub-agent, passed back as a tool result, and followed by a privileged
call of the orchestrator is reported as AT-006 with the full path — when content was captured.

### Attribute encodings

Message attributes may be JSON strings (semconv v1.41 on spans) or structured OTLP values
(`arrayValue` / `kvlistValue`, the current spec); both are read. Message parts of type `text`,
`tool_call` and `tool_call_response` are used. `gen_ai.provider.name` is read, with the
deprecated `gen_ai.system` as a fallback.

## Limits

- **File import only.** There is no built-in OTLP receiver: agent-trace opens no listening port.
  Use the Collector as shown above.
- **Other conventions** (OpenInference `llm.*` / `tool.*` attributes, OpenLLMetry's indexed
  `gen_ai.prompt.N.*`) are not mapped; their spans are skipped.
- The GenAI conventions are still changing. Unknown operation names are skipped, not guessed;
  new mappings get a new `otel_mapping` version.
- At most 100,000 spans and 512 MiB per file.
