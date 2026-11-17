//! MCP proxy: sits between an MCP client (Claude Code, Cursor, Claude Desktop, a custom agent)
//! and an upstream MCP server, forwards the traffic and records it. The proxies of one client
//! session can share one trace (see [`Proxy`]).
//!
//! What is recorded:
//! * `tools/call`: request, policy decision, execution, result (lower-trust) and outcome, the
//!   same lifecycle as the lab ([`crate::gated_tool_call`]).
//! * `tools/list`, `resources/read`, `prompts/get`: the returned content as
//!   `external_content_observed` (lower-trust), so poisoned tool descriptions and injected
//!   resource or prompt text are scanned by AT-001/AT-005.
//!
//! Causality: the proxy sees tool traffic, not the model's context. It never invents a
//! `caused_by` link. A tool request instead lists the lower-trust content returned earlier in
//! the session as `context_event_ids`, marked with
//! [`LINK_BASIS_KEY`] = [`LINK_BASIS_SESSION_CONTEXT`]; rules report such findings with
//! medium confidence. Which content counts is set by [`ProxyConfig::taint_sources`].
//! Tool descriptions from `tools/list` are scanned but never linked: they are in every
//! session, so linking them would mark every privileged call.

use std::sync::{Arc, Mutex};

use agent_trace_core::rules::{LINK_BASIS_KEY, LINK_BASIS_SESSION_CONTEXT, TAINT_SOURCE_KEY};
use agent_trace_core::{
    Decision, EventKind, EventSpec, Origin, PolicyOutcome, ToolPolicy, ToolState, TraceAccess,
    TraceRecorder, TraceStatus, TrustLevel, glob_match,
};
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, GetPromptRequestParams,
    GetPromptResponse, Implementation, ListPromptsResult, ListResourceTemplatesResult,
    ListResourcesResult, ListToolsResult, PaginatedRequestParams, PromptsCapability,
    ReadResourceRequestParams, ReadResourceResponse, ResourceContents, ResourcesCapability,
    ServerCapabilities, ServerConfig,
};
use rmcp::service::{NotificationContext, RequestContext};
use rmcp::{ErrorData, RoleServer, ServerHandler, ServiceError, ServiceExt};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::adapter::{CallSpec, McpSession};
use crate::lab::record_gate;

/// At most this many earlier lower-trust events are linked to one tool request (newest kept).
pub const MAX_SESSION_CONTEXT: usize = 256;

/// What the proxy does with a call its policy denies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyMode {
    /// Record and forward everything; a denial is recorded as "would deny".
    #[default]
    Observe,
    /// Answer denied calls with a tool error; they never reach the upstream server.
    Enforce,
}

impl ProxyMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observe => "observe",
            Self::Enforce => "enforce",
        }
    }
}

/// Proxy settings.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Name of this proxied server (shown in the trace name `proxy/<name>`).
    pub name: String,
    pub mode: ProxyMode,
    pub policy: ToolPolicy,
    /// Sources whose content counts as untrusted session context (`*` wildcards): tool names
    /// for tool results, `resource:<uri>` for resources, `prompt:<name>` for prompts.
    pub taint_sources: Vec<String>,
    /// What the proxy connects to (server program or URL without credentials), for the trace.
    pub endpoint: Option<String>,
}

impl ProxyConfig {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            mode: ProxyMode::default(),
            policy: ToolPolicy::default(),
            taint_sources: vec!["*".into()],
            endpoint: None,
        }
    }

    fn taints(&self, source: &str) -> bool {
        self.taint_sources.iter().any(|p| glob_match(p, source))
    }

    /// The policy verdict on a tool call, before the mode is applied.
    fn evaluate(
        &self,
        tool: &str,
        arguments: &Map<String, Value>,
        tainted: &[(Uuid, String)],
    ) -> PolicyOutcome {
        let sources: Vec<&str> = tainted.iter().map(|(_, s)| s.as_str()).collect();
        self.policy.evaluate_in_session(tool, arguments, &sources)
    }
}

/// Apply `mode` to a policy verdict: in observe mode a denial becomes an allow that records
/// what would have been denied. Returns the effective outcome and the extra fields for the
/// decision payload.
pub fn apply_mode(mode: ProxyMode, verdict: PolicyOutcome) -> (PolicyOutcome, Map<String, Value>) {
    let mut extra = Map::new();
    extra.insert("mode".into(), mode.as_str().into());
    if mode == ProxyMode::Observe && verdict.decision == Decision::Deny {
        extra.insert("would_deny".into(), true.into());
        let outcome = PolicyOutcome {
            decision: Decision::Allow,
            reason: format!("observe mode, not enforced; would deny: {}", verdict.reason),
        };
        return (outcome, extra);
    }
    (verdict, extra)
}

/// Trace metadata key: number of proxies currently connected to the trace. The trace is
/// `completed` when the last one disconnects.
pub const OPEN_CONNECTIONS_KEY: &str = "open_proxy_connections";

/// Why recording failed.
#[derive(Debug)]
enum RecordError {
    /// The connection was already finished.
    Finished,
    /// The trace store failed.
    Access(String),
}

impl RecordError {
    fn to_mcp(&self) -> ErrorData {
        match self {
            Self::Finished => ErrorData::internal_error("agent-trace proxy is shutting down", None),
            Self::Access(e) => {
                ErrorData::internal_error(format!("agent-trace could not record: {e}"), None)
            }
        }
    }
}

struct Inner {
    upstream: McpSession,
    config: ProxyConfig,
    trace: Arc<dyn TraceAccess>,
    /// This connection's `mcp-server-connected` event, parent of its events.
    /// `None` after [`Proxy::finish`].
    connection: Mutex<Option<Uuid>>,
}

/// The proxy: an MCP server handler that forwards to `upstream` and records into `trace`.
///
/// Several proxies (one per MCP server of a client) may write to the same trace through a
/// shared [`TraceAccess`]. Untrusted content returned by any of them then counts for the
/// calls of all of them: an injection that arrives through one server and a privileged call
/// to another are in one trace, and the call is linked to the content.
#[derive(Clone)]
pub struct Proxy {
    inner: Arc<Inner>,
}

/// The main agent's `agent_started` of the trace; recorded by the first proxy.
fn main_started(rec: &mut TraceRecorder) -> Uuid {
    if let Some(e) = rec
        .events()
        .iter()
        .find(|e| e.kind == EventKind::AgentStarted && e.agent_id.is_none())
    {
        return e.event_id;
    }
    rec.set_trace_metadata(
        "notice",
        "Recorded by the agent-trace MCP proxy: tool traffic is recorded, the model's context \
         is not. Links to earlier content are session context, not observed causes.",
    );
    rec.record(EventSpec::new(
        EventKind::AgentStarted,
        Origin::System,
        TrustLevel::Trusted,
        "mcp-client",
    ))
}

fn open_connections(rec: &TraceRecorder) -> u64 {
    rec.trace()
        .metadata
        .get(OPEN_CONNECTIONS_KEY)
        .and_then(Value::as_u64)
        .unwrap_or(0)
}

/// Untrusted content of the whole trace that counts as session context: (event, source).
fn tainted(rec: &TraceRecorder) -> Vec<(Uuid, String)> {
    rec.events()
        .iter()
        .filter_map(|e| {
            e.metadata
                .get(TAINT_SOURCE_KEY)
                .and_then(Value::as_str)
                .map(|label| (e.event_id, label.to_owned()))
        })
        .collect()
}

impl Proxy {
    /// Connect this proxy to `trace` (which may be shared with other proxies of the same
    /// client session) and record the connection.
    pub fn new(
        upstream: McpSession,
        trace: Arc<dyn TraceAccess>,
        config: ProxyConfig,
    ) -> anyhow::Result<Self> {
        let mut connection = None;
        trace
            .with_recorder(&mut |rec| {
                let main = main_started(rec);
                rec.set_trace_metadata(OPEN_CONNECTIONS_KEY, open_connections(rec) + 1);
                rec.set_status(TraceStatus::Running);
                connection = Some(
                    rec.record(
                        upstream.mcp_metadata(
                            EventSpec::new(
                                EventKind::AgentDecision,
                                Origin::System,
                                TrustLevel::Trusted,
                                "mcp-server-connected",
                            )
                            .payload(json!({
                                "proxy": config.name,
                                "mode": config.mode.as_str(),
                                "upstream": upstream.server_name,
                                "upstream_version": upstream.server_version,
                                "endpoint": config.endpoint,
                                "taint_sources": config.taint_sources,
                                "policy": serde_json::to_value(&config.policy).unwrap_or(Value::Null),
                            }))
                            .parent(main)
                            .meta("proxy", config.name.clone()),
                        ),
                    ),
                );
            })
            .map_err(|e| anyhow::anyhow!("cannot record the proxy connection: {e}"))?;
        Ok(Self {
            inner: Arc::new(Inner {
                upstream,
                config,
                trace,
                connection: Mutex::new(connection),
            }),
        })
    }

    /// The id of the trace being recorded.
    pub fn trace_id(&self) -> Uuid {
        self.inner.trace.trace_id()
    }

    fn connection(&self) -> Option<Uuid> {
        *self
            .inner
            .connection
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Run `f` with the recorder and this connection's event, under the trace's lock.
    fn with<R>(&self, f: impl FnOnce(&mut TraceRecorder, Uuid) -> R) -> Result<R, RecordError> {
        let connection = self.connection().ok_or(RecordError::Finished)?;
        let mut f = Some(f);
        let mut out = None;
        self.inner
            .trace
            .with_recorder(&mut |rec| {
                if let Some(f) = f.take() {
                    out = Some(f(rec, connection));
                }
            })
            .map_err(|e| RecordError::Access(e.to_string()))?;
        out.ok_or(RecordError::Finished)
    }

    /// Record the end of this connection; the trace is `completed` when no other proxy is
    /// connected to it any more. `ended_by` says why (e.g. `client_disconnected`, `signal`).
    /// Later calls do nothing.
    pub fn finish(&self, ended_by: &str) -> anyhow::Result<()> {
        let Some(connection) = self.connection() else {
            return Ok(());
        };
        let upstream = &self.inner.upstream;
        let result = self.inner.trace.with_recorder(&mut |rec| {
            rec.record(
                upstream.mcp_metadata(
                    EventSpec::new(
                        EventKind::AgentDecision,
                        Origin::System,
                        TrustLevel::Trusted,
                        "mcp-server-disconnected",
                    )
                    .payload(json!({"proxy": self.inner.config.name, "ended_by": ended_by}))
                    .parent(connection),
                ),
            );
            let open = open_connections(rec).saturating_sub(1);
            rec.set_trace_metadata(OPEN_CONNECTIONS_KEY, open);
            if open == 0 {
                let main = main_started(rec);
                rec.record(
                    EventSpec::new(
                        EventKind::AgentCompleted,
                        Origin::System,
                        TrustLevel::Trusted,
                        "mcp-client",
                    )
                    .payload(json!({"ended_by": ended_by}))
                    .parent(main),
                );
                rec.set_trace_metadata("ended_by", ended_by);
                rec.set_status(TraceStatus::Completed);
            }
        });
        *self
            .inner
            .connection
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
        result.map_err(|e| anyhow::anyhow!("cannot record the end of the session: {e}"))
    }

    /// Serve the client on this process's stdin/stdout until it disconnects or `shutdown`
    /// completes, then finish the connection. It is also finished when the handshake fails,
    /// before the error is returned. Returns why the session ended.
    pub async fn serve_stdio(
        self,
        shutdown: impl std::future::Future<Output = ()>,
    ) -> anyhow::Result<&'static str> {
        let running = match self.clone().serve(rmcp::transport::stdio()).await {
            Ok(running) => running,
            Err(e) => {
                let _ = self.finish("initialize_failed");
                return Err(anyhow::Error::new(e)
                    .context("MCP initialize handshake with the client failed"));
            }
        };
        let ended_by = tokio::select! {
            quit = running.waiting() => match quit {
                Ok(_) => "client_disconnected",
                Err(_) => "server_task_failed",
            },
            () = shutdown => "signal",
        };
        self.finish(ended_by)?;
        Ok(ended_by)
    }

    /// The label of untrusted content from `source` in this proxy (`<name>:<source>`).
    fn label(&self, source: &str) -> String {
        format!("{}:{source}", self.inner.config.name)
    }

    /// Record upstream content that the model may read, and mark it as session context if
    /// `source` is a taint source and `link` is set. Recording errors are logged, never
    /// returned: the content is forwarded either way.
    fn observe(&self, source: &str, method: &str, payload: Value, link: bool) {
        let upstream = &self.inner.upstream;
        let config = &self.inner.config;
        let label = self.label(source);
        let recorded = self.with(|rec, connection| {
            let mut spec = upstream
                .mcp_metadata(
                    EventSpec::new(
                        EventKind::ExternalContentObserved,
                        Origin::McpTool,
                        TrustLevel::LowerTrust,
                        source,
                    )
                    .payload(payload)
                    .parent(connection),
                )
                .meta("jsonrpc_method", method);
            if link && config.taints(source) {
                spec = spec.meta(TAINT_SOURCE_KEY, label);
            }
            rec.record(spec);
        });
        if let Err(RecordError::Access(e)) = recorded {
            tracing::warn!("agent-trace could not record {method}: {e}");
        }
    }

    async fn proxied_call(
        &self,
        request: CallToolRequestParams,
    ) -> Result<CallToolResult, ErrorData> {
        let upstream = &self.inner.upstream;
        let config = &self.inner.config;
        let tool = request.name.to_string();
        let arguments = request.arguments.clone().unwrap_or_default();

        // Request, decision and (if allowed) execution, in one access to the trace.
        let gate = self.with(|rec, connection| {
            let tainted = tainted(rec);
            let verdict = config.evaluate(&tool, &arguments, &tainted);
            let (effective, extra) = apply_mode(config.mode, verdict);
            let start = tainted.len().saturating_sub(MAX_SESSION_CONTEXT);
            let context: Vec<Uuid> = tainted[start..].iter().map(|(id, _)| *id).collect();
            let mut spec = upstream
                .mcp_metadata(
                    EventSpec::new(
                        EventKind::ToolCallRequested,
                        Origin::Agent,
                        TrustLevel::Unknown,
                        &tool,
                    )
                    .payload(json!({"tool": tool, "arguments": arguments}))
                    .parent(connection)
                    .context(context.iter().copied())
                    .tool_state(ToolState::Requested),
                )
                .meta("privileged", config.policy.is_privileged(&tool))
                .meta("jsonrpc_method", "tools/call")
                .meta("proxy", config.name.clone());
            if !context.is_empty() {
                spec = spec.meta(LINK_BASIS_KEY, LINK_BASIS_SESSION_CONTEXT);
            }
            if start > 0 {
                spec = spec.meta("session_context_truncated", true);
            }
            let (request_event, decision_event) =
                record_gate(rec, spec, None, &tool, &effective, extra);
            let call = CallSpec {
                request_event,
                caused_by: decision_event,
                agent: None,
                mock_tool: false,
            };
            let executed = (effective.decision == Decision::Allow)
                .then(|| upstream.record_executed(rec, &call, &tool));
            (call, effective, executed)
        });
        let (call, executed) = match gate {
            Ok((_, outcome, _)) if outcome.decision == Decision::Deny => {
                return Ok(CallToolResult::error(vec![ContentBlock::text(format!(
                    "BLOCKED by agent-trace proxy policy: {}",
                    outcome.reason
                ))]));
            }
            Ok((call, _, executed)) => (Some(call), executed),
            Err(RecordError::Access(e)) if config.mode == ProxyMode::Enforce => {
                // Without the session's history there is no decision: fail closed.
                return Ok(CallToolResult::error(vec![ContentBlock::text(format!(
                    "BLOCKED: agent-trace could not check this call against the session \
                     ({e}); in enforce mode unchecked calls are not forwarded"
                ))]));
            }
            Err(RecordError::Access(e)) => {
                tracing::warn!("agent-trace could not record tools/call {tool}: {e}");
                (None, None)
            }
            Err(e @ RecordError::Finished) => return Err(e.to_mcp()),
        };

        let response = upstream.call_tool_raw(request).await;
        if let (Some(call), Some(executed)) = (call, executed) {
            let recorded = self.with(|rec, _| {
                let mut meta = Map::new();
                if config.taints(&tool) {
                    meta.insert(TAINT_SOURCE_KEY.into(), self.label(&tool).into());
                }
                upstream.record_result(
                    rec,
                    &call,
                    executed,
                    &tool,
                    response.as_ref().map_err(|(_, text)| text.as_str()),
                    meta,
                );
            });
            if let Err(RecordError::Access(e)) = recorded {
                tracing::warn!("agent-trace could not record the result of {tool}: {e}");
            }
        }
        response.map_err(|(error, text)| {
            error.unwrap_or_else(|| {
                ErrorData::internal_error(format!("upstream MCP server: {text}"), None)
            })
        })
    }
}

fn upstream_error(e: ServiceError) -> ErrorData {
    match e {
        ServiceError::McpError(e) => e,
        other => ErrorData::internal_error(format!("upstream MCP server: {other}"), None),
    }
}

fn content_text(blocks: impl IntoIterator<Item = String>) -> String {
    blocks.into_iter().collect::<Vec<_>>().join("\n")
}

impl ServerHandler for Proxy {
    fn get_info(&self) -> ServerConfig {
        let upstream = &self.inner.upstream;
        let mut capabilities = ServerCapabilities::builder().enable_tools().build();
        // Only what the proxy forwards: no subscriptions or list-changed notifications.
        if upstream.capabilities.resources.is_some() {
            capabilities.resources = Some(ResourcesCapability::default());
        }
        if upstream.capabilities.prompts.is_some() {
            capabilities.prompts = Some(PromptsCapability::default());
        }
        let config = ServerConfig::new(capabilities).with_server_info(
            Implementation::new(
                upstream.server_name.clone(),
                upstream.server_version.clone(),
            )
            .with_title(format!(
                "{} (recorded by agent-trace proxy, {} mode)",
                upstream.server_name,
                self.inner.config.mode.as_str()
            )),
        );
        match &upstream.instructions {
            Some(text) => config.with_instructions(text.clone()),
            None => config,
        }
    }

    async fn on_initialized(&self, context: NotificationContext<RoleServer>) {
        if let Some(info) = context.peer.peer_info() {
            let client = &info.client_info;
            let _ = self.with(|rec, _| {
                rec.set_trace_metadata("mcp_client", client.name.clone());
                rec.set_trace_metadata("mcp_client_version", client.version.clone());
            });
        }
    }

    async fn list_tools(
        &self,
        request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let result = self
            .inner
            .upstream
            .peer()
            .list_tools(request)
            .await
            .map_err(upstream_error)?;
        let tools: Vec<Value> = result
            .tools
            .iter()
            .map(|t| {
                json!({
                    "name": t.name,
                    "description": t.description,
                    "input_schema": Value::Object((*t.input_schema).clone()),
                })
            })
            .collect();
        self.observe(
            "tools/list",
            "tools/list",
            json!({"method": "tools/list", "tools": tools}),
            false,
        );
        Ok(result)
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        self.proxied_call(request).await.map(Into::into)
    }

    async fn list_resources(
        &self,
        request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, ErrorData> {
        self.inner
            .upstream
            .peer()
            .list_resources(request)
            .await
            .map_err(upstream_error)
    }

    async fn list_resource_templates(
        &self,
        request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourceTemplatesResult, ErrorData> {
        self.inner
            .upstream
            .peer()
            .list_resource_templates(request)
            .await
            .map_err(upstream_error)
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, ErrorData> {
        let uri = request.uri.clone();
        let result = self
            .inner
            .upstream
            .peer()
            .read_resource(request)
            .await
            .map_err(upstream_error)?;
        let mut blobs = 0;
        let text = content_text(result.contents.iter().filter_map(|c| match c {
            ResourceContents::TextResourceContents { text, .. } => Some(text.clone()),
            // Binary and future content kinds are counted, not recorded.
            _ => {
                blobs += 1;
                None
            }
        }));
        self.observe(
            &format!("resource:{uri}"),
            "resources/read",
            json!({"method": "resources/read", "uri": uri, "content": text, "binary_parts": blobs}),
            true,
        );
        Ok(result.into())
    }

    async fn list_prompts(
        &self,
        request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListPromptsResult, ErrorData> {
        self.inner
            .upstream
            .peer()
            .list_prompts(request)
            .await
            .map_err(upstream_error)
    }

    async fn get_prompt(
        &self,
        request: GetPromptRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<GetPromptResponse, ErrorData> {
        let name = request.name.clone();
        let arguments = request.arguments.clone();
        let result = self
            .inner
            .upstream
            .peer()
            .get_prompt(request)
            .await
            .map_err(upstream_error)?;
        let text = content_text(
            result
                .messages
                .iter()
                .filter_map(|m| m.content.as_text().map(|t| t.text.clone())),
        );
        self.observe(
            &format!("prompt:{name}"),
            "prompts/get",
            json!({"method": "prompts/get", "name": name, "arguments": arguments, "content": text}),
            true,
        );
        Ok(result.into())
    }
}
