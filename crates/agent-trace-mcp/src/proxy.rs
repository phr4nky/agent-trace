//! MCP proxy: sits between an MCP client (Claude Code, Cursor, Claude Desktop, a custom agent)
//! and an upstream MCP server, forwards the traffic and records it as one agent-trace trace.
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

use std::sync::{Arc, Mutex, MutexGuard};

use agent_trace_core::policy::host_of;
use agent_trace_core::rules::{LINK_BASIS_KEY, LINK_BASIS_SESSION_CONTEXT};
use agent_trace_core::{
    Decision, EventKind, EventSpec, Origin, PolicyOutcome, ToolPolicy, ToolState, TraceRecord,
    TraceRecorder, TrustLevel, glob_match,
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
}

impl ProxyConfig {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            mode: ProxyMode::default(),
            policy: ToolPolicy::default(),
            taint_sources: vec!["*".into()],
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
        let p = &self.policy;
        if p.is_outbound(tool)
            && let Some(destination) = p.disallowed_destination(arguments)
        {
            return deny(format!(
                "outbound destination host {:?} is not on the allowlist",
                host_of(&destination).unwrap_or_default()
            ));
        }
        if p.is_privileged(tool) && !tainted.is_empty() {
            let mut sources: Vec<&str> = Vec::new();
            for (_, s) in tainted.iter().rev() {
                if !sources.contains(&s.as_str()) {
                    sources.push(s);
                }
            }
            let shown = sources
                .iter()
                .take(3)
                .copied()
                .collect::<Vec<_>>()
                .join(", ");
            let more = if sources.len() > 3 { ", …" } else { "" };
            return deny(format!(
                "privileged tool requested after lower-trust content entered the session \
                 (from {shown}{more})"
            ));
        }
        PolicyOutcome {
            decision: Decision::Allow,
            reason: if p.is_outbound(tool) {
                "destination allowlisted; no lower-trust content in the session".into()
            } else if p.is_privileged(tool) {
                "privileged tool; no lower-trust content in the session".into()
            } else {
                "not a privileged tool".into()
            },
        }
    }
}

fn deny(reason: String) -> PolicyOutcome {
    PolicyOutcome {
        decision: Decision::Deny,
        reason,
    }
}

/// The recording state of one proxied session.
struct Session {
    rec: TraceRecorder,
    started: Uuid,
    /// Lower-trust content returned in this session that counts as context: (event, source).
    tainted: Vec<(Uuid, String)>,
}

struct Inner {
    upstream: McpSession,
    config: ProxyConfig,
    session: Mutex<Option<Session>>,
}

/// The proxy: an MCP server handler that forwards to `upstream` and records.
#[derive(Clone)]
pub struct Proxy {
    inner: Arc<Inner>,
}

impl Proxy {
    /// Start recording a session. `rec` is a fresh recorder (with a live sink, if wanted).
    pub fn new(upstream: McpSession, mut rec: TraceRecorder, config: ProxyConfig) -> Self {
        crate::lab::record_session_metadata(&mut rec, &upstream);
        rec.set_trace_metadata("proxy", config.name.clone());
        rec.set_trace_metadata("proxy_mode", config.mode.as_str());
        rec.set_trace_metadata("taint_sources", json!(config.taint_sources));
        rec.set_trace_metadata(
            "policy",
            serde_json::to_value(&config.policy).unwrap_or(Value::Null),
        );
        rec.set_trace_metadata(
            "notice",
            "Recorded by an MCP proxy: tool traffic is recorded, the model's context is not. \
             Links to earlier content are session context, not observed causes.",
        );
        let started = rec.record(
            upstream.mcp_metadata(
                EventSpec::new(
                    EventKind::AgentStarted,
                    Origin::System,
                    TrustLevel::Trusted,
                    "mcp-client",
                )
                .payload(json!({
                    "proxy": config.name,
                    "mode": config.mode.as_str(),
                    "upstream": upstream.server_name,
                })),
            ),
        );
        Self {
            inner: Arc::new(Inner {
                upstream,
                config,
                session: Mutex::new(Some(Session {
                    rec,
                    started,
                    tainted: Vec::new(),
                })),
            }),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Option<Session>> {
        // A panic while recording must not take the proxy down with it.
        self.inner
            .session
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Run `f` on the open session; `None` once the session is finished.
    fn with_session<R>(&self, f: impl FnOnce(&mut Session) -> R) -> Option<R> {
        self.lock().as_mut().map(f)
    }

    /// The id of the trace being recorded (`None` after [`Self::finish`]).
    pub fn trace_id(&self) -> Option<Uuid> {
        self.with_session(|s| s.rec.trace_id())
    }

    /// End the session and return the finished trace. `ended_by` says why
    /// (e.g. `client_disconnected`, `signal`). Later calls return `None`.
    pub fn finish(&self, ended_by: &str) -> Option<TraceRecord> {
        let mut session = self.lock().take()?;
        let upstream = &self.inner.upstream;
        session.rec.set_trace_metadata("ended_by", ended_by);
        session.rec.record(
            upstream.mcp_metadata(
                EventSpec::new(
                    EventKind::AgentCompleted,
                    Origin::System,
                    TrustLevel::Trusted,
                    "mcp-client",
                )
                .payload(json!({"ended_by": ended_by}))
                .parent(session.started),
            ),
        );
        Some(session.rec.finish())
    }

    /// Serve the client on this process's stdin/stdout until it disconnects or `shutdown`
    /// completes, then finish the trace. The trace is also finished when the handshake
    /// fails, before the error is returned.
    pub async fn serve_stdio(
        self,
        shutdown: impl std::future::Future<Output = ()>,
    ) -> anyhow::Result<Option<TraceRecord>> {
        let running = match self.clone().serve(rmcp::transport::stdio()).await {
            Ok(running) => running,
            Err(e) => {
                self.finish("initialize_failed");
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
        Ok(self.finish(ended_by))
    }

    /// Record upstream content that the model may read, and add it to the session context if
    /// `source` is a taint source and `link` is set.
    fn observe(&self, source: &str, method: &str, payload: Value, link: bool) {
        let upstream = &self.inner.upstream;
        let config = &self.inner.config;
        self.with_session(|s| {
            let id = s.rec.record(
                upstream.mcp_metadata(
                    EventSpec::new(
                        EventKind::ExternalContentObserved,
                        Origin::McpTool,
                        TrustLevel::LowerTrust,
                        source,
                    )
                    .payload(payload)
                    .parent(s.started)
                    .meta("jsonrpc_method", method),
                ),
            );
            if link && config.taints(source) {
                s.tainted.push((id, source.to_owned()));
            }
        });
    }

    async fn proxied_call(
        &self,
        request: CallToolRequestParams,
    ) -> Result<CallToolResult, ErrorData> {
        let upstream = &self.inner.upstream;
        let config = &self.inner.config;
        let tool = request.name.to_string();
        let arguments = request.arguments.clone().unwrap_or_default();

        // Request and decision.
        let gate = self.with_session(|s| {
            let verdict = config.evaluate(&tool, &arguments, &s.tainted);
            let (effective, extra) = match (config.mode, verdict.decision.clone()) {
                (ProxyMode::Observe, Decision::Deny) => (
                    PolicyOutcome {
                        decision: Decision::Allow,
                        reason: format!(
                            "observe mode, not enforced; would deny: {}",
                            verdict.reason
                        ),
                    },
                    json!({"mode": "observe", "would_deny": true}),
                ),
                (mode, _) => (verdict, json!({"mode": mode.as_str()})),
            };
            let start = s.tainted.len().saturating_sub(MAX_SESSION_CONTEXT);
            let context: Vec<Uuid> = s.tainted[start..].iter().map(|(id, _)| *id).collect();
            let mut spec = upstream
                .mcp_metadata(
                    EventSpec::new(
                        EventKind::ToolCallRequested,
                        Origin::Agent,
                        TrustLevel::Unknown,
                        &tool,
                    )
                    .payload(json!({"tool": tool, "arguments": arguments}))
                    .parent(s.started)
                    .context(context.iter().copied())
                    .tool_state(ToolState::Requested),
                )
                .meta("privileged", config.policy.is_privileged(&tool))
                .meta("jsonrpc_method", "tools/call");
            if !context.is_empty() {
                spec = spec.meta(LINK_BASIS_KEY, LINK_BASIS_SESSION_CONTEXT);
            }
            if start > 0 {
                spec = spec.meta("session_context_truncated", true);
            }
            let extra = match extra {
                Value::Object(m) => m,
                _ => Map::new(),
            };
            let (request_event, decision_event) =
                record_gate(&mut s.rec, spec, None, &tool, &effective, extra);
            (request_event, decision_event, effective)
        });
        let Some((request_event, decision_event, outcome)) = gate else {
            return Err(shutting_down());
        };
        if outcome.decision == Decision::Deny {
            return Ok(CallToolResult::error(vec![ContentBlock::text(format!(
                "BLOCKED by agent-trace proxy policy: {}",
                outcome.reason
            ))]));
        }

        // Execution.
        let spec = CallSpec {
            request_event,
            caused_by: decision_event,
            agent: None,
            mock_tool: false,
        };
        let executed_event = self
            .with_session(|s| upstream.record_executed(&mut s.rec, &spec, &tool))
            .ok_or_else(shutting_down)?;
        let response = upstream.call_tool_raw(request).await;
        self.with_session(|s| {
            let outcome = upstream.record_result(
                &mut s.rec,
                &spec,
                executed_event,
                &tool,
                response.as_ref().map_err(|(_, text)| text.as_str()),
            );
            if config.taints(&tool) {
                s.tainted.push((outcome.result_event, tool.clone()));
            }
        });
        response.map_err(|(error, text)| {
            error.unwrap_or_else(|| {
                ErrorData::internal_error(format!("upstream MCP server: {text}"), None)
            })
        })
    }
}

fn shutting_down() -> ErrorData {
    ErrorData::internal_error("agent-trace proxy is shutting down", None)
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
            self.with_session(|s| {
                s.rec.set_trace_metadata("mcp_client", client.name.clone());
                s.rec
                    .set_trace_metadata("mcp_client_version", client.version.clone());
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
