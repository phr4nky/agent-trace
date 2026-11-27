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
//!
//! Tool pinning ([`crate::pins`]): with [`ProxyConfig::pins`] set, the proxy compares the
//! server's tool definitions with their pins before the first call and on every complete
//! `tools/list`. Changed tools are reported (AT-008); in enforce mode they are hidden from
//! `tools/list` and their calls are denied.
//!
//! Ask mode: a call the session heuristics would deny ([`DenialClass::Askable`]) is put to
//! the user through MCP elicitation (`elicitation/create`) when the client announced that
//! capability. The trace records the `ask` decision and then how it was resolved
//! ([`HUMAN_APPROVAL_KEY`]). Without an accepted answer the call is denied (fail closed).
//!
//! Profiles ([`ToolProfile`]): a tool outside the active profile is denied in enforce and
//! ask mode (never asked) and hidden from `tools/list`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use agent_trace_core::rules::{
    HUMAN_APPROVAL_KEY, LINK_BASIS_KEY, LINK_BASIS_SESSION_CONTEXT, TAINT_SOURCE_KEY,
    TOOL_PINS_ACTION_BLOCKED, TOOL_PINS_ACTION_KEY, TOOL_PINS_ACTION_OBSERVED, TOOL_PINS_ADDED_KEY,
    TOOL_PINS_CHANGED, TOOL_PINS_CHANGED_KEY, TOOL_PINS_KEY,
};
use agent_trace_core::{
    Decision, DenialClass, EventKind, EventSpec, Origin, PolicyOutcome, Redactor, ToolPolicy,
    ToolProfile, ToolState, TraceAccess, TraceRecorder, TraceStatus, TrustLevel, glob_match,
};
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, ElicitRequestParams,
    ElicitationAction, ElicitationSchema, GetPromptRequestParams, GetPromptResponse,
    Implementation, ListPromptsResult, ListResourceTemplatesResult, ListResourcesResult,
    ListToolsResult, PaginatedRequestParams, PromptsCapability, ReadResourceRequestParams,
    ReadResourceResponse, ResourceContents, ResourcesCapability, ServerCapabilities, ServerConfig,
    Tool,
};
use rmcp::service::{ElicitationMode, NotificationContext, Peer, RequestContext};
use rmcp::{ErrorData, RoleServer, ServerHandler, ServiceError, ServiceExt};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::adapter::{CallSpec, McpSession};
use crate::lab::record_gate;
use crate::pins::{self, PinStore};

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
    /// As enforce, but ask a human about calls denied by a session heuristic (a privileged
    /// call after lower-trust content, a destination not on the allowlist). Hard denials
    /// (canary tokens, tools outside the profile) are never asked.
    Ask,
}

impl ProxyMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observe => "observe",
            Self::Enforce => "enforce",
            Self::Ask => "ask",
        }
    }

    /// Whether denials take effect (enforce and ask mode).
    pub fn gates(self) -> bool {
        self != Self::Observe
    }
}

/// How long the proxy waits for the user's answer to an approval question by default.
pub const DEFAULT_ASK_TIMEOUT: Duration = Duration::from_secs(300);

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
    /// Where tool definitions are pinned; `None` turns pinning off.
    pub pins: Option<PinStore>,
    /// The active task profile: tools outside it are denied (hard) and hidden in enforce and
    /// ask mode, recorded as "would deny" in observe mode.
    pub profile: Option<ToolProfile>,
    /// How long to wait for the user's answer in ask mode (then the call is denied).
    pub ask_timeout: Duration,
}

impl ProxyConfig {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            mode: ProxyMode::default(),
            policy: ToolPolicy::default(),
            taint_sources: vec!["*".into()],
            endpoint: None,
            pins: None,
            profile: None,
            ask_timeout: DEFAULT_ASK_TIMEOUT,
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
        self.policy
            .evaluate_scoped(tool, arguments, &sources, self.profile.as_ref())
    }

    /// Whether `tools/list` shows `tool`: everything in observe mode, otherwise only the
    /// tools of the active profile.
    fn lists(&self, tool: &str) -> bool {
        !self.mode.gates() || self.profile.as_ref().is_none_or(|p| p.allows(tool))
    }
}

/// Apply `mode` to a policy verdict: in observe mode a denial becomes an allow that records
/// what would have been denied; in ask mode an askable denial becomes [`Decision::Ask`].
/// Hard denials stay denials in enforce and ask mode. Returns the effective outcome and the
/// extra fields for the decision payload.
pub fn apply_mode(mode: ProxyMode, verdict: PolicyOutcome) -> (PolicyOutcome, Map<String, Value>) {
    let mut extra = Map::new();
    extra.insert("mode".into(), mode.as_str().into());
    if mode == ProxyMode::Observe && verdict.decision == Decision::Deny {
        extra.insert("would_deny".into(), true.into());
        let outcome = PolicyOutcome::allow(format!(
            "observe mode, not enforced; would deny: {}",
            verdict.reason
        ));
        return (outcome, extra);
    }
    if mode == ProxyMode::Ask && verdict.is_askable() {
        let outcome = PolicyOutcome {
            decision: Decision::Ask,
            reason: format!("approval required: {}", verdict.reason),
            class: DenialClass::Askable,
        };
        return (outcome, extra);
    }
    (verdict, extra)
}

/// How an `ask` decision of the proxy was resolved (the [`HUMAN_APPROVAL_KEY`] value).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Approval {
    /// The user approved the call.
    Accepted,
    /// The user answered no (declined, or accepted the form without approving).
    Declined,
    /// The user dismissed the question.
    Cancelled,
    /// No answer within the ask timeout.
    Timeout,
    /// The client did not announce form elicitation in `initialize`.
    Unsupported,
    /// The elicitation request failed.
    Error(String),
}

impl Approval {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Declined => "declined",
            Self::Cancelled => "cancelled",
            Self::Timeout => "timeout",
            Self::Unsupported => "unsupported",
            Self::Error(_) => "error",
        }
    }

    fn explain(&self) -> String {
        match self {
            Self::Accepted => "approved by the user".into(),
            Self::Declined => "the user declined".into(),
            Self::Cancelled => "the user cancelled the question".into(),
            Self::Timeout => "no answer from the user in time".into(),
            Self::Unsupported => {
                "the MCP client does not support elicitation, so no one could be asked".into()
            }
            Self::Error(e) => format!("the approval question failed ({e})"),
        }
    }
}

/// Name of the yes/no field of the approval form.
const APPROVE_FIELD: &str = "approve";
/// At most this many characters of the arguments are shown in the approval question.
const MAX_ASK_ARGUMENTS: usize = 1000;

/// Ask the user through MCP elicitation whether `tool` may run. Only an accepted form with
/// `approve = true` approves; anything else is a refusal.
pub async fn ask_user(
    peer: &Peer<RoleServer>,
    server: &str,
    tool: &str,
    arguments: &Map<String, Value>,
    reason: &str,
    timeout: Duration,
) -> Approval {
    if !peer
        .supported_elicitation_modes()
        .contains(&ElicitationMode::Form)
    {
        return Approval::Unsupported;
    }
    let mut args = Redactor::new().scrub(&Value::Object(arguments.clone()).to_string());
    if args.chars().count() > MAX_ASK_ARGUMENTS {
        args = args.chars().take(MAX_ASK_ARGUMENTS).collect::<String>() + "…";
    }
    let message = format!(
        "agent-trace: allow the tool call `{tool}` on MCP server \"{server}\"?\n\
         Why you are asked: {reason}\n\
         Arguments: {args}"
    );
    let schema = match ElicitationSchema::builder()
        .required_bool_with(APPROVE_FIELD, |b| {
            b.title("Allow this call")
                .description("Yes runs the call once; no blocks it.")
                .with_default(false)
        })
        .build()
    {
        Ok(schema) => schema,
        Err(e) => return Approval::Error(e.to_owned()),
    };
    let request = ElicitRequestParams::FormElicitationParams {
        meta: None,
        message,
        requested_schema: schema,
    };
    match peer
        .create_elicitation_with_timeout(request, Some(timeout))
        .await
    {
        Ok(result) => match result.action {
            ElicitationAction::Accept => {
                let approved = result
                    .content
                    .as_ref()
                    .and_then(|c| c.get(APPROVE_FIELD))
                    .and_then(Value::as_bool)
                    == Some(true);
                if approved {
                    Approval::Accepted
                } else {
                    Approval::Declined
                }
            }
            ElicitationAction::Decline => Approval::Declined,
            ElicitationAction::Cancel => Approval::Cancelled,
            // A future action is not an approval.
            _ => Approval::Declined,
        },
        Err(ServiceError::Timeout { .. }) => Approval::Timeout,
        Err(e) => Approval::Error(e.to_string()),
    }
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
    pins: Mutex<PinState>,
}

/// What this connection knows about the server's tools and their pins.
#[derive(Default)]
struct PinState {
    /// The tools were compared with their pins at least once.
    checked: bool,
    /// Tools whose definitions differ from their pins, with the reason a call is denied.
    changed: HashMap<String, String>,
    /// The changed tools last recorded, so an unchanged situation is recorded once.
    reported: Vec<String>,
}

fn now_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
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
        let mut payload = json!({
            "proxy": config.name,
            "mode": config.mode.as_str(),
            "upstream": upstream.server_name,
            "upstream_version": upstream.server_version,
            "endpoint": config.endpoint,
            "taint_sources": config.taint_sources,
            "policy": serde_json::to_value(&config.policy).unwrap_or(Value::Null),
        });
        if let Some(profile) = &config.profile {
            payload["profile"] = json!({"name": profile.name, "tools": profile.tools});
        }
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
                            .payload(payload.clone())
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
                pins: Mutex::new(PinState::default()),
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
            .unwrap_or_else(std::sync::PoisonError::into_inner)
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
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
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

    fn pin_state(&self) -> std::sync::MutexGuard<'_, PinState> {
        self.inner
            .pins
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Compare the server's tools with their pins once per connection, before the first call.
    async fn ensure_pins_checked(&self) {
        if self.inner.config.pins.is_some() && !self.pin_state().checked {
            self.check_pins(None).await;
        }
    }

    /// Compare the server's complete tool list (`full_list`, or fetched now) with its pins:
    /// pin what is new, remember what changed, and record both. Errors are logged; a
    /// changed tool stays changed until the next complete list says otherwise.
    async fn check_pins(&self, full_list: Option<&[Tool]>) {
        let config = &self.inner.config;
        let upstream = &self.inner.upstream;
        let Some(store) = &config.pins else {
            return;
        };
        let fetched;
        let tools: &[Tool] = match full_list {
            Some(tools) => tools,
            None => match upstream.peer().list_all_tools().await {
                Ok(tools) => {
                    fetched = tools;
                    &fetched
                }
                Err(e) => {
                    tracing::warn!("agent-trace could not list the tools to check their pins: {e}");
                    return;
                }
            },
        };
        let pinned = match store.load(&config.name) {
            Ok(p) => p,
            Err(e) => {
                // Never overwrite a pin file that cannot be read: it may hold the evidence.
                tracing::warn!("agent-trace could not read the tool pins: {e:#}");
                return;
            }
        };
        let (check, file) = pins::check(
            &config.name,
            pinned.as_ref(),
            tools,
            Some(upstream.server_version.as_str()),
            &now_rfc3339(),
        );
        if (check.first_use || !check.added.is_empty())
            && let Err(e) = store.save(&file)
        {
            tracing::warn!("agent-trace could not save the tool pins: {e:#}");
        }
        let changed: Vec<String> = check.changed.iter().map(|c| c.tool.clone()).collect();
        let report_change = {
            let mut state = self.pin_state();
            state.checked = true;
            state.changed = check
                .changed
                .iter()
                .map(|c| {
                    let version = c
                        .pinned
                        .server_version
                        .as_deref()
                        .map(|v| format!(" (server version {v})"))
                        .unwrap_or_default();
                    (
                        c.tool.clone(),
                        format!(
                            "the definition of tool {:?} changed since it was pinned on {}{version}; \
                             review the change and accept it with `agent-trace pins reset {} --tool {}`",
                            c.tool, c.pinned.pinned_at, config.name, c.tool
                        ),
                    )
                })
                .collect();
            let new_situation = state.reported != changed;
            state.reported = changed.clone();
            !check.added.is_empty() || (!changed.is_empty() && new_situation)
        };
        let added: Vec<String> = check.added.iter().map(|(t, _)| t.clone()).collect();
        let action = if config.mode.gates() {
            TOOL_PINS_ACTION_BLOCKED
        } else {
            TOOL_PINS_ACTION_OBSERVED
        };
        let recorded = self.with(|rec, connection| {
            if check.first_use {
                rec.record(
                    EventSpec::new(
                        EventKind::AgentDecision,
                        Origin::Policy,
                        TrustLevel::Trusted,
                        "mcp-tools-pinned",
                    )
                    .payload(json!({
                        "proxy": config.name,
                        "upstream": upstream.server_name,
                        "upstream_version": upstream.server_version,
                        "tools": file.tools.keys().collect::<Vec<_>>(),
                        "pin_file": store.path(&config.name).display().to_string(),
                    }))
                    .parent(connection)
                    .meta("proxy", config.name.clone()),
                );
            }
            if report_change {
                let mut payload = pins::change_payload(&check);
                payload.insert("proxy".into(), config.name.clone().into());
                payload.insert("upstream".into(), upstream.server_name.clone().into());
                payload.insert(
                    "upstream_version".into(),
                    upstream.server_version.clone().into(),
                );
                payload.insert("mode".into(), config.mode.as_str().into());
                if !changed.is_empty() {
                    payload.insert("action".into(), action.into());
                }
                let mut spec = EventSpec::new(
                    EventKind::AgentDecision,
                    Origin::Policy,
                    TrustLevel::Trusted,
                    "mcp-tool-definitions-changed",
                )
                .payload(Value::Object(payload))
                .parent(connection)
                .meta("proxy", config.name.clone())
                .meta(TOOL_PINS_KEY, TOOL_PINS_CHANGED)
                .meta(TOOL_PINS_CHANGED_KEY, json!(changed))
                .meta(TOOL_PINS_ADDED_KEY, json!(added));
                if !changed.is_empty() {
                    spec = spec.meta(TOOL_PINS_ACTION_KEY, action);
                }
                rec.record(spec);
            }
        });
        if let Err(RecordError::Access(e)) = recorded {
            tracing::warn!("agent-trace could not record the tool pin check: {e}");
        }
    }

    /// Why a call of `tool` is denied by its pin, if it is.
    fn pin_denial(&self, tool: &str) -> Option<String> {
        self.pin_state().changed.get(tool).cloned()
    }

    async fn proxied_call(
        &self,
        request: CallToolRequestParams,
        peer: &Peer<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let upstream = &self.inner.upstream;
        let config = &self.inner.config;
        let tool = request.name.to_string();
        let arguments = request.arguments.clone().unwrap_or_default();
        self.ensure_pins_checked().await;
        let pin_denial = self.pin_denial(&tool);

        // Request, decision and (if allowed) execution, in one access to the trace.
        let gate = self.with(|rec, connection| {
            let tainted = tainted(rec);
            // A changed tool definition is a hard denial: it is never put to the user.
            let verdict = match pin_denial {
                Some(reason) => PolicyOutcome::deny(reason),
                None => config.evaluate(&tool, &arguments, &tainted),
            };
            let (effective, mut extra) = apply_mode(config.mode, verdict);
            if let Some(profile) = &config.profile {
                extra.insert("profile".into(), profile.name.clone().into());
            }
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
        let blocked = |reason: &str| {
            Ok(CallToolResult::error(vec![ContentBlock::text(format!(
                "BLOCKED by agent-trace proxy policy: {reason}"
            ))]))
        };
        let (call, executed) = match gate {
            Ok((_, outcome, _)) if outcome.decision == Decision::Deny => {
                return blocked(&outcome.reason);
            }
            Ok((asked, outcome, _)) if outcome.decision == Decision::Ask => {
                // The trace is not locked while the user thinks.
                let approval = ask_user(
                    peer,
                    &config.name,
                    &tool,
                    &arguments,
                    &outcome.reason,
                    config.ask_timeout,
                )
                .await;
                let resolved = self.with(|rec, _| {
                    record_approval(rec, upstream, &asked, &tool, &outcome, &approval)
                });
                match resolved {
                    Ok((call, Some(executed))) => (Some(call), Some(executed)),
                    Ok((_, None)) => {
                        return blocked(&format!("{}; {}", outcome.reason, approval.explain()));
                    }
                    Err(RecordError::Access(e)) => {
                        // An approval that cannot be recorded is not forwarded.
                        return Ok(CallToolResult::error(vec![ContentBlock::text(format!(
                            "BLOCKED: agent-trace could not record the approval of this call \
                             ({e}); unrecorded calls are not forwarded in ask mode"
                        ))]));
                    }
                    Err(e @ RecordError::Finished) => return Err(e.to_mcp()),
                }
            }
            Ok((call, _, executed)) => (Some(call), executed),
            Err(RecordError::Access(e)) if config.mode.gates() => {
                // Without the session's history there is no decision: fail closed.
                return Ok(CallToolResult::error(vec![ContentBlock::text(format!(
                    "BLOCKED: agent-trace could not check this call against the session \
                     ({e}); in {} mode unchecked calls are not forwarded",
                    config.mode.as_str()
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

/// Record how the `ask` decision of `asked` was resolved: a second `tool_policy_decision`
/// (allow or deny, with [`HUMAN_APPROVAL_KEY`]) caused by the first, and for an approved call
/// its execution. Returns the call spec for the result and the execution, if any.
fn record_approval(
    rec: &mut TraceRecorder,
    upstream: &McpSession,
    asked: &CallSpec,
    tool: &str,
    outcome: &PolicyOutcome,
    approval: &Approval,
) -> (CallSpec, Option<Uuid>) {
    let accepted = *approval == Approval::Accepted;
    let decision = if accepted {
        Decision::Allow
    } else {
        Decision::Deny
    };
    let mut payload = json!({
        "tool": tool,
        "decision": decision,
        "reason": format!("{}; {}", outcome.reason, approval.explain()),
        "outbound_request_sent": false,
        "mode": ProxyMode::Ask.as_str(),
        HUMAN_APPROVAL_KEY: approval.as_str(),
    });
    if let Approval::Error(e) = approval {
        payload["approval_error"] = e.clone().into();
    }
    let decided = rec.record(
        upstream.mcp_metadata(
            EventSpec::new(
                EventKind::ToolPolicyDecision,
                Origin::Policy,
                TrustLevel::Trusted,
                tool,
            )
            .payload(payload)
            .parent(asked.request_event)
            .caused_by(asked.caused_by)
            .tool_state(if accepted {
                ToolState::PolicyDecision
            } else {
                ToolState::Blocked
            }),
        ),
    );
    let call = CallSpec {
        request_event: asked.request_event,
        caused_by: decided,
        agent: None,
        mock_tool: false,
    };
    let executed = accepted.then(|| upstream.record_executed(rec, &call, tool));
    (call, executed)
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
        let first_page = request.as_ref().is_none_or(|r| r.cursor.is_none());
        let mut result = self
            .inner
            .upstream
            .peer()
            .list_tools(request)
            .await
            .map_err(upstream_error)?;
        if first_page && result.next_cursor.is_none() {
            self.check_pins(Some(&result.tools)).await;
        } else {
            self.ensure_pins_checked().await;
        }
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
        let config = &self.inner.config;
        let hidden: Vec<String> = result
            .tools
            .iter()
            .filter(|t| !config.lists(&t.name))
            .map(|t| t.name.to_string())
            .collect();
        let mut payload = json!({"method": "tools/list", "tools": tools});
        if let Some(profile) = &config.profile {
            payload["profile"] = profile.name.clone().into();
            payload["hidden_by_profile"] = json!(hidden);
        }
        self.observe("tools/list", "tools/list", payload, false);
        result.tools.retain(|t| config.lists(&t.name));
        if config.mode.gates() {
            // A changed definition never reaches the model in enforce or ask mode.
            let state = self.pin_state();
            result
                .tools
                .retain(|t| !state.changed.contains_key(t.name.as_ref()));
        }
        Ok(result)
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        self.proxied_call(request, &context.peer)
            .await
            .map(Into::into)
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
