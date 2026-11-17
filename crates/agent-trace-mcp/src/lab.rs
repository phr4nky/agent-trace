//! Scripted demo agent for `examples/local-lab`, plus building blocks shared with the
//! LLM-driven agent (policy gate, lab recorder setup).
//!
//! The scripted agent is NOT a reasoning model. Every "decision" comes from the scenario
//! file and is recorded with `execution_mode = simulated` and `simulated_decision = true`.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::time::Duration;

use agent_trace_core::{
    Decision, EventKind, EventSpec, ExecutionMode, Origin, PolicyOutcome, ToolPolicy, ToolState,
    TraceRecord, TraceRecorder, TraceStatus, TrustLevel,
};
use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::adapter::{CallSpec, McpSession, ServerCommand};

pub const SCENARIO_NAMES: &[&str] = &[
    "benign",
    "prompt-injection",
    "exfil-attempt",
    "multi-agent-handoff",
];

/// One scripted step.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Step {
    /// A simulated agent decision (caused by the previous step's key event).
    Decide { rationale: String },
    /// Request an MCP tool; goes through the policy gate first.
    CallTool {
        tool: String,
        arguments: Map<String, Value>,
    },
    /// Hand a task to another agent, run its steps, and receive its report.
    Delegate {
        agent: String,
        task: String,
        steps: Vec<Step>,
        report: String,
    },
    /// Final answer to the user.
    Respond { text: String },
}

/// A scenario file from `examples/local-lab/scenarios`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scenario {
    pub name: String,
    pub title: String,
    pub description: String,
    pub user_prompt: String,
    /// Fixture document the task is about (used to brief LLM agents).
    #[serde(default)]
    pub document: Option<String>,
    /// Name of the top-level agent (default: `main`).
    #[serde(default)]
    pub agent: Option<String>,
    /// Name of the sub-agent an LLM orchestrator may delegate to (multi-agent scenarios).
    #[serde(default)]
    pub delegate_to: Option<String>,
    pub steps: Vec<Step>,
}

/// Paths of a local lab directory.
#[derive(Debug, Clone)]
pub struct LabPaths {
    pub root: PathBuf,
}

impl LabPaths {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }
    pub fn documents(&self) -> PathBuf {
        self.root.join("documents")
    }
    pub fn scenarios(&self) -> PathBuf {
        self.root.join("scenarios")
    }
    pub fn expected_findings(&self) -> PathBuf {
        self.root.join("expected-findings.json")
    }
    pub fn load_scenario(&self, name: &str) -> anyhow::Result<Scenario> {
        if !SCENARIO_NAMES.contains(&name) {
            bail!(
                "unknown scenario {name:?} (expected one of: {})",
                SCENARIO_NAMES.join(", ")
            );
        }
        let path = self.scenarios().join(format!("{name}.json"));
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("cannot read scenario {}", path.display()))?;
        let scenario: Scenario = serde_json::from_str(&text)
            .with_context(|| format!("invalid scenario {}", path.display()))?;
        if scenario.name != name {
            bail!(
                "scenario file {} declares name {:?}",
                path.display(),
                scenario.name
            );
        }
        Ok(scenario)
    }
}

/// Options for running a scenario.
#[derive(Debug, Clone, Default)]
pub struct RunOptions {
    /// Derive IDs and timestamps from the scenario name (golden tests).
    pub deterministic: bool,
    pub policy: ToolPolicy,
    /// Pause between steps (to watch a run live).
    pub step_delay: Duration,
}

/// Create the recorder for a lab scenario. `mode` is `Simulated` for the scripted agent and
/// `Live` for real models; lab tools are always mocks, which is recorded in the metadata.
pub fn lab_recorder(
    scenario: &Scenario,
    mode: ExecutionMode,
    deterministic: bool,
) -> TraceRecorder {
    let name = format!("local-lab/{}", scenario.name);
    let mut rec = if deterministic {
        TraceRecorder::deterministic(&name, mode, &format!("agent-trace-lab/{}", scenario.name))
    } else {
        TraceRecorder::new(&name, mode)
    };
    rec.set_trace_metadata("scenario", scenario.name.clone());
    rec.set_trace_metadata("mock_tools", true);
    if mode == ExecutionMode::Simulated {
        rec.set_trace_metadata("agent", "scripted-demo-agent");
        rec.set_trace_metadata("simulated", true);
        rec.set_trace_metadata(
            "notice",
            "SIMULATED: decisions are scripted, privileged tools are mocks, no shell or network is used.",
        );
    }
    rec
}

/// Record MCP connection details on the trace.
pub fn record_session_metadata(rec: &mut TraceRecorder, session: &McpSession) {
    rec.set_trace_metadata("transport", session.transport);
    rec.set_trace_metadata("mcp_server", session.server_name.clone());
    rec.set_trace_metadata("mcp_server_version", session.server_version.clone());
    rec.set_trace_metadata("mcp_protocol_version", session.protocol_version.clone());
}

/// Run one scenario against a freshly spawned local MCP server.
pub async fn run_scenario(
    scenario: &Scenario,
    server: &ServerCommand,
    options: &RunOptions,
) -> anyhow::Result<TraceRecord> {
    let rec = lab_recorder(scenario, ExecutionMode::Simulated, options.deterministic);
    run_scenario_with(rec, scenario, server, options).await
}

/// Run one scenario with a prepared recorder (e.g. one with a live sink).
/// On failure the trace is finished with status `aborted` before the error is returned.
pub async fn run_scenario_with(
    mut rec: TraceRecorder,
    scenario: &Scenario,
    server: &ServerCommand,
    options: &RunOptions,
) -> anyhow::Result<TraceRecord> {
    let session = match McpSession::connect(server).await {
        Ok(s) => s,
        Err(e) => {
            rec.finish_with(TraceStatus::Aborted);
            return Err(e);
        }
    };
    record_session_metadata(&mut rec, &session);
    let tools = session.list_tools().await;
    let result = match tools {
        Ok(tools) => drive(scenario, &session, &tools, options, &mut rec).await,
        Err(e) => Err(e),
    };
    let closed = session.close().await;
    match result.and(closed) {
        Ok(()) => Ok(rec.finish()),
        Err(e) => {
            rec.finish_with(TraceStatus::Aborted);
            Err(e)
        }
    }
}

fn simulated(spec: EventSpec) -> EventSpec {
    spec.meta("simulated_decision", true)
        .meta("decision_source", "scenario_script")
}

/// Mutable state of one (scripted) agent while it runs.
struct AgentRun<'s> {
    session: &'s McpSession,
    options: &'s RunOptions,
    agent: Option<String>,
    started: Uuid,
}

async fn drive(
    scenario: &Scenario,
    session: &McpSession,
    tools: &[String],
    options: &RunOptions,
    rec: &mut TraceRecorder,
) -> anyhow::Result<()> {
    let agent = scenario.agent.clone();
    let started = rec.record(
        EventSpec::new(
            EventKind::AgentStarted,
            Origin::System,
            TrustLevel::Trusted,
            agent
                .clone()
                .unwrap_or_else(|| "scripted-demo-agent".into()),
        )
        .payload(json!({
            "scenario": scenario.name,
            "title": scenario.title,
            "mcp_tools": tools,
        }))
        .agent(agent.clone())
        .meta("scenario", scenario.name.clone()),
    );
    let prompt = rec.record(
        EventSpec::new(
            EventKind::UserPromptReceived,
            Origin::User,
            TrustLevel::Trusted,
            "user_prompt",
        )
        .payload(json!({"text": scenario.user_prompt}))
        .agent(agent.clone())
        .parent(started)
        .caused_by(started),
    );
    let run = AgentRun {
        session,
        options,
        agent: agent.clone(),
        started,
    };
    let last = drive_steps(&run, rec, &scenario.steps, prompt).await?;
    rec.record(
        EventSpec::new(
            EventKind::AgentCompleted,
            Origin::System,
            TrustLevel::Trusted,
            agent
                .clone()
                .unwrap_or_else(|| "scripted-demo-agent".into()),
        )
        .payload(json!({"status": "completed"}))
        .agent(agent)
        .parent(started)
        .caused_by(last),
    );
    Ok(())
}

type StepFuture<'a> = Pin<Box<dyn Future<Output = anyhow::Result<Uuid>> + 'a>>;

fn drive_steps<'a>(
    run: &'a AgentRun<'a>,
    rec: &'a mut TraceRecorder,
    steps: &'a [Step],
    first_cause: Uuid,
) -> StepFuture<'a> {
    Box::pin(async move {
        let mut last = first_cause;
        for step in steps {
            if !run.options.step_delay.is_zero() {
                tokio::time::sleep(run.options.step_delay).await;
            }
            last = match step {
                Step::Decide { rationale } => rec.record(simulated(
                    EventSpec::new(
                        EventKind::AgentDecision,
                        Origin::Agent,
                        TrustLevel::Unknown,
                        "simulated_decision",
                    )
                    .payload(json!({"rationale": rationale}))
                    .agent(run.agent.clone())
                    .parent(run.started)
                    .caused_by(last),
                )),
                Step::CallTool { tool, arguments } => {
                    let gate = GateRequest {
                        agent: run.agent.clone(),
                        parent: run.started,
                        cause: last,
                        context: Vec::new(),
                        simulated: true,
                        extra_meta: Map::new(),
                        offered_tools: None,
                    };
                    gated_tool_call(run.session, &run.options.policy, rec, gate, tool, arguments)
                        .await?
                        .key_event
                }
                Step::Delegate {
                    agent: sub,
                    task,
                    steps: sub_steps,
                    report,
                } => delegate(run, rec, last, sub, task, sub_steps, report).await?,
                Step::Respond { text } => rec.record(simulated(
                    EventSpec::new(
                        EventKind::AgentDecision,
                        Origin::Agent,
                        TrustLevel::Unknown,
                        "final_response",
                    )
                    .payload(json!({"response": text}))
                    .agent(run.agent.clone())
                    .parent(run.started)
                    .caused_by(last),
                )),
            };
        }
        Ok(last)
    })
}

async fn delegate(
    run: &AgentRun<'_>,
    rec: &mut TraceRecorder,
    cause: Uuid,
    sub: &str,
    task: &str,
    steps: &[Step],
    report: &str,
) -> anyhow::Result<Uuid> {
    let handoff = begin_delegation(rec, run.agent.clone(), run.started, cause, sub, task, true);
    let sub_run = AgentRun {
        session: run.session,
        options: run.options,
        agent: Some(sub.to_owned()),
        started: handoff.sub_started,
    };
    let sub_last = drive_steps(&sub_run, rec, steps, handoff.sub_started).await?;
    Ok(end_delegation(
        rec,
        &handoff,
        run.agent.clone(),
        run.started,
        sub_last,
        report,
        true,
    ))
}

/// IDs of an ongoing delegation.
#[derive(Debug, Clone)]
pub struct Handoff {
    pub sub_agent: String,
    pub delegated: Uuid,
    pub sub_started: Uuid,
}

/// Record that `agent` delegates `task` to `sub` (and that `sub` starts).
pub fn begin_delegation(
    rec: &mut TraceRecorder,
    agent: Option<String>,
    parent: Uuid,
    cause: Uuid,
    sub: &str,
    task: &str,
    simulated_decision: bool,
) -> Handoff {
    let mut spec = EventSpec::new(
        EventKind::AgentDelegated,
        Origin::Agent,
        TrustLevel::Unknown,
        format!("delegate:{sub}"),
    )
    .payload(json!({"to_agent": sub, "task": task}))
    .agent(agent.clone())
    .parent(parent)
    .caused_by(cause);
    if simulated_decision {
        spec = simulated(spec);
    }
    let delegated = rec.record(spec);
    let sub_started = rec.record(
        EventSpec::new(
            EventKind::AgentStarted,
            Origin::System,
            TrustLevel::Trusted,
            sub,
        )
        .payload(json!({"task": task}))
        .agent(Some(sub.to_owned()))
        .parent(delegated)
        .caused_by(delegated)
        .meta(
            "parent_agent",
            agent.unwrap_or_else(|| agent_trace_core::DEFAULT_AGENT.into()),
        ),
    );
    Handoff {
        sub_agent: sub.to_owned(),
        delegated,
        sub_started,
    }
}

/// Record the sub-agent's report flowing back. The report inherits `lower_trust` if the
/// sub-agent observed any lower-trust content (taint propagation); those events are linked
/// as context. Returns the `agent_message_received` event of the parent agent.
pub fn end_delegation(
    rec: &mut TraceRecorder,
    handoff: &Handoff,
    agent: Option<String>,
    parent: Uuid,
    sub_last: Uuid,
    report: &str,
    simulated_decision: bool,
) -> Uuid {
    let start_seq = rec
        .event(handoff.sub_started)
        .map(|e| e.sequence)
        .unwrap_or(0);
    let tainted: Vec<Uuid> = rec
        .events()
        .iter()
        .filter(|e| {
            e.sequence > start_seq
                && e.agent() == handoff.sub_agent
                && e.trust_level == TrustLevel::LowerTrust
        })
        .map(|e| e.event_id)
        .collect();
    let trust = if tainted.is_empty() {
        TrustLevel::Unknown
    } else {
        TrustLevel::LowerTrust
    };
    let parent_name = agent
        .clone()
        .unwrap_or_else(|| agent_trace_core::DEFAULT_AGENT.into());
    let mut sent_spec = EventSpec::new(
        EventKind::AgentMessageSent,
        Origin::Agent,
        trust,
        format!("report:{parent_name}"),
    )
    .payload(json!({"to_agent": parent_name, "content": report}))
    .agent(Some(handoff.sub_agent.clone()))
    .parent(handoff.sub_started)
    .caused_by(sub_last)
    .context(tainted.iter().copied())
    .meta("tainted", !tainted.is_empty());
    if simulated_decision {
        sent_spec = simulated(sent_spec);
    }
    let sent = rec.record(sent_spec);
    rec.record(
        EventSpec::new(
            EventKind::AgentCompleted,
            Origin::System,
            TrustLevel::Trusted,
            handoff.sub_agent.clone(),
        )
        .payload(json!({"status": "completed"}))
        .agent(Some(handoff.sub_agent.clone()))
        .parent(handoff.sub_started)
        .caused_by(sent),
    );
    rec.record(
        EventSpec::new(
            EventKind::AgentMessageReceived,
            Origin::Agent,
            trust,
            format!("report:{}", handoff.sub_agent),
        )
        .payload(json!({"from_agent": handoff.sub_agent, "content": report}))
        .agent(agent)
        .parent(parent)
        .caused_by(sent)
        .meta("tainted", !tainted.is_empty()),
    )
}

/// How a tool request is attributed and linked.
#[derive(Debug, Clone)]
pub struct GateRequest {
    pub agent: Option<String>,
    /// Structural parent of the request (the agent's `agent_started`).
    pub parent: Uuid,
    /// Direct cause (a decision or model response).
    pub cause: Uuid,
    /// Additional context links (e.g. everything in an LLM's context window).
    pub context: Vec<Uuid>,
    /// Whether the request comes from the scripted agent.
    pub simulated: bool,
    /// Extra metadata on the request event (e.g. `tool_use_id`).
    pub extra_meta: Map<String, Value>,
    /// Tools offered to this agent. A request for any other tool is recorded and denied.
    /// `None` = no per-agent restriction (the scripted agent).
    pub offered_tools: Option<Vec<String>>,
}

/// Outcome of a gated tool call.
#[derive(Debug, Clone)]
pub struct GateOutcome {
    pub request: Uuid,
    pub decision: Uuid,
    /// `tool_result_received` if executed, otherwise the blocking policy decision.
    pub key_event: Uuid,
    pub blocked: bool,
    pub is_error: bool,
    /// Text to hand back to the agent (tool output or the policy denial).
    pub text: String,
}

/// Record a tool request, apply the policy, and execute it over MCP if allowed.
pub async fn gated_tool_call(
    session: &McpSession,
    policy: &ToolPolicy,
    rec: &mut TraceRecorder,
    gate: GateRequest,
    tool: &str,
    arguments: &Map<String, Value>,
) -> anyhow::Result<GateOutcome> {
    let mut spec = EventSpec::new(
        EventKind::ToolCallRequested,
        Origin::Agent,
        TrustLevel::Unknown,
        tool,
    )
    .payload(json!({"tool": tool, "arguments": arguments}))
    .agent(gate.agent.clone())
    .parent(gate.parent)
    .caused_by(gate.cause)
    .context(gate.context.iter().copied())
    .tool_state(ToolState::Requested)
    .meta("privileged", policy.is_privileged(tool));
    for (k, v) in gate.extra_meta {
        spec = spec.meta(&k, v);
    }
    if gate.simulated {
        spec = simulated(spec);
    }
    let outcome = match &gate.offered_tools {
        Some(offered) if !offered.iter().any(|t| t == tool) => PolicyOutcome {
            decision: Decision::Deny,
            reason: format!("tool {tool:?} was not offered to this agent"),
        },
        _ => policy.evaluate(tool, arguments),
    };
    let (request, decision) =
        record_gate(rec, spec, gate.agent.clone(), tool, &outcome, Map::new());
    if outcome.decision == Decision::Deny {
        return Ok(GateOutcome {
            request,
            decision,
            key_event: decision,
            blocked: true,
            is_error: true,
            text: format!("BLOCKED by policy: {}", outcome.reason),
        });
    }
    let result = session
        .call_tool_as(
            rec,
            CallSpec {
                request_event: request,
                caused_by: decision,
                agent: gate.agent,
                mock_tool: tool.ends_with("_mock"),
            },
            tool,
            arguments.clone(),
        )
        .await?;
    Ok(GateOutcome {
        request,
        decision,
        key_event: result.result_event,
        blocked: false,
        is_error: result.is_error,
        text: result.text,
    })
}

/// Record a `tool_call_requested` event (`request`, built by the caller) and the
/// `tool_policy_decision` on it. `extra` is added to the decision payload.
/// Returns the ids of the request and the decision.
pub fn record_gate(
    rec: &mut TraceRecorder,
    request: EventSpec,
    agent: Option<String>,
    tool: &str,
    outcome: &PolicyOutcome,
    extra: Map<String, Value>,
) -> (Uuid, Uuid) {
    let request = rec.record(request);
    let denied = outcome.decision == Decision::Deny;
    let mut payload = json!({
        "tool": tool,
        "decision": outcome.decision,
        "reason": outcome.reason,
        "outbound_request_sent": false,
    });
    if let Value::Object(map) = &mut payload {
        map.extend(extra);
    }
    let decision = rec.record(
        EventSpec::new(
            EventKind::ToolPolicyDecision,
            Origin::Policy,
            TrustLevel::Trusted,
            tool,
        )
        .payload(payload)
        .agent(agent)
        .parent(request)
        .caused_by(request)
        .tool_state(if denied {
            ToolState::Blocked
        } else {
            ToolState::PolicyDecision
        }),
    );
    (request, decision)
}

/// Resolve the lab directory: explicit path, `AGENT_TRACE_LAB_DIR`, the source checkout,
/// or `./examples/local-lab`.
pub fn locate_lab_dir(explicit: Option<&Path>) -> anyhow::Result<PathBuf> {
    let candidates: Vec<PathBuf> = explicit
        .map(Path::to_path_buf)
        .into_iter()
        .chain(std::env::var_os("AGENT_TRACE_LAB_DIR").map(PathBuf::from))
        .chain(std::iter::once(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/local-lab"),
        ))
        .chain(std::iter::once(PathBuf::from("examples/local-lab")))
        .collect();
    for c in &candidates {
        if c.join("scenarios").is_dir() && c.join("documents").is_dir() {
            return Ok(c.canonicalize()?);
        }
        if explicit.is_some() {
            bail!("{} is not a local lab directory", c.display());
        }
    }
    bail!("could not find examples/local-lab; pass --lab-dir")
}
