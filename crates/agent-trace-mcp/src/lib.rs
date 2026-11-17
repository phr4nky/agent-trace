//! `agent-trace-mcp`: real MCP (stdio, `rmcp`) integration for agent-trace.
//!
//! * [`adapter`] normalizes MCP tool calls into agent-trace events.
//! * [`server`] is the local lab MCP server with sandboxed fixtures and mock-only privileged tools.
//! * [`lab`] is the deterministic, scripted (simulated) demo agent.
//! * [`proxy`] records the traffic between a real MCP client and server.

pub mod adapter;
pub mod lab;
pub mod proxy;
pub mod server;

pub use adapter::{CallOutcome, CallSpec, McpSession, ServerCommand, ToolSpec};
pub use lab::{
    GateOutcome, GateRequest, Handoff, LabPaths, RunOptions, SCENARIO_NAMES, Scenario, Step,
    begin_delegation, end_delegation, gated_tool_call, lab_recorder, locate_lab_dir, record_gate,
    record_session_metadata, run_scenario, run_scenario_with,
};
pub use proxy::{Proxy, ProxyConfig, ProxyMode, apply_mode};
pub use server::{LabServer, resolve_fixture_path, serve_stdio};
