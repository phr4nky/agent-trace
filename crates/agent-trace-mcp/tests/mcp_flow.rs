//! Real MCP over stdio: spawns the `agent-trace-lab-server` binary as a child process.

use std::path::PathBuf;

use agent_trace_core::{EventKind, ExecutionMode, Origin, TraceRecorder, TrustLevel};
use agent_trace_mcp::{LabPaths, McpSession, RunOptions, ServerCommand, run_scenario};
use serde_json::{Map, Value, json};
use uuid::Uuid;

fn lab() -> LabPaths {
    LabPaths::new(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/local-lab"))
}

fn server() -> ServerCommand {
    ServerCommand {
        program: PathBuf::from(env!("CARGO_BIN_EXE_agent-trace-lab-server")),
        args: vec![
            "--documents".into(),
            lab().documents().display().to_string(),
        ],
    }
}

fn args(v: Value) -> Map<String, Value> {
    v.as_object().unwrap().clone()
}

#[tokio::test]
async fn handshake_and_tool_listing() {
    let session = McpSession::connect(&server()).await.unwrap();
    assert_eq!(session.server_name, "agent-trace-lab-server");
    let mut tools = session.list_tools().await.unwrap();
    tools.sort();
    assert_eq!(
        tools,
        ["read_document", "run_command_mock", "send_webhook_mock"]
    );
    session.close().await.unwrap();
}

#[tokio::test]
async fn read_document_over_stdio_is_recorded_as_lower_trust() {
    let session = McpSession::connect(&server()).await.unwrap();
    let mut rec = TraceRecorder::new("t", ExecutionMode::Simulated);
    let req = Uuid::new_v4();
    let out = session
        .call_tool(
            &mut rec,
            req,
            req,
            "read_document",
            args(json!({"path": "benign-readme.md"})),
        )
        .await
        .unwrap();
    assert!(!out.is_error);
    assert!(out.text.contains("tiny-notes"));
    let events = rec.events();
    let kinds: Vec<_> = events.iter().map(|e| e.kind).collect();
    assert_eq!(
        kinds,
        [
            EventKind::ToolCallExecuted,
            EventKind::ToolResultReceived,
            EventKind::ToolCallCompleted
        ]
    );
    let result = &events[1];
    assert_eq!(result.origin, Origin::McpTool);
    assert_eq!(result.trust_level, TrustLevel::LowerTrust);
    assert_eq!(result.metadata["transport"], "stdio");
    session.close().await.unwrap();
}

#[tokio::test]
async fn read_document_blocks_traversal_over_mcp() {
    let session = McpSession::connect(&server()).await.unwrap();
    for path in [
        "../scenarios/benign.json",
        "../../../Cargo.toml",
        "/etc/passwd",
        "../expected-findings.json",
        "documents/../../README.md",
    ] {
        let mut rec = TraceRecorder::new("t", ExecutionMode::Simulated);
        let req = Uuid::new_v4();
        let out = session
            .call_tool(
                &mut rec,
                req,
                req,
                "read_document",
                args(json!({"path": path})),
            )
            .await
            .unwrap();
        assert!(out.is_error, "{path} must be rejected");
        assert!(out.text.contains("rejected"), "{path}: {}", out.text);
        assert_eq!(rec.events()[2].kind, EventKind::ToolCallFailed);
    }
    session.close().await.unwrap();
}

#[tokio::test]
async fn mock_tools_never_execute_or_transmit() {
    let session = McpSession::connect(&server()).await.unwrap();
    let mut rec = TraceRecorder::new("t", ExecutionMode::Simulated);
    let req = Uuid::new_v4();
    session
        .call_tool(
            &mut rec,
            req,
            req,
            "run_command_mock",
            args(json!({"command": "touch /tmp/agent-trace-must-not-exist"})),
        )
        .await
        .unwrap();
    assert!(!std::path::Path::new("/tmp/agent-trace-must-not-exist").exists());
    let result = &rec.events()[1].payload["structured_content"];
    assert_eq!(result["shell_invoked"], false);

    let out = session
        .call_tool(
            &mut rec,
            req,
            req,
            "send_webhook_mock",
            args(json!({"destination": "https://example.invalid/x", "body": "hi"})),
        )
        .await
        .unwrap();
    assert!(
        out.is_error,
        "server-side policy denies non-allowlisted destinations"
    );
    let result = &rec.events()[4].payload["structured_content"];
    assert_eq!(result["network_used"], false);
    assert_eq!(result["sent"], false);
    session.close().await.unwrap();
}

#[tokio::test]
async fn scenarios_run_end_to_end() {
    for name in agent_trace_mcp::SCENARIO_NAMES {
        let scenario = lab().load_scenario(name).unwrap();
        let rec = run_scenario(&scenario, &server(), &RunOptions::default())
            .await
            .unwrap();
        agent_trace_core::validate(&rec).unwrap();
        assert!(
            rec.events
                .iter()
                .all(|e| e.execution_mode == ExecutionMode::Simulated)
        );
        assert!(
            rec.events
                .iter()
                .filter(|e| e.kind == EventKind::AgentDecision)
                .all(|e| e.metadata["simulated_decision"] == true)
        );
        assert!(
            rec.events
                .iter()
                .any(|e| e.kind == EventKind::ToolResultReceived && e.name == "read_document")
        );
    }
}

#[test]
fn unknown_scenarios_are_rejected() {
    assert!(lab().load_scenario("../../etc/passwd").is_err());
}
