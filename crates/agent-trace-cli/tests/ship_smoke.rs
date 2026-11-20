//! `agent-trace ship` against a real agent-trace-server on a loopback port.

use std::net::SocketAddr;
use std::path::Path;
use std::process::{Command, Output};

use agent_trace_core::Analyzer;
use agent_trace_server::{AppState, Settings, spawn, token};
use agent_trace_storage::Store;
use serde_json::Value;

fn exe() -> &'static str {
    env!("CARGO_BIN_EXE_agent-trace")
}

fn cli(data: &Path, args: &[&str], token: Option<&str>) -> Output {
    let mut cmd = Command::new(exe());
    cmd.arg("--data-dir")
        .arg(data)
        .arg("--no-color")
        .args(args)
        .env_remove("AGENT_TRACE_DATA_DIR")
        .env_remove("AGENT_TRACE_CONFIG")
        .env_remove("AGENT_TRACE_DATABASE_URL")
        .env_remove("AGENT_TRACE_SHIP_TOKEN");
    if let Some(t) = token {
        cmd.env("AGENT_TRACE_SHIP_TOKEN", t);
    }
    cmd.output().unwrap()
}

fn text(out: &Output) -> (String, String) {
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn ship_sends_new_traces_once_and_the_server_analyzes_them() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let server_dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(server_dir.path().join("server.sqlite3")).unwrap();
    let laptop = token::generate().unwrap();
    store.add_source("laptop", &token::hash(&laptop)).unwrap();
    let state = AppState::new(store, Analyzer::default(), Settings::default());
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let addr: SocketAddr = runtime
        .block_on(spawn("127.0.0.1:0".parse().unwrap(), state))
        .unwrap();
    let url = format!("http://{addr}");

    // A local recording: the exfiltration scenario (4 findings).
    let data = tempfile::tempdir().unwrap();
    let d = data.path();
    assert!(
        cli(d, &["demo", "run", "--scenario", "exfil-attempt"], None)
            .status
            .success()
    );

    let out = cli(d, &["ship", "--to", &url], Some(&laptop));
    let (stdout, stderr) = text(&out);
    assert!(out.status.success(), "{stdout}\n{stderr}");
    assert!(stdout.contains("1 trace(s) sent"), "{stdout}");
    assert!(stdout.contains("local-lab/exfil-attempt"), "{stdout}");

    // Nothing is sent twice.
    let out = cli(d, &["ship", "--to", &url], Some(&laptop));
    let (stdout, _) = text(&out);
    assert!(
        stdout.contains("0 trace(s) sent") && stdout.contains("1 up to date"),
        "{stdout}"
    );

    // The server has the trace with its own findings, under the source.
    let http = reqwest::Client::new();
    let sources: Value = runtime.block_on(async {
        http.get(format!("{url}/api/v1/sources"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap()
    });
    assert_eq!(sources[0]["name"], "laptop");
    assert_eq!(sources[0]["traces"], 1);
    let source_id = sources[0]["source_id"].as_str().unwrap().to_owned();
    let traces: Value = runtime.block_on(async {
        http.get(format!("{url}/api/v1/traces?source={source_id}"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap()
    });
    assert_eq!(traces[0]["name"], "local-lab/exfil-attempt");
    assert_eq!(
        traces[0]["findings"], 4,
        "same findings as recorded locally"
    );
    assert_eq!(traces[0]["events"], 13);

    // A wrong token, a missing token and plain http to another host are refused.
    let wrong = token::generate().unwrap();
    let out = cli(d, &["ship", "--to", &url], Some(&wrong));
    let (_, stderr) = text(&out);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr.contains("did not accept the token"), "{stderr}");
    let out = cli(d, &["ship", "--to", &url], None);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out).1.contains("AGENT_TRACE_SHIP_TOKEN"));
    let out = cli(
        d,
        &["ship", "--to", "http://trace.example.com"],
        Some(&laptop),
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out).1.contains("https"), "{}", text(&out).1);
}
