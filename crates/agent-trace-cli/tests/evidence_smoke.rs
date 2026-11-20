//! End-to-end: `agent-trace evidence` on signed exports of the demo traces and on the store.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

fn bin(data: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_agent-trace"))
        .arg("--data-dir")
        .arg(data)
        .arg("--no-color")
        .args(args)
        .env_remove("AGENT_TRACE_DATA_DIR")
        .env_remove("AGENT_TRACE_CONFIG")
        .env_remove("AGENT_TRACE_DATABASE_URL")
        .env_remove("AGENT_TRACE_SIGNING_KEY")
        .current_dir(data)
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

/// Demo run, signing key, and one signed export per trace. Returns the export paths.
fn setup(data: &Path) -> Vec<PathBuf> {
    ok(&bin(data, &["demo", "run", "--scenario", "all"]));
    ok(&bin(data, &["keys", "generate"]));
    let list = ok(&bin(data, &["trace", "list"]));
    let ids: Vec<String> = list
        .lines()
        .skip(1)
        .map(|l| l.split_whitespace().nth(1).unwrap().to_owned())
        .collect();
    assert_eq!(ids.len(), 4, "{list}");
    ids.iter()
        .map(|id| {
            let path = data.join(format!("signed-{id}.jsonl"));
            ok(&bin(
                data,
                &[
                    "export",
                    id,
                    "--format",
                    "jsonl",
                    "--sign",
                    "--output",
                    path.to_str().unwrap(),
                ],
            ));
            path
        })
        .collect()
}

fn args<'a>(files: &'a [PathBuf], extra: &[&'a str]) -> Vec<&'a str> {
    let mut v = vec!["evidence"];
    v.extend(files.iter().map(|p| p.to_str().unwrap()));
    v.extend(extra);
    v
}

/// Text from the demo payloads (prompts, tool arguments and results) that must never appear.
const PAYLOAD_TEXT: &[&str] = &[
    "Summarize this repository",
    "tiny-notes deployment notes",
    "exfil-readme.md",
    "Read the deployment notes",
    "example.invalid",
];

#[test]
fn evidence_report_on_signed_exports() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path();
    let files = setup(data);

    // JSON: stable fields, integrity, counts.
    let out = bin(data, &args(&files, &["--all", "--format", "json"]));
    let text = ok(&out);
    let r: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(r["report_version"], "1");
    assert_eq!(r["report_type"], "agent-trace-evidence");
    assert_eq!(r["result"], "ok");
    let keys: Vec<&str> = r.as_object().unwrap().keys().map(String::as_str).collect();
    for k in [
        "report_version",
        "report_type",
        "generated_at",
        "generated_by",
        "disclaimer",
        "result",
        "summary",
        "configuration",
        "retention",
        "traces",
        "not_proven",
        "references",
    ] {
        assert!(keys.contains(&k), "missing {k}: {keys:?}");
    }
    assert!(
        r["disclaimer"]
            .as_str()
            .unwrap()
            .contains("not a statement of compliance")
    );
    let s = &r["summary"];
    assert_eq!(s["traces"], 8);
    assert_eq!(s["from_files"], 4);
    assert_eq!(s["from_store"], 4);
    assert_eq!(s["verified"], 4);
    assert_eq!(s["failed"], 0);
    assert_eq!(s["not_tamper_evident"], 4);
    assert_eq!(s["events"], 2 * (11 + 16 + 13 + 22));
    assert_eq!(r["configuration"]["sha256"].as_str().unwrap().len(), 64);
    assert_eq!(r["retention"]["store"]["traces"], 4);
    assert!(r["retention"]["store"]["oldest"]["trace_id"].is_string());

    let traces = r["traces"].as_array().unwrap();
    let mut file_findings = 0;
    let mut store_findings = 0;
    for t in traces {
        let i = &t["integrity"];
        let f = &t["trace"];
        match t["source"].as_str().unwrap() {
            "file" => {
                assert_eq!(i["status"], "verified", "{t}");
                assert_eq!(i["signed"], true);
                assert_eq!(i["signer_trusted"], true);
                assert_eq!(i["trusted_by"], "your signing key");
                assert_eq!(i["signer_key_id"].as_str().unwrap().len(), 16);
                assert!(
                    i["chained_records"].as_u64().unwrap() > f["event_count"].as_u64().unwrap()
                );
                file_findings += f["findings"]["total"].as_u64().unwrap();
            }
            "store" => {
                assert_eq!(i["status"], "not_tamper_evident");
                store_findings += f["findings"]["total"].as_u64().unwrap();
            }
            other => panic!("source {other}"),
        }
        assert_eq!(f["execution_mode"], "simulated");
        assert_eq!(f["mcp_servers"][0], "agent-trace-lab-server");
        assert!(
            f["tools"]
                .as_array()
                .unwrap()
                .contains(&Value::from("read_document"))
        );
        let sev: u64 = f["findings"]["by_severity"]
            .as_object()
            .unwrap()
            .values()
            .map(|v| v.as_u64().unwrap())
            .sum();
        let rules: u64 = f["findings"]["by_rule"]
            .as_object()
            .unwrap()
            .values()
            .map(|v| v.as_u64().unwrap())
            .sum();
        assert_eq!(sev, f["findings"]["total"].as_u64().unwrap());
        assert_eq!(rules, sev);
        if f["name"] == "local-lab/exfil-attempt" {
            assert_eq!(f["redaction"]["redacted_values"], 2, "{f}");
            assert_eq!(f["findings"]["by_rule"]["AT-003"], 1, "{f}");
        }
        if f["name"] == "local-lab/multi-agent-handoff" {
            assert_eq!(
                f["agents"],
                serde_json::json!(["orchestrator", "researcher"])
            );
        }
    }
    assert_eq!(file_findings, 10);
    assert_eq!(store_findings, 10);
    assert_eq!(s["findings"], 20);

    // Markdown (default): headline, disclaimer, sections, no payload text.
    let md = ok(&bin(data, &args(&files, &["--all"])));
    for needle in [
        "# agent-trace evidence report",
        "**Not a compliance statement.**",
        "**VERIFIED**",
        "(trusted: your signing key)",
        "**NOT TAMPER-EVIDENT**",
        "## What this report does not prove",
        "https://artificialintelligenceact.eu/article/12/",
        "No retention is configured",
    ] {
        assert!(md.contains(needle), "missing {needle:?}:\n{md}");
    }
    for leaked in PAYLOAD_TEXT {
        assert!(!text.contains(leaked), "payload text {leaked:?} in JSON");
        assert!(!md.contains(leaked), "payload text {leaked:?} in Markdown");
    }

    // --output writes a private file.
    let path = data.join("evidence.md");
    ok(&bin(
        data,
        &args(&files[..1], &["--output", path.to_str().unwrap()]),
    ));
    assert!(
        std::fs::read_to_string(&path)
            .unwrap()
            .contains("**VERIFIED**")
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}

#[test]
fn tampered_untrusted_and_unsigned_inputs_fail() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path();
    let files = setup(data);

    // A changed record: FAILED in the report, exit 1, report still written.
    let tampered = data.join("tampered.jsonl");
    let text = std::fs::read_to_string(&files[0]).unwrap();
    std::fs::write(
        &tampered,
        text.replacen("read_document", "read_documenX", 1),
    )
    .unwrap();
    let out_path = data.join("r.json");
    let out = bin(
        data,
        &[
            "evidence",
            files[1].to_str().unwrap(),
            tampered.to_str().unwrap(),
            "--format",
            "json",
            "--output",
            out_path.to_str().unwrap(),
        ],
    );
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stderr).contains("FAILED verification"));
    let r: Value = serde_json::from_str(&std::fs::read_to_string(&out_path).unwrap()).unwrap();
    assert_eq!(r["result"], "failed");
    assert_eq!(r["summary"]["failed"], 1);
    assert_eq!(r["summary"]["verified"], 1);
    let failed = &r["traces"][1];
    assert_eq!(failed["integrity"]["status"], "failed");
    assert!(failed["trace"].is_null());
    assert!(
        failed["integrity"]["error"]
            .as_str()
            .unwrap()
            .contains("changed after it was exported")
    );
    let md = String::from_utf8_lossy(&bin(data, &["evidence", tampered.to_str().unwrap()]).stdout)
        .into_owned();
    assert!(md.contains("**FAILED**"), "{md}");

    // A valid signature by a key that is not trusted: fails (as `verify` does).
    let other = tempfile::tempdir().unwrap();
    let files_other = setup(other.path());
    let out = bin(
        data,
        &[
            "evidence",
            files_other[0].to_str().unwrap(),
            "--format",
            "json",
        ],
    );
    assert_eq!(out.status.code(), Some(1));
    let r: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(r["traces"][0]["integrity"]["status"], "untrusted_signer");
    assert_eq!(r["traces"][0]["integrity"]["signer_trusted"], false);
    // ... and passes when that key is trusted explicitly.
    let pub_key = other.path().join("keys/signing-key.pk8.pub");
    let out = bin(
        data,
        &[
            "evidence",
            files_other[0].to_str().unwrap(),
            "--public-key",
            pub_key.to_str().unwrap(),
            "--format",
            "json",
        ],
    );
    let r: Value = serde_json::from_str(&ok(&out)).unwrap();
    assert_eq!(r["traces"][0]["integrity"]["status"], "verified");

    // Unsigned: ok by default, failed with --require-signature.
    let id = files[0]
        .file_stem()
        .unwrap()
        .to_str()
        .unwrap()
        .trim_start_matches("signed-")
        .to_owned();
    let unsigned = data.join("unsigned.jsonl");
    ok(&bin(
        data,
        &[
            "export",
            &id,
            "--format",
            "jsonl",
            "--output",
            unsigned.to_str().unwrap(),
        ],
    ));
    let r: Value = serde_json::from_str(&ok(&bin(
        data,
        &["evidence", unsigned.to_str().unwrap(), "--format", "json"],
    )))
    .unwrap();
    assert_eq!(r["traces"][0]["integrity"]["status"], "unsigned");
    let out = bin(
        data,
        &[
            "evidence",
            unsigned.to_str().unwrap(),
            "--require-signature",
        ],
    );
    assert_eq!(out.status.code(), Some(1));

    // No input at all is a usage error.
    assert_eq!(bin(data, &["evidence"]).status.code(), Some(1));
}

#[test]
fn short_retention_and_config_summary() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path();
    let files = setup(data);
    std::fs::write(
        data.join("agent-trace.toml"),
        r#"
[retention]
max_age_days = 30

[redaction]
keys = ["x_internal_token"]
patterns = [{ label = "corp_key", regex = "CORP-[0-9A-F]{24}" }]

[[canaries]]
name = "aws-decoy"
value = "AKIAZ7Q3CANARY4X2LMN"

[profiles.read-only]
tools = ["Read", "mcp__github__get_*"]

[[rules]]
id = "CORP-001"
title = "Shell tool"
severity = "high"
tools = ["run_command*"]
"#,
    )
    .unwrap();
    let text = ok(&bin(data, &args(&files[..1], &["--format", "json"])));
    let r: Value = serde_json::from_str(&text).unwrap();
    let warnings = r["retention"]["warnings"].as_array().unwrap();
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert!(
        warnings[0]
            .as_str()
            .unwrap()
            .contains("Article 26(6) of the EU AI Act names at least six months")
    );
    assert_eq!(r["retention"]["max_age_days"], 30);
    let c = &r["configuration"];
    assert_eq!(c["canaries"], serde_json::json!(["aws-decoy"]));
    assert_eq!(c["custom_rules"], serde_json::json!(["CORP-001"]));
    assert_eq!(
        c["profiles"],
        serde_json::json!({"read-only": ["Read", "mcp__github__get_*"]})
    );
    assert_eq!(
        c["redaction"]["pattern_labels"],
        serde_json::json!(["corp_key"])
    );
    // Never the canary value or a redaction pattern.
    assert!(!text.contains("AKIAZ7Q3CANARY4X2LMN"));
    assert!(!text.contains("CORP-[0-9A-F]"));

    let md = ok(&bin(data, &args(&files[..1], &[])));
    assert!(md.contains("shorter than six months"), "{md}");
    assert!(!md.contains("AKIAZ7Q3CANARY4X2LMN"));
}
