//! `agent-trace sarif FILE...`: turn recorded traces (JSONL) into one SARIF file for GitHub
//! Code Scanning. The files are validated and re-redacted like `import`; nothing is stored.

use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

use agent_trace_core::Finding;
use agent_trace_storage::{
    SarifTrace, create_private_file, jsonl_event_lines, read_jsonl, write_sarif,
};
use anyhow::{Context as _, bail};

use super::{Context, threshold_exit};
use crate::Threshold;

/// The URI of `path` for SARIF: relative to the working directory (the repository root in
/// CI), forward slashes, characters outside the URI path set percent-encoded.
pub fn artifact_uri(path: &Path) -> String {
    let relative = std::env::current_dir()
        .ok()
        .and_then(|cwd| path.strip_prefix(&cwd).ok().map(Path::to_path_buf))
        .unwrap_or_else(|| path.to_path_buf());
    let text = relative.to_string_lossy().replace('\\', "/");
    let text = text.strip_prefix("./").unwrap_or(&text);
    let mut out = String::with_capacity(text.len());
    for b in text.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~/".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

pub fn run(
    ctx: &Context,
    inputs: &[PathBuf],
    output: Option<&Path>,
    fail_on: Option<Threshold>,
) -> anyhow::Result<u8> {
    if inputs.is_empty() {
        bail!("pass at least one JSONL trace file");
    }
    let analyzer = ctx.analyzer()?;
    let mut loaded = Vec::new();
    for path in inputs {
        let file = File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
        let imported = read_jsonl(file).with_context(|| format!("rejected {}", path.display()))?;
        let lines = jsonl_event_lines(BufReader::new(File::open(path)?))?;
        let findings: Vec<Finding> =
            analyzer.analyze(&imported.record, time::OffsetDateTime::now_utc());
        loaded.push((artifact_uri(path), imported.record, findings, lines));
    }
    let traces: Vec<SarifTrace<'_>> = loaded
        .iter()
        .map(|(uri, record, findings, lines)| SarifTrace {
            artifact_uri: uri,
            record,
            findings,
            event_lines: Some(lines),
        })
        .collect();
    let writer: Box<dyn Write> = match output {
        Some(path) => Box::new(BufWriter::new(create_private_file(path)?)),
        None => Box::new(std::io::stdout().lock()),
    };
    write_sarif(writer, &traces, &analyzer)?;
    let all: Vec<Finding> = loaded.iter().flat_map(|(_, _, f, _)| f.clone()).collect();
    if let Some(path) = output {
        eprintln!(
            "wrote {} result(s) from {} trace(s) to {} (SARIF 2.1.0, redacted)",
            all.len(),
            loaded.len(),
            path.display()
        );
    }
    Ok(threshold_exit(&all, fail_on))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uris_are_relative_and_encoded() {
        assert_eq!(artifact_uri(Path::new("traces/a.jsonl")), "traces/a.jsonl");
        assert_eq!(
            artifact_uri(Path::new("./traces/a b.jsonl")),
            "traces/a%20b.jsonl"
        );
        let cwd = std::env::current_dir().unwrap();
        assert_eq!(artifact_uri(&cwd.join("t/x.jsonl")), "t/x.jsonl");
        assert_eq!(artifact_uri(Path::new("t/ü#.jsonl")), "t/%C3%BC%23.jsonl");
    }
}
