//! `agent-trace hook`: the command Claude Code runs for each hook event.
//!
//! Each invocation is a new process: it reads the event from stdin, takes the session's lock
//! (parallel tool calls fire hooks concurrently), continues the session's trace in the store,
//! runs the rules and, for a denied PreToolUse call, prints Claude Code's deny decision on
//! stdout. Nothing else is written to stdout.

use std::fs::{File, OpenOptions};
use std::io::Read;
use std::path::PathBuf;

use agent_trace_core::{TraceRecord, TraceRecorder};
use agent_trace_mcp::ProxyMode;
use agent_trace_storage::{StorageError, TraceSource, create_private_dir};
use anyhow::Context as _;
use serde_json::{Value, json};

use super::{Context, analyze_and_store};
use crate::EXIT_OK;
use crate::config::{DEFAULT_HOOK_TAINT_SOURCES, OnError};
use crate::hooks::{self, HookInput, HookOutput, HookSettings};

/// Hook input larger than this is rejected (tool results are truncated when recorded anyway).
const MAX_INPUT_BYTES: u64 = 64 * 1024 * 1024;
/// Exit code with which Claude Code denies a PreToolUse call (stderr becomes the reason).
const EXIT_BLOCK: u8 = 2;

/// Hook events `--print-settings` registers, and whether they take a tool matcher.
const EVENTS: &[(&str, bool)] = &[
    ("SessionStart", false),
    ("UserPromptSubmit", false),
    ("PreToolUse", true),
    ("PostToolUse", true),
    ("PostToolUseFailure", true),
    ("SubagentStart", false),
    ("SubagentStop", false),
    ("Stop", false),
    ("SessionEnd", false),
];

pub struct HookArgs {
    pub mode: Option<ProxyMode>,
    pub print_settings: bool,
}

pub fn run(ctx: &Context, args: HookArgs) -> anyhow::Result<u8> {
    if args.print_settings {
        return print_settings(ctx, args.mode);
    }
    let loaded = ctx.config()?;
    let section = &loaded.config.hooks;
    let mode = args.mode.or(section.mode).unwrap_or_default();
    let settings = HookSettings {
        mode,
        policy: loaded.policy(),
        taint_sources: section.taint_sources.clone().unwrap_or_else(|| {
            DEFAULT_HOOK_TAINT_SOURCES
                .iter()
                .map(|s| s.to_string())
                .collect()
        }),
    };
    let mut raw = Vec::new();
    std::io::stdin()
        .take(MAX_INPUT_BYTES + 1)
        .read_to_end(&mut raw)
        .context("cannot read the hook event from stdin")?;
    let input: Option<HookInput> = (raw.len() as u64 <= MAX_INPUT_BYTES)
        .then(|| serde_json::from_slice(&raw).ok())
        .flatten();
    let pre_tool_use = input
        .as_ref()
        .is_some_and(|i| i.hook_event_name == "PreToolUse");
    let result = match &input {
        Some(i) if !i.session_id.is_empty() => record(ctx, i, &settings, &loaded),
        Some(_) => Err(anyhow::anyhow!("hook event without session_id")),
        None => Err(anyhow::anyhow!(
            "stdin is not a Claude Code hook event (JSON, at most {MAX_INPUT_BYTES} bytes)"
        )),
    };
    match result {
        Ok(HookOutput { deny: Some(reason) }) => {
            let decision = json!({"hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }});
            println!("{decision}");
            Ok(EXIT_OK)
        }
        Ok(_) => Ok(EXIT_OK),
        Err(e)
            if pre_tool_use && mode == ProxyMode::Enforce && section.on_error == OnError::Deny =>
        {
            // Fail closed: deny the call, with the error as the reason Claude sees.
            let redactor = agent_trace_core::Redactor::new();
            eprintln!(
                "agent-trace could not record this tool call, denied (on_error = \"deny\"): {}",
                redactor.scrub(&format!("{e:#}"))
            );
            Ok(EXIT_BLOCK)
        }
        // Any other non-zero exit lets Claude Code continue (fail open) and shows the error.
        Err(e) => Err(e),
    }
}

fn record(
    ctx: &Context,
    input: &HookInput,
    settings: &HookSettings,
    loaded: &crate::config::Loaded,
) -> anyhow::Result<HookOutput> {
    let trace_id = hooks::trace_id_for(&input.session_id);
    let _lock = lock_session(ctx, trace_id)?;
    let mut store = ctx.open_store()?;
    let (mut rec, is_new) = match store.load_trace(trace_id) {
        Ok(record) => (TraceRecorder::resume(record), false),
        Err(StorageError::TraceNotFound(_)) => (hooks::new_recorder(input), true),
        Err(e) => return Err(e.into()),
    };
    let before = if is_new { 0 } else { rec.events().len() };
    let output = hooks::apply(&mut rec, input, settings);
    if is_new {
        store.begin_trace(rec.trace(), TraceSource::Recorded)?;
    }
    for event in &rec.events()[before..] {
        store.append_event(event)?;
    }
    store.update_trace(rec.trace())?;
    let record = TraceRecord {
        trace: rec.trace().clone(),
        events: rec.events().to_vec(),
    };
    analyze_and_store(&loaded.analyzer(), &mut store, &record)?;
    Ok(output)
}

/// Exclusive lock for one session, released when the returned file is dropped. Concurrent
/// hooks of the same session wait for each other, so sequence numbers never collide.
fn lock_session(ctx: &Context, trace_id: uuid::Uuid) -> anyhow::Result<File> {
    let dir = ctx.data_dir()?.join("hooks");
    create_private_dir(&dir)?;
    let path = dir.join(format!("{trace_id}.lock"));
    let mut options = OpenOptions::new();
    options.create(true).truncate(false).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(&path)
        .with_context(|| format!("cannot open lock file {}", path.display()))?;
    file.lock()
        .with_context(|| format!("cannot lock {}", path.display()))?;
    Ok(file)
}

/// Print the `hooks` block for Claude Code's settings.json.
fn print_settings(ctx: &Context, mode: Option<ProxyMode>) -> anyhow::Result<u8> {
    let exe = std::env::current_exe().context("cannot locate own executable")?;
    let mut parts = vec![quote(&exe.display().to_string())];
    if let Some(config) = &ctx.config {
        let absolute = std::path::absolute(config).unwrap_or_else(|_| PathBuf::from(config));
        parts.push("--config".into());
        parts.push(quote(&absolute.display().to_string()));
    }
    parts.push("hook".into());
    if let Some(m) = mode {
        parts.push("--mode".into());
        parts.push(m.as_str().into());
    }
    let command = parts.join(" ");
    let mut hooks = serde_json::Map::new();
    for (event, matcher) in EVENTS {
        let mut entry = json!({"hooks": [{"type": "command", "command": command}]});
        if *matcher {
            entry["matcher"] = Value::from("*");
        }
        hooks.insert((*event).into(), json!([entry]));
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({ "hooks": hooks }))?
    );
    Ok(EXIT_OK)
}

/// Quote for a POSIX shell (Claude Code runs hook commands through a shell).
fn quote(s: &str) -> String {
    if !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "/._-+:@".contains(c))
    {
        return s.to_owned();
    }
    format!("'{}'", s.replace('\'', r"'\''"))
}

#[cfg(test)]
mod tests {
    use super::quote;

    #[test]
    fn shell_quoting() {
        assert_eq!(
            quote("/usr/local/bin/agent-trace"),
            "/usr/local/bin/agent-trace"
        );
        assert_eq!(quote("/Users/a b/x"), "'/Users/a b/x'");
        assert_eq!(quote("it's"), r"'it'\''s'");
        assert_eq!(quote(""), "''");
    }
}
