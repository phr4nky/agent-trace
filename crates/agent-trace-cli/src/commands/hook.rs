//! `agent-trace hook`: the command Claude Code runs for each hook event.
//!
//! Each invocation is a new process: it reads the event from stdin and continues the
//! session's trace through [`SharedTrace`] (which locks it, because parallel tool calls fire
//! hooks concurrently), runs the rules and, for a denied or questioned PreToolUse call, prints
//! Claude Code's `deny` or `ask` decision on stdout. Nothing else is written to stdout.

use std::io::Read;
use std::path::PathBuf;

use agent_trace_core::TraceAccess;
use agent_trace_mcp::ProxyMode;
use agent_trace_storage::SharedTrace;
use anyhow::Context as _;
use serde_json::{Value, json};

use super::Context;
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
    /// Task profile (`--profile`; else `$AGENT_TRACE_PROFILE`).
    pub profile: Option<String>,
    pub print_settings: bool,
}

pub fn run(ctx: &Context, args: HookArgs) -> anyhow::Result<u8> {
    if args.print_settings {
        return print_settings(ctx, args.mode, args.profile.as_deref());
    }
    let input = read_input()?;
    let pre_tool_use = input
        .as_ref()
        .is_some_and(|i| i.hook_event_name == "PreToolUse");
    let loaded = match ctx.config() {
        Ok(loaded) => loaded,
        Err(e) => return config_error(ctx, args.mode, pre_tool_use, e),
    };
    let section = &loaded.config.hooks;
    let mode = args.mode.or(section.mode).unwrap_or_default();
    // An unknown profile is an error like any other: without the profile nothing is decided.
    let result = loaded.profile(args.profile.as_deref()).and_then(|profile| {
        let settings = HookSettings {
            mode,
            profile,
            policy: loaded.policy(),
            taint_sources: section.taint_sources.clone().unwrap_or_else(|| {
                DEFAULT_HOOK_TAINT_SOURCES
                    .iter()
                    .map(std::string::ToString::to_string)
                    .collect()
            }),
        };
        match &input {
            Some(i) if !i.session_id.is_empty() => record(ctx, i, &settings, &loaded),
            Some(_) => Err(anyhow::anyhow!("hook event without session_id")),
            None => Err(anyhow::anyhow!(
                "stdin is not a Claude Code hook event (JSON, at most {MAX_INPUT_BYTES} bytes)"
            )),
        }
    });
    match result {
        Ok(HookOutput {
            decision: Some((decision, reason)),
        }) => {
            let decision = json!({"hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": decision.as_str(),
                "permissionDecisionReason": reason,
            }});
            println!("{decision}");
            Ok(EXIT_OK)
        }
        Ok(_) => Ok(EXIT_OK),
        Err(e) if pre_tool_use && mode.gates() && section.on_error == OnError::Deny => {
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

/// The hook event on stdin: `None` if it is not a Claude Code hook event (not JSON, or larger
/// than [`MAX_INPUT_BYTES`]).
fn read_input() -> anyhow::Result<Option<HookInput>> {
    let mut raw = Vec::new();
    std::io::stdin()
        .take(MAX_INPUT_BYTES + 1)
        .read_to_end(&mut raw)
        .context("cannot read the hook event from stdin")?;
    Ok((raw.len() as u64 <= MAX_INPUT_BYTES)
        .then(|| serde_json::from_slice(&raw).ok())
        .flatten())
}

/// The configuration could not be loaded (`main` checks it before any command runs), so
/// nothing can be recorded or decided. Handled like any other recording error.
pub fn config_failed(
    ctx: &Context,
    mode: Option<ProxyMode>,
    error: anyhow::Error,
) -> anyhow::Result<u8> {
    let pre_tool_use = read_input()
        .ok()
        .flatten()
        .is_some_and(|i| i.hook_event_name == "PreToolUse");
    config_error(ctx, mode, pre_tool_use, error)
}

/// A PreToolUse call is denied (exit 2) when the `[hooks]` table, read on its own, asks for it
/// (`on_error = "deny"` in enforce or ask mode); otherwise the error is returned (exit 1, Claude
/// Code continues). A file that is not TOML cannot say `on_error`, so it fails open.
///
/// The reason Claude sees does not repeat the error: it may name canary tokens and the
/// variables that hold them, which the agent must not learn.
fn config_error(
    ctx: &Context,
    mode: Option<ProxyMode>,
    pre_tool_use: bool,
    error: anyhow::Error,
) -> anyhow::Result<u8> {
    let data_dir = ctx.data_dir().ok();
    let fail_closed = pre_tool_use
        && crate::config::hooks_section(ctx.config.as_deref(), data_dir.as_deref()).is_some_and(
            |s| mode.or(s.mode).unwrap_or_default().gates() && s.on_error == OnError::Deny,
        );
    if !fail_closed {
        return Err(error);
    }
    eprintln!(
        "agent-trace could not load its configuration, denied (on_error = \"deny\"). The \
         error is not shown to the agent; run `agent-trace trace list` with the hook's options \
         in a terminal to see it."
    );
    Ok(EXIT_BLOCK)
}

fn record(
    ctx: &Context,
    input: &HookInput,
    settings: &HookSettings,
    loaded: &crate::config::Loaded,
) -> anyhow::Result<HookOutput> {
    let trace_id = hooks::trace_id_for(&input.session_id);
    let first = hooks::new_recorder(input);
    let created = std::sync::Mutex::new(Some(first));
    let trace = SharedTrace::new(
        ctx.open_store()?,
        &ctx.data_dir()?.join("hooks"),
        trace_id,
        Some(loaded.analyzer()),
        move || {
            created
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
                .expect("a trace is created at most once per hook call")
        },
    )?;
    let mut output = HookOutput::default();
    trace
        .with_recorder(&mut |rec| output = hooks::apply(rec, input, settings))
        .map_err(|e| anyhow::anyhow!(e))?;
    Ok(output)
}

/// Print the `hooks` block for Claude Code's settings.json.
fn print_settings(
    ctx: &Context,
    mode: Option<ProxyMode>,
    profile: Option<&str>,
) -> anyhow::Result<u8> {
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
    if let Some(p) = profile {
        // Fail here, not on every hook call, if the profile does not exist.
        ctx.config()?.profile(Some(p))?;
        parts.push("--profile".into());
        parts.push(quote(p));
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
