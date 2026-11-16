//! Plain terminal formatting helpers.

use agent_trace_core::{
    AttemptStatus, Event, ExecutionMode, Finding, Origin, Severity, ToolState, TraceRecord,
    TrustLevel,
};
use std::borrow::Cow;
use std::fmt;

/// `println!` for command output on stdout that tolerates a closed pipe
/// (`agent-trace ... | head`): output stops, the command finishes with its real exit code.
macro_rules! outln {
    () => {
        $crate::output::emit(format_args!(""), true)
    };
    ($($arg:tt)*) => {
        $crate::output::emit(format_args!($($arg)*), true)
    };
}

/// `print!` counterpart of [`outln!`].
macro_rules! out {
    ($($arg:tt)*) => {
        $crate::output::emit(format_args!($($arg)*), false)
    };
}

/// Write to stdout. A reader that went away (broken pipe) silences further output instead
/// of panicking like `println!` (exit 101, outside the documented exit codes); any other
/// write error still panics as before.
pub fn emit(args: fmt::Arguments<'_>, newline: bool) {
    use std::io::Write;
    use std::sync::atomic::{AtomicBool, Ordering};
    static CLOSED: AtomicBool = AtomicBool::new(false);
    if CLOSED.load(Ordering::Relaxed) {
        return;
    }
    let mut stdout = std::io::stdout().lock();
    let result = stdout
        .write_fmt(args)
        .and_then(|()| {
            if newline {
                stdout.write_all(b"\n")
            } else {
                Ok(())
            }
        })
        .and_then(|()| stdout.flush());
    match result {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {
            CLOSED.store(true, Ordering::Relaxed);
        }
        Err(e) => panic!("failed printing to stdout: {e}"),
    }
}

use uuid::Uuid;

/// Make untrusted text safe for a terminal or CI log: control characters (C0, DEL, C1,
/// including newlines) and bidi/zero-width format characters are shown as `\u{..}` escapes.
/// Trace data (names, agent ids, payloads, error texts) must pass through here before it is
/// printed; otherwise it can emit escape sequences or start forged log lines.
pub fn term_safe(text: &str) -> Cow<'_, str> {
    if !text.chars().any(needs_escape) {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len() + 8);
    for c in text.chars() {
        if needs_escape(c) {
            out.push_str(&format!("\\u{{{:x}}}", c as u32));
        } else {
            out.push(c);
        }
    }
    Cow::Owned(out)
}

/// Like [`term_safe`], but keeps line breaks (for multi-line text we render ourselves).
pub fn term_safe_lines(text: &str) -> String {
    text.split('\n')
        .map(|l| term_safe(l).into_owned())
        .collect::<Vec<_>>()
        .join("\n")
}

fn needs_escape(c: char) -> bool {
    c.is_control()
        || matches!(c, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{feff}')
}

#[derive(Debug, Clone, Copy)]
pub struct Style {
    color: bool,
}

impl Style {
    pub fn new(color: bool) -> Self {
        Self { color }
    }

    fn paint(&self, code: &str, text: &str) -> String {
        if self.color {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_owned()
        }
    }

    pub fn bold(&self, t: &str) -> String {
        self.paint("1", t)
    }
    pub fn dim(&self, t: &str) -> String {
        self.paint("2", t)
    }
    pub fn red(&self, t: &str) -> String {
        self.paint("31", t)
    }
    pub fn yellow(&self, t: &str) -> String {
        self.paint("33", t)
    }
    pub fn green(&self, t: &str) -> String {
        self.paint("32", t)
    }
    pub fn magenta(&self, t: &str) -> String {
        self.paint("35", t)
    }
    pub fn cyan(&self, t: &str) -> String {
        self.paint("36", t)
    }

    pub fn severity(&self, s: Severity) -> String {
        let text = format!("{:<8}", s.as_str().to_uppercase());
        match s {
            Severity::Critical | Severity::High => self.red(&text),
            Severity::Medium => self.yellow(&text),
            _ => self.dim(&text),
        }
    }

    pub fn status(&self, s: AttemptStatus) -> String {
        let text = format!("{:<9}", s.as_str());
        match s {
            AttemptStatus::Blocked => self.green(&text),
            AttemptStatus::Executed => self.red(&text),
            _ => self.yellow(&text),
        }
    }

    pub fn mode(&self, m: ExecutionMode) -> String {
        match m {
            ExecutionMode::Simulated => self.magenta("SIMULATED"),
            ExecutionMode::Live => self.cyan("LIVE"),
        }
    }

    /// Short label for an event row, colored by origin/trust/outcome.
    pub fn event_marker(&self, e: &Event) -> String {
        if e.tool_state == Some(ToolState::Blocked) {
            return self.green("BLOCKED");
        }
        if e.trust_level == TrustLevel::LowerTrust {
            return self.yellow("UNTRUSTED");
        }
        match e.origin {
            Origin::User => self.cyan("user"),
            Origin::Agent => self.magenta("agent"),
            Origin::McpTool => self.yellow("mcp"),
            Origin::Policy => self.green("policy"),
            _ => self.dim(e.origin.as_str()),
        }
    }
}

pub fn short(id: Uuid) -> String {
    id.to_string()[..8].to_owned()
}

pub fn seq_of(record: &TraceRecord, id: Uuid) -> String {
    record
        .event(id)
        .map(|e| format!("#{}", e.sequence))
        .unwrap_or_else(|| format!("?{}", short(id)))
}

pub fn finding_line(style: &Style, record: &TraceRecord, f: &Finding) -> String {
    let evidence: Vec<String> = f
        .evidence_event_ids
        .iter()
        .map(|id| seq_of(record, *id))
        .collect();
    format!(
        "{} {} {} conf={:<6} {}  evidence: {}",
        style.bold(&term_safe(&f.rule_id)),
        style.severity(f.severity),
        style.status(f.attempt_status),
        f.confidence.as_str(),
        term_safe(&f.title),
        evidence.join(" → ")
    )
}

pub fn max_severity(findings: &[Finding]) -> Option<Severity> {
    findings.iter().map(|f| f.severity).max()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn term_safe_escapes_controls_and_bidi() {
        assert_eq!(term_safe("plain name"), "plain name");
        assert_eq!(term_safe("a\u{1b}[31mb"), "a\\u{1b}[31mb");
        assert_eq!(term_safe("x\n::notice::y"), "x\\u{a}::notice::y");
        assert_eq!(
            term_safe("\u{9b}2J\u{7f}\u{202e}"),
            "\\u{9b}2J\\u{7f}\\u{202e}"
        );
        assert_eq!(term_safe_lines("a\nb\u{1b}"), "a\nb\\u{1b}");
    }
}
