//! Diagnostic logging on stderr, passed through the shared redactor.
//! Captured agent events are never written to the diagnostic log.

use std::io::{self, Write};

use agent_trace_core::Redactor;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::MakeWriter;

/// Writer that redacts each formatted log line before it reaches the inner writer.
pub struct RedactingWriter<W: Write> {
    inner: W,
    redactor: Redactor,
}

impl<W: Write> RedactingWriter<W> {
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            redactor: Redactor::new(),
        }
    }
}

impl<W: Write> Write for RedactingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let text = String::from_utf8_lossy(buf);
        self.inner
            .write_all(self.redactor.scrub(&text).as_bytes())?;
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

struct StderrRedacted;

impl<'a> MakeWriter<'a> for StderrRedacted {
    type Writer = RedactingWriter<io::Stderr>;
    fn make_writer(&'a self) -> Self::Writer {
        RedactingWriter::new(io::stderr())
    }
}

pub fn init(verbosity: u8) {
    let default = match verbosity {
        0 => "warn",
        1 => "info",
        _ => "debug",
    };
    let filter =
        EnvFilter::try_from_env("AGENT_TRACE_LOG").unwrap_or_else(|_| EnvFilter::new(default));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(StderrRedacted)
        .with_target(false)
        .try_init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_lines_are_redacted() {
        let mut buf = Vec::new();
        {
            let mut w = RedactingWriter::new(&mut buf);
            writeln!(
                w,
                "connecting with Authorization: Bearer abcdefghijklmnopqrstuvwxyz"
            )
            .unwrap();
            writeln!(w, "env API_TOKEN=FAKE_SECRET_FOR_TESTING_ONLY").unwrap();
        }
        let out = String::from_utf8(buf).unwrap();
        assert!(!out.contains("abcdefghijklmnopqrstuvwxyz"), "{out}");
        assert!(!out.contains("FAKE_SECRET_FOR_TESTING_ONLY"), "{out}");
        assert!(out.contains("[REDACTED"));
    }
}
