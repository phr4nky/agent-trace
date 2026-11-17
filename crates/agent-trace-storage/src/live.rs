//! Live persistence: a writer thread owns the [`Store`] and persists every event as soon as
//! the recorder emits it. Findings are re-computed after each event, so a viewer
//! (`agent-trace explore --follow`) sees the trace and its findings grow in real time.
//!
//! A dedicated thread keeps blocking database drivers away from async agent code.

use std::collections::HashMap;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::thread::JoinHandle;

use agent_trace_core::{Analyzer, Event, RecorderEvent, Trace, TraceRecord};
use uuid::Uuid;

use crate::{StorageError, Store, TraceSource};

enum Msg {
    Start(Box<Trace>),
    Event(Box<Event>),
    Finish(Box<Trace>),
}

/// Handle to the writer thread.
pub struct LiveWriter {
    tx: Sender<Msg>,
    handle: JoinHandle<(Store, Result<(), StorageError>)>,
}

impl LiveWriter {
    /// Start the writer thread. With `analyze`, findings are updated after every event
    /// with the default policy.
    pub fn spawn(store: Store, source: TraceSource, analyze: bool) -> Self {
        Self::spawn_with(store, source, analyze.then(Analyzer::default))
    }

    /// Start the writer thread; with an analyzer, findings are updated after every event.
    pub fn spawn_with(store: Store, source: TraceSource, analyzer: Option<Analyzer>) -> Self {
        let (tx, rx) = channel();
        let handle = std::thread::Builder::new()
            .name("agent-trace-live-writer".into())
            .spawn(move || run(store, rx, source, analyzer))
            .expect("spawn live writer thread");
        Self { tx, handle }
    }

    /// A recorder sink that forwards events to this writer.
    pub fn sink(&self) -> impl FnMut(RecorderEvent<'_>) + Send + 'static {
        let tx = self.tx.clone();
        move |event| {
            let msg = match event {
                RecorderEvent::Started(t) => Msg::Start(Box::new(t.clone())),
                RecorderEvent::Recorded(_, e) => Msg::Event(Box::new(e.clone())),
                RecorderEvent::Finished(t) => Msg::Finish(Box::new(t.clone())),
            };
            // If the writer died, its error is reported by `finish`.
            let _ = tx.send(msg);
        }
    }

    /// Wait until everything is written; returns the store and the first error, if any.
    pub fn finish(self) -> (Store, Result<(), StorageError>) {
        drop(self.tx);
        self.handle
            .join()
            .unwrap_or_else(|_| panic!("live writer thread panicked"))
    }
}

fn run(
    mut store: Store,
    rx: Receiver<Msg>,
    source: TraceSource,
    analyzer: Option<Analyzer>,
) -> (Store, Result<(), StorageError>) {
    let versions: Vec<(&str, u32)> = analyzer
        .iter()
        .flat_map(|a| a.rules().map(|r| (r.id(), r.version())))
        .collect();
    let mut open: HashMap<Uuid, TraceRecord> = HashMap::new();
    let mut first_error: Option<StorageError> = None;

    let mut step = |store: &mut Store, msg: Msg| -> Result<(), StorageError> {
        match msg {
            Msg::Start(trace) => {
                store.begin_trace(&trace, source)?;
                open.insert(
                    trace.trace_id,
                    TraceRecord {
                        trace: *trace,
                        events: Vec::new(),
                    },
                );
            }
            Msg::Event(event) => {
                store.append_event(&event)?;
                if let Some(record) = open.get_mut(&event.trace_id) {
                    record.events.push(*event);
                    if let Some(analyzer) = &analyzer {
                        let findings = analyzer.analyze(record, time::OffsetDateTime::now_utc());
                        store.save_findings(record.trace.trace_id, &versions, &findings)?;
                    }
                }
            }
            Msg::Finish(trace) => {
                store.update_trace(&trace)?;
                if let Some(mut record) = open.remove(&trace.trace_id) {
                    record.trace = *trace;
                    if let Some(analyzer) = &analyzer {
                        let findings = analyzer.analyze(&record, time::OffsetDateTime::now_utc());
                        store.save_findings(record.trace.trace_id, &versions, &findings)?;
                    }
                }
            }
        }
        Ok(())
    };

    for msg in rx {
        if first_error.is_some() {
            continue; // drain; the first error is reported
        }
        if let Err(e) = step(&mut store, msg) {
            first_error = Some(e);
        }
    }
    (store, first_error.map_or(Ok(()), Err))
}
