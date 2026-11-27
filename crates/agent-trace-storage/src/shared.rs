//! A trace written by several processes: the MCP proxies of one client session, or one
//! `agent-trace hook` process per Claude Code hook event.
//!
//! Every access takes an exclusive file lock for the trace, loads it from the store, lets the
//! caller record on the resumed recorder, appends the new events, updates the header and
//! re-runs the rules. The lock serializes writers on one machine, so sequence numbers never
//! collide; all state lives in the store.

use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use agent_trace_core::{AccessError, Analyzer, TraceAccess, TraceRecord, TraceRecorder};
use uuid::Uuid;

use crate::{StorageError, Store, TraceSource, create_private_dir};

type Create = Box<dyn Fn() -> TraceRecorder + Send + Sync>;

/// [`TraceAccess`] backed by a [`Store`] and a lock file.
pub struct SharedTrace {
    store: Mutex<Store>,
    lock_path: PathBuf,
    trace_id: Uuid,
    analyzer: Option<Analyzer>,
    create: Create,
}

impl std::fmt::Debug for SharedTrace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedTrace")
            .field("trace_id", &self.trace_id)
            .field("lock_path", &self.lock_path)
            .finish()
    }
}

impl SharedTrace {
    /// `create` starts the trace when it is not stored yet; its recorder must use `trace_id`.
    /// Lock files live in `lock_dir` (created private). With `analyzer`, findings are
    /// updated after every access.
    pub fn new(
        store: Store,
        lock_dir: &Path,
        trace_id: Uuid,
        analyzer: Option<Analyzer>,
        create: impl Fn() -> TraceRecorder + Send + Sync + 'static,
    ) -> Result<Self, StorageError> {
        create_private_dir(lock_dir)?;
        Ok(Self {
            store: Mutex::new(store),
            lock_path: lock_dir.join(format!("{trace_id}.lock")),
            trace_id,
            analyzer,
            create: Box::new(create),
        })
    }

    /// The stored trace (outside the lock: for reporting after the work is done).
    pub fn load(&self) -> Result<TraceRecord, StorageError> {
        self.store
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .load_trace(self.trace_id)
    }

    /// The stored findings of the trace.
    pub fn findings(&self) -> Result<Vec<agent_trace_core::Finding>, StorageError> {
        self.store
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .load_findings(self.trace_id)
    }

    fn lock_file(&self) -> std::io::Result<File> {
        let mut options = OpenOptions::new();
        options.create(true).truncate(false).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(&self.lock_path)?;
        file.lock()?;
        Ok(file)
    }

    fn access(&self, f: &mut dyn FnMut(&mut TraceRecorder)) -> Result<(), StorageError> {
        // Released when dropped, after everything is written.
        let _lock = self.lock_file()?;
        let mut store = self
            .store
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (mut rec, is_new) = match store.load_trace(self.trace_id) {
            Ok(record) => (TraceRecorder::resume(record), false),
            Err(StorageError::TraceNotFound(_)) => ((self.create)(), true),
            Err(e) => return Err(e),
        };
        if rec.trace_id() != self.trace_id {
            return Err(StorageError::Corrupt(format!(
                "new recorder has trace id {}, expected {}",
                rec.trace_id(),
                self.trace_id
            )));
        }
        let before = rec.events().len();
        f(&mut rec);
        if is_new {
            store.begin_trace(rec.trace(), TraceSource::Recorded)?;
        }
        for event in &rec.events()[before..] {
            store.append_event(event)?;
        }
        store.update_trace(rec.trace())?;
        if let Some(analyzer) = &self.analyzer {
            let record = TraceRecord {
                trace: rec.trace().clone(),
                events: rec.events().to_vec(),
            };
            let findings = analyzer.analyze(&record, time::OffsetDateTime::now_utc());
            let versions: Vec<(&str, u32)> =
                analyzer.rules().map(|r| (r.id(), r.version())).collect();
            store.save_findings(self.trace_id, &versions, &findings)?;
        }
        Ok(())
    }
}

impl TraceAccess for SharedTrace {
    fn trace_id(&self) -> Uuid {
        self.trace_id
    }

    fn with_recorder(&self, f: &mut dyn FnMut(&mut TraceRecorder)) -> Result<(), AccessError> {
        self.access(f).map_err(|e| Box::new(e) as AccessError)
    }
}

#[cfg(test)]
mod tests {
    use agent_trace_core::{EventKind, EventSpec, ExecutionMode, Origin, TrustLevel};

    use super::*;

    fn shared(dir: &Path, id: Uuid) -> SharedTrace {
        let store = Store::open(dir.join("db.sqlite3")).unwrap();
        SharedTrace::new(
            store,
            &dir.join("locks"),
            id,
            Some(Analyzer::default()),
            move || TraceRecorder::with_trace_id("shared", ExecutionMode::Live, id),
        )
        .unwrap()
    }

    fn record_one(access: &SharedTrace, name: &str) {
        access
            .with_recorder(&mut |rec| {
                rec.record(EventSpec::new(
                    EventKind::AgentDecision,
                    Origin::System,
                    TrustLevel::Trusted,
                    name,
                ));
            })
            .unwrap();
    }

    #[test]
    fn writers_with_separate_stores_append_to_one_trace() {
        let dir = tempfile::tempdir().unwrap();
        let id = Uuid::new_v4();
        // Each thread has its own store connection, like separate processes.
        let threads: Vec<_> = (0..6)
            .map(|i| {
                let dir = dir.path().to_path_buf();
                std::thread::spawn(move || {
                    let access = shared(&dir, id);
                    for j in 0..5 {
                        record_one(&access, &format!("w{i}-{j}"));
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        let record = shared(dir.path(), id).load().unwrap();
        assert_eq!(record.events.len(), 30);
        for (i, e) in record.events.iter().enumerate() {
            assert_eq!(e.sequence, i as u64 + 1);
        }
        agent_trace_core::validate(&record).unwrap();
    }

    #[test]
    fn a_recorder_for_another_trace_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("db.sqlite3")).unwrap();
        let access = SharedTrace::new(store, dir.path(), Uuid::new_v4(), None, || {
            TraceRecorder::new("other", ExecutionMode::Live)
        })
        .unwrap();
        assert!(access.with_recorder(&mut |_| {}).is_err());
    }
}
