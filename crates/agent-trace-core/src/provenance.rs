//! Provenance helpers: explicit causal links, trust-boundary walks and trace validation.

use std::collections::{HashMap, HashSet, VecDeque};

use thiserror::Error;
use uuid::Uuid;

use crate::event::{Event, SUPPORTED_SCHEMA_VERSIONS, TraceRecord, TrustLevel};
use crate::redact::MAX_PAYLOAD_BYTES;

/// Index over the events of one trace for link lookups.
#[derive(Debug)]
pub struct TraceIndex<'a> {
    by_id: HashMap<Uuid, &'a Event>,
    children: HashMap<Uuid, Vec<&'a Event>>,
}

impl<'a> TraceIndex<'a> {
    pub fn new(events: &'a [Event]) -> Self {
        let mut by_id = HashMap::new();
        let mut children: HashMap<Uuid, Vec<&'a Event>> = HashMap::new();
        for event in events {
            by_id.insert(event.event_id, event);
            for link in event.links() {
                children.entry(link).or_default().push(event);
            }
        }
        for list in children.values_mut() {
            list.sort_by_key(|e| e.sequence);
            list.dedup_by_key(|e| e.event_id);
        }
        Self { by_id, children }
    }

    pub fn get(&self, id: Uuid) -> Option<&'a Event> {
        self.by_id.get(&id).copied()
    }

    /// Events that name `id` as parent or cause, ordered by sequence.
    pub fn dependents(&self, id: Uuid) -> &[&'a Event] {
        self.children.get(&id).map(Vec::as_slice).unwrap_or(&[])
    }

    /// All events transitively depending on `id` (breadth first, by explicit links only).
    pub fn descendants(&self, id: Uuid) -> Vec<&'a Event> {
        let mut seen = HashSet::new();
        let mut queue = vec![id];
        let mut out = Vec::new();
        while let Some(current) = queue.pop() {
            for child in self.dependents(current) {
                if seen.insert(child.event_id) {
                    out.push(*child);
                    queue.push(child.event_id);
                }
            }
        }
        out.sort_by_key(|e| e.sequence);
        out
    }

    /// The explicit causal chain of `id`: follows `caused_by_event_id`, falling back to
    /// `parent_event_id`. Returns events from the root cause to `id` (inclusive).
    /// Missing links terminate the chain; nothing is invented.
    pub fn causal_chain(&self, id: Uuid) -> Vec<&'a Event> {
        let mut chain = Vec::new();
        let mut seen = HashSet::new();
        let mut current = self.get(id);
        while let Some(event) = current {
            if !seen.insert(event.event_id) {
                break; // defensive: validated traces are acyclic
            }
            chain.push(event);
            current = event
                .caused_by_event_id
                .or(event.parent_event_id)
                .and_then(|next| self.get(next));
        }
        chain.reverse();
        chain
    }

    /// Shortest explicit cause path from the nearest event matching `pred` to `id`
    /// (both inclusive). Follows `caused_by_event_id` (or the parent if no cause was recorded)
    /// and all `context_event_ids`. Returns `None` if no ancestor matches.
    pub fn cause_path(&self, id: Uuid, pred: impl Fn(&Event) -> bool) -> Option<Vec<&'a Event>> {
        let start = self.get(id)?;
        let mut prev: HashMap<Uuid, Uuid> = HashMap::new();
        let mut seen = HashSet::from([id]);
        let mut queue = VecDeque::from([start]);
        while let Some(current) = queue.pop_front() {
            if current.event_id != id && pred(current) {
                let mut path = vec![current];
                let mut cursor = current.event_id;
                while let Some(next) = prev.get(&cursor) {
                    path.push(self.get(*next)?);
                    cursor = *next;
                }
                return Some(path);
            }
            // Visit nearer causes first: direct cause before context links.
            for link in current.cause_links() {
                if seen.insert(link)
                    && let Some(e) = self.get(link)
                {
                    prev.insert(link, current.event_id);
                    queue.push_back(e);
                }
            }
        }
        None
    }

    /// All explicit causal ancestors of `id` (excluding `id`), nearest first.
    pub fn cause_ancestors(&self, id: Uuid) -> Vec<&'a Event> {
        let mut out = Vec::new();
        let mut seen = HashSet::from([id]);
        let mut queue: VecDeque<Uuid> = self
            .get(id)
            .map(|e| e.cause_links().collect())
            .unwrap_or_default();
        while let Some(current) = queue.pop_front() {
            if !seen.insert(current) {
                continue;
            }
            if let Some(e) = self.get(current) {
                out.push(e);
                queue.extend(e.cause_links());
            }
        }
        out
    }

    /// Nearest lower-trust ancestor of `id` by explicit causal links, if any.
    pub fn lower_trust_source(&self, id: Uuid) -> Option<&'a Event> {
        self.cause_path(id, |e| e.trust_level == TrustLevel::LowerTrust)
            .and_then(|p| p.into_iter().next())
    }
}

fn links(event: &Event) -> impl Iterator<Item = Uuid> + '_ {
    event.links()
}

/// Why a trace failed validation.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ValidationError {
    #[error("unsupported schema version {found:?} (supported: {supported})")]
    UnsupportedSchema { found: String, supported: String },
    #[error("event {event_id} belongs to trace {found}, expected {expected}")]
    ForeignEvent {
        event_id: Uuid,
        found: Uuid,
        expected: Uuid,
    },
    #[error("duplicate event id {0}")]
    DuplicateEventId(Uuid),
    #[error("event {event_id} has sequence {found}, expected {expected}")]
    BadSequence {
        event_id: Uuid,
        found: u64,
        expected: u64,
    },
    #[error("event {event_id} links to unknown event {target}")]
    DanglingLink { event_id: Uuid, target: Uuid },
    #[error("event {event_id} links to itself")]
    SelfLink { event_id: Uuid },
    #[error("cyclic causal graph involving event {0}")]
    Cycle(Uuid),
    #[error("event {event_id} links forward to later event {target}")]
    ForwardLink { event_id: Uuid, target: Uuid },
    #[error("event {event_id} payload is {size} bytes (limit {limit})")]
    PayloadTooLarge {
        event_id: Uuid,
        size: usize,
        limit: usize,
    },
}

/// Validate the documented trace invariants. Used for imports of untrusted data.
pub fn validate(record: &TraceRecord) -> Result<(), ValidationError> {
    check_schema(&record.trace.schema_version)?;
    let trace_id = record.trace.trace_id;
    let mut ids = HashSet::new();
    for (i, event) in record.events.iter().enumerate() {
        check_schema(&event.schema_version)?;
        if event.trace_id != trace_id {
            return Err(ValidationError::ForeignEvent {
                event_id: event.event_id,
                found: event.trace_id,
                expected: trace_id,
            });
        }
        if !ids.insert(event.event_id) {
            return Err(ValidationError::DuplicateEventId(event.event_id));
        }
        let expected = i as u64 + 1;
        if event.sequence != expected {
            return Err(ValidationError::BadSequence {
                event_id: event.event_id,
                found: event.sequence,
                expected,
            });
        }
        let size = serde_json::to_vec(&event.payload)
            .map(|v| v.len())
            .unwrap_or(0);
        // Allow some slack for redaction placeholders added on import.
        let limit = MAX_PAYLOAD_BYTES * 4;
        if size > limit {
            return Err(ValidationError::PayloadTooLarge {
                event_id: event.event_id,
                size,
                limit,
            });
        }
    }
    let seq: HashMap<Uuid, u64> = record
        .events
        .iter()
        .map(|e| (e.event_id, e.sequence))
        .collect();
    for event in &record.events {
        for target in links(event) {
            if target == event.event_id {
                return Err(ValidationError::SelfLink {
                    event_id: event.event_id,
                });
            }
            if !seq.contains_key(&target) {
                return Err(ValidationError::DanglingLink {
                    event_id: event.event_id,
                    target,
                });
            }
        }
    }
    detect_cycle(&record.events)?;
    for event in &record.events {
        for target in links(event) {
            if seq[&target] > event.sequence {
                return Err(ValidationError::ForwardLink {
                    event_id: event.event_id,
                    target,
                });
            }
        }
    }
    Ok(())
}

fn check_schema(version: &str) -> Result<(), ValidationError> {
    if SUPPORTED_SCHEMA_VERSIONS.contains(&version) {
        Ok(())
    } else {
        Err(ValidationError::UnsupportedSchema {
            found: version.to_owned(),
            supported: SUPPORTED_SCHEMA_VERSIONS.join(", "),
        })
    }
}

fn detect_cycle(events: &[Event]) -> Result<(), ValidationError> {
    #[derive(Clone, Copy, PartialEq)]
    enum Mark {
        Visiting,
        Done,
    }
    let edges: HashMap<Uuid, Vec<Uuid>> = events
        .iter()
        .map(|e| (e.event_id, links(e).collect()))
        .collect();
    let mut marks: HashMap<Uuid, Mark> = HashMap::new();
    for start in events.iter().map(|e| e.event_id) {
        if marks.contains_key(&start) {
            continue;
        }
        // iterative DFS: (node, next edge index)
        let mut stack = vec![(start, 0usize)];
        marks.insert(start, Mark::Visiting);
        while let Some((node, idx)) = stack.pop() {
            let next = edges.get(&node).and_then(|v| v.get(idx)).copied();
            match next {
                Some(target) => {
                    stack.push((node, idx + 1));
                    match marks.get(&target) {
                        Some(Mark::Visiting) => return Err(ValidationError::Cycle(target)),
                        Some(Mark::Done) => {}
                        None => {
                            marks.insert(target, Mark::Visiting);
                            stack.push((target, 0));
                        }
                    }
                }
                None => {
                    marks.insert(node, Mark::Done);
                }
            }
        }
    }
    Ok(())
}
