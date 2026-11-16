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
    /// Events in sequence order.
    order: Vec<&'a Event>,
    /// Every link points to an earlier event (always true for validated traces). Enables
    /// the single-pass computations below; otherwise they fall back to per-event walks.
    backward_only: bool,
}

/// Maximum number of events kept in an evidence path; longer paths keep the source and the
/// events nearest to the request.
pub const MAX_EVIDENCE_PATH: usize = 64;
/// Maximum number of sensitive ancestors tracked per event (see [`TraceIndex::sensitive_causes`]).
pub const MAX_SENSITIVE_CAUSES: usize = 32;

/// One nearest matching ancestor: hop distance, the matching event and the first hop.
#[derive(Debug, Clone, Copy)]
struct Hit<'a> {
    dist: u32,
    source: &'a Event,
    next: Uuid,
}

/// Nearest matching cause of every event, computed in one pass over the trace.
/// For each event it keeps the nearest match and the nearest match of a *different agent*
/// than that one, which answers "nearest match whose agent is not X" for any X.
pub struct NearestCauses<'i, 'a> {
    index: &'i TraceIndex<'a>,
    table: HashMap<Uuid, [Option<Hit<'a>>; 2]>,
    pred: Box<dyn Fn(&Event) -> bool + 'i>,
}

impl<'a> NearestCauses<'_, 'a> {
    /// Shortest explicit cause path from the nearest matching ancestor to `id` (both
    /// inclusive), optionally excluding matches of `exclude_agent`. Same semantics as
    /// [`TraceIndex::cause_path`]; paths longer than [`MAX_EVIDENCE_PATH`] are shortened.
    pub fn path(&self, id: Uuid, exclude_agent: Option<&str>) -> Option<Vec<&'a Event>> {
        if !self.index.backward_only {
            let pred = &self.pred;
            return self
                .index
                .cause_path(id, |e| {
                    pred(e) && exclude_agent.is_none_or(|a| e.agent() != a)
                })
                .map(cap_path);
        }
        let hits = self.table.get(&id)?;
        let ok = |h: &&Hit<'a>| exclude_agent.is_none_or(|a| h.source.agent() != a);
        let mut hit = *hits.iter().flatten().find(ok)?;
        let mut path = vec![self.index.get(id)?];
        loop {
            // Stop after the request-side part of a long path; the source closes it.
            if hit.next == hit.source.event_id || path.len() >= MAX_EVIDENCE_PATH - 1 {
                path.push(hit.source);
                break;
            }
            path.push(self.index.get(hit.next)?);
            let source = hit.source.event_id;
            hit = *self
                .table
                .get(&hit.next)?
                .iter()
                .flatten()
                .find(|h| h.source.event_id == source)?;
        }
        path.reverse();
        Some(path)
    }
}

/// Keep the source and the request-side end of an over-long path (same shape as above).
fn cap_path(path: Vec<&Event>) -> Vec<&Event> {
    if path.len() <= MAX_EVIDENCE_PATH {
        return path;
    }
    let mut out = vec![path[0]];
    out.extend_from_slice(&path[path.len() - (MAX_EVIDENCE_PATH - 1)..]);
    out
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
        let mut order: Vec<&'a Event> = events.iter().collect();
        order.sort_by_key(|e| e.sequence);
        let backward_only = order.iter().all(|e| {
            e.links()
                .all(|l| by_id.get(&l).is_none_or(|t| t.sequence < e.sequence))
        });
        Self {
            by_id,
            children,
            order,
            backward_only,
        }
    }

    /// Precompute the nearest ancestor matching `pred` for every event (linear in the
    /// number of links). Use this instead of calling [`Self::cause_path`] per event.
    pub fn nearest_causes<'i>(
        &'i self,
        pred: impl Fn(&Event) -> bool + 'i,
    ) -> NearestCauses<'i, 'a> {
        let mut table: HashMap<Uuid, [Option<Hit<'a>>; 2]> = HashMap::new();
        if self.backward_only {
            for event in &self.order {
                let mut candidates: Vec<Hit<'a>> = Vec::new();
                for link in event.cause_links() {
                    let Some(target) = self.get(link) else {
                        continue;
                    };
                    if pred(target) {
                        candidates.push(Hit {
                            dist: 1,
                            source: target,
                            next: link,
                        });
                    }
                    if let Some(hits) = table.get(&link) {
                        candidates.extend(hits.iter().flatten().map(|h| Hit {
                            dist: h.dist + 1,
                            source: h.source,
                            next: link,
                        }));
                    }
                }
                // Stable: on equal distance the earlier link (direct cause first) wins.
                candidates.sort_by_key(|h| h.dist);
                let best = candidates.first().copied();
                let second = best.and_then(|b| {
                    candidates
                        .iter()
                        .find(|h| h.source.agent() != b.source.agent())
                        .copied()
                });
                if best.is_some() {
                    table.insert(event.event_id, [best, second]);
                }
            }
        }
        NearestCauses {
            index: self,
            table,
            pred: Box::new(pred),
        }
    }

    /// For every event, its sensitive causal ancestors (nearest first by sequence, at most
    /// [`MAX_SENSITIVE_CAUSES`]) and whether more exist. Linear in links times the cap.
    pub fn sensitive_causes(&self) -> HashMap<Uuid, (Vec<&'a Event>, bool)> {
        let mut table: HashMap<Uuid, (Vec<&'a Event>, bool)> = HashMap::new();
        if !self.backward_only {
            for event in &self.order {
                let all: Vec<&'a Event> = self
                    .cause_ancestors(event.event_id)
                    .into_iter()
                    .filter(|e| e.is_sensitive())
                    .collect();
                let more = all.len() > MAX_SENSITIVE_CAUSES;
                let mut all = all;
                all.sort_by_key(|e| std::cmp::Reverse(e.sequence));
                all.truncate(MAX_SENSITIVE_CAUSES);
                table.insert(event.event_id, (all, more));
            }
            return table;
        }
        let sensitive: HashSet<Uuid> = self
            .order
            .iter()
            .filter(|e| e.is_sensitive())
            .map(|e| e.event_id)
            .collect();
        for event in &self.order {
            let mut set: Vec<&'a Event> = Vec::new();
            let mut more = false;
            for link in event.cause_links() {
                let Some(target) = self.get(link) else {
                    continue;
                };
                if sensitive.contains(&link) {
                    set.push(target);
                }
                if let Some((inherited, m)) = table.get(&link) {
                    set.extend(inherited.iter().copied());
                    more |= *m;
                }
            }
            set.sort_by_key(|e| std::cmp::Reverse(e.sequence));
            set.dedup_by_key(|e| e.event_id);
            if set.len() > MAX_SENSITIVE_CAUSES {
                set.truncate(MAX_SENSITIVE_CAUSES);
                more = true;
            }
            if !set.is_empty() {
                table.insert(event.event_id, (set, more));
            }
        }
        table
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
