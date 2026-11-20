//! Analyzer findings: evidence-based indicators, not proof of compromise.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::recorder::DETERMINISTIC_NAMESPACE;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Severity {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "info" => Ok(Self::Info),
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            "critical" => Ok(Self::Critical),
            other => Err(format!("unknown severity {other:?}")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl Confidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

/// What the trace shows about the risky action. There is intentionally no
/// "succeeded"/"exfiltrated" state: `executed` only means the trace records an
/// execution event, which for the demo is always a mock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptStatus {
    Suspected,
    Attempted,
    Blocked,
    Executed,
    Unknown,
}

impl AttemptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Suspected => "suspected",
            Self::Attempted => "attempted",
            Self::Blocked => "blocked",
            Self::Executed => "executed",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub finding_id: Uuid,
    pub trace_id: Uuid,
    pub rule_id: String,
    pub rule_version: u32,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub evidence_event_ids: Vec<Uuid>,
    pub attempt_status: AttemptStatus,
    pub remediation: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// Taxonomy tags of the rule (OWASP LLM Top 10, MITRE ATLAS, custom), see
    /// [`crate::taxonomy`]. Absent in reports and stored findings from older versions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

impl Finding {
    /// Deterministic finding id: same trace, rule version and evidence → same id.
    /// This makes re-analysis idempotent.
    pub fn derive_id(trace_id: Uuid, rule_id: &str, rule_version: u32, evidence: &[Uuid]) -> Uuid {
        let mut key = format!("{trace_id}/{rule_id}/v{rule_version}");
        for id in evidence {
            key.push('/');
            key.push_str(&id.to_string());
        }
        Uuid::new_v5(&DETERMINISTIC_NAMESPACE, key.as_bytes())
    }

    /// Fill in the built-in tags when the finding has none (findings stored or exported by
    /// versions before tags existed). Custom rule findings are left as they are.
    pub fn with_default_tags(mut self) -> Self {
        if self.tags.is_empty() {
            self.tags = crate::taxonomy::builtin_tags(&self.rule_id)
                .iter()
                .map(|t| (*t).to_owned())
                .collect();
        }
        self
    }
}
