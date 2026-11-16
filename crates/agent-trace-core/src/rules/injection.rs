//! AT-001 (prompt injection indicators) and AT-005 (authority spoofing).

use std::sync::OnceLock;

use regex::Regex;

use super::{FindingDraft, Rule, RuleContext};
use crate::event::{Event, TrustLevel};
use crate::finding::{AttemptStatus, Confidence, Finding, Severity};

struct Indicator {
    label: &'static str,
    regex: Regex,
}

fn compile(list: &[(&'static str, &str)]) -> Vec<Indicator> {
    list.iter()
        .map(|(label, re)| Indicator {
            label,
            regex: Regex::new(re).expect("valid indicator regex"),
        })
        .collect()
}

fn injection_indicators() -> &'static [Indicator] {
    static I: OnceLock<Vec<Indicator>> = OnceLock::new();
    I.get_or_init(|| {
        compile(&[
            (
                "override_task",
                r"(?i)\b(?:ignore|disregard|forget|abandon)\s+(?:all\s+|any\s+)?(?:of\s+)?(?:your|the|previous|prior|above|earlier|original)\b[^\n.]{0,40}\b(?:instructions?|task|rules|prompt|guidelines|summari[sz]ation)",
            ),
            (
                "role_reassignment",
                r"(?i)\b(?:you are now|from now on,? you|act as (?:an? )?(?:unrestricted|admin|root))",
            ),
            ("new_instructions", r"(?i)\bnew (?:instructions|task|objective)\s*:"),
            (
                "tool_invocation",
                r"(?i)\b(?:call|invoke|request|execute|trigger)\s+(?:the\s+)?(?:tool\s+)?`[A-Za-z0-9_.-]+`",
            ),
            (
                "data_transfer",
                r"(?i)\b(?:send|post|upload|forward|exfiltrate|transmit|leak)\b[^\n]{0,120}?\bto\s+(?:https?://|[\w.+-]+@[\w-]+\.)",
            ),
            (
                "concealment",
                r"(?i)\b(?:do not|don't|never)\s+(?:tell|inform|mention|reveal)\b[^\n]{0,30}\b(?:user|human|operator)",
            ),
        ])
    })
}

fn authority_indicators() -> &'static [Indicator] {
    static I: OnceLock<Vec<Indicator>> = OnceLock::new();
    I.get_or_init(|| {
        compile(&[
            (
                "role_header",
                r"(?im)^\s*(?:#+\s*)?\[?(?:system|developer|administrator|admin)(?:\s+(?:message|prompt|override|instruction|notice))?\]?\s*:",
            ),
            ("role_tag", r"(?i)<\|?\s*/?\s*(?:system|im_start\|?>\s*system)\s*\|?>"),
            (
                "ignore_previous",
                r"(?i)\b(?:ignore|disregard)\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+instructions\b",
            ),
            (
                "claimed_origin",
                r"(?i)\bthis (?:message|instruction|notice) (?:is|comes) from (?:the |your )?(?:system|developer|administrator|operator|anthropic|openai)\b",
            ),
            (
                "claimed_privilege",
                r"(?i)\b(?:highest[- ]priority|top[- ]priority|authori[sz]ed) (?:instruction|override|directive)s?\b|\byou have been granted (?:admin|root|elevated)",
            ),
        ])
    })
}

fn matches(event: &Event, indicators: &[Indicator]) -> Vec<&'static str> {
    let text = event.payload_text();
    indicators
        .iter()
        .filter(|i| i.regex.is_match(&text))
        .map(|i| i.label)
        .collect()
}

fn content_events<'a>(ctx: &RuleContext<'a>) -> impl Iterator<Item = &'a Event> {
    ctx.record
        .events
        .iter()
        .filter(|e| e.kind.carries_content() && e.trust_level == TrustLevel::LowerTrust)
}

/// AT-001: lower-trust content contains instructions that try to change agent behavior.
pub struct PromptInjectionRule;

impl Rule for PromptInjectionRule {
    fn id(&self) -> &'static str {
        "AT-001"
    }
    fn version(&self) -> u32 {
        1
    }
    fn title(&self) -> &'static str {
        "Potential prompt injection in lower-trust content"
    }
    fn evaluate(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        content_events(ctx)
            .filter_map(|event| {
                let hits = matches(event, injection_indicators());
                if hits.is_empty() {
                    return None;
                }
                let confidence = if hits.len() >= 2 {
                    Confidence::High
                } else {
                    Confidence::Medium
                };
                Some(
                    FindingDraft {
                        title: self.title().to_owned(),
                        description: format!(
                            "Event #{} ({}, origin {}) contains instruction-like text from a lower-trust \
                             source. Indicators: {}. This is a suspicion based on content patterns, not \
                             proof that the agent followed the instruction.",
                            event.sequence,
                            event.kind.as_str(),
                            event.origin.as_str(),
                            hits.join(", ")
                        ),
                        severity: Severity::Medium,
                        confidence,
                        evidence: vec![event.event_id],
                        status: AttemptStatus::Suspected,
                        remediation: "Treat tool results and documents as data. Keep untrusted content \
                                      out of the instruction channel and require confirmation for \
                                      privileged tools that follow untrusted input.",
                    }
                    .build(self, ctx),
                )
            })
            .collect()
    }
}

/// AT-005: lower-trust content claims system/developer authority.
pub struct AuthoritySpoofingRule;

impl Rule for AuthoritySpoofingRule {
    fn id(&self) -> &'static str {
        "AT-005"
    }
    fn version(&self) -> u32 {
        1
    }
    fn title(&self) -> &'static str {
        "Lower-trust content claims system-level authority"
    }
    fn evaluate(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        content_events(ctx)
            .filter_map(|event| {
                let hits = matches(event, authority_indicators());
                if hits.is_empty() {
                    return None;
                }
                let confidence = match hits.len() {
                    1 if hits[0] == "ignore_previous" => Confidence::Low,
                    1 => Confidence::Medium,
                    _ => Confidence::High,
                };
                Some(
                    FindingDraft {
                        title: self.title().to_owned(),
                        description: format!(
                            "Event #{} ({}) is lower-trust content that presents itself as \
                             system/developer authority. Indicators: {}.",
                            event.sequence,
                            event.kind.as_str(),
                            hits.join(", ")
                        ),
                        severity: Severity::Medium,
                        confidence,
                        evidence: vec![event.event_id],
                        status: AttemptStatus::Suspected,
                        remediation: "Never grant authority based on content claims. Only the \
                                      host application may set system or developer instructions.",
                    }
                    .build(self, ctx),
                )
            })
            .collect()
    }
}
