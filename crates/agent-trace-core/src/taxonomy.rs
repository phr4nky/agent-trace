//! Taxonomy tags: the mapping of rules to the [OWASP Top 10 for LLM Applications (2025)][owasp]
//! and to [MITRE ATLAS][atlas] techniques.
//!
//! Tags are plain IDs (`LLM01:2025`, `AML.T0051.001`) so they filter well in GitHub Code
//! Scanning and in `jq`. The mapping is conservative: a rule gets a tag only when the entry
//! clearly describes what the rule detects. IDs and names were checked against
//! genai.owasp.org/llm-top-10 and the ATLAS data (mitre-atlas/atlas-data, release 2026.10).
//!
//! [owasp]: https://genai.owasp.org/llm-top-10/
//! [atlas]: https://atlas.mitre.org/

/// Which framework a tag belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framework {
    OwaspLlm2025,
    MitreAtlas,
}

/// A known taxonomy entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaxonomyEntry {
    pub id: &'static str,
    pub name: &'static str,
    pub framework: Framework,
    pub url: &'static str,
}

const fn owasp(id: &'static str, name: &'static str, url: &'static str) -> TaxonomyEntry {
    TaxonomyEntry {
        id,
        name,
        framework: Framework::OwaspLlm2025,
        url,
    }
}

const fn atlas(id: &'static str, name: &'static str, url: &'static str) -> TaxonomyEntry {
    TaxonomyEntry {
        id,
        name,
        framework: Framework::MitreAtlas,
        url,
    }
}

/// Every entry the built-in mapping uses, with its official name.
pub const ENTRIES: &[TaxonomyEntry] = &[
    owasp(
        "LLM01:2025",
        "Prompt Injection",
        "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
    ),
    owasp(
        "LLM02:2025",
        "Sensitive Information Disclosure",
        "https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/",
    ),
    owasp(
        "LLM03:2025",
        "Supply Chain",
        "https://genai.owasp.org/llmrisk/llm032025-supply-chain/",
    ),
    owasp(
        "LLM06:2025",
        "Excessive Agency",
        "https://genai.owasp.org/llmrisk/llm062025-excessive-agency/",
    ),
    atlas(
        "AML.T0051.001",
        "LLM Prompt Injection: Indirect",
        "https://atlas.mitre.org/techniques/AML.T0051.001",
    ),
    atlas(
        "AML.T0053",
        "AI Agent Tool Invocation",
        "https://atlas.mitre.org/techniques/AML.T0053",
    ),
    atlas(
        "AML.T0073",
        "Impersonation",
        "https://atlas.mitre.org/techniques/AML.T0073",
    ),
    atlas(
        "AML.T0086",
        "Exfiltration via AI Agent Tool Invocation",
        "https://atlas.mitre.org/techniques/AML.T0086",
    ),
    atlas(
        "AML.T0109",
        "AI Supply Chain Rug Pull",
        "https://atlas.mitre.org/techniques/AML.T0109",
    ),
    atlas(
        "AML.T0110.000",
        "AI Agent Tool Poisoning: Definition and Instructions",
        "https://atlas.mitre.org/techniques/AML.T0110.000",
    ),
    atlas(
        "AML.T0143",
        "LLM Prompt Propagation",
        "https://atlas.mitre.org/techniques/AML.T0143",
    ),
];

/// Tags of a built-in rule (empty for unknown IDs). OWASP first, then ATLAS.
pub fn builtin_tags(rule_id: &str) -> &'static [&'static str] {
    match rule_id {
        // Instructions hidden in untrusted content the agent ingests: indirect prompt injection
        // (LLM01 "input from external sources, such as websites or files"; ATLAS Indirect).
        "AT-001" => &["LLM01:2025", "AML.T0051.001"],
        // A privileged tool requested on a causal path from untrusted content: injection that
        // turns into tool use (LLM01 "unauthorized access to functions"), an agent with more
        // agency than the input deserves (LLM06), and the tool call itself (ATLAS T0053).
        "AT-002" => &["LLM01:2025", "LLM06:2025", "AML.T0053"],
        // Sensitive data sent to a non-allowlisted destination by an outbound tool: disclosure
        // (LLM02) through an agent tool call (ATLAS T0086).
        "AT-003" => &["LLM02:2025", "AML.T0086"],
        // A tool call denied by policy. The denial is the LLM06 mitigation at work; whether an
        // adversary caused the call is unknown, so no ATLAS technique is claimed.
        "AT-004" => &["LLM06:2025"],
        // Untrusted content claiming system/operator authority: an injection technique (LLM01,
        // ATLAS Indirect) that relies on a claimed role (ATLAS T0073 Impersonation).
        "AT-005" => &["LLM01:2025", "AML.T0051.001", "AML.T0073"],
        // Untrusted content seen by one agent reached a privileged action of another agent:
        // injected instructions carried onward to another agent (ATLAS T0143) ending in a
        // tool call (T0053), like AT-002 across an agent boundary.
        "AT-006" => &["LLM01:2025", "LLM06:2025", "AML.T0053", "AML.T0143"],
        // A decoy secret in a tool call's arguments: the agent moved a secret (LLM02) through
        // a tool call (ATLAS T0086).
        "AT-007" => &["LLM02:2025", "AML.T0086"],
        // An MCP tool definition changed after it was pinned: a vetted third-party component
        // changed underneath (LLM03, whose mitigations include hash-based integrity checks;
        // ATLAS T0109 rug pull) in its model-visible definition (ATLAS T0110.000).
        "AT-008" => &["LLM03:2025", "AML.T0109", "AML.T0110.000"],
        _ => &[],
    }
}

/// The known entry for a tag, if any.
pub fn lookup(tag: &str) -> Option<&'static TaxonomyEntry> {
    ENTRIES.iter().find(|e| e.id == tag)
}

/// `LLM01:2025 Prompt Injection` for known tags, the tag itself otherwise.
pub fn label(tag: &str) -> String {
    match lookup(tag) {
        Some(e) => format!("{} {}", e.id, e.name),
        None => tag.to_owned(),
    }
}

/// Maximum length of a tag in bytes.
pub const MAX_TAG_LEN: usize = 64;
/// Maximum number of tags on one rule.
pub const MAX_TAGS: usize = 32;

/// Loose validation of a user-supplied tag: non-empty, at most [`MAX_TAG_LEN`] bytes, no
/// surrounding whitespace, no control or invisible formatting characters.
pub fn validate_tag(tag: &str) -> Result<(), String> {
    if tag.is_empty() {
        return Err("tag is empty".into());
    }
    if tag.len() > MAX_TAG_LEN {
        return Err(format!("tag {tag:?} is longer than {MAX_TAG_LEN} bytes"));
    }
    if tag.trim() != tag {
        return Err(format!("tag {tag:?} has leading or trailing whitespace"));
    }
    if tag.chars().any(|c| {
        c.is_control()
            || matches!(c, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{feff}')
    }) {
        return Err(format!(
            "tag {tag:?} contains control or formatting characters"
        ));
    }
    Ok(())
}

/// Whether `tag` has the format of an OWASP LLM Top 10 (2025) ID, e.g. `LLM01:2025`.
pub fn is_owasp_llm_id(tag: &str) -> bool {
    tag.strip_prefix("LLM")
        .and_then(|rest| rest.strip_suffix(":2025"))
        .is_some_and(|n| n.len() == 2 && n.chars().all(|c| c.is_ascii_digit()))
}

/// Whether `tag` has the format of a MITRE ATLAS technique ID, e.g. `AML.T0051` or
/// `AML.T0051.001`.
pub fn is_atlas_technique_id(tag: &str) -> bool {
    let Some(rest) = tag.strip_prefix("AML.T") else {
        return false;
    };
    let digits = |s: &str, n: usize| s.len() == n && s.chars().all(|c| c.is_ascii_digit());
    match rest.split_once('.') {
        Some((t, sub)) => digits(t, 4) && digits(sub, 3),
        None => digits(rest, 4),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{Analyzer, Rule};

    #[test]
    fn every_builtin_rule_is_mapped_with_known_ids() {
        let analyzer = Analyzer::default();
        let rules: Vec<&dyn Rule> = analyzer.rules().collect();
        assert!(rules.len() >= 7);
        for rule in rules {
            let tags = rule.tags();
            assert!(!tags.is_empty(), "{} has no tags", rule.id());
            assert!(
                tags.iter().any(|t| is_owasp_llm_id(t)),
                "{} has no OWASP tag",
                rule.id()
            );
            for tag in &tags {
                assert!(
                    is_owasp_llm_id(tag) || is_atlas_technique_id(tag),
                    "{}: {tag} has an unexpected format",
                    rule.id()
                );
                assert!(lookup(tag).is_some(), "{}: {tag} has no entry", rule.id());
                validate_tag(tag).unwrap();
            }
        }
    }

    #[test]
    fn at008_is_mapped_and_unknown_ids_are_not() {
        let tags = builtin_tags("AT-008");
        assert!(tags.contains(&"LLM03:2025"));
        assert!(tags.contains(&"AML.T0110.000"));
        assert!(builtin_tags("AT-999").is_empty());
        assert!(builtin_tags("CORP-001").is_empty());
    }

    #[test]
    fn entries_are_unique_and_well_formed() {
        for (i, e) in ENTRIES.iter().enumerate() {
            assert!(ENTRIES[i + 1..].iter().all(|o| o.id != e.id), "{}", e.id);
            match e.framework {
                Framework::OwaspLlm2025 => {
                    assert!(is_owasp_llm_id(e.id), "{}", e.id);
                    assert!(e.url.starts_with("https://genai.owasp.org/llmrisk/"));
                }
                Framework::MitreAtlas => {
                    assert!(is_atlas_technique_id(e.id), "{}", e.id);
                    assert_eq!(
                        e.url,
                        format!("https://atlas.mitre.org/techniques/{}", e.id)
                    );
                }
            }
        }
        // Every mapped tag has an entry, and every entry is used.
        let all: Vec<&str> = (1..=8)
            .flat_map(|n| builtin_tags(&format!("AT-{n:03}")).iter().copied())
            .collect();
        for e in ENTRIES {
            assert!(all.contains(&e.id), "{} is unused", e.id);
        }
    }

    #[test]
    fn formats_and_labels() {
        assert!(is_owasp_llm_id("LLM10:2025"));
        assert!(!is_owasp_llm_id("LLM1:2025"));
        assert!(!is_owasp_llm_id("LLM01:2023"));
        assert!(is_atlas_technique_id("AML.T0051"));
        assert!(is_atlas_technique_id("AML.T0051.001"));
        assert!(!is_atlas_technique_id("AML.TA0005"));
        assert!(!is_atlas_technique_id("AML.T51"));
        assert_eq!(label("LLM01:2025"), "LLM01:2025 Prompt Injection");
        assert_eq!(label("CORP-x"), "CORP-x");
    }

    #[test]
    fn tag_validation_is_loose_but_safe() {
        validate_tag("LLM01:2025").unwrap();
        validate_tag("CORP-xyz").unwrap();
        validate_tag("team/payments risk").unwrap();
        assert!(validate_tag("").is_err());
        assert!(validate_tag(" x").is_err());
        assert!(validate_tag("a\nb").is_err());
        assert!(validate_tag("a\u{1b}[31m").is_err());
        assert!(validate_tag("a\u{202e}b").is_err());
        assert!(validate_tag(&"x".repeat(MAX_TAG_LEN + 1)).is_err());
    }
}
