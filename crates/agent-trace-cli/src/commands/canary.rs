//! `agent-trace canary`: create decoy secrets and list the configured ones.
//!
//! * `canary new NAME [--kind aws|github|hex|password]`: print a fresh decoy value and the
//!   `[[canaries]]` entry for `agent-trace.toml`.
//! * `canary list`: the canaries the current configuration installs (names only).

use agent_trace_core::canary::{self, Canary};
use anyhow::bail;
use clap::ValueEnum;
use uuid::Uuid;

use super::Context;
use crate::EXIT_OK;
use crate::output::term_safe;

/// The shape of a generated decoy. Realistic shapes make the decoy look worth stealing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
pub enum CanaryKind {
    /// AWS access key ID (`AKIA` + 16 characters).
    #[default]
    Aws,
    /// GitHub personal access token (`ghp_` + 36 characters).
    Github,
    /// 40 hex characters (a generic API key).
    Hex,
    /// A 24-character password.
    Password,
}

const BASE32: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const HEX: &[u8] = b"0123456789abcdef";
const PASSWORD: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!#%+=?@";

/// Random bytes from the operating system's generator (through UUID v4), skipping the fixed
/// version and variant bits.
fn random_bytes(n: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(n);
    while out.len() < n {
        let id = Uuid::new_v4();
        out.extend(
            id.as_bytes()
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != 6 && *i != 8)
                .map(|(_, b)| *b),
        );
    }
    out.truncate(n);
    out
}

/// `n` characters of `alphabet`, uniformly (rejection sampling, no modulo bias).
fn random_chars(alphabet: &[u8], n: usize) -> String {
    let limit = 256 - (256 % alphabet.len());
    let mut out = String::with_capacity(n);
    while out.len() < n {
        for b in random_bytes(n * 2) {
            if (b as usize) < limit && out.len() < n {
                out.push(alphabet[b as usize % alphabet.len()] as char);
            }
        }
    }
    out
}

pub fn generate_value(kind: CanaryKind) -> String {
    match kind {
        CanaryKind::Aws => format!("AKIA{}", random_chars(BASE32, 16)),
        CanaryKind::Github => format!("ghp_{}", random_chars(ALNUM, 36)),
        CanaryKind::Hex => random_chars(HEX, 40),
        CanaryKind::Password => random_chars(PASSWORD, 24),
    }
}

fn env_var_name(name: &str) -> String {
    let upper: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect();
    format!("AGENT_TRACE_CANARY_{upper}")
}

fn plant_hint(kind: CanaryKind, value: &str) -> String {
    match kind {
        CanaryKind::Aws => format!("AWS_ACCESS_KEY_ID={value}"),
        CanaryKind::Github => format!("GITHUB_TOKEN={value}"),
        CanaryKind::Hex => format!("API_KEY={value}"),
        CanaryKind::Password => format!("DB_PASSWORD={value}"),
    }
}

pub fn new(name: &str, kind: CanaryKind) -> anyhow::Result<u8> {
    if !canary::valid_name(name) {
        bail!(
            "canary name {:?}: use 1 to {} lowercase letters, digits, `-`, `_` or `.`",
            term_safe(name),
            canary::MAX_NAME_LEN
        );
    }
    let value = generate_value(kind);
    // The generated value must pass the same checks as a configured one.
    Canary::new(name, &value).map_err(anyhow::Error::msg)?;
    let env = env_var_name(name);
    println!("# Canary {name:?}: plant the value where an attacker would look for secrets,");
    println!("# for example as a line in a .env file the agent can read:");
    println!("#   {}", plant_hint(kind, &value));
    println!("# Keep this entry where the agent cannot read it (the agent-trace.toml in the data");
    println!("# directory, or --config), or set `env = \"{env}\"` instead of `value`");
    println!("# and export {env} in the environment of agent-trace.");
    println!("[[canaries]]");
    println!("name = \"{name}\"");
    println!("value = \"{value}\"");
    Ok(EXIT_OK)
}

pub fn list(ctx: &Context) -> anyhow::Result<u8> {
    let loaded = ctx.config()?;
    loaded.announce();
    let configs = &loaded.config.canaries;
    if configs.is_empty() {
        outln!(
            "no canaries configured (add [[canaries]] to agent-trace.toml; see `agent-trace canary new`)"
        );
        return Ok(EXIT_OK);
    }
    for c in configs {
        let source = match &c.env {
            Some(var) => format!("from ${var}"),
            None => "value in the config file".to_owned(),
        };
        outln!("{}  ({})", term_safe(&c.name), term_safe(&source));
    }
    outln!(
        "{} canar{} active: tool calls that carry one are reported (AT-007) and denied in enforce mode",
        configs.len(),
        if configs.len() == 1 { "y" } else { "ies" }
    );
    Ok(EXIT_OK)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_values_have_the_expected_shape_and_differ() {
        for kind in [
            CanaryKind::Aws,
            CanaryKind::Github,
            CanaryKind::Hex,
            CanaryKind::Password,
        ] {
            let a = generate_value(kind);
            let b = generate_value(kind);
            assert_ne!(a, b);
            assert!(Canary::new("x", &a).is_ok(), "{a}");
        }
        let aws = generate_value(CanaryKind::Aws);
        assert!(aws.starts_with("AKIA") && aws.len() == 20, "{aws}");
        assert!(aws[4..].bytes().all(|b| BASE32.contains(&b)));
        let gh = generate_value(CanaryKind::Github);
        assert!(gh.starts_with("ghp_") && gh.len() == 40, "{gh}");
        let hex = generate_value(CanaryKind::Hex);
        assert!(
            hex.len() == 40 && hex.bytes().all(|b| HEX.contains(&b)),
            "{hex}"
        );
    }

    #[test]
    fn env_names_are_shell_safe() {
        assert_eq!(
            env_var_name("aws-prod.decoy_1"),
            "AGENT_TRACE_CANARY_AWS_PROD_DECOY_1"
        );
    }
}
