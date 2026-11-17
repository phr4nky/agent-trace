//! Signing keys and verification of exported traces.
//!
//! * `keys generate` / `keys show`: an Ed25519 key for signing exports (default:
//!   `<data dir>/keys/signing-key.pk8`, or `--key` / `$AGENT_TRACE_SIGNING_KEY`).
//! * `verify FILE`: check a JSONL export's hash chain and signature.

use std::fs::File;
use std::path::{Path, PathBuf};

use agent_trace_storage::{
    SigningKey, create_private_dir, parse_public_key, public_key_path, read_jsonl,
};
use anyhow::{Context as _, bail};

use super::Context;
use crate::EXIT_OK;
use crate::output::term_safe;

/// The signing key path: `--key`, `$AGENT_TRACE_SIGNING_KEY`, then the data directory.
pub fn key_path(ctx: &Context, explicit: Option<&Path>) -> anyhow::Result<PathBuf> {
    if let Some(p) = explicit {
        return Ok(p.to_path_buf());
    }
    if let Some(p) = std::env::var_os("AGENT_TRACE_SIGNING_KEY").filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(p));
    }
    Ok(ctx.data_dir()?.join("keys").join("signing-key.pk8"))
}

pub fn load_key(ctx: &Context, explicit: Option<&Path>) -> anyhow::Result<SigningKey> {
    let path = key_path(ctx, explicit)?;
    SigningKey::load(&path).with_context(|| {
        format!(
            "cannot load the signing key {} (create one with `agent-trace keys generate`)",
            path.display()
        )
    })
}

pub fn generate(ctx: &Context, explicit: Option<&Path>) -> anyhow::Result<u8> {
    let path = key_path(ctx, explicit)?;
    if let Some(dir) = path.parent() {
        create_private_dir(dir)?;
    }
    let key = SigningKey::generate(&path)?;
    outln!("created signing key {}", key.key_id());
    outln!(
        "  private key: {} (keep it secret)",
        term_safe(&path.display().to_string())
    );
    outln!(
        "  public key : {} (share it with whoever verifies your exports)",
        term_safe(&public_key_path(&path).display().to_string())
    );
    outln!("  {}", key.public_key());
    Ok(EXIT_OK)
}

pub fn show(ctx: &Context, explicit: Option<&Path>) -> anyhow::Result<u8> {
    let key = load_key(ctx, explicit)?;
    outln!("key id     : {}", key.key_id());
    outln!("public key : {}", key.public_key());
    Ok(EXIT_OK)
}

/// A trusted public key: hex, or a file containing it (e.g. a `.pub` file).
fn trusted_key(spec: &str) -> anyhow::Result<String> {
    if let Some(key) = parse_public_key(spec) {
        return Ok(key);
    }
    let text = std::fs::read_to_string(spec).with_context(|| {
        format!("--public-key {spec:?} is neither a hex key nor a readable file")
    })?;
    parse_public_key(&text).with_context(|| format!("{spec} contains no Ed25519 public key"))
}

pub fn verify(
    ctx: &Context,
    file: &Path,
    public_keys: &[String],
    require_signature: bool,
) -> anyhow::Result<u8> {
    let s = &ctx.style;
    let mut trusted: Vec<(String, String)> = Vec::new();
    for spec in public_keys {
        trusted.push((trusted_key(spec)?, format!("--public-key {spec}")));
    }
    // The local signing key, if there is one, is trusted too.
    if let Ok(path) = key_path(ctx, None)
        && let Ok(key) = SigningKey::load(&path)
    {
        trusted.push((key.public_key(), "your signing key".into()));
    }
    let input = File::open(file).with_context(|| format!("cannot open {}", file.display()))?;
    let imported =
        read_jsonl(input).with_context(|| format!("{} failed verification", file.display()))?;
    let Some(integrity) = imported.integrity else {
        bail!(
            "{} has no integrity record: it was written by hand, by an agent-trace version \
             without tamper evidence, or the record was removed",
            file.display()
        );
    };
    outln!(
        "{} {} records of trace {} are unchanged (hash chain)",
        s.green("ok"),
        integrity.lines,
        imported.record.trace.trace_id
    );
    match integrity.signed_by {
        None => {
            outln!(
                "{}",
                s.yellow(
                    "unsigned: this shows the file is consistent, not who exported it \
                     (anyone can recompute an unsigned chain)"
                )
            );
            if require_signature {
                bail!("--require-signature: the file is not signed");
            }
        }
        Some((key_id, public)) => match trusted.iter().find(|(k, _)| *k == public) {
            Some((_, source)) => outln!("{} signed by key {key_id} ({source})", s.green("ok")),
            None => {
                outln!("signature by key {key_id} is valid, but the key is not trusted");
                outln!("  public key: {public}");
                bail!(
                    "the signer is unknown: pass the expected key with --public-key \
                     (anyone can sign a changed file with their own key)"
                );
            }
        },
    }
    Ok(EXIT_OK)
}
