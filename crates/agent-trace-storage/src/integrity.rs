//! Tamper evidence for exported traces: a hash chain over the lines of a JSONL export and an
//! optional Ed25519 signature over its head.
//!
//! Chain (version 1): `h0 = SHA-256("agent-trace-chain-v1")`, and for every non-blank line
//! before the integrity record, in order, `hᵢ = SHA-256(hᵢ₋₁ ‖ line bytes)` (without the line
//! break). The `integrity` record at the end of the file holds the number of chained lines, the
//! head and a checkpoint every [`CHECKPOINT_EVERY`] lines (so a verifier can say where a file
//! was changed). Changing, removing, reordering or adding a line changes the head.
//!
//! A hash chain alone only shows that a file is consistent: whoever changes the file can
//! recompute it. A signature by a key the verifier trusts shows that the file is the one its
//! holder exported. The signed message is
//! `"agent-trace-integrity-v1\n" ‖ trace_id ‖ "\n" ‖ lines ‖ "\n" ‖ head`.

use std::path::Path;

use agent_trace_core::encoding::{hex, unhex};
use ring::rand::SystemRandom;
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{StorageError, create_private_file};

/// A checkpoint is recorded after every this many chained lines.
pub const CHECKPOINT_EVERY: u64 = 256;
const CHAIN_SEED: &[u8] = b"agent-trace-chain-v1";
const SIGNATURE_CONTEXT: &str = "agent-trace-integrity-v1";

/// The running hash chain over the lines of a file.
#[derive(Debug, Clone)]
pub struct Chain {
    head: [u8; 32],
    lines: u64,
    checkpoints: Vec<Checkpoint>,
}

impl Default for Chain {
    fn default() -> Self {
        Self {
            head: Sha256::digest(CHAIN_SEED).into(),
            lines: 0,
            checkpoints: Vec::new(),
        }
    }
}

impl Chain {
    /// Add one line (without its line break).
    pub fn push(&mut self, line: &[u8]) {
        let mut h = Sha256::new();
        h.update(self.head);
        h.update(line);
        self.head = h.finalize().into();
        self.lines += 1;
        if self.lines.is_multiple_of(CHECKPOINT_EVERY) {
            self.checkpoints.push(Checkpoint {
                line: self.lines,
                hash: hex(&self.head),
            });
        }
    }

    pub fn lines(&self) -> u64 {
        self.lines
    }

    pub fn head(&self) -> String {
        hex(&self.head)
    }

    /// The integrity record for the lines so far, signed with `key` if given.
    pub fn record(&self, trace_id: Uuid, key: Option<&SigningKey>) -> IntegrityRecord {
        let mut record = IntegrityRecord {
            version: 1,
            algorithm: "sha256-chain".into(),
            lines: self.lines,
            head: self.head(),
            checkpoints: self.checkpoints.clone(),
            signature: None,
        };
        if let Some(key) = key {
            let sig = key
                .pair
                .sign(signed_message(trace_id, self.lines, &record.head).as_bytes());
            record.signature = Some(Signature {
                algorithm: "ed25519".into(),
                key_id: key.key_id(),
                public_key: key.public_key(),
                value: hex(sig.as_ref()),
            });
        }
        record
    }
}

fn signed_message(trace_id: Uuid, lines: u64, head: &str) -> String {
    format!("{SIGNATURE_CONTEXT}\n{trace_id}\n{lines}\n{head}")
}

/// Chain value after a given number of lines.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    pub line: u64,
    pub hash: String,
}

/// An Ed25519 signature over the chain head.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    pub algorithm: String,
    /// First 16 hex digits of SHA-256 of the public key.
    pub key_id: String,
    /// The signer's public key (hex). A verifier must decide whether it trusts it.
    pub public_key: String,
    pub value: String,
}

/// The last record of a JSONL export (`"record_type": "integrity"`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrityRecord {
    pub version: u32,
    pub algorithm: String,
    pub lines: u64,
    pub head: String,
    #[serde(default)]
    pub checkpoints: Vec<Checkpoint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<Signature>,
}

/// Why a file failed verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntegrityError {
    Unsupported(String),
    /// The chain differs from the record. `after_line`/`before_line`: the change is between
    /// these chained lines (from the checkpoints).
    Modified {
        after_line: u64,
        before_line: u64,
    },
    BadSignature(String),
}

impl std::fmt::Display for IntegrityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported(what) => write!(f, "unsupported integrity record: {what}"),
            Self::Modified {
                after_line,
                before_line,
            } => write!(
                f,
                "the file was changed after it was exported (hash chain differs between \
                 record {} and record {before_line})",
                after_line + 1
            ),
            Self::BadSignature(why) => write!(f, "invalid signature: {why}"),
        }
    }
}

/// A verified integrity record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    pub lines: u64,
    /// `(key id, public key hex)` of a valid signature.
    pub signed_by: Option<(String, String)>,
}

impl IntegrityRecord {
    /// Check `chain` (the lines actually read) against this record, and the signature if any.
    pub fn verify(&self, chain: &Chain, trace_id: Uuid) -> Result<Verified, IntegrityError> {
        if self.version != 1 || self.algorithm != "sha256-chain" {
            return Err(IntegrityError::Unsupported(format!(
                "version {} / {}",
                self.version, self.algorithm
            )));
        }
        if self.lines != chain.lines || !self.head.eq_ignore_ascii_case(&chain.head()) {
            // Narrow the change down with the checkpoints both sides have.
            let mut after = 0;
            let mut before = self.lines.max(chain.lines);
            for cp in &self.checkpoints {
                match chain.checkpoints.iter().find(|c| c.line == cp.line) {
                    Some(c) if c.hash.eq_ignore_ascii_case(&cp.hash) => after = cp.line,
                    _ => {
                        before = cp.line;
                        break;
                    }
                }
            }
            return Err(IntegrityError::Modified {
                after_line: after,
                before_line: before,
            });
        }
        let signed_by = match &self.signature {
            None => None,
            Some(sig) => {
                if sig.algorithm != "ed25519" {
                    return Err(IntegrityError::Unsupported(sig.algorithm.clone()));
                }
                let public = unhex(&sig.public_key)
                    .ok_or_else(|| IntegrityError::BadSignature("public key is not hex".into()))?;
                let value = unhex(&sig.value)
                    .ok_or_else(|| IntegrityError::BadSignature("signature is not hex".into()))?;
                if key_id(&public) != sig.key_id {
                    return Err(IntegrityError::BadSignature(
                        "key id does not match the public key".into(),
                    ));
                }
                UnparsedPublicKey::new(&ED25519, &public)
                    .verify(
                        signed_message(trace_id, self.lines, &self.head).as_bytes(),
                        &value,
                    )
                    .map_err(|_| {
                        IntegrityError::BadSignature("does not match the content".into())
                    })?;
                Some((sig.key_id.clone(), hex(&public)))
            }
        };
        Ok(Verified {
            lines: self.lines,
            signed_by,
        })
    }
}

fn key_id(public_key: &[u8]) -> String {
    hex(&Sha256::digest(public_key))[..16].to_owned()
}

/// A public key given as hex, or a `.pub` file written by [`SigningKey::generate`].
pub fn parse_public_key(text: &str) -> Option<String> {
    let line = text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))?;
    let bytes = unhex(line)?;
    (bytes.len() == 32).then(|| hex(&bytes))
}

/// An Ed25519 signing key (PKCS#8 file, private to its owner).
pub struct SigningKey {
    pair: Ed25519KeyPair,
}

impl std::fmt::Debug for SigningKey {
    // Never print key material.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningKey")
            .field("key_id", &self.key_id())
            .finish()
    }
}

impl SigningKey {
    /// Create a key and write it to `path` (mode 0600, never following a symlink) and its
    /// public key to `path` with `.pub` appended. Fails if either file exists.
    pub fn generate(path: &Path) -> Result<Self, StorageError> {
        let pub_path = public_key_path(path);
        if path.exists() || pub_path.exists() {
            return Err(StorageError::Config(format!(
                "{} already exists; refusing to overwrite a key",
                path.display()
            )));
        }
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|_| StorageError::Config("could not generate a key".into()))?;
        let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
            .map_err(|_| StorageError::Config("generated key is invalid".into()))?;
        use std::io::Write;
        let mut file = create_private_file(path)?;
        file.write_all(pkcs8.as_ref())?;
        file.flush()?;
        let key = Self { pair };
        let mut public = create_private_file(&pub_path)?;
        writeln!(
            public,
            "# agent-trace public key, key id {}\n{}",
            key.key_id(),
            key.public_key()
        )?;
        #[cfg(unix)]
        {
            // The public key is meant to be shared.
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&pub_path, std::fs::Permissions::from_mode(0o644))?;
        }
        Ok(key)
    }

    /// Load a key written by [`Self::generate`].
    pub fn load(path: &Path) -> Result<Self, StorageError> {
        let bytes = std::fs::read(path)?;
        let pair = Ed25519KeyPair::from_pkcs8(&bytes).map_err(|_| {
            StorageError::Config(format!("{} is not an Ed25519 PKCS#8 key", path.display()))
        })?;
        Ok(Self { pair })
    }

    /// Public key, hex.
    pub fn public_key(&self) -> String {
        hex(self.pair.public_key().as_ref())
    }

    pub fn key_id(&self) -> String {
        key_id(self.pair.public_key().as_ref())
    }
}

/// Where [`SigningKey::generate`] writes the public key of `key_path`.
pub fn public_key_path(key_path: &Path) -> std::path::PathBuf {
    let mut p = key_path.as_os_str().to_owned();
    p.push(".pub");
    p.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chain(lines: &[&str]) -> Chain {
        let mut c = Chain::default();
        for l in lines {
            c.push(l.as_bytes());
        }
        c
    }

    #[test]
    fn any_change_breaks_the_chain() {
        let id = Uuid::new_v4();
        let original = chain(&["a", "b", "c"]);
        let record = original.record(id, None);
        assert_eq!(
            record
                .verify(&chain(&["a", "b", "c"]), id)
                .unwrap()
                .signed_by,
            None
        );
        for changed in [
            vec!["a", "B", "c"],
            vec!["a", "c", "b"],
            vec!["a", "b"],
            vec!["a", "b", "c", "d"],
            vec!["a ", "b", "c"],
        ] {
            assert!(
                matches!(
                    record.verify(&chain(&changed), id),
                    Err(IntegrityError::Modified { .. })
                ),
                "{changed:?}"
            );
        }
    }

    #[test]
    fn checkpoints_locate_a_change() {
        let id = Uuid::nil();
        let lines: Vec<String> = (0..700).map(|i| format!("line {i}")).collect();
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        let record = chain(&refs).record(id, None);
        assert_eq!(record.checkpoints.len(), 2);
        let mut changed = lines.clone();
        changed[400] = "tampered".into();
        let refs: Vec<&str> = changed.iter().map(String::as_str).collect();
        assert_eq!(
            record.verify(&chain(&refs), id),
            Err(IntegrityError::Modified {
                after_line: 256,
                before_line: 512
            })
        );
    }

    #[test]
    fn signatures_bind_content_and_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("k.pk8");
        let key = SigningKey::generate(&path).unwrap();
        assert!(
            SigningKey::generate(&path).is_err(),
            "never overwrite a key"
        );
        let loaded = SigningKey::load(&path).unwrap();
        assert_eq!(loaded.public_key(), key.public_key());
        let pub_text = std::fs::read_to_string(public_key_path(&path)).unwrap();
        assert_eq!(parse_public_key(&pub_text).unwrap(), key.public_key());

        let id = Uuid::new_v4();
        let c = chain(&["x", "y"]);
        let record = c.record(id, Some(&key));
        let verified = record.verify(&c, id).unwrap();
        assert_eq!(verified.signed_by.unwrap().1, key.public_key());

        // Re-signing a changed head with another key: valid, but by another key.
        let other = SigningKey::generate(&dir.path().join("other.pk8")).unwrap();
        let forged = chain(&["x", "z"]).record(id, Some(&other));
        let v = forged.verify(&chain(&["x", "z"]), id).unwrap();
        assert_ne!(v.signed_by.unwrap().1, key.public_key());

        // A changed head under the original signature fails.
        let mut tampered = record.clone();
        tampered.head = chain(&["x", "z"]).head();
        assert!(matches!(
            tampered.verify(&chain(&["x", "z"]), id),
            Err(IntegrityError::BadSignature(_))
        ));
        // The signature is bound to the trace id.
        assert!(record.verify(&c, Uuid::new_v4()).is_err());
        // A swapped public key fails the key id check or the signature.
        let mut swapped = record;
        swapped.signature.as_mut().unwrap().public_key = other.public_key();
        assert!(swapped.verify(&c, id).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn key_files_have_safe_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("k.pk8");
        SigningKey::generate(&path).unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(&public_key_path(&path)), 0o644);
    }
}
