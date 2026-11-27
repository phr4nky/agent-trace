//! Source tokens: `ats_` and 64 hex digits (32 random bytes). The server stores only the
//! SHA-256 of a token; it is shown once, when the source is added.

use agent_trace_core::encoding::hex;
use axum::http::{HeaderMap, header};
use ring::rand::{SecureRandom, SystemRandom};
use sha2::{Digest, Sha256};

/// Prefix of every source token (recognizable in logs and by secret scanners).
pub const TOKEN_PREFIX: &str = "ats_";

/// A new random token.
pub fn generate() -> anyhow::Result<String> {
    let mut bytes = [0u8; 32];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| anyhow::anyhow!("the system random generator failed"))?;
    Ok(format!("{TOKEN_PREFIX}{}", hex(&bytes)))
}

/// Hex SHA-256 of a token, as stored.
pub fn hash(token: &str) -> String {
    hex(&Sha256::digest(token.trim().as_bytes()))
}

/// The bearer token of a request, if it looks like a source token.
pub fn bearer(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.trim().split_once(' ')?;
    let token = token.trim();
    (scheme.eq_ignore_ascii_case("bearer")
        && token.starts_with(TOKEN_PREFIX)
        && token.len() == TOKEN_PREFIX.len() + 64
        && token[TOKEN_PREFIX.len()..]
            .chars()
            .all(|c| c.is_ascii_hexdigit()))
    .then_some(token)
}

/// Whether `name` can name a source: 1 to 64 lowercase letters, digits, `-`, `_` or `.`.
pub fn valid_source_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "-_.".contains(c))
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    #[test]
    fn tokens_are_random_hashed_and_parsed_strictly() {
        let a = generate().unwrap();
        let b = generate().unwrap();
        assert_ne!(a, b);
        assert!(a.starts_with(TOKEN_PREFIX) && a.len() == 68, "{a}");
        assert_eq!(hash(&a).len(), 64);
        assert_eq!(hash(&a), hash(&format!(" {a}\n")));
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {a}")).unwrap(),
        );
        assert_eq!(bearer(&headers), Some(a.as_str()));
        for bad in [
            "Bearer ats_123",
            "Basic abc",
            "Bearer",
            &format!("Token {a}"),
        ] {
            headers.insert(header::AUTHORIZATION, HeaderValue::from_str(bad).unwrap());
            assert_eq!(bearer(&headers), None, "{bad}");
        }
        assert!(valid_source_name("frank-macbook"));
        assert!(valid_source_name("ci.main_1"));
        for bad in ["", "Frank", "a b", "x/y", &"a".repeat(65)] {
            assert!(!valid_source_name(bad), "{bad}");
        }
    }
}
