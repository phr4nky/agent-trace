//! Small text encodings shared by the crates: lowercase hex and RFC 3986 percent-encoding.

const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";
const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";

/// Lowercase hex of `bytes` (two digits per byte).
pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(char::from(HEX_LOWER[usize::from(b >> 4)]));
        out.push(char::from(HEX_LOWER[usize::from(b & 0x0f)]));
    }
    out
}

/// The bytes of hex `text` (either case, surrounding whitespace ignored), or `None` if it
/// has an odd length or a non-hex character.
pub fn unhex(text: &str) -> Option<Vec<u8>> {
    let text = text.trim().as_bytes();
    if !text.len().is_multiple_of(2) {
        return None;
    }
    let digit = |c: u8| {
        char::from(c)
            .to_digit(16)
            .and_then(|d| u8::try_from(d).ok())
    };
    let (pairs, _) = text.as_chunks::<2>();
    pairs
        .iter()
        .map(|&[high, low]| Some((digit(high)? << 4) | digit(low)?))
        .collect()
}

/// RFC 3986 percent-encoding: unreserved characters (`A-Z a-z 0-9 - . _ ~`) and the bytes in
/// `also_safe` are kept, every other byte becomes `%XX` (uppercase hex).
pub fn percent_encode(text: &str, also_safe: &[u8]) -> String {
    let mut out = String::with_capacity(text.len());
    for b in text.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) || also_safe.contains(&b) {
            out.push(char::from(b));
        } else {
            out.push('%');
            out.push(char::from(HEX_UPPER[usize::from(b >> 4)]));
            out.push(char::from(HEX_UPPER[usize::from(b & 0x0f)]));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips() {
        let bytes: Vec<u8> = (0..=255).collect();
        let text = hex(&bytes);
        assert_eq!(&text[..6], "000102");
        assert_eq!(&text[text.len() - 4..], "feff");
        assert_eq!(unhex(&text).as_deref(), Some(bytes.as_slice()));
        assert_eq!(unhex(" ABcd\n"), Some(vec![0xab, 0xcd]));
        assert_eq!(hex(&[]), "");
    }

    #[test]
    fn unhex_rejects_malformed_input() {
        assert_eq!(unhex("abc"), None);
        assert_eq!(unhex("zz"), None);
        assert_eq!(unhex("+1"), None);
        assert_eq!(unhex("é0"), None);
    }

    #[test]
    fn percent_encode_keeps_unreserved_and_extra_safe_bytes() {
        assert_eq!(percent_encode("a-b._~Z9", b""), "a-b._~Z9");
        assert_eq!(percent_encode("a/b c", b""), "a%2Fb%20c");
        assert_eq!(percent_encode("a/b c", b"/"), "a/b%20c");
        assert_eq!(percent_encode("ü#", b"/"), "%C3%BC%23");
    }
}
