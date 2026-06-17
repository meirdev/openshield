use base64::Engine as _;
use sha1::{Digest, Sha1};

pub fn base64_encode(input: &[u8]) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .encode(input)
        .into_bytes()
}

pub fn hex_encode(input: &[u8]) -> Vec<u8> {
    hex::encode(input).into_bytes()
}

pub fn sha1(input: &[u8]) -> Vec<u8> {
    hex::encode(Sha1::digest(input)).into_bytes()
}

pub fn utf8_to_unicode(input: &[u8]) -> Vec<u8> {
    let s = match std::str::from_utf8(input) {
        Ok(s) => s,
        Err(_) => return input.to_vec(),
    };
    let mut result = Vec::with_capacity(s.len() * 6);
    for ch in s.chars() {
        if ch.is_ascii() {
            result.push(ch as u8);
        } else {
            // \uXXXX format
            for byte in format!("\\u{:04x}", ch as u32).bytes() {
                result.push(byte);
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::super::decode;
    use super::*;

    #[test]
    fn base64_encode_known_vector() {
        assert_eq!(base64_encode(b"hello"), b"aGVsbG8=");
        assert_eq!(base64_encode(b""), b"");
    }

    #[test]
    fn base64_roundtrip() {
        let data = b"The quick brown fox \x00\xff";
        let encoded = base64_encode(data);
        assert_eq!(decode::base64_decode(&encoded), data);
    }

    #[test]
    fn hex_encode_known_vector() {
        assert_eq!(hex_encode(&[0xde, 0xad, 0xbe, 0xef]), b"deadbeef");
        assert_eq!(hex_encode(b""), b"");
    }

    #[test]
    fn hex_roundtrip() {
        let data = b"\x00\x01\x02\xfe\xff";
        let encoded = hex_encode(data);
        assert_eq!(decode::hex_decode(&encoded), data);
    }

    #[test]
    fn sha1_known_vector() {
        // RFC 3174 test vector for "abc".
        assert_eq!(sha1(b"abc"), b"a9993e364706816aba3e25717850c26c9cd0d89d");
    }

    #[test]
    fn utf8_to_unicode_escapes_non_ascii() {
        // ASCII passes through verbatim.
        assert_eq!(utf8_to_unicode(b"abc"), b"abc");
        // U+00E9 (é) -> é.
        assert_eq!(utf8_to_unicode("é".as_bytes()), b"\\u00e9");
        // Mixed content.
        assert_eq!(utf8_to_unicode("a\u{20ac}".as_bytes()), b"a\\u20ac");
    }

    #[test]
    fn utf8_to_unicode_invalid_utf8_passes_through() {
        let input = [0xff, 0xfe];
        assert_eq!(utf8_to_unicode(&input), &input);
    }
}
