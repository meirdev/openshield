//! Encoders and digests.

use std::borrow::Cow;

use base64::Engine as _;
#[cfg(feature = "hash")]
use sha1::Digest as _;

/// ModSecurity `t:base64Encode`.
pub fn base64_encode(input: &[u8]) -> Cow<'_, [u8]> {
    Cow::Owned(
        base64::engine::general_purpose::STANDARD
            .encode(input)
            .into_bytes(),
    )
}

/// ModSecurity `t:hexEncode`, lowercase.
pub fn hex_encode(input: &[u8]) -> Cow<'_, [u8]> {
    Cow::Owned(hex::encode(input).into_bytes())
}

/// ModSecurity `t:md5`: the raw 16-byte digest. Chain `hex_encode` for hex.
#[cfg(feature = "hash")]
pub fn md5(input: &[u8]) -> Cow<'_, [u8]> {
    Cow::Owned(md5::Md5::digest(input).to_vec())
}

/// ModSecurity `t:sha1`: the raw 20-byte digest. Chain `hex_encode` for hex.
#[cfg(feature = "hash")]
pub fn sha1(input: &[u8]) -> Cow<'_, [u8]> {
    Cow::Owned(sha1::Sha1::digest(input).to_vec())
}

/// ModSecurity `t:utf8toUnicode`: non-ASCII characters become `\uXXXX`.
/// Input that is not UTF-8 passes through.
pub fn utf8_to_unicode(input: &[u8]) -> Cow<'_, [u8]> {
    let Ok(s) = std::str::from_utf8(input) else {
        return Cow::Borrowed(input);
    };
    if s.is_ascii() {
        return Cow::Borrowed(input);
    }
    let mut result = Vec::with_capacity(s.len() * 6);
    for ch in s.chars() {
        if ch.is_ascii() {
            result.push(ch as u8);
        } else {
            result.extend(format!("\\u{:04x}", ch as u32).bytes());
        }
    }
    Cow::Owned(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode;

    #[test]
    fn base64_encode_known_vector() {
        assert_eq!(&*base64_encode(b"hello"), b"aGVsbG8=");
        assert_eq!(&*base64_encode(b""), b"");
    }

    #[test]
    fn base64_roundtrip() {
        let data = b"The quick brown fox \x00\xff";
        let encoded = base64_encode(data);
        assert_eq!(&*decode::base64_decode(&encoded), data);
    }

    #[test]
    fn hex_encode_known_vector() {
        assert_eq!(&*hex_encode(&[0xde, 0xad, 0xbe, 0xef]), b"deadbeef");
        assert_eq!(&*hex_encode(b""), b"");
    }

    #[test]
    fn hex_roundtrip() {
        let data = b"\x00\x01\x02\xfe\xff";
        let encoded = hex_encode(data);
        assert_eq!(&*decode::hex_decode(&encoded), data);
    }

    #[cfg(feature = "hash")]
    #[test]
    fn md5_known_vector() {
        // RFC 1321 test vectors; the digest is raw bytes, not hex.
        assert_eq!(md5(b"abc").len(), 16);
        assert_eq!(
            &*hex_encode(&md5(b"abc")),
            b"900150983cd24fb0d6963f7d28e17f72"
        );
        assert_eq!(&*hex_encode(&md5(b"")), b"d41d8cd98f00b204e9800998ecf8427e");
    }

    #[cfg(feature = "hash")]
    #[test]
    fn sha1_known_vector() {
        // RFC 3174 test vector for "abc"; the digest is raw bytes, not hex.
        assert_eq!(sha1(b"abc").len(), 20);
        assert_eq!(
            &*hex_encode(&sha1(b"abc")),
            b"a9993e364706816aba3e25717850c26c9cd0d89d"
        );
    }

    #[test]
    fn utf8_to_unicode_escapes_non_ascii() {
        // ASCII passes through verbatim, without copying.
        assert!(matches!(utf8_to_unicode(b"abc"), Cow::Borrowed(_)));
        // U+00E9 (é) -> é.
        assert_eq!(&*utf8_to_unicode("é".as_bytes()), b"\\u00e9");
        // Mixed content.
        assert_eq!(&*utf8_to_unicode("a\u{20ac}".as_bytes()), b"a\\u20ac");
    }

    #[test]
    fn utf8_to_unicode_invalid_utf8_passes_through() {
        let input = [0xff, 0xfe];
        assert_eq!(&*utf8_to_unicode(&input), &input);
    }
}
