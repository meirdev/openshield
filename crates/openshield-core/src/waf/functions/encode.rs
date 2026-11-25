use std::borrow::Cow;

use base64::Engine as _;
use sha2::Digest as _;

pub fn encode_base64(input: &[u8]) -> Cow<'_, [u8]> {
    Cow::Owned(
        base64::engine::general_purpose::STANDARD
            .encode(input)
            .into_bytes(),
    )
}

pub fn hex_encode(input: &[u8]) -> Cow<'_, [u8]> {
    Cow::Owned(hex::encode(input).into_bytes())
}

pub fn md5(input: &[u8]) -> Cow<'_, [u8]> {
    Cow::Owned(md5::Md5::digest(input).to_vec())
}

pub fn sha1(input: &[u8]) -> Cow<'_, [u8]> {
    Cow::Owned(sha1::Sha1::digest(input).to_vec())
}

pub fn sha256(input: &[u8]) -> Cow<'_, [u8]> {
    Cow::Owned(sha2::Sha256::digest(input).to_vec())
}

pub fn sha512(input: &[u8]) -> Cow<'_, [u8]> {
    Cow::Owned(sha2::Sha512::digest(input).to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::waf::functions::decode;

    #[test]
    fn encode_base64_known_vector() {
        assert_eq!(&*encode_base64(b"hello"), b"aGVsbG8=");
        assert_eq!(&*encode_base64(b""), b"");
    }

    #[test]
    fn base64_roundtrip() {
        let data = b"The quick brown fox \x00\xff";
        let encoded = encode_base64(data);
        assert_eq!(&*decode::decode_base64(&encoded), data);
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

    #[test]
    fn digests_are_raw_bytes() {
        // Known "abc" vectors (RFC 1321, RFC 3174, FIPS 180-2).
        let hex = |d: Cow<'_, [u8]>| String::from_utf8(hex_encode(&d).into_owned()).unwrap();
        assert_eq!(md5(b"abc").len(), 16);
        assert_eq!(hex(md5(b"abc")), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(sha1(b"abc").len(), 20);
        assert_eq!(
            hex(sha1(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(sha256(b"abc").len(), 32);
        assert_eq!(
            hex(sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(sha512(b"abc").len(), 64);
        assert_eq!(
            hex(sha512(b"abc")),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
    }
}
