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
