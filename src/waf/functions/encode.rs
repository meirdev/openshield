use base64::Engine as _;
use sha1::{Digest, Sha1};

pub fn base64_encode(input: &[u8]) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .encode(input)
        .into_bytes()
}

pub fn hex_encode(input: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(input.len() * 2);
    for &b in input {
        result.push(HEX_CHARS[(b >> 4) as usize]);
        result.push(HEX_CHARS[(b & 0x0f) as usize]);
    }
    result
}

pub fn sha1(input: &[u8]) -> Vec<u8> {
    let hash = Sha1::digest(input);
    let mut result = Vec::with_capacity(40);
    for &b in hash.as_slice() {
        result.push(HEX_CHARS[(b >> 4) as usize]);
        result.push(HEX_CHARS[(b & 0x0f) as usize]);
    }
    result
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

const HEX_CHARS: [u8; 16] = *b"0123456789abcdef";
