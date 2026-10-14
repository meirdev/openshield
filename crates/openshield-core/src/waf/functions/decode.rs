use base64::Engine as _;

pub fn url_decode_uni(input: &[u8]) -> Vec<u8> {
    if !input.contains(&b'%') && !input.contains(&b'+') {
        return input.to_vec();
    }
    let bytes = input;
    let mut result = Vec::with_capacity(bytes.len());
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'%' {
            // %uXXXX unicode escape
            if i + 5 < bytes.len()
                && (bytes[i + 1] == b'u' || bytes[i + 1] == b'U')
                && bytes[i + 2].is_ascii_hexdigit()
                && bytes[i + 3].is_ascii_hexdigit()
                && bytes[i + 4].is_ascii_hexdigit()
                && bytes[i + 5].is_ascii_hexdigit()
            {
                let mut decoded = hex2(bytes[i + 4], bytes[i + 5]);
                if decoded > 0x00
                    && decoded < 0x5f
                    && (bytes[i + 2] | 0x20) == b'f'
                    && (bytes[i + 3] | 0x20) == b'f'
                {
                    decoded = decoded.wrapping_add(0x20);
                }
                result.push(decoded);
                i += 6;
                continue;
            }
            // %XX hex escape
            if i + 2 < bytes.len()
                && bytes[i + 1].is_ascii_hexdigit()
                && bytes[i + 2].is_ascii_hexdigit()
            {
                result.push(hex2(bytes[i + 1], bytes[i + 2]));
                i += 3;
                continue;
            }
            result.push(bytes[i]);
            i += 1;
        } else if bytes[i] == b'+' {
            result.push(b' ');
            i += 1;
        } else {
            result.push(bytes[i]);
            i += 1;
        }
    }
    result
}

pub fn base64_decode(input: &[u8]) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(input)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(input))
        .unwrap_or_else(|_| input.to_vec())
}

pub fn hex_decode(input: &[u8]) -> Vec<u8> {
    hex::decode(input).unwrap_or_else(|_| input.to_vec())
}

pub fn html_entity_decode(input: &[u8]) -> Vec<u8> {
    let s = match std::str::from_utf8(input) {
        Ok(s) => s,
        Err(_) => return input.to_vec(),
    };
    html_escape::decode_html_entities(s)
        .into_owned()
        .into_bytes()
}

fn hex2(a: u8, b: u8) -> u8 {
    let hi = match a {
        b'0'..=b'9' => a - b'0',
        b'a'..=b'f' => a - b'a' + 10,
        b'A'..=b'F' => a - b'A' + 10,
        _ => 0,
    };
    let lo = match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    };
    (hi << 4) | lo
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_decode_passthrough_when_no_escapes() {
        assert_eq!(url_decode_uni(b"plain text"), b"plain text");
        assert_eq!(url_decode_uni(b""), b"");
    }

    #[test]
    fn url_decode_plus_becomes_space() {
        assert_eq!(url_decode_uni(b"a+b+c"), b"a b c");
    }

    #[test]
    fn url_decode_percent_hex() {
        // %41 == 'A', case-insensitive hex digits.
        assert_eq!(url_decode_uni(b"%41%42%43"), b"ABC");
        assert_eq!(url_decode_uni(b"%2f"), b"/");
        assert_eq!(url_decode_uni(b"%2F"), b"/");
        // Decodes a classic SQLi quote: %27 == '\''.
        assert_eq!(url_decode_uni(b"1%27%20OR%201"), b"1' OR 1");
    }

    #[test]
    fn url_decode_unicode_escape() {
        // %u0041 -> 'A' (high pair "00", low pair "41").
        assert_eq!(url_decode_uni(b"%u0041"), b"A");
        // Uppercase U is also accepted.
        assert_eq!(url_decode_uni(b"%U0041"), b"A");
    }

    #[test]
    fn url_decode_fullwidth_normalization() {
        // %uffXX with high pair "ff" maps fullwidth ASCII back to ASCII:
        // 0x41 + 0x20 == 0x61 == 'a'. Defeats fullwidth-encoding bypasses.
        assert_eq!(url_decode_uni(b"%uff41"), b"a");
    }

    #[test]
    fn url_decode_malformed_passes_through() {
        // Non-hex after % is left intact.
        assert_eq!(url_decode_uni(b"%zz"), b"%zz");
        // Truncated escape at end is left intact.
        assert_eq!(url_decode_uni(b"abc%4"), b"abc%4");
        assert_eq!(url_decode_uni(b"%"), b"%");
    }

    #[test]
    fn base64_decode_standard_and_urlsafe() {
        assert_eq!(base64_decode(b"aGVsbG8="), b"hello");
        // URL-safe alphabet ('-' and '_') is accepted via fallback.
        assert_eq!(base64_decode(b"-_8="), &[0xfb, 0xff]);
    }

    #[test]
    fn base64_decode_invalid_passes_through() {
        assert_eq!(base64_decode(b"not valid!!"), b"not valid!!");
    }

    #[test]
    fn hex_decode_roundtrip_and_invalid() {
        assert_eq!(hex_decode(b"6162"), b"ab");
        // Odd-length / non-hex input is returned unchanged.
        assert_eq!(hex_decode(b"xyz"), b"xyz");
        assert_eq!(hex_decode(b"616"), b"616");
    }

    #[test]
    fn html_entity_decode_basic() {
        assert_eq!(html_entity_decode(b"&lt;script&gt;"), b"<script>");
        assert_eq!(html_entity_decode(b"&amp;"), b"&");
        assert_eq!(html_entity_decode(b"&#39;"), b"'");
        // No entities -> unchanged.
        assert_eq!(html_entity_decode(b"plain"), b"plain");
    }

    #[test]
    fn html_entity_decode_invalid_utf8_passes_through() {
        let input = [0xff, 0xfe, 0x41];
        assert_eq!(html_entity_decode(&input), &input);
    }
}
