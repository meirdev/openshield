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
    let mut result = Vec::with_capacity(input.len() / 2);
    let mut i = 0;
    while i + 1 < input.len() {
        if input[i].is_ascii_hexdigit() && input[i + 1].is_ascii_hexdigit() {
            result.push(hex2(input[i], input[i + 1]));
            i += 2;
        } else {
            result.push(input[i]);
            i += 1;
        }
    }
    if i < input.len() {
        result.push(input[i]);
    }
    result
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
