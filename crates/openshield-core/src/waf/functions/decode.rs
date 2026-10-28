use base64::Engine as _;

use super::string::is_space;

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

const fn is_odigit(c: u8) -> bool {
    matches!(c, b'0'..=b'7')
}

/// Decode JavaScript backslash escapes.
///
/// Handles `\uHHHH`, `\xHH`, octal `\OOO`, the C escapes `\a \b \f \n \r \t
/// \v`, and a bare `\C` which just drops the backslash. Matches ModSecurity's
/// quirks: `\uHHHH` keeps only the low byte, full-width ASCII (`\uffXX`, low
/// byte `0x01..=0x5e`) is folded to ASCII by adding `0x20`, and a 3-digit
/// octal that would exceed one byte falls back to 2 digits.
pub fn js_decode(input: &[u8]) -> Vec<u8> {
    let is_hex = |c: &u8| c.is_ascii_hexdigit();

    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] != b'\\' {
            out.push(input[i]);
            i += 1;
            continue;
        }
        let rest = &input[i + 1..];
        match rest {
            // \uHHHH -> low byte, with full-width ASCII folded to ASCII.
            [b'u', h @ ..] if h.len() >= 4 && h[..4].iter().all(is_hex) => {
                let mut b = hex2(h[2], h[3]);
                if b > 0x00 && b < 0x5f && (h[0] | 0x20) == b'f' && (h[1] | 0x20) == b'f' {
                    b += 0x20;
                }
                out.push(b);
                i += 6;
            }
            [b'x', h0, h1, ..] if is_hex(h0) && is_hex(h1) => {
                out.push(hex2(*h0, *h1));
                i += 4;
            }
            // \OOO octal, one byte (\000 - \377).
            [d0, ..] if is_odigit(*d0) => {
                let mut digits = 1;
                while digits < 3 && rest.get(digits).is_some_and(|&c| is_odigit(c)) {
                    digits += 1;
                }
                // Don't use 3 digits if the value would exceed one byte.
                if digits == 3 && rest[0] > b'3' {
                    digits = 2;
                }
                out.push(octal(&rest[..digits]));
                i += 1 + digits;
            }
            // \C escapes: named ones translate, anything else drops the backslash.
            [c, ..] => {
                out.push(match c {
                    b'a' => 0x07,
                    b'b' => 0x08,
                    b'f' => 0x0c,
                    b'n' => b'\n',
                    b'r' => b'\r',
                    b't' => b'\t',
                    b'v' => 0x0b,
                    other => *other,
                });
                i += 2;
            }
            // Trailing lone backslash is kept.
            [] => {
                out.push(b'\\');
                i += 1;
            }
        }
    }
    out
}

/// Decode ANSI-C escape sequences.
///
/// Handles `\a \b \f \n \r \t \v \\ \? \' \"`, `\xHH`, and octal `\OOO`
/// (up to three digits, truncated to one byte). An unrecognised `\C` keeps `C`.
pub fn escape_seq_decode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] != b'\\' || i + 1 >= input.len() {
            out.push(input[i]);
            i += 1;
            continue;
        }
        let next = input[i + 1];
        let named = match next {
            b'a' => Some(0x07),
            b'b' => Some(0x08),
            b'f' => Some(0x0c),
            b'n' => Some(b'\n'),
            b'r' => Some(b'\r'),
            b't' => Some(b'\t'),
            b'v' => Some(0x0b),
            b'\\' | b'?' | b'\'' | b'"' => Some(next),
            _ => None,
        };
        if let Some(c) = named {
            out.push(c);
            i += 2;
            continue;
        }
        // Hexadecimal \xHH / \XHH.
        if (next == b'x' || next == b'X')
            && i + 3 < input.len()
            && input[i + 2].is_ascii_hexdigit()
            && input[i + 3].is_ascii_hexdigit()
        {
            out.push(hex2(input[i + 2], input[i + 3]));
            i += 4;
            continue;
        }
        // Octal \OOO (1-3 digits, one byte).
        if is_odigit(next) {
            let mut digits = 1;
            while digits < 3 && input.get(i + 1 + digits).is_some_and(|&c| is_odigit(c)) {
                digits += 1;
            }
            out.push(octal(&input[i + 1..i + 1 + digits]));
            i += 1 + digits;
            continue;
        }
        // Unrecognised escape: drop the backslash, keep the char.
        out.push(next);
        i += 2;
    }
    out
}

/// Decode CSS escapes.
///
/// A backslash starts an escape: 1-6 hex digits decode to a byte (only the
/// last two hex digits are used; a single trailing whitespace is then
/// consumed), a backslash-newline is a line continuation and drops both bytes,
/// and any other `\C` keeps `C`. Matches ModSecurity's quirks, including the
/// full-width ASCII fold (`\ff41` -> `a`) for the 4/5/6-digit `00ffXX` forms.
pub fn css_decode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] != b'\\' {
            out.push(input[i]);
            i += 1;
            continue;
        }
        // Trailing backslash: continuation to nothing.
        if i + 1 >= input.len() {
            break;
        }
        i += 1;
        let hex = &input[i..];
        let j = hex
            .iter()
            .take(6)
            .take_while(|c| c.is_ascii_hexdigit())
            .count();

        if j == 0 {
            // Backslash-newline is a line continuation; \C -> C.
            if input[i] != b'\n' {
                out.push(input[i]);
            }
            i += 1;
            continue;
        }

        // Single digit for j == 1, else the last two hex digits.
        let mut byte = if j == 1 {
            hex2(b'0', hex[0])
        } else {
            hex2(hex[j - 2], hex[j - 1])
        };

        // Full-width ASCII fold applies to the 00ffXX forms (j 4/5/6 with the
        // leading digits zero), when the two hex digits before the last two
        // are `ff`.
        let fullcheck = match j {
            4 => true,
            5 => hex[0] == b'0',
            6 => hex[0] == b'0' && hex[1] == b'0',
            _ => false,
        };
        if fullcheck
            && byte > 0x00
            && byte < 0x5f
            && (hex[j - 3] | 0x20) == b'f'
            && (hex[j - 4] | 0x20) == b'f'
        {
            byte += 0x20;
        }
        out.push(byte);

        i += j;
        // A single whitespace after a hex escape is ignored.
        if i < input.len() && is_space(input[i]) {
            i += 1;
        }
    }
    out
}

/// Value of 1-3 octal digits, truncated to one byte.
fn octal(digits: &[u8]) -> u8 {
    digits
        .iter()
        .fold(0u32, |acc, &c| acc * 8 + u32::from(c - b'0')) as u8
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

    #[test]
    fn js_decode_escapes() {
        assert_eq!(js_decode(br"\x41\x42"), b"AB");
        assert_eq!(js_decode(br"\u0041"), b"A");
        assert_eq!(js_decode(br"a\tb\nc"), b"a\tb\nc");
        assert_eq!(js_decode(br"\a\b\f\v"), &[0x07, 0x08, 0x0c, 0x0b]);
        // Unknown escapes drop the backslash.
        assert_eq!(js_decode(br#"\"\\\'\q"#), br#""\'q"#);
        // Full-width ASCII \uffXX folds to ASCII; low byte 0x00 is not folded.
        assert_eq!(js_decode(br"\uff41\uFF21"), b"aA");
        assert_eq!(js_decode(br"\uff00"), &[0x00]);
        // Octal: \412 would exceed a byte, so it is \41 ('!') + literal '2'.
        assert_eq!(js_decode(br"\101"), b"A");
        assert_eq!(js_decode(br"\412"), b"!2");
        // Trailing lone backslash is kept.
        assert_eq!(js_decode(br"ab\"), b"ab\\");
        // Incomplete \xH falls through to the generic \C case.
        assert_eq!(js_decode(br"\x4"), b"x4");
        assert_eq!(js_decode(b"plain text"), b"plain text");
    }

    #[test]
    fn escape_seq_decode_ansi_c() {
        assert_eq!(escape_seq_decode(br"\n\t\r"), b"\n\t\r");
        assert_eq!(escape_seq_decode(br"\x41\X42"), b"AB");
        assert_eq!(escape_seq_decode(br"\101"), b"A");
        // Octal truncates to a byte.
        assert_eq!(escape_seq_decode(br"\777"), &[0xff]);
        assert_eq!(escape_seq_decode(br#"\\\?\'\""#), br#"\?'""#);
        assert_eq!(escape_seq_decode(br"\z"), b"z");
        assert_eq!(escape_seq_decode(br"\xG1"), b"xG1");
        assert_eq!(escape_seq_decode(br"ab\"), br"ab\");
        assert_eq!(escape_seq_decode(b"plain"), b"plain");
    }

    #[test]
    fn css_decode_escapes() {
        // 1-6 hex digits, last two used; single trailing whitespace consumed.
        assert_eq!(css_decode(br"\41"), b"A");
        assert_eq!(css_decode(br"\41 B"), b"AB");
        assert_eq!(css_decode(br"\000041"), b"A");
        assert_eq!(css_decode(br"\4"), &[0x04]);
        // Full-width fold for the 4/5/6-digit 00ffXX forms.
        assert_eq!(css_decode(br"\ff41"), b"a");
        assert_eq!(css_decode(br"\0ff41"), b"a");
        assert_eq!(css_decode(br"\00ff21"), b"A");
        // Non-hex \C keeps C; backslash-newline is a line continuation.
        assert_eq!(css_decode(br"\."), b".");
        assert_eq!(css_decode(b"a\\\nb"), b"ab");
        assert_eq!(css_decode(br"\6a\61va"), b"java");
        // Trailing lone backslash is dropped.
        assert_eq!(css_decode(br"ab\"), b"ab");
        assert_eq!(css_decode(b"no escapes"), b"no escapes");
    }
}
