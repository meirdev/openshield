//! Decoders that undo the encodings an attacker layers over a payload.

use std::borrow::Cow;

use base64::Engine as _;

use super::helpers::Transform;

/// `url_decode(s[, "options"])`: `%XX` and `+`. Options, as in Cloudflare's
/// rules language: `u` also decodes `%uXXXX` to UTF-8, `r` decodes
/// repeatedly until nothing changes. Malformed escapes pass through.
pub fn url_decode_with(options: Option<&[u8]>) -> Result<Transform, String> {
    let (mut unicode, mut recursive) = (false, false);
    for &c in options.unwrap_or_default() {
        match c {
            b'u' => unicode = true,
            b'r' => recursive = true,
            _ => {
                return Err(format!(
                    "unknown url_decode option {:?}; expected \"r\" or \"u\"",
                    char::from(c)
                ));
            }
        }
    }
    Ok(Box::new(move |input: &[u8]| {
        url_decode(input, unicode, recursive)
    }))
}

pub fn url_decode(input: &[u8], unicode: bool, recursive: bool) -> Cow<'_, [u8]> {
    let Cow::Owned(mut out) = url_decode_once(input, unicode) else {
        return Cow::Borrowed(input);
    };
    // Each pass that changes anything shortens the value or replaces a `+`,
    // so this terminates.
    if recursive {
        while let Cow::Owned(next) = url_decode_once(&out, unicode) {
            out = next;
        }
    }
    Cow::Owned(out)
}

/// One decoding pass; borrowed when nothing was decoded.
fn url_decode_once(input: &[u8], unicode: bool) -> Cow<'_, [u8]> {
    if !input.iter().any(|&c| c == b'%' || c == b'+') {
        return Cow::Borrowed(input);
    }
    let mut out = Vec::with_capacity(input.len());
    let mut changed = false;
    let mut i = 0;
    while i < input.len() {
        let rest = &input[i..];
        match rest {
            [b'+', ..] => {
                out.push(b' ');
                i += 1;
            }
            [b'%', b'u' | b'U', ..] if unicode && percent_u(rest).is_some() => {
                let (ch, len) = percent_u(rest).unwrap();
                out.extend_from_slice(ch.encode_utf8(&mut [0; 4]).as_bytes());
                i += len;
            }
            [b'%', h, l, ..] if h.is_ascii_hexdigit() && l.is_ascii_hexdigit() => {
                out.push(hex2(*h, *l));
                i += 3;
            }
            [c, ..] => {
                out.push(*c);
                i += 1;
                continue;
            }
            [] => unreachable!(),
        }
        changed = true;
    }
    if changed {
        Cow::Owned(out)
    } else {
        Cow::Borrowed(input)
    }
}

/// `%uXXXX` at the start of `s`: the character and the escape's length. A
/// surrogate pair (`%uD83D%uDE00`) is combined; a lone surrogate is not a
/// character and is left as is.
fn percent_u(s: &[u8]) -> Option<(char, usize)> {
    fn unit(s: &[u8]) -> Option<u32> {
        match s {
            [b'%', b'u' | b'U', a, b, c, d, ..]
                if [a, b, c, d].iter().all(|h| h.is_ascii_hexdigit()) =>
            {
                Some((u32::from(hex2(*a, *b)) << 8) | u32::from(hex2(*c, *d)))
            }
            _ => None,
        }
    }
    let first = unit(s)?;
    if (0xd800..0xdc00).contains(&first) {
        let second = unit(&s[6..]).filter(|u| (0xdc00..0xe000).contains(u))?;
        let cp = 0x10000 + ((first - 0xd800) << 10) + (second - 0xdc00);
        return char::from_u32(cp).map(|c| (c, 12));
    }
    char::from_u32(first).map(|c| (c, 6))
}

pub fn decode_base64(input: &[u8]) -> Cow<'_, [u8]> {
    base64::engine::general_purpose::STANDARD
        .decode(input)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(input))
        .map_or(Cow::Borrowed(input), Cow::Owned)
}

/// Input that is not hex passes through.
pub fn hex_decode(input: &[u8]) -> Cow<'_, [u8]> {
    hex::decode(input).map_or(Cow::Borrowed(input), Cow::Owned)
}

/// Input that is not UTF-8 passes through.
pub fn html_entity_decode(input: &[u8]) -> Cow<'_, [u8]> {
    let Ok(s) = std::str::from_utf8(input) else {
        return Cow::Borrowed(input);
    };
    match html_escape::decode_html_entities(s) {
        Cow::Borrowed(s) => Cow::Borrowed(s.as_bytes()),
        Cow::Owned(s) => Cow::Owned(s.into_bytes()),
    }
}

fn hex2(a: u8, b: u8) -> u8 {
    let digit = |c: u8| match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => 0,
    };
    (digit(a) << 4) | digit(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(input: &[u8]) -> Cow<'_, [u8]> {
        url_decode(input, false, false)
    }

    #[test]
    fn url_decode_passthrough_when_no_escapes() {
        assert!(matches!(decode(b"plain text"), Cow::Borrowed(_)));
        // A `%` that starts no valid escape is not a change either.
        assert!(matches!(decode(b"100%"), Cow::Borrowed(_)));
        assert_eq!(&*decode(b""), b"");
    }

    #[test]
    fn url_decode_plus_becomes_space() {
        assert_eq!(&*decode(b"a+b+c"), b"a b c");
    }

    #[test]
    fn url_decode_percent_hex() {
        // %41 == 'A', case-insensitive hex digits.
        assert_eq!(&*decode(b"%41%42%43"), b"ABC");
        assert_eq!(&*decode(b"%2f"), b"/");
        assert_eq!(&*decode(b"%2F"), b"/");
        // Decodes a classic SQLi quote: %27 == '\''.
        assert_eq!(&*decode(b"1%27%20OR%201"), b"1' OR 1");
    }

    #[test]
    fn url_decode_malformed_passes_through() {
        assert_eq!(&*decode(b"%zz"), b"%zz");
        assert_eq!(&*decode(b"abc%4"), b"abc%4");
        assert_eq!(&*decode(b"%"), b"%");
    }

    #[test]
    fn url_decode_unicode_only_with_u_option() {
        // Without `u`, %uXXXX is not an escape.
        assert_eq!(&*decode(b"%u0041"), b"%u0041");
        // With `u`, it decodes to UTF-8.
        assert_eq!(&*url_decode(b"%u0041", true, false), b"A");
        assert_eq!(&*url_decode(b"%U00e9", true, false), "é".as_bytes());
        // Full-width A stays full-width (no ModSecurity-style ASCII fold).
        assert_eq!(&*url_decode(b"%uff21", true, false), "Ａ".as_bytes());
        // A surrogate pair is one character; a lone surrogate is left alone.
        assert_eq!(&*url_decode(b"%uD83D%uDE00", true, false), "😀".as_bytes());
        assert_eq!(&*url_decode(b"%uD83Dx", true, false), b"%uD83Dx");
        // %XX still decodes alongside.
        assert_eq!(&*url_decode(b"%u0041%42", true, false), b"AB");
    }

    #[test]
    fn url_decode_recursive_option() {
        // %2527 -> %27 -> '
        assert_eq!(&*decode(b"%2527"), b"%27");
        assert_eq!(&*url_decode(b"%2527", false, true), b"'");
        // %2B -> + -> space
        assert_eq!(&*url_decode(b"%2B", false, true), b" ");
        assert!(matches!(
            url_decode(b"plain", false, true),
            Cow::Borrowed(_)
        ));
    }

    #[test]
    fn url_decode_options_are_validated() {
        assert!(url_decode_with(None).is_ok());
        assert!(url_decode_with(Some(b"ur")).is_ok());
        assert!(url_decode_with(Some(b"x")).is_err());
    }

    #[test]
    fn decode_base64_standard_and_urlsafe() {
        assert_eq!(&*decode_base64(b"aGVsbG8="), b"hello");
        // URL-safe alphabet ('-' and '_') is accepted via fallback.
        assert_eq!(&*decode_base64(b"-_8="), &[0xfb, 0xff]);
    }

    #[test]
    fn decode_base64_invalid_passes_through() {
        assert!(matches!(
            decode_base64(b"not valid!!"),
            Cow::Borrowed(b"not valid!!")
        ));
    }

    #[test]
    fn hex_decode_roundtrip_and_invalid() {
        assert_eq!(&*hex_decode(b"6162"), b"ab");
        // Odd-length / non-hex input is returned unchanged.
        assert!(matches!(hex_decode(b"xyz"), Cow::Borrowed(b"xyz")));
        assert_eq!(&*hex_decode(b"616"), b"616");
    }

    #[test]
    fn html_entity_decode_basic() {
        assert_eq!(&*html_entity_decode(b"&lt;script&gt;"), b"<script>");
        assert_eq!(&*html_entity_decode(b"&amp;"), b"&");
        assert_eq!(&*html_entity_decode(b"&#39;"), b"'");
        assert!(matches!(html_entity_decode(b"plain"), Cow::Borrowed(_)));
    }

    #[test]
    fn html_entity_decode_invalid_utf8_passes_through() {
        let input = [0xff, 0xfe, 0x41];
        assert_eq!(&*html_entity_decode(&input), &input);
    }

    mod via_scheme {
        use crate::waf::functions::test_support::{eval_array, eval_bytes, scheme};

        const ARGS: &str = "http.request.uri.args.values";

        #[test]
        fn url_decode_with_and_without_options() {
            assert!(eval_bytes(
                r#"url_decode(http.host) == "a b""#,
                "http.host",
                b"a%20b"
            ));
            assert!(eval_bytes(
                r#"url_decode(http.host, "ur") == "'A""#,
                "http.host",
                b"%2527%u0041"
            ));
            assert!(eval_array(
                r#"any(url_decode(http.request.uri.args.values[*])[*] == "1' OR 1")"#,
                ARGS,
                &[b"x", b"1%27+OR+1"],
            ));
            assert!(
                scheme()
                    .parse(r#"url_decode(http.host, "x") == """#)
                    .is_err()
            );
        }
    }
}
