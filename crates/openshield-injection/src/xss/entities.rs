//! HTML character reference decoding for attribute values.
//!
//! Browsers decode references before interpreting a URL or style, so
//! `java&#115;cript:` and `java&Tab;script:` both run. The decoder accepts
//! numeric references with or without the closing semicolon and the named
//! references that are short enough to be useful in a payload.

/// The named references worth decoding: punctuation and whitespace that can
/// break up a scheme or a keyword. Sorted by name.
const NAMED: &[(&[u8], u32)] = &[
    (b"AMP", '&' as u32),
    (b"GT", '>' as u32),
    (b"Hat", '^' as u32),
    (b"LT", '<' as u32),
    (b"NewLine", '\n' as u32),
    (b"QUOT", '"' as u32),
    (b"Tab", '\t' as u32),
    (b"amp", '&' as u32),
    (b"apos", '\'' as u32),
    (b"ast", '*' as u32),
    (b"bsol", '\\' as u32),
    (b"colon", ':' as u32),
    (b"comma", ',' as u32),
    (b"commat", '@' as u32),
    (b"dollar", '$' as u32),
    (b"equals", '=' as u32),
    (b"excl", '!' as u32),
    (b"grave", '`' as u32),
    (b"gt", '>' as u32),
    (b"lbrace", '{' as u32),
    (b"lbrack", '[' as u32),
    (b"lcub", '{' as u32),
    (b"lowbar", '_' as u32),
    (b"lpar", '(' as u32),
    (b"lsqb", '[' as u32),
    (b"lt", '<' as u32),
    (b"nbsp", 0xa0),
    (b"num", '#' as u32),
    (b"percnt", '%' as u32),
    (b"period", '.' as u32),
    (b"plus", '+' as u32),
    (b"quest", '?' as u32),
    (b"quot", '"' as u32),
    (b"rbrace", '}' as u32),
    (b"rbrack", ']' as u32),
    (b"rcub", '}' as u32),
    (b"rpar", ')' as u32),
    (b"rsqb", ']' as u32),
    (b"semi", ';' as u32),
    (b"sol", '/' as u32),
    (b"tilde", '~' as u32),
    (b"verbar", '|' as u32),
];

/// Decodes the character at the start of `s`, returning the code point and
/// the number of bytes consumed. Bytes that are not a reference, including a
/// `&` that starts nothing recognizable, decode to themselves.
pub fn decode_char(s: &[u8]) -> (u32, usize) {
    let plain = (u32::from(s[0]), 1);
    if s[0] != b'&' || s.len() < 2 {
        return plain;
    }
    if s[1] == b'#' {
        let (radix, digits_at) = match s.get(2) {
            Some(b'x' | b'X') => (16, 3),
            _ => (10, 2),
        };
        return decode_numeric(s, radix, digits_at).unwrap_or(plain);
    }
    decode_named(&s[1..])
        .map(|(cp, len)| (cp, len + 1))
        .unwrap_or(plain)
}

fn decode_numeric(s: &[u8], radix: u32, digits_at: usize) -> Option<(u32, usize)> {
    let mut i = digits_at;
    let mut value: u32 = 0;
    while let Some(d) = s.get(i).and_then(|&b| (b as char).to_digit(radix)) {
        // Out-of-range references render as U+FFFD; saturate instead of
        // wrapping.
        value = value.saturating_mul(radix).saturating_add(d).min(0x11_0000);
        i += 1;
    }
    if i == digits_at {
        return None;
    }
    if s.get(i) == Some(&b';') {
        i += 1;
    }
    Some((value, i))
}

fn decode_named(s: &[u8]) -> Option<(u32, usize)> {
    let end = s
        .iter()
        .position(|b| !b.is_ascii_alphanumeric())
        .unwrap_or(s.len());
    let name = &s[..end];
    let idx = NAMED.binary_search_by_key(&name, |(n, _)| n).ok()?;
    let len = if s.get(end) == Some(&b';') {
        end + 1
    } else {
        end
    };
    Some((NAMED[idx].1, len))
}

/// Iterates over the decoded code points of `s`.
pub fn decode(s: &[u8]) -> impl Iterator<Item = u32> + '_ {
    let mut pos = 0;
    std::iter::from_fn(move || {
        let rest = s.get(pos..).filter(|rest| !rest.is_empty())?;
        let (cp, len) = decode_char(rest);
        pos += len;
        Some(cp)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decoded(s: &str) -> String {
        decode(s.as_bytes())
            .map(|cp| char::from_u32(cp).unwrap_or('\u{fffd}'))
            .collect()
    }

    #[test]
    fn named_table_is_sorted_for_binary_search() {
        assert!(NAMED.windows(2).all(|w| w[0].0 < w[1].0));
    }

    #[test]
    fn numeric_references() {
        assert_eq!(decoded("&#106;avascript"), "javascript");
        assert_eq!(decoded("&#x6A;&#X61;"), "ja");
        assert_eq!(decoded("&#106avascript"), "javascript");
        assert_eq!(decoded("&#0000106;"), "j");
        assert_eq!(decoded("&#;&#x;"), "&#;&#x;");
    }

    #[test]
    fn named_references() {
        assert_eq!(decoded("java&Tab;script&colon;x"), "java\tscript:x");
        assert_eq!(decoded("a&NewLine;b"), "a\nb");
        assert_eq!(decoded("&colon"), ":");
        assert_eq!(decoded("&bogus;"), "&bogus;");
        assert_eq!(decoded("fish & chips"), "fish & chips");
    }
}
