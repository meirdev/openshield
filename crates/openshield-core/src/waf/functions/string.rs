use wirefilter_engine::{FunctionArgs, LhsValue};

pub fn lower(input: &[u8]) -> Vec<u8> {
    input.to_ascii_lowercase()
}

pub fn upper(input: &[u8]) -> Vec<u8> {
    input.to_ascii_uppercase()
}

pub fn trim(input: &[u8]) -> Vec<u8> {
    let start = input
        .iter()
        .position(|&c| !c.is_ascii_whitespace())
        .unwrap_or(input.len());
    let end = input
        .iter()
        .rposition(|&c| !c.is_ascii_whitespace())
        .map(|i| i + 1)
        .unwrap_or(start);
    input[start..end].to_vec()
}

pub fn trim_start(input: &[u8]) -> Vec<u8> {
    let start = input
        .iter()
        .position(|&c| !c.is_ascii_whitespace())
        .unwrap_or(input.len());
    input[start..].to_vec()
}

pub fn trim_end(input: &[u8]) -> Vec<u8> {
    let end = input
        .iter()
        .rposition(|&c| !c.is_ascii_whitespace())
        .map(|i| i + 1)
        .unwrap_or(0);
    input[..end].to_vec()
}

pub fn remove_nulls(input: &[u8]) -> Vec<u8> {
    input.iter().copied().filter(|&c| c != 0).collect()
}

pub fn replace_nulls(input: &[u8]) -> Vec<u8> {
    input
        .iter()
        .copied()
        .map(|c| if c == 0 { b' ' } else { c })
        .collect()
}

pub fn remove_whitespace(input: &[u8]) -> Vec<u8> {
    input
        .iter()
        .copied()
        .filter(|c| !c.is_ascii_whitespace())
        .collect()
}

/// Unlike `u8::is_ascii_whitespace`, this includes vertical tab (0x0B).
const fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t'..=b'\r')
}

pub fn compress_whitespace(input: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = input
        .iter()
        .map(|&c| if is_space(c) { b' ' } else { c })
        .collect();
    out.dedup_by(|a, b| *a == b' ' && *b == b' ');
    out
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

pub fn replace_comments(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut rest = input;
    while let Some(start) = find(rest, b"/*") {
        out.extend_from_slice(&rest[..start]);
        out.push(b' ');
        let body = &rest[start + 2..];
        rest = find(body, b"*/").map_or(&[][..], |end| &body[end + 2..]);
    }
    out.extend_from_slice(rest);
    out
}

pub fn starts_with_fn<'a>(args: FunctionArgs<'_, 'a>) -> Option<LhsValue<'a>> {
    let LhsValue::Bytes(input) = args.next()?.ok()? else {
        return None;
    };
    let LhsValue::Bytes(prefix) = args.next()?.ok()? else {
        return None;
    };
    Some(LhsValue::Bool(input.starts_with(&prefix)))
}

pub fn ends_with_fn<'a>(args: FunctionArgs<'_, 'a>) -> Option<LhsValue<'a>> {
    let LhsValue::Bytes(input) = args.next()?.ok()? else {
        return None;
    };
    let LhsValue::Bytes(suffix) = args.next()?.ok()? else {
        return None;
    };
    Some(LhsValue::Bool(input.ends_with(&suffix)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lower_upper_ascii_only() {
        assert_eq!(lower(b"AbC123"), b"abc123");
        assert_eq!(upper(b"AbC123"), b"ABC123");
        // Non-ASCII bytes are untouched (ASCII-only casing).
        let utf8 = "É".as_bytes();
        assert_eq!(lower(utf8), utf8);
    }

    #[test]
    fn trim_variants() {
        assert_eq!(trim(b"  hello  "), b"hello");
        assert_eq!(trim(b"\t\n hi \r\n"), b"hi");
        assert_eq!(trim_start(b"  hello  "), b"hello  ");
        assert_eq!(trim_end(b"  hello  "), b"  hello");
    }

    #[test]
    fn trim_all_whitespace_is_empty() {
        assert_eq!(trim(b"    "), b"");
        assert_eq!(trim_start(b"    "), b"");
        assert_eq!(trim_end(b"    "), b"");
        assert_eq!(trim(b""), b"");
    }

    #[test]
    fn null_handling() {
        assert_eq!(remove_nulls(b"a\0b\0c"), b"abc");
        assert_eq!(replace_nulls(b"a\0b\0c"), b"a b c");
        assert_eq!(remove_nulls(b"abc"), b"abc");
    }

    #[test]
    fn remove_whitespace_strips_interior_too() {
        assert_eq!(remove_whitespace(b" a b\tc\n"), b"abc");
        assert_eq!(remove_whitespace(b"nospace"), b"nospace");
    }

    #[test]
    fn compress_whitespace_collapses_runs() {
        assert_eq!(compress_whitespace(b"a  b \t\r\n c"), b"a b c");
        assert_eq!(compress_whitespace(b"  a  "), b" a ");
        // A lone whitespace byte is still normalized to a space.
        assert_eq!(compress_whitespace(b"a\tb\nc"), b"a b c");
        assert_eq!(compress_whitespace(b"nospace"), b"nospace");
        assert_eq!(compress_whitespace(b""), b"");
    }

    #[test]
    fn replace_comments_replaces_each_with_one_space() {
        assert_eq!(
            replace_comments(b"UN/**/ION/* x */SELECT"),
            b"UN ION SELECT"
        );
        assert_eq!(replace_comments(b"a/* 1 *//* 2 */b"), b"a  b");
        assert_eq!(replace_comments(b"a/* line\nbreak */b"), b"a b");
        assert_eq!(replace_comments(b"no comments"), b"no comments");
        assert_eq!(replace_comments(b""), b"");
    }

    #[test]
    fn replace_comments_edge_cases() {
        // Unterminated comment swallows the rest of the input.
        assert_eq!(replace_comments(b"a/* b"), b"a ");
        // `/*/` opens a comment but does not close it.
        assert_eq!(replace_comments(b"a/*/b"), b"a ");
        // A standalone `*/` is left alone.
        assert_eq!(replace_comments(b"a*/b"), b"a*/b");
        // Comments do not nest: the first `*/` closes.
        assert_eq!(replace_comments(b"a/* /* */b*/"), b"a b*/");
    }

    #[test]
    fn compress_whitespace_uses_c_isspace() {
        // Vertical tab and form feed are whitespace for C `isspace`.
        assert_eq!(compress_whitespace(b"a\x0b\x0cb"), b"a b");
        // NUL and NBSP (0xA0) are not.
        assert_eq!(compress_whitespace(b"a\0\0b"), b"a\0\0b");
        assert_eq!(compress_whitespace(b"a\xa0\xa0b"), b"a\xa0\xa0b");
    }

    // Expression-level tests: confirm the functions are registered and wired
    // through the scheme the way rules invoke them.
    mod via_scheme {
        use crate::waf::functions::test_support::eval_bytes;

        const HOST: &str = "http.host";

        #[test]
        fn starts_with_literal() {
            assert!(eval_bytes(
                r#"starts_with(http.host, "he")"#,
                HOST,
                b"hello"
            ));
            assert!(!eval_bytes(
                r#"starts_with(http.host, "xy")"#,
                HOST,
                b"hello"
            ));
        }

        #[test]
        fn ends_with_literal() {
            assert!(eval_bytes(r#"ends_with(http.host, "lo")"#, HOST, b"hello"));
            assert!(!eval_bytes(r#"ends_with(http.host, "xy")"#, HOST, b"hello"));
        }

        #[test]
        fn transform_then_compare() {
            // Polymorphic Bytes path: lower(field) applied before comparison.
            assert!(eval_bytes(r#"lower(http.host) == "abc""#, HOST, b"ABC"));
        }

        #[test]
        fn transform_over_array() {
            use crate::waf::functions::test_support::eval_array;
            // Polymorphic Array path: lower() maps element-wise over the array,
            // feeding its transformed array into detect_sqli's array path.
            assert!(eval_array(
                "any(detect_sqli(lower(http.request.uri.args.values[*])))",
                "http.request.uri.args.values",
                &[b"benign", b"1' OR '1'='1"],
            ));
            assert!(!eval_array(
                "any(detect_sqli(lower(http.request.uri.args.values[*])))",
                "http.request.uri.args.values",
                &[b"hello", b"world"],
            ));
        }
    }
}
