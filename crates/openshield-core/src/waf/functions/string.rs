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
pub(super) const fn is_space(c: u8) -> bool {
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

/// Strip C/HTML/SQL/shell comments.
///
/// Removes `/* ... */` and `<!-- ... -->` blocks, and truncates at the first
/// `--` or `#`. Faithful to ModSecurity's quirks: the byte immediately after a
/// closing `*/`/`-->` is copied through, and an unterminated block becomes a
/// single trailing space.
pub fn remove_comments(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    let mut in_comment = false;
    while i < input.len() {
        if !in_comment {
            match &input[i..] {
                [b'/', b'*', ..] => {
                    in_comment = true;
                    i += 2;
                }
                [b'<', b'!', b'-', b'-', ..] => {
                    in_comment = true;
                    i += 4;
                }
                // `--` and `#` start a comment that runs to end of input.
                [b'-', b'-', ..] | [b'#', ..] => break,
                _ => {
                    out.push(input[i]);
                    i += 1;
                }
            }
        } else {
            let close = match &input[i..] {
                [b'*', b'/', ..] => Some(2),
                [b'-', b'-', b'>', ..] => Some(3),
                _ => None,
            };
            match close {
                Some(skip) => {
                    in_comment = false;
                    i += skip;
                    // ModSecurity copies the byte right after the close marker;
                    // past the end it reads the string's NUL terminator.
                    out.push(input.get(i).copied().unwrap_or(0));
                    i += 1;
                }
                None => i += 1,
            }
        }
    }
    if in_comment {
        out.push(b' ');
    }
    out
}

/// Normalise an obfuscated command line.
///
/// Deletes `" ' \ ^`, collapses runs of `, ; \t \r \n` and space into a single
/// space, drops the space immediately before `/` or `(`, and lowercases
/// everything else.
pub fn cmd_line(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut space = false;
    for &c in input {
        match c {
            b'"' | b'\'' | b'\\' | b'^' => {}
            b' ' | b',' | b';' | b'\t' | b'\r' | b'\n' => {
                if !space {
                    out.push(b' ');
                    space = true;
                }
            }
            b'/' | b'(' => {
                if space {
                    out.pop();
                }
                space = false;
                out.push(c);
            }
            _ => {
                out.push(c.to_ascii_lowercase());
                space = false;
            }
        }
    }
    out
}

/// Normalise a filesystem path.
pub fn normalize_path(input: &[u8]) -> Vec<u8> {
    normalize_path_impl(input, false)
}

/// Normalise a Windows-style filesystem path (also treats `\` as a separator).
pub fn normalize_path_win(input: &[u8]) -> Vec<u8> {
    normalize_path_impl(input, true)
}

/// Collapse `//`, resolve `.` and `..` segments, and drop a trailing slash
/// that was not in the input. `win` also treats `\` as a separator.
fn normalize_path_impl(input: &[u8], win: bool) -> Vec<u8> {
    if input.is_empty() {
        return Vec::new();
    }
    let mut buf = input.to_vec();
    let end: isize = buf.len() as isize - 1;
    let mut src: isize = 0;
    let mut dst: isize = 0;
    let mut done = false;
    let mut hitroot = false;

    let is_sep = |c: u8| c == b'/' || (win && c == b'\\');
    let relative = !is_sep(buf[0]);
    let trailing = is_sep(buf[end as usize]);

    while !done && src <= end && dst <= end {
        let s = src as usize;
        if win {
            if buf[s] == b'\\' {
                buf[s] = b'/';
            }
            if src < end && buf[s + 1] == b'\\' {
                buf[s + 1] = b'/';
            }
        }

        // Only normalise at a segment boundary (end of input, or next is '/').
        let mut goto_copy = false;
        if src == end {
            done = true;
        } else if buf[s + 1] != b'/' {
            goto_copy = true;
        }

        let mut skip_copy = false;
        if !goto_copy {
            if src != end && buf[s] == b'/' {
                // Empty segment; the copy step collapses it.
            } else if buf[s] == b'.' {
                if dst > 0 && buf[(dst - 1) as usize] == b'.' {
                    // Back-reference "..".
                    if relative && (hitroot || (dst - 2) <= 0) {
                        // Can't go above root; copy the backref.
                        hitroot = true;
                    } else {
                        dst -= 3;
                        while dst > 0 && buf[dst as usize] != b'/' {
                            dst -= 1;
                        }
                        if dst <= 0 {
                            hitroot = true;
                            dst = 0;
                            if !relative && src == end {
                                dst += 1;
                            }
                        }
                        if done {
                            skip_copy = true;
                        } else {
                            src += 1;
                        }
                    }
                } else if dst == 0 {
                    // Leading self-reference ".".
                    if done {
                        skip_copy = true;
                    } else {
                        src += 1;
                    }
                } else if buf[(dst - 1) as usize] == b'/' {
                    // Self-reference "/.".
                    if done {
                        skip_copy = true;
                    } else {
                        dst -= 1;
                        src += 1;
                    }
                }
                // A '.' inside a segment (e.g. "a.") is copied.
            } else if dst > 0 {
                hitroot = false;
            }
        }

        if !skip_copy {
            // Copy step: collapse consecutive separators.
            if buf[src as usize] == b'/' {
                while src < end && is_sep(buf[(src + 1) as usize]) {
                    src += 1;
                }
                if relative && dst == 0 {
                    src += 1;
                    skip_copy = true;
                }
            }
            if !skip_copy {
                buf[dst as usize] = buf[src as usize];
                dst += 1;
                src += 1;
            }
        }
    }

    // Drop a trailing slash that was not present in the input.
    if !trailing && dst > 0 && buf[(dst - 1) as usize] == b'/' {
        dst -= 1;
    }
    buf.truncate(dst as usize);
    buf
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

    #[test]
    fn remove_comments_strips_blocks() {
        assert_eq!(remove_comments(b"a/* c */b"), b"ab");
        assert_eq!(remove_comments(b"1/**/2"), b"12");
        assert_eq!(remove_comments(b"<!--x-->y"), b"y");
        // `--` and `#` truncate to end of input.
        assert_eq!(remove_comments(b"abc--def"), b"abc");
        assert_eq!(remove_comments(b"abc#def"), b"abc");
        // Unterminated block -> single trailing space.
        assert_eq!(remove_comments(b"a/*unterminated"), b"a ");
        // Byte right after a close marker is copied through (here 'z').
        assert_eq!(remove_comments(b"/*c*/z/*d*/w"), b"zw");
        assert_eq!(remove_comments(b"no comments here"), b"no comments here");
    }

    #[test]
    fn cmd_line_normalises() {
        assert_eq!(cmd_line(b"\"C:\\WINDOWS\\cmd.exe\""), b"c:windowscmd.exe");
        assert_eq!(cmd_line(b"cat  /etc/passwd"), b"cat/etc/passwd");
        assert_eq!(cmd_line(b"n^et u,s,e,r"), b"net u s e r");
        assert_eq!(cmd_line(b"echo ('x')"), b"echo(x)");
        assert_eq!(cmd_line(b"PING\tlocalhost"), b"ping localhost");
    }

    #[test]
    fn normalize_path_resolves_dots_and_slashes() {
        assert_eq!(normalize_path(b"/a//b///c"), b"/a/b/c");
        assert_eq!(normalize_path(b"/a/./b"), b"/a/b");
        assert_eq!(normalize_path(b"/a/b/../c"), b"/a/c");
        assert_eq!(normalize_path(b"/foo/../../etc/passwd"), b"/etc/passwd");
        // Relative path keeps a leading `..` that can't be resolved.
        assert_eq!(normalize_path(b"a/../../b"), b"../b");
        // Trailing slash only preserved if present in input.
        assert_eq!(normalize_path(b"/a/b/"), b"/a/b/");
        assert_eq!(normalize_path(b"/a/b/."), b"/a/b");
        assert_eq!(normalize_path(b""), b"");
    }

    #[test]
    fn normalize_path_win_treats_backslash_as_separator() {
        assert_eq!(normalize_path_win(br"c:\a\..\b"), b"c:/b");
        assert_eq!(normalize_path_win(br"\a\\b\.\c"), b"/a/b/c");
        // The non-Windows variant leaves backslashes alone.
        assert_eq!(normalize_path(br"a\b"), br"a\b");
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
