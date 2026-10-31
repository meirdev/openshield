//! Case, whitespace, comment, command-line and path normalization.

use std::borrow::Cow;

/// ModSecurity `t:lowercase`, ASCII only.
pub fn lower(input: &[u8]) -> Cow<'_, [u8]> {
    if input.iter().any(u8::is_ascii_uppercase) {
        Cow::Owned(input.to_ascii_lowercase())
    } else {
        Cow::Borrowed(input)
    }
}

/// ModSecurity `t:uppercase`, ASCII only.
pub fn upper(input: &[u8]) -> Cow<'_, [u8]> {
    if input.iter().any(u8::is_ascii_lowercase) {
        Cow::Owned(input.to_ascii_uppercase())
    } else {
        Cow::Borrowed(input)
    }
}

/// ModSecurity `t:trim`.
pub fn trim(input: &[u8]) -> Cow<'_, [u8]> {
    Cow::Borrowed(input.trim_ascii())
}

/// ModSecurity `t:trimLeft`.
pub fn trim_start(input: &[u8]) -> Cow<'_, [u8]> {
    Cow::Borrowed(input.trim_ascii_start())
}

/// ModSecurity `t:trimRight`.
pub fn trim_end(input: &[u8]) -> Cow<'_, [u8]> {
    Cow::Borrowed(input.trim_ascii_end())
}

/// ModSecurity `t:removeNulls`.
pub fn remove_nulls(input: &[u8]) -> Cow<'_, [u8]> {
    if !input.contains(&0) {
        return Cow::Borrowed(input);
    }
    Cow::Owned(input.iter().copied().filter(|&c| c != 0).collect())
}

/// ModSecurity `t:replaceNulls`: every NUL becomes a space.
pub fn replace_nulls(input: &[u8]) -> Cow<'_, [u8]> {
    if !input.contains(&0) {
        return Cow::Borrowed(input);
    }
    Cow::Owned(
        input
            .iter()
            .map(|&c| if c == 0 { b' ' } else { c })
            .collect(),
    )
}

/// ModSecurity `t:removeWhitespace`.
pub fn remove_whitespace(input: &[u8]) -> Cow<'_, [u8]> {
    if !input.iter().any(u8::is_ascii_whitespace) {
        return Cow::Borrowed(input);
    }
    Cow::Owned(
        input
            .iter()
            .copied()
            .filter(|c| !c.is_ascii_whitespace())
            .collect(),
    )
}

/// C `isspace`: unlike `u8::is_ascii_whitespace` this includes vertical tab.
pub(crate) const fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t'..=b'\r')
}

/// ModSecurity `t:compressWhitespace`: every run of whitespace becomes one
/// space.
pub fn compress_whitespace(input: &[u8]) -> Cow<'_, [u8]> {
    let needs_work =
        input.iter().any(|&c| is_space(c) && c != b' ') || input.windows(2).any(|w| w == b"  ");
    if !needs_work {
        return Cow::Borrowed(input);
    }
    let mut out: Vec<u8> = input
        .iter()
        .map(|&c| if is_space(c) { b' ' } else { c })
        .collect();
    out.dedup_by(|a, b| *a == b' ' && *b == b' ');
    Cow::Owned(out)
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// ModSecurity `t:replaceComments`: each `/* ... */` becomes one space; an
/// unterminated comment swallows the rest of the input.
pub fn replace_comments(input: &[u8]) -> Cow<'_, [u8]> {
    let Some(first) = find(input, b"/*") else {
        return Cow::Borrowed(input);
    };
    let mut out = Vec::with_capacity(input.len());
    out.extend_from_slice(&input[..first]);
    let mut rest = &input[first..];
    while let Some(start) = find(rest, b"/*") {
        out.extend_from_slice(&rest[..start]);
        out.push(b' ');
        let body = &rest[start + 2..];
        rest = find(body, b"*/").map_or(&[][..], |end| &body[end + 2..]);
    }
    out.extend_from_slice(rest);
    Cow::Owned(out)
}

/// ModSecurity `t:removeComments`.
///
/// Removes `/* ... */` and `<!-- ... -->` blocks, and truncates at the first
/// `--` or `#`. Faithful to ModSecurity's quirks: the byte immediately after a
/// closing `*/`/`-->` is copied through, and an unterminated block becomes a
/// single trailing space.
pub fn remove_comments(input: &[u8]) -> Cow<'_, [u8]> {
    let has_comment = input.contains(&b'#')
        || find(input, b"/*").is_some()
        || find(input, b"--").is_some()
        || find(input, b"<!--").is_some();
    if !has_comment {
        return Cow::Borrowed(input);
    }
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
    Cow::Owned(out)
}

/// ModSecurity `t:cmdLine`: normalises an obfuscated command line.
///
/// Deletes `" ' \ ^`, collapses runs of `, ; \t \r \n` and space into a single
/// space, drops the space immediately before `/` or `(`, and lowercases
/// everything else.
pub fn cmd_line(input: &[u8]) -> Cow<'_, [u8]> {
    let untouched = |c: &u8| {
        !c.is_ascii_uppercase()
            && !matches!(
                c,
                b'"' | b'\'' | b'\\' | b'^' | b' ' | b',' | b';' | b'\t' | b'\r' | b'\n'
            )
    };
    if input.iter().all(untouched) {
        return Cow::Borrowed(input);
    }
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
    Cow::Owned(out)
}

/// ModSecurity `t:normalizePath`.
pub fn normalize_path(input: &[u8]) -> Cow<'_, [u8]> {
    normalize_path_impl(input, false)
}

/// ModSecurity `t:normalizePathWin`: also treats `\` as a separator.
pub fn normalize_path_win(input: &[u8]) -> Cow<'_, [u8]> {
    normalize_path_impl(input, true)
}

/// Collapse `//`, resolve `.` and `..` segments, and drop a trailing slash
/// that was not in the input. `win` also treats `\` as a separator.
fn normalize_path_impl(input: &[u8], win: bool) -> Cow<'_, [u8]> {
    let may_change = input.first() == Some(&b'.')
        || find(input, b"//").is_some()
        || find(input, b"/.").is_some()
        || (win && input.contains(&b'\\'));
    if !may_change {
        return Cow::Borrowed(input);
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
    Cow::Owned(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lower_upper_ascii_only() {
        assert_eq!(&*lower(b"AbC123"), b"abc123");
        assert_eq!(&*upper(b"AbC123"), b"ABC123");
        // Non-ASCII bytes are untouched (ASCII-only casing).
        let utf8 = "É".as_bytes();
        assert_eq!(&*lower(utf8), utf8);
    }

    #[test]
    fn unchanged_input_is_borrowed() {
        assert!(matches!(lower(b"abc"), Cow::Borrowed(_)));
        assert!(matches!(lower(b"Abc"), Cow::Owned(_)));
        assert!(matches!(trim(b"  a  "), Cow::Borrowed(_)));
        assert!(matches!(remove_nulls(b"abc"), Cow::Borrowed(_)));
        assert!(matches!(compress_whitespace(b"a b c"), Cow::Borrowed(_)));
        assert!(matches!(compress_whitespace(b"a  b"), Cow::Owned(_)));
        assert!(matches!(replace_comments(b"a*/b"), Cow::Borrowed(_)));
        assert!(matches!(remove_comments(b"plain"), Cow::Borrowed(_)));
        assert!(matches!(cmd_line(b"cat/etc/passwd"), Cow::Borrowed(_)));
        assert!(matches!(normalize_path(b"/a/b/c"), Cow::Borrowed(_)));
        assert!(matches!(normalize_path_win(b"a\\b"), Cow::Owned(_)));
    }

    #[test]
    fn trim_variants() {
        assert_eq!(&*trim(b"  hello  "), b"hello");
        assert_eq!(&*trim(b"\t\n hi \r\n"), b"hi");
        assert_eq!(&*trim_start(b"  hello  "), b"hello  ");
        assert_eq!(&*trim_end(b"  hello  "), b"  hello");
    }

    #[test]
    fn trim_all_whitespace_is_empty() {
        assert_eq!(&*trim(b"    "), b"");
        assert_eq!(&*trim_start(b"    "), b"");
        assert_eq!(&*trim_end(b"    "), b"");
        assert_eq!(&*trim(b""), b"");
    }

    #[test]
    fn null_handling() {
        assert_eq!(&*remove_nulls(b"a\0b\0c"), b"abc");
        assert_eq!(&*replace_nulls(b"a\0b\0c"), b"a b c");
        assert_eq!(&*remove_nulls(b"abc"), b"abc");
    }

    #[test]
    fn remove_whitespace_strips_interior_too() {
        assert_eq!(&*remove_whitespace(b" a b\tc\n"), b"abc");
        assert_eq!(&*remove_whitespace(b"nospace"), b"nospace");
    }

    #[test]
    fn compress_whitespace_collapses_runs() {
        assert_eq!(&*compress_whitespace(b"a  b \t\r\n c"), b"a b c");
        assert_eq!(&*compress_whitespace(b"  a  "), b" a ");
        // A lone whitespace byte is still normalized to a space.
        assert_eq!(&*compress_whitespace(b"a\tb\nc"), b"a b c");
        assert_eq!(&*compress_whitespace(b"nospace"), b"nospace");
        assert_eq!(&*compress_whitespace(b""), b"");
    }

    #[test]
    fn compress_whitespace_uses_c_isspace() {
        // Vertical tab and form feed are whitespace for C `isspace`.
        assert_eq!(&*compress_whitespace(b"a\x0b\x0cb"), b"a b");
        // NUL and NBSP (0xA0) are not.
        assert_eq!(&*compress_whitespace(b"a\0\0b"), b"a\0\0b");
        assert_eq!(&*compress_whitespace(b"a\xa0\xa0b"), b"a\xa0\xa0b");
    }

    #[test]
    fn replace_comments_replaces_each_with_one_space() {
        assert_eq!(
            &*replace_comments(b"UN/**/ION/* x */SELECT"),
            b"UN ION SELECT"
        );
        assert_eq!(&*replace_comments(b"a/* 1 *//* 2 */b"), b"a  b");
        assert_eq!(&*replace_comments(b"a/* line\nbreak */b"), b"a b");
        assert_eq!(&*replace_comments(b"no comments"), b"no comments");
        assert_eq!(&*replace_comments(b""), b"");
    }

    #[test]
    fn replace_comments_edge_cases() {
        // Unterminated comment swallows the rest of the input.
        assert_eq!(&*replace_comments(b"a/* b"), b"a ");
        // `/*/` opens a comment but does not close it.
        assert_eq!(&*replace_comments(b"a/*/b"), b"a ");
        // A standalone `*/` is left alone.
        assert_eq!(&*replace_comments(b"a*/b"), b"a*/b");
        // Comments do not nest: the first `*/` closes.
        assert_eq!(&*replace_comments(b"a/* /* */b*/"), b"a b*/");
    }

    #[test]
    fn remove_comments_strips_blocks() {
        assert_eq!(&*remove_comments(b"a/* c */b"), b"ab");
        assert_eq!(&*remove_comments(b"1/**/2"), b"12");
        assert_eq!(&*remove_comments(b"<!--x-->y"), b"y");
        // `--` and `#` truncate to end of input.
        assert_eq!(&*remove_comments(b"abc--def"), b"abc");
        assert_eq!(&*remove_comments(b"abc#def"), b"abc");
        // Unterminated block -> single trailing space.
        assert_eq!(&*remove_comments(b"a/*unterminated"), b"a ");
        // Byte right after a close marker is copied through (here 'z').
        assert_eq!(&*remove_comments(b"/*c*/z/*d*/w"), b"zw");
        assert_eq!(&*remove_comments(b"no comments here"), b"no comments here");
    }

    #[test]
    fn cmd_line_normalises() {
        assert_eq!(&*cmd_line(b"\"C:\\WINDOWS\\cmd.exe\""), b"c:windowscmd.exe");
        assert_eq!(&*cmd_line(b"cat  /etc/passwd"), b"cat/etc/passwd");
        assert_eq!(&*cmd_line(b"n^et u,s,e,r"), b"net u s e r");
        assert_eq!(&*cmd_line(b"echo ('x')"), b"echo(x)");
        assert_eq!(&*cmd_line(b"PING\tlocalhost"), b"ping localhost");
    }

    #[test]
    fn normalize_path_resolves_dots_and_slashes() {
        assert_eq!(&*normalize_path(b"/a//b///c"), b"/a/b/c");
        assert_eq!(&*normalize_path(b"/a/./b"), b"/a/b");
        assert_eq!(&*normalize_path(b"/a/b/../c"), b"/a/c");
        assert_eq!(&*normalize_path(b"/foo/../../etc/passwd"), b"/etc/passwd");
        // Relative path keeps a leading `..` that can't be resolved.
        assert_eq!(&*normalize_path(b"a/../../b"), b"../b");
        assert_eq!(&*normalize_path(b"./a/b"), b"a/b");
        // Trailing slash only preserved if present in input.
        assert_eq!(&*normalize_path(b"/a/b/"), b"/a/b/");
        assert_eq!(&*normalize_path(b"/a/b/."), b"/a/b");
        assert_eq!(&*normalize_path(b""), b"");
    }

    #[test]
    fn normalize_path_win_treats_backslash_as_separator() {
        assert_eq!(&*normalize_path_win(br"c:\a\..\b"), b"c:/b");
        assert_eq!(&*normalize_path_win(br"\a\\b\.\c"), b"/a/b/c");
        // The non-Windows variant leaves backslashes alone.
        assert_eq!(&*normalize_path(br"a\b"), br"a\b");
    }
}
