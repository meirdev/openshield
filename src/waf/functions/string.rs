use wirefilter_engine::{FunctionArgs, LhsValue};

/// C `isspace`: space, tab, newline, vertical tab, form feed, carriage return.
fn is_c_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

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

/// Decode JavaScript backslash escapes (ModSecurity `t:jsDecode`).
///
/// Handles `\uHHHH`, `\xHH`, octal `\OOO`, the C escapes `\a \b \f \n \r \t
/// \v`, and a bare `\C` which just drops the backslash. Matches ModSecurity's
/// byte-level behaviour, including its quirks: `\uHHHH` keeps only the low
/// byte, full-width ASCII (`\uffXX`, low byte `0x01..=0x5e`) is folded to ASCII
/// by adding `0x20`, and a 3-digit octal that would exceed one byte falls back
/// to 2 digits.
pub fn js_decode(input: &[u8]) -> Vec<u8> {
    fn hex_val(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }
    let hex2 = |hi: u8, lo: u8| (hex_val(hi).unwrap() << 4) | hex_val(lo).unwrap();
    let is_hex = |c: u8| hex_val(c).is_some();
    let is_odigit = |c: u8| (b'0'..=b'7').contains(&c);

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
            [b'u', h0, h1, h2, h3, ..] if [*h0, *h1, *h2, *h3].iter().all(|&c| is_hex(c)) => {
                let mut b = hex2(*h2, *h3);
                if b > 0x00 && b < 0x5f && (*h0 | 0x20) == b'f' && (*h1 | 0x20) == b'f' {
                    b += 0x20;
                }
                out.push(b);
                i += 6;
            }
            // \xHH
            [b'x', h0, h1, ..] if is_hex(*h0) && is_hex(*h1) => {
                out.push(hex2(*h0, *h1));
                i += 4;
            }
            // \OOO octal, one byte (\000 - \377)
            [d0, ..] if is_odigit(*d0) => {
                let mut digits = 1;
                while digits < 3 && rest.get(digits).is_some_and(|&c| is_odigit(c)) {
                    digits += 1;
                }
                // Don't use 3 digits if the value would exceed one byte.
                if digits == 3 && rest[0] > b'3' {
                    digits = 2;
                }
                let val = rest[..digits]
                    .iter()
                    .fold(0u32, |acc, &c| acc * 8 + u32::from(c - b'0'));
                out.push(val as u8);
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
            // Trailing lone backslash: copy the rest verbatim.
            [] => {
                out.push(b'\\');
                i += 1;
            }
        }
    }
    out
}

/// Normalise a filesystem path (ModSecurity `t:normalizePath`): collapse `//`,
/// resolve `.` and `..` segments, and drop a trailing slash that was not in the
/// input. `win` also treats `\` as a separator (`t:normalizePathWin`).
///
/// Faithful port of ModSecurity's `normalize_path_inplace`, index-based instead
/// of pointer-based; `src`/`dst` are signed so the back-reference arithmetic
/// matches the original (which lets `dst` go before the start, then clamps).
fn normalize_path(input: &[u8], win: bool) -> Vec<u8> {
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
                // Empty segment; fall through to the copy step, which collapses it.
            } else if buf[s] == b'.' {
                if dst > 0 && buf[(dst - 1) as usize] == b'.' {
                    // Back-reference "..".
                    if relative && (hitroot || (dst - 2) <= 0) {
                        // Can't go above root; fall through and copy the backref.
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
                // A '.' inside a segment (e.g. "a.") falls through to copy.
            } else if dst > 0 {
                hitroot = false;
            }
        }

        if !skip_copy {
            // Copy step: collapse consecutive separators.
            if buf[src as usize] == b'/' {
                let oldsrc = src;
                while src < end && is_sep(buf[(src + 1) as usize]) {
                    src += 1;
                }
                let _ = oldsrc;
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

/// ModSecurity `t:normalizePath`.
pub fn normalize_path_transform(input: &[u8]) -> Vec<u8> {
    normalize_path(input, false)
}

/// ModSecurity `t:normalizePathWin` (also treats `\` as a separator).
pub fn normalize_path_win(input: &[u8]) -> Vec<u8> {
    normalize_path(input, true)
}

/// Collapse each run of whitespace into a single space (ModSecurity
/// `t:compressWhitespace`).
pub fn compress_whitespace(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut in_ws = false;
    for &c in input {
        if is_c_space(c) {
            if !in_ws {
                in_ws = true;
                out.push(b' ');
            }
        } else {
            in_ws = false;
            out.push(c);
        }
    }
    out
}

/// Replace each `/* ... */` comment with a single space (ModSecurity
/// `t:replaceComments`). Unterminated comments also become one space.
pub fn replace_comments(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    let mut in_comment = false;
    while i < input.len() {
        if !in_comment {
            if input[i..].starts_with(b"/*") {
                in_comment = true;
                i += 2;
            } else {
                out.push(input[i]);
                i += 1;
            }
        } else if input[i..].starts_with(b"*/") {
            in_comment = false;
            i += 2;
            out.push(b' ');
        } else {
            i += 1;
        }
    }
    if in_comment {
        out.push(b' ');
    }
    out
}

/// Decode ANSI-C escape sequences (ModSecurity `t:escapeSeqDecode`).
///
/// Handles `\a \b \f \n \r \t \v \\ \? \' \"`, `\xHH`, and octal `\OOO`
/// (up to three digits, truncated to one byte). An unrecognised `\C` keeps `C`.
pub fn escape_seq_decode(input: &[u8]) -> Vec<u8> {
    fn is_hex(c: u8) -> bool {
        c.is_ascii_hexdigit()
    }
    fn hex_val(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => c - b'A' + 10,
        }
    }
    let is_odigit = |c: u8| (b'0'..=b'7').contains(&c);

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
            b'\\' => Some(b'\\'),
            b'?' => Some(b'?'),
            b'\'' => Some(b'\''),
            b'"' => Some(b'"'),
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
            && is_hex(input[i + 2])
            && is_hex(input[i + 3])
        {
            out.push((hex_val(input[i + 2]) << 4) | hex_val(input[i + 3]));
            i += 4;
            continue;
        }
        // Octal \OOO (1-3 digits, one byte).
        if is_odigit(next) {
            let mut digits = 1;
            while digits < 3 && input.get(i + 1 + digits).is_some_and(|&c| is_odigit(c)) {
                digits += 1;
            }
            let val = input[i + 1..i + 1 + digits]
                .iter()
                .fold(0u32, |acc, &c| acc * 8 + u32::from(c - b'0'));
            out.push(val as u8);
            i += 1 + digits;
            continue;
        }
        // Unrecognised escape: drop the backslash, keep the char.
        out.push(next);
        i += 2;
    }
    out
}

/// Decode CSS escapes (ModSecurity `t:cssDecode`).
///
/// A backslash starts an escape: 1–6 hex digits decode to a byte (only the last
/// two hex digits are used; a single trailing whitespace is then consumed), a
/// backslash-newline is a line continuation and drops both bytes, and any other
/// `\C` keeps `C` verbatim. Matches ModSecurity's quirks, including the
/// full-width ASCII fold (`\ff41` → `a`) for the 4/5/6-digit `00ffXX` forms.
pub fn css_decode(input: &[u8]) -> Vec<u8> {
    fn hex_val(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }
    // C's isspace(): space, tab, newline, vertical tab, form feed, carriage return.
    let is_space = |c: u8| matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r');

    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] != b'\\' {
            out.push(input[i]);
            i += 1;
            continue;
        }
        // Backslash. Drop it and look at what follows.
        if i + 1 >= input.len() {
            i += 1; // trailing backslash: continuation to nothing
            continue;
        }
        i += 1;
        let hex = &input[i..];
        let j = hex.iter().take(6).take_while(|&&c| hex_val(c).is_some()).count();

        if j == 0 {
            if input[i] == b'\n' {
                i += 1; // backslash-newline line continuation
            } else {
                out.push(input[i]); // \C -> C
                i += 1;
            }
            continue;
        }

        // Byte value: single digit for j==1, else the last two hex digits.
        let mut byte = if j == 1 {
            hex_val(hex[0]).unwrap()
        } else {
            (hex_val(hex[j - 2]).unwrap() << 4) | hex_val(hex[j - 1]).unwrap()
        };

        // Full-width ASCII fold applies to the 00ffXX forms (j 4/5/6 with the
        // leading digits zero), when the two hex digits before the last two are
        // `ff`.
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

/// Normalise an obfuscated command line (ModSecurity `t:cmdLine`).
///
/// Deletes `" ' \ ^`, collapses runs of `` , ; \t \r \n`` and space into a
/// single space, drops the space immediately before `/` or `(`, and
/// lowercases everything else.
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

/// Strip C/HTML/SQL/shell comments (ModSecurity `t:removeComments`).
///
/// Removes `/* ... */` and `<!-- ... -->` blocks, and truncates at the first
/// `--` or `#`. Faithful to ModSecurity's quirks: the byte immediately after a
/// closing `*/`/`-->` is copied through, and an unterminated block becomes a
/// single trailing space.
pub fn remove_comments(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    let n = input.len();
    let mut in_comment = false;
    while i < n {
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
    fn js_decode_escapes() {
        // \xHH, \uHHHH (low byte), named and generic escapes.
        assert_eq!(js_decode(br"\x41\x42"), b"AB");
        assert_eq!(js_decode(br"\u0041"), b"A");
        assert_eq!(js_decode(br"a\tb\nc"), b"a\tb\nc");
        assert_eq!(js_decode(br"\a\b\f\v"), &[0x07, 0x08, 0x0c, 0x0b]);
        assert_eq!(js_decode(br#"\"\\\'\q"#), br#""\'q"#); // backslash dropped
        // Full-width ASCII \uffXX folds to ASCII: \uff41 -> 'a', \uFF21 -> 'A'.
        assert_eq!(js_decode(br"\uff41\uFF21"), b"aA");
        // \uff00 low byte 0x00 is left alone (not folded).
        assert_eq!(js_decode(br"\uff00"), &[0x00]);
        // Octal: \101 -> 'A'; \412 truncates to \41 ('!') + literal '2'.
        assert_eq!(js_decode(br"\101"), b"A");
        assert_eq!(js_decode(br"\412"), b"!2");
        // Incomplete escapes at the end are copied verbatim.
        assert_eq!(js_decode(br"ab\"), b"ab\\");
        // Incomplete \xH falls through to the generic \C case: backslash dropped.
        assert_eq!(js_decode(br"\x4"), b"x4");
        // No escapes: unchanged.
        assert_eq!(js_decode(b"plain text"), b"plain text");
    }

    #[test]
    fn compress_whitespace_collapses_runs() {
        assert_eq!(compress_whitespace(b"a   b\t\n c"), b"a b c");
        assert_eq!(compress_whitespace(b"  lead"), b" lead");
        assert_eq!(compress_whitespace(b"none"), b"none");
    }

    #[test]
    fn replace_comments_become_space() {
        assert_eq!(replace_comments(b"a/*x*/b"), b"a b");
        assert_eq!(replace_comments(b"1/**/2"), b"1 2");
        assert_eq!(replace_comments(b"un/*terminated"), b"un ");
        assert_eq!(replace_comments(b"no comment"), b"no comment");
    }

    #[test]
    fn escape_seq_decode_ansi_c() {
        assert_eq!(escape_seq_decode(br"\n\t\r"), b"\n\t\r");
        assert_eq!(escape_seq_decode(br"\x41\x42"), b"AB");
        assert_eq!(escape_seq_decode(br"\101"), b"A"); // octal
        assert_eq!(escape_seq_decode(br"\777"), &[0xff]); // octal truncates to a byte
        assert_eq!(escape_seq_decode(br#"\\\?\'\""#), br#"\?'""#);
        assert_eq!(escape_seq_decode(br"\z"), b"z"); // unknown -> drop backslash
        assert_eq!(escape_seq_decode(br"\xG1"), b"xG1"); // invalid hex -> keep 'x'
        assert_eq!(escape_seq_decode(b"plain"), b"plain");
    }

    #[test]
    fn normalize_path_resolves_dots_and_slashes() {
        // Collapse duplicate slashes.
        assert_eq!(normalize_path_transform(b"/a//b///c"), b"/a/b/c");
        // Resolve self-references.
        assert_eq!(normalize_path_transform(b"/a/./b"), b"/a/b");
        // Resolve back-references.
        assert_eq!(normalize_path_transform(b"/a/b/../c"), b"/a/c");
        assert_eq!(normalize_path_transform(b"/foo/../../etc/passwd"), b"/etc/passwd");
        // Relative path keeps a leading `..` that can't be resolved.
        assert_eq!(normalize_path_transform(b"a/../../b"), b"../b");
        // Trailing slash only preserved if present in input.
        assert_eq!(normalize_path_transform(b"/a/b/"), b"/a/b/");
        assert_eq!(normalize_path_transform(b"/a/b/."), b"/a/b");
    }

    #[test]
    fn normalize_path_win_treats_backslash_as_separator() {
        assert_eq!(normalize_path_win(br"c:\a\..\b"), b"c:/b");
        assert_eq!(normalize_path_win(br"\a\\b\.\c"), b"/a/b/c");
        // Forward version leaves backslashes alone.
        assert_eq!(normalize_path_transform(br"a\b"), br"a\b");
    }

    #[test]
    fn css_decode_escapes() {
        // 1-6 hex digits, last two used; single trailing whitespace consumed.
        assert_eq!(css_decode(br"\41"), b"A"); // \41 -> 'A'
        assert_eq!(css_decode(br"\41 B"), b"AB"); // trailing space eaten
        assert_eq!(css_decode(br"\000041"), b"A"); // 6 digits, last two
        assert_eq!(css_decode(br"\4"), &[0x04]); // single hex digit
        // Full-width fold: \ff41 -> 'a', \0000ff21 not valid (7); \00ff21 -> 'A'.
        assert_eq!(css_decode(br"\ff41"), b"a");
        assert_eq!(css_decode(br"\00ff21"), b"A"); // 0xff21 -> low 0x21 +0x20 -> 'A'
        assert_eq!(css_decode(br"\0ff41"), b"a"); // 5-digit fold
        // Non-hex \C keeps C; backslash-newline is a line continuation.
        assert_eq!(css_decode(br"\."), b".");
        assert_eq!(css_decode(b"a\\\nb"), b"ab");
        // Classic CSS-obfuscated "javascript" fragment decodes to ASCII.
        assert_eq!(css_decode(br"\6a\61va"), b"java");
        // Trailing lone backslash is dropped.
        assert_eq!(css_decode(br"ab\"), b"ab");
        assert_eq!(css_decode(b"no escapes"), b"no escapes");
    }

    #[test]
    fn cmd_line_normalises() {
        // Delete quotes/backslash/caret, lowercase, collapse space, drop space
        // before '/' and '('.
        assert_eq!(cmd_line(b"\"C:\\WINDOWS\\cmd.exe\""), b"c:windowscmd.exe");
        assert_eq!(cmd_line(b"cat  /etc/passwd"), b"cat/etc/passwd");
        assert_eq!(cmd_line(b"n^et u,s,e,r"), b"net u s e r");
        assert_eq!(cmd_line(b"echo ('x')"), b"echo(x)");
        assert_eq!(cmd_line(b"PING\tlocalhost"), b"ping localhost");
    }

    #[test]
    fn remove_comments_strips_blocks() {
        assert_eq!(remove_comments(b"a/* c */b"), b"ab");
        assert_eq!(remove_comments(b"1/**/2"), b"12");
        assert_eq!(remove_comments(b"<!--x-->y"), b"y");
        // `--` and `#` truncate to end of input (no trailing space kept).
        assert_eq!(remove_comments(b"abc--def"), b"abc");
        assert_eq!(remove_comments(b"abc#def"), b"abc");
        // Unterminated block -> single trailing space.
        assert_eq!(remove_comments(b"a/*unterminated"), b"a ");
        // Byte right after a close marker is copied through (here 'z').
        assert_eq!(remove_comments(b"/*c*/z/*d*/w"), b"zw");
        assert_eq!(remove_comments(b"no comments here"), b"no comments here");
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
