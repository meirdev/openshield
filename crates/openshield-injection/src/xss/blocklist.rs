//! What counts as dangerous once markup is recognized: tag names that load
//! or run code, attributes that take scripts, URLs or styles, and the URL
//! schemes and style constructs that execute.

use std::cmp::Ordering;

use super::entities;
use super::events::EVENT_HANDLERS;
use super::tokenizer::is_space;

/// Tags that execute, load or redefine content by themselves.
const TAGS: &[&[u8]] = &[
    b"applet",
    b"base",
    b"comment",
    b"embed",
    b"frame",
    b"frameset",
    b"handler",
    b"iframe",
    b"import",
    b"isindex",
    b"link",
    b"listener",
    b"meta",
    b"noscript",
    b"object",
    b"script",
    b"style",
    b"vmlframe",
    b"xml",
    b"xss",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttrKind {
    /// The value runs as script, or the attribute is dangerous whatever the
    /// value.
    Script,
    /// The value is a URL, dangerous if it has an executable scheme.
    Url,
    /// The value is a form submission URL: dangerous if executable, or if it
    /// points at another origin (dangling markup exfiltration).
    FormTarget,
    /// The value is CSS, dangerous if it uses executable constructs.
    Style,
    /// The value names another attribute (SVG `attributeName`).
    IndirectName,
}

const ATTRS: &[(&[u8], AttrKind)] = &[
    (b"action", AttrKind::FormTarget),
    (b"attributename", AttrKind::IndirectName),
    (b"background", AttrKind::Url),
    (b"by", AttrKind::Url),
    (b"data", AttrKind::Url),
    (b"dataformatas", AttrKind::Script),
    (b"datasrc", AttrKind::Script),
    (b"dynsrc", AttrKind::Url),
    (b"filter", AttrKind::Style),
    (b"folder", AttrKind::Url),
    (b"formaction", AttrKind::FormTarget),
    (b"from", AttrKind::Url),
    (b"handler", AttrKind::Url),
    (b"href", AttrKind::Url),
    (b"lowsrc", AttrKind::Url),
    (b"poster", AttrKind::Url),
    (b"src", AttrKind::Url),
    (b"srcdoc", AttrKind::Script),
    (b"style", AttrKind::Style),
    (b"to", AttrKind::Url),
    (b"values", AttrKind::Url),
    (b"xlink:href", AttrKind::Url),
];

const SCHEMES: &[&[u8]] = &[b"data", b"javascript", b"vbscript", b"view-source"];

/// Style constructs that ran code in some browser, matched after whitespace
/// and comments are stripped.
const STYLE_NEEDLES: &[&[u8]] = &[
    b"@import",
    b"behavior:",
    b"behaviour:",
    b"binding:",
    b"expression(",
    b"javascript:",
    b"vbscript:",
];

/// The bytes of a name as the lookup tables spell them: lowercase, without
/// the nulls IE ignored inside names.
fn letters(name: &[u8]) -> impl Iterator<Item = u8> + '_ {
    name.iter().filter(|&&b| b != 0).map(u8::to_ascii_lowercase)
}

/// Orders a lowercase table entry against a raw name, for binary search.
fn compare(entry: &[u8], name: &[u8]) -> Ordering {
    entry.iter().copied().cmp(letters(name))
}

fn has_prefix(name: &[u8], prefix: &[u8]) -> bool {
    letters(name).take(prefix.len()).eq(prefix.iter().copied())
}

/// Drops the leading `prefix` from a raw name, nulls included.
fn strip_prefix<'a>(name: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    if !has_prefix(name, prefix) {
        return None;
    }
    let mut remaining = prefix.len();
    let end = name.iter().position(|&b| {
        if b != 0 {
            remaining -= 1;
        }
        remaining == 0
    })?;
    Some(&name[end + 1..])
}

pub fn is_dangerous_tag(name: &[u8]) -> bool {
    letters(name).nth(2).is_some()
        && (TAGS.binary_search_by(|tag| compare(tag, name)).is_ok()
            || has_prefix(name, b"svg")
            || has_prefix(name, b"xsl"))
}

pub fn classify_attr(name: &[u8]) -> Option<AttrKind> {
    letters(name).nth(1)?;
    if letters(name).nth(4).is_some() {
        if let Some(event) = strip_prefix(name, b"on")
            && EVENT_HANDLERS
                .binary_search_by(|handler| compare(handler, event))
                .is_ok()
        {
            return Some(AttrKind::Script);
        }
        // Namespace declarations let a payload redefine what any tag means.
        if has_prefix(name, b"xmlns") || has_prefix(name, b"xlink") {
            return Some(AttrKind::Script);
        }
    }
    ATTRS
        .binary_search_by(|(attr, _)| compare(attr, name))
        .ok()
        .map(|i| ATTRS[i].1)
}

/// The executable scheme `value` starts with, after the decoding and
/// stripping a browser's URL parser applies.
pub fn dangerous_scheme(value: &[u8]) -> Option<&'static [u8]> {
    let mut scheme = [0; 16];
    let scheme = url_scheme(value, &mut scheme)?;
    SCHEMES.binary_search(&scheme).ok().map(|i| SCHEMES[i])
}

/// Whether an unclosed URL value is set up to exfiltrate the markup that
/// follows it: it points at another origin and ends inside the query
/// string, so the swallowed page content becomes a parameter.
pub fn is_dangling_exfiltration(value: &[u8]) -> bool {
    let trimmed = value.trim_ascii_end();
    trimmed
        .last()
        .is_some_and(|b| matches!(b, b'?' | b'&' | b'='))
        && is_cross_origin(trimmed)
}

/// Whether a form would submit `value` to another origin: an absolute URL
/// or a scheme-relative one.
pub fn is_cross_origin(value: &[u8]) -> bool {
    let mut scheme = [0; 16];
    let mut chars = url_chars(value);
    if chars.next() == Some('/' as u32) && chars.next() == Some('/' as u32) {
        return true;
    }
    url_scheme(value, &mut scheme).is_some()
}

/// The code points of `value` as a URL parser sees them: references
/// decoded, control characters dropped, leading whitespace stripped. Old
/// browsers also ignored nulls inside references, so those go first.
fn url_chars(value: &[u8]) -> impl Iterator<Item = u32> + '_ {
    let without_nulls: std::borrow::Cow<'_, [u8]> = if value.contains(&0) {
        value.iter().copied().filter(|&b| b != 0).collect()
    } else {
        value.into()
    };
    let mut pos = 0;
    std::iter::from_fn(move || {
        let rest = without_nulls.get(pos..).filter(|rest| !rest.is_empty())?;
        let (cp, len) = entities::decode_char(rest);
        pos += len;
        Some(cp)
    })
    .filter(|&c| c >= 0x20)
    .skip_while(|&c| c == 0x20 || c >= 0x7f)
}

/// The lowercased scheme of `value`, if it has one.
fn url_scheme<'b>(value: &[u8], buf: &'b mut [u8; 16]) -> Option<&'b [u8]> {
    for (n, c) in url_chars(value).enumerate() {
        if c == ':' as u32 {
            return (n > 0).then_some(&buf[..n]);
        }
        let b = u8::try_from(c).ok()?;
        if !(b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.')) {
            return None;
        }
        *buf.get_mut(n)? = b.to_ascii_lowercase();
    }
    None
}

/// The executable construct an inline style contains, if any. HTML
/// references, CSS escapes, comments and whitespace are all undone first,
/// since every one of them has been used to hide `expression(`.
pub fn dangerous_style(value: &[u8]) -> Option<&'static [u8]> {
    let mut css = Vec::with_capacity(value.len());
    let mut chars = entities::decode(value).peekable();
    while let Some(c) = chars.next() {
        let c = match c {
            0x2f if chars.peek() == Some(&0x2a) => {
                skip_css_comment(&mut chars);
                continue;
            }
            0x5c => decode_css_escape(&mut chars),
            c => c,
        };
        match u8::try_from(c) {
            Ok(b) if b == 0 || is_space(b) => {}
            Ok(b) if b.is_ascii() => css.push(b.to_ascii_lowercase()),
            _ => css.push(b'?'),
        }
    }
    STYLE_NEEDLES
        .iter()
        .find(|needle| css.windows(needle.len()).any(|w| &w == *needle))
        .copied()
}

fn skip_css_comment(chars: &mut std::iter::Peekable<impl Iterator<Item = u32>>) {
    chars.next();
    let mut prev = 0;
    for c in chars.by_ref() {
        if prev == 0x2a && c == 0x2f {
            return;
        }
        prev = c;
    }
}

/// Decodes what follows a backslash: up to six hex digits and an optional
/// space, or a single literally-escaped character.
fn decode_css_escape(chars: &mut std::iter::Peekable<impl Iterator<Item = u32>>) -> u32 {
    let hex = |c: u32| char::from_u32(c).and_then(|c| c.to_digit(16));
    let mut value = 0;
    let mut digits = 0;
    while digits < 6
        && let Some(d) = chars.peek().copied().and_then(hex)
    {
        value = value * 16 + d;
        digits += 1;
        chars.next();
    }
    if digits > 0 {
        if chars.peek().is_some_and(|&c| c == 0x20) {
            chars.next();
        }
        return value;
    }
    chars.next().unwrap_or(0x5c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tables_are_sorted_for_binary_search() {
        assert!(TAGS.windows(2).all(|w| w[0] < w[1]));
        assert!(ATTRS.windows(2).all(|w| w[0].0 < w[1].0));
        assert!(SCHEMES.windows(2).all(|w| w[0] < w[1]));
        assert!(EVENT_HANDLERS.windows(2).all(|w| w[0] < w[1]));
    }

    #[test]
    fn tag_names_ignore_case_and_nulls() {
        assert!(is_dangerous_tag(b"SCRIPT"));
        assert!(is_dangerous_tag(b"scr\0ipt"));
        assert!(is_dangerous_tag(b"svg"));
        assert!(is_dangerous_tag(b"svgfoo"));
        assert!(!is_dangerous_tag(b"div"));
        assert!(!is_dangerous_tag(b"b"));
    }

    #[test]
    fn attribute_kinds() {
        assert_eq!(classify_attr(b"onerror"), Some(AttrKind::Script));
        assert_eq!(classify_attr(b"ONLOAD"), Some(AttrKind::Script));
        assert_eq!(classify_attr(b"o\0n\0load"), Some(AttrKind::Script));
        assert_eq!(classify_attr(b"on"), None);
        assert_eq!(classify_attr(b"onload\0"), Some(AttrKind::Script));
        assert_eq!(classify_attr(b"onion"), None);
        assert_eq!(classify_attr(b"online"), None);
        assert_eq!(classify_attr(b"href"), Some(AttrKind::Url));
        assert_eq!(classify_attr(b"style"), Some(AttrKind::Style));
        assert_eq!(classify_attr(b"xmlns:xlink"), Some(AttrKind::Script));
        assert_eq!(classify_attr(b"class"), None);
    }

    #[test]
    fn schemes_survive_encoding_tricks() {
        assert_eq!(
            dangerous_scheme(b"javascript:alert(1)"),
            Some(&b"javascript"[..])
        );
        assert_eq!(
            dangerous_scheme(b"  JaVaScRiPt:alert(1)"),
            Some(&b"javascript"[..])
        );
        assert_eq!(
            dangerous_scheme(b"java\tscript\n:alert(1)"),
            Some(&b"javascript"[..])
        );
        assert_eq!(
            dangerous_scheme(b"&#106;ava&Tab;script&colon;x"),
            Some(&b"javascript"[..])
        );
        assert_eq!(
            dangerous_scheme(b"javascript&\0colon\0;x"),
            Some(&b"javascript"[..])
        );
        assert_eq!(
            dangerous_scheme(b"\x01javascript:x"),
            Some(&b"javascript"[..])
        );
        assert_eq!(
            dangerous_scheme(b"javas\x01cript:x"),
            Some(&b"javascript"[..])
        );
        assert_eq!(dangerous_scheme(b"data:text/html,x"), Some(&b"data"[..]));
        assert_eq!(dangerous_scheme(b"https://example.com"), None);
        assert_eq!(dangerous_scheme(b"database.html"), None);
        assert_eq!(dangerous_scheme(b"javascript"), None);
        assert_eq!(dangerous_scheme(b"/path?x=javascript:y"), None);
    }

    #[test]
    fn dangling_exfiltration() {
        assert!(is_dangling_exfiltration(b"//evil.example?"));
        assert!(is_dangling_exfiltration(b"https://evil.example/log?x="));
        assert!(!is_dangling_exfiltration(b"https://example.com/a.png"));
        assert!(!is_dangling_exfiltration(b"/local?"));
        assert!(!is_dangling_exfiltration(b"HTTP:/WWW.EXAMPLE.COM"));
    }

    #[test]
    fn form_targets() {
        assert!(is_cross_origin(b"//evil.example"));
        assert!(is_cross_origin(b"https://evil.example/collect"));
        assert!(is_cross_origin(b"  HTTPS://evil.example"));
        assert!(!is_cross_origin(b"/submit"));
        assert!(!is_cross_origin(b"submit.php?x=1"));
        assert!(!is_cross_origin(b"#"));
        assert!(!is_cross_origin(b""));
    }

    #[test]
    fn styles_need_an_executable_construct() {
        assert_eq!(dangerous_style(b"color: red"), None);
        assert_eq!(dangerous_style(b"background:url(/x.png)"), None);
        assert_eq!(
            dangerous_style(b"width: expression(alert(1))"),
            Some(&b"expression("[..])
        );
        assert_eq!(
            dangerous_style(b"x:exp/* */ression (1)"),
            Some(&b"expression("[..])
        );
        assert_eq!(
            dangerous_style(b"background:url(javascript:alert(1))"),
            Some(&b"javascript:"[..])
        );
        assert_eq!(
            dangerous_style(b"behavior: url(x.htc)"),
            Some(&b"behavior:"[..])
        );
        assert_eq!(
            dangerous_style(b"x:expression\\28write(1)\\29"),
            Some(&b"expression("[..])
        );
        assert_eq!(
            dangerous_style(
                b"background-image:\\0075\\0072\\006C\\0028'\\006a\\0061vascript:alert(1)')"
            ),
            Some(&b"javascript:"[..])
        );
        assert_eq!(dangerous_style(b"content: '\\\\'"), None);
    }
}
