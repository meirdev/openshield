//! Tokens of the SQL tokenizer.

use std::fmt;
use std::ops::Deref;

/// What a token is, in libinjection's taxonomy. Each kind has a one-byte
/// symbol; a fingerprint is the symbols of the folded tokens in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    Keyword,
    Union,
    Group,
    Expression,
    SqlType,
    Function,
    Bareword,
    Number,
    Variable,
    String,
    Operator,
    LogicOperator,
    Comment,
    Collate,
    LeftParens,
    RightParens,
    LeftBrace,
    RightBrace,
    Dot,
    Comma,
    Colon,
    Semicolon,
    Tsql,
    Unknown,
    /// Syntax that cannot be tokenized reliably, such as nested comments.
    /// Any fingerprint containing it collapses to just this kind.
    Evil,
    Backslash,
}

impl Kind {
    pub const fn symbol(self) -> u8 {
        match self {
            Kind::Keyword => b'k',
            Kind::Union => b'U',
            Kind::Group => b'B',
            Kind::Expression => b'E',
            Kind::SqlType => b't',
            Kind::Function => b'f',
            Kind::Bareword => b'n',
            Kind::Number => b'1',
            Kind::Variable => b'v',
            Kind::String => b's',
            Kind::Operator => b'o',
            Kind::LogicOperator => b'&',
            Kind::Comment => b'c',
            Kind::Collate => b'A',
            Kind::LeftParens => b'(',
            Kind::RightParens => b')',
            Kind::LeftBrace => b'{',
            Kind::RightBrace => b'}',
            Kind::Dot => b'.',
            Kind::Comma => b',',
            Kind::Colon => b':',
            Kind::Semicolon => b';',
            Kind::Tsql => b'T',
            Kind::Unknown => b'?',
            Kind::Evil => b'X',
            Kind::Backslash => b'\\',
        }
    }

    /// The kind of a single punctuation byte that is its own token.
    pub(crate) const fn punctuation(b: u8) -> Option<Kind> {
        Some(match b {
            b'(' => Kind::LeftParens,
            b')' => Kind::RightParens,
            b'{' => Kind::LeftBrace,
            b'}' => Kind::RightBrace,
            b',' => Kind::Comma,
            b';' => Kind::Semicolon,
            _ => return None,
        })
    }
}

/// A token's text, capped at the length libinjection keeps. Longer tokens
/// are truncated, which matters only for display and for keyword lookup,
/// where nothing that long is a keyword.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Text {
    len: u8,
    bytes: [u8; Text::CAPACITY],
}

impl Text {
    pub const CAPACITY: usize = 31;

    pub fn new(bytes: &[u8]) -> Self {
        let len = bytes.len().min(Self::CAPACITY);
        let mut buf = [0; Self::CAPACITY];
        buf[..len].copy_from_slice(&bytes[..len]);
        Self {
            len: len as u8,
            bytes: buf,
        }
    }

    /// `a`, a space and `b`, if that fits.
    pub fn joined(a: &[u8], b: &[u8]) -> Option<Self> {
        let len = a.len() + 1 + b.len();
        if len > Self::CAPACITY {
            return None;
        }
        let mut buf = [0; Self::CAPACITY];
        buf[..a.len()].copy_from_slice(a);
        buf[a.len()] = b' ';
        buf[a.len() + 1..len].copy_from_slice(b);
        Some(Self {
            len: len as u8,
            bytes: buf,
        })
    }
}

impl Deref for Text {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

impl fmt::Debug for Text {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", String::from_utf8_lossy(self))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Token {
    pub kind: Kind,
    /// Offset of the text in the input. For strings this is the content,
    /// after the opening quote.
    pub pos: usize,
    pub text: Text,
    /// The opening delimiter of a string, when one was present.
    pub open: Option<u8>,
    /// The closing delimiter of a string, when one was found.
    pub close: Option<u8>,
    /// How many `@` prefixed a variable.
    pub ats: u8,
}

impl Token {
    pub(crate) fn new(kind: Kind, pos: usize, text: &[u8]) -> Self {
        Self {
            kind,
            pos,
            text: Text::new(text),
            open: None,
            close: None,
            ats: 0,
        }
    }

    pub fn is_unary_op(&self) -> bool {
        self.kind == Kind::Operator
            && match &*self.text {
                [b'+' | b'-' | b'!' | b'~'] => true,
                b"!!" => true,
                word => word.eq_ignore_ascii_case(b"NOT"),
            }
    }

    pub fn is_arithmetic_op(&self) -> bool {
        self.kind == Kind::Operator && matches!(&*self.text, [b'*' | b'/' | b'-' | b'+' | b'%'])
    }

    pub fn text_is(&self, upper: &[u8]) -> bool {
        self.text.eq_ignore_ascii_case(upper)
    }
}
