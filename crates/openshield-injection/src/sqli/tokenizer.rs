//! A tokenizer for the union of SQL dialects an attacker might target.
//!
//! It knows the string, number and comment syntaxes of MySQL, PostgreSQL,
//! SQL Server and Oracle and accepts all of them at once, so that a payload
//! aimed at any engine tokenizes the way that engine would read it.

use super::keywords::KEYWORDS;
use super::token::{Kind, Text, Token};

/// Whether the input is assumed to land inside an SQL string literal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Quote {
    None,
    Single,
    Double,
}

/// Comment syntax: ANSI treats `--x` as a comment and `#` as an operator,
/// MySQL the other way round.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Dialect {
    Ansi,
    Mysql,
}

/// Bytes that end a bare word.
const WORD_END: &[u8] = b" []{}<>:\\?=@!#~+-*/&|^%(),';\t\n\x0b\x0c\r\"\xa0\0";
/// Bytes that end a variable name.
const VARIABLE_END: &[u8] = b" <>:\\?=@!#~+-*/&|^%(),';\t\n\x0b\x0c\r'`\"";

pub struct Tokenizer<'a> {
    input: &'a [u8],
    pos: usize,
    quote: Quote,
    dialect: Dialect,
    /// Tokens produced so far, comments included.
    pub count: usize,
    /// Whether the input had `--x` or `#`, which MySQL reads differently
    /// from ANSI SQL and so warrants a second pass in that dialect.
    pub mysql_hint: bool,
}

impl<'a> Tokenizer<'a> {
    pub fn new(input: &'a [u8], quote: Quote, dialect: Dialect) -> Self {
        Self {
            input,
            pos: 0,
            quote,
            dialect,
            count: 0,
            mysql_hint: false,
        }
    }

    fn byte(&self, at: usize) -> Option<u8> {
        self.input.get(at).copied()
    }

    fn find_bytes(&self, needle: &[u8], from: usize) -> Option<usize> {
        let haystack = self.input.get(from..)?;
        haystack
            .windows(needle.len())
            .position(|w| w == needle)
            .map(|i| from + i)
    }

    fn span_of(&self, from: usize, accept: impl Fn(u8) -> bool) -> usize {
        self.input[from..]
            .iter()
            .take_while(|&&b| accept(b))
            .count()
    }

    fn produce(&mut self, kind: Kind, start: usize, end: usize) -> Token {
        self.pos = end;
        Token::new(kind, start, &self.input[start..end])
    }

    fn next_token(&mut self) -> Option<Token> {
        let delim = match self.quote {
            Quote::Single => Some(b'\''),
            Quote::Double => Some(b'"'),
            Quote::None => None,
        };
        if self.pos == 0
            && let Some(delim) = delim
            && !self.input.is_empty()
        {
            return Some(self.string_body(0, delim, 0));
        }
        while let Some(b) = self.byte(self.pos) {
            let token = match b {
                0..=32 | 127 | 160 => {
                    self.pos += 1;
                    continue;
                }
                b'!' | b'&' | b'*' | b':' | b'<' | b'=' | b'>' | b'|' => self.operator2(),
                b'"' | b'\'' => self.string(),
                b'#' => self.hash(),
                b'$' => self.money(),
                b'%' | b'^' | b'+' | b'~' => self.operator1(),
                b'(' | b')' | b',' | b';' | b'{' | b'}' => {
                    let kind = Kind::punctuation(b).unwrap();
                    self.produce(kind, self.pos, self.pos + 1)
                }
                b'-' => self.dash(),
                b'.' | b'0'..=b'9' => match self.number() {
                    Some(token) => token,
                    None => continue,
                },
                b'/' => self.slash(),
                b'?' | b']' => self.produce(Kind::Unknown, self.pos, self.pos + 1),
                b'@' => self.variable(),
                b'B' | b'b' => self.quoted_literal(|b| matches!(b, b'0' | b'1')),
                b'E' | b'e' => self.escaped_string(),
                b'N' | b'n' => self.national_string(),
                b'Q' | b'q' => self.q_string(0),
                b'U' | b'u' => self.unicode_string(),
                b'X' | b'x' => self.quoted_literal(|b| b.is_ascii_hexdigit()),
                b'[' => self.bracket_word(),
                b'\\' => self.backslash(),
                b'`' => self.tick(),
                _ => self.word(),
            };
            return Some(token);
        }
        None
    }

    fn operator1(&mut self) -> Token {
        self.produce(Kind::Operator, self.pos, self.pos + 1)
    }

    fn operator2(&mut self) -> Token {
        let pos = self.pos;
        let Some(pair) = self.input.get(pos..pos + 2) else {
            return self.operator1();
        };
        if self.input.get(pos..pos + 3) == Some(b"<=>") {
            return self.produce(Kind::Operator, pos, pos + 3);
        }
        if let Some(kind) = lookup(pair) {
            return self.produce(kind, pos, pos + 2);
        }
        if pair[0] == b':' {
            return self.produce(Kind::Colon, pos, pos + 1);
        }
        self.operator1()
    }

    fn eol_comment(&mut self) -> Token {
        let start = self.pos;
        match self.find_bytes(b"\n", start) {
            Some(nl) => {
                let token = self.produce(Kind::Comment, start, nl);
                self.pos = nl + 1;
                token
            }
            None => self.produce(Kind::Comment, start, self.input.len()),
        }
    }

    fn hash(&mut self) -> Token {
        self.mysql_hint = true;
        match self.dialect {
            Dialect::Mysql => self.eol_comment(),
            Dialect::Ansi => self.operator1(),
        }
    }

    fn dash(&mut self) -> Token {
        let pos = self.pos;
        if self.byte(pos + 1) == Some(b'-') {
            let ends_input = pos + 2 == self.input.len();
            if ends_input || self.byte(pos + 2).is_some_and(is_sql_space) {
                return self.eol_comment();
            }
            // `--x` is a comment in ANSI SQL but two minus signs in MySQL.
            if self.dialect == Dialect::Ansi {
                self.mysql_hint = true;
                return self.eol_comment();
            }
        }
        self.operator1()
    }

    fn slash(&mut self) -> Token {
        let pos = self.pos;
        if self.byte(pos + 1) != Some(b'*') {
            return self.operator1();
        }
        let (end, closed) = match self.find_bytes(b"*/", pos + 2) {
            Some(close) => (close + 2, true),
            None => (self.input.len(), false),
        };
        // PostgreSQL nests comments and MySQL executes `/*! */`, so neither
        // can be tokenized consistently.
        let nested = closed && self.input[pos + 2..end - 1].windows(2).any(|w| w == b"/*");
        let kind = if nested || self.byte(pos + 2) == Some(b'!') {
            Kind::Evil
        } else {
            Kind::Comment
        };
        self.produce(kind, pos, end)
    }

    fn backslash(&mut self) -> Token {
        let pos = self.pos;
        // MySQL's `\N` is NULL.
        if self.byte(pos + 1) == Some(b'N') {
            self.produce(Kind::Number, pos, pos + 2)
        } else {
            self.produce(Kind::Backslash, pos, pos + 1)
        }
    }

    fn string(&mut self) -> Token {
        let delim = self.input[self.pos];
        self.string_body(self.pos, delim, 1)
    }

    /// A string whose content starts `offset` bytes after `start`; the
    /// content runs to the first `delim` that is neither backslash-escaped
    /// nor doubled. With `offset` 0 the quote is implied by the context.
    fn string_body(&mut self, start: usize, delim: u8, offset: usize) -> Token {
        let content = start + offset;
        let mut from = content;
        let end = loop {
            let Some(q) = self.input[from..]
                .iter()
                .position(|&b| b == delim)
                .map(|i| from + i)
            else {
                break None;
            };
            let escaped = self.input[content..q]
                .iter()
                .rev()
                .take_while(|&&b| b == b'\\')
                .count()
                % 2
                == 1;
            if escaped {
                from = q + 1;
            } else if self.byte(q + 1) == Some(delim) {
                from = q + 2;
            } else {
                break Some(q);
            }
        };
        let mut token = match end {
            Some(q) => {
                let token = self.produce(Kind::String, content, q);
                self.pos = q + 1;
                token
            }
            None => self.produce(Kind::String, content, self.input.len()),
        };
        token.open = (offset > 0).then_some(delim);
        token.close = end.map(|_| delim);
        token
    }

    /// PostgreSQL `E'...'` and MySQL `N'...'`.
    fn escaped_string(&mut self) -> Token {
        let pos = self.pos;
        if pos + 2 >= self.input.len() || self.byte(pos + 1) != Some(b'\'') {
            return self.word();
        }
        self.string_body(pos, b'\'', 2)
    }

    /// SQL `U&'...'`.
    fn unicode_string(&mut self) -> Token {
        let pos = self.pos;
        if self.input.get(pos + 1..pos + 3) != Some(b"&'") {
            return self.word();
        }
        self.pos = pos + 2;
        let mut token = self.string();
        token.open = Some(b'u');
        if token.close.is_some() {
            token.close = Some(b'u');
        }
        token
    }

    /// Oracle `q'(...)'`, `nq'[...]'` and friends, starting `offset` bytes in.
    fn q_string(&mut self, offset: usize) -> Token {
        let pos = self.pos + offset;
        let is_q = matches!(self.byte(pos), Some(b'q' | b'Q'));
        if !is_q || pos + 2 >= self.input.len() || self.byte(pos + 1) != Some(b'\'') {
            return self.word();
        }
        let opener = self.input[pos + 2];
        if opener < 33 {
            return self.word();
        }
        let closer = match opener {
            b'(' => b')',
            b'[' => b']',
            b'{' => b'}',
            b'<' => b'>',
            other => other,
        };
        let content = pos + 3;
        let end = self.find_bytes(&[closer, b'\''], content);
        let mut token = self.produce(Kind::String, content, end.unwrap_or(self.input.len()));
        if let Some(end) = end {
            self.pos = end + 2;
        }
        token.open = Some(b'q');
        token.close = end.map(|_| b'q');
        token
    }

    fn national_string(&mut self) -> Token {
        let pos = self.pos;
        if pos + 2 < self.input.len() && self.byte(pos + 1) == Some(b'\'') {
            self.escaped_string()
        } else {
            self.q_string(1)
        }
    }

    /// `b'0101'` and `x'DEAD'` literals, which are numbers.
    fn quoted_literal(&mut self, digit: impl Fn(u8) -> bool) -> Token {
        let pos = self.pos;
        if pos + 2 >= self.input.len() || self.byte(pos + 1) != Some(b'\'') {
            return self.word();
        }
        let digits = self.span_of(pos + 2, digit);
        let close = pos + 2 + digits;
        if self.byte(close) != Some(b'\'') {
            return self.word();
        }
        self.produce(Kind::Number, pos, close + 1)
    }

    /// SQL Server `[name]`.
    fn bracket_word(&mut self) -> Token {
        let pos = self.pos;
        let end = self
            .find_bytes(b"]", pos)
            .map_or(self.input.len(), |i| i + 1);
        self.produce(Kind::Bareword, pos, end)
    }

    fn word(&mut self) -> Token {
        let pos = self.pos;
        let len = self.span_of(pos, |b| !WORD_END.contains(&b));
        let word = &self.input[pos..pos + len];
        let mut token = Token::new(Kind::Bareword, pos, word);
        // `SELECT.1` and `SELECT\`x\``: a keyword glued to what follows.
        for (i, &b) in token.text.iter().enumerate() {
            if matches!(b, b'.' | b'`')
                && let Some(kind) = lookup(&word[..i])
                && kind != Kind::Bareword
            {
                return self.produce(kind, pos, pos + i);
            }
        }
        if len < Text::CAPACITY + 1
            && let Some(kind) = lookup(word)
        {
            token.kind = kind;
        }
        self.pos = pos + len;
        token
    }

    /// MySQL backtick quoting: a bare word, unless it names a function.
    fn tick(&mut self) -> Token {
        let mut token = self.string_body(self.pos, b'`', 1);
        token.kind = match lookup(&token.text) {
            Some(Kind::Function) => Kind::Function,
            _ => Kind::Bareword,
        };
        token
    }

    fn variable(&mut self) -> Token {
        let mut pos = self.pos + 1;
        if self.byte(pos) == Some(b'@') {
            pos += 1;
        }
        let ats = (pos - self.pos) as u8;
        let mut token = match self.byte(pos) {
            Some(b'`') => {
                self.pos = pos;
                self.tick()
            }
            Some(b'\'' | b'"') => {
                self.pos = pos;
                self.string()
            }
            _ => {
                let len = self.span_of(pos, |b| !VARIABLE_END.contains(&b));
                self.produce(Kind::Variable, pos, pos + len)
            }
        };
        token.kind = Kind::Variable;
        token.ats = ats;
        token
    }

    /// `$`: money, a PostgreSQL `$tag$...$tag$` string, or noise.
    fn money(&mut self) -> Token {
        let pos = self.pos;
        let len = self.input.len();
        if pos + 1 == len {
            return self.produce(Kind::Bareword, pos, len);
        }
        let digits = self.span_of(pos + 1, |b| b.is_ascii_digit() || matches!(b, b'.' | b','));
        if digits == 1 && self.byte(pos + 1) == Some(b'.') {
            return self.word();
        }
        if digits > 0 {
            return self.produce(Kind::Number, pos, pos + 1 + digits);
        }
        let tag_len = if self.byte(pos + 1) == Some(b'$') {
            0
        } else {
            let letters = self.span_of(pos + 1, |b| b.is_ascii_alphabetic());
            if letters == 0 || self.byte(pos + 1 + letters) != Some(b'$') {
                return self.produce(Kind::Bareword, pos, pos + 1);
            }
            letters
        };
        let tag = &self.input[pos..pos + tag_len + 2];
        let content = pos + tag.len();
        let end = self.find_bytes(tag, content);
        let mut token = self.produce(Kind::String, content, end.unwrap_or(len));
        if let Some(end) = end {
            self.pos = end + tag.len();
        }
        token.open = Some(b'$');
        token.close = end.map(|_| b'$');
        token
    }

    /// Returns `None` for the MySQL `1.e` form, which its parser drops.
    fn number(&mut self) -> Option<Token> {
        let start = self.pos;
        let input = self.input;
        if input[start] == b'0'
            && let Some(radix) = self.byte(start + 1)
        {
            let digit: Option<fn(u8) -> bool> = match radix {
                b'x' | b'X' => Some(|b| b.is_ascii_hexdigit()),
                b'b' | b'B' => Some(|b| matches!(b, b'0' | b'1')),
                _ => None,
            };
            if let Some(digit) = digit {
                let len = self.span_of(start + 2, digit);
                let kind = if len == 0 {
                    Kind::Bareword
                } else {
                    Kind::Number
                };
                return Some(self.produce(kind, start, start + 2 + len));
            }
        }
        let mut pos = start + self.span_of(start, |b| b.is_ascii_digit());
        if self.byte(pos) == Some(b'.') {
            pos += 1;
            pos += self.span_of(pos, |b| b.is_ascii_digit());
            if pos - start == 1 {
                return Some(self.produce(Kind::Dot, start, pos));
            }
        }
        let mut exponent = None;
        if matches!(self.byte(pos), Some(b'e' | b'E')) {
            pos += 1;
            if matches!(self.byte(pos), Some(b'+' | b'-')) {
                pos += 1;
            }
            let digits = self.span_of(pos, |b| b.is_ascii_digit());
            pos += digits;
            exponent = Some(digits > 0);
        }
        // Oracle's float and double suffixes.
        if matches!(self.byte(pos), Some(b'd' | b'D' | b'f' | b'F')) {
            match self.byte(pos + 1) {
                None | Some(b';' | b'u' | b'U') => pos += 1,
                Some(b) if is_sql_space(b) => pos += 1,
                Some(_) => {}
            }
        }
        if exponent == Some(false) {
            self.pos = pos;
            return None;
        }
        Some(self.produce(Kind::Number, start, pos))
    }
}

impl Iterator for Tokenizer<'_> {
    type Item = Token;

    fn next(&mut self) -> Option<Token> {
        let token = self.next_token()?;
        self.count += 1;
        Some(token)
    }
}

/// Whitespace as SQL engines see it, including Oracle's nulls and Latin-1
/// non-breaking spaces.
pub(crate) fn is_sql_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r' | 0xa0 | 0)
}

/// The kind of a keyword, function, type or operator, case-insensitively.
pub(crate) fn lookup(word: &[u8]) -> Option<Kind> {
    lookup_by(|key| {
        key.iter()
            .copied()
            .cmp(word.iter().map(u8::to_ascii_uppercase))
    })
}

/// Looks up `a`, a space and `b` as one phrase, such as `UNION ALL`.
pub(crate) fn lookup_phrase(a: &[u8], b: &[u8]) -> Option<Kind> {
    lookup_by(|key| {
        let phrase = a.iter().chain(b" ").chain(b).map(u8::to_ascii_uppercase);
        key.iter().copied().cmp(phrase)
    })
}

fn lookup_by(compare: impl Fn(&[u8]) -> std::cmp::Ordering) -> Option<Kind> {
    KEYWORDS
        .binary_search_by(|(key, _)| compare(key))
        .ok()
        .map(|i| KEYWORDS[i].1)
}
