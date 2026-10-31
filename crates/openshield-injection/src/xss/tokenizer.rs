//! A permissive HTML tokenizer.
//!
//! It follows the HTML5 tokenizer states, but where browsers have disagreed
//! it accepts every reading: nulls inside names, IE's extra whitespace
//! characters, backtick-quoted values and `<% %>` comments all tokenize the
//! way the most lenient browser treated them. The aim is to recognize markup
//! an attacker could get some browser to execute, not to render it.
//!
//! Tokens borrow from the input and no state is allocated, so a scan is a
//! single pass over the bytes.

/// Where the scanned bytes would land if a page reflected them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Context {
    /// Between tags: `<p>HERE</p>`.
    Text,
    /// An unquoted attribute value: `<a title=HERE>`.
    UnquotedAttribute,
    /// `<a title='HERE'>`.
    SingleQuotedAttribute,
    /// `<a title="HERE">`.
    DoubleQuotedAttribute,
    /// `` <a title=`HERE`> ``, which IE accepted.
    BacktickAttribute,
}

impl Context {
    pub const ALL: [Context; 5] = [
        Context::Text,
        Context::UnquotedAttribute,
        Context::SingleQuotedAttribute,
        Context::DoubleQuotedAttribute,
        Context::BacktickAttribute,
    ];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Token<'a> {
    Text(&'a [u8]),
    /// The name of an opening tag; its attributes follow as separate tokens.
    StartTag(&'a [u8]),
    EndTag(&'a [u8]),
    /// The `>` that ends a start tag.
    TagEnd,
    /// The `/>` that ends a start tag.
    SelfClosingTagEnd,
    AttrName(&'a [u8]),
    AttrValue(&'a [u8]),
    /// A quoted attribute value whose closing quote never came, so it
    /// swallowed the rest of the input.
    UnclosedAttrValue(&'a [u8]),
    /// The body of `<!-- -->`, `<? >`, `<% %>` or any other bogus comment.
    Comment(&'a [u8]),
    /// Everything after `<!` in a doctype declaration.
    Doctype(&'a [u8]),
}

#[derive(Debug, Clone, Copy)]
enum State {
    Data,
    TagOpen,
    EndTagOpen,
    TagName { closing: bool },
    TagEnd,
    BeforeAttrName,
    AttrName,
    AfterAttrName,
    BeforeAttrValue,
    QuotedAttrValue(u8),
    UnquotedAttrValue,
    AfterQuotedAttrValue,
    SelfClosingStartTag,
    MarkupDeclarationOpen,
    Comment,
    BogusComment,
    PercentComment,
    Cdata,
    Doctype,
    Eof,
}

pub struct Tokenizer<'a> {
    input: &'a [u8],
    pos: usize,
    state: State,
}

impl<'a> Tokenizer<'a> {
    pub fn new(input: &'a [u8], context: Context) -> Self {
        let state = match context {
            Context::Text => State::Data,
            Context::UnquotedAttribute => State::BeforeAttrName,
            Context::SingleQuotedAttribute => State::QuotedAttrValue(b'\''),
            Context::DoubleQuotedAttribute => State::QuotedAttrValue(b'"'),
            Context::BacktickAttribute => State::QuotedAttrValue(b'`'),
        };
        Self {
            input,
            pos: 0,
            state,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.pos).copied()
    }

    fn find_byte(&self, needle: u8, from: usize) -> Option<usize> {
        self.input[from..]
            .iter()
            .position(|&b| b == needle)
            .map(|i| from + i)
    }

    /// Advances past whitespace, including the nulls IE skipped.
    fn skip_space(&mut self) -> Option<u8> {
        while let Some(b) = self.peek() {
            if b == 0 || is_space(b) {
                self.pos += 1;
            } else {
                return Some(b);
            }
        }
        None
    }

    /// Emits `token` over `start..end`, resuming at `resume` in `state`.
    fn emit(
        &mut self,
        token: fn(&'a [u8]) -> Token<'a>,
        start: usize,
        end: usize,
        resume: usize,
        state: State,
    ) -> Option<Token<'a>> {
        self.pos = resume;
        self.state = state;
        Some(token(&self.input[start..end]))
    }

    /// Emits the rest of the input as `token` and stops.
    fn emit_rest(&mut self, token: fn(&'a [u8]) -> Token<'a>, start: usize) -> Option<Token<'a>> {
        let len = self.input.len();
        self.emit(token, start, len, len, State::Eof)
    }

    fn stop(&mut self) -> Option<Token<'a>> {
        self.state = State::Eof;
        None
    }

    fn data(&mut self) -> Option<Token<'a>> {
        let start = self.pos;
        match self.find_byte(b'<', start) {
            Some(lt) => {
                self.pos = lt + 1;
                self.state = State::TagOpen;
                (lt > start).then(|| Token::Text(&self.input[start..lt]))
            }
            None if start == self.input.len() => self.stop(),
            None => self.emit_rest(Token::Text, start),
        }
    }

    fn tag_open(&mut self) -> Option<Token<'a>> {
        let Some(b) = self.peek() else {
            return self.stop();
        };
        match b {
            b'!' => {
                self.pos += 1;
                self.state = State::MarkupDeclarationOpen;
            }
            b'/' => {
                self.pos += 1;
                self.state = State::EndTagOpen;
            }
            b'?' => {
                self.pos += 1;
                self.state = State::BogusComment;
            }
            // `<% %>` was a comment in old IE and Safari.
            b'%' => {
                self.pos += 1;
                self.state = State::PercentComment;
            }
            0 => self.state = State::TagName { closing: false },
            b if b.is_ascii_alphabetic() => self.state = State::TagName { closing: false },
            _ => {
                // A lone `<` is text.
                self.state = State::Data;
                return Some(Token::Text(&self.input[self.pos - 1..self.pos]));
            }
        }
        None
    }

    fn end_tag_open(&mut self) -> Option<Token<'a>> {
        let Some(b) = self.peek() else {
            return self.stop();
        };
        match b {
            b'>' => {
                self.pos += 1;
                self.state = State::Data;
            }
            b if b.is_ascii_alphabetic() => self.state = State::TagName { closing: true },
            _ => self.state = State::BogusComment,
        }
        None
    }

    fn tag_name(&mut self, closing: bool) -> Option<Token<'a>> {
        let token = if closing {
            Token::EndTag
        } else {
            Token::StartTag
        };
        let start = self.pos;
        let mut i = start;
        while let Some(&b) = self.input.get(i) {
            match b {
                0 => i += 1,
                b'/' => return self.emit(token, start, i, i + 1, State::SelfClosingStartTag),
                b'>' if closing => return self.emit(token, start, i, i + 1, State::Data),
                b'>' => return self.emit(token, start, i, i, State::TagEnd),
                b if is_space(b) => {
                    return self.emit(token, start, i, i + 1, State::BeforeAttrName);
                }
                _ => i += 1,
            }
        }
        self.emit_rest(token, start)
    }

    fn tag_end(&mut self) -> Option<Token<'a>> {
        self.pos += 1;
        self.state = if self.pos < self.input.len() {
            State::Data
        } else {
            State::Eof
        };
        Some(Token::TagEnd)
    }

    fn before_attr_name(&mut self) -> Option<Token<'a>> {
        loop {
            let Some(b) = self.skip_space() else {
                return self.stop();
            };
            match b {
                // A stray `/` between attributes is ignored unless it closes the tag.
                b'/' => {
                    self.pos += 1;
                    if self.peek() == Some(b'>') {
                        self.state = State::SelfClosingStartTag;
                        return None;
                    }
                }
                b'>' => {
                    self.state = State::TagEnd;
                    return None;
                }
                _ => {
                    self.state = State::AttrName;
                    return None;
                }
            }
        }
    }

    fn attr_name(&mut self) -> Option<Token<'a>> {
        let start = self.pos;
        // The first byte always belongs to the name, so `=x` is an attribute
        // named `=`.
        let mut i = start + 1;
        while let Some(&b) = self.input.get(i) {
            match b {
                b'/' => {
                    return self.emit(Token::AttrName, start, i, i + 1, State::SelfClosingStartTag);
                }
                b'=' => return self.emit(Token::AttrName, start, i, i + 1, State::BeforeAttrValue),
                b'>' => return self.emit(Token::AttrName, start, i, i, State::TagEnd),
                b if is_space(b) => {
                    return self.emit(Token::AttrName, start, i, i + 1, State::AfterAttrName);
                }
                _ => i += 1,
            }
        }
        self.emit_rest(Token::AttrName, start)
    }

    fn after_attr_name(&mut self) -> Option<Token<'a>> {
        let Some(b) = self.skip_space() else {
            return self.stop();
        };
        match b {
            b'/' => {
                self.pos += 1;
                self.state = State::SelfClosingStartTag;
            }
            b'=' => {
                self.pos += 1;
                self.state = State::BeforeAttrValue;
            }
            b'>' => self.state = State::TagEnd,
            _ => self.state = State::AttrName,
        }
        None
    }

    fn before_attr_value(&mut self) -> Option<Token<'a>> {
        let Some(b) = self.skip_space() else {
            return self.stop();
        };
        match b {
            b'"' | b'\'' | b'`' => {
                self.pos += 1;
                self.state = State::QuotedAttrValue(b);
            }
            _ => self.state = State::UnquotedAttrValue,
        }
        None
    }

    fn quoted_attr_value(&mut self, quote: u8) -> Option<Token<'a>> {
        let start = self.pos;
        match self.find_byte(quote, start) {
            Some(end) => self.emit(
                Token::AttrValue,
                start,
                end,
                end + 1,
                State::AfterQuotedAttrValue,
            ),
            None => self.emit_rest(Token::UnclosedAttrValue, start),
        }
    }

    fn unquoted_attr_value(&mut self) -> Option<Token<'a>> {
        let start = self.pos;
        let mut i = start;
        while let Some(&b) = self.input.get(i) {
            match b {
                b'>' => return self.emit(Token::AttrValue, start, i, i, State::TagEnd),
                b if is_space(b) => {
                    return self.emit(Token::AttrValue, start, i, i + 1, State::BeforeAttrName);
                }
                _ => i += 1,
            }
        }
        self.emit_rest(Token::AttrValue, start)
    }

    fn after_quoted_attr_value(&mut self) -> Option<Token<'a>> {
        let Some(b) = self.peek() else {
            return self.stop();
        };
        match b {
            b'/' => {
                self.pos += 1;
                self.state = State::SelfClosingStartTag;
            }
            b'>' => self.state = State::TagEnd,
            b if is_space(b) => {
                self.pos += 1;
                self.state = State::BeforeAttrName;
            }
            // `<a href="x"onclick=...>`: browsers start the next attribute here.
            _ => self.state = State::BeforeAttrName,
        }
        None
    }

    fn self_closing_start_tag(&mut self) -> Option<Token<'a>> {
        match self.peek() {
            None => self.stop(),
            Some(b'>') => {
                self.pos += 1;
                self.state = State::Data;
                Some(Token::SelfClosingTagEnd)
            }
            Some(_) => {
                self.state = State::BeforeAttrName;
                None
            }
        }
    }

    fn markup_declaration_open(&mut self) -> Option<Token<'a>> {
        let rest = &self.input[self.pos..];
        if rest.len() >= 7 && rest[..7].eq_ignore_ascii_case(b"doctype") {
            self.state = State::Doctype;
        } else if rest.starts_with(b"[CDATA[") {
            self.pos += 7;
            self.state = State::Cdata;
        } else if rest.starts_with(b"--") {
            self.pos += 2;
            self.state = State::Comment;
        } else {
            self.state = State::BogusComment;
        }
        None
    }

    /// `<!-- -->`, also ending at `--!>` and skipping nulls between the
    /// dashes as IE did.
    fn comment(&mut self) -> Option<Token<'a>> {
        let start = self.pos;
        let input = self.input;
        let mut from = start;
        while let Some(dash) = self.find_byte(b'-', from) {
            from = dash + 1;
            let mut i = from;
            while input.get(i) == Some(&0) {
                i += 1;
            }
            if input.get(i) != Some(&b'-') {
                continue;
            }
            i += 1;
            if input.get(i) == Some(&b'!') {
                i += 1;
            }
            if input.get(i) == Some(&b'>') {
                return self.emit(Token::Comment, start, dash, i + 1, State::Data);
            }
        }
        self.emit_rest(Token::Comment, start)
    }

    /// `<? >`, `</ >` with a non-letter, `<! >` without a known keyword: up to
    /// the next `>`.
    fn bogus_comment(&mut self) -> Option<Token<'a>> {
        let start = self.pos;
        match self.find_byte(b'>', start) {
            Some(gt) => self.emit(Token::Comment, start, gt, gt + 1, State::Data),
            None => self.emit_rest(Token::Comment, start),
        }
    }

    fn percent_comment(&mut self) -> Option<Token<'a>> {
        let start = self.pos;
        let mut from = start;
        while let Some(pct) = self.find_byte(b'%', from) {
            if self.input.get(pct + 1) == Some(&b'>') {
                return self.emit(Token::Comment, start, pct, pct + 2, State::Data);
            }
            from = pct + 1;
        }
        self.emit_rest(Token::Comment, start)
    }

    fn cdata(&mut self) -> Option<Token<'a>> {
        let start = self.pos;
        let mut from = start;
        while let Some(rb) = self.find_byte(b']', from) {
            if self.input[rb..].starts_with(b"]]>") {
                return self.emit(Token::Text, start, rb, rb + 3, State::Data);
            }
            from = rb + 1;
        }
        self.emit_rest(Token::Text, start)
    }

    fn doctype(&mut self) -> Option<Token<'a>> {
        let start = self.pos;
        match self.find_byte(b'>', start) {
            Some(gt) => self.emit(Token::Doctype, start, gt, gt + 1, State::Data),
            None => self.emit_rest(Token::Doctype, start),
        }
    }
}

impl<'a> Iterator for Tokenizer<'a> {
    type Item = Token<'a>;

    fn next(&mut self) -> Option<Token<'a>> {
        loop {
            let token = match self.state {
                State::Eof => return None,
                State::Data => self.data(),
                State::TagOpen => self.tag_open(),
                State::EndTagOpen => self.end_tag_open(),
                State::TagName { closing } => self.tag_name(closing),
                State::TagEnd => self.tag_end(),
                State::BeforeAttrName => self.before_attr_name(),
                State::AttrName => self.attr_name(),
                State::AfterAttrName => self.after_attr_name(),
                State::BeforeAttrValue => self.before_attr_value(),
                State::QuotedAttrValue(quote) => self.quoted_attr_value(quote),
                State::UnquotedAttrValue => self.unquoted_attr_value(),
                State::AfterQuotedAttrValue => self.after_quoted_attr_value(),
                State::SelfClosingStartTag => self.self_closing_start_tag(),
                State::MarkupDeclarationOpen => self.markup_declaration_open(),
                State::Comment => self.comment(),
                State::BogusComment => self.bogus_comment(),
                State::PercentComment => self.percent_comment(),
                State::Cdata => self.cdata(),
                State::Doctype => self.doctype(),
            };
            if token.is_some() || matches!(self.state, State::Eof) {
                return token;
            }
        }
    }
}

/// HTML whitespace plus `\v`, which IE also treated as a separator.
pub(crate) const fn is_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tokens(input: &str) -> Vec<Token<'_>> {
        Tokenizer::new(input.as_bytes(), Context::Text).collect()
    }

    #[test]
    fn plain_text_is_one_token() {
        assert_eq!(tokens("hello"), [Token::Text(b"hello")]);
        assert!(tokens("").is_empty());
    }

    #[test]
    fn start_tag_with_attributes() {
        assert_eq!(
            tokens(r#"<img src="x" onerror=alert(1)>"#),
            [
                Token::StartTag(b"img"),
                Token::AttrName(b"src"),
                Token::AttrValue(b"x"),
                Token::AttrName(b"onerror"),
                Token::AttrValue(b"alert(1)"),
                Token::TagEnd,
            ]
        );
    }

    #[test]
    fn slash_separates_attributes() {
        assert_eq!(
            tokens("<svg/onload=alert(1)>"),
            [
                Token::StartTag(b"svg"),
                Token::AttrName(b"onload"),
                Token::AttrValue(b"alert(1)"),
                Token::TagEnd,
            ]
        );
    }

    #[test]
    fn end_tags_and_lone_angle_brackets() {
        assert_eq!(
            tokens("a<b>c</b>"),
            [
                Token::Text(b"a"),
                Token::StartTag(b"b"),
                Token::TagEnd,
                Token::Text(b"c"),
                Token::EndTag(b"b"),
            ]
        );
        assert_eq!(
            tokens("1 < 2"),
            [Token::Text(b"1 "), Token::Text(b"<"), Token::Text(b" 2")]
        );
        assert_eq!(tokens("</>x"), [Token::Text(b"x")]);
    }

    #[test]
    fn comments_in_all_flavours() {
        assert_eq!(
            tokens("<!-- x -->y"),
            [Token::Comment(b" x "), Token::Text(b"y")]
        );
        assert_eq!(
            tokens("<!-- x --!>y"),
            [Token::Comment(b" x "), Token::Text(b"y")]
        );
        assert_eq!(
            tokens("<?xml x?>y"),
            [Token::Comment(b"xml x?"), Token::Text(b"y")]
        );
        assert_eq!(
            tokens("<% x %>y"),
            [Token::Comment(b" x "), Token::Text(b"y")]
        );
        assert_eq!(tokens("<!-- open"), [Token::Comment(b" open")]);
    }

    #[test]
    fn attribute_contexts_start_inside_the_value() {
        let got: Vec<_> =
            Tokenizer::new(br#"x" onfocus="alert(1)"#, Context::DoubleQuotedAttribute).collect();
        assert_eq!(
            got,
            [
                Token::AttrValue(b"x"),
                Token::AttrName(b"onfocus"),
                Token::UnclosedAttrValue(b"alert(1)"),
            ]
        );
    }

    #[test]
    fn unclosed_quote_swallows_the_rest() {
        assert_eq!(
            tokens(r#"<img src="//evil? <b>secret</b>"#),
            [
                Token::StartTag(b"img"),
                Token::AttrName(b"src"),
                Token::UnclosedAttrValue(b"//evil? <b>secret</b>"),
            ]
        );
    }
}
