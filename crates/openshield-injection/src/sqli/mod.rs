//! SQL injection detection.
//!
//! The input is tokenized as SQL, the tokens are folded down to the few
//! that carry structure, and the sequence of their kinds, the fingerprint,
//! is looked up in a database of sequences seen in attacks. Because an
//! injected value may land inside a string literal, the input is also
//! scanned as if it began with a single or double quote, and inputs with
//! MySQL-style comments are scanned again under MySQL's comment rules.

mod fingerprints;
mod fold;
mod keywords;
mod token;
mod tokenizer;

use std::fmt;

pub use fold::{MAX_TOKENS, fold};
pub use token::{Kind, Text, Token};
pub use tokenizer::{Dialect, Quote, Tokenizer};

/// The kinds of the folded tokens, in libinjection's notation: `s&1o` is a
/// string, a logic operator, a number and an operator, as in `' or 1=`.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Fingerprint {
    len: u8,
    symbols: [u8; MAX_TOKENS],
}

impl Fingerprint {
    fn new(tokens: &[Token]) -> Self {
        let mut symbols = [0; MAX_TOKENS];
        for (slot, token) in symbols.iter_mut().zip(tokens) {
            *slot = token.kind.symbol();
        }
        Self {
            len: tokens.len().min(MAX_TOKENS) as u8,
            symbols,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.symbols[..usize::from(self.len)]
    }

    /// Whether this sequence is in the database of attack fingerprints.
    fn is_known_attack(&self) -> bool {
        let mut upper = [0; MAX_TOKENS];
        for (dst, src) in upper.iter_mut().zip(self.as_bytes()) {
            *dst = src.to_ascii_uppercase();
        }
        fingerprints::FINGERPRINTS
            .binary_search(&&upper[..self.as_bytes().len()])
            .is_ok()
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(std::str::from_utf8(self.as_bytes()).unwrap_or("?"))
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fingerprint({self})")
    }
}

/// Why an input was judged to be SQL injection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Finding {
    pub fingerprint: Fingerprint,
    /// The string context in which the input became SQL.
    pub quote: Quote,
    pub dialect: Dialect,
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} fingerprint in {}", self.fingerprint, self.quote)?;
        if self.dialect == Dialect::Mysql {
            f.write_str(" (mysql)")?;
        }
        Ok(())
    }
}

impl fmt::Display for Quote {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Quote::None => "bare context",
            Quote::Single => "single-quoted context",
            Quote::Double => "double-quoted context",
        })
    }
}

/// Returns why `input` would be SQL injection, or `None` when it is not.
pub fn detect_sqli(input: &[u8]) -> Option<Finding> {
    if input.is_empty() {
        return None;
    }
    let mut tokens = Vec::with_capacity(MAX_TOKENS + 3);
    let mut scan = |quote, dialect| {
        let mut tokenizer = Tokenizer::new(input, quote, dialect);
        let fingerprint = fingerprint(&mut tokenizer, &mut tokens);
        let found = fingerprint.is_known_attack()
            && !whitelisted(input, &tokens, fingerprint, tokenizer.count);
        (
            found.then_some(Finding {
                fingerprint,
                quote,
                dialect,
            }),
            tokenizer.mysql_hint,
        )
    };
    let mut scan_both_dialects = |quote| {
        let (finding, mysql_hint) = scan(quote, Dialect::Ansi);
        finding.or_else(|| mysql_hint.then(|| scan(quote, Dialect::Mysql).0).flatten())
    };

    scan_both_dialects(Quote::None)
        .or_else(|| {
            input
                .contains(&b'\'')
                .then(|| scan_both_dialects(Quote::Single))
                .flatten()
        })
        .or_else(|| {
            input
                .contains(&b'"')
                .then(|| scan(Quote::Double, Dialect::Mysql).0)
                .flatten()
        })
}

/// Folds the input and reads off its fingerprint, leaving the folded
/// tokens in `tokens`.
pub fn fingerprint(tokenizer: &mut Tokenizer<'_>, tokens: &mut Vec<Token>) -> Fingerprint {
    fold(tokenizer, tokens);
    // PHP's backtick operator: an unclosed, empty backtick at the end is a
    // comment in practice.
    if let [.., _, _, last] = tokens.as_mut_slice()
        && last.kind == Kind::Bareword
        && last.open == Some(b'`')
        && last.close.is_none()
        && last.text.is_empty()
    {
        last.kind = Kind::Comment;
    }
    if tokens.iter().any(|t| t.kind == Kind::Evil) {
        tokens.clear();
        tokens.push(Token::new(Kind::Evil, 0, b"X"));
    }
    Fingerprint::new(tokens)
}

/// Known-attack fingerprints that are too short to be sure about, judged
/// on the tokens themselves.
fn whitelisted(input: &[u8], tokens: &[Token], fp: Fingerprint, total_tokens: usize) -> bool {
    let fp = fp.as_bytes();
    // SQL Server's audit log skips anything mentioning sp_password.
    if fp.len() > 1
        && tokens[fp.len() - 1].kind == Kind::Comment
        && input.windows(11).any(|w| w == b"sp_password")
    {
        return false;
    }
    match fp.len() {
        2 => whitelisted_pair(input, tokens, total_tokens),
        3 => whitelisted_triple(tokens, fp, total_tokens),
        _ => false,
    }
}

fn whitelisted_pair(input: &[u8], tokens: &[Token], total_tokens: usize) -> bool {
    let is_alnum = |at: Option<usize>| {
        at.and_then(|i| input.get(i))
            .is_some_and(u8::is_ascii_alphanumeric)
    };
    let (first, second) = (&tokens[0], &tokens[1]);
    if second.kind == Kind::Union {
        // `1 union` alone is common in normal input; with folding or
        // comments around it, it is an attack.
        return total_tokens == 2;
    }
    if second.text.first() == Some(&b'#') {
        return true;
    }
    if first.kind == Kind::Bareword
        && second.kind == Kind::Comment
        && second.text.first() != Some(&b'/')
    {
        return true;
    }
    if first.kind == Kind::Number && second.kind == Kind::Comment {
        if second.text.first() == Some(&b'/') {
            return false;
        }
        let after = first.pos + first.text.len();
        if total_tokens > 2 {
            // Folding ate something after the number. `1*1--` is an attack
            // hiding arithmetic, but `1611-IioXXIG--` is an identifier and
            // `1,1--` a list: a separator followed by a letter is not SQL.
            return match input.get(after) {
                Some(b'-' | b'/') => {
                    is_alnum(Some(after + 1)) && !input[after + 1].is_ascii_digit()
                }
                Some(b',') => true,
                _ => false,
            };
        }
        // `1234-ABCDEF--` is a base64-ish value, `1234 --` is an attack:
        // the number must end at whitespace or a comment opener.
        return !match input.get(after) {
            None => true,
            Some(&b) if b <= 32 => true,
            Some(b'/') => input.get(after + 1) == Some(&b'*'),
            Some(b'-') => input.get(after + 1) == Some(&b'-'),
            Some(_) => false,
        };
    }
    // Many people write `--` in prose; only a bare trailing `--` counts.
    second.text.len() > 2 && second.text[0] == b'-'
}

fn whitelisted_triple(tokens: &[Token], fp: &[u8], total_tokens: usize) -> bool {
    match fp {
        b"sos" | b"s&s" => {
            // `foo' + 'bar` with no quote at either end means the input
            // closes one string and opens another; anything else is prose.
            let (a, c) = (&tokens[0], &tokens[2]);
            let breaks_out = a.open.is_none() && c.close.is_none() && a.close == c.open;
            // `'='`, `'*'`, `'LIKE'` and even `'IS'` (with `\N`) all change a
            // WHERE clause through MySQL's implicit conversions, but NOT
            // cannot sit between two values, so `STOCKING "NOT" STUFFER` is
            // prose.
            !breaks_out || tokens[1].text_is(b"NOT")
        }
        // `sexy and 17` is prose, `sexy and 17<18` is not.
        b"s&n" | b"n&1" | b"1&1" | b"1&v" | b"1&s" => total_tokens == 3,
        _ if tokens[1].kind == Kind::Keyword => {
            // Only `INTO OUTFILE` and `INTO DUMPFILE` are dangerous here.
            !(tokens[1].text.len() >= 5 && tokens[1].text[..4].eq_ignore_ascii_case(b"INTO"))
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reason(input: &[u8]) -> String {
        detect_sqli(input)
            .map(|f| f.to_string())
            .unwrap_or_default()
    }

    #[test]
    fn classic_payloads() {
        assert_eq!(
            reason(b"1' OR '1'='1"),
            "s&sos fingerprint in single-quoted context"
        );
        assert_eq!(
            reason(b"' UNION SELECT username, password FROM users--"),
            "sUEnk fingerprint in single-quoted context"
        );
        assert_eq!(
            reason(b"1; DROP TABLE users"),
            "1;Tnn fingerprint in bare context"
        );
        assert_eq!(reason(b"1 or 1=1"), "1&1 fingerprint in bare context");
        assert_eq!(
            reason(b"foo\" + \"bar"),
            "sos fingerprint in double-quoted context (mysql)"
        );
        assert_eq!(reason(b"1*1--"), "1c fingerprint in bare context");
    }

    #[test]
    fn benign_text() {
        assert_eq!(reason(b"hello world"), "");
        assert_eq!(reason(b""), "");
        assert_eq!(reason(b"O'Brien"), "");
        assert_eq!(reason(b"rock 'n' roll"), "");
        assert_eq!(reason(b"1 union"), "");
        assert_eq!(reason(b"sexy and 17"), "");
        assert_eq!(reason(b"1234-ABCDEF--"), "");
    }

    #[test]
    fn operators_that_cannot_be_binary_are_prose() {
        assert_eq!(reason(b"CHRISTMAS STOCKING \"NOT\" STUFFER"), "");
        // Anything MySQL can evaluate between two strings still counts.
        assert_eq!(
            reason(b"\"*\""),
            "sos fingerprint in double-quoted context (mysql)"
        );
        assert_eq!(
            reason(b"' is \\N = '"),
            "sos fingerprint in single-quoted context"
        );
        assert_eq!(
            reason(b"1 'or' 1"),
            "s&s fingerprint in single-quoted context"
        );
    }

    #[test]
    fn identifiers_ending_in_dashes_are_not_comments() {
        assert_eq!(reason(b"1611-IioXXIG1ti8rspL2vbXFy--"), "");
        assert_eq!(reason(b"1611/IioXXIG1ti8rspL2vbXFy--"), "");
        assert_eq!(reason(b"1,1--"), "");
        assert_eq!(reason(b"1-1--"), "1c fingerprint in bare context");
    }

    #[test]
    fn mysql_comments_trigger_a_second_pass() {
        assert_eq!(
            reason(b"1 or 1=1#"),
            "1&1c fingerprint in bare context (mysql)"
        );
        assert!(reason(b"1' or 1=1 --x").contains("single-quoted"));
    }

    #[test]
    fn evil_syntax_is_its_own_fingerprint() {
        assert_eq!(
            reason(b"1 /*! union */ select 1"),
            "X fingerprint in bare context"
        );
    }
}
