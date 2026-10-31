//! Token folding: collapses a token stream into the few tokens that carry
//! its SQL structure, so that `1 + 2 + 3` and `1` fingerprint the same.
//!
//! The rules and their order are libinjection's; the fingerprint database
//! was learned against exactly this folding, so changing a rule means
//! regenerating the database.

use super::token::{Kind, Text, Token};
use super::tokenizer::{Tokenizer, lookup_phrase};

/// Fingerprints use at most this many tokens.
pub const MAX_TOKENS: usize = 5;

/// Folds the rest of `tokenizer` into `tokens`, which is cleared first.
pub fn fold(tokenizer: &mut Tokenizer<'_>, tokens: &mut Vec<Token>) {
    tokens.clear();
    let mut last_comment = None;

    let Some(first) = tokenizer.find(|t| {
        !(matches!(t.kind, Kind::Comment | Kind::LeftParens | Kind::SqlType) || t.is_unary_op())
    }) else {
        return;
    };
    tokens.push(first);

    let mut more = true;
    let mut left = 0;
    loop {
        if tokens.len() >= MAX_TOKENS && is_arithmetic_noise(&tokens[..MAX_TOKENS]) {
            if tokens.len() > MAX_TOKENS {
                tokens[1] = tokens[MAX_TOKENS];
                tokens.truncate(2);
            } else {
                tokens.truncate(1);
            }
            left = 0;
        }
        if !more || left >= MAX_TOKENS {
            break;
        }

        fetch(tokenizer, tokens, &mut more, &mut last_comment, left, 2);
        if tokens.len() - left < 2 {
            left = tokens.len();
            continue;
        }
        let (a, b) = (tokens[left], tokens[left + 1]);
        let same = |kind: Kind| a.kind == kind && b.kind == kind;
        if same(Kind::String) || same(Kind::Semicolon) {
            tokens.pop();
            continue;
        } else if matches!(a.kind, Kind::Operator | Kind::LogicOperator)
            && (b.is_unary_op() || b.kind == Kind::SqlType)
        {
            tokens.pop();
            left = 0;
            continue;
        } else if a.kind == Kind::LeftParens && b.is_unary_op() {
            tokens.pop();
            left = left.saturating_sub(1);
            continue;
        } else if let Some(merged) = merge_phrase(a, b) {
            tokens[left] = merged;
            tokens.pop();
            left = left.saturating_sub(1);
            continue;
        } else if a.kind == Kind::Semicolon
            && b.kind == Kind::Function
            && b.text
                .get(..2)
                .is_some_and(|w| w.eq_ignore_ascii_case(b"IF"))
        {
            // In Transact-SQL a statement-level IF is control flow, not a
            // function.
            tokens[left + 1].kind = Kind::Tsql;
            continue;
        } else if matches!(a.kind, Kind::Bareword | Kind::Variable)
            && b.kind == Kind::LeftParens
            && FUNCTION_LIKE_WORDS.iter().any(|w| a.text_is(w))
        {
            tokens[left].kind = Kind::Function;
            continue;
        } else if a.kind == Kind::Keyword && (a.text_is(b"IN") || a.text_is(b"NOT IN")) {
            tokens[left].kind = if b.kind == Kind::LeftParens {
                Kind::Operator
            } else {
                Kind::Bareword
            };
            continue;
        } else if a.kind == Kind::Operator && (a.text_is(b"LIKE") || a.text_is(b"NOT LIKE")) {
            let after_value = left > 0
                && matches!(
                    tokens[left - 1].kind,
                    Kind::Number
                        | Kind::String
                        | Kind::Bareword
                        | Kind::Variable
                        | Kind::RightParens
                );
            if b.kind == Kind::LeftParens && !after_value {
                tokens[left].kind = Kind::Function;
            }
        } else if a.kind == Kind::SqlType
            && matches!(
                b.kind,
                Kind::Bareword
                    | Kind::Number
                    | Kind::SqlType
                    | Kind::LeftParens
                    | Kind::Function
                    | Kind::Variable
                    | Kind::String
            )
        {
            tokens[left] = b;
            tokens.pop();
            left = 0;
            continue;
        } else if a.kind == Kind::Collate && b.kind == Kind::Bareword {
            // Collation names all contain an underscore; there are too many to
            // list.
            if b.text.contains(&b'_') {
                tokens[left + 1].kind = Kind::SqlType;
                left = 0;
            }
        } else if a.kind == Kind::Backslash {
            // Transact-SQL reads `\%1` as `0 % 1` and `\1` as `1`.
            if b.is_arithmetic_op() {
                tokens[left].kind = Kind::Number;
            } else {
                tokens[left] = b;
                tokens.pop();
            }
            left = 0;
            continue;
        } else if same(Kind::LeftParens) || same(Kind::RightParens) {
            tokens.pop();
            left = 0;
            continue;
        } else if a.kind == Kind::LeftBrace && b.kind == Kind::Bareword {
            // MySQL accepts `{ ``.``.id }` and nothing else like it; just ban
            // it.
            if b.text.is_empty() {
                tokens[left + 1].kind = Kind::Evil;
                tokens.truncate(left + 2);
                return;
            }
            // ODBC `{fn expr}` means `expr`.
            tokens.truncate(tokens.len() - 2);
            left = 0;
            continue;
        } else if b.kind == Kind::RightBrace {
            tokens.pop();
            left = 0;
            continue;
        }

        fetch(tokenizer, tokens, &mut more, &mut last_comment, left, 3);
        if tokens.len() - left < 3 {
            left = tokens.len();
            continue;
        }
        let (a, b, c) = (tokens[left], tokens[left + 1], tokens[left + 2]);
        if is_expression(a, b, c) {
            tokens.truncate(tokens.len() - 2);
            left = 0;
        } else if is_unary_after_clause(a, b, c) {
            tokens[left + 1] = c;
            tokens.pop();
            left = 0;
        } else if a.kind == Kind::Comma && b.is_unary_op() && is_value(c.kind) {
            // `1,-1` folds to `1`: drop all three and let the previous token
            // refold.
            tokens.truncate(tokens.len() - 3);
            left = 0;
        } else if a.kind == Kind::Comma && b.is_unary_op() && c.kind == Kind::Function {
            tokens[left + 1] = c;
            tokens.pop();
            left = 0;
        } else if a.kind == Kind::Bareword && b.kind == Kind::Dot && c.kind == Kind::Bareword {
            tokens.truncate(tokens.len() - 2);
            left = 0;
        } else if a.kind == Kind::Expression && b.kind == Kind::Dot && c.kind == Kind::Bareword {
            tokens[left + 1] = c;
            tokens.pop();
            left = 0;
        } else {
            // `USER()` is a function but `USER(x)` is a column.
            if a.kind == Kind::Function
                && b.kind == Kind::LeftParens
                && c.kind != Kind::RightParens
                && a.text_is(b"USER")
            {
                tokens[left].kind = Kind::Bareword;
            }
            left += 1;
        }
    }

    if tokens.len() < MAX_TOKENS
        && let Some(comment) = last_comment
    {
        tokens.push(comment);
    }
    tokens.truncate(MAX_TOKENS);
}

fn is_value(kind: Kind) -> bool {
    matches!(
        kind,
        Kind::Number | Kind::Bareword | Kind::Variable | Kind::String
    )
}

/// Three tokens that are an operand, an operator and an operand (or a
/// list, or a cast), which fold to the first operand.
fn is_expression(a: Token, b: Token, c: Token) -> bool {
    let operands = |x: Kind, y: Kind| {
        (x == Kind::Number && y == Kind::Number)
            || (x == Kind::Variable && matches!(y, Kind::Variable | Kind::Number | Kind::Bareword))
            || (matches!(x, Kind::Bareword | Kind::Number)
                && matches!(y, Kind::Number | Kind::Bareword))
    };
    (b.kind == Kind::Operator && operands(a.kind, c.kind))
        || (a.kind == Kind::Operator && b.kind != Kind::LeftParens && c.kind == Kind::Operator)
        || (a.kind == Kind::LogicOperator && c.kind == Kind::LogicOperator)
        || (is_value(a.kind)
            && b.kind == Kind::Operator
            && &*b.text == b"::"
            && c.kind == Kind::SqlType)
        || (is_value(a.kind) && b.kind == Kind::Comma && is_value(c.kind))
}

/// `SELECT -1`, `LIMIT +(`: a unary operator after a clause keyword adds
/// nothing and is dropped.
fn is_unary_after_clause(a: Token, b: Token, c: Token) -> bool {
    b.is_unary_op()
        && ((matches!(a.kind, Kind::Expression | Kind::Group | Kind::Comma)
            && c.kind == Kind::LeftParens)
            || (matches!(a.kind, Kind::Keyword | Kind::Expression | Kind::Group)
                && (is_value(c.kind) || c.kind == Kind::Function)))
}

/// Barewords that are functions when followed by `(`.
const FUNCTION_LIKE_WORDS: &[&[u8]] = &[
    b"USER_ID",
    b"USER_NAME",
    b"DATABASE",
    b"PASSWORD",
    b"USER",
    b"CURRENT_USER",
    b"CURRENT_DATE",
    b"CURRENT_TIME",
    b"CURRENT_TIMESTAMP",
    b"LOCALTIME",
    b"LOCALTIMESTAMP",
];

/// Pulls tokens until `want` are waiting past `left`, keeping the last
/// comment aside so it can be appended if the fingerprint ends up short.
fn fetch(
    tokenizer: &mut Tokenizer<'_>,
    tokens: &mut Vec<Token>,
    more: &mut bool,
    last_comment: &mut Option<Token>,
    left: usize,
    want: usize,
) {
    while *more && tokens.len() <= MAX_TOKENS && tokens.len() - left < want {
        match tokenizer.next() {
            None => *more = false,
            Some(t) if t.kind == Kind::Comment => *last_comment = Some(t),
            Some(t) => {
                *last_comment = None;
                tokens.push(t);
            }
        }
    }
}

/// Five-token shapes such as `1,(1)` and `n=(n)` that are arithmetic or
/// list noise, not structure.
fn is_arithmetic_noise(t: &[Token]) -> bool {
    let k = |i: usize| t[i].kind;
    (k(0) == Kind::Number
        && matches!(k(1), Kind::Operator | Kind::Comma)
        && k(2) == Kind::LeftParens
        && k(3) == Kind::Number
        && k(4) == Kind::RightParens)
        || (k(0) == Kind::Bareword
            && k(1) == Kind::Operator
            && k(2) == Kind::LeftParens
            && matches!(k(3), Kind::Bareword | Kind::Number)
            && k(4) == Kind::RightParens)
        || (k(0) == Kind::Number
            && k(1) == Kind::RightParens
            && k(2) == Kind::Comma
            && k(3) == Kind::LeftParens
            && k(4) == Kind::Number)
        || (k(0) == Kind::Bareword
            && k(1) == Kind::RightParens
            && k(2) == Kind::Operator
            && k(3) == Kind::LeftParens
            && k(4) == Kind::Bareword)
}

/// Merges two words into a multi-word phrase such as `UNION ALL` when the
/// phrase is in the keyword table.
fn merge_phrase(a: Token, b: Token) -> Option<Token> {
    let word_like = |k: Kind| {
        matches!(
            k,
            Kind::Keyword
                | Kind::Bareword
                | Kind::Operator
                | Kind::Union
                | Kind::Function
                | Kind::Expression
                | Kind::Tsql
                | Kind::SqlType
        )
    };
    if !word_like(a.kind) || !(word_like(b.kind) || b.kind == Kind::LogicOperator) {
        return None;
    }
    let text = Text::joined(&a.text, &b.text)?;
    let kind = lookup_phrase(&a.text, &b.text)?;
    Some(Token {
        kind,
        pos: a.pos,
        text,
        open: a.open,
        close: a.close,
        ats: a.ats,
    })
}
