//! Tokenizer conformance against libinjection's `test-html5-*.txt` suite.

use openshield_injection::testdata::{cases, trimmed_lines};
use openshield_injection::xss::{Context, Token, Tokenizer};

fn render(token: Token<'_>) -> String {
    let (kind, text): (&str, &[u8]) = match token {
        Token::Text(t) => ("DATA_TEXT", t),
        Token::StartTag(t) => ("TAG_NAME_OPEN", t),
        Token::EndTag(t) => ("TAG_CLOSE", t),
        Token::TagEnd => ("TAG_NAME_CLOSE", b">"),
        Token::SelfClosingTagEnd => ("TAG_NAME_SELFCLOSE", b"/>"),
        Token::AttrName(t) => ("ATTR_NAME", t),
        Token::AttrValue(t) | Token::UnclosedAttrValue(t) => ("ATTR_VALUE", t),
        Token::Comment(t) => ("TAG_COMMENT", t),
        Token::Doctype(t) => ("DOCTYPE", t),
    };
    format!("{kind},{},{}", text.len(), String::from_utf8_lossy(text))
}

#[test]
fn matches_libinjection_html5_suite() {
    let cases = cases("html5", "test-html5-");
    assert!(cases.len() > 100, "conformance suite missing");

    let mut failures = Vec::new();
    for (file, case) in cases {
        let got: Vec<String> = Tokenizer::new(&case.input, Context::Text)
            .map(render)
            .collect();
        let got = got.join("\n");
        if trimmed_lines(&got) != trimmed_lines(&case.expected) {
            failures.push(format!(
                "{file} ({}):\n  input:    {:?}\n  expected: {:?}\n  got:      {:?}",
                case.name,
                String::from_utf8_lossy(&case.input),
                case.expected,
                got
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
