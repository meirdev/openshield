//! Conformance against libinjection's SQLi suites: `test-tokens-*` for the
//! tokenizer, `test-folding-*` for folding and `test-sqli-*` for the
//! verdict and fingerprint.

use openshield_injection::sqli::{Dialect, Kind, Quote, Token, Tokenizer, detect_sqli, fold};
use openshield_injection::testdata::{Case, cases, trimmed_lines};

fn render(token: &Token) -> String {
    let mut out = format!("{} ", token.kind.symbol() as char);
    out.extend(std::iter::repeat_n('@', usize::from(token.ats)));
    if matches!(token.kind, Kind::String | Kind::Variable) {
        out.extend(token.open.map(char::from));
        out.push_str(&String::from_utf8_lossy(&token.text));
        out.extend(token.close.map(char::from));
    } else {
        out.push_str(&String::from_utf8_lossy(&token.text));
    }
    out
}

fn tokens(case: &Case) -> String {
    let lines: Vec<String> = Tokenizer::new(&case.input, Quote::None, Dialect::Ansi)
        .map(|t| render(&t))
        .collect();
    lines.join("\n")
}

fn folded(case: &Case) -> String {
    let mut tokenizer = Tokenizer::new(&case.input, Quote::None, Dialect::Ansi);
    let mut out = Vec::new();
    fold(&mut tokenizer, &mut out);
    let lines: Vec<String> = out.iter().map(render).collect();
    lines.join("\n")
}

fn verdict(case: &Case) -> String {
    detect_sqli(&case.input)
        .map(|f| f.fingerprint.to_string())
        .unwrap_or_default()
}

fn check(prefix: &str, run: fn(&Case) -> String) {
    let cases = cases("sqli-suite", prefix);
    assert!(!cases.is_empty(), "no {prefix} cases");
    let mut failures = Vec::new();
    for (file, case) in cases {
        let got = run(&case);
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

#[test]
fn tokens_match_libinjection() {
    check("test-tokens-", tokens);
}

#[test]
fn folding_matches_libinjection() {
    check("test-folding-", folded);
}

#[test]
fn verdicts_match_libinjection() {
    check("test-sqli-", verdict);
}
