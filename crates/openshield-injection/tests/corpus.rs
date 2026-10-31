//! Detection over the vendored corpora. Every positive must be detected
//! unless it is listed in that detector's `positive-exceptions.txt`, and no
//! negative may be unless it is listed in `negative-exceptions.txt`. Both
//! lists are checked for stale entries, so they only ever shrink.

use std::collections::HashSet;

use openshield_injection::testdata::{Sample, samples};
use openshield_injection::{detect_sqli, detect_xss};

type Detector = fn(&[u8]) -> Option<String>;

fn xss(input: &[u8]) -> Option<String> {
    detect_xss(input).map(|f| f.to_string())
}

fn sqli(input: &[u8]) -> Option<String> {
    detect_sqli(input).map(|f| f.to_string())
}

fn describe(sample: &Sample) -> String {
    format!(
        "{}:{}: {:?}",
        sample.file,
        sample.line,
        String::from_utf8_lossy(&sample.input)
    )
}

fn exceptions(dir: &str, file: &str) -> HashSet<Vec<u8>> {
    samples(&format!("{dir}/exceptions"))
        .into_iter()
        .filter(|s| s.file == file)
        .map(|s| s.input)
        .collect()
}

fn positives_are_detected(dir: &str, detect: Detector) {
    let exceptions = exceptions(dir, "positive-exceptions.txt");
    let mut missed = Vec::new();
    let mut stale = Vec::new();
    for sample in samples(&format!("{dir}/positive")) {
        let detected = detect(&sample.input).is_some();
        let excepted = exceptions.contains(&sample.input);
        if !detected && !excepted {
            missed.push(describe(&sample));
        }
        if detected && excepted {
            stale.push(describe(&sample));
        }
    }
    assert!(
        missed.is_empty(),
        "{} positives missed:\n{}",
        missed.len(),
        missed.join("\n")
    );
    assert!(
        stale.is_empty(),
        "{} positive exceptions are now detected and should be removed:\n{}",
        stale.len(),
        stale.join("\n")
    );
}

fn negatives_are_clean(dir: &str, detect: Detector) {
    let exceptions = exceptions(dir, "negative-exceptions.txt");
    let mut hits = Vec::new();
    let mut stale = Vec::new();
    for sample in samples(&format!("{dir}/negative")) {
        let found = detect(&sample.input);
        let excepted = exceptions.contains(&sample.input);
        if let Some(why) = &found
            && !excepted
        {
            hits.push(format!("{} -> {why}", describe(&sample)));
        }
        if found.is_none() && excepted {
            stale.push(describe(&sample));
        }
    }
    assert!(
        hits.is_empty(),
        "{} false positives:\n{}",
        hits.len(),
        hits.join("\n")
    );
    assert!(
        stale.is_empty(),
        "{} negative exceptions are now clean and should be removed:\n{}",
        stale.len(),
        stale.join("\n")
    );
}

#[test]
fn xss_positives_are_detected() {
    positives_are_detected("xss", xss);
}

#[test]
fn xss_negatives_are_clean() {
    negatives_are_clean("xss", xss);
}

#[test]
fn sqli_positives_are_detected() {
    positives_are_detected("sqli", sqli);
}

#[test]
fn sqli_negatives_are_clean() {
    negatives_are_clean("sqli", sqli);
}
