//! Compares this crate's detectors with libinjectionrs over the corpora.
//!
//! ```text
//! cargo run -p openshield-injection --example eval [xss|sqli] [--diff]
//! ```
//!
//! `--diff` lists every input where the two disagree.

use openshield_injection::testdata::samples;
use openshield_injection::{detect_sqli, detect_xss};

struct Detector {
    name: &'static str,
    ours: fn(&[u8]) -> Option<String>,
    theirs: fn(&[u8]) -> bool,
}

const DETECTORS: [Detector; 2] = [
    Detector {
        name: "xss",
        ours: |input| detect_xss(input).map(|f| f.to_string()),
        theirs: |input| libinjectionrs::detect_xss(input).is_injection(),
    },
    Detector {
        name: "sqli",
        ours: |input| detect_sqli(input).map(|f| f.to_string()),
        theirs: |input| libinjectionrs::detect_sqli(input).is_injection(),
    },
];

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let diff = args.iter().any(|a| a == "--diff");
    for detector in DETECTORS
        .iter()
        .filter(|d| args.iter().all(|a| a.starts_with("--") || a == d.name))
    {
        for (kind, expect) in [("positive", "attack"), ("negative", "clean")] {
            let dir = format!("{}/{kind}", detector.name);
            println!("== {dir} (expected: {expect})");
            println!("{:<52} {:>6} {:>8} {:>8}", "file", "n", "ours", "libinj");
            let mut rows: Vec<(String, usize, usize, usize)> = Vec::new();
            let mut disagreements = Vec::new();
            for sample in samples(&dir) {
                let ours = (detector.ours)(&sample.input);
                let theirs = (detector.theirs)(&sample.input);
                if rows.last().is_none_or(|r| r.0 != sample.file) {
                    rows.push((sample.file.clone(), 0, 0, 0));
                }
                let row = rows.last_mut().unwrap();
                row.1 += 1;
                row.2 += usize::from(ours.is_some());
                row.3 += usize::from(theirs);
                if ours.is_some() != theirs {
                    disagreements.push(format!(
                        "  {}:{} ours={} libinj={} {:?}",
                        sample.file,
                        sample.line,
                        ours.as_deref().unwrap_or("-"),
                        theirs,
                        String::from_utf8_lossy(&sample.input)
                    ));
                }
            }
            let mut total = (0, 0, 0);
            for (file, n, ours, theirs) in &rows {
                println!("{file:<52} {n:>6} {ours:>8} {theirs:>8}");
                total = (total.0 + n, total.1 + ours, total.2 + theirs);
            }
            println!(
                "{:<52} {:>6} {:>8} {:>8}",
                "TOTAL", total.0, total.1, total.2
            );
            println!("disagreements: {}", disagreements.len());
            if diff {
                println!("{}", disagreements.join("\n"));
            }
            println!();
        }
    }
}
