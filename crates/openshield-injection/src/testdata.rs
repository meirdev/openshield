//! Loader for the corpora under `testdata/`, shared by the tests and the
//! eval example. Lines follow libinjection's convention: blank lines and
//! lines starting with `#` are skipped, everything else is URL-decoded.

use std::fs;
use std::path::{Path, PathBuf};

pub struct Sample {
    pub file: String,
    pub line: usize,
    pub input: Vec<u8>,
}

pub fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata")
}

/// Every sample in every `.txt` file directly under `testdata/<dir>`.
pub fn samples(dir: &str) -> Vec<Sample> {
    let mut files: Vec<PathBuf> = fs::read_dir(root().join(dir))
        .unwrap_or_else(|e| panic!("reading testdata/{dir}: {e}"))
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "txt"))
        .collect();
    files.sort();

    let mut out = Vec::new();
    for path in files {
        let file = path.file_name().unwrap().to_string_lossy().into_owned();
        let bytes = fs::read(&path).unwrap();
        for (idx, line) in bytes.split(|&b| b == b'\n').enumerate() {
            let line = trim_end(line);
            if line.is_empty() || line[0] == b'#' {
                continue;
            }
            out.push(Sample {
                file: file.clone(),
                line: idx + 1,
                input: url_decode(line),
            });
        }
    }
    out
}

fn trim_end(line: &[u8]) -> &[u8] {
    let end = line
        .iter()
        .rposition(|b| !b.is_ascii_whitespace())
        .map_or(0, |i| i + 1);
    &line[..end]
}

fn url_decode(line: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(line.len());
    let mut i = 0;
    while i < line.len() {
        match line[i] {
            b'%' if line.len() - i >= 3 => {
                let hex = |b: u8| (b as char).to_digit(16);
                match (hex(line[i + 1]), hex(line[i + 2])) {
                    (Some(hi), Some(lo)) => {
                        out.push((hi * 16 + lo) as u8);
                        i += 3;
                    }
                    _ => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    out
}

/// One case of libinjection's `--TEST--` / `--INPUT--` / `--EXPECTED--`
/// test files.
pub struct Case {
    pub name: String,
    pub input: Vec<u8>,
    pub expected: String,
}

/// Parses a libinjection test file. The input keeps its inner newlines
/// and need not be UTF-8; both input and expectation lose trailing
/// whitespace, as the upstream driver trims them.
pub fn parse_case(file: &[u8]) -> Case {
    let mut sections: [Vec<u8>; 3] = Default::default();
    let mut current = None;
    for line in file.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        match line {
            b"--TEST--" => current = Some(0),
            b"--INPUT--" => current = Some(1),
            b"--EXPECTED--" => current = Some(2),
            _ => {
                let Some(target) = current.map(|i| &mut sections[i]) else {
                    continue;
                };
                if !target.is_empty() {
                    target.push(b'\n');
                }
                target.extend_from_slice(line);
            }
        }
    }
    let [name, input, expected] = sections;
    Case {
        name: String::from_utf8_lossy(&name).trim().to_owned(),
        input: trim_end(&input).to_vec(),
        expected: String::from_utf8_lossy(trim_end(&expected)).into_owned(),
    }
}

/// Every test case whose file name starts with `prefix` under `testdata/<dir>`.
pub fn cases(dir: &str, prefix: &str) -> Vec<(String, Case)> {
    let mut paths: Vec<PathBuf> = fs::read_dir(root().join(dir))
        .unwrap_or_else(|e| panic!("reading testdata/{dir}: {e}"))
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with(prefix))
        })
        .collect();
    paths.sort();
    paths
        .into_iter()
        .map(|path| {
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            (name, parse_case(&fs::read(&path).unwrap()))
        })
        .collect()
}

/// Lines compared without trailing whitespace, since the upstream files
/// are inconsistent about it.
pub fn trimmed_lines(s: &str) -> Vec<&str> {
    s.lines().map(str::trim_end).collect()
}
