use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::sync::Mutex;

use log::warn;

use super::{AuditLogEntry, AuditSink, Formatter};

pub struct FileSink {
    formatter: Box<dyn Formatter>,
    target: Mutex<Target>,
}

enum Target {
    Stdout,
    Stderr,
    File(File),
}

impl FileSink {
    pub fn open(path: &Path, formatter: Box<dyn Formatter>) -> io::Result<Self> {
        let target = match path.to_str() {
            Some("/dev/stdout") => Target::Stdout,
            Some("/dev/stderr") => Target::Stderr,
            _ => Target::File(OpenOptions::new().create(true).append(true).open(path)?),
        };
        Ok(Self {
            formatter,
            target: Mutex::new(target),
        })
    }
}

impl AuditSink for FileSink {
    fn write(&self, entry: &AuditLogEntry) {
        let bytes = self.formatter.format(entry);
        let mut target = self.target.lock().unwrap();
        let result = match &mut *target {
            Target::Stdout => io::stdout().lock().write_all(&bytes),
            Target::Stderr => io::stderr().lock().write_all(&bytes),
            Target::File(file) => write_locked(file, &bytes),
        };
        if let Err(e) = result {
            warn!("Audit log write failed: {e}");
        }
    }
}

fn write_locked(file: &mut File, bytes: &[u8]) -> io::Result<()> {
    file.lock()?;
    let written = file.write_all(bytes);
    let unlocked = file.unlock();
    written.and(unlocked)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use super::super::{AuditRequest, JsonFormatter};
    use super::*;

    fn entry(id: &str, padding: usize) -> AuditLogEntry {
        AuditLogEntry {
            request_id: id.to_string(),
            timestamp: "t".into(),
            waf_action: "block".into(),
            waf_matched_rules: Vec::new(),
            waf_scores: HashMap::new(),
            waf_payloads: serde_json::Map::new(),
            request: AuditRequest {
                client_ip: "1.2.3.4".into(),
                method: "GET".into(),
                protocol: "HTTP/1.1".into(),
                host: "h".into(),
                path: "x".repeat(padding),
                query: String::new(),
                headers: Vec::new(),
                body: None,
                body_size: 0,
            },
            response: None,
        }
    }

    #[test]
    fn concurrent_writers_never_interleave_records() {
        let dir = std::env::temp_dir().join(format!("openshield-audit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.log");

        // Two sinks on the same path stand in for two processes: they share
        // nothing but the file and its lock. Records are larger than a pipe
        // buffer so unlocked writes could be split.
        let sinks: Vec<Arc<FileSink>> = (0..2)
            .map(|_| Arc::new(FileSink::open(&path, Box::new(JsonFormatter)).unwrap()))
            .collect();
        let threads: Vec<_> = sinks
            .iter()
            .enumerate()
            .map(|(i, sink)| {
                let sink = Arc::clone(sink);
                std::thread::spawn(move || {
                    for n in 0..200 {
                        sink.write(&entry(&format!("{i}-{n}"), 20_000));
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }

        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 400);
        for line in lines {
            let v: serde_json::Value = serde_json::from_str(line).expect("intact JSON record");
            assert_eq!(v["request"]["path"].as_str().unwrap().len(), 20_000);
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
