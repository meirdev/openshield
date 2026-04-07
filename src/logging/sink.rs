use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;

use super::{AccessLogEntry, AuditLogEntry, Formatter, LogSink};

/// A sink that writes formatted log entries to `Write` destinations.
pub struct WriterSink {
    formatter: Box<dyn Formatter>,
    access_writer: Mutex<Box<dyn Write + Send>>,
    audit_writer: Mutex<Box<dyn Write + Send>>,
}

impl WriterSink {
    pub fn new(
        formatter: Box<dyn Formatter>,
        access_writer: Box<dyn Write + Send>,
        audit_writer: Box<dyn Write + Send>,
    ) -> Self {
        Self {
            formatter,
            access_writer: Mutex::new(access_writer),
            audit_writer: Mutex::new(audit_writer),
        }
    }
}

impl LogSink for WriterSink {
    fn on_access(&self, entry: &AccessLogEntry) {
        let bytes = self.formatter.format_access(entry);
        let mut writer = self.access_writer.lock().unwrap();
        let _ = writer.write_all(&bytes);
    }

    fn on_audit(&self, entry: &AuditLogEntry) {
        let bytes = self.formatter.format_audit(entry);
        let mut writer = self.audit_writer.lock().unwrap();
        let _ = writer.write_all(&bytes);
    }
}

pub fn open_writer(path: &Path) -> Box<dyn Write + Send> {
    match path.to_str() {
        Some("/dev/stdout") => Box::new(std::io::stdout()),
        Some("/dev/stderr") => Box::new(std::io::stderr()),
        _ => {
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .unwrap_or_else(|e| panic!("Failed to open log file {:?}: {}", path, e));
            Box::new(file)
        }
    }
}
