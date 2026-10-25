use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::Path;
use std::sync::Mutex;

use log::warn;
use openshield_core::TransactionSummary;
use openshield_core::logging::LogFormat;

pub struct AccessLog {
    format: LogFormat,
    writer: Mutex<Box<dyn Write + Send>>,
}

impl AccessLog {
    pub fn open(path: &Path, format: LogFormat) -> io::Result<Self> {
        let writer: Box<dyn Write + Send> = match path.to_str() {
            Some("/dev/stdout") => Box::new(io::stdout()),
            Some("/dev/stderr") => Box::new(io::stderr()),
            _ => Box::new(OpenOptions::new().create(true).append(true).open(path)?),
        };
        Ok(Self {
            format,
            writer: Mutex::new(writer),
        })
    }

    pub fn write(&self, summary: &TransactionSummary) {
        let line = match self.format {
            LogFormat::Json => {
                let mut buf = serde_json::to_vec(summary).unwrap_or_default();
                buf.push(b'\n');
                buf
            }
            LogFormat::Text => text_line(summary).into_bytes(),
        };
        let mut writer = self.writer.lock().unwrap();
        if let Err(e) = writer.write_all(&line) {
            warn!("Access log write failed: {e}");
        }
    }
}

fn text_line(s: &TransactionSummary) -> String {
    let error = s
        .error
        .as_ref()
        .map(|e| format!(" error={e}"))
        .unwrap_or_default();
    format!(
        "{} [{}] {} {} {} -> {} {:.3}ms waf={}{error}\n",
        s.timestamp,
        s.request_id,
        s.client_ip,
        s.method,
        s.path,
        s.status,
        s.duration_ms,
        s.waf_action,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_line_has_the_essentials() {
        let line = text_line(&TransactionSummary {
            request_id: "r1".into(),
            timestamp: "2026-01-01T00:00:00.000Z".into(),
            client_ip: "1.2.3.4".into(),
            method: "GET".into(),
            protocol: "HTTP/1.1".into(),
            host: "h".into(),
            path: "/x".into(),
            query: String::new(),
            status: 403,
            duration_ms: 1.5,
            bytes_received: 0,
            bytes_sent: 10,
            error: None,
            waf_action: "block".into(),
            waf_matched_rules: vec!["r".into()],
        });
        assert_eq!(
            line,
            "2026-01-01T00:00:00.000Z [r1] 1.2.3.4 GET /x -> 403 1.500ms waf=block\n"
        );
    }
}
