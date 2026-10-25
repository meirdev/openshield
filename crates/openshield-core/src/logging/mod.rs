mod format;
mod sink;

use std::collections::HashMap;
use std::path::PathBuf;

pub use format::{JsonFormatter, TextFormatter};
use serde::{Deserialize, Serialize};
pub use sink::FileSink;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    #[default]
    Json,
    Text,
}

impl LogFormat {
    pub fn formatter(self) -> Box<dyn Formatter> {
        match self {
            Self::Json => Box::new(JsonFormatter),
            Self::Text => Box::new(TextFormatter),
        }
    }
}

/// Where and how the audit log is written.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuditLogConfig {
    /// `/dev/stdout`, `/dev/stderr`, or a file that is appended to.
    pub path: PathBuf,
    pub format: LogFormat,
}

impl Default for AuditLogConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from("/dev/stderr"),
            format: LogFormat::Json,
        }
    }
}

/// Renders an entry as the bytes of one record, newline included.
pub trait Formatter: Send + Sync {
    fn format(&self, entry: &AuditLogEntry) -> Vec<u8>;
}

/// Receives audit entries. Hosts add their own, such as one forwarding to
/// the server's error log.
pub trait AuditSink: Send + Sync {
    fn write(&self, entry: &AuditLogEntry);
}

pub struct AuditLog {
    sinks: Vec<Box<dyn AuditSink>>,
}

impl AuditLog {
    /// An audit log writing to the configured file.
    pub fn new(config: &AuditLogConfig) -> std::io::Result<Self> {
        let sink = FileSink::open(&config.path, config.format.formatter())?;
        Ok(Self {
            sinks: vec![Box::new(sink)],
        })
    }

    pub fn add_sink(&mut self, sink: Box<dyn AuditSink>) {
        self.sinks.push(sink);
    }

    pub fn write(&self, entry: &AuditLogEntry) {
        for sink in &self.sinks {
            sink.write(entry);
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditLogEntry {
    pub request_id: String,
    pub timestamp: String,
    pub waf_action: String,
    pub waf_matched_rules: Vec<MatchedRule>,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub waf_scores: HashMap<String, i64>,
    #[serde(skip_serializing_if = "serde_json::Map::is_empty")]
    pub waf_payloads: serde_json::Map<String, serde_json::Value>,
    pub request: AuditRequest,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<AuditResponse>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MatchedRule {
    pub id: String,
    pub action: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditRequest {
    pub client_ip: String,
    pub method: String,
    pub protocol: String,
    pub host: String,
    pub path: String,
    pub query: String,
    /// In wire order; a name may repeat.
    pub headers: Vec<(String, String)>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    pub body_size: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditResponse {
    pub status: u16,
    /// In wire order; a name may repeat.
    pub headers: Vec<(String, String)>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    pub body_size: usize,
}
