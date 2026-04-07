mod format;
mod sink;

use std::collections::HashMap;

pub use format::{JsonFormatter, TextFormatter};
use serde::Serialize;
pub use sink::{WriterSink, open_writer};

use crate::config::LoggingConfig;

/// Formats log entries into bytes.
pub trait Formatter: Send + Sync {
    fn format_access(&self, entry: &AccessLogEntry) -> Vec<u8>;
    fn format_audit(&self, entry: &AuditLogEntry) -> Vec<u8>;
}

/// Receives log events.
pub trait LogSink: Send + Sync {
    fn on_access(&self, entry: &AccessLogEntry);
    fn on_audit(&self, entry: &AuditLogEntry);
}

pub struct Logger {
    sinks: Vec<Box<dyn LogSink>>,
}

impl Logger {
    pub fn new(config: &LoggingConfig) -> Self {
        let formatter: Box<dyn Formatter> = match config.format.as_str() {
            "json" => Box::new(JsonFormatter),
            _ => Box::new(TextFormatter),
        };
        let sink = WriterSink::new(
            formatter,
            open_writer(&config.access_log),
            open_writer(&config.audit_log),
        );
        Self {
            sinks: vec![Box::new(sink)],
        }
    }

    #[allow(dead_code)]
    pub fn add_sink(&mut self, sink: Box<dyn LogSink>) {
        self.sinks.push(sink);
    }

    pub fn access(&self, entry: &AccessLogEntry) {
        for sink in &self.sinks {
            sink.on_access(entry);
        }
    }

    pub fn audit(&self, entry: &AuditLogEntry) {
        for sink in &self.sinks {
            sink.on_audit(entry);
        }
    }
}

#[derive(Serialize)]
pub struct AccessLogEntry {
    pub request_id: String,
    pub timestamp: String,
    pub client_ip: String,
    pub method: String,
    pub protocol: String,
    pub host: String,
    pub path: String,
    pub query: String,
    pub status: u16,
    pub duration_ms: f64,
    pub bytes_received: usize,
    pub bytes_sent: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Serialize)]
pub struct AuditLogEntry {
    pub request_id: String,
    pub timestamp: String,
    pub waf_action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub waf_rule_id: Option<String>,
    pub waf_matched_rules: Vec<MatchedRule>,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub waf_scores: HashMap<String, i64>,
    pub request: AuditRequest,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<AuditResponse>,
}

#[derive(Serialize)]
pub struct MatchedRule {
    pub id: String,
    pub action: String,
}

#[derive(Serialize)]
pub struct AuditRequest {
    pub client_ip: String,
    pub method: String,
    pub protocol: String,
    pub host: String,
    pub path: String,
    pub query: String,
    pub headers: HashMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    pub body_size: usize,
}

#[derive(Serialize)]
pub struct AuditResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    pub body_size: usize,
}
