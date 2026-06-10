use std::collections::HashMap;
use std::time::Instant;

use tokio::sync::mpsc;
use wirefilter_engine::ExecutionContext;

use super::metrics::ACTIVE_CONNECTIONS;
use crate::geoip::GeoIpLookup;

pub fn next_request_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Buffered body with size tracking and truncation.
pub struct BodyBuffer {
    pub buf: Vec<u8>,
    pub total_size: usize,
    pub truncated: bool,
    max_size: usize,
}

impl BodyBuffer {
    pub fn new(max_size: usize) -> Self {
        Self {
            buf: Vec::new(),
            total_size: 0,
            truncated: false,
            max_size,
        }
    }

    pub fn feed(&mut self, data: &[u8]) {
        self.total_size += data.len();
        if !self.truncated {
            let remaining = self.max_size.saturating_sub(self.buf.len());
            if data.len() <= remaining {
                self.buf.extend_from_slice(data);
            } else {
                self.buf.extend_from_slice(&data[..remaining]);
                self.truncated = true;
            }
        }
    }
}

pub use crate::waf::data::MultipartPartData;

/// A block decision made during a body phase, rendered later (in
/// `fail_to_proxy` for requests, or as a replacement response body for
/// responses).
#[derive(Clone)]
pub struct PendingBlock {
    pub status_code: u16,
    pub content_type: Option<String>,
    pub content: Option<String>,
}

pub struct RequestCtx {
    pub request_id: String,
    pub start: Instant,
    pub geo: Option<GeoIpLookup>,
    pub exec_ctx: ExecutionContext<'static>,
    pub req_body: BodyBuffer,
    pub res_body: BodyBuffer,
    pub multipart_tx: Option<mpsc::Sender<Result<bytes::Bytes, std::convert::Infallible>>>,
    pub multipart_task: Option<tokio::task::JoinHandle<Vec<MultipartPartData>>>,
    pub waf_scores: HashMap<String, i64>,
    pub waf_matched_rules: Vec<(String, String)>, // (rule_id, action)
    pub waf_payloads: serde_json::Map<String, serde_json::Value>,
    pub waf_action: String,
    pub waf_blocked: bool,

    /// Block decision from a body phase, rendered in `fail_to_proxy`.
    pub pending_block: Option<PendingBlock>,
    /// Request body bytes withheld from upstream pending an inspection verdict.
    pub req_body_pending: Vec<u8>,
    /// Once true, the request body buffer was released and remaining chunks
    /// stream straight through (process_partial after exceeding the limit).
    pub req_passthrough: bool,
    /// Response body bytes withheld from downstream pending a verdict.
    pub res_body_pending: Vec<u8>,
    /// Once true, the response body buffer was released and remaining chunks
    /// stream straight through.
    pub res_passthrough: bool,
    /// Once true, the response body matched a block rule and is being
    /// suppressed.
    pub res_blocked: bool,
}

impl Drop for RequestCtx {
    fn drop(&mut self) {
        if let Some(handle) = self.multipart_task.take() {
            handle.abort();
        }
        ACTIVE_CONNECTIONS.dec();
    }
}
