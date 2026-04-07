use super::{AccessLogEntry, AuditLogEntry, Formatter};

/// JSON formatter: one JSON object per line.
pub struct JsonFormatter;

impl Formatter for JsonFormatter {
    fn format_access(&self, entry: &AccessLogEntry) -> Vec<u8> {
        let mut buf = serde_json::to_vec(entry).unwrap_or_default();
        buf.push(b'\n');
        buf
    }

    fn format_audit(&self, entry: &AuditLogEntry) -> Vec<u8> {
        let mut buf = serde_json::to_vec(entry).unwrap_or_default();
        buf.push(b'\n');
        buf
    }
}

/// Human-readable text formatter.
pub struct TextFormatter;

impl Formatter for TextFormatter {
    fn format_access(&self, entry: &AccessLogEntry) -> Vec<u8> {
        let err = entry
            .error
            .as_ref()
            .map(|e| format!(" error={e}"))
            .unwrap_or_default();
        format!(
            "{} [{}] {} {} {} -> {} {:.3}ms{err}\n",
            entry.timestamp,
            entry.request_id,
            entry.client_ip,
            entry.method,
            entry.path,
            entry.status,
            entry.duration_ms,
        )
        .into_bytes()
    }

    fn format_audit(&self, entry: &AuditLogEntry) -> Vec<u8> {
        let mut buf = format!(
            "[AUDIT] {} [{}] action={} rules=[{}] scores=[{}]\n",
            entry.timestamp,
            entry.request_id,
            entry.waf_action,
            entry
                .waf_matched_rules
                .iter()
                .map(|r| format!("{}:{}", r.id, r.action))
                .collect::<Vec<_>>()
                .join(","),
            entry
                .waf_scores
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join(","),
        );
        for (k, v) in &entry.request.headers {
            buf.push_str(&format!("  req.{k}: {v}\n"));
        }
        if let Some(ref body) = entry.request.body {
            let truncated = if body.len() > 500 { &body[..500] } else { body };
            buf.push_str(&format!("  req.body: {truncated}\n"));
        }
        if let Some(ref resp) = entry.response {
            for (k, v) in &resp.headers {
                buf.push_str(&format!("  resp.{k}: {v}\n"));
            }
        }
        buf.into_bytes()
    }
}
