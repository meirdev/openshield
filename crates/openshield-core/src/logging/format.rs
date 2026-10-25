use super::{AuditLogEntry, Formatter};

pub struct JsonFormatter;

impl Formatter for JsonFormatter {
    fn format(&self, entry: &AuditLogEntry) -> Vec<u8> {
        let mut buf = serde_json::to_vec(entry).unwrap_or_default();
        buf.push(b'\n');
        buf
    }
}

pub struct TextFormatter;

/// Longest body excerpt shown, in bytes.
const BODY_EXCERPT: usize = 500;

impl Formatter for TextFormatter {
    fn format(&self, entry: &AuditLogEntry) -> Vec<u8> {
        use std::fmt::Write as _;

        let req = &entry.request;
        let mut out = String::new();
        let target = if req.query.is_empty() {
            req.path.clone()
        } else {
            format!("{}?{}", req.path, req.query)
        };
        let status = entry
            .response
            .as_ref()
            .map_or_else(|| "-".to_string(), |r| r.status.to_string());
        let _ = writeln!(
            out,
            "{} [{}] {} {} {} \"{} {} {}\" -> {}",
            entry.timestamp,
            entry.request_id,
            entry.waf_action,
            req.client_ip,
            req.host,
            req.method,
            target,
            req.protocol,
            status
        );

        let rules: Vec<String> = entry
            .waf_matched_rules
            .iter()
            .map(|r| format!("{}:{}", r.id, r.action))
            .collect();
        let _ = writeln!(out, "  rules: {}", rules.join(", "));
        if !entry.waf_scores.is_empty() {
            let mut scores: Vec<String> = entry
                .waf_scores
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect();
            scores.sort_unstable();
            let _ = writeln!(out, "  scores: {}", scores.join(", "));
        }
        for (k, v) in &entry.waf_payloads {
            let _ = writeln!(out, "  payload {k}: {v}");
        }

        write_headers(&mut out, '>', &req.headers);
        write_body(&mut out, '>', req.body.as_deref(), req.body_size);
        if let Some(resp) = &entry.response {
            write_headers(&mut out, '<', &resp.headers);
            write_body(&mut out, '<', resp.body.as_deref(), resp.body_size);
        }
        out.into_bytes()
    }
}

fn write_headers(out: &mut String, mark: char, headers: &[(String, String)]) {
    use std::fmt::Write as _;
    for (name, value) in headers {
        let _ = writeln!(out, "  {mark} {name}: {value}");
    }
}

fn write_body(out: &mut String, mark: char, body: Option<&str>, size: usize) {
    use std::fmt::Write as _;
    let Some(body) = body else {
        if size > 0 {
            let _ = writeln!(out, "  {mark} body ({size} bytes, not captured)");
        }
        return;
    };
    let excerpt = excerpt(body, BODY_EXCERPT);
    let more = if excerpt.len() < body.len() {
        "…"
    } else {
        ""
    };
    let _ = writeln!(
        out,
        "  {mark} body ({size} bytes): {}{more}",
        excerpt.replace('\r', "\\r").replace('\n', "\\n")
    );
}

/// The longest prefix of `s` within `max` bytes that ends on a character
/// boundary.
fn excerpt(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::super::{AuditRequest, AuditResponse, MatchedRule};
    use super::*;

    fn entry() -> AuditLogEntry {
        AuditLogEntry {
            request_id: "7f3c".into(),
            timestamp: "2026-10-25T10:00:00.000Z".into(),
            waf_action: "block".into(),
            waf_matched_rules: vec![
                MatchedRule {
                    id: "admin".into(),
                    action: "block".into(),
                },
                MatchedRule {
                    id: "942100".into(),
                    action: "log".into(),
                },
            ],
            waf_scores: HashMap::from([("sqli".to_string(), 10)]),
            waf_payloads: serde_json::Map::from_iter([(
                "http.request.uri.path".to_string(),
                serde_json::Value::String("/admin".into()),
            )]),
            request: AuditRequest {
                client_ip: "10.0.0.1".into(),
                method: "POST".into(),
                protocol: "HTTP/1.1".into(),
                host: "example.com".into(),
                path: "/admin".into(),
                query: "x=1".into(),
                headers: vec![
                    ("content-type".to_string(), "text/plain".to_string()),
                    ("user-agent".to_string(), "curl".to_string()),
                    ("cookie".to_string(), "a=1".to_string()),
                    ("cookie".to_string(), "b=2".to_string()),
                ],
                body: Some("pay\nload".into()),
                body_size: 8,
            },
            response: Some(AuditResponse {
                status: 418,
                headers: vec![("content-type".to_string(), "text/plain".to_string())],
                body: None,
                body_size: 4,
            }),
        }
    }

    #[test]
    fn text_record_is_a_summary_line_plus_details() {
        let text = String::from_utf8(TextFormatter.format(&entry())).unwrap();
        assert_eq!(
            text,
            "2026-10-25T10:00:00.000Z [7f3c] block 10.0.0.1 example.com \"POST /admin?x=1 HTTP/1.1\" -> 418\n\
             \x20 rules: admin:block, 942100:log\n\
             \x20 scores: sqli=10\n\
             \x20 payload http.request.uri.path: \"/admin\"\n\
             \x20 > content-type: text/plain\n\
             \x20 > user-agent: curl\n\
             \x20 > cookie: a=1\n\
             \x20 > cookie: b=2\n\
             \x20 > body (8 bytes): pay\\nload\n\
             \x20 < content-type: text/plain\n\
             \x20 < body (4 bytes, not captured)\n"
        );
    }

    #[test]
    fn empty_parts_are_omitted() {
        let mut e = entry();
        e.waf_scores.clear();
        e.waf_payloads.clear();
        e.request.query.clear();
        e.request.body = None;
        e.request.body_size = 0;
        e.response = None;
        let text = String::from_utf8(TextFormatter.format(&e)).unwrap();
        assert_eq!(
            text,
            "2026-10-25T10:00:00.000Z [7f3c] block 10.0.0.1 example.com \"POST /admin HTTP/1.1\" -> -\n\
             \x20 rules: admin:block, 942100:log\n\
             \x20 > content-type: text/plain\n\
             \x20 > user-agent: curl\n\
             \x20 > cookie: a=1\n\
             \x20 > cookie: b=2\n"
        );
    }

    #[test]
    fn body_excerpt_respects_character_boundaries() {
        let body = "é".repeat(400); // 800 bytes
        let mut e = entry();
        e.request.body = Some(body.clone());
        e.request.body_size = body.len();
        let text = String::from_utf8(TextFormatter.format(&e)).unwrap();
        let line = text.lines().find(|l| l.starts_with("  > body")).unwrap();
        assert!(line.ends_with('…'));
        assert_eq!(excerpt(&body, BODY_EXCERPT).len(), 500);
        assert_eq!(excerpt("abc", 2), "ab");
        assert_eq!(excerpt("abc", 3), "abc");
    }

    #[test]
    fn json_is_one_object_per_line() {
        let bytes = JsonFormatter.format(&entry());
        assert!(bytes.ends_with(b"\n"));
        let v: serde_json::Value = serde_json::from_slice(&bytes[..bytes.len() - 1]).unwrap();
        assert_eq!(v["waf_action"], "block");
        assert_eq!(v["request"]["path"], "/admin");
        // Headers keep wire order and repeated names.
        assert_eq!(
            v["request"]["headers"][2],
            serde_json::json!(["cookie", "a=1"])
        );
        assert_eq!(
            v["request"]["headers"][3],
            serde_json::json!(["cookie", "b=2"])
        );
    }
}
