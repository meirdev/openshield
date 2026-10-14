use pingora::proxy::Session;

/// Set upstream proxy headers (Host, X-Forwarded-*, X-Real-IP).
pub fn set_upstream_headers(
    session: &Session,
    upstream_request: &mut pingora::http::RequestHeader,
    upstream_host: &str,
    upstream_port: u16,
) {
    let host = if upstream_port == 443 || upstream_port == 80 {
        upstream_host.to_string()
    } else {
        format!("{upstream_host}:{upstream_port}")
    };
    let _ = upstream_request.insert_header("Host", &host);

    let client_ip_str = session
        .client_addr()
        .and_then(|a| a.as_inet().map(|s| s.ip().to_string()))
        .unwrap_or_default();

    if !client_ip_str.is_empty() {
        let xff = match session.req_header().headers.get("X-Forwarded-For") {
            Some(existing) => {
                format!("{}, {client_ip_str}", existing.to_str().unwrap_or_default())
            }
            None => client_ip_str.clone(),
        };
        let _ = upstream_request.insert_header("X-Forwarded-For", &xff);
    }

    let proto = if session.digest().map_or(false, |d| d.ssl_digest.is_some()) {
        "https"
    } else {
        "http"
    };
    let _ = upstream_request.insert_header("X-Forwarded-Proto", proto);

    if let Some(orig_host) = session.req_header().headers.get("Host") {
        let _ = upstream_request
            .insert_header("X-Forwarded-Host", orig_host.to_str().unwrap_or_default());
    }

    if !client_ip_str.is_empty() {
        let _ = upstream_request.insert_header("X-Real-IP", &client_ip_str);
    }
}
