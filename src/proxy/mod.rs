pub mod context;
pub mod headers;
pub mod metrics;

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use context::{BodyBuffer, PendingBlock, RequestCtx};
use metrics::{ACTIVE_CONNECTIONS, BYTES_RECEIVED, BYTES_SENT, TOTAL_REQUESTS};
use pingora::prelude::*;
use pingora::proxy::{ProxyHttp, Session};

use crate::challenge::ChallengeManager;
use crate::config::BodyLimitAction;
use crate::geoip::GeoIp;
use crate::logging::{
    AccessLogEntry, AuditLogEntry, AuditRequest, AuditResponse, Logger, MatchedRule,
};
use crate::waf::data::{MultipartPartData, RequestData, ResponseData};
use crate::waf::engine::{Engine, Phase, RuleAction};
use crate::waf::lists::{BytesListMatcher, IpListMatcher};
use crate::waf::populate;

pub struct ReverseProxyHandler {
    pub detection_only: bool,
    pub upstream_tls: bool,
    pub upstream_host: String,
    pub upstream_port: u16,
    pub geoip: Option<GeoIp>,
    pub scheme: Arc<wirefilter_engine::Scheme>,
    pub engine: Engine,
    pub max_request_body_buffer: usize,
    pub request_body_limit_action: BodyLimitAction,
    pub inspect_response_body: bool,
    pub max_response_body_buffer: usize,
    pub response_body_limit_action: BodyLimitAction,
    pub ip_lists: Arc<IpListMatcher>,
    pub bytes_lists: Arc<BytesListMatcher>,
    pub challenge: Option<Arc<ChallengeManager>>,
    pub logger: Arc<Logger>,
    pub has_request_body_rules: bool,
    pub has_response_body_rules: bool,
}

fn evaluate_phase(
    handler: &ReverseProxyHandler,
    ctx: &mut RequestCtx,
    phase: &Phase,
) -> RuleAction {
    crate::waf::engine::sync_scores(&mut ctx.exec_ctx, &handler.scheme, &ctx.waf_scores);
    let action = handler.engine.evaluate(
        phase,
        &ctx.exec_ctx,
        &mut ctx.waf_scores,
        &mut ctx.waf_matched_rules,
        &mut ctx.waf_payloads,
    );

    match &action {
        RuleAction::Block { rule_id, .. } => {
            ctx.waf_matched_rules
                .push((rule_id.clone(), "block".into()));
            ctx.waf_action = "block".into();
        }
        RuleAction::Allow { rule_id } => {
            ctx.waf_matched_rules
                .push((rule_id.clone(), "allow".into()));
            ctx.waf_action = "allow".into();
        }
        RuleAction::Challenge { rule_id } => {
            ctx.waf_matched_rules
                .push((rule_id.clone(), "challenge".into()));
            ctx.waf_action = "challenge".into();
        }
        RuleAction::NoMatch => {}
    }

    if handler.detection_only {
        RuleAction::NoMatch
    } else {
        action
    }
}

/// Populate request-body wirefilter fields (form/multipart/raw) from the
/// buffer.
async fn finalize_request_body(
    handler: &ReverseProxyHandler,
    session: &mut Session,
    ctx: &mut RequestCtx,
) {
    let content_type = session
        .req_header()
        .headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    populate::body_fields(
        &mut ctx.exec_ctx,
        &handler.scheme,
        &ctx.req_body.buf,
        ctx.req_body.total_size,
        ctx.req_body.truncated,
        content_type.as_deref(),
    );

    if let Some(tx) = ctx.multipart_tx.take() {
        drop(tx);
        if let Some(handle) = ctx.multipart_task.take() {
            if let Ok(parts) = handle.await {
                populate::multipart_fields(&mut ctx.exec_ctx, &handler.scheme, &parts);
            }
        }
    }
}

/// Populate response-body wirefilter fields from the buffer.
fn finalize_response_body(handler: &ReverseProxyHandler, ctx: &mut RequestCtx) {
    populate::response_body_fields(
        &mut ctx.exec_ctx,
        &handler.scheme,
        &ctx.res_body.buf,
        ctx.res_body.total_size,
        ctx.res_body.truncated,
    );
}

/// Evaluate a body phase and translate a Block action into a [`PendingBlock`].
///
/// Note: this runs the phase, so it has the usual side effects (scores,
/// matched-rules, payload capture) regardless of the returned decision.
fn evaluate_body_phase(
    handler: &ReverseProxyHandler,
    ctx: &mut RequestCtx,
    phase: &Phase,
) -> Option<PendingBlock> {
    match evaluate_phase(handler, ctx, phase) {
        RuleAction::Block {
            status_code,
            content_type,
            content,
            ..
        } => Some(PendingBlock {
            status_code,
            content_type,
            content,
        }),
        _ => None,
    }
}

/// Suppress a response body that matched a ResponseBody block rule, replacing
/// it with the rule's block content. The response status/headers were already
/// sent downstream, so only the body bytes can change here —
/// `PendingBlock.status_code` and `content_type` are ignored on this path; only
/// `content` is used.
fn suppress_response_body(body: &mut Option<bytes::Bytes>, ctx: &mut RequestCtx, pb: PendingBlock) {
    ctx.res_blocked = true;
    ctx.res_body_pending.clear();
    ctx.waf_blocked = true;
    let content = pb.content.unwrap_or_default().into_bytes();
    BYTES_SENT.inc_by(content.len() as u64);
    *body = Some(bytes::Bytes::from(content));
}

fn extract_request_data(session: &Session, geo: &Option<crate::geoip::GeoIpLookup>) -> RequestData {
    let req = session.req_header();
    let headers: Vec<(String, String)> = req
        .headers
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    let is_tls = session.digest().map_or(false, |d| d.ssl_digest.is_some());
    let host = req
        .headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .or_else(|| req.uri.host())
        .unwrap_or("")
        .to_string();
    let path = req.uri.path().to_string();
    let query = req.uri.query().unwrap_or("").to_string();
    let scheme_str = req
        .uri
        .scheme_str()
        .unwrap_or(if is_tls { "https" } else { "http" });
    let full_uri = if query.is_empty() {
        format!("{scheme_str}://{host}{path}")
    } else {
        format!("{scheme_str}://{host}{path}?{query}")
    };
    let uri = if query.is_empty() {
        path.clone()
    } else {
        format!("{path}?{query}")
    };
    let after_slash = path.rsplit_once('/').map(|(_, f)| f).unwrap_or(&path);
    let extension = after_slash
        .rsplit_once('.')
        .map(|(_, ext)| ext)
        .unwrap_or("")
        .to_string();

    RequestData {
        client_ip: client_ip(session),
        is_tls,
        method: req.method.as_str().to_string(),
        version: format!("{:?}", req.version),
        host,
        full_uri,
        uri,
        path,
        query,
        extension,
        headers,
        geo: geo.as_ref().map(|g| crate::waf::data::GeoData {
            asn: g.as_num,
            city: g.city.clone(),
            continent: g.continent.clone(),
            country: g.country.clone(),
            lat: g.lat,
            lon: g.lon,
            metro_code: g.metro_code,
            postal_code: g.postal_code.clone(),
            region: g.region.clone(),
            region_code: g.region_code.clone(),
            timezone: g.timezone.clone(),
        }),
    }
}

fn extract_response_data(resp: &pingora::http::ResponseHeader) -> ResponseData {
    let headers: Vec<(String, String)> = resp
        .headers
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    ResponseData {
        status: resp.status.as_u16(),
        headers,
    }
}

fn spawn_multipart_parser(
    boundary: String,
) -> (
    tokio::sync::mpsc::Sender<Result<bytes::Bytes, std::convert::Infallible>>,
    tokio::task::JoinHandle<Vec<MultipartPartData>>,
) {
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<bytes::Bytes, std::convert::Infallible>>(16);
    let handle = tokio::spawn(async move {
        let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
        let mut multipart = multer::Multipart::new(stream, boundary);
        let mut parts = Vec::new();
        while let Ok(Some(field)) = multipart.next_field().await {
            let name = field.name().map(String::from);
            let filename = field.file_name().map(String::from);
            let content_type = field.content_type().map(|m| m.to_string());
            let content_disposition = field
                .headers()
                .get("content-disposition")
                .and_then(|v| v.to_str().ok())
                .map(String::from);
            let content_transfer_encoding = field
                .headers()
                .get("content-transfer-encoding")
                .and_then(|v| v.to_str().ok())
                .map(String::from);
            let value = field.text().await.unwrap_or_default();
            parts.push(MultipartPartData {
                name,
                filename,
                content_type,
                content_disposition,
                content_transfer_encoding,
                value,
            });
        }
        parts
    });
    (tx, handle)
}

async fn send_block_response(
    session: &mut Session,
    status_code: u16,
    content_type: Option<&str>,
    content: Option<&str>,
) {
    let code = http::StatusCode::from_u16(status_code).unwrap_or(http::StatusCode::FORBIDDEN);
    let body = content.unwrap_or("").as_bytes();
    let ct = content_type.unwrap_or("text/plain");

    let mut resp_header = pingora::http::ResponseHeader::build(code, Some(3)).unwrap();
    let _ = resp_header.insert_header("Content-Type", ct);
    let _ = resp_header.insert_header("Content-Length", body.len().to_string());
    let _ = session
        .write_response_header(Box::new(resp_header), false)
        .await;
    let _ = session
        .write_response_body(Some(bytes::Bytes::copy_from_slice(body)), true)
        .await;
}

async fn send_challenge_page(session: &mut Session, cm: &ChallengeManager) {
    let body = cm.challenge_page().as_bytes();
    let mut resp =
        pingora::http::ResponseHeader::build(http::StatusCode::FORBIDDEN, Some(3)).unwrap();
    let _ = resp.insert_header("Content-Type", "text/html; charset=utf-8");
    let _ = resp.insert_header("Content-Length", body.len().to_string());
    let _ = resp.insert_header("Cache-Control", "no-store");
    let _ = session.write_response_header(Box::new(resp), false).await;
    let _ = session
        .write_response_body(Some(bytes::Bytes::copy_from_slice(body)), true)
        .await;
}

fn client_ip(session: &Session) -> Option<IpAddr> {
    session
        .client_addr()
        .and_then(|a| a.as_inet().map(|s| s.ip()))
}

impl ReverseProxyHandler {
    async fn handle_challenge_verify(
        &self,
        session: &mut Session,
        ctx: &mut RequestCtx,
        cm: &ChallengeManager,
    ) -> Result<bool> {
        // Read the POST body to get the Turnstile token
        let mut body_buf = Vec::new();
        loop {
            let body = session.read_request_body().await?;
            match body {
                Some(data) => {
                    body_buf.extend_from_slice(&data);
                    if body_buf.len() > 8192 {
                        break;
                    }
                }
                None => break,
            }
        }

        let params: Vec<(String, String)> = form_urlencoded::parse(&body_buf)
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();

        let token = params
            .iter()
            .find(|(k, _)| k == "cf-turnstile-response")
            .map(|(_, v)| v.as_str());
        let redirect = params
            .iter()
            .find(|(k, _)| k == "redirect")
            .map(|(_, v)| v.as_str());

        let client_ip_str = client_ip(session)
            .map(|ip| ip.to_string())
            .unwrap_or_default();

        if let Some(token) = token {
            if cm.verify_turnstile(token, &client_ip_str).await {
                // Verification passed — set cookie and redirect
                let cookie = cm.create_cookie(&client_ip_str);
                let location = redirect.unwrap_or("/");
                let mut resp =
                    pingora::http::ResponseHeader::build(http::StatusCode::FOUND, Some(3)).unwrap();
                let _ = resp.insert_header("Location", location);
                let _ = resp.insert_header("Set-Cookie", &cookie);
                let _ = resp.insert_header("Cache-Control", "no-store");
                let _ = session.write_response_header(Box::new(resp), true).await;
                ctx.waf_blocked = true;
                return Ok(true);
            }
        }

        // Verification failed — show challenge again
        send_challenge_page(session, cm).await;
        ctx.waf_blocked = true;
        Ok(true)
    }
}

#[async_trait]
impl ProxyHttp for ReverseProxyHandler {
    type CTX = RequestCtx;

    fn new_ctx(&self) -> Self::CTX {
        TOTAL_REQUESTS.inc();
        ACTIVE_CONNECTIONS.inc();
        RequestCtx {
            request_id: context::next_request_id(),
            start: Instant::now(),
            geo: None,
            exec_ctx: {
                let mut ctx = wirefilter_engine::ExecutionContext::new(&self.scheme);
                if let Some(list_ref) = self.scheme.get_list(&wirefilter_engine::Type::Ip) {
                    let matcher = ctx.get_list_matcher_mut(list_ref);
                    let ip_matcher = matcher
                        .as_any_mut()
                        .downcast_mut::<IpListMatcher>()
                        .unwrap();
                    *ip_matcher = (*self.ip_lists).clone();
                }
                if let Some(list_ref) = self.scheme.get_list(&wirefilter_engine::Type::Bytes) {
                    let matcher = ctx.get_list_matcher_mut(list_ref);
                    let bytes_matcher = matcher
                        .as_any_mut()
                        .downcast_mut::<BytesListMatcher>()
                        .unwrap();
                    *bytes_matcher = (*self.bytes_lists).clone();
                }
                ctx
            },
            req_body: BodyBuffer::new(self.max_request_body_buffer),
            multipart_tx: None,
            multipart_task: None,
            res_body: BodyBuffer::new(self.max_response_body_buffer),
            waf_scores: HashMap::new(),
            waf_matched_rules: Vec::new(),
            waf_payloads: serde_json::Map::new(),
            waf_action: "pass".into(),
            waf_blocked: false,
            pending_block: None,
            req_body_pending: Vec::new(),
            req_passthrough: false,
            res_body_pending: Vec::new(),
            res_passthrough: false,
            res_blocked: false,
        }
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        // Handle challenge verification POST
        if let Some(ref cm) = self.challenge {
            let req = session.req_header();
            if req.method == http::Method::POST && req.uri.path() == cm.challenge_path() {
                return self.handle_challenge_verify(session, ctx, cm).await;
            }
        }

        if let Some(ip) = client_ip(session) {
            if let Some(ref g) = self.geoip {
                ctx.geo = Some(g.lookup(ip));
            }
        }
        let req_data = extract_request_data(session, &ctx.geo);
        populate::request_fields(&mut ctx.exec_ctx, &self.scheme, &req_data);

        if let Some(ct) = session
            .req_header()
            .headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
        {
            if let Ok(boundary) = multer::parse_boundary(ct) {
                let (tx, handle) = spawn_multipart_parser(boundary);
                ctx.multipart_tx = Some(tx);
                ctx.multipart_task = Some(handle);
            }
        }

        match evaluate_phase(self, ctx, &Phase::RequestHeaders) {
            RuleAction::Block {
                status_code,
                content_type,
                content,
                ..
            } => {
                send_block_response(
                    session,
                    status_code,
                    content_type.as_deref(),
                    content.as_deref(),
                )
                .await;
                ctx.waf_blocked = true;
                return Ok(true);
            }
            RuleAction::Allow { .. } => return Ok(false),
            RuleAction::Challenge { .. } => {
                if let Some(ref cm) = self.challenge {
                    let client_ip_str = client_ip(session)
                        .map(|ip| ip.to_string())
                        .unwrap_or_default();
                    let cookie_header = session
                        .req_header()
                        .headers
                        .get("cookie")
                        .and_then(|v| v.to_str().ok());
                    if !cm.is_verified(cookie_header, &client_ip_str) {
                        send_challenge_page(session, cm).await;
                        ctx.waf_blocked = true;
                        return Ok(true);
                    }
                }
            }
            RuleAction::NoMatch => {}
        }

        Ok(false)
    }

    async fn request_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<bytes::Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        // Fast path: no RequestBody-phase rules. Stream chunks through unchanged,
        // keeping a capped copy for audit/field population (original behavior).
        if !self.has_request_body_rules {
            if let Some(data) = body.as_ref() {
                BYTES_RECEIVED.inc_by(data.len() as u64);
                ctx.req_body.feed(data);
                if let Some(ref tx) = ctx.multipart_tx {
                    let _ = tx.send(Ok(data.clone())).await;
                }
            }
            if end_of_stream {
                finalize_request_body(self, session, ctx).await;
            }
            return Ok(());
        }

        // Already released to upstream (process_partial past the limit): pass through.
        if ctx.req_passthrough {
            if let Some(data) = body.as_ref() {
                BYTES_RECEIVED.inc_by(data.len() as u64);
            }
            return Ok(());
        }

        // Inspection mode: accumulate and withhold from upstream until a verdict.
        if let Some(data) = body.as_ref() {
            BYTES_RECEIVED.inc_by(data.len() as u64);
            ctx.req_body.feed(data);
            ctx.req_body_pending.extend_from_slice(data);
            if let Some(ref tx) = ctx.multipart_tx {
                let _ = tx.send(Ok(data.clone())).await;
            }
        }

        // Body exceeded the buffer limit before the stream ended.
        if !end_of_stream && ctx.req_body.truncated {
            match self.request_body_limit_action {
                BodyLimitAction::Reject => {
                    ctx.pending_block = Some(PendingBlock {
                        status_code: 413,
                        content_type: None,
                        content: Some("request body too large".into()),
                    });
                    ctx.waf_action = "block".into();
                    return Err(pingora::Error::new(pingora::ErrorType::HTTPStatus(413)));
                }
                BodyLimitAction::ProcessPartial => {
                    finalize_request_body(self, session, ctx).await;
                    if let Some(pb) = evaluate_body_phase(self, ctx, &Phase::RequestBody) {
                        ctx.pending_block = Some(pb);
                        // Status/content come from pending_block in fail_to_proxy; the
                        // error code here only signals "abort proxying".
                        return Err(pingora::Error::new(pingora::ErrorType::HTTPStatus(403)));
                    }
                    // Allowed: release what we buffered, stream the remainder uninspected.
                    *body = Some(bytes::Bytes::from(std::mem::take(
                        &mut ctx.req_body_pending,
                    )));
                    ctx.req_passthrough = true;
                    return Ok(());
                }
            }
        }

        if end_of_stream {
            finalize_request_body(self, session, ctx).await;
            if let Some(pb) = evaluate_body_phase(self, ctx, &Phase::RequestBody) {
                ctx.pending_block = Some(pb);
                // Status/content come from pending_block in fail_to_proxy; the
                // error code here only signals "abort proxying".
                return Err(pingora::Error::new(pingora::ErrorType::HTTPStatus(403)));
            }
            // Allowed: release the full buffered body as the final chunk.
            *body = Some(bytes::Bytes::from(std::mem::take(
                &mut ctx.req_body_pending,
            )));
            return Ok(());
        }

        // Withhold this chunk. An empty chunk (not None) avoids signalling
        // end-of-body to the upstream (`upstream_end_of_body = end || data.is_none()`).
        *body = Some(bytes::Bytes::new());
        Ok(())
    }

    async fn fail_to_proxy(
        &self,
        session: &mut Session,
        e: &pingora::Error,
        ctx: &mut Self::CTX,
    ) -> pingora::proxy::FailToProxy
    where
        Self::CTX: Send + Sync,
    {
        // A body-phase rule asked to block: render the configured block response.
        if let Some(pb) = ctx.pending_block.take() {
            let code = pb.status_code;
            send_block_response(
                session,
                pb.status_code,
                pb.content_type.as_deref(),
                pb.content.as_deref(),
            )
            .await;
            ctx.waf_blocked = true;
            return pingora::proxy::FailToProxy {
                error_code: code,
                can_reuse_downstream: false,
            };
        }

        // Otherwise mirror pingora's default error handling.
        let code = match e.etype() {
            pingora::ErrorType::HTTPStatus(code) => *code,
            _ => match e.esource() {
                pingora::ErrorSource::Upstream => 502,
                pingora::ErrorSource::Downstream => match e.etype() {
                    pingora::ErrorType::WriteError
                    | pingora::ErrorType::ReadError
                    | pingora::ErrorType::ConnectionClosed => 0,
                    _ => 400,
                },
                pingora::ErrorSource::Internal | pingora::ErrorSource::Unset => 500,
            },
        };
        if code > 0 {
            let _ = session.respond_error(code).await;
        }
        pingora::proxy::FailToProxy {
            error_code: code,
            can_reuse_downstream: false,
        }
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let peer = Box::new(HttpPeer::new(
            (&*self.upstream_host, self.upstream_port),
            self.upstream_tls,
            self.upstream_host.clone(),
        ));
        Ok(peer)
    }

    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut pingora::http::RequestHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<()> {
        headers::set_upstream_headers(
            session,
            upstream_request,
            &self.upstream_host,
            self.upstream_port,
        );
        Ok(())
    }

    async fn upstream_response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut pingora::http::ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        let resp_data = extract_response_data(upstream_response);
        populate::response_fields(&mut ctx.exec_ctx, &self.scheme, &resp_data);
        evaluate_phase(self, ctx, &Phase::ResponseHeaders);
        // If a ResponseBody rule might rewrite/suppress the body, drop
        // Content-Length so the (possibly altered) body can be re-framed as chunked.
        if self.inspect_response_body && self.has_response_body_rules {
            upstream_response.remove_header(http::header::CONTENT_LENGTH.as_str());
        }
        Ok(())
    }

    fn response_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<bytes::Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<Option<std::time::Duration>> {
        // Fast path: not inspecting, or no ResponseBody rules to act on. Stream
        // through, evaluating only for side effects (score/log/payload), as before.
        if !self.inspect_response_body || !self.has_response_body_rules {
            if let Some(data) = body.as_ref() {
                BYTES_SENT.inc_by(data.len() as u64);
            }
            if self.inspect_response_body {
                if let Some(data) = body.as_ref() {
                    ctx.res_body.feed(data);
                }
                if end_of_stream {
                    finalize_response_body(self, ctx);
                    evaluate_phase(self, ctx, &Phase::ResponseBody);
                }
            }
            return Ok(None);
        }

        // Already suppressing a blocked response: drop remaining upstream body.
        if ctx.res_blocked {
            *body = Some(bytes::Bytes::new());
            return Ok(None);
        }
        // Already released (process_partial past the limit): stream the rest.
        if ctx.res_passthrough {
            if let Some(data) = body.as_ref() {
                BYTES_SENT.inc_by(data.len() as u64);
            }
            return Ok(None);
        }

        // Inspection mode: accumulate and withhold from downstream until a verdict.
        if let Some(data) = body.as_ref() {
            ctx.res_body.feed(data);
            ctx.res_body_pending.extend_from_slice(data);
        }

        // Body exceeded the buffer limit before the response ended.
        if !end_of_stream && ctx.res_body.truncated {
            match self.response_body_limit_action {
                BodyLimitAction::Reject => {
                    let pb = PendingBlock {
                        status_code: 0,
                        content_type: None,
                        content: Some("response blocked".into()),
                    };
                    suppress_response_body(body, ctx, pb);
                    return Ok(None);
                }
                BodyLimitAction::ProcessPartial => {
                    finalize_response_body(self, ctx);
                    if let Some(pb) = evaluate_body_phase(self, ctx, &Phase::ResponseBody) {
                        suppress_response_body(body, ctx, pb);
                        return Ok(None);
                    }
                    // Allowed: release buffered bytes, stream the remainder uninspected.
                    let pending = std::mem::take(&mut ctx.res_body_pending);
                    BYTES_SENT.inc_by(pending.len() as u64);
                    *body = Some(bytes::Bytes::from(pending));
                    ctx.res_passthrough = true;
                    return Ok(None);
                }
            }
        }

        if end_of_stream {
            finalize_response_body(self, ctx);
            if let Some(pb) = evaluate_body_phase(self, ctx, &Phase::ResponseBody) {
                suppress_response_body(body, ctx, pb);
                return Ok(None);
            }
            // Allowed: release the full buffered body as the final chunk.
            let pending = std::mem::take(&mut ctx.res_body_pending);
            BYTES_SENT.inc_by(pending.len() as u64);
            *body = Some(bytes::Bytes::from(pending));
            return Ok(None);
        }

        // Withhold this chunk (empty, not None) until a verdict is reached.
        *body = Some(bytes::Bytes::new());
        Ok(None)
    }

    async fn logging(
        &self,
        session: &mut Session,
        error: Option<&pingora::Error>,
        ctx: &mut Self::CTX,
    ) {
        evaluate_phase(self, ctx, &Phase::Logging);

        let elapsed = ctx.start.elapsed();
        let status = session
            .response_written()
            .map(|r| r.status.as_u16())
            .unwrap_or(0);
        let req = session.req_header();
        let method = req.method.as_str().to_string();
        let host = req
            .headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("-")
            .to_string();
        let path = req.uri.path().to_string();
        let query = req.uri.query().unwrap_or("").to_string();
        let client_ip_str = session
            .client_addr()
            .and_then(|a| a.as_inet().map(|s| s.ip().to_string()))
            .unwrap_or_else(|| "-".into());
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

        let access = AccessLogEntry {
            request_id: ctx.request_id.clone(),
            timestamp: now.clone(),
            client_ip: client_ip_str,
            method: method.clone(),
            protocol: format!("{:?}", req.version),
            host: host.clone(),
            path: path.clone(),
            query: query.clone(),
            status,
            duration_ms: elapsed.as_secs_f64() * 1000.0,
            bytes_received: ctx.req_body.total_size,
            bytes_sent: ctx.res_body.total_size,
            error: error.map(|e| e.to_string()),
        };
        self.logger.access(&access);

        if !ctx.waf_matched_rules.is_empty() {
            let req_headers: HashMap<String, String> = session
                .req_header()
                .headers
                .iter()
                .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
                .collect();

            let req_body_str = if ctx.req_body.buf.is_empty() {
                None
            } else {
                Some(String::from_utf8_lossy(&ctx.req_body.buf).into_owned())
            };

            let resp = session.response_written().map(|r| {
                let resp_headers: HashMap<String, String> = r
                    .headers
                    .iter()
                    .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
                    .collect();
                let resp_body_str = if ctx.res_body.buf.is_empty() {
                    None
                } else {
                    Some(String::from_utf8_lossy(&ctx.res_body.buf).into_owned())
                };
                AuditResponse {
                    status,
                    headers: resp_headers,
                    body: resp_body_str,
                    body_size: ctx.res_body.total_size,
                }
            });

            let audit = AuditLogEntry {
                request_id: ctx.request_id.clone(),
                timestamp: now,
                waf_action: std::mem::take(&mut ctx.waf_action),
                waf_matched_rules: std::mem::take(&mut ctx.waf_matched_rules)
                    .into_iter()
                    .map(|(id, action)| MatchedRule { id, action })
                    .collect(),
                waf_scores: std::mem::take(&mut ctx.waf_scores),
                waf_payloads: std::mem::take(&mut ctx.waf_payloads),
                request: AuditRequest {
                    client_ip: access.client_ip.clone(),
                    method,
                    protocol: format!("{:?}", session.req_header().version),
                    host,
                    path,
                    query,
                    headers: req_headers,
                    body: req_body_str,
                    body_size: ctx.req_body.total_size,
                },
                response: resp,
            };
            self.logger.audit(&audit);
        }
    }
}
