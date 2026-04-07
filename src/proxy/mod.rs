pub mod context;
pub mod headers;
pub mod metrics;

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::Instant;

use async_trait::async_trait;
use context::{BodyBuffer, RequestCtx};
use metrics::{ACTIVE_CONNECTIONS, BYTES_RECEIVED, BYTES_SENT, TOTAL_REQUESTS};
use pingora::prelude::*;
use pingora::proxy::{ProxyHttp, Session};

use crate::geoip::GeoIp;
use crate::logging::{
    AccessLogEntry, AuditLogEntry, AuditRequest, AuditResponse, Logger, MatchedRule,
};
use crate::waf::data::{MultipartPartData, RequestData, ResponseData};
use crate::waf::engine::{Engine, Phase, RuleAction};
use crate::waf::lists::{BytesListMatcher, IpListMatcher};
use crate::waf::populate;

pub struct ReverseProxyHandler {
    pub upstream_tls: bool,
    pub upstream_host: String,
    pub upstream_port: u16,
    pub geoip: Arc<RwLock<Option<GeoIp>>>,
    pub scheme: Arc<wirefilter_engine::Scheme>,
    pub engine: Arc<RwLock<Engine>>,
    pub max_request_body_buffer: usize,
    pub inspect_response_body: bool,
    pub max_response_body_buffer: usize,
    pub ip_lists: Arc<RwLock<IpListMatcher>>,
    pub bytes_lists: Arc<RwLock<BytesListMatcher>>,
    pub logger: Arc<Logger>,
}

fn evaluate_phase(
    handler: &ReverseProxyHandler,
    ctx: &mut RequestCtx,
    phase: &Phase,
) -> RuleAction {
    crate::waf::engine::sync_scores(&mut ctx.exec_ctx, &handler.scheme, &ctx.waf_scores);
    let engine = handler.engine.read().unwrap();
    let action = engine.evaluate(
        phase,
        &ctx.exec_ctx,
        &mut ctx.waf_scores,
        &mut ctx.waf_matched_rules,
    );

    match &action {
        RuleAction::Block { rule_id, .. } => {
            ctx.waf_matched_rules
                .push((rule_id.clone(), "block".into()));
            ctx.waf_action = "block".into();
            ctx.waf_rule_id = Some(rule_id.clone());
        }
        RuleAction::Allow { rule_id } => {
            ctx.waf_matched_rules
                .push((rule_id.clone(), "allow".into()));
            ctx.waf_action = "allow".into();
            ctx.waf_rule_id = Some(rule_id.clone());
        }
        RuleAction::Challenge { rule_id } => {
            ctx.waf_matched_rules
                .push((rule_id.clone(), "challenge".into()));
            ctx.waf_action = "challenge".into();
            ctx.waf_rule_id = Some(rule_id.clone());
        }
        RuleAction::NoMatch => {}
    }

    action
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

fn client_ip(session: &Session) -> Option<IpAddr> {
    session
        .client_addr()
        .and_then(|a| a.as_inet().map(|s| s.ip()))
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
                    *ip_matcher = self.ip_lists.read().unwrap().clone();
                }
                if let Some(list_ref) = self.scheme.get_list(&wirefilter_engine::Type::Bytes) {
                    let matcher = ctx.get_list_matcher_mut(list_ref);
                    let bytes_matcher = matcher
                        .as_any_mut()
                        .downcast_mut::<BytesListMatcher>()
                        .unwrap();
                    *bytes_matcher = self.bytes_lists.read().unwrap().clone();
                }
                ctx
            },
            req_body: BodyBuffer::new(self.max_request_body_buffer),
            multipart_tx: None,
            multipart_task: None,
            res_body: BodyBuffer::new(self.max_response_body_buffer),
            waf_scores: HashMap::new(),
            waf_matched_rules: Vec::new(),
            waf_action: "pass".into(),
            waf_rule_id: None,
            waf_blocked: false,
        }
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        if let Some(ip) = client_ip(session) {
            let geoip = self.geoip.read().unwrap();
            if let Some(ref g) = *geoip {
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
            _ => {}
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
        if let Some(data) = body.as_ref() {
            BYTES_RECEIVED.inc_by(data.len() as u64);
            ctx.req_body.feed(data);
            if let Some(ref tx) = ctx.multipart_tx {
                let _ = tx.send(Ok(data.clone())).await;
            }
        }

        if end_of_stream {
            let content_type = session
                .req_header()
                .headers
                .get("content-type")
                .and_then(|v| v.to_str().ok());
            populate::body_fields(
                &mut ctx.exec_ctx,
                &self.scheme,
                &ctx.req_body.buf,
                ctx.req_body.total_size,
                ctx.req_body.truncated,
                content_type,
            );

            if let Some(tx) = ctx.multipart_tx.take() {
                drop(tx);
                if let Some(handle) = ctx.multipart_task.take() {
                    if let Ok(parts) = handle.await {
                        populate::multipart_fields(&mut ctx.exec_ctx, &self.scheme, &parts);
                    }
                }
            }
        }
        Ok(())
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
        Ok(())
    }

    fn response_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<bytes::Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<Option<std::time::Duration>> {
        if let Some(data) = body.as_ref() {
            BYTES_SENT.inc_by(data.len() as u64);
        }

        if self.inspect_response_body {
            if let Some(data) = body.as_ref() {
                ctx.res_body.feed(data);
            }
            if end_of_stream {
                populate::response_body_fields(
                    &mut ctx.exec_ctx,
                    &self.scheme,
                    &ctx.res_body.buf,
                    ctx.res_body.total_size,
                    ctx.res_body.truncated,
                );
                evaluate_phase(self, ctx, &Phase::ResponseBody);
            }
        }
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
                waf_rule_id: ctx.waf_rule_id.take(),
                waf_matched_rules: std::mem::take(&mut ctx.waf_matched_rules)
                    .into_iter()
                    .map(|(id, action)| MatchedRule { id, action })
                    .collect(),
                waf_scores: std::mem::take(&mut ctx.waf_scores),
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
