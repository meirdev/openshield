pub mod context;
pub mod headers;
pub mod metrics;

use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;
use context::RequestCtx;
use log::warn;
use metrics::{ACTIVE_CONNECTIONS, BYTES_RECEIVED, BYTES_SENT, TOTAL_REQUESTS};
use openshield_core::challenge::{ChallengeManager, TURNSTILE_VERIFY_URL, VerificationForm};
use openshield_core::waf::data::{RequestData, ResponseData};
use openshield_core::{BodyVerdict, Intervention, ResponseOutcome, Verdict, Waf};
use pingora::prelude::*;
use pingora::proxy::{ProxyHttp, Session};

pub struct ReverseProxyHandler {
    pub waf: Arc<Waf>,
    pub access_log: Arc<crate::access_log::AccessLog>,
    pub http_client: reqwest::Client,
    pub upstream_tls: bool,
    pub upstream_host: String,
    pub upstream_port: u16,
}

fn header_pairs(headers: &http::HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
        .collect()
}

fn extract_request_data(session: &Session) -> RequestData {
    let req = session.req_header();
    let headers = header_pairs(&req.headers);

    let is_tls = session.digest().is_some_and(|d| d.ssl_digest.is_some());
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
        geo: None,
    }
}

fn extract_response_data(resp: &pingora::http::ResponseHeader) -> ResponseData {
    ResponseData {
        status: resp.status.as_u16(),
        headers: header_pairs(&resp.headers),
    }
}

async fn send_block_response(session: &mut Session, intervention: &Intervention) {
    let code =
        http::StatusCode::from_u16(intervention.status_code).unwrap_or(http::StatusCode::FORBIDDEN);
    let body = intervention.content.as_deref().unwrap_or("").as_bytes();
    let ct = intervention.content_type.as_deref().unwrap_or("text/plain");

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
    /// Ask Cloudflare whether a Turnstile token is genuine. Network errors
    /// and timeouts count as not verified.
    async fn verify_turnstile(&self, cm: &ChallengeManager, token: &str, client_ip: &str) -> bool {
        let request = cm.turnstile_request(token, client_ip);
        let response = self
            .http_client
            .post(TURNSTILE_VERIFY_URL)
            .form(&request.form)
            .send()
            .await;
        match response {
            Ok(response) => match response.bytes().await {
                Ok(body) => cm.turnstile_verified(&body),
                Err(e) => {
                    warn!("Failed to read Turnstile response: {}", e);
                    false
                }
            },
            Err(e) => {
                warn!("Turnstile API request failed: {}", e);
                false
            }
        }
    }

    async fn handle_challenge_verify(
        &self,
        session: &mut Session,
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

        let form = VerificationForm::parse(&body_buf);
        let client_ip_str = client_ip(session)
            .map(|ip| ip.to_string())
            .unwrap_or_default();

        if let Some(token) = form.token.as_deref()
            && self.verify_turnstile(cm, token, &client_ip_str).await
        {
            // Verification passed: set cookie and redirect
            let cookie = cm.create_cookie(&client_ip_str);
            let location = form.redirect.as_deref().unwrap_or("/");
            let mut resp =
                pingora::http::ResponseHeader::build(http::StatusCode::FOUND, Some(3)).unwrap();
            let _ = resp.insert_header("Location", location);
            let _ = resp.insert_header("Set-Cookie", &cookie);
            let _ = resp.insert_header("Cache-Control", "no-store");
            let _ = session.write_response_header(Box::new(resp), true).await;
            return Ok(true);
        }

        // Verification failed: show the challenge again
        send_challenge_page(session, cm).await;
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
            tx: self.waf.transaction(),
            pending_block: None,
        }
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        let req_data = extract_request_data(session);

        // The challenge page posting back for verification.
        if let Some(cm) = self.waf.challenge()
            && cm.is_verification_request(&req_data.method, &req_data.path)
        {
            ctx.tx.set_request(req_data);
            return self.handle_challenge_verify(session, cm).await;
        }

        match ctx.tx.request_headers(req_data) {
            Verdict::Pass | Verdict::Allow => Ok(false),
            Verdict::Block(intervention) => {
                send_block_response(session, &intervention).await;
                Ok(true)
            }
            Verdict::Challenge => match self.waf.challenge() {
                Some(cm) => {
                    send_challenge_page(session, cm).await;
                    Ok(true)
                }
                None => Ok(false),
            },
        }
    }

    async fn request_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<bytes::Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        let data = body.as_deref().unwrap_or(&[]);
        BYTES_RECEIVED.inc_by(data.len() as u64);

        match ctx.tx.request_body_chunk(data, end_of_stream) {
            BodyVerdict::Passthrough => {}
            // An empty chunk (not None) avoids signalling end-of-body to the
            // upstream (`upstream_end_of_body = end || data.is_none()`).
            BodyVerdict::Hold => *body = Some(bytes::Bytes::new()),
            BodyVerdict::Forward(released) => *body = Some(bytes::Bytes::from(released)),
            BodyVerdict::Block(intervention) => {
                // Status and content are rendered from pending_block in
                // fail_to_proxy; the error only aborts proxying.
                let code = intervention.status_code;
                ctx.pending_block = Some(intervention);
                return Err(pingora::Error::new(pingora::ErrorType::HTTPStatus(code)));
            }
        }
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
        // A body-phase rule asked to block: render the configured block
        // response.
        if let Some(intervention) = ctx.pending_block.take() {
            send_block_response(session, &intervention).await;
            return pingora::proxy::FailToProxy {
                error_code: intervention.status_code,
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
        // Evaluated for its side effects only: by this point the response is
        // being proxied, so a block verdict here is not acted on.
        let _ = ctx
            .tx
            .response_headers(extract_response_data(upstream_response));
        // If a ResponseBody rule might rewrite/suppress the body, drop
        // Content-Length so the (possibly altered) body can be re-framed as
        // chunked.
        if self.waf.rewrites_response_body() {
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
        let data = body.as_deref().unwrap_or(&[]);
        match ctx.tx.response_body_chunk(data, end_of_stream) {
            BodyVerdict::Passthrough => BYTES_SENT.inc_by(data.len() as u64),
            BodyVerdict::Hold => *body = Some(bytes::Bytes::new()),
            BodyVerdict::Forward(released) => {
                BYTES_SENT.inc_by(released.len() as u64);
                *body = Some(bytes::Bytes::from(released));
            }
            BodyVerdict::Block(intervention) => {
                // Status and headers were already sent downstream; only the
                // body can change here.
                let content = intervention.content.unwrap_or_default().into_bytes();
                BYTES_SENT.inc_by(content.len() as u64);
                *body = Some(bytes::Bytes::from(content));
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
        let written = session.response_written();
        let status = written.map(|r| r.status.as_u16()).unwrap_or(0);
        let headers = written.map(|r| header_pairs(&r.headers));

        let summary = ctx.tx.finish(ResponseOutcome {
            status,
            headers: headers.as_deref(),
            error: error.map(|e| e.to_string()),
        });
        self.access_log.write(&summary);
    }
}
