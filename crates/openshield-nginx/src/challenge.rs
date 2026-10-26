//! The challenge page's verification POST.
//!
//! The form carries the Turnstile token. Checking it means asking
//! Cloudflare, which must not block a worker, so the module issues an
//! in-memory subrequest to the internal location named by
//! `openshield_turnstile_location`, which `proxy_pass`es to
//! [`TURNSTILE_VERIFY_URL`]. When it completes, nginx resumes the main
//! request's phases and [`step`] sets the cookie and redirects, or serves
//! the page again.

use core::ffi::c_void;
use core::ptr;

use ngx::core::Status;
use ngx::ffi::{
    NGX_HTTP_POST, NGX_HTTP_SUBREQUEST_IN_MEMORY, NGX_HTTP_SUBREQUEST_WAITED, NGX_LOG_ERR,
    NGX_LOG_INFO, ngx_alloc_chain_link, ngx_create_temp_buf, ngx_http_post_subrequest_t,
    ngx_http_request_body_t, ngx_http_request_t, ngx_http_subrequest, ngx_int_t, ngx_str_t,
    ngx_uint_t,
};
use ngx::http::{HttpModuleMainConf, Request};
use ngx::{ngx_log_error, ngx_string};
use openshield_core::challenge::{TURNSTILE_VERIFY_URL, VerificationForm};

use crate::request::{client_ip, request_body_bytes, send_response};
use crate::{Module, RequestCtx, ctx_mut};

/// Largest verification POST we read; the form holds a token and a URL.
const MAX_FORM_BYTES: usize = 8 * 1024;

pub enum ChallengeState {
    /// Not a verification request.
    None,
    /// nginx is reading the posted form.
    ReadingForm,
    /// The form is read; the Turnstile subrequest is next.
    Form(VerificationForm),
    /// Waiting for the subrequest's answer.
    Verifying { redirect: Option<String> },
    /// Cloudflare answered.
    Verified { ok: bool, redirect: Option<String> },
}

/// The posted form, from the buffered request body.
pub fn read_form(request: &Request) -> VerificationForm {
    VerificationForm::parse(&request_body_bytes(request, MAX_FORM_BYTES))
}

/// Advance a verification request from its current state. Returns the
/// status for the access handler.
pub fn step(request: &mut Request, ctx: &mut RequestCtx) -> Status {
    let Some(cm) = ctx.tx.waf().challenge() else {
        return Status::NGX_DECLINED;
    };
    let ip = client_ip(request)
        .map(|ip| ip.to_string())
        .unwrap_or_default();
    let page = cm.challenge_page().to_string();
    match std::mem::replace(&mut ctx.challenge, ChallengeState::None) {
        ChallengeState::Form(form) => {
            let Some(token) = form.token else {
                return serve_page(request, ctx, &page);
            };
            let body = encode_form(&cm.turnstile_request(&token, &ip).form);
            let location = Module::main_conf(request)
                .map(|m| m.turnstile_location.clone())
                .unwrap_or_default();
            match unsafe { verify_subrequest(request, &location, body.as_bytes()) } {
                Ok(()) => {
                    ctx.challenge = ChallengeState::Verifying {
                        redirect: form.redirect,
                    };
                    Status::NGX_AGAIN
                }
                Err(()) => {
                    ngx_log_error!(
                        NGX_LOG_ERR,
                        request.log(),
                        "openshield: Turnstile subrequest to {location} failed; is the location defined?"
                    );
                    Status::NGX_ERROR
                }
            }
        }
        ChallengeState::Verifying { redirect } => {
            ctx.challenge = ChallengeState::Verifying { redirect };
            Status::NGX_AGAIN
        }
        ChallengeState::Verified { ok: true, redirect } => {
            ctx.answered = true;
            let cookie = cm.create_cookie(&ip);
            // For a redirect status nginx takes the value as the Location.
            send_response(
                request,
                302,
                "",
                redirect.as_deref().unwrap_or("/"),
                &[("Set-Cookie", &cookie), ("Cache-Control", "no-store")],
            )
        }
        ChallengeState::Verified { ok: false, .. } => serve_page(request, ctx, &page),
        ChallengeState::ReadingForm | ChallengeState::None => Status::NGX_DECLINED,
    }
}

fn serve_page(request: &mut Request, ctx: &mut RequestCtx, page: &str) -> Status {
    ctx.answered = true;
    send_response(
        request,
        403,
        "text/html; charset=utf-8",
        page,
        &[("Cache-Control", "no-store")],
    )
}

fn encode_form(form: &[(&str, String)]) -> String {
    form_urlencoded::Serializer::new(String::new())
        .extend_pairs(form.iter().map(|(k, v)| (*k, v.as_str())))
        .finish()
}

/// POST `body` to `uri` as an in-memory subrequest; [`turnstile_done`] runs
/// when it completes.
unsafe fn verify_subrequest(request: &mut Request, uri: &str, body: &[u8]) -> Result<(), ()> {
    let pool = request.pool();
    let r: *mut ngx_http_request_t = request.into();

    let uri_str = pool.alloc_type::<ngx_str_t>();
    let post = pool.alloc_type::<ngx_http_post_subrequest_t>();
    let rb = pool.calloc_type::<ngx_http_request_body_t>();
    let buf = unsafe { ngx_create_temp_buf(pool.as_ptr(), body.len().max(1)) };
    let link = unsafe { ngx_alloc_chain_link(pool.as_ptr()) };
    if uri_str.is_null() || post.is_null() || rb.is_null() || buf.is_null() || link.is_null() {
        return Err(());
    }

    unsafe {
        *uri_str = ngx_str_t {
            len: uri.len(),
            data: ngx::ffi::detail::str_to_uchar(pool.as_ptr(), uri),
        };
        (*post).handler = Some(turnstile_done);
        (*post).data = ptr::null_mut();

        let mut sr: *mut ngx_http_request_t = ptr::null_mut();
        let rc = ngx_http_subrequest(
            r,
            uri_str,
            ptr::null_mut(),
            &mut sr,
            post,
            (NGX_HTTP_SUBREQUEST_IN_MEMORY | NGX_HTTP_SUBREQUEST_WAITED) as ngx_uint_t,
        );
        if Status(rc) != Status::NGX_OK || sr.is_null() {
            return Err(());
        }

        // Give the subrequest its own POST body; the proxy module sends it.
        ptr::copy_nonoverlapping(body.as_ptr(), (*buf).pos, body.len());
        (*buf).last = (*buf).pos.add(body.len());
        (*buf).set_last_buf(1);
        (*link).buf = buf;
        (*link).next = ptr::null_mut();
        (*rb).bufs = link;
        (*sr).request_body = rb;
        (*sr).method = NGX_HTTP_POST as ngx_uint_t;
        (*sr).method_name = ngx_string!("POST");
        (*sr).headers_in.content_length_n = body.len() as _;
        (*sr).headers_in.set_chunked(0);
    }
    Ok(())
}

/// Records Cloudflare's answer on the main request. nginx then resumes the
/// main request's phases.
unsafe extern "C" fn turnstile_done(
    sr: *mut ngx_http_request_t,
    _data: *mut c_void,
    rc: ngx_int_t,
) -> ngx_int_t {
    let parent = unsafe { (*sr).parent };
    if parent.is_null() {
        return rc;
    }
    let request = unsafe { Request::from_ngx_http_request(parent) };
    if let Some(ctx) = ctx_mut(request)
        && let ChallengeState::Verifying { redirect } =
            std::mem::replace(&mut ctx.challenge, ChallengeState::None)
    {
        let status = unsafe { (*sr).headers_out.status };
        let body: &[u8] = unsafe {
            let upstream = (*sr).upstream;
            if upstream.is_null() {
                &[]
            } else {
                let b = &(*upstream).buffer;
                if b.pos.is_null() || b.last <= b.pos {
                    &[]
                } else {
                    core::slice::from_raw_parts(b.pos, b.last.offset_from(b.pos) as usize)
                }
            }
        };
        let ok = status == 200
            && ctx
                .tx
                .waf()
                .challenge()
                .is_some_and(|cm| cm.turnstile_verified(body));
        if status == 200 {
            ngx_log_error!(
                NGX_LOG_INFO,
                request.log(),
                "openshield: Turnstile verification {} ({} bytes answered)",
                if ok { "passed" } else { "rejected" },
                body.len()
            );
        } else {
            ngx_log_error!(
                NGX_LOG_ERR,
                request.log(),
                "openshield: Turnstile verification returned status {status} (expected 200 from {TURNSTILE_VERIFY_URL})"
            );
        }
        ctx.challenge = ChallengeState::Verified { ok, redirect };
    }
    rc
}
