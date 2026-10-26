//! Response header and body filters.
//!
//! Installed at the top of nginx's filter chains, so they see the upstream
//! response before gzip and the other output filters. The header filter runs
//! the `response_headers` phase; the body filter feeds the body through the
//! transaction and maps its verdicts onto buffers: pass through, hold,
//! release, or replace the rest with the block content.

use core::ptr;

use ngx::core::Status;
use ngx::ffi::{
    ngx_alloc_chain_link, ngx_buf_t, ngx_chain_t, ngx_create_temp_buf,
    ngx_http_output_body_filter_pt, ngx_http_output_header_filter_pt, ngx_http_request_t,
    ngx_http_top_body_filter, ngx_http_top_header_filter, ngx_int_t, ngx_pool_t,
};
use ngx::http::Request;
use openshield_core::BodyVerdict;

use crate::ctx_mut;
use crate::request::{consume_buf, read_buf, response_data};

static mut NEXT_HEADER_FILTER: ngx_http_output_header_filter_pt = None;
static mut NEXT_BODY_FILTER: ngx_http_output_body_filter_pt = None;

/// Put our filters at the top of the chains. Called from postconfiguration.
pub unsafe fn install() {
    unsafe {
        NEXT_HEADER_FILTER = ngx_http_top_header_filter;
        ngx_http_top_header_filter = Some(header_filter);
        NEXT_BODY_FILTER = ngx_http_top_body_filter;
        ngx_http_top_body_filter = Some(body_filter);
    }
}

unsafe fn next_header(r: *mut ngx_http_request_t) -> ngx_int_t {
    match unsafe { NEXT_HEADER_FILTER } {
        Some(f) => unsafe { f(r) },
        None => Status::NGX_OK.into(),
    }
}

unsafe fn next_body(r: *mut ngx_http_request_t, chain: *mut ngx_chain_t) -> ngx_int_t {
    match unsafe { NEXT_BODY_FILTER } {
        Some(f) => unsafe { f(r, chain) },
        None => Status::NGX_OK.into(),
    }
}

unsafe extern "C" fn header_filter(r: *mut ngx_http_request_t) -> ngx_int_t {
    let request = unsafe { Request::from_ngx_http_request(r) };
    if request.is_main()
        && let Some(ctx) = ctx_mut(request)
        && !ctx.answered
        && !ctx.headers_seen
    {
        ctx.headers_seen = true;
        // Evaluated for its side effects: the response is already on its
        // way, so a block verdict here is not acted on (as in the proxy).
        let _ = ctx.tx.response_headers(response_data(request));
        if ctx.tx.waf().rewrites_response_body() {
            // The body may be withheld or replaced; let nginx re-frame it.
            unsafe { clear_content_length(r) };
        }
    }
    unsafe { next_header(r) }
}

unsafe fn clear_content_length(r: *mut ngx_http_request_t) {
    let out = unsafe { &mut (*r).headers_out };
    out.content_length_n = -1;
    if !out.content_length.is_null() {
        unsafe { (*out.content_length).hash = 0 };
        out.content_length = ptr::null_mut();
    }
}

unsafe extern "C" fn body_filter(r: *mut ngx_http_request_t, input: *mut ngx_chain_t) -> ngx_int_t {
    let request = unsafe { Request::from_ngx_http_request(r) };
    let ctx = if request.is_main() {
        ctx_mut(request)
    } else {
        None
    };
    let Some(ctx) = ctx else {
        return unsafe { next_body(r, input) };
    };
    if ctx.answered || !ctx.inspect_response || input.is_null() {
        return unsafe { next_body(r, input) };
    }

    let pool = request.pool().as_ptr();
    let mut out = OutChain::default();
    let mut cl = input;
    while !cl.is_null() {
        let buf = unsafe { (*cl).buf };
        cl = unsafe { (*cl).next };
        if buf.is_null() {
            continue;
        }
        let last = unsafe { (*buf).last_buf() } != 0;
        if ctx.response_done {
            // The block content was already sent as the final buffer.
            unsafe { consume_buf(buf) };
            continue;
        }
        let mut ended_without_output = last;
        unsafe {
            read_buf(buf, &mut |data, last_piece| {
                let end = last && last_piece;
                let (bytes, done): (Vec<u8>, bool) = match ctx.tx.response_body_chunk(data, end) {
                    BodyVerdict::Passthrough => (data.to_vec(), false),
                    BodyVerdict::Hold => return true,
                    BodyVerdict::Forward(released) => (released, false),
                    BodyVerdict::Block(intervention) => {
                        (intervention.content.unwrap_or_default().into_bytes(), true)
                    }
                };
                let final_buf = end || done;
                if final_buf {
                    ended_without_output = false;
                }
                if done {
                    ctx.response_done = true;
                }
                out.push(pool, &bytes, final_buf);
                !done
            });
            consume_buf(buf);
        }
        if ended_without_output {
            // Nothing released on the last buffer: still close the response.
            out.push(pool, &[], true);
        }
    }

    if out.head.is_null() {
        Status::NGX_OK.into()
    } else {
        unsafe { next_body(r, out.head) }
    }
}

/// Buffers we send on, in order.
#[derive(Default)]
struct OutChain {
    head: *mut ngx_chain_t,
    tail: *mut ngx_chain_t,
}

impl OutChain {
    /// Append `bytes` as a flushed buffer; `last` marks the end of the body.
    fn push(&mut self, pool: *mut ngx_pool_t, bytes: &[u8], last: bool) {
        if bytes.is_empty() && !last {
            return;
        }
        let buf: *mut ngx_buf_t = unsafe {
            if bytes.is_empty() {
                let b = ngx::ffi::ngx_pcalloc(pool, core::mem::size_of::<ngx_buf_t>())
                    as *mut ngx_buf_t;
                if !b.is_null() {
                    (*b).set_sync(1);
                }
                b
            } else {
                let b = ngx_create_temp_buf(pool, bytes.len());
                if !b.is_null() {
                    ptr::copy_nonoverlapping(bytes.as_ptr(), (*b).pos, bytes.len());
                    (*b).last = (*b).pos.add(bytes.len());
                }
                b
            }
        };
        if buf.is_null() {
            return;
        }
        unsafe {
            (*buf).set_flush(1);
            (*buf).set_last_buf(last as u32);
            (*buf).set_last_in_chain(last as u32);
        }
        let link = unsafe { ngx_alloc_chain_link(pool) };
        if link.is_null() {
            return;
        }
        unsafe {
            (*link).buf = buf;
            (*link).next = ptr::null_mut();
            if self.head.is_null() {
                self.head = link;
            } else {
                (*self.tail).next = link;
            }
        }
        self.tail = link;
    }
}
