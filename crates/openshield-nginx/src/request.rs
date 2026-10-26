//! Between nginx's request and the core's data types.

use core::ptr;
use std::net::IpAddr;

use ngx::core::Status;
use ngx::ffi::{
    ngx_buf_t, ngx_http_complex_value_t, ngx_http_finalize_request, ngx_http_send_response,
    ngx_read_file, ngx_str_t, ngx_uint_t,
};
use ngx::http::{NgxListIterator, Request};
use openshield_core::waf::data::{RequestData, ResponseData};
use openshield_core::{BodyVerdict, Intervention, Transaction};

fn ngx_str(s: &ngx_str_t) -> &[u8] {
    if s.data.is_null() || s.len == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(s.data, s.len) }
    }
}

fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Header names lowercased, in wire order.
pub fn header_pairs(iter: NgxListIterator<'_>) -> Vec<(String, String)> {
    iter.map(|(k, v)| {
        (
            lossy(k.as_bytes()).to_ascii_lowercase(),
            lossy(v.as_bytes()),
        )
    })
    .collect()
}

/// The client's address, as nginx renders it.
pub fn client_ip(request: &Request) -> Option<IpAddr> {
    let connection = unsafe { &*request.connection() };
    lossy(ngx_str(&connection.addr_text)).parse().ok()
}

pub fn request_data(request: &Request) -> RequestData {
    let r = request.as_ref();
    let connection = unsafe { &*request.connection() };

    let client_ip = client_ip(request);
    #[cfg(ngx_feature = "http_ssl")]
    let is_tls = !connection.ssl.is_null();
    #[cfg(not(ngx_feature = "http_ssl"))]
    let is_tls = false;

    let headers = header_pairs(request.headers_in_iterator());
    let host = headers
        .iter()
        .find(|(k, _)| k == "host")
        .map(|(_, v)| v.clone())
        .unwrap_or_default();

    let uri = lossy(ngx_str(&r.unparsed_uri));
    let (path, query) = match uri.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (uri.clone(), String::new()),
    };
    let scheme = if is_tls { "https" } else { "http" };
    let full_uri = format!("{scheme}://{host}{uri}");
    let after_slash = path.rsplit_once('/').map(|(_, f)| f).unwrap_or(&path);
    let extension = after_slash
        .rsplit_once('.')
        .map(|(_, ext)| ext)
        .unwrap_or("")
        .to_string();

    RequestData {
        client_ip,
        is_tls,
        method: lossy(ngx_str(&r.method_name)),
        version: lossy(ngx_str(&r.http_protocol)),
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

/// The response nginx is about to send: status and headers, including the
/// ones nginx keeps in dedicated fields rather than the header list.
pub fn response_data(request: &Request) -> ResponseData {
    let out = &request.as_ref().headers_out;
    let mut headers = header_pairs(request.headers_out_iterator());
    if out.content_type.len > 0 {
        headers.push(("content-type".into(), lossy(ngx_str(&out.content_type))));
    }
    if out.content_length_n >= 0 {
        headers.push(("content-length".into(), out.content_length_n.to_string()));
    }
    ResponseData {
        status: out.status as u16,
        headers,
    }
}

/// Hand a buffer's bytes to `feed` in bounded pieces, in memory or read back
/// from the file it lives in. `feed` gets `(data, last_piece)` and returns
/// whether to continue.
///
/// # Safety
/// `buf` must be a valid nginx buffer.
pub unsafe fn read_buf(buf: *mut ngx_buf_t, feed: &mut dyn FnMut(&[u8], bool) -> bool) {
    if unsafe { (*buf).in_file() } != 0 {
        let file = unsafe { (*buf).file };
        let (mut pos, last) = unsafe { ((*buf).file_pos, (*buf).file_last) };
        if pos >= last {
            feed(&[], true);
            return;
        }
        let mut piece = vec![0u8; 64 * 1024];
        while pos < last {
            let want = usize::try_from(last - pos)
                .unwrap_or(usize::MAX)
                .min(piece.len());
            let n = unsafe { ngx_read_file(file, piece.as_mut_ptr(), want, pos) };
            if n <= 0 {
                feed(&[], true);
                return;
            }
            pos += n as i64;
            if !feed(&piece[..n as usize], pos >= last) {
                return;
            }
        }
    } else {
        let data = unsafe {
            let (p, l) = ((*buf).pos, (*buf).last);
            if p.is_null() || l <= p {
                &[][..]
            } else {
                core::slice::from_raw_parts(p, l.offset_from(p) as usize)
            }
        };
        feed(data, true);
    }
}

/// Mark a buffer as fully consumed so nginx can reuse it.
///
/// # Safety
/// `buf` must be a valid nginx buffer.
pub unsafe fn consume_buf(buf: *mut ngx_buf_t) {
    unsafe {
        if (*buf).in_file() != 0 {
            (*buf).file_pos = (*buf).file_last;
        }
        (*buf).pos = (*buf).last;
    }
}

/// Answer the request ourselves with `status` and `body`, and finish it. The
/// caller returns the result from its phase handler.
pub fn send_response(
    request: &mut Request,
    status: u16,
    content_type: &str,
    body: &str,
    extra_headers: &[(&str, &str)],
) -> Status {
    for (name, value) in extra_headers {
        if request.add_header_out(name, value).is_none() {
            return Status::NGX_ERROR;
        }
    }
    let pool = request.pool().as_ptr();
    let mut ct = ngx_str_t {
        len: content_type.len(),
        data: unsafe { ngx::ffi::detail::str_to_uchar(pool, content_type) },
    };
    let mut cv: ngx_http_complex_value_t = unsafe { core::mem::zeroed() };
    cv.value = ngx_str_t {
        len: body.len(),
        data: unsafe { ngx::ffi::detail::str_to_uchar(pool, body) },
    };
    if (!content_type.is_empty() && ct.data.is_null())
        || (!body.is_empty() && cv.value.data.is_null())
    {
        return Status::NGX_ERROR;
    }

    let r: *mut ngx::ffi::ngx_http_request_t = request.into();
    let rc = unsafe {
        ngx_http_send_response(
            r,
            status as ngx_uint_t,
            if content_type.is_empty() {
                ptr::null_mut()
            } else {
                &mut ct
            },
            &mut cv,
        )
    };
    unsafe { ngx_http_finalize_request(r, rc) };
    Status::NGX_DONE
}

/// Up to `limit` bytes of the buffered request body.
pub fn request_body_bytes(request: &Request, limit: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let body = request.as_ref().request_body;
    let mut chain = if body.is_null() {
        ptr::null_mut()
    } else {
        unsafe { (*body).bufs }
    };
    while !chain.is_null() && out.len() < limit {
        let buf = unsafe { (*chain).buf };
        if !buf.is_null() {
            unsafe {
                read_buf(buf, &mut |data, _| {
                    let room = limit - out.len();
                    out.extend_from_slice(&data[..data.len().min(room)]);
                    out.len() < limit
                });
            }
        }
        chain = unsafe { (*chain).next };
    }
    out
}

/// Feed the buffered request body (memory buffers, or the temp file nginx
/// spilled it to) through the transaction. Returns a block to send, if any.
pub fn inspect_request_body(tx: &mut Transaction, request: &Request) -> Option<Intervention> {
    let mut block = None;
    let body = request.as_ref().request_body;
    let mut chain = if body.is_null() {
        ptr::null_mut()
    } else {
        unsafe { (*body).bufs }
    };
    while !chain.is_null() && block.is_none() {
        let buf = unsafe { (*chain).buf };
        if !buf.is_null() {
            unsafe {
                read_buf(
                    buf,
                    &mut |data, _| match tx.request_body_chunk(data, false) {
                        BodyVerdict::Block(intervention) => {
                            block = Some(intervention);
                            false
                        }
                        _ => true,
                    },
                );
            }
        }
        chain = unsafe { (*chain).next };
    }
    if block.is_some() {
        return block;
    }
    match tx.request_body_chunk(&[], true) {
        BodyVerdict::Block(intervention) => Some(intervention),
        _ => None,
    }
}
