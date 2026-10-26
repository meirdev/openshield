//! OpenShield as an nginx dynamic module.
//!
//! ```nginx
//! load_module modules/libopenshield_nginx.so;
//!
//! http {
//!     openshield_config /etc/openshield/waf.yaml;
//!
//!     server {
//!         location / {
//!             openshield on;
//!             proxy_pass http://backend;
//!         }
//!     }
//! }
//! ```
//!
//! The WAF is built once from the YAML when nginx reads its configuration,
//! so `nginx -t` validates it. Each request on an enabled location gets a
//! [`Transaction`]: the request-headers phase runs in nginx's access phase,
//! and the logging phase runs in nginx's log phase, which also fills the
//! `$openshield_action`, `$openshield_rules` and `$openshield_request_id`
//! variables for `log_format`.
//!
//! When the configuration has `request_body` rules, the access handler asks
//! nginx to read the body first (the way nginx's own `mirror` module does),
//! inspects it once it is buffered, and acts on the verdict.
//!
//! Response headers and bodies go through filters installed at the top of
//! nginx's filter chains (see [`filters`]).
//!
//! Rate-limit counters live in a shared memory zone (see [`ratelimit`]), so
//! all worker processes count together.
//!
//! The challenge page's verification POST is checked with Turnstile through
//! an in-memory subrequest to an internal location that proxies to
//! Cloudflare (see [`challenge`]), so no worker ever blocks on the network.

mod challenge;
mod filters;
mod log_bridge;
mod ratelimit;
mod request;
mod vars;

use core::ffi::{c_char, c_void};
use core::ptr;
use std::sync::Arc;

use ngx::core::{NGX_CONF_ERROR, NGX_CONF_OK, Status};
use ngx::ffi::{
    NGX_CONF_FLAG, NGX_CONF_TAKE1, NGX_HTTP_LOC_CONF, NGX_HTTP_LOC_CONF_OFFSET, NGX_HTTP_MAIN_CONF,
    NGX_HTTP_MAIN_CONF_OFFSET, NGX_HTTP_MODULE, NGX_HTTP_SPECIAL_RESPONSE, NGX_HTTP_SRV_CONF,
    NGX_LOG_EMERG, NGX_LOG_ERR, NGX_OK, ngx_array_push, ngx_command_t, ngx_conf_full_name,
    ngx_conf_t, ngx_http_core_run_phases, ngx_http_finalize_request, ngx_http_handler_pt,
    ngx_http_module_t, ngx_http_phases_NGX_HTTP_ACCESS_PHASE, ngx_http_phases_NGX_HTTP_LOG_PHASE,
    ngx_http_read_client_request_body, ngx_http_request_t, ngx_int_t, ngx_module_t, ngx_parse_size,
    ngx_shared_memory_add, ngx_shm_zone_t, ngx_str_t, ngx_uint_t,
};
use ngx::http::{
    HttpModule, HttpModuleLocationConf, HttpModuleMainConf, Merge, MergeConfigError,
    NgxHttpCoreModule, Request,
};
use ngx::{http_request_handler, ngx_conf_log_error, ngx_log_error, ngx_string};
use openshield_core::config::WafConfig;
use openshield_core::{
    Intervention, ResponseOutcome, Transaction, TransactionSummary, Verdict, Waf,
};

use crate::challenge::ChallengeState;
use crate::request::{header_pairs, inspect_request_body, request_data, send_response};

pub struct Module;

impl HttpModule for Module {
    fn module() -> &'static ngx_module_t {
        unsafe { &*ptr::addr_of!(ngx_http_openshield_module) }
    }

    unsafe extern "C" fn preconfiguration(cf: *mut ngx_conf_t) -> ngx_int_t {
        unsafe { vars::add_variables(cf) }
    }

    unsafe extern "C" fn postconfiguration(cf: *mut ngx_conf_t) -> ngx_int_t {
        let cf = unsafe { &mut *cf };
        let Some(cmcf) = NgxHttpCoreModule::main_conf_mut(cf) else {
            return Status::NGX_ERROR.into();
        };
        let handlers: [(u32, ngx_http_handler_pt); 2] = [
            (ngx_http_phases_NGX_HTTP_ACCESS_PHASE, Some(access_handler)),
            (ngx_http_phases_NGX_HTTP_LOG_PHASE, Some(log_handler)),
        ];
        for (phase, handler) in handlers {
            let slot = unsafe { ngx_array_push(&mut cmcf.phases[phase as usize].handlers) }
                as *mut ngx_http_handler_pt;
            if slot.is_null() {
                return Status::NGX_ERROR.into();
            }
            unsafe { *slot = handler };
        }
        unsafe { filters::install() };
        Status::NGX_OK.into()
    }

    unsafe extern "C" fn init_main_conf(cf: *mut ngx_conf_t, conf: *mut c_void) -> *mut c_char {
        let main = unsafe { &mut *(conf as *mut MainConf) };
        let Some(path) = main.config_path.as_deref() else {
            return NGX_CONF_OK;
        };

        // Resolve relative to nginx's prefix, like every other path directive.
        let full_path = match unsafe { full_name(cf, path) } {
            Some(p) => p,
            None => {
                ngx_conf_log_error!(
                    NGX_LOG_EMERG,
                    cf,
                    "openshield_config: invalid path {path:?}"
                );
                return NGX_CONF_ERROR;
            }
        };

        log_bridge::install();
        let zone: *mut ngx_shm_zone_t = unsafe {
            ngx_shared_memory_add(
                cf,
                &raw mut RATELIMIT_ZONE_NAME,
                main.ratelimit_zone_size,
                &raw mut ngx_http_openshield_module as *mut c_void,
            )
        };
        if zone.is_null() {
            ngx_conf_log_error!(
                NGX_LOG_EMERG,
                cf,
                "openshield: cannot add the rate-limit zone"
            );
            return NGX_CONF_ERROR;
        }
        unsafe { (*zone).init = Some(ratelimit::zone_init) };
        let store = Arc::new(ratelimit::SharedStore::new(zone));
        let waf = WafConfig::load(std::path::Path::new(&full_path)).and_then(|mut config| {
            // A relative audit log path is meant relative to nginx's prefix,
            // like nginx's own log paths, not to the working directory.
            let audit = &mut config.audit_log.path;
            if audit.is_relative() && !audit.starts_with("/dev") {
                match unsafe { full_name(cf, &audit.to_string_lossy()) } {
                    Some(p) => *audit = p.into(),
                    None => return Err("invalid audit_log path".into()),
                }
            }
            Waf::from_config_with_store(&config, store)
        });
        match waf {
            Ok(waf) => {
                main.waf = Some(Arc::new(waf));
                NGX_CONF_OK
            }
            Err(e) => {
                ngx_conf_log_error!(NGX_LOG_EMERG, cf, "openshield_config {full_path}: {e}");
                NGX_CONF_ERROR
            }
        }
    }
}

/// `http`-level state: the config path and the WAF built from it.
pub struct MainConf {
    config_path: Option<String>,
    waf: Option<Arc<Waf>>,
    /// Internal location that proxies to Turnstile's siteverify endpoint.
    turnstile_location: String,
    /// Size of the shared memory zone for rate-limit counters.
    ratelimit_zone_size: usize,
}

impl Default for MainConf {
    fn default() -> Self {
        Self {
            config_path: None,
            waf: None,
            turnstile_location: "/_openshield/turnstile".into(),
            ratelimit_zone_size: 10 * 1024 * 1024,
        }
    }
}

static mut RATELIMIT_ZONE_NAME: ngx_str_t = ngx_string!("openshield_ratelimit");

unsafe impl HttpModuleMainConf for Module {
    type MainConf = MainConf;
}

/// Per-location switch, inherited from the enclosing server and http blocks.
#[derive(Debug, Default)]
pub struct LocConf {
    enable: Option<bool>,
}

impl Merge for LocConf {
    fn merge(&mut self, prev: &LocConf) -> Result<(), MergeConfigError> {
        if self.enable.is_none() {
            self.enable = prev.enable;
        }
        Ok(())
    }
}

unsafe impl HttpModuleLocationConf for Module {
    type LocationConf = LocConf;
}

static mut NGX_HTTP_OPENSHIELD_COMMANDS: [ngx_command_t; 5] = [
    ngx_command_t {
        name: ngx_string!("openshield_config"),
        type_: (NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1) as ngx_uint_t,
        set: Some(set_config_path),
        conf: NGX_HTTP_MAIN_CONF_OFFSET as ngx_uint_t,
        offset: 0,
        post: ptr::null_mut(),
    },
    ngx_command_t {
        name: ngx_string!("openshield_ratelimit_zone"),
        type_: (NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1) as ngx_uint_t,
        set: Some(set_ratelimit_zone),
        conf: NGX_HTTP_MAIN_CONF_OFFSET as ngx_uint_t,
        offset: 0,
        post: ptr::null_mut(),
    },
    ngx_command_t {
        name: ngx_string!("openshield_turnstile_location"),
        type_: (NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1) as ngx_uint_t,
        set: Some(set_turnstile_location),
        conf: NGX_HTTP_MAIN_CONF_OFFSET as ngx_uint_t,
        offset: 0,
        post: ptr::null_mut(),
    },
    ngx_command_t {
        name: ngx_string!("openshield"),
        type_: (NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG)
            as ngx_uint_t,
        set: Some(set_enable),
        conf: NGX_HTTP_LOC_CONF_OFFSET as ngx_uint_t,
        offset: 0,
        post: ptr::null_mut(),
    },
    ngx_command_t::empty(),
];

static NGX_HTTP_OPENSHIELD_MODULE_CTX: ngx_http_module_t = ngx_http_module_t {
    preconfiguration: Some(Module::preconfiguration),
    postconfiguration: Some(Module::postconfiguration),
    create_main_conf: Some(Module::create_main_conf),
    init_main_conf: Some(Module::init_main_conf),
    create_srv_conf: None,
    merge_srv_conf: None,
    create_loc_conf: Some(Module::create_loc_conf),
    merge_loc_conf: Some(Module::merge_loc_conf),
};

// The `ngx_modules` table nginx looks up in a dynamic module built outside
// its build system.
#[cfg(feature = "export-modules")]
ngx::ngx_modules!(ngx_http_openshield_module);

#[used]
#[allow(non_upper_case_globals)]
#[cfg_attr(not(feature = "export-modules"), unsafe(no_mangle))]
pub static mut ngx_http_openshield_module: ngx_module_t = ngx_module_t {
    ctx: &raw const NGX_HTTP_OPENSHIELD_MODULE_CTX as _,
    commands: unsafe { &raw mut NGX_HTTP_OPENSHIELD_COMMANDS[0] },
    type_: NGX_HTTP_MODULE as ngx_uint_t,
    ..ngx_module_t::default()
};

extern "C" fn set_config_path(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    let main = unsafe { &mut *(conf as *mut MainConf) };
    let args: &[ngx_str_t] = unsafe { (*(*cf).args).as_slice() };
    match args[1].to_str() {
        Ok(path) if !path.is_empty() => {
            main.config_path = Some(path.to_string());
            NGX_CONF_OK
        }
        _ => {
            ngx_conf_log_error!(NGX_LOG_EMERG, cf, "openshield_config: path must be UTF-8");
            NGX_CONF_ERROR
        }
    }
}

extern "C" fn set_ratelimit_zone(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    let main = unsafe { &mut *(conf as *mut MainConf) };
    let args: &mut [ngx_str_t] = unsafe { (*(*cf).args).as_slice_mut() };
    let size = unsafe { ngx_parse_size(&mut args[1]) };
    if size < 64 * 1024 {
        ngx_conf_log_error!(
            NGX_LOG_EMERG,
            cf,
            "openshield_ratelimit_zone: expected a size of at least 64k, like \"10m\""
        );
        return NGX_CONF_ERROR;
    }
    main.ratelimit_zone_size = size as usize;
    NGX_CONF_OK
}

extern "C" fn set_turnstile_location(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    let main = unsafe { &mut *(conf as *mut MainConf) };
    let args: &[ngx_str_t] = unsafe { (*(*cf).args).as_slice() };
    match args[1].to_str() {
        Ok(uri) if uri.starts_with('/') => {
            main.turnstile_location = uri.to_string();
            NGX_CONF_OK
        }
        _ => {
            ngx_conf_log_error!(
                NGX_LOG_EMERG,
                cf,
                "openshield_turnstile_location: expected a URI starting with \"/\""
            );
            NGX_CONF_ERROR
        }
    }
}

extern "C" fn set_enable(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    let loc = unsafe { &mut *(conf as *mut LocConf) };
    let args: &[ngx_str_t] = unsafe { (*(*cf).args).as_slice() };
    match args[1].to_str().map(|s| s.to_ascii_lowercase()).as_deref() {
        Ok("on") => loc.enable = Some(true),
        Ok("off") => loc.enable = Some(false),
        _ => {
            ngx_conf_log_error!(NGX_LOG_EMERG, cf, "openshield: expected \"on\" or \"off\"");
            return NGX_CONF_ERROR;
        }
    }
    NGX_CONF_OK
}

/// `name` made absolute against nginx's prefix.
unsafe fn full_name(cf: *mut ngx_conf_t, name: &str) -> Option<String> {
    let pool = unsafe { (*cf).pool };
    let mut s = ngx_str_t {
        len: name.len(),
        data: unsafe { ngx::ffi::detail::str_to_uchar(pool, name) },
    };
    if unsafe { ngx_conf_full_name((*cf).cycle, &mut s, 0) } != NGX_OK as ngx_int_t {
        return None;
    }
    let bytes = unsafe { core::slice::from_raw_parts(s.data, s.len) };
    Some(String::from_utf8_lossy(bytes).into_owned())
}

/// Per-request state, kept in the request pool and dropped with it.
pub struct RequestCtx {
    pub tx: Transaction,
    pub summary: Option<TransactionSummary>,
    /// Where request body inspection stands; see [`access_handler`].
    pub body: BodyState,
    /// We sent the response ourselves (block or challenge); the filters
    /// leave it alone.
    pub answered: bool,
    /// Response bodies are inspected, so the body filter must look.
    pub inspect_response: bool,
    /// The header filter ran for the upstream response.
    pub headers_seen: bool,
    /// The body filter sent the block content as the final buffer.
    pub response_done: bool,
    /// Progress of a challenge verification POST; see [`challenge`].
    pub challenge: ChallengeState,
}

pub enum BodyState {
    /// No body inspection for this request.
    None,
    /// nginx is reading the body; the access handler will run again.
    Reading,
    /// The body was inspected. `Some` is a block to send.
    Done(Option<Intervention>),
}

/// This module's context for the request, if the access handler created it.
///
/// The returned borrow is not tied to `request`: the context lives in the
/// request pool, so it is valid for as long as the request is.
fn ctx_mut<'a>(request: &mut Request) -> Option<&'a mut RequestCtx> {
    let r: *mut ngx_http_request_t = request.into();
    unsafe {
        let slots = (*r).ctx;
        if slots.is_null() {
            return None;
        }
        (*slots.add(Module::module().ctx_index) as *mut RequestCtx).as_mut()
    }
}

/// Sends a block from a body or header verdict, or lets the request through.
fn act(request: &mut Request, intervention: Option<Intervention>) -> Status {
    match intervention {
        Some(i) => answer(
            request,
            i.status_code,
            i.content_type.as_deref().unwrap_or("text/plain"),
            i.content.as_deref().unwrap_or(""),
            &[],
        ),
        None => Status::NGX_DECLINED,
    }
}

/// Send our own response, flagging the context so the filters skip it.
fn answer(
    request: &mut Request,
    status: u16,
    content_type: &str,
    body: &str,
    extra_headers: &[(&str, &str)],
) -> Status {
    if let Some(ctx) = ctx_mut(request) {
        ctx.answered = true;
    }
    send_response(request, status, content_type, body, extra_headers)
}

http_request_handler!(access_handler, |request: &mut Request| {
    // Only the main request of a client connection is inspected: subrequests
    // and `error_page` redirects reuse its verdict.
    if !request.is_main() || request.as_ref().internal() != 0 {
        return Status::NGX_DECLINED;
    }
    let enabled = Module::location_conf(request).and_then(|c| c.enable) == Some(true);
    if !enabled {
        return Status::NGX_DECLINED;
    }
    if let Some(ctx) = ctx_mut(request) {
        if !matches!(ctx.challenge, ChallengeState::None) {
            return challenge::step(request, ctx);
        }
        // Second pass, after nginx read the body for us.
        return match std::mem::replace(&mut ctx.body, BodyState::None) {
            BodyState::Done(intervention) => act(request, intervention),
            _ => Status::NGX_DECLINED,
        };
    }
    let Some(waf) = Module::main_conf(request).and_then(|m| m.waf.as_ref()) else {
        ngx_log_error!(
            NGX_LOG_ERR,
            request.log(),
            "openshield is on but no openshield_config is set; request not inspected"
        );
        return Status::NGX_DECLINED;
    };

    let mut tx = waf.transaction();
    let data = request_data(request);
    let verification = waf
        .challenge()
        .is_some_and(|cm| cm.is_verification_request(&data.method, &data.path));
    let verdict = if verification {
        // The challenge page posting back: no rules, just the Turnstile check.
        tx.set_request(data);
        Verdict::Pass
    } else {
        tx.request_headers(data)
    };
    let inspect_response = waf.settings().inspect_response_body;
    let ctx = request.pool().allocate(RequestCtx {
        tx,
        summary: None,
        body: BodyState::None,
        answered: false,
        inspect_response,
        headers_seen: false,
        response_done: false,
        challenge: ChallengeState::None,
    });
    if ctx.is_null() {
        return Status::NGX_ERROR;
    }
    request.set_module_ctx(ctx as *mut c_void, Module::module());
    let ctx = unsafe { &mut *ctx };

    if verification {
        if !has_body(request) {
            ctx.challenge = ChallengeState::Form(Default::default());
            return challenge::step(request, ctx);
        }
        ctx.challenge = ChallengeState::ReadingForm;
        return read_body(request);
    }

    match verdict {
        Verdict::Pass | Verdict::Allow => {
            if !waf.inspects_request_body() || !has_body(request) {
                return Status::NGX_DECLINED;
            }
            ctx.body = BodyState::Reading;
            read_body(request)
        }
        Verdict::Block(intervention) => act(request, Some(intervention)),
        Verdict::Challenge => match waf.challenge() {
            Some(cm) => answer(
                request,
                403,
                "text/html; charset=utf-8",
                cm.challenge_page(),
                &[("Cache-Control", "no-store")],
            ),
            None => Status::NGX_DECLINED,
        },
    }
});

/// Ask nginx to read the body; `body_handler` resumes the phases once it is
/// buffered, so the access handler runs again. Mirrors nginx's own `mirror`
/// module.
fn read_body(request: &mut Request) -> Status {
    let r: *mut ngx_http_request_t = request.into();
    let rc = unsafe { ngx_http_read_client_request_body(r, Some(body_handler)) };
    if rc >= NGX_HTTP_SPECIAL_RESPONSE as ngx_int_t {
        return Status(rc);
    }
    unsafe { ngx_http_finalize_request(r, Status::NGX_DONE.into()) };
    Status::NGX_DONE
}

fn has_body(request: &Request) -> bool {
    let headers_in = &request.as_ref().headers_in;
    headers_in.content_length_n > 0 || headers_in.chunked() != 0
}

/// Called by nginx once the whole request body is buffered. Inspects it,
/// keeps the body for the upstream, and resumes the phases so the access
/// handler can act.
unsafe extern "C" fn body_handler(r: *mut ngx_http_request_t) {
    let request = unsafe { Request::from_ngx_http_request(r) };
    if let Some(ctx) = ctx_mut(request) {
        if matches!(ctx.challenge, ChallengeState::ReadingForm) {
            ctx.challenge = ChallengeState::Form(challenge::read_form(request));
        } else {
            let verdict = inspect_request_body(&mut ctx.tx, request);
            ctx.body = BodyState::Done(verdict);
        }
    }
    unsafe {
        (*r).set_preserve_body(1);
        (*r).write_event_handler = Some(ngx_http_core_run_phases);
        ngx_http_core_run_phases(r);
    }
}

/// The transaction's summary, finishing it (logging phase, audit entry) on
/// first use. nginx runs log-phase handlers in registration order, so the
/// access log's variables are read before our log handler runs; this makes
/// the first read do the work.
pub fn summary<'a>(ctx: &'a mut RequestCtx, request: &Request) -> &'a TransactionSummary {
    if ctx.summary.is_none() {
        let headers = header_pairs(request.headers_out_iterator());
        let status = request.as_ref().headers_out.status as u16;
        ctx.summary = Some(ctx.tx.finish(ResponseOutcome {
            status,
            headers: Some(&headers),
            error: None,
        }));
    }
    ctx.summary.as_ref().expect("just set")
}

http_request_handler!(log_handler, |request: &mut Request| {
    if let Some(ctx) = ctx_mut(request) {
        summary(ctx, request);
    }
    Status::NGX_OK
});
