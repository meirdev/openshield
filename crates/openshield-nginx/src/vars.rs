//! `$openshield_action`, `$openshield_rules` and `$openshield_request_id`.
//!
//! They read the request's finished [`summary`](crate::summary). Requests
//! the module did not inspect leave them unset, which `log_format` renders
//! as `-`.

use ngx::core::Status;
use ngx::ffi::{
    NGX_HTTP_VAR_NOCACHEABLE, ngx_conf_t, ngx_http_add_variable, ngx_http_request_t,
    ngx_http_variable_value_t, ngx_int_t, ngx_str_t, ngx_uint_t,
};
use ngx::http::Request;
use ngx::ngx_string;

use crate::{ctx_mut, summary};

const ACTION: usize = 0;
const RULES: usize = 1;
const REQUEST_ID: usize = 2;

static mut NAMES: [(ngx_str_t, usize); 3] = [
    (ngx_string!("openshield_action"), ACTION),
    (ngx_string!("openshield_rules"), RULES),
    (ngx_string!("openshield_request_id"), REQUEST_ID),
];

pub unsafe fn add_variables(cf: *mut ngx_conf_t) -> ngx_int_t {
    for (name, which) in unsafe { &mut *core::ptr::addr_of_mut!(NAMES) } {
        let var =
            unsafe { ngx_http_add_variable(cf, name, NGX_HTTP_VAR_NOCACHEABLE as ngx_uint_t) };
        if var.is_null() {
            return Status::NGX_ERROR.into();
        }
        unsafe {
            (*var).get_handler = Some(get_variable);
            (*var).data = *which;
        }
    }
    Status::NGX_OK.into()
}

unsafe extern "C" fn get_variable(
    r: *mut ngx_http_request_t,
    v: *mut ngx_http_variable_value_t,
    data: usize,
) -> ngx_int_t {
    let request = unsafe { Request::from_ngx_http_request(r) };
    let v = unsafe { &mut *v };
    let Some(ctx) = ctx_mut(request) else {
        v.set_not_found(1);
        return Status::NGX_OK.into();
    };
    let summary = summary(ctx, request);
    let value = match data {
        ACTION => summary.waf_action.clone(),
        RULES => summary.waf_matched_rules.join(","),
        _ => summary.request_id.clone(),
    };
    let data = unsafe { ngx::ffi::detail::str_to_uchar(request.pool().as_ptr(), &value) };
    if data.is_null() {
        return Status::NGX_ERROR.into();
    }
    v.data = data;
    v.set_len(value.len() as u32);
    v.set_valid(1);
    v.set_no_cacheable(1);
    v.set_not_found(0);
    Status::NGX_OK.into()
}
